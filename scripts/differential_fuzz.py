#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Differential fuzzer for the scitt-cose verifiers (Python vs Go clean-room).

Seeds a corpus from the committed v1 test vectors, applies byte-level and
CBOR-structural mutations, and runs every mutant through BOTH verifiers as
isolated subprocesses (timeout + memory rlimit). Two oracles:

* **Conformance:** the two runtimes must agree on accept/reject for every
  mutant. A mutant that one VERIFIES and the other REJECTS is a finding (a
  cross-implementation split — at worst a forgery one side accepts).
* **Robustness:** no input may crash or hang either verifier. A non-zero/
  traceback exit (CRASH) or a killed-on-timeout (TIMEOUT/HANG) is a finding —
  this is what catches the hostile-CBOR DoS classes (giant declared lengths,
  pathological tree sizes) without the fuzzer itself dying, because each
  verifier runs in its own bounded subprocess.

Determinism: a fixed ``--seed`` reproduces the exact mutant stream, so a CI run
is repeatable and a found mutant can be replayed. Each finding is reduced to a
stable signature; signatures already in ``tests/fuzz/baseline.json`` are KNOWN
(the open hardening findings) and do not fail the run — anything NEW does. When
the hardening fixes land, baseline entries are removed and a regression would
re-introduce them as a hard failure.

Usage:
    python scripts/differential_fuzz.py --go-binary ./gv --iterations 400 --seed 1
    python scripts/differential_fuzz.py --go-binary ./gv --write-findings out/
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

import cbor2

REPO = Path(__file__).resolve().parents[1]
VECTORS = REPO / "test-vectors" / "v1"
BASELINE = REPO / "tests" / "fuzz" / "baseline.json"

# A verifier must answer fast: a hang -> TIMEOUT finding. (We deliberately do
# NOT impose an RLIMIT_AS memory cap on the children — it breaks the Go
# runtime's virtual-address reservation and produces platform-dependent spurious
# crashes. Pathological allocations raise MemoryError on their own, and the
# classifier below treats a tracebacked/aborted exit as CRASH.)
SUBPROC_TIMEOUT_S = 3


def _load_seeds() -> list[dict]:
    """Seed corpus from the committed v1 vectors (statement + receipt + keys)."""
    seeds = []
    for d in sorted(VECTORS.iterdir()):
        if not d.is_dir():
            continue
        exp = json.loads((d / "expected.json").read_text())
        seeds.append({
            "id": d.name,
            "kind": "statement",
            "bytes": (d / "statement.cose").read_bytes(),
            "pubkey": d / "issuer-key.pub",
            # Go's statement path selects the verifier from the --alg flag, so it
            # must match the seed's algorithm (EdDSA vs ES256) — not be hardcoded,
            # or every ES256 mutant looks like a divergence.
            "alg": exp["protected_header"]["statement"]["alg"],
        })
        seeds.append({
            "id": d.name,
            "kind": "receipt",
            "bytes": (d / "receipt.cose").read_bytes(),
            "pubkey": d / "log-key.pub",
            "leaf_entry": exp["leaf_entry"],
        })
    return seeds


# --- mutators ---------------------------------------------------------------


def _bitflip(rng: random.Random, data: bytes) -> bytes:
    if not data:
        return b"\x00"
    b = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        i = rng.randrange(len(b))
        b[i] ^= 1 << rng.randrange(8)
    return bytes(b)


def _truncate(rng: random.Random, data: bytes) -> bytes:
    if len(data) < 2:
        return data
    return data[: rng.randrange(1, len(data))]


def _splice(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    chunk = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
    at = rng.randrange(len(b) + 1)
    b[at:at] = chunk
    return bytes(b)


def _struct_giant_length(rng: random.Random, data: bytes) -> bytes:
    """Set a structural length/size field to a huge int. Targets the
    'huge declared length' / 'pathological tree_size' DoS classes. Capped at
    2**40 so an honest bytes()/loop fails fast rather than consuming the host."""
    try:
        tag = cbor2.loads(data)
    except Exception:  # noqa: BLE001
        return _bitflip(rng, data)
    if not isinstance(tag, cbor2.CBORTag):
        return _bitflip(rng, data)
    val = list(tag.value)
    big = rng.choice([2**40, 2**62, 2**63 - 1])
    try:
        unprot = dict(val[1]) if isinstance(val[1], dict) else {}
        vdp = dict(unprot.get(396) or {})
        proofs = vdp.get(-1)
        if proofs:  # receipt: corrupt tree_size inside the first inclusion proof
            arr = list(cbor2.loads(bytes(proofs[0])))
            arr[rng.choice([0, 1])] = big  # tree_size or leaf_index
            vdp[-1] = [cbor2.dumps(arr)] + list(proofs[1:])
            unprot[396] = vdp
            val[1] = unprot
            return cbor2.dumps(cbor2.CBORTag(tag.tag, val))
    except Exception:  # noqa: BLE001
        pass
    # else: replace the inclusion-proofs array element with a bare giant int
    try:
        unprot = dict(val[1]) if isinstance(val[1], dict) else {}
        unprot[396] = {-1: [big]}
        val[1] = unprot
        return cbor2.dumps(cbor2.CBORTag(tag.tag, val))
    except Exception:  # noqa: BLE001
        return _bitflip(rng, data)


def _struct_dup_key(rng: random.Random, data: bytes) -> bytes:
    """Duplicate a protected-header key (alg) with a different value — targets
    the duplicate-key last-wins algorithm-confusion class."""
    try:
        tag = cbor2.loads(data)
        val = list(tag.value)
        prot = val[0]
        inner = cbor2.loads(prot) if prot else {}
        if not isinstance(inner, dict) or 1 not in inner:
            return _bitflip(rng, data)
        # hand-assemble a 2-key map with duplicate label 1
        body = cbor2.dumps({1: inner[1]})[1:]  # drop the map header
        dup = bytes([0xA0 | (len(inner) + 1)]) + cbor2.dumps(1) + cbor2.dumps(-7) + body
        val[0] = dup
        return cbor2.dumps(cbor2.CBORTag(tag.tag, val))
    except Exception:  # noqa: BLE001
        return _bitflip(rng, data)


def _struct_indefinite_payload(rng: random.Random, data: bytes) -> bytes:
    """Re-encode the payload slot as an indefinite-length bstr — targets the
    non-canonical/indefinite-encoding malleability class."""
    try:
        tag = cbor2.loads(data)
        if tag.tag != 18:
            return _bitflip(rng, data)
        val = list(tag.value)
        payload = val[2]
        if not isinstance(payload, bytes) or not payload:
            return _bitflip(rng, data)
        # Hand-assemble tag(18) array(4) with the payload slot re-encoded as a
        # single-chunk indefinite-length bstr (0x5f <chunk> 0xff). The protected
        # bytes are unchanged, so the Sig_structure — and the signature — still
        # bind; only the payload's wire encoding becomes non-canonical.
        indef = b"\x5f" + cbor2.dumps(payload) + b"\xff"
        out = b"\xd2\x84" + cbor2.dumps(val[0]) + cbor2.dumps(val[1]) + indef + cbor2.dumps(val[3])
        return out
    except Exception:  # noqa: BLE001
        return _bitflip(rng, data)


def _struct_oversize_tree(rng: random.Random, data: bytes) -> bytes:
    """Build a receipt inclusion proof at a tree_size just above the 2^62 ceiling
    with a CORRECTLY-SIZED audit path. Unlike _struct_giant_length (which leaves a
    wrong-length path, so both verifiers reject on length regardless of the
    ceiling), this exercises the ceiling itself — the two runtimes must agree on
    rejecting it, so a future change that lets one ceiling drift from the other is
    caught here, not just in a unit test."""
    try:
        tag = cbor2.loads(data)
        if tag.tag != 18:
            return _bitflip(rng, data)
        val = list(tag.value)
        unprot = dict(val[1]) if isinstance(val[1], dict) else {}
        if 396 not in unprot:  # receipts only
            return _bitflip(rng, data)
        oversize = (1 << 62) + rng.randint(1, 1 << 20)
        # Path length = depth of index 0 in a 2^62 tree (62); enough that the
        # rejection must come from the ceiling check, not the length check.
        path = [bytes(rng.randrange(256) for _ in range(32)) for _ in range(62)]
        proof = cbor2.dumps([oversize, 0, path])
        unprot[396] = {-1: [proof]}
        val[1] = unprot
        return cbor2.dumps(cbor2.CBORTag(tag.tag, val))
    except Exception:  # noqa: BLE001
        return _bitflip(rng, data)


MUTATORS = [
    _bitflip, _bitflip, _bitflip,  # weight byte-level higher
    _truncate, _splice,
    _struct_giant_length, _struct_dup_key, _struct_indefinite_payload,
    _struct_oversize_tree,
]


# --- running a verdict ------------------------------------------------------


# Stderr markers that mean the verifier *crashed* rather than cleanly rejected
# (both can exit 1). A Python uncaught exception prints "Traceback"; a Go panic
# or runtime abort prints "panic:" / "fatal error:".
_CRASH_MARKERS = (b"Traceback", b"panic:", b"fatal error:", b"runtime:")


def _classify(proc: subprocess.CompletedProcess | None) -> str:
    if proc is None:
        return "TIMEOUT"
    if proc.returncode < 0:
        return "CRASH"  # killed by signal (segfault, abort, OOM-kill)
    if any(m in (proc.stderr or b"") for m in _CRASH_MARKERS):
        return "CRASH"  # exited but with a traceback/panic -> not a clean verdict
    if proc.returncode == 0:
        return "VALID"
    if proc.returncode == 1:
        return "INVALID"
    return "CRASH"  # any other non-zero (CLI usage error, unexpected abort)


def _run(cmd: list[str]) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=SUBPROC_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return None


def _py_verdict(mutant: Path, seed: dict) -> str:
    if seed["kind"] == "statement":
        cmd = [sys.executable, "-m", "scitt_cose.cli",
               "--statement", str(mutant), "--statement-pubkey", str(seed["pubkey"])]
    else:
        cmd = [sys.executable, "-m", "scitt_cose.cli",
               "--receipt", str(mutant), "--receipt-log-pubkey", str(seed["pubkey"]),
               "--leaf-entry-hex", seed["leaf_entry"]]
    return _classify(_run(cmd))


def _go_verdict(go_binary: str, mutant: Path, seed: dict) -> str:
    if seed["kind"] == "statement":
        cmd = [go_binary, "--statement", str(mutant),
               "--pubkey", str(seed["pubkey"]), "--alg", seed["alg"]]
    else:
        cmd = [go_binary, "--receipt", str(mutant),
               "--log-pubkey", str(seed["pubkey"]), "--leaf-entry-hex", seed["leaf_entry"]]
    return _classify(_run(cmd))


def _signature(seed_kind: str, py: str, go: str) -> str | None:
    """Stable category for a (py, go) outcome pair, or None if it's agreement
    on a clean verdict (VALID/VALID or INVALID/INVALID)."""
    if py == go and py in ("VALID", "INVALID"):
        return None
    bad = {"CRASH", "TIMEOUT"}
    if py in bad or go in bad:
        return f"robustness:{seed_kind}:py={py}:go={go}"
    # both answered cleanly but disagree
    return f"conformance:{seed_kind}:py={py}:go={go}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Differential fuzzer: Python vs Go scitt-cose verifiers.")
    ap.add_argument("--go-binary", required=True, help="path to the built Go verifier")
    ap.add_argument("--iterations", type=int, default=400)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--write-findings", help="dir to write reproducing mutant bytes")
    ap.add_argument("--update-baseline", action="store_true",
                    help="write the observed signatures to baseline.json and exit 0")
    args = ap.parse_args(argv)

    rng = random.Random(args.seed)
    seeds = _load_seeds()
    if not seeds:
        print("no seeds found under", VECTORS, file=sys.stderr)
        return 2

    baseline = set(json.loads(BASELINE.read_text())["known"]) if BASELINE.is_file() else set()
    findings: dict[str, dict] = {}
    out_dir = Path(args.write_findings) if args.write_findings else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as td:
        mutant = Path(td) / "mutant.bin"
        for i in range(args.iterations):
            seed = rng.choice(seeds)
            mutator = rng.choice(MUTATORS)
            data = mutator(rng, seed["bytes"])
            mutant.write_bytes(data)
            py = _py_verdict(mutant, seed)
            go = _go_verdict(args.go_binary, mutant, seed)
            sig = _signature(seed["kind"], py, go)
            if sig and sig not in findings:
                findings[sig] = {"iteration": i, "seed_id": seed["id"],
                                 "mutator": mutator.__name__, "py": py, "go": go}
                if out_dir:
                    (out_dir / f"{sig.replace(':', '_')}.bin").write_bytes(data)

    observed = set(findings)
    if args.update_baseline:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps({"known": sorted(observed)}, indent=2) + "\n")
        print(f"baseline updated: {len(observed)} signatures")
        return 0

    new = observed - baseline
    cleared = baseline - observed  # baseline entries no longer reproduced (fixed)

    print(f"differential fuzz: {args.iterations} iterations, seed {args.seed}")
    print(f"  signatures observed: {len(observed)}  known(baseline): {len(baseline)}")
    for sig, meta in sorted(findings.items()):
        mark = "NEW" if sig in new else "known"
        print(f"  [{mark}] {sig}  (seed={meta['seed_id']} mutator={meta['mutator']} iter={meta['iteration']})")
    if cleared:
        print("  baseline signatures NOT reproduced this run (candidate-fixed or under-sampled):")
        for sig in sorted(cleared):
            print(f"    - {sig}")
    if new:
        print(f"\nFAIL: {len(new)} new verifier divergence(s) not in baseline.")
        return 1
    print("\nPASS: no divergence outside the known baseline.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
