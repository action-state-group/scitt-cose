#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ONE-TIME generator for ``test-vectors/capsule-id/expected.json`` — pins the
vanilla-JS capsule_id recompute port (``hosted_profiles.hosted``'s
``computeCapsuleId``/``verifyCapsuleId``, duplicated verbatim in ``CAPSULE_JS``
and ``BUNDLE_JS``) against agent-action-capsule's Python reference
(``agent_action_capsule.canonical.compute_capsule_id`` — RFC 8785 JCS +
SHA-256, draft-mih-scitt-agent-action-capsule S2/S5.1).

This script is NOT run in CI and has NO runtime dependency from scitt-cose on
agent-action-capsule (dependency direction is the other way: agent-action-capsule
depends on scitt-cose, never the reverse). It requires a local
``agent-action-capsule`` checkout next to this repo (``../agent-action-capsule``
by default, override with ``--aac-path``) purely as a one-time, read-only
oracle to mint the committed JSON. The committed vectors are the artifact;
re-running this script is only for provenance / regenerating a future version.

The four capsule-*.json inputs are real, live-anchored AAC capsules (not
synthetic): the 3-capsule dapr-agents-capsule demo chain run on
2026-08-03 against anchor.agentactioncapsule.org (capsule-emit repo,
examples/dapr-agents-capsule/run-transcript.md — leaves 242/243/244), plus
one hand-tampered variant of capsule-2 (see capsule-2-tampered.json's own
comment-equivalent in PROVENANCE.md) built for
[aac-viewer-recompute-capsule-id]'s negative-fixture requirement: same
capsule_id, disposition flipped from {decision:reject, verdict_class:blocked}
to {decision:accept, verdict_class:executed} -- the exact "denial reads as
approval" attack the task documents.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
VEC_DIR = REPO / "test-vectors" / "capsule-id"

FIXTURES = ("capsule-1", "capsule-2", "capsule-3", "capsule-2-tampered")


def _load_aac_canonical(aac_path: Path):
    sys.path.insert(0, str(aac_path / "python"))
    from agent_action_capsule import canonical  # noqa: PLC0415

    return canonical


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--aac-path", type=Path, default=REPO.parent / "agent-action-capsule")
    args = ap.parse_args()

    if not (args.aac_path / "python" / "agent_action_capsule" / "canonical.py").is_file():
        raise SystemExit(
            f"agent-action-capsule checkout not found at {args.aac_path} "
            "(pass --aac-path); this script is a one-time oracle run, not a CI step."
        )
    canonical = _load_aac_canonical(args.aac_path)

    expected = {}
    for name in FIXTURES:
        capsule = json.loads((VEC_DIR / f"{name}.json").read_text())
        stated = capsule["capsule_id"]
        recomputed = canonical.compute_capsule_id(capsule)
        expected[name] = {
            "stated": stated,
            "recomputed": recomputed,
            "ok": recomputed == stated,
        }

    # Sanity: the three real, untampered capsules must verify; the hand-
    # tampered one must not. If this ever fails, the fixtures are wrong.
    assert expected["capsule-1"]["ok"] is True
    assert expected["capsule-2"]["ok"] is True
    assert expected["capsule-3"]["ok"] is True
    assert expected["capsule-2-tampered"]["ok"] is False

    out = VEC_DIR / "expected.json"
    out.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out}")
    for name, v in expected.items():
        print(f"  {name}: ok={v['ok']}")


if __name__ == "__main__":
    main()
