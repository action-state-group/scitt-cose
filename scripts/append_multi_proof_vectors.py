# SPDX-License-Identifier: Apache-2.0
"""Append proof-selection regressions derived from immutable valid-eddsa bytes.

No keys or signatures are generated: only the unprotected VDP changes. The
reordered receipt is a positive control; the decoy-first receipt is the regression.
"""

import hashlib
import json
from pathlib import Path

import cbor2

ROOT = Path(__file__).resolve().parents[1] / "test-vectors"
SOURCE = ROOT / "v1/valid-eddsa"


def leaf(entry):
    return hashlib.sha256(b"\x00" + entry).digest()


def node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def root(leaves):
    if len(leaves) == 1:
        return leaves[0]
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    return node(root(leaves[:k]), root(leaves[k:]))


def path(leaves, index):
    if len(leaves) == 1:
        return []
    k = 1 << ((len(leaves) - 1).bit_length() - 1)
    if index < k:
        return path(leaves[:k], index) + [root(leaves[k:])]
    return path(leaves[k:], index - k) + [root(leaves[:k])]


def main():
    expected = json.loads((SOURCE / "expected.json").read_text())
    entries = [
        bytes.fromhex(expected["leaf_entry"])
        if i == 2
        else hashlib.sha256(
            f"scitt-cose test vectors v1 :: valid-eddsa :: filler leaf {i}".encode()
        ).digest()
        for i in range(8)
    ]
    leaves = [leaf(e) for e in entries]
    assert root(leaves).hex() == expected["reconstructed_root"]
    receipt = cbor2.loads((SOURCE / "receipt.cose").read_bytes())
    target = receipt.value[1][396][-1][0]
    decoy = cbor2.dumps([8, 1, path(leaves, 1)])
    specs = [
        ("valid-eddsa-multi-proof", [decoy, target], True, None),
        ("fail-zero-size-proof", [cbor2.dumps([0, 0, []])], False, "MALFORMED_INCLUSION_PROOF"),
    ]
    manifest_path = ROOT / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    sums = []
    for name, proofs, valid, failure in specs:
        out = ROOT / "v1" / name
        out.mkdir(exist_ok=False)
        for filename in ["statement.cose", "issuer-key.pub", "log-key.pub", "payload.bin"]:
            source = SOURCE / filename
            if source.exists():
                (out / filename).write_bytes(source.read_bytes())

        def with_proofs(values):
            return cbor2.CBORTag(
                18,
                [
                    receipt.value[0],
                    {**dict(receipt.value[1]), 396: {-1: values}},
                    receipt.value[2],
                    receipt.value[3],
                ],
            )

        (out / "receipt.cose").write_bytes(cbor2.dumps(with_proofs(proofs)))
        if valid:
            (out / "receipt-reordered.cose").write_bytes(
                cbor2.dumps(with_proofs(list(reversed(proofs))))
            )
        e = dict(expected)
        e["description"] = (
            "Inherited valid-eddsa signed bytes; unsigned proof selection/shape regression."
        )
        e["receipt_valid"] = valid
        e["result"] = "VALID" if valid else "INVALID"
        if failure:
            e["failure_code"] = failure
            e["failure_contains"] = "invalid tree size or leaf index"
        (out / "expected.json").write_text(json.dumps(e, indent=2) + "\n")
        manifest["vectors"].append(
            dict(
                id=name,
                dir=f"v1/{name}",
                description=e["description"],
                derived_from="v1/valid-eddsa",
                expected_result=e["result"],
                **({"failure_code": failure} if failure else {}),
            )
        )
        for f in sorted(out.iterdir()):
            sums.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.relative_to(ROOT)}\n")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    with (ROOT / "SHA256SUMS").open("a") as f:
        f.writelines(sums)


if __name__ == "__main__":
    main()
