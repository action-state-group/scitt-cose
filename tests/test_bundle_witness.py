# SPDX-License-Identifier: Apache-2.0
"""The bundle page's own witness check (viewer/src/witness.js, via the real
BUNDLE_JS ``describeWitness``).

The page checks, in the reader's browser: the bundle's signed checkpoint; each
witness receipt, under a key from a witness list the READER chose (never one
the bundle supplies); a cadence chain from the checkpoint to a witnessed
checkpoint; and "in part", an earlier witnessed checkpoint the bundle's
checkpoint extends. It names the level it checked, and says when it only found
evidence present.

Fixtures in tests/fixtures/witness/ were written by a producer (capsulectl)
and pass its own ``verify --bundle --witness-directory``: ``direct.json`` (a
receipt on the bundle's checkpoint), ``cadence-all.json`` (a cadence chain to
a witnessed checkpoint of the same size), ``cadence-part.json`` (the chain
reaches an earlier checkpoint: 5 of 6 entries). Each is cut down to its
``checkpoint`` and its ``cadence-witness/v0`` extension, which is all the
witness check reads. The witness keys are test keys.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from hosted_profiles.hosted import BUNDLE_JS, MMR_JS, WITNESS_LIST_JS, _PUBLISHED_WITNESS_LIST
from scitt_cose.receipt import build_receipt, verify_receipt

HERE = Path(__file__).parent
HARNESS = HERE / "js_harness_bundle.mjs"
FIXTURES = HERE / "fixtures" / "witness"
CADENCE = "cadence-witness/v0"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


@pytest.fixture(scope="module")
def js_paths():
    paths = []
    for src in (MMR_JS, BUNDLE_JS):
        f = tempfile.NamedTemporaryFile("w", suffix=".js", delete=False)
        f.write(src)
        f.close()
        paths.append(Path(f.name))
    yield paths
    for p in paths:
        p.unlink(missing_ok=True)


def check(js_paths, bundle, witness_list=None, list_name="your list"):
    op = {
        "fn": "checkWitness",
        "bundle": bundle,
        "list": None if witness_list is None else json.dumps(witness_list),
        "listName": list_name,
    }
    result = subprocess.run(
        ["node", str(HARNESS), str(js_paths[0]), str(js_paths[1])],
        input=json.dumps(op), capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    out = json.loads(result.stdout)
    return out["checked"], out["described"]


def load(name):
    return json.loads((FIXTURES / name).read_text())


def rows_of(described, status):
    return [r for r in described["rows"] if r["status"] == status]


# ---------------------------------------------------------------------------
# The three levels, checked
# ---------------------------------------------------------------------------


def test_direct_receipt_checked_under_the_readers_list(js_paths):
    checked, described = check(js_paths, load("direct.json"), load("direct-witnesses.json"))
    assert checked["checkpoint"]["status"] == "pass"
    assert checked["rung"] == "witnessed"
    assert [r["status"] for r in checked["receipts"]] == ["pass"]
    assert described["verdict"]["label"] == "Checked: witnessed"
    assert "your list" in described["verdict"]["text"]


def test_cadence_chain_to_a_witnessed_checkpoint(js_paths):
    checked, described = check(js_paths, load("cadence-all.json"), load("cadence-witnesses.json"))
    assert checked["chain"]["status"] == "pass"
    assert checked["rung"] == "witnessed"
    assert described["verdict"]["label"] == "Checked: witnessed"


def test_witnessed_in_part_names_how_much(js_paths):
    checked, described = check(js_paths, load("cadence-part.json"), load("cadence-witnesses.json"))
    assert checked["rung"] == "witnessed_in_part"
    assert (checked["stepsWitnessed"], checked["steps"]) == (5, 6)
    assert described["verdict"]["label"] == "Checked: witnessed in part"
    text = described["verdict"]["text"]
    assert "covering the first 5 of 6 entries" in text
    assert "Entry 6 is signed by the log's key only" in text


# ---------------------------------------------------------------------------
# Present is not checked
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["direct.json", "cadence-all.json", "cadence-part.json"])
def test_no_list_chosen_is_present_not_checked_never_a_pass(js_paths, name):
    checked, described = check(js_paths, load(name), None)
    assert checked["rung"] is None
    assert checked["status"] == "withheld"
    assert described["verdict"]["label"] == "Found present, not checked"
    assert "signed by the log's key only" in described["verdict"]["text"]
    assert all("present, not checked" in r["reason"] for r in checked["receipts"])


def test_a_list_without_this_witness_does_not_check_it(js_paths):
    other = {"witnesses": [{"name": "other", "endpoint": "https://other.example", "key_ids": ["ab" * 32]}]}
    checked, described = check(js_paths, load("direct.json"), other)
    assert checked["rung"] is None
    assert "has no entry for this witness" in checked["receipts"][0]["reason"]
    assert described["verdict"]["label"] == "Found present, not checked"


def test_a_rekor_row_is_not_checked_here(js_paths):
    row = dict(load("direct-witnesses.json")["witnesses"][0], binding="rekor")
    checked, _ = check(js_paths, load("direct.json"), {"witnesses": [row]})
    assert checked["rung"] is None
    assert checked["receipts"][0]["status"] == "withheld"


def test_the_published_list_does_not_vouch_for_a_witness_it_lacks(js_paths):
    """The published list shipped with the page names real witnesses only;
    a test witness's receipt stays unchecked under it."""
    checked, described = check(js_paths, load("direct.json"), _PUBLISHED_WITNESS_LIST, "the published list")
    assert checked["rung"] is None
    assert "the published list" in described["verdict"]["text"]


def test_the_published_list_is_offered_with_its_source():
    assert WITNESS_LIST_JS.startswith("globalThis.PUBLISHED_WITNESS_LIST=")
    payload = json.loads(WITNESS_LIST_JS[len("globalThis.PUBLISHED_WITNESS_LIST="):].rstrip().rstrip(";"))
    assert payload["source"]["url"].endswith("/witnesses.json")
    assert len(payload["source"]["commit"]) == 40
    assert payload["list"] == _PUBLISHED_WITNESS_LIST
    endpoints = [w["endpoint"] for w in payload["list"]["witnesses"]]
    assert "https://witness.agentactioncapsule.org" in endpoints


# ---------------------------------------------------------------------------
# Wrong keys and tampering fail, and say where
# ---------------------------------------------------------------------------


def test_a_receipt_under_another_key_fails(js_paths):
    lst = load("direct-witnesses.json")
    lst["witnesses"][0]["key_ids"] = ["ab" * 32]
    checked, described = check(js_paths, load("direct.json"), lst)
    assert checked["status"] == "fail"
    assert checked["rung"] is None
    assert described["verdict"]["label"] == "Witness check FAILED"


def test_a_key_listed_as_spki_der_is_used(js_paths):
    lst = load("direct-witnesses.json")
    row = lst["witnesses"][0]
    raw = bytes.fromhex(row["key_ids"][0])
    der = bytes.fromhex("302a300506032b6570032100") + raw
    row["public_keys"] = [base64.b64encode(der).decode()]
    row["key_ids"] = [hashlib.sha256(der).hexdigest()]
    checked, _ = check(js_paths, load("direct.json"), lst)
    assert checked["rung"] == "witnessed"


def _flip_signature_byte(cose_b64u: str) -> str:
    raw = bytearray(base64.urlsafe_b64decode(cose_b64u + "=" * (-len(cose_b64u) % 4)))
    raw[-1] ^= 1
    return base64.urlsafe_b64encode(bytes(raw)).decode().rstrip("=")


def test_a_forged_checkpoint_signature_fails_first(js_paths):
    b = load("direct.json")
    b["checkpoint"]["cose"] = _flip_signature_byte(b["checkpoint"]["cose"])
    checked, described = check(js_paths, b, load("direct-witnesses.json"))
    assert checked["checkpoint"]["status"] == "fail"
    assert "signature does not verify" in checked["checkpoint"]["reason"]
    assert described["verdict"]["label"] == "Witness check FAILED"


def test_the_bundles_copy_of_the_root_must_match_the_signed_one(js_paths):
    b = load("direct.json")
    b["checkpoint"]["root"] = "00" * 32
    checked, _ = check(js_paths, b, load("direct-witnesses.json"))
    assert checked["checkpoint"]["status"] == "fail"
    assert "root" in checked["checkpoint"]["reason"]


def _cadence(b):
    return b["extensions"][CADENCE]


@pytest.mark.parametrize(
    "name,tamper,reason",
    [
        ("cadence-all.json", lambda c: c["path"].__setitem__(0, "ab" * 32), "not included"),
        ("cadence-all.json", lambda c: c.__setitem__("salt", "00" * 32), "not included"),
        ("cadence-all.json", lambda c: c.__setitem__("index", c["index"] ^ 1), "not included"),
        ("cadence-all.json", lambda c: c.__setitem__("size", c["size"] + 1), "does not name this checkpoint"),
        ("cadence-all.json", lambda c: c["path"].pop(), "malformed"),
        ("cadence-part.json", lambda c: c["earlier"]["consistency_proof"]["new_peaks"].__setitem__(0, "ab" * 32),
         "does not extend"),
        ("cadence-part.json", lambda c: c.__setitem__("extent", "all"), "does not name this checkpoint"),
        ("cadence-part.json",
         lambda c: c["earlier"]["checkpoint"].__setitem__("cose", c["cadence"]["checkpoint"]["cose"]),
         "not an earlier checkpoint of this log"),
    ],
)
def test_a_tampered_chain_fails_and_says_where(js_paths, name, tamper, reason):
    b = load(name)
    tamper(_cadence(b))
    checked, described = check(js_paths, b, load("cadence-witnesses.json"))
    assert checked["chain"]["status"] == "fail", checked
    assert reason in checked["chain"]["reason"]
    assert checked["rung"] is None
    assert described["verdict"]["label"] == "Witness check FAILED"


def test_a_cadence_checkpoint_signed_by_another_key_fails(js_paths):
    b = load("cadence-all.json")
    inner = _cadence(b)["cadence"]["checkpoint"]
    inner["cose"] = _flip_signature_byte(inner["cose"])
    checked, _ = check(js_paths, b, load("cadence-witnesses.json"))
    assert checked["chain"]["status"] == "fail"
    assert "cadence checkpoint does not verify" in checked["chain"]["reason"]


# ---------------------------------------------------------------------------
# Receipts from a larger log (the fixtures' witness logs hold one entry)
# ---------------------------------------------------------------------------


def _larger_log_receipt(entry_hex: str, index: int = 4, size: int = 7):
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    entries = [hashlib.sha256(bytes([i])).hexdigest() for i in range(size)]
    entries[index] = entry_hex
    receipt = build_receipt(leaf_entry_hex=entry_hex, leaf_index=index, tree_entries_hex=entries,
                            alg="EdDSA", log_private_key_pem=pem)
    return receipt, raw, key


@pytest.mark.parametrize("index,size", [(0, 2), (4, 7), (6, 7), (5, 13)])
def test_a_receipt_from_a_larger_log_verifies(js_paths, index, size):
    b = load("direct.json")
    w = b["checkpoint"]["witnesses"][0]
    receipt, raw, key = _larger_log_receipt(w["entry_hash"], index, size)
    # the scitt-cose receipt verifier agrees with the page
    pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert verify_receipt(receipt, leaf_entry_hex=w["entry_hash"], log_public_key_pem=pub_pem).ok
    w.update(receipt_b64=base64.b64encode(receipt).decode(), leaf_index=index, tree_size=str(size))
    lst = {"witnesses": [{"name": "w", "endpoint": w["ts_url"], "key_ids": [raw.hex()]}]}
    checked, _ = check(js_paths, b, lst)
    assert checked["rung"] == "witnessed", checked
    # the same receipt filed at the wrong index fails
    w["leaf_index"] = (index + 1) % size
    checked, _ = check(js_paths, copy.deepcopy(b), lst)
    assert checked["receipts"][0]["status"] == "fail"


def test_a_receipt_for_another_checkpoint_fails(js_paths):
    b = load("direct.json")
    b["checkpoint"]["witnesses"][0]["entry_hash"] = "ab" * 32
    checked, _ = check(js_paths, b, load("direct-witnesses.json"))
    assert checked["receipts"][0]["status"] == "fail"
    assert "different checkpoint" in checked["receipts"][0]["reason"]


# ---------------------------------------------------------------------------
# Nothing to check
# ---------------------------------------------------------------------------


def test_no_signed_checkpoint(js_paths):
    checked, described = check(js_paths, {"records": []}, load("direct-witnesses.json"))
    assert checked["status"] == "absent"
    assert described["verdict"]["label"] == "No signed checkpoint"


def test_signed_only(js_paths):
    b = load("direct.json")
    del b["checkpoint"]["witnesses"]
    checked, described = check(js_paths, b, load("direct-witnesses.json"))
    assert checked["checkpoint"]["status"] == "pass"
    assert described["verdict"]["label"] == "Signed only"
