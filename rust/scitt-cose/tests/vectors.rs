//! Cross-implementation conformance: run the committed `test-vectors/`
//! bytes (the same bytes the Python and Go verifiers check) through this
//! crate and compare against each vector's `expected.json`.
//!
//! Two vector sets:
//!
//! * `test-vectors/v1/` — statement+receipt bundles (append-only, shared
//!   with Python/Go). Only the receipt half is exercised here; `valid-ccf-vds2`
//!   is INTENTIONALLY not asserted `VALID` -- CCF (`vds=2`) is out of scope
//!   for this crate (see `src/receipt.rs` docs), so it is checked separately
//!   below to confirm it is *rejected* as unsupported vds, not silently
//!   mis-verified.
//! * `test-vectors/receipt-v1/` — receipt-only vectors for the `iat`/`grade`
//!   protected-header labels this crate reads beyond the base RFC 9162 proof.

use serde::Deserialize;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    // rust/scitt-cose -> rust -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[derive(Deserialize)]
struct V1Expected {
    leaf_entry: String,
    receipt_valid: bool,
    reconstructed_root: Option<String>,
}

fn v1_dir(id: &str) -> PathBuf {
    repo_root().join("test-vectors/v1").join(id)
}

fn read_pem(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn run_v1(id: &str) -> (V1Expected, scitt_cose_receipt::ReceiptResult) {
    let dir = v1_dir(id);
    let expected: V1Expected =
        serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    let receipt = std::fs::read(dir.join("receipt.cose")).unwrap();
    let log_pub = read_pem(&dir.join("log-key.pub"));
    let leaf_entry = hex::decode(&expected.leaf_entry).unwrap();
    let result = scitt_cose_receipt::verify_receipt(&receipt, &leaf_entry, &log_pub);
    (expected, result)
}

#[test]
fn v1_valid_eddsa_receipt_verifies() {
    let (expected, result) = run_v1("valid-eddsa");
    assert_eq!(result.ok, expected.receipt_valid, "{:?}", result.errors);
}

#[test]
fn v1_valid_es256_receipt_verifies() {
    let (expected, result) = run_v1("valid-es256");
    assert_eq!(result.ok, expected.receipt_valid, "{:?}", result.errors);
}

#[test]
fn v1_tampered_inclusion_path_rejected() {
    let (expected, result) = run_v1("fail-tampered-path");
    assert_eq!(result.ok, expected.receipt_valid);
    assert!(!result.ok);
}

#[test]
fn v1_unsupported_vds_rejected() {
    let (expected, result) = run_v1("fail-unsupported-vds");
    assert_eq!(result.ok, expected.receipt_valid);
    assert!(!result.ok);
    assert!(result.errors.iter().any(|e| e.contains("unsupported")));
}

#[test]
fn v1_bad_statement_sig_receipt_still_verifies() {
    // This vector's FAILURE is in the Signed Statement, which this
    // receipt-only crate never reads -- the receipt itself must still verify.
    let (expected, result) = run_v1("fail-bad-statement-sig");
    assert_eq!(result.ok, expected.receipt_valid, "{:?}", result.errors);
    assert!(result.ok);
}

/// CCF (`vds=2`) is explicitly out of scope for this crate. This is not a
/// silent gap: `valid-ccf-vds2` is a REAL, valid CCF receipt that the Python
/// verifier accepts -- this crate must reject it (as unsupported vds), never
/// silently mis-verify it as ok.
#[test]
fn v1_ccf_vds2_is_rejected_not_silently_verified() {
    let dir = v1_dir("valid-ccf-vds2");
    let expected: V1Expected =
        serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    assert!(expected.receipt_valid, "vector assumption changed");
    let receipt = std::fs::read(dir.join("receipt.cose")).unwrap();
    let log_pub = read_pem(&dir.join("log-key.pub"));
    let leaf_entry = hex::decode(&expected.leaf_entry).unwrap();
    let result = scitt_cose_receipt::verify_receipt(&receipt, &leaf_entry, &log_pub);
    assert!(!result.ok, "CCF vds=2 is out of scope and must not verify");
    assert!(result.errors.iter().any(|e| e.contains("unsupported")));
}

// --- receipt-v1: iat/grade -------------------------------------------------

#[derive(Deserialize)]
struct ReceiptV1Expected {
    leaf_entry_hex: String,
    ok: bool,
    root: Option<String>,
    iat: Option<i64>,
    grade: Option<String>,
    witness_time_established: bool,
    grade_cryptographically_bound: bool,
    failure_contains: Option<String>,
    /// What the verifier must report for `root`/`tree_size`/`leaf_index`,
    /// on vectors that pin it (scitt-cose#91); older vectors leave it out.
    returned: Option<ReceiptV1Returned>,
}

#[derive(Deserialize)]
struct ReceiptV1Returned {
    root: Option<String>,
    tree_size: Option<u64>,
    leaf_index: Option<u64>,
}

fn run_receipt_v1(id: &str) -> (ReceiptV1Expected, scitt_cose_receipt::ReceiptResult) {
    let dir = repo_root().join("test-vectors/receipt-v1").join(id);
    let expected: ReceiptV1Expected =
        serde_json::from_str(&std::fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    let receipt = std::fs::read(dir.join("receipt.cose")).unwrap();
    let log_pub = read_pem(&dir.join("log-key.pub"));
    let leaf_entry = hex::decode(&expected.leaf_entry_hex).unwrap();
    let result = scitt_cose_receipt::verify_receipt(&receipt, &leaf_entry, &log_pub);
    (expected, result)
}

/// The `failed_at` a receipt-v1 vector pins (scitt-cose#93): from its own
/// `expected.json` when it carries one, otherwise from `failed-at.json`.
/// Every vector must pin one; `null` (ok) reads as `None`.
fn pinned_failed_at(id: &str) -> Option<String> {
    let dir = repo_root().join("test-vectors/receipt-v1");
    let read = |p: PathBuf| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    };
    let own = read(dir.join(id).join("expected.json"));
    let shared = read(dir.join("failed-at.json"));
    let pinned = own
        .get("failed_at")
        .or_else(|| shared["failed_at"].get(id))
        .unwrap_or_else(|| panic!("{id}: no failed_at pinned"));
    pinned.as_str().map(str::to_owned)
}

fn assert_matches(id: &str) {
    let (expected, result) = run_receipt_v1(id);
    assert_eq!(
        result.failed_at.map(|f| f.as_str().to_owned()),
        pinned_failed_at(id),
        "{id}: failed_at"
    );
    assert_eq!(result.ok, expected.ok, "{id}: errors={:?}", result.errors);
    assert_eq!(
        result.witness_time_established, expected.witness_time_established,
        "{id}: witness_time_established"
    );
    assert_eq!(
        result.grade_cryptographically_bound, expected.grade_cryptographically_bound,
        "{id}: grade_cryptographically_bound"
    );
    // iat/grade are checked on EVERY vector: the fail-* expected.json files
    // freeze them as null, i.e. never surfaced from an unverified receipt.
    assert_eq!(result.iat, expected.iat, "{id}: iat");
    assert_eq!(result.grade, expected.grade, "{id}: grade");
    if let Some(returned) = &expected.returned {
        assert_eq!(
            result.root.map(hex::encode),
            returned.root,
            "{id}: returned root"
        );
        assert_eq!(
            result.tree_size, returned.tree_size,
            "{id}: returned tree_size"
        );
        assert_eq!(
            result.leaf_index, returned.leaf_index,
            "{id}: returned leaf_index"
        );
    }
    if expected.ok {
        assert_eq!(result.root.map(hex::encode), expected.root, "{id}: root");
    } else if let Some(needle) = &expected.failure_contains {
        assert!(
            result.errors.iter().any(|e| e.contains(needle.as_str())),
            "{id}: errors {:?} do not contain {needle:?}",
            result.errors
        );
    }
}

#[test]
fn receipt_v1_trace_sept7_witness_both_limits_false() {
    // The real, pre-#44 external TRACE witness receipt: no iat/grade labels
    // at all, both booleans false, same root/tree_size/leaf_index the
    // Python verifier reports for this exact packet.
    assert_matches("trace-sept7-witness");
}

#[test]
fn receipt_v1_synthetic_eddsa_iat_grade_both_limits_true() {
    assert_matches("synthetic-eddsa-iat-grade");
}

#[test]
fn receipt_v1_synthetic_es256_iat_grade_both_limits_true() {
    assert_matches("synthetic-es256-iat-grade");
}

#[test]
fn receipt_v1_synthetic_es256_iat_grade_observed_only_both_limits_true() {
    assert_matches("synthetic-es256-iat-grade-observed-only");
}

#[test]
fn receipt_v1_iat_only_never_infers_grade() {
    assert_matches("synthetic-eddsa-iat-only");
}

#[test]
fn receipt_v1_tampered_iat_fails_signature() {
    let (_, result) = run_receipt_v1("fail-tampered-iat");
    assert!(!result.ok);
    assert!(!result.witness_time_established);
    assert_matches("fail-tampered-iat");
}

#[test]
fn receipt_v1_tampered_grade_fails_signature() {
    let (_, result) = run_receipt_v1("fail-tampered-grade");
    assert!(!result.ok);
    assert!(!result.grade_cryptographically_bound);
    assert_matches("fail-tampered-grade");
}

// Attached payloads and alg/key pairings (scitt-cose#87). Each receipt has a
// valid proof and a genuine signature under its log key, and must still fail.

#[test]
fn receipt_v1_attached_payload_rejected() {
    assert_matches("fail-attached-payload");
}

#[test]
fn receipt_v1_attached_root_payload_rejected() {
    assert_matches("fail-attached-payload-root");
}

#[test]
fn receipt_v1_es256_under_secp256k1_rejected() {
    assert_matches("fail-es256-secp256k1-key");
}

#[test]
fn receipt_v1_es384_under_p256_rejected() {
    assert_matches("fail-es384-p256-key");
}

#[test]
fn receipt_v1_eddsa_under_p256_rejected() {
    assert_matches("fail-eddsa-p256-key");
}

// Failure shape (scitt-cose#91): a failure in the signature step reports the
// first proof's root/tree_size/leaf_index as a diagnostic; an earlier failure
// reports none. The vectors pin `returned`.

#[test]
fn receipt_v1_wrong_log_key_reports_diagnostic() {
    assert_matches("fail-wrong-log-key");
}

#[test]
fn receipt_v1_unsupported_alg_reports_diagnostic() {
    assert_matches("fail-unsupported-alg");
}

#[test]
fn receipt_v1_malformed_proof_reports_nothing() {
    assert_matches("fail-malformed-proof");
}

#[test]
fn receipt_v1_malformed_tail_proof_reports_nothing() {
    // A valid first proof does not make a malformed later one a signature-step
    // failure: every proof is checked first, so no diagnostic is reported.
    assert_matches("fail-malformed-tail-proof");
}

#[test]
fn receipt_v1_attached_payload_reports_nothing() {
    // The attached-payload check runs before any proof is read.
    for id in [
        "fail-attached-payload",
        "fail-attached-payload-root",
        "fail-undefined-payload",
    ] {
        let (_, result) = run_receipt_v1(id);
        assert!(!result.ok, "{id}");
        assert_eq!(
            (result.root, result.tree_size, result.leaf_index),
            (None, None, None),
            "{id}"
        );
    }
}

#[test]
fn receipt_v1_undefined_payload_rejected() {
    // scitt-cose#104: CBOR libraries read a payload of undefined (0xf7) as
    // absent, so only the raw payload slot tells it from null.
    assert_matches("fail-undefined-payload");
}

#[test]
fn receipt_v1_undefined_payload_is_the_only_defect() {
    // The same bytes with the payload slot set back to null verify, so the
    // vector fails on the payload alone. The slot sits just before the
    // 64-byte signature and its two-byte head. Tag and array heads re-encoded
    // non-minimally or indefinitely break the receipt encoding rule
    // (scitt-cose#106), but an undefined payload is still reported as such.
    let (expected, _) = run_receipt_v1("fail-undefined-payload");
    let dir = repo_root().join("test-vectors/receipt-v1/fail-undefined-payload");
    let mut receipt = std::fs::read(dir.join("receipt.cose")).unwrap();
    let log_pub = read_pem(&dir.join("log-key.pub"));
    let leaf = hex::decode(&expected.leaf_entry_hex).unwrap();
    let slot = receipt.len() - 67;
    assert_eq!(&receipt[..2], &[0xd2, 0x84]);
    assert_eq!(receipt[slot], 0xf7);
    receipt[slot] = 0xf6;
    let null = scitt_cose_receipt::verify_receipt(&receipt, &leaf, &log_pub);
    assert!(null.ok, "{:?}", null.errors);
    let mut long_heads = vec![0xd8, 0x12, 0x98, 0x04];
    long_heads.extend_from_slice(&receipt[2..]);
    let result = scitt_cose_receipt::verify_receipt(&long_heads, &leaf, &log_pub);
    assert!(!result.ok);
    assert!(
        result.errors.iter().any(|e| e.contains("shortest form")),
        "{:?}",
        result.errors
    );
    let mut indefinite = vec![0xd2, 0x9f];
    indefinite.extend_from_slice(&receipt[2..]);
    indefinite.push(0xff);
    let result = scitt_cose_receipt::verify_receipt(&indefinite, &leaf, &log_pub);
    assert!(!result.ok);
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("indefinite length")),
        "{:?}",
        result.errors
    );
    indefinite[slot] = 0xf7;
    let result = scitt_cose_receipt::verify_receipt(&indefinite, &leaf, &log_pub);
    assert!(!result.ok);
    assert!(result.errors.iter().any(|e| e.contains("detached")));
}

#[test]
fn receipt_v1_alg_key_mismatch_reports_diagnostic() {
    // A mismatch fails in the signature step, as in the Python verifier.
    let (_, good) = run_receipt_v1("synthetic-eddsa-iat-only");
    for id in [
        "fail-es256-secp256k1-key",
        "fail-es384-p256-key",
        "fail-eddsa-p256-key",
    ] {
        let (_, result) = run_receipt_v1(id);
        assert!(!result.ok, "{id}");
        assert_eq!(result.root, good.root, "{id}: root");
        assert_eq!(
            (result.tree_size, result.leaf_index),
            (Some(4), Some(1)),
            "{id}"
        );
    }
}

// --- header claims are never surfaced from a receipt whose signature fails --
// Grade-forgery class, mirroring the Python tests: a receipt carrying grade
// "mmr-verified" that does not verify under the pinned key must expose no
// grade/iat, and must say the claims were withheld.

const CLAIMS_WITHHELD: &str = "protected header claims withheld";

fn assert_claims_withheld(result: &scitt_cose_receipt::ReceiptResult) {
    assert!(!result.ok, "errors={:?}", result.errors);
    assert_eq!(result.iat, None);
    assert_eq!(result.grade, None);
    assert!(!result.witness_time_established);
    assert!(!result.grade_cryptographically_bound);
    assert!(!format!("{result:?}").contains("mmr-verified"));
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("signature did not verify")),
        "errors={:?}",
        result.errors
    );
    assert!(
        result.errors.iter().any(|e| e.contains(CLAIMS_WITHHELD)),
        "errors={:?}",
        result.errors
    );
}

#[test]
fn grade_not_exposed_when_signed_by_non_pinned_key() {
    // A graded receipt (iat + "mmr-verified") signed by one key, verified
    // under a DIFFERENT pinned Ed25519 key (the real TRACE witness key).
    let graded = repo_root().join("test-vectors/receipt-v1/synthetic-eddsa-iat-grade");
    let pinned = repo_root().join("test-vectors/receipt-v1/trace-sept7-witness/log-key.pub");
    let receipt = std::fs::read(graded.join("receipt.cose")).unwrap();
    let result = scitt_cose_receipt::verify_receipt(&receipt, &[0x02], &read_pem(&pinned));
    assert_claims_withheld(&result);
}

#[test]
fn grade_not_exposed_when_signature_bytes_corrupted() {
    let dir = repo_root().join("test-vectors/receipt-v1/synthetic-eddsa-iat-grade");
    let receipt = std::fs::read(dir.join("receipt.cose")).unwrap();
    // The signature is the last element of the COSE_Sign1 array, so its
    // final byte is the receipt's final byte.
    let mut tampered = receipt.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    let result =
        scitt_cose_receipt::verify_receipt(&tampered, &[0x02], &read_pem(&dir.join("log-key.pub")));
    assert_claims_withheld(&result);
}

#[test]
fn grade_still_exposed_on_valid_receipt() {
    let (_, result) = run_receipt_v1("synthetic-eddsa-iat-grade");
    assert!(result.ok, "errors={:?}", result.errors);
    assert_eq!(result.grade.as_deref(), Some("mmr-verified"));
    assert_eq!(result.iat, Some(1_700_000_000));
    assert!(!result.errors.iter().any(|e| e.contains(CLAIMS_WITHHELD)));
}

#[test]
fn donated_multi_proof_receipt_selects_target_in_either_order() {
    let (expected, result) = run_v1("valid-eddsa-multi-proof");
    assert!(expected.receipt_valid);
    assert!(result.ok, "decoy masked target: {:?}", result.errors);
    let dir = v1_dir("valid-eddsa-multi-proof");
    let reordered = std::fs::read(dir.join("receipt-reordered.cose")).unwrap();
    let result = scitt_cose_receipt::verify_receipt(
        &reordered,
        &hex::decode(expected.leaf_entry).unwrap(),
        &read_pem(&dir.join("log-key.pub")),
    );
    assert!(result.ok, "reordered pair: {:?}", result.errors);
}

/// Root the decoy (first) proof of `valid-eddsa-multi-proof`'s `receipt.cose`
/// rebuilds for the vector's leaf: tree_size 8, leaf_index 1.
const MULTI_PROOF_DECOY_ROOT: &str =
    "188f4dc7ce35a72f065bcfa3f8387889ae06a2a84c8eb5e04b92cd6849d819f1";

#[test]
fn wrong_key_reports_the_first_proof_in_either_order() {
    // scitt-cose#91: with no proof verifying, the diagnostic is the FIRST
    // proof that rebuilds a root, whichever order the proofs come in.
    let (expected, _) = run_v1("valid-eddsa-multi-proof");
    let dir = v1_dir("valid-eddsa-multi-proof");
    let wrong =
        read_pem(&repo_root().join("test-vectors/receipt-v1/fail-wrong-log-key/log-key.pub"));
    let leaf = hex::decode(&expected.leaf_entry).unwrap();
    for (name, root, index) in [
        ("receipt.cose", MULTI_PROOF_DECOY_ROOT, 1),
        (
            "receipt-reordered.cose",
            expected.reconstructed_root.as_deref().unwrap(),
            2,
        ),
    ] {
        let receipt = std::fs::read(dir.join(name)).unwrap();
        let result = scitt_cose_receipt::verify_receipt(&receipt, &leaf, &wrong);
        assert!(!result.ok, "{name}");
        assert_eq!(
            result.root.map(hex::encode).as_deref(),
            Some(root),
            "{name}"
        );
        assert_eq!(
            (result.tree_size, result.leaf_index),
            (Some(8), Some(index)),
            "{name}"
        );
    }
}

#[test]
fn donated_zero_size_proof_is_reported_malformed() {
    let (_, result) = run_v1("fail-zero-size-proof");
    assert!(!result.ok);
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("invalid tree size or leaf index")),
        "{:?}",
        result.errors
    );
}

#[test]
fn candidate_verification_preserves_invalid_key_diagnostic() {
    let (expected, _) = run_v1("valid-eddsa-multi-proof");
    let receipt = std::fs::read(v1_dir("valid-eddsa-multi-proof").join("receipt.cose")).unwrap();
    let result = scitt_cose_receipt::verify_receipt(
        &receipt,
        &hex::decode(expected.leaf_entry).unwrap(),
        "not a public key",
    );
    assert!(!result.ok);
    assert!(
        result
            .errors
            .iter()
            .any(|e| e.contains("could not load EdDSA public key")),
        "{:?}",
        result.errors
    );
}
