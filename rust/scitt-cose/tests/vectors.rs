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

fn assert_matches(id: &str) {
    let (expected, result) = run_receipt_v1(id);
    assert_eq!(result.ok, expected.ok, "{id}: errors={:?}", result.errors);
    assert_eq!(
        result.witness_time_established, expected.witness_time_established,
        "{id}: witness_time_established"
    );
    assert_eq!(
        result.grade_cryptographically_bound, expected.grade_cryptographically_bound,
        "{id}: grade_cryptographically_bound"
    );
    if expected.ok {
        assert_eq!(result.root.map(hex::encode), expected.root, "{id}: root");
        assert_eq!(result.iat, expected.iat, "{id}: iat");
        assert_eq!(result.grade, expected.grade, "{id}: grade");
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
