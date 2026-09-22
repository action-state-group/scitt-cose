//! Command scitt-cose-rust-verify: an INDEPENDENT, non-Python second opinion on
//! a generic SCITT/RFC 9162 COSE Receipt -- the Rust sibling of
//! `scitt-cose-go-verify`. Profile-opaque: it verifies the receipt's
//! cryptographic claims and treats everything else as opaque.
//!
//! Usage: scitt-cose-rust-verify --receipt <file> --log-pubkey <pem-file> \
//!         --leaf-entry-hex <hex>
//!
//! Prints one JSON object to stdout and exits 0 iff the receipt verifies.

use std::process::ExitCode;

use serde::Serialize;

#[derive(Serialize)]
struct Output {
    ok: bool,
    root: Option<String>,
    tree_size: Option<u64>,
    leaf_index: Option<u64>,
    iat: Option<i64>,
    grade: Option<String>,
    witness_time_established: bool,
    grade_cryptographically_bound: bool,
    errors: Vec<String>,
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (receipt_path, pubkey_path, leaf_entry_hex) = match (
        arg_value(&args, "--receipt"),
        arg_value(&args, "--log-pubkey"),
        arg_value(&args, "--leaf-entry-hex"),
    ) {
        (Some(r), Some(k), Some(l)) => (r, k, l),
        _ => {
            eprintln!(
                "usage: scitt-cose-rust-verify --receipt <file> --log-pubkey <pem-file> --leaf-entry-hex <hex>"
            );
            return ExitCode::FAILURE;
        }
    };

    let receipt = match std::fs::read(&receipt_path) {
        Ok(b) => b,
        Err(e) => return emit_error(format!("read receipt {receipt_path}: {e}")),
    };
    let pubkey_pem = match std::fs::read_to_string(&pubkey_path) {
        Ok(s) => s,
        Err(e) => return emit_error(format!("read log-pubkey {pubkey_path}: {e}")),
    };
    let leaf_entry = match hex::decode(&leaf_entry_hex) {
        Ok(b) => b,
        Err(e) => return emit_error(format!("--leaf-entry-hex is not valid hex: {e}")),
    };

    let result = scitt_cose_receipt::verify_receipt(&receipt, &leaf_entry, &pubkey_pem);
    let out = Output {
        ok: result.ok,
        root: result.root.map(hex::encode),
        tree_size: result.tree_size,
        leaf_index: result.leaf_index,
        iat: result.iat,
        grade: result.grade,
        witness_time_established: result.witness_time_established,
        grade_cryptographically_bound: result.grade_cryptographically_bound,
        errors: result.errors,
    };
    println!(
        "{}",
        serde_json::to_string(&out).expect("Output serializes")
    );
    if out.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn emit_error(msg: String) -> ExitCode {
    let out = Output {
        ok: false,
        root: None,
        tree_size: None,
        leaf_index: None,
        iat: None,
        grade: None,
        witness_time_established: false,
        grade_cryptographically_bound: false,
        errors: vec![msg],
    };
    println!(
        "{}",
        serde_json::to_string(&out).expect("Output serializes")
    );
    ExitCode::FAILURE
}
