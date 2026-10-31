//! checkpointed-local-log's shared receipt vectors
//! (`test-vectors/cll-receipt/receipt-vectors.json`): this crate accepts
//! exactly the cases agent-action-capsule's receipt encoding rule accepts
//! (scitt-cose#106).

use base64ct::{Base64, Encoding};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::EncodePublicKey;
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct Vectors {
    entry_hash_hex: String,
    authority_public_key_hex: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    accept: bool,
    tree_size: u64,
    leaf_index: u64,
    receipt_b64: String,
}

#[test]
fn cll_receipt_vectors_decide_as_pinned() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-vectors/cll-receipt/receipt-vectors.json");
    let vectors: Vectors = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let key: [u8; 32] = hex::decode(&vectors.authority_public_key_hex)
        .unwrap()
        .try_into()
        .unwrap();
    let pem = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .unwrap()
        .to_public_key_pem(LineEnding::LF)
        .unwrap();
    let entry = hex::decode(&vectors.entry_hash_hex).unwrap();
    let mut wrong = Vec::new();
    for case in &vectors.cases {
        let receipt = Base64::decode_vec(&case.receipt_b64).unwrap();
        let r = scitt_cose_receipt::verify_receipt(&receipt, &entry, &pem);
        let accepted =
            r.ok && r.tree_size == Some(case.tree_size) && r.leaf_index == Some(case.leaf_index);
        if accepted != case.accept {
            wrong.push(format!(
                "{} (accept {}): {:?}",
                case.name, case.accept, r.errors
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} cases differ:\n{}",
        wrong.len(),
        vectors.cases.len(),
        wrong.join("\n")
    );
}
