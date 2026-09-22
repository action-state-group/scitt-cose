//! COSE Receipt (RFC 9162 SHA-256 vds) offline verification.
//!
//! A *Receipt* is a COSE_Sign1, signed by a transparency log, whose payload
//! is the Merkle tree root and whose unprotected header carries an RFC 9162
//! SHA-256 inclusion proof for one leaf (draft-ietf-cose-merkle-tree-proofs).
//! This module verifies a receipt against a caller-supplied pinned log
//! public key and a caller-supplied leaf entry -- no network, no key
//! discovery, no receipt issuance.
//!
//! Layering: this crate never reads or writes CLL/MMR checkpoint bytes --
//! receipts are SCITT, not CLL. Capsule/profile semantics never enter here;
//! this is a generic SCITT/COSE receipt verifier.
//!
//! Two label reads beyond the base RFC 9162 proof, following the same wire
//! shape independently converged on by scitt-cose's `iat`/`grade` support
//! (open PR action-state-group/scitt-cose#44) and the TRACE registry's own
//! receipt consumer (`trace_registry`'s `verify_witness_receipt.py`):
//!
//! * `iat` -- CWT Claims (protected header label 15, RFC 9597) claim 6
//!   (RFC 8392 §3.1.6), the witness-observed registration time.
//! * `grade` -- private-use protected-header label `-65537`, a witness-
//!   issued qualitative grade string (e.g. `"mmr-verified"`).
//!
//! Both are read from the PROTECTED header only, so a valid signature covers
//! them; [`ReceiptResult::witness_time_established`] and
//! [`ReceiptResult::grade_cryptographically_bound`] are `true` only when the
//! corresponding value is present *and* the receipt's signature verifies --
//! never inferred, never true on a failed verify.

use coset::cbor::value::Value as CborValue;
use coset::iana::EnumI64 as _;
use coset::{CoseSign1, RegisteredLabelWithPrivate, TaggedCborSerializable};
use ecdsa::signature::Verifier as _;

use crate::merkle::root_from_inclusion_proof;

/// COSE algorithm code point for EdDSA (RFC 9053).
const ALG_EDDSA: i64 = -8;
/// COSE algorithm code point for ES256 (RFC 9053).
const ALG_ES256: i64 = -7;

/// Protected header label carrying the verifiable-data-structure identifier
/// (draft-ietf-cose-merkle-tree-proofs).
const HDR_VDS: i64 = 395;
/// Unprotected header label carrying the verifiable-data-proofs map.
const HDR_VDP: i64 = 396;
/// vdp map key for the inclusion-proofs array.
const VDP_INCLUSION_PROOFS: i64 = -1;
/// vds value: RFC 9162 SHA-256 Merkle tree -- the only vds this crate
/// understands. `vds=2` (CCF `ccf.v1`) is out of scope: it is rejected the
/// same way any other unsupported vds is, never silently mis-verified.
const VDS_RFC9162_SHA256: i64 = 1;

/// CWT Claims protected-header label (RFC 9597 / COSE header label 15).
const HDR_CWT_CLAIMS: i64 = 15;
/// CWT claim number for issued-at (RFC 8392 §3.1.6).
const CWT_CLAIM_IAT: i64 = 6;
/// Private-use protected-header label carrying a witness-issued grade
/// string. Provisional by bilateral convention (see module docs), not an
/// IANA registration.
const HDR_GRADE: i64 = -65537;

/// A receipt carries one inclusion proof per leaf; an array longer than this
/// is hostile padding, capped before any per-element work (same ceiling as
/// the Python/Go verifiers).
const MAX_INCLUSION_PROOFS: usize = 16;
/// An inclusion path longer than this cannot belong to any tree this crate
/// accepts (`MAX_TREE_SIZE` -> depth <= 62). Reject before building the path.
const MAX_AUDIT_PATH: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ReceiptError {
    #[error("{0}")]
    Malformed(String),
}

fn malformed(msg: impl Into<String>) -> ReceiptError {
    ReceiptError::Malformed(msg.into())
}

/// Outcome of [`verify_receipt`]. `ok` is `true` only when the inclusion
/// proof reconstructs a root *and* the COSE_Sign1 over that root verifies
/// under the supplied log key. On any failure `ok` is `false` and `errors`
/// explains why; other fields may still be populated with what was read
/// before the failing check (same "partial state, but only meaningful when
/// `ok`" discipline as the Python `ReceiptResult`).
#[derive(Debug, Clone, Default)]
pub struct ReceiptResult {
    pub ok: bool,
    pub root: Option<[u8; 32]>,
    pub tree_size: Option<u64>,
    pub leaf_index: Option<u64>,
    pub errors: Vec<String>,
    /// Witness-observed registration time (RFC 8392 `iat`), read from the
    /// SIGNED protected header. `None` when the receipt carries no CWT
    /// claims map or no `iat` claim.
    pub iat: Option<i64>,
    /// Witness-issued qualitative grade string, read from the SIGNED
    /// protected header. `None` when absent.
    pub grade: Option<String>,
    /// `true` iff `iat` is present AND the receipt verified ok -- a signed
    /// witness clock inside the covered bytes. Never inferred from absence.
    pub witness_time_established: bool,
    /// `true` iff `grade` is present AND the receipt verified ok -- the
    /// grade is cryptographically bound to the log's signature (whether a
    /// caller's own untrusted metadata *agrees* with it is that caller's
    /// concern, not this generic verifier's).
    pub grade_cryptographically_bound: bool,
}

impl ReceiptResult {
    fn fail(mut self, msg: impl Into<String>) -> Self {
        self.ok = false;
        self.errors.push(msg.into());
        self
    }
}

fn decode_inclusion_proof(blob: &[u8]) -> Result<(u64, u64, Vec<[u8; 32]>), ReceiptError> {
    let value: CborValue = coset::cbor::de::from_reader(blob)
        .map_err(|e| malformed(format!("inclusion proof is not valid CBOR: {e:?}")))?;
    let arr = value
        .as_array()
        .ok_or_else(|| malformed("inclusion proof must be [tree_size, leaf_index, [path]]"))?;
    if arr.len() != 3 {
        return Err(malformed(
            "inclusion proof must be [tree_size, leaf_index, [path]]",
        ));
    }
    let tree_size = arr[0]
        .as_integer()
        .map(i128::from)
        .filter(|n| *n >= 0)
        .ok_or_else(|| malformed("inclusion proof tree_size must be a non-negative int"))?
        as u64;
    let leaf_index = arr[1]
        .as_integer()
        .map(i128::from)
        .filter(|n| *n >= 0)
        .ok_or_else(|| malformed("inclusion proof leaf_index must be a non-negative int"))?
        as u64;
    let path_raw = arr[2]
        .as_array()
        .ok_or_else(|| malformed("inclusion proof path must be an array"))?;
    if path_raw.len() > MAX_AUDIT_PATH {
        return Err(malformed(format!(
            "inclusion proof path too long ({} > {MAX_AUDIT_PATH})",
            path_raw.len()
        )));
    }
    let mut path = Vec::with_capacity(path_raw.len());
    for node in path_raw {
        let bytes = node
            .as_bytes()
            .ok_or_else(|| malformed("inclusion proof path element is not a byte string"))?;
        let arr32: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| malformed("inclusion proof path element must be 32 bytes"))?;
        path.push(arr32);
    }
    Ok((tree_size, leaf_index, path))
}

/// Read the protected header's integer-labeled entries into a lookup map,
/// tolerating both `Label::Int` (registered) and any other label shape by
/// simply skipping it -- callers here only ever look up known int labels.
fn protected_map(sign1: &CoseSign1) -> Vec<(i64, CborValue)> {
    sign1
        .protected
        .header
        .rest
        .iter()
        .filter_map(|(label, v)| match label {
            coset::Label::Int(i) => Some((*i, v.clone())),
            coset::Label::Text(_) => None,
        })
        .collect()
}

fn find_label(map: &[(i64, CborValue)], label: i64) -> Option<CborValue> {
    map.iter()
        .find(|(l, _)| *l == label)
        .map(|(_, v)| v.clone())
}

/// Verify a COSE Receipt for `leaf_entry` (raw bytes of the leaf entry, NOT
/// its RFC 6962 leaf hash) under `log_public_key_pem` (a PEM
/// SubjectPublicKeyInfo, EdDSA or ES256). Never panics -- every failure
/// lands in [`ReceiptResult::errors`].
pub fn verify_receipt(
    receipt: &[u8],
    leaf_entry: &[u8],
    log_public_key_pem: &str,
) -> ReceiptResult {
    let mut result = ReceiptResult::default();

    let sign1 = match CoseSign1::from_tagged_slice(receipt) {
        Ok(s) => s,
        Err(e) => return result.fail(format!("receipt is not a COSE_Sign1 message: {e:?}")),
    };

    let prot = protected_map(&sign1);

    // vds MUST come from the protected (integrity-protected) header.
    let vds = match find_label(&prot, HDR_VDS)
        .as_ref()
        .and_then(CborValue::as_integer)
    {
        Some(v) => i128::from(v),
        None => return result.fail("protected header missing vds (label 395)"),
    };

    let alg_code = match &sign1.protected.header.alg {
        Some(RegisteredLabelWithPrivate::Assigned(a)) => a.to_i64(),
        Some(RegisteredLabelWithPrivate::PrivateUse(i)) => *i,
        None => return result.fail("protected header missing alg (label 1)"),
        _ => return result.fail("protected header alg is not an integer code point"),
    };

    // Surface iat/grade from the PROTECTED header, same trust discipline as
    // root/tree_size/leaf_index below: read now, only meaningful once `ok`.
    if let Some(claims) = find_label(&prot, HDR_CWT_CLAIMS)
        .as_ref()
        .and_then(CborValue::as_map)
    {
        if let Some((_, v)) = claims
            .iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(CWT_CLAIM_IAT as i128))
        {
            if let Some(n) = v.as_integer() {
                result.iat = Some(i128::from(n) as i64);
            }
        }
    }
    if let Some(g) = find_label(&prot, HDR_GRADE)
        .as_ref()
        .and_then(CborValue::as_text)
    {
        result.grade = Some(g.to_string());
    }

    if vds != VDS_RFC9162_SHA256 as i128 {
        return result.fail(
            "unsupported verifiable data structure (protected label 395); expected RFC9162_SHA256 (vds=1)",
        );
    }

    let vdp = match sign1
        .unprotected
        .rest
        .iter()
        .find(|(label, _)| *label == coset::Label::Int(HDR_VDP))
        .map(|(_, v)| v)
        .and_then(CborValue::as_map)
    {
        Some(m) => m,
        None => return result.fail("unprotected vdp (label 396) missing or not a map"),
    };
    let proofs = match vdp
        .iter()
        .find(|(k, _)| k.as_integer().map(i128::from) == Some(VDP_INCLUSION_PROOFS as i128))
        .map(|(_, v)| v)
        .and_then(CborValue::as_array)
    {
        Some(p) if !p.is_empty() => p,
        _ => return result.fail("vdp has no inclusion proofs (key -1)"),
    };
    if proofs.len() > MAX_INCLUSION_PROOFS {
        return result.fail(format!(
            "too many inclusion proofs ({} > {MAX_INCLUSION_PROOFS})",
            proofs.len()
        ));
    }
    let first_proof = match proofs[0].as_bytes() {
        Some(b) => b,
        None => return result.fail("inclusion proof entry is not a byte string"),
    };

    let (tree_size, leaf_index, audit_path) = match decode_inclusion_proof(first_proof) {
        Ok(v) => v,
        Err(e) => return result.fail(e.to_string()),
    };
    result.tree_size = Some(tree_size);
    result.leaf_index = Some(leaf_index);

    let reconstructed =
        match root_from_inclusion_proof(leaf_entry, leaf_index, tree_size, &audit_path) {
            Some(r) => r,
            None => {
                return result.fail("inclusion proof does not reconstruct a root for this leaf")
            }
        };
    result.root = Some(reconstructed);

    if let Err(e) = verify_signature(&sign1, alg_code, log_public_key_pem, &reconstructed) {
        return result.fail(format!("receipt signature did not verify: {e}"));
    }

    result.ok = true;
    result.witness_time_established = result.iat.is_some();
    result.grade_cryptographically_bound = result.grade.is_some();
    result
}

fn verify_signature(
    sign1: &CoseSign1,
    alg_code: i64,
    public_key_pem: &str,
    detached_payload: &[u8; 32],
) -> Result<(), ReceiptError> {
    if sign1.payload.is_some() {
        return Err(malformed(
            "receipt carries an attached payload; this verifier only accepts the detached form",
        ));
    }
    let tbs = sign1.tbs_detached_data(detached_payload, &[]);
    match alg_code {
        ALG_EDDSA => {
            use ed25519_dalek::pkcs8::DecodePublicKey;
            use ed25519_dalek::Verifier;
            let key = ed25519_dalek::VerifyingKey::from_public_key_pem(public_key_pem)
                .map_err(|e| malformed(format!("could not load EdDSA public key: {e}")))?;
            let sig_bytes: [u8; 64] = sign1
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| malformed("EdDSA signature must be 64 raw bytes"))?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            key.verify(&tbs, &sig)
                .map_err(|_| malformed("signature verification FAILED"))
        }
        ALG_ES256 => {
            use p256::pkcs8::DecodePublicKey;
            let key = p256::ecdsa::VerifyingKey::from_public_key_pem(public_key_pem)
                .map_err(|e| malformed(format!("could not load ES256 public key: {e}")))?;
            if sign1.signature.len() != 64 {
                return Err(malformed(format!(
                    "ES256 COSE signature must be 64 raw bytes (r||s), got {}",
                    sign1.signature.len()
                )));
            }
            let sig = p256::ecdsa::Signature::from_slice(&sign1.signature)
                .map_err(|e| malformed(format!("malformed ES256 signature: {e}")))?;
            key.verify(&tbs, &sig)
                .map_err(|_| malformed("signature verification FAILED"))
        }
        other => Err(malformed(format!(
            "unsupported alg code point {other} for verification"
        ))),
    }
}
