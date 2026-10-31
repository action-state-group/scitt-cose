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

use ciborium::value::Value as CborValue;
use ecdsa::signature::Verifier as _;

use crate::encoding;
use crate::merkle::{expected_inclusion_path_len, root_from_inclusion_proof, MAX_TREE_SIZE};

/// Protected-header labels for alg and crit (RFC 9052 §3.1).
const HDR_ALG: i64 = 1;
const HDR_CRIT: i64 = 2;

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

/// The receipt encoding rule's octet limit, the Python package's
/// `MAX_MESSAGE_BYTES`.
pub const MAX_RECEIPT_OCTETS: usize = 10 * 1024 * 1024;

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

/// The step a failed [`verify_receipt`] stopped at (scitt-cose#93). Match
/// on [`FailedAt::Signature`] rather than [`FailedAt::Structure`]: the type
/// is non-exhaustive so that a finer split of the earlier steps stays
/// compatible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailedAt {
    /// The receipt failed before the signature step: it is not a usable
    /// COSE_Sign1 receipt, or no inclusion proof rebuilds a root for this
    /// leaf.
    Structure,
    /// A proof rebuilt a root for this leaf and the signature step failed
    /// under every proof: a wrong key, an alg/key mismatch, an unsupported
    /// alg or a bad signature. Never evidence of anything.
    Signature,
}

impl FailedAt {
    /// The wire name shared with the Python and Go verifiers.
    pub fn as_str(self) -> &'static str {
        match self {
            FailedAt::Structure => "structure",
            FailedAt::Signature => "signature",
        }
    }
}

/// Outcome of [`verify_receipt`]. `ok` is `true` only when the inclusion
/// proof reconstructs a root *and* the COSE_Sign1 over that root verifies
/// under the supplied log key. On any failure `ok` is `false` and `errors`
/// explains why. When `ok` is `true`, `root`/`tree_size`/`leaf_index` come
/// from the inclusion proof the signature verified under. When every proof is
/// well-formed but the signature step fails under each of them (a wrong key,
/// an alg/key mismatch, a bad signature), they are a diagnostic from the
/// first proof: the receipt is shaped right for this leaf, but the values are
/// unauthenticated (the proof sits in the unprotected header) and are never a
/// log root, size or position. On any earlier failure they stay `None`. The
/// Python and Go verifiers report the same. The
/// protected-header claims (`iat`, `grade`) are likewise populated ONLY when
/// `ok` is `true` -- a claim from a receipt that failed verification is never
/// surfaced (same rule as the Python `ReceiptResult`). `failed_at` names the
/// step a failure stopped at and is `None` when `ok` is `true`; read it, not
/// whether `root` is set, to tell a malformed receipt from one signed by a
/// key the caller does not hold.
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
    /// The step a failed verify stopped at; `None` when `ok` is `true`.
    pub failed_at: Option<FailedAt>,
}

impl ReceiptResult {
    fn fail(mut self, msg: impl Into<String>) -> Self {
        self.ok = false;
        self.iat = None;
        self.grade = None;
        self.witness_time_established = false;
        self.grade_cryptographically_bound = false;
        self.failed_at.get_or_insert(FailedAt::Structure);
        self.errors.push(msg.into());
        self
    }
}

fn decode_inclusion_proof(blob: &[u8]) -> Result<(u64, u64, Vec<[u8; 32]>), ReceiptError> {
    let mut reader = blob;
    let value: CborValue = ciborium::de::from_reader(&mut reader)
        .map_err(|e| malformed(format!("inclusion proof is not valid CBOR: {e:?}")))?;
    if !reader.is_empty() {
        return Err(malformed("inclusion proof has trailing CBOR bytes"));
    }
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
    if tree_size == 0 || tree_size > MAX_TREE_SIZE || leaf_index >= tree_size {
        return Err(malformed("invalid tree size or leaf index"));
    }
    if path.len() as u64 != expected_inclusion_path_len(tree_size, leaf_index) {
        return Err(malformed(
            "inclusion proof path length does not match tree size and leaf index",
        ));
    }
    Ok((tree_size, leaf_index, path))
}

/// Whether the payload item of a tagged COSE_Sign1 is CBOR null (`0xf6`),
/// the only detached form. Skips the tag and array heads, lets ciborium
/// consume the protected and unprotected items, and reads the next byte.
/// ciborium reads CBOR undefined (0xf7) as null too, so only the raw slot
/// tells them apart (scitt-cose#104).
fn payload_slot_is_null(receipt: &[u8]) -> bool {
    // Length of a tag or array head: the initial byte plus 0, 1, 2, 4 or 8
    // argument bytes (31 is an indefinite-length array with none).
    fn head_len(initial: u8) -> Option<usize> {
        match initial & 31 {
            0..=23 | 31 => Some(1),
            info @ 24..=27 => Some(1 + (1 << (info - 24))),
            _ => None,
        }
    }
    let mut rest = receipt;
    for _ in 0..2 {
        match rest.first().copied().and_then(head_len) {
            Some(n) if n <= rest.len() => rest = &rest[n..],
            _ => return false,
        }
    }
    for _ in 0..2 {
        if ciborium::de::from_reader::<CborValue, _>(&mut rest).is_err() {
            return false;
        }
    }
    rest.first() == Some(&0xf6)
}

/// The four items of a tagged COSE_Sign1.
struct Sign1 {
    protected: Vec<u8>,
    unprotected: Vec<(CborValue, CborValue)>,
    payload: CborValue,
    signature: Vec<u8>,
}

/// Read a tag-18 COSE_Sign1 `[protected bstr, unprotected map, payload,
/// signature bstr]` with nothing after it. Only the item types are checked
/// here; the header labels are read by the caller, so a label this verifier
/// does not read is ignored whatever its value.
fn parse_sign1(receipt: &[u8]) -> Result<Sign1, String> {
    let mut reader = receipt;
    let value: CborValue =
        ciborium::de::from_reader(&mut reader).map_err(|e| format!("not valid CBOR: {e:?}"))?;
    if !reader.is_empty() {
        return Err("trailing bytes after the COSE_Sign1".into());
    }
    let items = match value {
        CborValue::Tag(18, inner) => match *inner {
            CborValue::Array(items) if items.len() == 4 => items,
            _ => return Err("tag 18 does not hold a four-item array".into()),
        },
        _ => return Err("not a tag-18 COSE_Sign1".into()),
    };
    let mut items = items.into_iter();
    let (protected, unprotected, payload, signature) = (
        items.next().unwrap(),
        items.next().unwrap(),
        items.next().unwrap(),
        items.next().unwrap(),
    );
    Ok(Sign1 {
        protected: protected
            .into_bytes()
            .map_err(|_| "protected header is not a byte string")?,
        unprotected: unprotected
            .into_map()
            .map_err(|_| "unprotected header is not a map")?,
        payload,
        signature: signature
            .into_bytes()
            .map_err(|_| "signature is not a byte string")?,
    })
}

/// Protected-header labels this verifier processes, for RFC 9052 §3.1 `crit`:
/// alg (1), crit (2) itself, CWT_Claims (15) and vds (395). The Python
/// verifier's RFC 9162 set is the same.
const UNDERSTOOD_LABELS: [i64; 4] = [HDR_ALG, HDR_CRIT, HDR_CWT_CLAIMS, HDR_VDS];

/// RFC 9052 §3.1: a protected `crit` is a non-empty array of integer or text
/// labels, each present in the protected header and understood here.
fn check_crit(protected: &[(CborValue, CborValue)]) -> Result<(), String> {
    let Some(crit) = find_label(protected, HDR_CRIT) else {
        return Ok(());
    };
    let labels = match crit.as_array() {
        Some(labels) if !labels.is_empty() => labels,
        _ => return Err("crit (label 2) must be a non-empty array (RFC 9052 §3.1)".into()),
    };
    for label in labels {
        if !label.is_integer() && !label.is_text() {
            return Err("crit lists a label that is not an integer or a text string".into());
        }
        if !protected.iter().any(|(k, _)| k == label) {
            return Err("crit lists a header absent from the protected header".into());
        }
        let understood = label
            .as_integer()
            .and_then(|n| i64::try_from(n).ok())
            .is_some_and(|n| UNDERSTOOD_LABELS.contains(&n));
        if !understood {
            return Err(
                "crit marks a header this verifier does not understand (RFC 9052 §3.1)".into(),
            );
        }
    }
    Ok(())
}

/// The value under integer `label` in a decoded CBOR map.
fn find_label(map: &[(CborValue, CborValue)], label: i64) -> Option<&CborValue> {
    map.iter()
        .find(|(k, _)| k.as_integer() == Some(label.into()))
        .map(|(_, v)| v)
}

/// Finding added when the signature fails: the protected-header claims are
/// withheld because nothing in an unverified header may be surfaced. Same
/// text as the Python verifier's, so callers can match either.
const CLAIMS_WITHHELD: &str =
    "protected header claims withheld (iat/iss/sub/protected_header_ext): receipt signature did not verify";

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

    if receipt.is_empty() || receipt.len() > MAX_RECEIPT_OCTETS {
        return result.fail(format!(
            "receipt size is not 1 to {MAX_RECEIPT_OCTETS} octets"
        ));
    }
    let sign1 = match parse_sign1(receipt) {
        Ok(s) => s,
        Err(e) => return result.fail(format!("receipt is not a COSE_Sign1 message: {e}")),
    };

    // The signature must cover the root rebuilt from the leaf, so the payload
    // is detached; an attached one is refused before any proof is read.
    if !sign1.payload.is_null() || !payload_slot_is_null(receipt) {
        return result.fail(
            "receipt carries an attached payload; this verifier only accepts the detached form",
        );
    }

    // The receipt encoding rule then decides the octets, so this verifier
    // accepts exactly what every verifier that applies the rule accepts. It
    // runs before any header or proof is read; the checks above only name the
    // more specific failure for a receipt it also refuses.
    if let Err(e) = encoding::check(receipt, "the receipt", true) {
        return result.fail(format!("receipt rejected: {e}"));
    }
    let prot = if sign1.protected.is_empty() {
        Vec::new()
    } else {
        if let Err(e) = encoding::check(&sign1.protected, "the protected header", false) {
            return result.fail(format!("receipt rejected: {e}"));
        }
        match ciborium::de::from_reader::<CborValue, _>(sign1.protected.as_slice())
            .ok()
            .and_then(|v| v.into_map().ok())
        {
            Some(m) => m,
            None => return result.fail("protected header is not a map"),
        }
    };
    if let Err(e) = check_crit(&prot) {
        return result.fail(e);
    }

    // vds MUST come from the protected (integrity-protected) header.
    let vds = match find_label(&prot, HDR_VDS).and_then(CborValue::as_integer) {
        Some(v) => i128::from(v),
        None => return result.fail("protected header missing vds (label 395)"),
    };

    let alg_code = match find_label(&prot, HDR_ALG) {
        None => return result.fail("protected header missing alg (label 1)"),
        Some(v) => match v.as_integer().and_then(|n| i64::try_from(n).ok()) {
            Some(code) => code,
            None => return result.fail("protected header alg is not an integer code point"),
        },
    };

    // Read iat/grade from the PROTECTED header into locals; they are copied
    // onto the result only after the signature verifies (never on failure).
    let mut iat: Option<i64> = None;
    let mut grade: Option<String> = None;
    if let Some(claims) = find_label(&prot, HDR_CWT_CLAIMS).and_then(CborValue::as_map) {
        if let Some(n) = find_label(claims, CWT_CLAIM_IAT).and_then(CborValue::as_integer) {
            // An iat beyond i64 is not reported rather than truncated.
            iat = i64::try_from(n).ok();
        }
    }
    if let Some(g) = find_label(&prot, HDR_GRADE).and_then(CborValue::as_text) {
        grade = Some(g.to_string());
    }

    if vds != VDS_RFC9162_SHA256 as i128 {
        return result.fail(
            "unsupported verifiable data structure (protected label 395); expected RFC9162_SHA256 (vds=1)",
        );
    }

    let vdp = match find_label(&sign1.unprotected, HDR_VDP).and_then(CborValue::as_map) {
        Some(m) => m,
        None => return result.fail("unprotected vdp (label 396) missing or not a map"),
    };
    let proofs = match find_label(vdp, VDP_INCLUSION_PROOFS).and_then(CborValue::as_array) {
        Some(p) if !p.is_empty() => p,
        _ => return result.fail("vdp has no inclusion proofs (key -1)"),
    };
    if proofs.len() > MAX_INCLUSION_PROOFS {
        return result.fail(format!(
            "too many inclusion proofs ({} > {MAX_INCLUSION_PROOFS})",
            proofs.len()
        ));
    }
    // Proof order is unprotected. Validate every entry before selecting a
    // candidate whose reconstructed root authenticates the caller's leaf.
    let mut candidates = Vec::with_capacity(proofs.len());
    for proof in proofs {
        let blob = match proof.as_bytes() {
            Some(b) => b,
            None => return result.fail("inclusion proof entry is not a byte string"),
        };
        if let Err(e) = encoding::check(blob, "an inclusion proof", false) {
            return result.fail(format!("receipt rejected: {e}"));
        }
        match decode_inclusion_proof(blob) {
            Ok(candidate) => candidates.push(candidate),
            Err(e) => return result.fail(e.to_string()),
        }
    }
    let mut matched = false;
    let mut last_error = None;
    // When no proof's root verifies, the first proof's values stay as a
    // diagnostic (ok stays false): callers tell a malformed receipt from one
    // signed by a key they do not hold by checking `root`.
    let mut diagnostic = None;
    for (tree_size, leaf_index, audit_path) in candidates {
        let reconstructed =
            root_from_inclusion_proof(leaf_entry, leaf_index, tree_size, &audit_path)
                .expect("decoded proof has validated shape");
        if let Err(error) = verify_signature(&sign1, alg_code, log_public_key_pem, &reconstructed) {
            last_error = Some(error);
            diagnostic.get_or_insert((tree_size, leaf_index, reconstructed));
        } else {
            result.tree_size = Some(tree_size);
            result.leaf_index = Some(leaf_index);
            result.root = Some(reconstructed);
            matched = true;
            break;
        }
    }
    if !matched {
        if let Some((tree_size, leaf_index, root)) = diagnostic {
            result.tree_size = Some(tree_size);
            result.leaf_index = Some(leaf_index);
            result.root = Some(root);
            result.failed_at = Some(FailedAt::Signature);
        }
        return result
            .fail(format!(
                "receipt signature did not verify for any inclusion proof: {}",
                last_error.expect("nonempty candidates each produced a signature error")
            ))
            .fail(CLAIMS_WITHHELD);
    }

    result.ok = true;
    result.iat = iat;
    result.grade = grade;
    result.witness_time_established = result.iat.is_some();
    result.grade_cryptographically_bound = result.grade.is_some();
    result
}

fn verify_signature(
    sign1: &Sign1,
    alg_code: i64,
    public_key_pem: &str,
    detached_payload: &[u8; 32],
) -> Result<(), ReceiptError> {
    let tbs = sig_structure(&sign1.protected, detached_payload);
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

/// The `Signature1` Sig_structure over a detached payload with an empty
/// external AAD (RFC 9052 §4.4).
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let value = CborValue::Array(vec![
        CborValue::Text("Signature1".into()),
        CborValue::Bytes(protected.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload.to_vec()),
    ]);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out).expect("writing to a Vec cannot fail");
    out
}

#[cfg(test)]
mod proof_shape_tests {
    use super::*;

    #[test]
    fn impossible_proof_shapes_are_malformed() {
        for (size, index, count) in [
            (0u64, 0u64, 0usize),
            (1, 1, 0),
            (2, 0, 0),
            (1, 0, 1),
            ((1u64 << 62) + 1, 0, 0),
        ] {
            let value = CborValue::Array(vec![
                size.into(),
                index.into(),
                CborValue::Array(vec![CborValue::Bytes(vec![0; 32]); count]),
            ]);
            let mut bytes = Vec::new();
            ciborium::ser::into_writer(&value, &mut bytes).unwrap();
            assert!(matches!(
                decode_inclusion_proof(&bytes),
                Err(ReceiptError::Malformed(_))
            ));
        }
    }

    #[test]
    fn nested_proof_trailing_bytes_are_malformed() {
        assert!(matches!(
            decode_inclusion_proof(&[0x83, 1, 0, 0x80, 0]),
            Err(ReceiptError::Malformed(_))
        ));
    }
}

#[cfg(test)]
mod rule_tests {
    use super::*;
    use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
    use ed25519_dalek::pkcs8::EncodePublicKey;
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};

    fn encode(value: &CborValue) -> Vec<u8> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(value, &mut out).unwrap();
        out
    }

    /// A one-leaf EdDSA receipt over leaf 0xaa with exactly `protected` as
    /// its header and `extra` added to its unprotected header, and the PEM
    /// key it verifies under.
    fn signed(
        protected: Vec<(CborValue, CborValue)>,
        extra: Vec<(CborValue, CborValue)>,
    ) -> (Vec<u8>, String) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let protected = encode(&CborValue::Map(protected));
        let root: [u8; 32] = Sha256::new().chain_update([0x00, 0xaa]).finalize().into();
        let signature = key.sign(&sig_structure(&protected, &root));
        let proof = encode(&CborValue::Array(vec![
            1.into(),
            0.into(),
            CborValue::Array(vec![]),
        ]));
        let mut unprotected = vec![(
            HDR_VDP.into(),
            CborValue::Map(vec![(
                VDP_INCLUSION_PROOFS.into(),
                CborValue::Array(vec![CborValue::Bytes(proof)]),
            )]),
        )];
        unprotected.extend(extra);
        let receipt = encode(&CborValue::Tag(
            18,
            Box::new(CborValue::Array(vec![
                CborValue::Bytes(protected),
                CborValue::Map(unprotected),
                CborValue::Null,
                CborValue::Bytes(signature.to_bytes().to_vec()),
            ])),
        ));
        let pem = key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        (receipt, pem)
    }

    fn eddsa() -> Vec<(CborValue, CborValue)> {
        vec![
            (HDR_ALG.into(), ALG_EDDSA.into()),
            (HDR_VDS.into(), 1.into()),
        ]
    }

    #[test]
    fn a_long_array_under_an_unread_label_is_accepted() {
        let long = CborValue::Array(vec![0.into(); 131_073]);
        let wide = CborValue::Map((0..131_073).map(|i| (i.into(), 0.into())).collect());
        let (receipt, pem) = signed(
            eddsa(),
            vec![((-70000).into(), long), ((-70001).into(), wide)],
        );
        let r = verify_receipt(&receipt, &[0xaa], &pem);
        assert!(r.ok, "{:?}", r.errors);
    }

    #[test]
    fn octet_limit() {
        let padded = |n: usize| {
            signed(
                eddsa(),
                vec![((-70000).into(), CborValue::Bytes(vec![0; n]))],
            )
        };
        let base = padded(70_000).0.len();
        let pad = MAX_RECEIPT_OCTETS - base + 70_000;
        let (receipt, pem) = padded(pad);
        assert_eq!(receipt.len(), MAX_RECEIPT_OCTETS);
        let r = verify_receipt(&receipt, &[0xaa], &pem);
        assert!(r.ok, "{:?}", r.errors);
        let (receipt, pem) = padded(pad + 1);
        let r = verify_receipt(&receipt, &[0xaa], &pem);
        assert!(!r.ok);
        assert_eq!(r.failed_at, Some(FailedAt::Structure));
    }

    #[test]
    fn an_alg_above_int64_is_not_eddsa() {
        let (receipt, pem) = signed(eddsa(), vec![]);
        assert!(verify_receipt(&receipt, &[0xaa], &pem).ok);
        let (receipt, pem) = signed(
            vec![
                (HDR_ALG.into(), (u64::MAX - 7).into()),
                (HDR_VDS.into(), 1.into()),
            ],
            vec![],
        );
        assert!(!verify_receipt(&receipt, &[0xaa], &pem).ok);
    }

    #[test]
    fn an_iat_beyond_i64_is_not_truncated() {
        let mut protected = eddsa();
        protected.push((
            HDR_CWT_CLAIMS.into(),
            CborValue::Map(vec![(CWT_CLAIM_IAT.into(), (1u64 << 63).into())]),
        ));
        let (receipt, pem) = signed(protected, vec![]);
        let r = verify_receipt(&receipt, &[0xaa], &pem);
        assert!(r.ok, "{:?}", r.errors);
        assert_eq!(r.iat, None);
    }

    #[test]
    fn a_bad_crit_fails_before_any_proof_is_read() {
        let mut protected = eddsa();
        protected.push((HDR_CRIT.into(), CborValue::Array(vec![99.into()])));
        protected.push((99.into(), 0.into()));
        let (receipt, pem) = signed(protected, vec![]);
        let r = verify_receipt(&receipt, &[0xaa], &pem);
        assert!(!r.ok);
        assert_eq!(r.failed_at, Some(FailedAt::Structure));
        assert_eq!(r.root, None);
        assert!(
            r.errors.iter().any(|e| e.contains("does not understand")),
            "{:?}",
            r.errors
        );
    }
}
