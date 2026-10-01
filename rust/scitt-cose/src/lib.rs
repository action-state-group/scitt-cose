//! Offline verifier for SCITT COSE Receipts that carry an RFC 9162 SHA-256
//! inclusion proof.
//!
//! [`verify_receipt`] checks a receipt's COSE_Sign1 signature under a pinned
//! log public key (EdDSA or ES256), rebuilds the Merkle root from the
//! inclusion proof for a caller-supplied leaf entry, and reports the
//! protected `iat` and `grade` labels only when the signature covers them.
//! It makes no network calls and never issues receipts.
//!
//! ```no_run
//! let receipt = std::fs::read("receipt.cose").unwrap();
//! let log_key_pem = std::fs::read_to_string("log.pem").unwrap();
//! let result = scitt_cose_receipt::verify_receipt(&receipt, &[0x02], &log_key_pem);
//! if result.ok {
//!     println!("verified, tree size {:?}", result.tree_size);
//! }
//! ```

pub mod merkle;
pub mod receipt;

pub use receipt::{verify_receipt, ReceiptError, ReceiptResult};
