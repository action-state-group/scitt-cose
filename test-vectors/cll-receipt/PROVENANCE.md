<!-- SPDX-License-Identifier: Apache-2.0 -->
# cll-receipt test vectors — provenance

`receipt-vectors.json` is a byte-for-byte copy of
checkpointed-local-log's `checkpoint-conformance-vectors/receipt-vectors.json`
at commit `b9b2054821ae687744b3a993864c36dc13b25634`
(action-state-group/checkpointed-local-log#126), generated there by
`generate_receipts.py`. Its digest is pinned in `../SHA256SUMS`.

Each case is a witness receipt over one checkpoint statement. A receipt
verifier pinned to `authority_public_key_hex` and given `entry_hash_hex` as
the leaf entry accepts exactly the cases whose `accept` is true, reporting
their `tree_size` and `leaf_index`. agent-action-capsule's
`VerifyCOSEReceipt` decides every case that way under the receipt encoding
rule of its interop profile v1 §6.2.2 (action-state-group/agent-action-capsule#523),
and so do scitt-cose's Python, Rust and Go receipt verifiers
(action-state-group/scitt-cose#106).

Refresh it by copying the file again from checkpointed-local-log, updating
the commit above and the digest in `../SHA256SUMS`; never edit it here.
