// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Action State Group, Inc.

// Command scitt-cose-go-verify is an INDEPENDENT, non-Python second opinion on
// GENERIC SCITT/COSE artifacts: a COSE_Sign1 Signed Statement and an RFC 9162
// COSE Receipt. It is deliberately PROFILE-OPAQUE — it knows nothing about any
// application profile (no agent-action-profile awareness). It verifies the
// COSE/SCITT envelope and the receipt's cryptographic claims, and treats the
// statement payload as opaque bytes.
//
// It uses veraison/go-cose (the established Go COSE library) to verify
// signatures and reads the CWT_Claims (RFC 9597, protected header label 15)
// directly from the protected bstr with fxamacker/cbor. The Merkle inclusion
// proof is reconstructed clean-room (RFC 6962 / RFC 9162 §2.1.1) so the receipt
// is verified WITHOUT trusting the log operator.
//
// The point is cross-language conformance: if our bytes verify under a clean Go
// COSE/Merkle implementation, we are guarded against the "self-consistent but
// wrong" class of bug (e.g. a CWT_Claims label mis-enum on the Python side —
// the python-cwt CWT_CLAIMS == 13 bug, where the conformant label is 15).
//
// Draft-tracking: the receipt structure follows the SCITT / COSE-Receipts
// documents, which are Active Internet-Drafts (Work in Progress) in the RFC
// Editor Queue, NOT yet published RFCs. There is no "RFC 9942".
package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// COSE protected-header labels (IANA COSE Header Parameters registry).
const (
	hdrAlg         = 1  // RFC 9052 §3.1
	hdrContentType = 3  // RFC 9052 §3.1
	hdrKID         = 4  // RFC 9052 §3.1
	hdrCWTClaims   = 15 // RFC 9597 "CWT Claims" (NOT 13 / kcwt)
)

// COSE algorithm code points (RFC 9053).
const (
	algEdDSA = -8
	algES256 = -7
)

// CWT claim labels (RFC 8392 / IANA CWT Claims registry).
const (
	cwtISS = 1 // issuer
	cwtSUB = 2 // subject
)

// Receipt (draft-ietf-cose-merkle-tree-proofs) labels.
const (
	hdrVDS            = 395 // verifiable-data-structure (protected)
	hdrVDP            = 396 // verifiable-data-proofs (unprotected)
	vdsRFC9162SHA256  = 1   // RFC 9162 SHA-256 Merkle tree
	vdpInclusionProof = -1  // inclusion-proofs array key
)

// receiptOut is the receipt sub-result.
type receiptOut struct {
	Ok        bool   `json:"ok"`
	Root      string `json:"root,omitempty"`
	TreeSize  int64  `json:"tree_size"`
	LeafIndex int64  `json:"leaf_index"`
	Error     string `json:"error,omitempty"`
}

// result is the JSON shape printed to stdout. It is PROFILE-OPAQUE: only generic
// SCITT/COSE/CWT fields are surfaced. Any application-profile claims are exposed
// verbatim in StringClaims with no interpretation.
type result struct {
	Valid       bool   `json:"valid"`
	Alg         string `json:"alg"`
	ContentType string `json:"content_type"`
	Kid         string `json:"kid,omitempty"`
	Iss         string `json:"iss"`
	Sub         string `json:"sub"`
	// StringClaims surfaces every string-keyed CWT claim with a string value,
	// verbatim. This keeps the verifier profile-opaque while letting callers
	// read whatever private/profile claims a statement carries.
	StringClaims map[string]string `json:"string_claims,omitempty"`
	Receipt      *receiptOut       `json:"receipt,omitempty"`
	Error        string            `json:"error,omitempty"`
}

func emit(r result) {
	b, _ := json.Marshal(r)
	fmt.Println(string(b))
}

// fail prints an invalid result and exits non-zero.
func fail(format string, args ...any) {
	emit(result{Valid: false, Error: fmt.Sprintf(format, args...)})
	os.Exit(1)
}

func main() {
	statementPath := flag.String("statement", "", "path to COSE_Sign1 SCITT Signed Statement (CBOR bytes)")
	pubkeyPath := flag.String("pubkey", "", "path to PEM SubjectPublicKeyInfo public key for the statement")
	algName := flag.String("alg", "EdDSA", "signature algorithm: EdDSA | ES256")
	receiptPath := flag.String("receipt", "", "path to a COSE Receipt (CBOR bytes); optional")
	logPubkeyPath := flag.String("log-pubkey", "", "path to PEM public key of the transparency log (with --receipt)")
	leafEntryHex := flag.String("leaf-entry-hex", "", "hex of the leaf entry the receipt proves (with --receipt)")
	flag.Parse()

	if *statementPath == "" && *receiptPath == "" {
		fail("usage: scitt-cose-go-verify --statement <file> --pubkey <pem> [--alg EdDSA|ES256] " +
			"[--receipt <file> --log-pubkey <pem> --leaf-entry-hex <hex>]")
	}

	out := result{Valid: true, Alg: *algName}

	// --- Statement verification (optional). ---
	if *statementPath != "" {
		if *pubkeyPath == "" {
			fail("--statement requires --pubkey")
		}
		verifyStatement(&out, *statementPath, *pubkeyPath, *algName)
	}

	// --- Receipt verification (optional). ---
	if *receiptPath != "" {
		if *logPubkeyPath == "" || *leafEntryHex == "" {
			fail("--receipt requires --log-pubkey and --leaf-entry-hex")
		}
		out.Receipt = verifyReceipt(*receiptPath, *logPubkeyPath, *leafEntryHex)
		if !out.Receipt.Ok {
			out.Valid = false
		}
	}

	emit(out)
	if !out.Valid {
		os.Exit(1)
	}
}

// verifyStatement verifies a COSE_Sign1 Signed Statement signature and extracts
// the generic (profile-opaque) header + CWT claim fields.
func verifyStatement(out *result, statementPath, pubkeyPath, algName string) {
	data, err := os.ReadFile(statementPath)
	if err != nil {
		fail("read statement: %v", err)
	}
	pub := loadPublicKey(pubkeyPath)

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		fail("decode COSE_Sign1: %v", err)
	}

	verifier := newVerifier(algName, pub)
	verr := msg.Verify(nil, verifier)
	out.Valid = verr == nil
	if verr != nil {
		out.Error = fmt.Sprintf("signature verification failed: %v", verr)
	}

	prot := rawProtectedMap(msg.Headers.RawProtected)
	if ct, ok := stringAt(prot, hdrContentType); ok {
		out.ContentType = ct
	}
	if kid, ok := mapGet(prot, hdrKID); ok {
		if b, ok := kid.([]byte); ok {
			out.Kid = hex.EncodeToString(b)
		}
	}
	if claims := claimsMap(prot); claims != nil {
		out.Iss = stringClaim(claims, cwtISS)
		out.Sub = stringClaim(claims, cwtSUB)
		out.StringClaims = stringKeyedClaims(claims)
	}
}

// verifyReceipt verifies an RFC 9162 COSE Receipt WITHOUT trusting the log:
// it reconstructs the Merkle root from the leaf + inclusion proof (clean-room),
// then checks the log's COSE_Sign1 over that reconstructed root.
func verifyReceipt(receiptPath, logPubkeyPath, leafEntryHex string) *receiptOut {
	r := &receiptOut{}
	data, err := os.ReadFile(receiptPath)
	if err != nil {
		r.Error = fmt.Sprintf("read receipt: %v", err)
		return r
	}
	logPub := loadPublicKey(logPubkeyPath)

	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		r.Error = fmt.Sprintf("decode receipt COSE_Sign1: %v", err)
		return r
	}

	prot := rawProtectedMap(msg.Headers.RawProtected)

	// vds MUST come from the protected (integrity-protected) header.
	vds, ok := intAt(prot, hdrVDS)
	if !ok || vds != vdsRFC9162SHA256 {
		r.Error = fmt.Sprintf("protected vds (label 395) is %v; expected %d (RFC9162_SHA256)", vds, vdsRFC9162SHA256)
		return r
	}
	algCode, ok := intAt(prot, hdrAlg)
	if !ok {
		r.Error = "receipt protected header missing alg (label 1)"
		return r
	}
	algName, err := algNameFromCode(algCode)
	if err != nil {
		r.Error = err.Error()
		return r
	}

	// Decode the inclusion proof from the unprotected vdp map.
	unprot := rawAnyMap(msg.Headers.RawUnprotected)
	vdpAny, ok := mapGet(unprot, hdrVDP)
	if !ok {
		r.Error = "unprotected vdp (label 396) missing"
		return r
	}
	vdp, ok := vdpAny.(map[any]any)
	if !ok {
		r.Error = "unprotected vdp (label 396) is not a map"
		return r
	}
	proofsAny, ok := mapGet(vdp, vdpInclusionProof)
	if !ok {
		r.Error = "vdp has no inclusion proofs (key -1)"
		return r
	}
	proofs, ok := proofsAny.([]any)
	if !ok || len(proofs) == 0 {
		r.Error = "vdp inclusion proofs is not a non-empty array"
		return r
	}
	proofBlob, ok := proofs[0].([]byte)
	if !ok {
		r.Error = "inclusion proof entry is not a bstr"
		return r
	}

	treeSize, leafIndex, auditPath, err := decodeInclusionProof(proofBlob)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.TreeSize = treeSize
	r.LeafIndex = leafIndex

	leafBytes, err := hex.DecodeString(leafEntryHex)
	if err != nil {
		r.Error = fmt.Sprintf("leaf-entry-hex is not hex: %v", err)
		return r
	}
	root, ok := rootFromInclusionProof(leafBytes, leafIndex, treeSize, auditPath)
	if !ok {
		r.Error = "inclusion proof does not reconstruct a root for this leaf"
		return r
	}
	r.Root = hex.EncodeToString(root)

	// Verify the log's COSE_Sign1 over the reconstructed (detached) root.
	msg.Payload = root
	verifier := newVerifier(algName, logPub)
	if err := msg.Verify(nil, verifier); err != nil {
		r.Error = fmt.Sprintf("receipt signature did not verify over reconstructed root: %v", err)
		return r
	}

	r.Ok = true
	return r
}

// --- Merkle (clean-room RFC 6962 §2.1.1) ------------------------------------

func leafHash(entry []byte) []byte {
	h := sha256.Sum256(append([]byte{0x00}, entry...))
	return h[:]
}

func nodeHash(left, right []byte) []byte {
	in := append([]byte{0x01}, left...)
	in = append(in, right...)
	h := sha256.Sum256(in)
	return h[:]
}

// maxTreeSize bounds an attacker-supplied tree_size. 2^62 is the largest power
// of two representable as a positive int64, so it is the EXACT same ceiling the
// Python verifier uses (MAX_TREE_SIZE) — the two agree on accept/reject for
// every tree_size, with no band one accepts and the other cannot represent. It
// also keeps every interim value (k, k*2) within int64. A proof claiming more is
// rejected before the Merkle fold runs.
const maxTreeSize int64 = 1 << 62

func largestPow2Below(n int64) int64 {
	// Overflow-safe for any int64: the loop guard `k <= (n-1)/2` is equivalent to
	// `k*2 < n` but never overflows (k stays <= 2^62 so the multiply below is in
	// range). Callers also bound tree_size to maxTreeSize, but this primitive is
	// self-protecting so no caller can spin it into the old int64-overflow hang.
	if n <= 1 {
		return 1
	}
	k := int64(1)
	for k <= (n-1)/2 {
		k *= 2
	}
	return k
}

// expectedInclusionPathLen is the exact number of audit-path siblings for index
// in an RFC 6962 tree of treeSize entries (the leaf's depth under the split).
func expectedInclusionPathLen(treeSize, index int64) int64 {
	var n int64
	size, m := treeSize, index
	for size > 1 {
		k := largestPow2Below(size)
		if m < k {
			size = k
		} else {
			size, m = size-k, m-k
		}
		n++
	}
	return n
}

// rootFromInclusionProof folds a leaf up its audit path to the root (RFC 6962
// §2.1.1). The audit path is consumed outermost-first, mirroring the Python
// reference (siblings.pop()).
func rootFromInclusionProof(leafEntry []byte, index, treeSize int64, auditPath [][]byte) ([]byte, bool) {
	// Bound tree_size and require the path to be exactly the expected length
	// BEFORE any hashing: a hostile tree_size near 2^63 otherwise overflows
	// largestPow2Below into an infinite loop, and an over-long path drives
	// unbounded recursion. Same checks (and ceiling) as the Python verifier.
	if index < 0 || index >= treeSize || treeSize > maxTreeSize {
		return nil, false
	}
	if int64(len(auditPath)) != expectedInclusionPathLen(treeSize, index) {
		return nil, false
	}
	target := leafHash(leafEntry)
	siblings := make([][]byte, len(auditPath))
	copy(siblings, auditPath)

	var fold func(size, m int64) ([]byte, bool)
	fold = func(size, m int64) ([]byte, bool) {
		if size == 1 {
			return target, true
		}
		if len(siblings) == 0 {
			return nil, false
		}
		k := largestPow2Below(size)
		sibling := siblings[len(siblings)-1] // outermost sibling at this level
		siblings = siblings[:len(siblings)-1]
		if m < k {
			child, ok := fold(k, m)
			if !ok {
				return nil, false
			}
			return nodeHash(child, sibling), true
		}
		child, ok := fold(size-k, m-k)
		if !ok {
			return nil, false
		}
		return nodeHash(sibling, child), true
	}

	computed, ok := fold(treeSize, index)
	if !ok || len(siblings) != 0 {
		return nil, false
	}
	return computed, true
}

// decodeInclusionProof decodes cbor([tree_size, leaf_index, [audit_path bstrs]]).
func decodeInclusionProof(blob []byte) (int64, int64, [][]byte, error) {
	var arr []cbor.RawMessage
	if err := cbor.Unmarshal(blob, &arr); err != nil || len(arr) != 3 {
		return 0, 0, nil, fmt.Errorf("inclusion proof must be [tree_size, leaf_index, [path]]")
	}
	var treeSize, leafIndex int64
	if err := cbor.Unmarshal(arr[0], &treeSize); err != nil {
		return 0, 0, nil, fmt.Errorf("inclusion proof tree_size not an int: %v", err)
	}
	if err := cbor.Unmarshal(arr[1], &leafIndex); err != nil {
		return 0, 0, nil, fmt.Errorf("inclusion proof leaf_index not an int: %v", err)
	}
	var path [][]byte
	if err := cbor.Unmarshal(arr[2], &path); err != nil {
		return 0, 0, nil, fmt.Errorf("inclusion proof path not an array of bstr: %v", err)
	}
	return treeSize, leafIndex, path, nil
}

// --- Keys, verifiers, header decoding ---------------------------------------

func loadPublicKey(path string) any {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		fail("read pubkey %s: %v", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		fail("pubkey %s: no PEM block found", path)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fail("parse public key %s: %v", path, err)
	}
	return pub
}

func newVerifier(algName string, pub any) cose.Verifier {
	var coseAlg cose.Algorithm
	switch algName {
	case "EdDSA":
		coseAlg = cose.AlgorithmEdDSA
		if _, ok := pub.(ed25519.PublicKey); !ok {
			fail("alg EdDSA requires an ed25519 public key, got %T", pub)
		}
	case "ES256":
		coseAlg = cose.AlgorithmES256
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			fail("alg ES256 requires an *ecdsa.PublicKey, got %T", pub)
		}
	default:
		fail("unknown alg %q (want EdDSA or ES256)", algName)
	}
	verifier, err := cose.NewVerifier(coseAlg, pub)
	if err != nil {
		fail("new verifier: %v", err)
	}
	return verifier
}

func algNameFromCode(code int64) (string, error) {
	switch code {
	case algEdDSA:
		return "EdDSA", nil
	case algES256:
		return "ES256", nil
	default:
		return "", fmt.Errorf("unsupported alg code point %d (want -8 EdDSA or -7 ES256)", code)
	}
}

// rawProtectedMap decodes go-cose's RawProtected (a bstr wrapping the encoded
// protected map) into a generic CBOR map.
func rawProtectedMap(rawProtected cbor.RawMessage) map[any]any {
	if len(rawProtected) == 0 {
		return nil
	}
	var inner []byte
	if err := cbor.Unmarshal(rawProtected, &inner); err != nil {
		// Fallback: maybe it's already the bare map (older/edge encodings).
		return rawAnyMap(rawProtected)
	}
	return rawAnyMap(inner)
}

// rawAnyMap decodes a CBOR map (not bstr-wrapped) into map[any]any.
func rawAnyMap(raw cbor.RawMessage) map[any]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[any]any
	if err := cbor.Unmarshal(raw, &m); err != nil {
		return nil
	}
	return m
}

// mapGet looks up a label that may have been decoded as int64/uint64/int.
func mapGet(m map[any]any, label int64) (any, bool) {
	if m == nil {
		return nil, false
	}
	for _, k := range []any{label, uint64(label), int(label)} {
		if v, ok := m[k]; ok {
			return v, true
		}
	}
	return nil, false
}

func stringAt(m map[any]any, label int64) (string, bool) {
	if v, ok := mapGet(m, label); ok {
		if s, ok := v.(string); ok {
			return s, true
		}
	}
	return "", false
}

func intAt(m map[any]any, label int64) (int64, bool) {
	v, ok := mapGet(m, label)
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case int:
		return int64(n), true
	}
	return 0, false
}

func claimsMap(prot map[any]any) map[any]any {
	v, ok := mapGet(prot, hdrCWTClaims)
	if !ok {
		return nil
	}
	claims, ok := v.(map[any]any)
	if !ok {
		return nil
	}
	return claims
}

// stringClaim reads a string CWT claim by integer label.
func stringClaim(claims map[any]any, label int64) string {
	if v, ok := mapGet(claims, label); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// stringKeyedClaims returns every string-keyed claim with a string value,
// verbatim. This is the profile-opaque escape hatch: a consumer can read any
// private/profile claim without this verifier interpreting it.
func stringKeyedClaims(claims map[any]any) map[string]string {
	out := map[string]string{}
	for k, v := range claims {
		ks, ok := k.(string)
		if !ok {
			continue
		}
		if vs, ok := v.(string); ok {
			out[ks] = vs
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
