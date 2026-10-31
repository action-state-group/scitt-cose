// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// checkpointed-local-log's shared receipt vectors: this verifier accepts
// exactly the cases agent-action-capsule's receipt encoding rule accepts
// (scitt-cose#106).
func TestCLLReceiptVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorsRoot, "cll-receipt", "receipt-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		EntryHashHex string `json:"entry_hash_hex"`
		AuthorityKey string `json:"authority_public_key_hex"`
		Cases        []struct {
			Name       string `json:"name"`
			Accept     bool   `json:"accept"`
			TreeSize   int64  `json:"tree_size"`
			LeafIndex  int64  `json:"leaf_index"`
			ReceiptB64 string `json:"receipt_b64"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(vectors.AuthorityKey)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(key))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "log-key.pub")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range vectors.Cases {
		receipt, err := base64.StdEncoding.DecodeString(c.ReceiptB64)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "receipt.cose")
		if err := os.WriteFile(path, receipt, 0o600); err != nil {
			t.Fatal(err)
		}
		r := verifyReceipt(path, keyPath, vectors.EntryHashHex)
		accepted := r.Ok && r.TreeSize == c.TreeSize && r.LeafIndex == c.LeafIndex
		if accepted != c.Accept {
			t.Errorf("%s: accepted %v, want %v (%s)", c.Name, accepted, c.Accept, r.Error)
		}
	}
}

func nest(depth int) []byte {
	return append([]byte(strings.Repeat("\x81", depth)), 0x00)
}

func TestEncodingRuleAccepts(t *testing.T) {
	for name, octets := range map[string][]byte{
		"unsigned 2^64-1":        {0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"negative -2^63":         {0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"false, true, null":      {0x83, 0xf4, 0xf5, 0xf6},
		"keys out of order":      {0xa2, 0x61, 'a', 0x01, 0x01, 0x02},
		"valid UTF-8":            {0x62, 0xc3, 0xa9},
		"item 16 levels deep":    nest(16),
		"empty array and map":    {0x82, 0x80, 0xa0},
		"tag 18 on the top item": {0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40},
	} {
		outer := name == "tag 18 on the top item"
		if err := checkEncoding(octets, "item", outer); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEncodingRuleRefuses(t *testing.T) {
	for _, c := range []struct {
		name   string
		octets []byte
		want   string
	}{
		{"indefinite array", []byte{0x9f, 0x00, 0xff}, "indefinite"},
		{"indefinite bytes", []byte{0x5f, 0x41, 0x00, 0xff}, "indefinite"},
		{"non-shortest integer", []byte{0x18, 0x17}, "shortest"},
		{"non-shortest length", []byte{0x59, 0x00, 0x01, 0x00}, "shortest"},
		{"non-shortest 8-octet", []byte{0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, "shortest"},
		{"below -2^63", []byte{0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0}, "below -2^63"},
		{"repeated key", []byte{0xa2, 0x01, 0x00, 0x01, 0x00}, "repeated"},
		{"bytes key", []byte{0xa1, 0x41, 0x00, 0x00}, "map key"},
		{"array key", []byte{0xa1, 0x80, 0x00}, "map key"},
		{"float key", []byte{0xa1, 0xf9, 0x7e, 0x00, 0x00}, "map key"},
		{"invalid UTF-8", []byte{0x61, 0xff}, "UTF-8"},
		{"half float", []byte{0xf9, 0x3c, 0x00}, "float"},
		{"double", []byte{0xfb, 0, 0, 0, 0, 0, 0, 0, 0}, "float"},
		{"undefined", []byte{0xf7}, "simple value"},
		{"simple 0", []byte{0xe0}, "simple value"},
		{"one-octet simple", []byte{0xf8, 0x20}, "simple value"},
		{"tag", []byte{0xc1, 0x00}, "tag"},
		{"bignum", []byte{0xc2, 0x41, 0x01}, "tag"},
		{"reserved info", []byte{0x1c}, "reserved"},
		{"17 levels deep", nest(17), "16 levels"},
		{"trailing", []byte{0x00, 0x00}, "trailing"},
		{"truncated", []byte{0x82, 0x00}, "truncated"},
		{"length past the end", []byte{0x5a, 0xff, 0xff, 0xff, 0xff}, "truncated"},
		{"nothing", []byte{}, "truncated"},
		{"tag 18 not on top", []byte{0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40}, "tag"},
	} {
		err := checkEncoding(c.octets, "item", false)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want %q", c.name, err, c.want)
		}
	}
	if err := checkEncoding([]byte{0xd1, 0x84, 0x40, 0xa0, 0xf6, 0x40}, "item", true); err == nil {
		t.Error("tag 17 on the top item accepted")
	}
	if err := checkEncoding([]byte{0x81, 0xd2, 0x84, 0x40, 0xa0, 0xf6, 0x40}, "item", true); err == nil {
		t.Error("nested tag 18 accepted")
	}
}

// withUnprotected writes the receipt-v1 synthetic-eddsa-iat-grade receipt with
// labels added to its unsigned header, so its signature still verifies, and
// returns the receipt and key paths.
func withUnprotected(t *testing.T, extra map[int64]any) (string, string, int) {
	t.Helper()
	dir := filepath.Join(vectorsRoot, "receipt-v1", "synthetic-eddsa-iat-grade")
	data, err := os.ReadFile(filepath.Join(dir, "receipt.cose"))
	if err != nil {
		t.Fatal(err)
	}
	var tagged cbor.Tag
	if err := cbor.Unmarshal(data, &tagged); err != nil {
		t.Fatal(err)
	}
	items := tagged.Content.([]any)
	unprot := items[1].(map[any]any)
	for k, v := range extra {
		unprot[k] = v
	}
	out, err := cbor.Marshal(cbor.Tag{Number: 18, Content: items})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt.cose")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, filepath.Join(dir, "log-key.pub"), len(out)
}

// The rule limits no array or map other than by the octet limit, so
// fxamacker's default cap of 131,072 must not decide it.
func TestLongArrayUnderUnreadLabelAccepted(t *testing.T) {
	long := make([]any, 131073)
	for i := range long {
		long[i] = 0
	}
	wide := make(map[int64]any, 131073)
	for i := int64(0); i < 131073; i++ {
		wide[i] = 0
	}
	path, key, _ := withUnprotected(t, map[int64]any{-70000: long, -70001: wide})
	if r := verifyReceipt(path, key, "02"); !r.Ok {
		t.Fatalf("long array refused: %+v", r)
	}
}

func TestOctetLimit(t *testing.T) {
	_, _, base := withUnprotected(t, map[int64]any{-70000: make([]byte, 70000)})
	pad := maxReceiptOctets - base + 70000
	path, key, n := withUnprotected(t, map[int64]any{-70000: make([]byte, pad)})
	if n != maxReceiptOctets {
		t.Fatalf("padded receipt is %d octets", n)
	}
	if r := verifyReceipt(path, key, "02"); !r.Ok {
		t.Fatalf("receipt at the limit refused: %+v", r)
	}
	path, key, _ = withUnprotected(t, map[int64]any{-70000: make([]byte, pad+1)})
	if r := verifyReceipt(path, key, "02"); r.Ok || r.FailedAt != failedAtStructure || !strings.Contains(r.Error, "size") {
		t.Fatalf("receipt over the limit not refused: %+v", r)
	}
}

// signedReceipt writes a one-leaf EdDSA receipt over leaf 0xaa with exactly
// protected as its header.
func signedReceipt(t *testing.T, protected map[any]any) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	protBytes, err := cbor.Marshal(protected)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, sigStructure(protBytes, leafHash([]byte{0xaa})))
	proof, _ := cbor.Marshal([]any{1, 0, []any{}})
	receipt, err := cbor.Marshal(cbor.Tag{Number: 18, Content: []any{
		protBytes, map[any]any{396: map[any]any{-1: []any{proof}}}, nil, signature,
	}})
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	dir := t.TempDir()
	path, keyPath := filepath.Join(dir, "receipt.cose"), filepath.Join(dir, "log-key.pub")
	if err := os.WriteFile(path, receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, keyPath
}

// 2^64-8 must not wrap to -8 (EdDSA).
func TestAlgAboveInt64IsNotEdDSA(t *testing.T) {
	path, key := signedReceipt(t, map[any]any{1: -8, 395: 1})
	if r := verifyReceipt(path, key, "aa"); !r.Ok {
		t.Fatalf("control receipt refused: %+v", r)
	}
	path, key = signedReceipt(t, map[any]any{1: uint64(1<<64 - 8), 395: 1})
	if r := verifyReceipt(path, key, "aa"); r.Ok {
		t.Fatalf("alg 2^64-8 accepted as EdDSA: %+v", r)
	}
}

// As in the Python and Rust verifiers: a bad crit fails at structure, with
// no diagnostic root.
func TestBadCritFailsBeforeProofs(t *testing.T) {
	path, key := signedReceipt(t, map[any]any{1: -8, 2: []any{99}, 99: 0, 395: 1})
	r := verifyReceipt(path, key, "aa")
	if r.Ok || r.FailedAt != failedAtStructure || r.Root != "" || !strings.Contains(r.Error, "does not understand") {
		t.Fatalf("bad crit: %+v", r)
	}
}
