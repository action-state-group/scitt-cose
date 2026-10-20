// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"github.com/fxamacker/cbor/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDonatedProofOrders(t *testing.T) {
	dir := filepath.Join(vectorsRoot, "v1", "valid-eddsa-multi-proof")
	data, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var exp expected
	if err := json.Unmarshal(data, &exp); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"receipt.cose", "receipt-reordered.cose"} {
		result := verifyReceipt(filepath.Join(dir, name), filepath.Join(dir, "log-key.pub"), exp.LeafEntry)
		if !result.Ok || result.LeafIndex != exp.LeafIndex {
			t.Fatalf("%s: %+v", name, result)
		}
	}
}

func TestProofShapeAndTrailingBytes(t *testing.T) {
	for _, proof := range [][]any{{0, 0, []any{}}, {1, 1, []any{}}, {2, 0, []any{}}, {1, 0, []any{make([]byte, 32)}}} {
		data, err := cbor.Marshal(proof)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := decodeInclusionProof(data); err == nil {
			t.Fatalf("invalid shape accepted: %v", proof[:2])
		}
	}
	data, err := cbor.Marshal([]any{1, 0, []any{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := decodeInclusionProof(append(data, 0)); err == nil {
		t.Fatal("trailing CBOR accepted")
	}
}

func TestMalformedProofAfterValidCandidate(t *testing.T) {
	dir := filepath.Join(vectorsRoot, "v1", "valid-eddsa-multi-proof")
	data, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var exp expected
	if err := json.Unmarshal(data, &exp); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(dir, "receipt-reordered.cose"))
	if err != nil {
		t.Fatal(err)
	}
	var tag cbor.Tag
	if err := cbor.Unmarshal(data, &tag); err != nil {
		t.Fatal(err)
	}
	message := tag.Content.([]any)
	unprotected := message[1].(map[any]any)
	vdpAny, _ := mapGet(unprotected, hdrVDP)
	vdp := vdpAny.(map[any]any)
	entries, _ := mapGet(vdp, vdpInclusionProof)
	malformed, err := cbor.Marshal([]any{0, 0, []any{}})
	if err != nil {
		t.Fatal(err)
	}
	message[1] = map[int]any{hdrVDP: map[int]any{vdpInclusionProof: append(entries.([]any), malformed)}}
	encoded, err := cbor.Marshal(tag)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt.cose")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	result := verifyReceipt(path, filepath.Join(dir, "log-key.pub"), exp.LeafEntry)
	if result.Ok || !strings.Contains(result.Error, "invalid tree size or leaf index") {
		t.Fatalf("malformed tail accepted: %+v", result)
	}
	if result.Root != "" {
		t.Fatalf("malformed tail reported a root: %+v", result)
	}
}

// TestWrongKeyReportsFirstProofInEitherOrder: with no proof verifying, the
// diagnostic is the first proof that rebuilds a root, whichever order the
// proofs come in (scitt-cose#91).
func TestWrongKeyReportsFirstProofInEitherOrder(t *testing.T) {
	dir := filepath.Join(vectorsRoot, "v1", "valid-eddsa-multi-proof")
	data, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatal(err)
	}
	var exp expected
	if err := json.Unmarshal(data, &exp); err != nil {
		t.Fatal(err)
	}
	wrong := filepath.Join(vectorsRoot, "receipt-v1", "fail-wrong-log-key", "log-key.pub")
	cases := []struct {
		name, root string
		index      int64
	}{
		{"receipt.cose", "188f4dc7ce35a72f065bcfa3f8387889ae06a2a84c8eb5e04b92cd6849d819f1", 1},
		{"receipt-reordered.cose", exp.ReconstructedRoot, 2},
	}
	for _, c := range cases {
		result := verifyReceipt(filepath.Join(dir, c.name), wrong, exp.LeafEntry)
		if result.Ok || result.Root != c.root || result.TreeSize != 8 || result.LeafIndex != c.index {
			t.Errorf("%s: %+v, expected root %s at 8/%d", c.name, result, c.root, c.index)
		}
	}
}
