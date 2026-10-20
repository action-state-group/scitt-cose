// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVectorsReceiptV1 runs the receipt-only vectors in ../test-vectors/receipt-v1
// through the CLI binary, as the Python and Rust runners do. This verifier
// surfaces no iat or grade, so only the verdict, the root, the reported
// root/tree_size/leaf_index where a vector pins them and, on a failure, the
// named error are compared.
func TestVectorsReceiptV1(t *testing.T) {
	root := filepath.Join(vectorsRoot, "receipt-v1")
	raw, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var man struct {
		Vectors []struct {
			ID  string `json:"id"`
			Dir string `json:"dir"`
			Ok  bool   `json:"ok"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if len(man.Vectors) == 0 {
		t.Fatal("manifest has no vectors")
	}
	// failed-at.json pins each vector's failure stage (scitt-cose#93); a
	// later vector may carry failed_at in its own expected.json instead.
	rawStages, err := os.ReadFile(filepath.Join(root, "failed-at.json"))
	if err != nil {
		t.Fatalf("read failed-at.json: %v", err)
	}
	var stages struct {
		FailedAt map[string]*string `json:"failed_at"`
	}
	if err := json.Unmarshal(rawStages, &stages); err != nil {
		t.Fatalf("parse failed-at.json: %v", err)
	}
	for _, v := range man.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			dir := filepath.Join(vectorsRoot, filepath.FromSlash(v.Dir))
			rawExp, err := os.ReadFile(filepath.Join(dir, "expected.json"))
			if err != nil {
				t.Fatalf("read expected.json: %v", err)
			}
			var exp struct {
				LeafEntryHex    string  `json:"leaf_entry_hex"`
				Ok              bool    `json:"ok"`
				Root            *string `json:"root"`
				FailureContains string  `json:"failure_contains"`
				// Returned pins what is reported on vectors that carry it
				// (scitt-cose#91); older vectors leave it out.
				Returned *struct {
					Root      *string `json:"root"`
					TreeSize  *int64  `json:"tree_size"`
					LeafIndex *int64  `json:"leaf_index"`
				} `json:"returned"`
			}
			if err := json.Unmarshal(rawExp, &exp); err != nil {
				t.Fatalf("parse expected.json: %v", err)
			}
			var own map[string]json.RawMessage
			if err := json.Unmarshal(rawExp, &own); err != nil {
				t.Fatalf("parse expected.json: %v", err)
			}
			wantStage, pinned := stages.FailedAt[v.ID]
			if rawStage, ok := own["failed_at"]; ok {
				wantStage, pinned = nil, true
				if err := json.Unmarshal(rawStage, &wantStage); err != nil {
					t.Fatalf("parse failed_at: %v", err)
				}
			}
			if !pinned {
				t.Fatalf("no failed_at pinned")
			}
			if v.Ok != exp.Ok {
				t.Errorf("manifest ok=%v != expected.json ok=%v", v.Ok, exp.Ok)
			}
			out := runBinary(t,
				"--receipt", filepath.Join(dir, "receipt.cose"),
				"--log-pubkey", filepath.Join(dir, "log-key.pub"),
				"--leaf-entry-hex", exp.LeafEntryHex,
			)
			// A key the CLI cannot load ends the run before a receipt
			// sub-result exists; the error is then the top-level one.
			ok, errText := false, out.Error
			if out.Receipt != nil {
				ok = out.Receipt.Ok
				errText += out.Receipt.Error
			}
			if ok != exp.Ok {
				t.Fatalf("ok=%v (%s), expected %v (a negative vector that verifies is a FAIL)", ok, errText, exp.Ok)
			}
			// Go cannot load a secp256k1 key, so that run ends before a
			// receipt sub-result exists and reports no stage.
			if out.Receipt != nil || v.ID != "fail-es256-secp256k1-key" {
				if out.Receipt == nil {
					t.Fatalf("no receipt sub-result to compare failed_at against")
				}
				want := ""
				if wantStage != nil {
					want = *wantStage
				}
				if out.Receipt.FailedAt != want {
					t.Errorf("failed_at %q, expected %q", out.Receipt.FailedAt, want)
				}
			}
			if ret := exp.Returned; ret != nil {
				// Go's coordinates are non-nullable: absent is an empty root
				// and zero coordinates.
				wantRoot, wantSize, wantIndex := "", int64(0), int64(0)
				if ret.Root != nil {
					wantRoot = *ret.Root
				}
				if ret.TreeSize != nil {
					wantSize = *ret.TreeSize
				}
				if ret.LeafIndex != nil {
					wantIndex = *ret.LeafIndex
				}
				if out.Receipt == nil {
					t.Fatalf("no receipt sub-result to compare returned against")
				}
				got := out.Receipt
				if got.Root != wantRoot || got.TreeSize != wantSize || got.LeafIndex != wantIndex {
					t.Errorf("returned root/tree_size/leaf_index %q/%d/%d, expected %q/%d/%d",
						got.Root, got.TreeSize, got.LeafIndex, wantRoot, wantSize, wantIndex)
				}
			}
			if exp.Ok {
				if exp.Root == nil || out.Receipt.Root != *exp.Root {
					t.Errorf("root %s != expected %v", out.Receipt.Root, exp.Root)
				}
			} else if !strings.Contains(errText, exp.FailureContains) {
				t.Errorf("error %q does not contain %q", errText, exp.FailureContains)
			}
		})
	}
}

// TestAlgKeyMismatchReportsDiagnostic: an alg/key mismatch fails in the
// signature step, so the first proof's root and coordinates stay as a
// diagnostic, as in the Python and Rust verifiers (scitt-cose#91). The
// secp256k1 vector is left out: Go cannot load that key at all.
func TestAlgKeyMismatchReportsDiagnostic(t *testing.T) {
	root := filepath.Join(vectorsRoot, "receipt-v1")
	rawGood, err := os.ReadFile(filepath.Join(root, "synthetic-eddsa-iat-only", "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	var good struct {
		Root string `json:"root"`
	}
	if err := json.Unmarshal(rawGood, &good); err != nil {
		t.Fatalf("parse expected.json: %v", err)
	}
	for _, id := range []string{"fail-es384-p256-key", "fail-eddsa-p256-key"} {
		dir := filepath.Join(root, id)
		out := runBinary(t,
			"--receipt", filepath.Join(dir, "receipt.cose"),
			"--log-pubkey", filepath.Join(dir, "log-key.pub"),
			"--leaf-entry-hex", "01",
		)
		r := out.Receipt
		if r == nil || r.Ok {
			t.Fatalf("%s: expected a failed receipt sub-result, got %+v", id, r)
		}
		if r.Root != good.Root || r.TreeSize != 4 || r.LeafIndex != 1 {
			t.Errorf("%s: root/tree_size/leaf_index %q/%d/%d, expected %q/4/1", id, r.Root, r.TreeSize, r.LeafIndex, good.Root)
		}
	}
}

// TestCCFFailedAt: the CCF (vds=2) path names its failure stage as the
// RFC 9162 path does (scitt-cose#93).
func TestCCFFailedAt(t *testing.T) {
	dir := filepath.Join(vectorsRoot, "v1", "valid-ccf-vds2")
	rawExp, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		t.Fatalf("read expected.json: %v", err)
	}
	var exp struct {
		LeafEntry string `json:"leaf_entry"`
	}
	if err := json.Unmarshal(rawExp, &exp); err != nil {
		t.Fatalf("parse expected.json: %v", err)
	}
	otherKey := filepath.Join(vectorsRoot, "receipt-v1", "fail-wrong-log-key", "log-key.pub")
	for _, tc := range []struct {
		name, key, leaf, want string
		ok                    bool
	}{
		{"ok", filepath.Join(dir, "log-key.pub"), exp.LeafEntry, "", true},
		{"wrong key", otherKey, exp.LeafEntry, failedAtSignature, false},
		{"bad leaf", otherKey, "zz", failedAtStructure, false},
	} {
		out := runBinary(t,
			"--receipt", filepath.Join(dir, "receipt.cose"),
			"--log-pubkey", tc.key,
			"--leaf-entry-hex", tc.leaf,
		)
		r := out.Receipt
		if r == nil || r.Ok != tc.ok || r.FailedAt != tc.want {
			t.Errorf("%s: got %+v, expected ok=%v failed_at=%q", tc.name, r, tc.ok, tc.want)
		}
	}
}
