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
// surfaces no iat or grade, so only the verdict, the root and, on a failure,
// the named error are compared.
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
			}
			if err := json.Unmarshal(rawExp, &exp); err != nil {
				t.Fatalf("parse expected.json: %v", err)
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
