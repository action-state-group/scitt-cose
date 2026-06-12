// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Action State Group, Inc.

// Cross-implementation test-vector runner (Go side). Walks the SAME
// ../test-vectors/manifest.json the Python runner uses and verifies every
// vector with THIS clean-room implementation, executed as the real CLI binary
// (the same way a third party would run it). Same files, two runtimes:
// agreement on accept AND reject is the conformance claim under test.
//
// A negative vector that unexpectedly verifies fails the test — rejection
// agreement matters as much as acceptance agreement.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const vectorsRoot = "../test-vectors"

type manifest struct {
	Version string `json:"version"`
	Vectors []struct {
		ID             string `json:"id"`
		Dir            string `json:"dir"`
		ExpectedResult string `json:"expected_result"`
		FailureCode    string `json:"failure_code"`
	} `json:"vectors"`
}

type expected struct {
	PayloadSHA256   string `json:"payload_sha256"`
	ProtectedHeader struct {
		Statement struct {
			Alg         string `json:"alg"`
			ContentType string `json:"content_type"`
			Issuer      string `json:"issuer"`
			Subject     string `json:"subject"`
		} `json:"statement"`
	} `json:"protected_header"`
	LeafEntry         string `json:"leaf_entry"`
	LeafIndex         int64  `json:"leaf_index"`
	TreeSize          int64  `json:"tree_size"`
	ReconstructedRoot string `json:"reconstructed_root"`
	StatementSigValid bool   `json:"statement_signature_valid"`
	ReceiptValid      bool   `json:"receipt_valid"`
	Result            string `json:"result"`
	FailureCode       string `json:"failure_code"`
}

var binaryPath string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "scitt-vectors-bin")
	if err != nil {
		panic(err)
	}
	binaryPath = filepath.Join(dir, "scitt-cose-go-verify")
	build := exec.Command("go", "build", "-o", binaryPath, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		os.RemoveAll(dir)
		panic("go build failed: " + err.Error())
	}
	// os.Exit skips deferred calls, so clean up explicitly before exiting.
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// runBinary executes the verifier CLI; the verdict is in the JSON on stdout
// (non-zero exit is EXPECTED for invalid artifacts, so it is not an error).
func runBinary(t *testing.T, args ...string) result {
	t.Helper()
	cmd := exec.Command(binaryPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, _ := cmd.Output()
	var r result
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("binary did not print JSON (args %v): %v\nstdout: %s\nstderr: %s",
			args, err, out, stderr.String())
	}
	return r
}

func sha256Hex(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(vectorsRoot, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var man manifest
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
			var exp expected
			if err := json.Unmarshal(rawExp, &exp); err != nil {
				t.Fatalf("parse expected.json: %v", err)
			}

			// The manifest is the advertised machine-readable index — it must
			// never drift from the expected.json it points at.
			if v.ExpectedResult != exp.Result {
				t.Errorf("manifest expected_result=%q != expected.json result=%q",
					v.ExpectedResult, exp.Result)
			}
			if v.FailureCode != exp.FailureCode {
				t.Errorf("manifest failure_code=%q != expected.json failure_code=%q",
					v.FailureCode, exp.FailureCode)
			}

			// Committed bytes pinned by digest, and the statement<->tree
			// binding (leaf = SHA-256 of the full statement bytes) checked
			// here too — same coverage as the Python runner.
			if got := sha256Hex(t, filepath.Join(dir, "payload.bin")); got != exp.PayloadSHA256 {
				t.Errorf("payload sha256 %s != expected %s", got, exp.PayloadSHA256)
			}
			if got := sha256Hex(t, filepath.Join(dir, "statement.cose")); got != exp.LeafEntry {
				t.Errorf("leaf_entry %s is not SHA-256(statement.cose) (%s)", exp.LeafEntry, got)
			}

			// --- Statement-only run -----------------------------------------
			stmt := runBinary(t,
				"--statement", filepath.Join(dir, "statement.cose"),
				"--pubkey", filepath.Join(dir, "issuer-key.pub"),
				"--alg", exp.ProtectedHeader.Statement.Alg,
			)
			if stmt.Valid != exp.StatementSigValid {
				t.Errorf("statement valid=%v (%s), expected %v (a negative vector that verifies is a FAIL)",
					stmt.Valid, stmt.Error, exp.StatementSigValid)
			}
			// Decoded protected-header agreement — only when the envelope
			// decoded (Iss set). On a structural parse failure the binary
			// emits empty fields and the verdict check above carries the
			// error; comparing empties would bury the root cause.
			if stmt.Iss != "" || stmt.Valid {
				if stmt.Iss != exp.ProtectedHeader.Statement.Issuer {
					t.Errorf("iss=%q, expected %q", stmt.Iss, exp.ProtectedHeader.Statement.Issuer)
				}
				if stmt.Sub != exp.ProtectedHeader.Statement.Subject {
					t.Errorf("sub=%q, expected %q", stmt.Sub, exp.ProtectedHeader.Statement.Subject)
				}
				if stmt.ContentType != exp.ProtectedHeader.Statement.ContentType {
					t.Errorf("content_type=%q, expected %q",
						stmt.ContentType, exp.ProtectedHeader.Statement.ContentType)
				}
			} else if stmt.Error != "" {
				t.Logf("statement did not decode: %s", stmt.Error)
			}

			// --- Receipt-only run -------------------------------------------
			rec := runBinary(t,
				"--receipt", filepath.Join(dir, "receipt.cose"),
				"--log-pubkey", filepath.Join(dir, "log-key.pub"),
				"--leaf-entry-hex", exp.LeafEntry,
			)
			if rec.Receipt == nil {
				t.Fatal("binary printed no receipt sub-result")
			}
			if rec.Receipt.Ok != exp.ReceiptValid {
				t.Errorf("receipt ok=%v (%s), expected %v",
					rec.Receipt.Ok, rec.Receipt.Error, exp.ReceiptValid)
			}
			if exp.ReceiptValid && rec.Receipt.Ok {
				if rec.Receipt.Root != exp.ReconstructedRoot {
					t.Errorf("clean-room root %s != published root %s",
						rec.Receipt.Root, exp.ReconstructedRoot)
				}
				if rec.Receipt.TreeSize != exp.TreeSize || rec.Receipt.LeafIndex != exp.LeafIndex {
					t.Errorf("tree_size/leaf_index %d/%d != expected %d/%d",
						rec.Receipt.TreeSize, rec.Receipt.LeafIndex, exp.TreeSize, exp.LeafIndex)
				}
			}

			// --- Overall verdict agreement ----------------------------------
			overall := stmt.Valid && rec.Receipt.Ok
			if overall != (exp.Result == "VALID") {
				t.Errorf("overall valid=%v, expected result %s", overall, exp.Result)
			}
		})
	}
}
