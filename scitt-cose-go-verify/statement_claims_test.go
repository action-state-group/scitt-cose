// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Action State Group, Inc.

// Protected-header claims are surfaced ONLY after the statement signature
// verifies under the pinned key (same rule as the Python/Rust receipt path).
// A statement signed by a different key, or with corrupted signature bytes,
// must report valid=false with every header-derived field empty and the
// "claims withheld" finding; a good statement still exposes them. Runs the
// real CLI binary built in TestMain (vectors_test.go).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veraison/go-cose"
)

const withheldPrefix = "protected header claims withheld"

// signStatement builds a COSE_Sign1 statement with a kid, content type and
// CWT claims (iss, sub and one string-keyed profile claim), signed by priv.
func signStatement(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	msg := cose.NewSign1Message()
	msg.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	msg.Headers.Protected[int64(hdrContentType)] = "application/widget+json"
	msg.Headers.Protected[int64(hdrKID)] = []byte{0xde, 0xad, 0xbe, 0xef}
	msg.Headers.Protected[int64(hdrCWTClaims)] = map[any]any{
		int64(cwtISS):   "https://issuer.example",
		int64(cwtSUB):   "urn:anything:goes",
		"profile_thing": "abc",
	}
	msg.Payload = []byte(`{"opaque":"bytes"}`)
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return out
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

func writePub(t *testing.T, dir string, pub ed25519.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	p := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return p
}

func runStatement(t *testing.T, stmt []byte, pub ed25519.PublicKey) result {
	t.Helper()
	dir := t.TempDir()
	s := filepath.Join(dir, "stmt.cose")
	if err := os.WriteFile(s, stmt, 0o600); err != nil {
		t.Fatalf("write stmt: %v", err)
	}
	return runBinary(t, "--statement", s, "--pubkey", writePub(t, dir, pub), "--alg", "EdDSA")
}

func assertWithheld(t *testing.T, r result) {
	t.Helper()
	if r.Valid {
		t.Fatalf("valid=true for a statement that must not verify: %+v", r)
	}
	if r.ContentType != "" || r.Kid != "" || r.Iss != "" || r.Sub != "" || len(r.StringClaims) != 0 {
		t.Errorf("header claims surfaced from an unverified statement: content_type=%q kid=%q iss=%q sub=%q string_claims=%v",
			r.ContentType, r.Kid, r.Iss, r.Sub, r.StringClaims)
	}
	if !strings.Contains(r.Error, withheldPrefix) {
		t.Errorf("error %q lacks the %q finding", r.Error, withheldPrefix)
	}
}

func TestStatementClaimsWithheld_wrongKey(t *testing.T) {
	_, priv := newKey(t)
	otherPub, _ := newKey(t)
	assertWithheld(t, runStatement(t, signStatement(t, priv), otherPub))
}

func TestStatementClaimsWithheld_corruptedSignature(t *testing.T) {
	pub, priv := newKey(t)
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(signStatement(t, priv)); err != nil {
		t.Fatalf("decode: %v", err)
	}
	msg.Signature[0] ^= 0x01
	bad, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	assertWithheld(t, runStatement(t, bad, pub))
}

func TestStatementClaimsExposed_validSignature(t *testing.T) {
	pub, priv := newKey(t)
	r := runStatement(t, signStatement(t, priv), pub)
	if !r.Valid {
		t.Fatalf("valid statement rejected: %s", r.Error)
	}
	if r.ContentType != "application/widget+json" || r.Kid != "deadbeef" ||
		r.Iss != "https://issuer.example" || r.Sub != "urn:anything:goes" ||
		r.StringClaims["profile_thing"] != "abc" {
		t.Errorf("verified claims not exposed: %+v", r)
	}
	if strings.Contains(r.Error, withheldPrefix) {
		t.Errorf("withheld finding on a verified statement: %q", r.Error)
	}
}
