// SPDX-License-Identifier: Apache-2.0
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// An attached payload is refused even when it is an empty byte string, which
// must not be read as the detached (nil) form.
func TestEmptyAttachedPayloadRejected(t *testing.T) {
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
	items[2] = []byte{}
	out, err := cbor.Marshal(cbor.Tag{Number: 18, Content: items})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt.cose")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	r := verifyReceipt(path, filepath.Join(dir, "log-key.pub"), "02")
	if r.Ok || !strings.Contains(r.Error, "attached") {
		t.Fatalf("empty attached payload not rejected as attached: %+v", r)
	}
}

func TestVerifierRefusesAKeyTheAlgDoesNotName(t *testing.T) {
	for _, c := range []struct {
		alg   string
		curve elliptic.Curve
		want  string
	}{
		{"ES256", elliptic.P384(), "ES256 (-7) requires a P-256 public key, got P-384"},
		{"ES384", elliptic.P256(), "ES384 (-35) requires a P-384 public key, got P-256"},
		{"EdDSA", elliptic.P256(), "requires an ed25519 public key"},
	} {
		key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newVerifier(c.alg, &key.PublicKey); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s under %s: error %v, want %q", c.alg, c.curve.Params().Name, err, c.want)
		}
	}
	for _, c := range []struct {
		alg   string
		curve elliptic.Curve
	}{{"ES256", elliptic.P256()}, {"ES384", elliptic.P384()}} {
		key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newVerifier(c.alg, &key.PublicKey); err != nil {
			t.Errorf("%s under %s refused: %v", c.alg, c.curve.Params().Name, err)
		}
	}
}
