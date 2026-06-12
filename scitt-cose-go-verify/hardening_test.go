// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Action State Group, Inc.

// Regression tests for the pre-Vienna hardening pass (Go side). Finding H2: a
// receipt with an attacker-supplied tree_size near 2^63 used to hang the Merkle
// fold forever (largestPow2Below's `k*2` overflowed int64). These pin the
// bounded-rejection behaviour directly against the package functions — no
// subprocess, so a re-introduced infinite loop is caught by the test timeout.
package main

import (
	"testing"
)

func TestH2_largestPow2BelowTerminates(t *testing.T) {
	// Values at and beyond the int64 ceiling must terminate, not loop forever on
	// k*2 overflow. A regression re-introducing the overflow hangs here and is
	// caught by `go test -timeout`. (Each result must be a power of two < n.)
	for _, n := range []int64{2, 8, maxTreeSize, maxTreeSize + 1, 1<<63 - 1} {
		k := largestPow2Below(n)
		// k must be a power of two, strictly below n, with no larger power of
		// two fitting (2k >= n, written overflow-safe as k >= n-k).
		if k < 1 || k&(k-1) != 0 || k >= n || k < n-k {
			t.Fatalf("largestPow2Below(%d)=%d is not the largest power of two below n", n, k)
		}
	}
}

func TestH2_rootFromInclusionProofRejectsHostileTreeSize(t *testing.T) {
	leaf := make([]byte, 32)
	sibling := make([]byte, 32)

	// tree_size beyond the ceiling -> rejected before any fold, no hang.
	if _, ok := rootFromInclusionProof(leaf, 0, 1<<63-1, [][]byte{sibling}); ok {
		t.Fatal("tree_size 2^63-1 must be rejected")
	}
	if _, ok := rootFromInclusionProof(leaf, 0, maxTreeSize+1, [][]byte{sibling}); ok {
		t.Fatal("tree_size > maxTreeSize must be rejected")
	}
	// A path whose length does not match the expected depth is rejected.
	if _, ok := rootFromInclusionProof(leaf, 3, 8, [][]byte{sibling}); ok {
		t.Fatal("wrong-length audit path must be rejected")
	}
}

func TestH2_expectedInclusionPathLen(t *testing.T) {
	// Matches the Python verifier (tree_size 8, index 2 -> depth 3).
	if got := expectedInclusionPathLen(8, 2); got != 3 {
		t.Fatalf("expectedInclusionPathLen(8,2)=%d, want 3", got)
	}
	if got := expectedInclusionPathLen(maxTreeSize, 0); got != 62 {
		t.Fatalf("expectedInclusionPathLen(maxTreeSize,0)=%d, want 62", got)
	}
}
