// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// The receipt encoding rule, checked on raw octets.
//
// agent-action-capsule's interop profile v1 §6.2.2 states one rule for the
// CBOR of a COSE Receipt, so that every verifier decides the same octets the
// same way: the COSE_Sign1, its protected header and each inclusion-proof
// blob are each one CBOR item with no trailing octet, definite lengths, every
// argument in its shortest form, no repeated map key, every integer from
// -2^63 to 2^64 - 1, every map key an integer or a text string, every text
// string valid UTF-8, no float, no simple value but false, true and null, no
// tag but the outer tag 18, and no item nested more than 16 levels deep (an
// item inside an array, a map or a tag is one level deeper). Map order is not
// checked.
//
// This walks the octets itself rather than asking fxamacker/cbor or go-cose,
// so the decision does not depend on how a CBOR library reads tags, floats or
// simple values. The Python package (scitt_cose/_encoding_rule.py) and the
// Rust crate (rust/scitt-cose/src/encoding.rs) carry the same walk.

// maxEncodingDepth is the deepest level an item may sit at; the top item is
// level 0.
const maxEncodingDepth = 16

var errTruncated = errors.New("truncated CBOR")

// checkEncoding returns an error naming the clause that failed unless octets
// is one CBOR item under the receipt encoding rule. outerTag admits tag 18 on
// the top item only.
func checkEncoding(octets []byte, what string, outerTag bool) error {
	end, err := encodingItem(octets, 0, 0, outerTag)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if end != len(octets) {
		return fmt.Errorf("%s: trailing octets after the CBOR item", what)
	}
	return nil
}

// encodingHead reads one head at pos: major type, additional information,
// argument and the position after the head.
func encodingHead(octets []byte, pos int) (byte, byte, uint64, int, error) {
	if pos >= len(octets) {
		return 0, 0, 0, 0, errTruncated
	}
	major, info := octets[pos]>>5, octets[pos]&0x1f
	pos++
	var width int
	var smallest uint64
	switch {
	case info < 24:
		return major, info, uint64(info), pos, nil
	case info == 24:
		width, smallest = 1, 24
	case info == 25:
		width, smallest = 2, 1<<8
	case info == 26:
		width, smallest = 4, 1<<16
	case info == 27:
		width, smallest = 8, 1<<32
	case info == 31:
		return 0, 0, 0, 0, errors.New("an indefinite length")
	default:
		return 0, 0, 0, 0, errors.New("a reserved additional-information value")
	}
	if width > len(octets)-pos {
		return 0, 0, 0, 0, errTruncated
	}
	var argument uint64
	for _, b := range octets[pos : pos+width] {
		argument = argument<<8 | uint64(b)
	}
	// A float has no shortest-form rule of its own here: every float is refused.
	if major != 7 && argument < smallest {
		return 0, 0, 0, 0, errors.New("an argument longer than its shortest form")
	}
	return major, info, argument, pos + width, nil
}

// encodingItem checks the item at pos at nesting depth and returns the
// position after it.
func encodingItem(octets []byte, pos, depth int, outerTag bool) (int, error) {
	if depth > maxEncodingDepth {
		return 0, errors.New("an item nested more than 16 levels deep")
	}
	major, info, argument, pos, err := encodingHead(octets, pos)
	if err != nil {
		return 0, err
	}
	switch major {
	case 0:
		return pos, nil
	case 1:
		if argument >= 1<<63 {
			return 0, errors.New("an integer below -2^63")
		}
		return pos, nil
	case 2, 3:
		if argument > uint64(len(octets)-pos) {
			return 0, errTruncated
		}
		end := pos + int(argument)
		if major == 3 && !utf8.Valid(octets[pos:end]) {
			return 0, errors.New("a text string that is not valid UTF-8")
		}
		return end, nil
	case 4:
		for i := uint64(0); i < argument; i++ {
			if pos, err = encodingItem(octets, pos, depth+1, false); err != nil {
				return 0, err
			}
		}
		return pos, nil
	case 5:
		keys := make(map[string]struct{})
		for i := uint64(0); i < argument; i++ {
			if pos >= len(octets) {
				return 0, errTruncated
			}
			if keyMajor := octets[pos] >> 5; keyMajor != 0 && keyMajor != 1 && keyMajor != 3 {
				return 0, errors.New("a map key that is not an integer or a text string")
			}
			keyStart := pos
			if pos, err = encodingItem(octets, pos, depth+1, false); err != nil {
				return 0, err
			}
			// Every argument is shortest, so equal keys have equal octets.
			key := string(octets[keyStart:pos])
			if _, seen := keys[key]; seen {
				return 0, errors.New("a repeated map key")
			}
			keys[key] = struct{}{}
			if pos, err = encodingItem(octets, pos, depth+1, false); err != nil {
				return 0, err
			}
		}
		return pos, nil
	case 6:
		if !(outerTag && depth == 0 && argument == 18) {
			return 0, errors.New("a CBOR tag other than the outer tag 18")
		}
		return encodingItem(octets, pos, depth+1, false)
	default:
		switch {
		case info >= 25 && info <= 27:
			return 0, errors.New("a float")
		case info >= 20 && info <= 22:
			return pos, nil
		default:
			return 0, errors.New("a simple value other than false, true and null")
		}
	}
}
