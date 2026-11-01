// SPDX-License-Identifier: BSD-3-Clause

package ldapdir

import (
	"bytes"
	"encoding/binary"
	"slices"
	"unicode"

	"github.com/go-ldap/ldap/v3"
)

// dnKey is a canonical form of a DN: dnKey(a) == dnKey(b) exactly when
// a.EqualFold(b), go-ldap's distinguishedNameMatch (RFC 4517 §4.2.15, as
// dn.go:421-484 of v3.4.15 implements it).
//
// That is: the same number of RDNs, in the same order; within an RDN the same
// multiset of type=value pairs in any order; types and values equal under
// strings.EqualFold. Each string is reduced to the smallest rune of every
// rune's unicode.SimpleFold orbit, which is what strings.EqualFold compares
// by (the Kelvin sign folds with k, the long s with s).
func dnKey(dn *ldap.DN) string { return string(appendDNKey(nil, dn)) }

// appendDNKey appends dnKey(dn) to dst. Each RDN is its attribute count (a
// uvarint) then its pairs sorted; every type and value ends in a 0 byte and
// escapes 0 and 1 as 1 2 and 1 1, so no value can pass for a separator.
func appendDNKey(dst []byte, dn *ldap.DN) []byte {
	for _, rdn := range dn.RDNs {
		dst = binary.AppendUvarint(dst, uint64(len(rdn.Attributes)))
		if len(rdn.Attributes) == 1 { // nearly every RDN: no sorting, no scratch
			a := rdn.Attributes[0]
			dst = appendField(appendField(dst, a.Type), a.Value)
			continue
		}
		pairs := make([][]byte, 0, len(rdn.Attributes))
		for _, a := range rdn.Attributes {
			pairs = append(pairs, appendField(appendField(nil, a.Type), a.Value))
		}
		slices.SortFunc(pairs, bytes.Compare)
		for _, p := range pairs {
			dst = append(dst, p...)
		}
	}
	return dst
}

// appendField appends canon(s), escaped, and a terminating 0.
func appendField(dst []byte, s string) []byte {
	for _, r := range s { // an invalid byte is U+FFFD, as strings.EqualFold reads it
		r = canon(r)
		switch {
		case r == 0:
			dst = append(dst, 1, 2)
		case r == 1:
			dst = append(dst, 1, 1)
		case r < 0x80:
			dst = append(dst, byte(r))
		default:
			dst = append(dst, string(r)...)
		}
	}
	return append(dst, 0)
}

// canon is the smallest rune equal to r under simple case folding.
func canon(r rune) rune {
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < m {
			m = f
		}
	}
	return m
}
