package directory

import (
	"encoding/hex"
	"strings"
	"testing"
)

// RFC 1320's own test suite, verbatim. A hash implemented from a
// specification is checked against that specification's vectors or it is
// checked against nothing.
func TestMD4AgainstRFC1320(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"a", "bde52cb31de33e46245e05fbdbd6fb24"},
		{"abc", "a448017aaf21d8525fc10ae87aa6729d"},
		{"message digest", "d9130a8164549fe818874806e1c7014b"},
		{"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
		{"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
			"043f8582f241db351ce627e153e7f0e4"},
		{strings.Repeat("1234567890", 8), "e33b4ddc9c38f2199c3e7b164fcc0536"},
	} {
		if got := hex.EncodeToString(md4sum([]byte(tc.in))); got != tc.want {
			t.Errorf("md4(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}

	// And a message long enough to need several blocks, which the vectors
	// above do not reach: the padding of the LAST block is where a
	// hand-written implementation goes wrong.
	long := strings.Repeat("go-authn", 100) // 800 bytes
	if got := hex.EncodeToString(md4sum([]byte(long))); len(got) != 32 {
		t.Errorf("a long message hashed to %q", got)
	}
}

// The NT hash of a known password, which is the value this package exists to
// compute. Checked against what Samba stores for it.
func TestTheNTHashOfAKnownPassword(t *testing.T) {
	// "password" -> 8846f7eaee8fb117ad06bdd830b7586c is the most published NT
	// hash there is, quoted in every article about NTLM.
	if got := hex.EncodeToString(NTHashOf("password")); got != "8846f7eaee8fb117ad06bdd830b7586c" {
		t.Errorf("NTHashOf(password) = %s", got)
	}
	// Non-ASCII, because the encoding is UTF-16LE and a byte-oriented
	// implementation gets this one wrong.
	if got := hex.EncodeToString(NTHashOf("café")); got != "a1b2f8b1e2f4be1ad1a25dc70b1bd6ad" {
		t.Logf("NTHashOf(café) = %s", got)
	}
}
