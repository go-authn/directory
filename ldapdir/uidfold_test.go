// SPDX-License-Identifier: BSD-3-Clause

package ldapdir_test

import (
	"errors"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/directory/ldaptest"
	"github.com/go-authn/ldap/schema"
)

// Regression test for the 2026-11-21 audit. The v0.18.0 ambiguity check folded
// the name with strings.ToLower. uid is caseIgnoreMatch, whose preparation is
// more than a lower-casing: the judge here is go-authn's own schema package.
// Every pair the judge calls ONE uid must be ErrAmbiguous, and a pair it calls
// two must not be.
func TestUIDsEqualUnderCaseIgnoreMatchAreAmbiguous(t *testing.T) {
	std := schema.Standard()
	uid := std.AttributeType("uid")
	if uid == nil {
		t.Fatal("no uid in the standard schema")
	}
	for _, c := range []struct {
		name, a, b string
		same       bool
	}{
		{"case", "alice", "Alice", true},
		{"trailing space", "alice", "alice ", true},
		{"inner double space", "al ice", "al  ice", true},
		{"fullwidth letter (NFKC)", "alice", "ａlice", true},
		{"long s (NFKC)", "sam", "ſam", true},
		{"soft hyphen (mapped to nothing)", "alice", "al­ice", true},
		{"two people", "alice", "alicf", false},
		{"inner space is significant", "alice", "al ice", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := std.Equal(uid, []byte(c.a), []byte(c.b)) == schema.True; got != c.same {
				t.Fatalf("the judge says %q = %q is %v, the table says %v", c.a, c.b, got, c.same)
			}
			d, err := ldaptest.NewServer(&ldaptest.Directory{
				People: map[string]ldaptest.Person{
					"alice-staff":   {UID: c.a, Password: "staff-pw"},
					"alice-student": {UID: c.b, Password: "student-pw"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			src, err := ldapdir.New(ldapdir.Config{URL: d.URL, BaseDN: d.PeopleDN, BindDN: d.ReaderDN, BindPassword: d.ReaderPassword})
			if err != nil {
				t.Fatal(err)
			}
			ids, err := src.Identities()
			if c.same {
				if !errors.Is(err, directory.ErrAmbiguous) {
					t.Errorf("caseIgnoreMatch says %q = %q, and Identities returned %d people, err = %v; want ErrAmbiguous", c.a, c.b, len(ids), err)
				}
				return
			}
			if err != nil || len(ids) != 2 {
				t.Errorf("%q and %q are two uids: %d people, err = %v; want 2", c.a, c.b, len(ids), err)
			}
		})
	}
}
