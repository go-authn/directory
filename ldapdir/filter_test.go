// SPDX-License-Identifier: BSD-3-Clause

package ldapdir_test

import (
	"slices"
	"testing"

	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/directory/ldaptest"
)

// The default filter reads a person by any of the three standard classes that
// carry a uid, and nothing else. go-authn/authnd publishes a person without
// the POSIX attributes as an account (or an inetOrgPerson) with uidObject, and
// such a person must not vanish for a client that kept the default.
//
// ⛔ The other half is the one that guards the widening: a plain
// inetOrgPerson -- the commonest entry in an institution's directory -- with
// neither account, uidObject nor posixAccount is still NOT read.
func TestTheDefaultUserFilter(t *testing.T) {
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			// The shape this package always read.
			"posix": {Password: "p", ObjectClasses: []string{"top", "account", "posixAccount"}},
			// What authnd publishes for a person without uidNumber,
			// gidNumber and homeDirectory and without sn.
			"plain": {Password: "p", ObjectClasses: []string{"top", "account", "uidObject"}},
			// ... and with sn.
			"named": {Password: "p", ObjectClasses: []string{"top", "person", "organizationalPerson", "inetOrgPerson", "uidObject"},
				Extra: map[string][]string{"sn": {"Named"}, "cn": {"named"}}},
			// An account without uidObject: RFC 4524's own class.
			"acct": {Password: "p", ObjectClasses: []string{"top", "account"}},
			// A plain inetOrgPerson with a uid and none of the three classes.
			"other": {Password: "p", ObjectClasses: []string{"top", "person", "organizationalPerson", "inetOrgPerson"},
				Extra: map[string][]string{"sn": {"Other"}, "cn": {"other"}}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	read := func(filter string) []string {
		t.Helper()
		src, err := ldapdir.New(ldapdir.Config{
			URL: d.URL, BaseDN: d.PeopleDN, BindDN: d.ReaderDN, BindPassword: d.ReaderPassword,
			UserFilter: filter,
		})
		if err != nil {
			t.Fatal(err)
		}
		ids, err := src.Identities()
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, id := range ids {
			names = append(names, id.Name())
		}
		slices.Sort(names)
		return names
	}

	if got, want := read(""), []string{"acct", "named", "plain", "posix"}; !slices.Equal(got, want) {
		t.Errorf("the default filter read %v, want %v", got, want)
	}
	if got := read(""); slices.Contains(got, "other") {
		t.Error("a plain inetOrgPerson with no account, uidObject or posixAccount was read by default: the default widened past the three classes")
	}
	// The old default stays available, and gives the old set.
	if got, want := read("(objectClass=posixAccount)"), []string{"posix"}; !slices.Equal(got, want) {
		t.Errorf("(objectClass=posixAccount) read %v, want %v", got, want)
	}
	if ldapdir.DefaultUserFilter != "(|(objectClass=posixAccount)(objectClass=account)(objectClass=uidObject))" {
		t.Errorf("DefaultUserFilter is %q", ldapdir.DefaultUserFilter)
	}
}
