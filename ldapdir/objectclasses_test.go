// SPDX-License-Identifier: BSD-3-Clause

package ldapdir_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/directory/ldaptest"
)

// ⛔ The planted negative: the upstream entries ARE supannPerson and
// supannGroupe, by their own objectClass values. What this source hands out
// is the configuration's declaration, and only that.
func classedDirectory(t *testing.T, cfg ldapdir.Config) *ldapdir.Source {
	t.Helper()
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			"alice": {Password: "hunter2",
				ObjectClasses: []string{"top", "account", "posixAccount", "supannPerson", "eduPerson"},
				Extra:         map[string][]string{"supannAliasLogin": {"aliddell"}}},
			"bob": {Password: "swordfish"},
		},
		Groups: map[string][]string{"staff": {"alice", "bob"}},
		GroupExtra: map[string]map[string][]string{
			"staff": {"objectClass": {"supannGroupe"}, "gidNumber": {"100"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	cfg.URL, cfg.BaseDN, cfg.GroupBaseDN = d.URL, d.PeopleDN, d.GroupsDN
	cfg.BindDN, cfg.BindPassword = d.ReaderDN, d.ReaderPassword
	src, err := ldapdir.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestDeclaredObjectClassesFromLDAP(t *testing.T) {
	src := classedDirectory(t, ldapdir.Config{
		ObjectClasses:      []string{"schacContactLocation", "eduPerson", "EDUPERSON"},
		GroupObjectClasses: []string{"eduOrg"},
	})
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("%d people", len(ids))
	}
	for _, id := range ids {
		// Declared order, repeats dropped -- and not supannPerson, which
		// alice's entry carries and nobody declared.
		if got := id.ObjectClasses(); !slices.Equal(got, []string{"schacContactLocation", "eduPerson"}) {
			t.Errorf("%s = %v", id.Name(), got)
		}
	}
	var gc directory.GroupObjectClasser = src
	if got, err := gc.GroupObjectClasses("staff"); err != nil || !slices.Equal(got.Names(), []string{"eduOrg"}) {
		t.Errorf("staff = %v, %v: the group's own supannGroupe must not come through", got.Names(), err)
	}
	if _, err := gc.GroupObjectClasses("nobody"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("a group the directory does not have: %v", err)
	}
}

func TestUpstreamObjectClassValuesSetNothing(t *testing.T) {
	src := classedDirectory(t, ldapdir.Config{Attributes: []string{"supannAliasLogin"}})
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if got := id.ObjectClasses(); len(got) != 0 {
			t.Errorf("%s = %v: an upstream objectClass value set a class", id.Name(), got)
		}
		// The attribute the class would explain comes through; the class
		// does not follow it.
		if id.Name() == "alice" && id.Attributes().Get("supannAliasLogin") == nil {
			t.Error("the copied attribute went missing")
		}
	}
	if got, err := src.GroupObjectClasses("staff"); err != nil || got.Len() != 0 {
		t.Errorf("staff = %v, %v", got.Names(), err)
	}
	// And objectClass cannot be copied as an attribute either.
	for _, cfg := range []ldapdir.Config{
		{URL: "ldaps://h", BaseDN: "dc=x", Attributes: []string{"objectClass"}},
		{URL: "ldaps://h", BaseDN: "dc=x", GroupAttributes: []string{"OBJECTCLASS"}},
	} {
		if _, err := ldapdir.New(cfg); !errors.Is(err, directory.ErrAttributeName) {
			t.Errorf("%v: objectClass copied: %v", cfg.Attributes, err)
		}
	}
}

// Refused before connecting: the url names a closed loopback port, so that a
// broken check fails at once with "not answering" rather than waiting on a
// dial.
func TestADeclaredLDAPClassThatIsNotADescriptor(t *testing.T) {
	for _, tc := range []struct {
		cfg  ldapdir.Config
		want string
	}{
		{ldapdir.Config{ObjectClasses: []string{"eduPerson", "edu Person"}}, "ldapdir: ObjectClasses:"},
		{ldapdir.Config{ObjectClasses: []string{"1.3.6.1.4.1.5923.1.1.2"}}, "is an OID"},
		{ldapdir.Config{GroupObjectClasses: []string{"x)(objectClass=*"}}, "ldapdir: GroupObjectClasses:"},
	} {
		tc.cfg.URL, tc.cfg.BaseDN = "ldaps://127.0.0.1:1", "dc=x"
		_, err := ldapdir.New(tc.cfg)
		if !errors.Is(err, directory.ErrObjectClassName) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v, want %q", err, tc.want)
		}
	}
}
