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

func describedDirectory(t *testing.T, cfg ldapdir.Config) (*ldapdir.Source, *ldaptest.Server) {
	t.Helper()
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			"alice": {
				Password:   "hunter2",
				TOTPSecret: "JBSWY3DPEHPK3PXP",
				Extra: map[string][]string{
					// The directory's spelling, not ours: a reader matches
					// without regard to case (RFC 4512 §2.5).
					"UIDNUMBER":           {"1000"},
					"homeDirectory":       {"/home/alice"},
					"mail":                {"alice@example.org", "a.liddell@example.org"},
					"description;lang-fr": {"une personne"},
					"description":         {"a person"},
					"loginShell":          {""}, // an empty value is no value
					"telephoneNumber":     {"+33 1 23 45 67 89"},
				},
			},
			"bob": {Password: "swordfish"},
		},
		Groups: map[string][]string{"staff": {"alice", "bob"}, "nobody-described": {"bob"}},
		GroupExtra: map[string]map[string][]string{
			"staff": {"gidNumber": {"100"}, "description": {"the people who work here"}},
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
	return src, d
}

func TestPeopleAttributesFromLDAP(t *testing.T) {
	src, _ := describedDirectory(t, ldapdir.Config{
		TOTPAttribute: "oathSecret",
		Attributes:    []string{"uidNumber", "homeDirectory", "mail", "loginShell", "description;LANG-FR"},
	})
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	var alice, bob directory.Attributes
	for _, id := range ids {
		switch id.Name() {
		case "alice":
			alice = id.Attributes()
			if !id.Can(directory.TOTPSecret) || !id.Can(directory.Verifier) {
				t.Error("alice's credentials went missing beside her attributes")
			}
		case "bob":
			bob = id.Attributes()
		}
	}
	// Copied under the configured spelling, though the directory answered
	// UIDNUMBER.
	if n := strings.Join(alice.Names(), ","); n != "uidNumber,homeDirectory,mail,description;LANG-FR" {
		t.Errorf("alice's attributes = %s", n)
	}
	if v := alice.Get("mail"); len(v) != 2 {
		t.Errorf("mail = %v", v)
	}
	// The tagged description is the one asked for; the untagged one is
	// another description, and was not.
	if v := alice.Get("description;lang-fr"); !slices.Equal(v, []string{"une personne"}) {
		t.Errorf("description;lang-fr = %v", v)
	}
	if alice.Get("description") != nil {
		t.Error("description was copied, and only description;lang-fr was asked for")
	}
	if alice.Get("telephoneNumber") != nil || alice.Get("loginShell") != nil {
		t.Errorf("alice = %v: something not asked for, or empty, arrived", alice.Names())
	}
	if bob.Len() != 0 {
		t.Errorf("bob = %v", bob.Names())
	}
}

func TestGroupAttributesFromLDAP(t *testing.T) {
	src, _ := describedDirectory(t, ldapdir.Config{GroupAttributes: []string{"gidNumber", "description"}})
	var _ directory.GroupAttributer = src

	staff, err := src.GroupAttributes("staff")
	if err != nil {
		t.Fatal(err)
	}
	if staff.Get("gidNumber")[0] != "100" || staff.Get("description") == nil {
		t.Errorf("staff = %v", staff.Names())
	}
	if a, err := src.GroupAttributes("nobody-described"); err != nil || a.Len() != 0 {
		t.Errorf("nobody-described = %v, %v", a.Names(), err)
	}
	if _, err := src.GroupAttributes("nobody"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("an unknown group gave %v", err)
	}

	// With nothing configured to copy, the question is still answered --
	// whether the group exists -- and nothing is copied.
	bare, _ := describedDirectory(t, ldapdir.Config{})
	if a, err := bare.GroupAttributes("staff"); err != nil || a.Len() != 0 {
		t.Errorf("bare staff = %v, %v", a.Names(), err)
	}
	if _, err := bare.GroupAttributes("nobody"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("bare nobody = %v", err)
	}

	// Through a Set, beside a file that knows the same group: the file's
	// gidNumber wins, the directory's description comes through.
	file := &directory.Static{
		Groups:     map[string][]string{"staff": {"carol"}},
		GroupAttrs: map[string]directory.Attributes{},
	}
	a, err := directory.NewAttributes(directory.Attribute{Name: "gidNumber", Values: []string{"5000"}})
	if err != nil {
		t.Fatal(err)
	}
	file.GroupAttrs["staff"] = a
	got, err := directory.NewSet(file, src).GroupAttributes("staff")
	if err != nil || got.Get("gidNumber")[0] != "5000" || got.Get("description") == nil {
		t.Errorf("set: %v, %v", got.Names(), err)
	}
}

// A directory that stops answering is an error, not "nothing to say".
func TestGroupAttributesFromADirectoryThatWentAway(t *testing.T) {
	src, d := describedDirectory(t, ldapdir.Config{GroupAttributes: []string{"gidNumber"}})
	d.Close()
	if _, err := src.GroupAttributes("staff"); err == nil || errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("gave %v", err)
	}
}

// Refused by New, before it connects: nothing here is listening, so an error
// that is not the refusal would say "not answering".
func TestAttributesLDAPDirMustNotCopy(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  ldapdir.Config
		want string
	}{
		{"a password", ldapdir.Config{Attributes: []string{"mail", "userPassword"}}, `ldapdir: Attributes: directory: not an attribute this package carries: "userPassword" holds a secret`},
		{"the NT hash, read as a credential already", ldapdir.Config{Attributes: []string{"sambaNTPassword"}}, "holds a secret"},
		{"the keys, read as a credential already", ldapdir.Config{Attributes: []string{"sshPublicKey"}}, "WithPublicKeys"},
		{"a site's own one-time-code attribute", ldapdir.Config{TOTPAttribute: "acmeOtp", Attributes: []string{"ACMEOTP;binary"}},
			`"ACMEOTP;binary" is TOTPAttribute: it holds a one-time-code secret`},
		{"a site's own membership attribute", ldapdir.Config{MemberAttribute: "teamMembers", GroupAttributes: []string{"teammembers"}},
			"is MemberAttribute"},
		{"a site's own group naming attribute", ldapdir.Config{GroupAttribute: "teamName", GroupAttributes: []string{"teamName"}},
			"is GroupAttribute"},
		{"the default membership attribute", ldapdir.Config{GroupAttributes: []string{"memberUid"}}, "is membership"},
		{"not a description", ldapdir.Config{Attributes: []string{"e mail"}}, "not an attribute description"},
	} {
		tc.cfg.URL, tc.cfg.BaseDN = "ldap://127.0.0.1:1", "dc=example,dc=org"
		_, err := ldapdir.New(tc.cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	// And what a site names for itself is fine to copy when it is not one of
	// those: a teamName is description in a person's entry.
	_, err := ldapdir.New(ldapdir.Config{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x",
		GroupAttribute: "teamName", Attributes: []string{"teamName"}})
	if err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Errorf("a harmless attribute was refused: %v", err)
	}
}
