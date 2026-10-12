// SPDX-License-Identifier: BSD-3-Clause

package hcldir_test

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
	"github.com/go-authn/directory/ldaptest"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// What a program decodes: the blocks, the way authnd and fileshare do, with
// gohcl. The attributes field has to survive THAT, not only a struct literal.
type config struct {
	Users  []hcldir.UserBlock  `hcl:"user,block"`
	Groups []hcldir.GroupBlock `hcl:"group,block"`
}

func decode(t *testing.T, src string) config {
	t.Helper()
	f, diags := hclsyntax.ParseConfig([]byte(src), "test.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	var c config
	if diags := gohcl.DecodeBody(f.Body, nil, &c); diags.HasErrors() {
		t.Fatal(diags)
	}
	return c
}

const attributesHCL = `
user "alice" {
  password   = "s3cret"
  attributes = {
    uidNumber     = "1000"
    gidNumber     = "100"
    homeDirectory = "/home/alice"
    loginShell    = "/bin/zsh"
    gecos         = "Alice Liddell"
    mail          = ["alice@example.org", "a.liddell@example.org"]
    "description;lang-fr" = "une personne"
    displayName   = null
  }
}

user "bob" {
  password = "hunter2"
}

group "staff" {
  members    = ["alice", "bob"]
  attributes = { gidNumber = "100", description = "the people who work here" }
}

group "empty" {
  members = []
}
`

func TestUserAndGroupBlocksCarryAttributes(t *testing.T) {
	c := decode(t, attributesHCL)
	src, err := hcldir.File(c.Users, c.Groups)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	alice := ids[0].Attributes()
	for name, want := range map[string][]string{
		"uidNumber":           {"1000"},
		"homeDirectory":       {"/home/alice"},
		"loginShell":          {"/bin/zsh"},
		"gecos":               {"Alice Liddell"},
		"mail":                {"alice@example.org", "a.liddell@example.org"},
		"description;lang-fr": {"une personne"},
	} {
		if got := alice.Get(name); !slices.Equal(got, want) {
			t.Errorf("alice's %s = %v, want %v", name, got, want)
		}
	}
	if alice.Get("displayName") != nil {
		t.Error("an attribute set to null arrived")
	}
	if !ids[0].Can(directory.Password) {
		t.Error("alice's password went missing beside her attributes")
	}
	if ids[1].Attributes().Len() != 0 {
		t.Errorf("bob = %v", ids[1].Attributes().Names())
	}

	ga, ok := src.(directory.GroupAttributer)
	if !ok {
		t.Fatal("the file's source cannot describe its groups")
	}
	staff, err := ga.GroupAttributes("staff")
	if err != nil || staff.Get("gidNumber")[0] != "100" || staff.Get("description") == nil {
		t.Errorf("staff = %v, %v", staff.Names(), err)
	}
	if a, err := ga.GroupAttributes("empty"); err != nil || a.Len() != 0 {
		t.Errorf("empty = %v, %v", a.Names(), err)
	}
	if _, err := ga.GroupAttributes("nobody"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("an undeclared group gave %v", err)
	}
}

// Each mistake an administrator can write, refused with the block it is in
// and what to do -- and refused for the whole file, since a server started
// without a person's attributes publishes them wrong.
func TestAttributesABlockCannotHave(t *testing.T) {
	for _, tc := range []struct {
		name, hcl, want string
	}{
		{"a password, as an attribute", `user "a" { attributes = { userPassword = "x" } }`,
			`user "a": attributes: directory: not an attribute this package carries: "userPassword" holds a secret`},
		{"an NT hash, as an attribute", `user "a" { attributes = { sambaNTPassword = "8846f7eaee8fb117ad06bdd830b7586c" } }`, "holds a secret"},
		{"keys, which have authorized_keys", `user "a" { attributes = { sshPublicKey = "ssh-ed25519 AAAA" } }`, "WithPublicKeys"},
		{"the name, which is the label", `user "a" { attributes = { uid = "a" } }`, "derived by the server"},
		{"membership, which is members", `group "g" {
			members = ["a"]
			attributes = { memberUid = ["b"] }
		}`, `group "g": attributes:`},
		{"a number", `user "a" { attributes = { uidNumber = 1000 } }`, `uidNumber is the number 1000: write it as a string, "1000"`},
		{"a number in a list", `user "a" { attributes = { mail = ["a@x.example", 7] } }`, "mail is the number 7"},
		{"a bool", `user "a" { attributes = { loginShell = true } }`, "loginShell is bool"},
		{"a nested map", `user "a" { attributes = { gecos = { a = "b" } } }`, "gecos is object"},
		{"a null in a list", `user "a" { attributes = { mail = ["a@x.example", null] } }`, "mail has a null among its values"},
		{"an empty value", `user "a" { attributes = { mail = "" } }`, `"mail" has an empty value`},
		{"no values", `user "a" { attributes = { mail = [] } }`, `"mail" has no values`},
		{"not a map", `user "a" { attributes = ["mail"] }`, "attributes is a map of names to values"},
		{"an OID", `user "a" { attributes = { "2.5.4.35" = "x" } }`, "is an OID"},
	} {
		c := decode(t, tc.hcl)
		_, err := hcldir.File(c.Users, c.Groups)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// A program building blocks by hand rather than decoding: a cty value, and
// the zero one is no attributes.
func TestABlockBuiltByHand(t *testing.T) {
	src, err := hcldir.File([]hcldir.UserBlock{
		{Name: "alice", Attributes: cty.ObjectVal(map[string]cty.Value{
			"mail": cty.ListVal([]cty.Value{cty.StringVal("alice@example.org")}),
		})},
		{Name: "bob"}, // cty.NilVal
		{Name: "carol", Attributes: cty.NullVal(cty.DynamicPseudoType)},
		{Name: "dave", Attributes: cty.MapVal(map[string]cty.Value{"gecos": cty.StringVal("Dave")})},
	}, []hcldir.GroupBlock{{Name: "staff", Members: []string{"alice"}}})
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := src.Identities()
	if ids[0].Attributes().Get("mail") == nil || ids[1].Attributes().Len() != 0 ||
		ids[2].Attributes().Len() != 0 || ids[3].Attributes().Get("gecos") == nil {
		t.Errorf("%v %v %v %v", ids[0].Attributes().Names(), ids[1].Attributes().Names(),
			ids[2].Attributes().Names(), ids[3].Attributes().Names())
	}
	if _, err := hcldir.File([]hcldir.UserBlock{{Name: "x",
		Attributes: cty.UnknownVal(cty.Map(cty.String))}}, nil); err == nil {
		t.Error("an unknown value was accepted")
	}
}

// SetPassword rewrites the block, and the attributes in it come through: it
// edits tokens, so nothing it does not touch may change.
func TestSetPasswordKeepsTheAttributes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "people.hcl")
	if err := os.WriteFile(path, []byte(attributesHCL), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hcldir.SetPassword([]string{path}, "alice", "n3w"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c := decode(t, string(raw))
	src, err := hcldir.File(c.Users, c.Groups)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := src.Identities()
	if ids[0].Verify("n3w") != nil || ids[0].Attributes().Get("uidNumber")[0] != "1000" || len(ids[0].Attributes().Get("mail")) != 2 {
		t.Errorf("after SetPassword: %v", ids[0].Attributes().Names())
	}
}

// The SQL block's two queries, through Open: the attributes arrive, and the
// opened source can still DESCRIBE its groups -- the wrapper that closes the
// database is exactly where an optional interface goes missing.
func TestASQLBlockReadsAttributes(t *testing.T) {
	b := hcldir.Block{
		Kind: "sql", Driver: "sqlite", DSNFile: sqliteWith(t, `
create table staff (login text primary key, secret text, uid_number integer, mail text);
insert into staff values ('dora', 'hunter2', 1000, 'dora@example.org'), ('eli', 'swordfish', 1001, null);
create table teams (team text, member text);
insert into teams values ('engineers', 'dora');
create table team_ids (team text, gid integer);
insert into team_ids values ('engineers', 500), ('dora', 1000);
`),
		UsersQuery:            "select login, secret from staff",
		GroupsQuery:           "select team, member from teams",
		UsersAttributesQuery:  "select login, uid_number as uidNumber, mail from staff",
		GroupsAttributesQuery: "select team, gid as gidNumber from team_ids",
	}
	src, err := hcldir.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	defer src.(interface{ Close() error }).Close()

	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id.Attributes().Get("uidNumber") == nil {
			t.Errorf("%s has no uidNumber", id.Name())
		}
	}
	ga, ok := src.(directory.GroupAttributer)
	if !ok {
		t.Fatal("the opened source cannot describe its groups: the wrapper dropped GroupAttributer")
	}
	if _, ok := src.(directory.GroupLister); !ok {
		t.Fatal("the opened source cannot list its groups any more")
	}
	if a, err := ga.GroupAttributes("engineers"); err != nil || a.Get("gidNumber")[0] != "500" {
		t.Errorf("engineers = %v, %v", a.Names(), err)
	}
	if m, err := src.Members("dora"); err != nil || len(m) != 0 {
		t.Errorf("dora's own group = %v, %v", m, err)
	}
}

func TestAnLDAPBlockCopiesAttributes(t *testing.T) {
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			"dora": {Password: "hunter2", Extra: map[string][]string{
				"mail": {"dora@example.org"}, "uidNumber": {"1000"}, "telephoneNumber": {"+33 1 23 45 67 89"},
			}},
		},
		Groups:     map[string][]string{"engineers": {"dora"}},
		GroupExtra: map[string]map[string][]string{"engineers": {"gidNumber": {"500"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	src, err := hcldir.Open(hcldir.Block{
		Kind: "ldap", URL: d.URL, BaseDN: d.PeopleDN, GroupBaseDN: d.GroupsDN,
		BindDN: d.ReaderDN, BindPasswordFile: write(t, "bind.pw", d.ReaderPassword),
		Attributes: []string{"mail", "uidNumber"}, GroupAttributes: []string{"gidNumber"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	a := ids[0].Attributes()
	if a.Get("mail") == nil || a.Get("uidNumber")[0] != "1000" {
		t.Errorf("dora = %v", a.Names())
	}
	if a.Get("telephoneNumber") != nil {
		t.Error("an attribute nobody asked to copy was copied")
	}
	g, err := src.(directory.GroupAttributer).GroupAttributes("engineers")
	if err != nil || g.Get("gidNumber")[0] != "500" {
		t.Errorf("engineers = %v, %v", g.Names(), err)
	}
}

// Refused by Check, before anything connects: a credential to copy, and the
// fields of one kind written into the other.
func TestBlocksWhoseAttributesCannotWork(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block hcldir.Block
		want  string
	}{
		{"a password to copy", hcldir.Block{Kind: "ldap", URL: "ldaps://h", BaseDN: "dc=x",
			Attributes: []string{"mail", "userPassword"}}, `users "ldap" attributes: directory: not an attribute this package carries: "userPassword" holds a secret`},
		{"membership to copy", hcldir.Block{Kind: "ldap", URL: "ldaps://h", BaseDN: "dc=x",
			GroupAttributes: []string{"memberUid"}}, `users "ldap" group_attributes:`},
		{"a query in an ldap block", hcldir.Block{Kind: "ldap", URL: "ldaps://h", BaseDN: "dc=x",
			UsersAttributesQuery: "select 1"}, "users_attributes in it, which belongs to a sql block"},
		{"a group query in an ldap block", hcldir.Block{Kind: "ldap", URL: "ldaps://h", BaseDN: "dc=x",
			GroupsAttributesQuery: "select 1"}, "groups_attributes in it, which belongs to a sql block"},
		{"a list in a sql block", hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFile: "/d", UsersQuery: "select 1",
			Attributes: []string{"mail"}, GroupAttributes: []string{"gidNumber"}}, "attributes and group_attributes in it, which belongs to an ldap block"},
	} {
		if err := tc.block.Check(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}
