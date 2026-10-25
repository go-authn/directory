// SPDX-License-Identifier: BSD-3-Clause

package hcldir_test

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
	"github.com/go-authn/directory/ldaptest"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// usersConfig is the `users` blocks, decoded the way a program decodes them.
type usersConfig struct {
	Users []hcldir.Block `hcl:"users,block"`
}

func decodeUsers(t *testing.T, src string) usersConfig {
	t.Helper()
	f, diags := hclsyntax.ParseConfig([]byte(src), "authnd.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	var c usersConfig
	if diags := gohcl.DecodeBody(f.Body, nil, &c); diags.HasErrors() {
		t.Fatal(diags)
	}
	return c
}

const classesHCL = `
user "alice" {
  password       = "s3cret"
  object_classes = ["supannPerson", "eduPerson", "EDUPERSON", "schacContactLocation"]
}

user "bob" {
  password = "hunter2"
}

group "staff" {
  members        = ["alice", "bob"]
  object_classes = ["supannGroupe"]
}

group "empty" {
  members = []
}
`

func TestFileBlocksDeclareObjectClasses(t *testing.T) {
	c := decode(t, classesHCL)
	src, err := hcldir.File(c.Users, c.Groups)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if got := ids[0].ObjectClasses(); !slices.Equal(got, []string{"supannPerson", "eduPerson", "schacContactLocation"}) {
		t.Errorf("alice = %v", got)
	}
	if got := ids[1].ObjectClasses(); len(got) != 0 {
		t.Errorf("bob, who declares nothing, = %v", got)
	}
	gc, ok := src.(directory.GroupObjectClasser)
	if !ok {
		t.Fatal("the file's source cannot say its groups' classes")
	}
	if got, err := gc.GroupObjectClasses("staff"); err != nil || !slices.Equal(got.Names(), []string{"supannGroupe"}) {
		t.Errorf("staff = %v, %v", got.Names(), err)
	}
	if got, err := gc.GroupObjectClasses("empty"); err != nil || got.Len() != 0 {
		t.Errorf("empty = %v, %v", got.Names(), err)
	}
	if _, err := gc.GroupObjectClasses("nobody"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("an undeclared group: %v", err)
	}
}

// A refusal names the file, the line and the block, as written.
func TestAFileBlockClassIsRefusedWhereItIsWritten(t *testing.T) {
	for _, tc := range []struct{ name, hcl, want string }{
		{"a space", "user \"a\" {\n  object_classes = [\"edu Person\"]\n}",
			`test.hcl:2,20-34: user "a" object_classes: directory: not an object class name: "edu Person" is not a descriptor`},
		{"an OID", "group \"g\" {\n  members = []\n  object_classes = [\"1.3.6.1.4.1.7135.1.2.2.1\"]\n}",
			`test.hcl:3,20-48: group "g" object_classes: directory: not an object class name: "1.3.6.1.4.1.7135.1.2.2.1" is an OID`},
		{"a parenthesis", "user \"a\" {\n  object_classes = [\"x)(y\"]\n}", `"x)(y" is not a descriptor`},
		{"a quote", "user \"a\" {\n  object_classes = [\"x'y\"]\n}", `is not a descriptor`},
		{"empty", "user \"a\" {\n  object_classes = [\"\"]\n}", `an object class needs a name`},
	} {
		c := decode(t, tc.hcl)
		_, err := hcldir.File(c.Users, c.Groups)
		if !errors.Is(err, directory.ErrObjectClassName) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
	// Built by hand: no position, and the block still named.
	_, err := hcldir.File([]hcldir.UserBlock{{Name: "a", ObjectClasses: []string{"x y"}}}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), `user "a" object_classes:`) {
		t.Errorf("by hand: %v", err)
	}
}

// Both kinds of `users` block take both lists, and Check refuses a bad name
// at its position before anything connects.
func TestUsersBlocksRefuseAClassWhereItIsWritten(t *testing.T) {
	for _, tc := range []struct{ name, hcl, want string }{
		{"ldap, people", "users \"ldap\" {\n  url = \"ldaps://h\"\n  base_dn = \"dc=x\"\n  object_classes = [\"eduPerson\", \"edu(Person)\"]\n}",
			`authnd.hcl:4,20-48: users "ldap" object_classes: directory: not an object class name: "edu(Person)"`},
		{"ldap, groups", "users \"ldap\" {\n  url = \"ldaps://h\"\n  base_dn = \"dc=x\"\n  group_object_classes = [\"2.5.6.9\"]\n}",
			`authnd.hcl:4,26-37: users "ldap" group_object_classes: directory: not an object class name: "2.5.6.9" is an OID`},
		{"sql, people", "users \"sql\" {\n  dsn_file = \"/d\"\n  users = \"select 1\"\n  object_classes = [\"edu Person\"]\n}",
			`authnd.hcl:4,20-34: users "sql" object_classes:`},
		{"sql, groups", "users \"sql\" {\n  dsn_file = \"/d\"\n  users = \"select 1\"\n  group_object_classes = [\"\\\"g\\\"\"]\n}",
			`authnd.hcl:4,26-35: users "sql" group_object_classes:`},
	} {
		c := decodeUsers(t, tc.hcl)
		err := c.Users[0].Check()
		if !errors.Is(err, directory.ErrObjectClassName) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
		if _, oerr := hcldir.OpenAll(c.Users); !errors.Is(oerr, directory.ErrObjectClassName) {
			t.Errorf("%s: OpenAll gave %v", tc.name, oerr)
		}
	}
	// A block built by hand says no place.
	err := hcldir.Block{Kind: "ldap", URL: "ldaps://h", BaseDN: "dc=x", ObjectClasses: []string{"a b"}}.Check()
	if err == nil || !strings.HasPrefix(err.Error(), `users "ldap" object_classes:`) {
		t.Errorf("by hand: %v", err)
	}
}

// The sql block, decoded and opened: every person and every group carries
// the block's declaration -- and a column called objectClass is refused, not
// read. The opened source is the sqldir source itself, with every optional
// interface, and closing the set closes the database.
func TestASQLBlockDeclaresObjectClasses(t *testing.T) {
	dsn := sqliteWith(t, `
create table staff (login text primary key, secret text, oc text);
insert into staff values ('dora', 'hunter2', 'posixAccount'), ('eli', 'swordfish', 'supannPerson');
create table teams (team text, member text);
insert into teams values ('engineers', 'dora');
`)
	c := decodeUsers(t, fmt.Sprintf(`
users "sql" {
  driver               = "sqlite"
  dsn_file             = %q
  users                = "select login, secret from staff"
  groups               = "select team, member from teams"
  object_classes       = ["supannPerson", "eduPerson"]
  group_object_classes = ["supannGroupe"]
}`, dsn))
	srcs, err := hcldir.OpenAll(c.Users)
	if err != nil {
		t.Fatal(err)
	}
	set := directory.NewSet(srcs...)
	ids, err := set.Identities()
	if err != nil || len(ids) != 2 {
		t.Fatal(ids, err)
	}
	for _, id := range ids {
		if got := id.ObjectClasses(); !slices.Equal(got, []string{"supannPerson", "eduPerson"}) {
			t.Errorf("%s = %v", id.Name(), got)
		}
	}
	if got, err := set.GroupObjectClasses("engineers"); err != nil || !slices.Equal(got.Names(), []string{"supannGroupe"}) {
		t.Errorf("engineers = %v, %v", got.Names(), err)
	}
	src := srcs[0]
	if _, ok := src.(directory.GroupLister); !ok {
		t.Error("the opened source cannot list its groups")
	}
	if _, ok := src.(directory.GroupAttributer); !ok {
		t.Error("the opened source cannot describe its groups")
	}
	if _, ok := src.(directory.GroupObjectClasser); !ok {
		t.Error("the opened source cannot say its groups' classes")
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Identities(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("after the set closed, the database answered: %v", err)
	}

	// The planted negative, through the block: a column the data calls
	// objectClass.
	b := c.Users[0]
	b.DSNFile = dsn
	b.UsersAttributesQuery = `select login, oc as objectClass from staff`
	opened, err := hcldir.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.(interface{ Close() error }).Close()
	if _, err := opened.Identities(); !errors.Is(err, directory.ErrAttributeName) {
		t.Errorf("an objectClass column gave %v", err)
	}
}

// The ldap block, decoded and opened, against an LDAP server whose entries
// carry objectClass values of their own: only the declaration comes through.
func TestAnLDAPBlockDeclaresObjectClasses(t *testing.T) {
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			"dora": {Password: "hunter2", ObjectClasses: []string{"top", "account", "supannPerson"}},
		},
		Groups:     map[string][]string{"engineers": {"dora"}},
		GroupExtra: map[string]map[string][]string{"engineers": {"objectClass": {"supannGroupe"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	c := decodeUsers(t, fmt.Sprintf(`
users "ldap" {
  url                  = %q
  base_dn              = %q
  group_base_dn        = %q
  bind_dn              = %q
  bind_password_file   = %q
  object_classes       = ["eduPerson"]
  group_object_classes = ["eduOrg"]
}`, d.URL, d.PeopleDN, d.GroupsDN, d.ReaderDN, write(t, "bind.pw", d.ReaderPassword)))
	src, err := hcldir.Open(c.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil || len(ids) != 1 {
		t.Fatal(ids, err)
	}
	if got := ids[0].ObjectClasses(); !slices.Equal(got, []string{"eduPerson"}) {
		t.Errorf("dora = %v: the entry's supannPerson must not come through", got)
	}
	got, err := src.(directory.GroupObjectClasser).GroupObjectClasses("engineers")
	if err != nil || !slices.Equal(got.Names(), []string{"eduOrg"}) {
		t.Errorf("engineers = %v, %v", got.Names(), err)
	}
}

// A file group and a directory group of one name: the file is first, and
// decides when it declares; when it does not, the directory's block does.
func TestASetCombinesAFileAndAUsersBlock(t *testing.T) {
	dsn := sqliteWith(t, `
create table staff (login text);
insert into staff values ('dora');
create table teams (team text, member text);
insert into teams values ('engineers', 'dora'), ('lab', 'dora');
`)
	db, err := hcldir.Open(hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFile: dsn,
		UsersQuery: "select login from staff", GroupsQuery: "select team, member from teams",
		GroupObjectClasses: []string{"supannGroupe"}})
	if err != nil {
		t.Fatal(err)
	}
	c := decode(t, `
group "engineers" {
  members        = ["alice"]
  object_classes = ["eduOrg"]
}
group "lab" {
  members = ["alice"]
}`)
	file, err := hcldir.File(c.Users, c.Groups)
	if err != nil {
		t.Fatal(err)
	}
	set := directory.NewSet(file, db)
	defer set.Close()
	for group, want := range map[string][]string{
		"engineers": {"eduOrg"},       // both declare: the file, first, wins whole
		"lab":       {"supannGroupe"}, // the file declares nothing: the block decides
	} {
		got, err := set.GroupObjectClasses(group)
		if err != nil || !slices.Equal(got.Names(), want) {
			t.Errorf("%s = %v, %v; want %v", group, got.Names(), err, want)
		}
	}
}
