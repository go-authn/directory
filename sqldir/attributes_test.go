// SPDX-License-Identifier: BSD-3-Clause

package sqldir_test

import (
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/sqldir"
)

// The schema a site already has: people in one table, their mail addresses in
// another (several each), groups with a gid, and a group nobody is listed in.
func withAttributesDB(t *testing.T) *sql.DB {
	t.Helper()
	db := withDB(t)
	for _, stmt := range []string{
		`create table accounts (login text, uid_number integer, home text, shell text)`,
		`create table mails (login text, address text)`,
		`create table teams (team text, gid integer, about text)`,
		`insert into accounts values ('alice', 1000, '/home/alice', '/bin/zsh')`,
		`insert into accounts values ('bob', 1001, '/home/bob', null)`,
		`insert into accounts values ('carol', 1002, '', null)`,
		`insert into accounts values ('zed', 1999, '/home/zed', null)`, // not in people
		`insert into mails values ('alice', 'alice@example.org')`,
		`insert into mails values ('alice', 'a.liddell@example.org')`,
		`insert into teams values ('staff', 100, 'the people who work here')`,
		`insert into teams values ('alice', 1000, null)`, // her own group, nobody listed
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	return db
}

const peopleAttributes = `
	select a.login, a.uid_number as uidNumber, a.home as homeDirectory,
	       a.shell as loginShell, m.address as mail
	from accounts a left join mails m on m.login = a.login
	order by a.login, m.rowid`

func TestPeopleAttributesFromADatabase(t *testing.T) {
	src, err := sqldir.New(withAttributesDB(t), sqldir.Queries{
		People:           `select name, password, nt_hash, ssh_keys from people order by name`,
		PeopleAttributes: peopleAttributes,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 4 {
		t.Fatalf("%d people, want 4: the attributes query names nobody new", len(ids))
	}
	by := map[string]directory.Attributes{}
	for _, id := range ids {
		by[id.Name()] = id.Attributes()
	}

	alice := by["alice"]
	// An integer column comes back as its decimal text: values are strings.
	if v := alice.Get("uidNumber"); !slices.Equal(v, []string{"1000"}) {
		t.Errorf("alice's uidNumber = %v", v)
	}
	// Two rows, two values -- and the columns that repeat on both rows are
	// kept once.
	if v := alice.Get("mail"); !slices.Equal(v, []string{"alice@example.org", "a.liddell@example.org"}) {
		t.Errorf("alice's mail = %v", v)
	}
	if v := alice.Get("homeDirectory"); len(v) != 1 {
		t.Errorf("alice's homeDirectory = %v, want one value though two rows carried it", v)
	}
	// The alias is the name, as written: SQLite keeps its case.
	if n := strings.Join(alice.Names(), ","); n != "uidNumber,homeDirectory,loginShell,mail" {
		t.Errorf("alice's attributes = %s", n)
	}

	// NULL is absent, and so is the empty string.
	if by["bob"].Get("loginShell") != nil || by["bob"].Get("mail") != nil {
		t.Errorf("bob = %v: a NULL became a value", by["bob"].Names())
	}
	if by["carol"].Get("homeDirectory") != nil {
		t.Error("carol's empty homeDirectory became a value")
	}
	// Somebody the attributes query does not name has none.
	if by["dave"].Len() != 0 {
		t.Errorf("dave = %v", by["dave"].Names())
	}

	// Credentials are untouched by all this.
	for _, id := range ids {
		if id.Name() == "alice" && !id.Can(directory.Password) {
			t.Error("alice lost her password to her attributes")
		}
	}
}

func TestGroupAttributesFromADatabase(t *testing.T) {
	src, err := sqldir.New(withAttributesDB(t), sqldir.Queries{
		People:          `select name from people`,
		Groups:          `select group_name, member from memberships`,
		GroupAttributes: `select team, gid as gidNumber, about as description from teams`,
	})
	if err != nil {
		t.Fatal(err)
	}
	var _ directory.GroupAttributer = src

	staff, err := src.GroupAttributes("staff")
	if err != nil {
		t.Fatal(err)
	}
	if v := staff.Get("gidnumber"); !slices.Equal(v, []string{"100"}) {
		t.Errorf("staff's gidNumber = %v", v)
	}
	// A group the groups query has and the attributes query does not:
	// a group, saying nothing.
	admins, err := src.GroupAttributes("admins")
	if err != nil || admins.Len() != 0 {
		t.Errorf("admins = %v, %v", admins.Names(), err)
	}
	if _, err := src.GroupAttributes("nobody"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("an unknown group gave %v", err)
	}

	// A group only the attributes query names EXISTS, with nobody in it --
	// a person's own primary group -- and every question agrees.
	own, err := src.GroupAttributes("alice")
	if err != nil || own.Get("description") != nil || own.Get("gidNumber")[0] != "1000" {
		t.Errorf("alice's group = %v, %v", own.Names(), err)
	}
	members, err := src.Members("alice")
	if err != nil || members == nil || len(members) != 0 {
		t.Errorf("Members(alice) = %#v, %v: want an empty group, not a missing one", members, err)
	}
	if _, err := directory.Expand([]string{"@alice"}, src); !errors.Is(err, directory.ErrEmptyGroup) {
		t.Errorf("Expand gave %v, want ErrEmptyGroup", err)
	}
	names, err := src.GroupNames()
	if err != nil || strings.Join(names, ",") != "admins,alice,staff" {
		t.Errorf("GroupNames = %v, %v", names, err)
	}

	// Only an attributes query, no groups query: the groups still exist.
	only, err := sqldir.New(withAttributesDB(t), sqldir.Queries{
		People:          `select name from people`,
		GroupAttributes: `select team, gid as gidNumber from teams`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := only.Members("staff"); err != nil || len(m) != 0 {
		t.Errorf("Members(staff) = %v, %v", m, err)
	}
	if _, err := only.Members("admins"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("admins = %v", err)
	}
	if names, err := only.GroupNames(); err != nil || strings.Join(names, ",") != "alice,staff" {
		t.Errorf("GroupNames = %v, %v", names, err)
	}

	// And with neither, GroupAttributes answers as Members always has.
	none, err := sqldir.New(withAttributesDB(t), sqldir.Queries{People: `select name from people`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := none.GroupAttributes("staff"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("no queries: %v", err)
	}
}

// Every way an attributes query can be wrong, refused with the column or the
// row it is -- and refused before any person is handed out.
func TestAttributesQueriesThatCannotWork(t *testing.T) {
	db := withAttributesDB(t)
	for _, tc := range []struct {
		name, query, want string
	}{
		{"a credential, by alias", `select name, password as userPassword from people`, `column 2: directory: not an attribute this package carries: "userPassword" holds a secret`},
		{"an NT hash, by alias", `select name, nt_hash as sambaNTPassword from people`, `"sambaNTPassword" holds a secret`},
		{"keys, which have their own column", `select name, ssh_keys as sshPublicKey from people`, "WithPublicKeys"},
		{"the name, again", `select name, name as uid from people`, "derived by the server"},
		{"an unaliased expression", `select login, upper(shell) from accounts`, `"upper(shell)" is not an attribute description`},
		{"an alias with a space", `select login, home as "home directory" from accounts`, "not an attribute description"},
		{"only a name", `select login from accounts`, "returns 1 column(s)"},
		{"no name", `select null, home as homeDirectory from accounts`, "a row with no name"},
		{"a query that is not one", `select from nowhere`, "reading the people's attributes"},
		{"a value that will not scan", `select login, 1 as x from accounts union all select 'alice', x'ff'`, ""},
	} {
		src, err := sqldir.New(db, sqldir.Queries{People: `select name from people`, PeopleAttributes: tc.query})
		if err != nil {
			t.Fatal(err)
		}
		ids, err := src.Identities()
		if tc.want == "" {
			// SQLite hands a blob to a string happily; this one is about
			// NOT failing on bytes, which is what an LDAP value is.
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
		if ids != nil {
			t.Errorf("%s: people were handed out by a refused configuration", tc.name)
		}
	}

	// The same for groups, through every question that reads the query.
	src, err := sqldir.New(db, sqldir.Queries{
		People:          `select name from people`,
		GroupAttributes: `select team, gid as gidNumber, about as memberUid from teams`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.GroupAttributes("staff"); err == nil || !strings.Contains(err.Error(), "is membership") {
		t.Errorf("GroupAttributes: %v", err)
	}
	if _, err := src.Members("staff"); err == nil || !strings.Contains(err.Error(), "is membership") {
		t.Errorf("Members: %v", err)
	}
	if _, err := src.GroupNames(); err == nil {
		t.Error("GroupNames read a refused query")
	}

	// A broken groups query is still reported as one, through GroupAttributes.
	broken, err := sqldir.New(db, sqldir.Queries{People: `select name from people`, Groups: `select nonsense`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broken.GroupAttributes("staff"); err == nil || errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("a broken groups query gave %v", err)
	}
	brokenAttrs, err := sqldir.New(db, sqldir.Queries{People: `select name from people`,
		Groups: `select group_name, member from memberships`, GroupAttributes: `select nonsense`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := brokenAttrs.Members("nobody"); err == nil || errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("a broken attributes query gave %v", err)
	}
}

// ⛔ Backward compatibility, asserted: the positional people query still
// stops at five columns. The sixth is not an attribute -- attributes come by
// NAME, in their own query -- and a sixth column quietly read as one would
// turn every existing query with an extra column into a publication.
func TestThePositionalQueryIsUnchanged(t *testing.T) {
	src, err := sqldir.New(withAttributesDB(t), sqldir.Queries{
		People: `select name, password, nt_hash, ssh_keys, null, 'x' as mail from people`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Identities(); err == nil || !strings.Contains(err.Error(), "it may return up to 5") {
		t.Errorf("a sixth column gave %v", err)
	}
}
