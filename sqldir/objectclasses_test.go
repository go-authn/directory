// SPDX-License-Identifier: BSD-3-Clause

package sqldir_test

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/sqldir"
)

// Declared classes reach every person and every group the database has, and
// nobody else.
func TestDeclaredObjectClassesFromADatabase(t *testing.T) {
	src, err := sqldir.New(withDB(t), sqldir.Queries{
		People: `select name, password from people order by name`,
		Groups: `select group_name, member from memberships`,
	},
		sqldir.WithObjectClasses("supannPerson", "eduPerson"),
		sqldir.WithObjectClasses("EDUPERSON", "schacContactLocation"),
		sqldir.WithGroupObjectClasses("supannGroupe"))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"supannPerson", "eduPerson", "schacContactLocation"}
	for _, id := range ids {
		if got := id.ObjectClasses(); !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", id.Name(), got, want)
		}
	}
	var gc directory.GroupObjectClasser = src
	if got, err := gc.GroupObjectClasses("staff"); err != nil || !slices.Equal(got.Names(), []string{"supannGroupe"}) {
		t.Errorf("staff = %v, %v", got.Names(), err)
	}
	if _, err := gc.GroupObjectClasses("nobody"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("a group the database does not have: %v", err)
	}

	// Without a declaration, nothing -- whatever the data holds.
	bare, err := sqldir.New(withDB(t), sqldir.Queries{People: `select name from people`,
		Groups: `select group_name, member from memberships`})
	if err != nil {
		t.Fatal(err)
	}
	ids, _ = bare.Identities()
	if got := ids[0].ObjectClasses(); len(got) != 0 {
		t.Errorf("undeclared, %s = %v", ids[0].Name(), got)
	}
	if got, err := bare.GroupObjectClasses("staff"); err != nil || got.Len() != 0 {
		t.Errorf("undeclared, staff = %v, %v", got.Names(), err)
	}
}

// ⛔ The planted negative: a database whose columns SAY objectClass, in
// every way a query could put it there, sets no class. A column so named in
// an attributes query is refused outright; one in the people query is not
// read as one.
func TestADatabaseColumnCannotSetAClass(t *testing.T) {
	db := withDB(t)
	for _, stmt := range []string{
		`create table oc (login text, oc text)`,
		`insert into oc values ('alice', 'supannPerson'), ('alice', 'posixAccount')`,
		`create table goc (team text, oc text)`,
		`insert into goc values ('staff', 'supannGroupe')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []sqldir.Queries{
		{People: `select name from people`, PeopleAttributes: `select login, oc as objectClass from oc`},
		{People: `select name from people`, PeopleAttributes: `select login, oc as "OBJECTCLASS" from oc`},
		{People: `select name from people`, Groups: `select group_name, member from memberships`,
			GroupAttributes: `select team, oc as objectClass from goc`},
	} {
		src, err := sqldir.New(db, q, sqldir.WithObjectClasses("eduPerson"))
		if err != nil {
			t.Fatal(err)
		}
		if q.GroupAttributes != "" {
			_, err = src.GroupAttributes("staff")
		} else {
			_, err = src.Identities()
		}
		if !errors.Is(err, directory.ErrAttributeName) {
			t.Errorf("%+v: an objectClass column gave %v", q, err)
		}
	}

	// A fifth column in the people query is refused by count, not read.
	src, _ := sqldir.New(db, sqldir.Queries{
		People: `select p.name, p.password, p.nt_hash, p.ssh_keys, null, o.oc as objectClass
		         from people p left join oc o on o.login = p.name`})
	if _, err := src.Identities(); err == nil {
		t.Error("a sixth column was read")
	}

	// The people query may carry a column the data calls objectClass in a
	// position this package reads as something else: it is never a class.
	src, _ = sqldir.New(db, sqldir.Queries{People: `select name as objectClass from people`},
		sqldir.WithObjectClasses("eduPerson"))
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if got := id.ObjectClasses(); !slices.Equal(got, []string{"eduPerson"}) {
			t.Errorf("%s = %v: the data reached the classes", id.Name(), got)
		}
	}
}

// New refuses a declaration that is not a descriptor, for people or groups,
// saying which.
func TestADeclaredClassThatIsNotADescriptor(t *testing.T) {
	q := sqldir.Queries{People: `select name from people`}
	for _, tc := range []struct {
		opt  sqldir.Option
		want string
	}{
		{sqldir.WithObjectClasses("eduPerson", "edu person"), "the people's object classes"},
		{sqldir.WithObjectClasses("1.3.6.1.4.1.5923.1.1.2"), "is an OID"},
		{sqldir.WithGroupObjectClasses("supannGroupe)"), "the groups' object classes"},
	} {
		_, err := sqldir.New(withDB(t), q, tc.opt)
		if !errors.Is(err, directory.ErrObjectClassName) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v, want %q", err, tc.want)
		}
	}
}

// Close closes the database only when the source was handed it.
func TestCloseClosesOnlyAHandedDatabase(t *testing.T) {
	q := sqldir.Queries{People: `select name from people`}
	for _, tc := range []struct {
		opts   []sqldir.Option
		closed bool
	}{
		{nil, false},
		{[]sqldir.Option{sqldir.ClosesDB()}, true},
	} {
		db := withDB(t)
		src, err := sqldir.New(db, q, tc.opts...)
		if err != nil {
			t.Fatal(err)
		}
		if err := src.Close(); err != nil {
			t.Fatal(err)
		}
		pingErr := db.Ping()
		if closed := pingErr != nil && strings.Contains(pingErr.Error(), "closed"); closed != tc.closed {
			t.Errorf("ClosesDB %v: after Close, Ping = %v", tc.closed, pingErr)
		}
	}
}
