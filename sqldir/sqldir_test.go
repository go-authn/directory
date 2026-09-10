package sqldir_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/sqldir"

	_ "modernc.org/sqlite" // a real database, in pure Go, in a temporary file
)

// A real database, not a stub: the queries are the caller's, so what is being
// tested is that ACTUAL SQL through an ACTUAL driver becomes the right
// identities. A fake DB would only prove that my idea of Scan matches my idea
// of Query.
func withDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/people.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, stmt := range []string{
		`create table people (name text, password text, nt_hash text, ssh_keys text)`,
		`create table memberships (group_name text, member text)`,
		`insert into people values ('alice', 'hunter2', null, null)`,
		`insert into people values ('bob', null, '8846f7eaee8fb117ad06bdd830b7586c', null)`,
		`insert into people values ('carol', null, null, 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH carol@laptop')`,
		`insert into people values ('dave', null, null, null)`,
		`insert into memberships values ('staff', 'alice')`,
		`insert into memberships values ('staff', 'bob')`,
		`insert into memberships values ('admins', 'alice')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	return db
}

func TestReadingPeopleFromADatabase(t *testing.T) {
	src, err := sqldir.New(withDB(t), sqldir.Queries{
		People: `select name, password, nt_hash, ssh_keys from people order by name`,
		Groups: `select group_name, member from memberships`,
	}, sqldir.Named("the staff database"))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 4 {
		t.Fatalf("%d people, want 4", len(ids))
	}

	// Each row's NULLs decide what that person can be proved with, which is
	// the whole point: a column that is empty is a protocol they cannot use.
	want := map[string]map[directory.Credential]bool{
		"alice": {directory.Password: true, directory.NTHash: true, directory.PublicKeys: false},
		"bob":   {directory.Password: false, directory.NTHash: true, directory.PublicKeys: false},
		"carol": {directory.Password: false, directory.NTHash: false, directory.PublicKeys: true},
		"dave":  {directory.Password: false, directory.NTHash: false, directory.PublicKeys: false},
	}
	for _, id := range ids {
		for c, expect := range want[id.Name()] {
			if got := id.Can(c); got != expect {
				t.Errorf("%s: Can(%v) = %v, want %v", id.Name(), c, got, expect)
			}
		}
		if id.Where() != "the staff database" {
			t.Errorf("%s came from %q", id.Name(), id.Where())
		}
	}

	// bob's NT hash is the one in the table, so SMB can be served to somebody
	// whose password this server never saw.
	for _, id := range ids {
		if id.Name() == "bob" {
			key, err := id.NTKey()
			if err != nil || len(key) != 16 {
				t.Errorf("bob's NT key: %x %v", key, err)
			}
		}
	}

	members, err := src.Members("staff")
	if err != nil || strings.Join(members, ",") != "alice,bob" {
		t.Errorf("staff = %v (%v)", members, err)
	}
	if _, err := src.Members("nobody"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("an unknown group gave %v", err)
	}
}

// A schema whose passwords are hashed hands the check back: the password never
// becomes something this process holds.
func TestAPasswordCheckTheCallerOwns(t *testing.T) {
	asked := ""
	src, err := sqldir.New(withDB(t), sqldir.Queries{
		People: `select name, password from people where password is not null`,
	}, sqldir.WithPasswordCheck(func(db *sql.DB, name, password string) error {
		asked = name
		if password == "hunter2" {
			return nil
		}
		return directory.ErrWrongPassword
	}))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("%d people", len(ids))
	}
	alice := ids[0]
	// The column is a hash this package will not look at, so alice cannot
	// serve SMB -- and Can says so.
	if alice.Can(directory.Password) || alice.Can(directory.NTHash) {
		t.Error("a hashed password was taken for a password")
	}
	if !alice.Can(directory.Verifier) {
		t.Error("the caller's check was not wired up")
	}
	if err := alice.Verify("hunter2"); err != nil || asked != "alice" {
		t.Errorf("verify = %v, asked about %q", err, asked)
	}
	if err := alice.Verify("wrong"); err == nil {
		t.Error("the wrong password passed")
	}
}

// What the queries must look like, said at construction rather than at the
// first login.
func TestQueriesThatCannotWork(t *testing.T) {
	db := withDB(t)
	if _, err := sqldir.New(nil, sqldir.Queries{People: "select 1"}); err == nil {
		t.Error("a nil database was accepted")
	}
	if _, err := sqldir.New(db, sqldir.Queries{}); err == nil {
		t.Error("a source with no people query was accepted")
	}
	src, err := sqldir.New(db, sqldir.Queries{People: `select name, password, nt_hash, ssh_keys, name from people`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Identities(); err == nil || !strings.Contains(err.Error(), "up to 4") {
		t.Errorf("a query with five columns gave %v", err)
	}
	// A hash that is not 16 bytes fails the READ, so a server does not start
	// and then refuse that person for no visible reason.
	if _, err := db.Exec(`insert into people values ('erin', null, 'nonsense', null)`); err != nil {
		t.Fatal(err)
	}
	src, _ = sqldir.New(db, sqldir.Queries{People: `select name, password, nt_hash from people where name = 'erin'`})
	if _, err := src.Identities(); err == nil || !strings.Contains(err.Error(), "erin") {
		t.Errorf("a mangled hash gave %v", err)
	}
}
