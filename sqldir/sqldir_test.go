package sqldir_test

import (
	"bytes"
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
	// Six columns is one more than there are credentials to fill.
	src, err := sqldir.New(db, sqldir.Queries{
		People: `select name, password, nt_hash, ssh_keys, name, name from people`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Identities(); err == nil || !strings.Contains(err.Error(), "up to 5") {
		t.Errorf("a query with six columns gave %v", err)
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

// Listing the groups, from the same query that answers about one.
func TestGroupNamesFromADatabase(t *testing.T) {
	db := withDB(t)
	src, err := sqldir.New(db, sqldir.Queries{
		People: "select name from people", Groups: "select group_name, member from memberships",
	})
	if err != nil {
		t.Fatal(err)
	}
	names, err := src.GroupNames()
	if err != nil {
		t.Fatal(err)
	}
	// Sorted and without repeats: staff has two rows in the table.
	if strings.Join(names, ",") != "admins,staff" {
		t.Errorf("GroupNames() = %v", names)
	}

	// A source with NO groups query cannot list groups, and that is not an
	// error: another source in the set may be the one holding them.
	bare, err := sqldir.New(db, sqldir.Queries{People: "select name from people"})
	if err != nil {
		t.Fatal(err)
	}
	if names, err := bare.GroupNames(); err != nil || len(names) != 0 {
		t.Errorf("GroupNames() with no groups query = %v, %v", names, err)
	}
	// Asking about a group by name, though, IS an error there: an empty
	// answer would grant nothing to nobody and read like a working one.
	if _, err := bare.Members("staff"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("Members() with no groups query = %v", err)
	}
}

// A groups query that cannot run is reported, not read as "no groups".
func TestGroupNamesReportsABrokenQuery(t *testing.T) {
	src, err := sqldir.New(withDB(t), sqldir.Queries{
		People: "select name from people", Groups: "select * from absent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.GroupNames(); err == nil {
		t.Error("a query that cannot run was read as no groups")
	}
}

// A fifth column: the secret behind a one-time code.
func TestAOneTimeCodeSecretFromADatabase(t *testing.T) {
	db := withDB(t)
	if _, err := db.Exec(`alter table people add column totp_secret text`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`update people set totp_secret = 'JBSWY3DPEHPK3PXP' where name = 'alice'`); err != nil {
		t.Fatal(err)
	}
	src, err := sqldir.New(db, sqldir.Queries{
		People: "select name, password, nt_hash, ssh_keys, totp_secret from people",
	})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	for _, id := range ids {
		switch id.Name() {
		case "alice":
			seen++
			if !id.Can(directory.TOTPSecret) {
				t.Error("alice's second factor did not arrive")
			}
			want, _ := directory.ParseTOTPSecret("JBSWY3DPEHPK3PXP")
			if got := id.TOTPSecret(); !bytes.Equal(got, want) {
				t.Errorf("alice's secret = %v", got)
			}
		default:
			// A NULL column is a person with no second factor, which is a
			// legitimate state and not an error.
			if id.Can(directory.TOTPSecret) {
				t.Errorf("%s has a second factor and the column was NULL", id.Name())
			}
		}
	}
	if seen != 1 {
		t.Error("alice was not read")
	}

	// A secret that does not parse is REFUSED, not dropped: dropping it turns
	// "this person has a second factor" into "this person has none".
	if _, err := db.Exec(`update people set totp_secret = 'not base 32!' where name = 'bob'`); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Identities(); err == nil {
		t.Error("a secret that is not base32 was read as no secret")
	} else if strings.Contains(err.Error(), "not base 32") {
		t.Errorf("the error quotes the secret: %v", err)
	}
}
