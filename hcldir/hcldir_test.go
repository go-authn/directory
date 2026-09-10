package hcldir_test

import (
	"database/sql"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
	"github.com/go-authn/directory/ldaptest"

	_ "modernc.org/sqlite" // the driver is the PROGRAM's choice; here, this one
)

// A block that cannot be what it says it is, refused before anything connects.
//
// An unreachable directory and a mistyped one produce the same symptom -- a
// server that will not start -- and only one of them is fixed by looking at
// the network. So Check answers without opening anything.
func TestBlocksThatCannotBeWhatTheySay(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block hcldir.Block
		want  string
	}{
		{
			"a kind nobody has",
			hcldir.Block{Kind: "kerberos"},
			`there is no "kerberos" directory here`,
		},
		{
			"ldap fields in a sql block",
			hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFile: "/d", URL: "ldap://h", BindDN: "cn=r"},
			"bind_dn and url in it, which belongs to an ldap block",
		},
		{
			"sql fields in an ldap block",
			hcldir.Block{Kind: "ldap", URL: "ldap://h", Driver: "sqlite"},
			"driver in it, which belongs to a sql block",
		},
		{
			// The one that matters: a url is printed by a server saying where
			// somebody came from, by the LDAP package's errors, and by
			// whatever collects that output.
			"a bind password in the url",
			hcldir.Block{Kind: "ldap", URL: "ldap://cn=reader:hunter2@h"},
			"credentials in its url",
		},
		{
			"a sql block with no dsn_file",
			hcldir.Block{Kind: "sql", Driver: "sqlite", UsersQuery: "select 1"},
			"a dsn_file is needed",
		},
		{
			"a sql block with no query",
			hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFile: "/d"},
			"no query for the people",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.block.Check()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Check() = %v, want one mentioning %q", err, tc.want)
			}
			// Open checks first, so it refuses the same way.
			if _, err := hcldir.Open(tc.block); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Open() = %v, want one mentioning %q", err, tc.want)
			}
			// And never the secret it is refusing.
			if err != nil && strings.Contains(err.Error(), "hunter2") {
				t.Error("the refusal printed the password it was refusing")
			}
		})
	}
}

// People and groups out of a real database, through a real block.
func TestASQLBlockReadsADatabase(t *testing.T) {
	b := hcldir.Block{
		Kind: "sql", Driver: "sqlite", DSNFile: sqliteWith(t, `
create table staff (login text primary key, secret text);
insert into staff values ('dora', 'hunter2'), ('eli', 'swordfish');
create table teams (team text, member text);
insert into teams values ('engineers', 'dora');
`),
		UsersQuery:  "select login, secret from staff",
		GroupsQuery: "select team, member from teams",
	}
	src, err := hcldir.Open(b)
	if err != nil {
		t.Fatal(err)
	}
	if got := src.Describe(); got != "a sqlite database" {
		t.Errorf("Describe() = %q", got)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("%d people, want 2", len(ids))
	}
	for _, id := range ids {
		// A cleartext column is a password, and a password answers everything.
		if !id.Can(directory.Password) || !id.Can(directory.NTHash) {
			t.Errorf("%s: %v", id.Name(), id)
		}
	}
	members, err := src.Members("engineers")
	if err != nil || len(members) != 1 || members[0] != "dora" {
		t.Errorf("Members(engineers) = %v, %v", members, err)
	}
	// ⛔ And it can still LIST them. Opening a block wraps the source so the
	// database is closed with it, and a wrapper embedding the Source
	// INTERFACE silently drops every optional interface the concrete type had
	// -- which is how a server that publishes this directory came to publish
	// no groups, with nothing anywhere saying why.
	lister, ok := src.(directory.GroupLister)
	if !ok {
		t.Fatal("the opened source cannot list its groups: the wrapper dropped GroupLister")
	}
	if names, err := lister.GroupNames(); err != nil || len(names) != 1 || names[0] != "engineers" {
		t.Errorf("GroupNames() = %v, %v", names, err)
	}

	// The database is closed with the source, because this package opened it.
	c, ok := src.(interface{ Close() error })
	if !ok {
		t.Fatal("the source cannot be closed, so the database it opened never is")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := src.Identities(); err == nil {
		t.Error("the database answered after it was closed")
	}
}

// A driver name that is RIGHT, in a binary that does not have it.
//
// This test binary imports modernc.org/sqlite and nothing else, so postgres
// and mysql are exactly that case -- and the message has to be the one that
// leads somewhere, since "unknown driver" reads like a typo in the
// configuration when the fix is one blank import in the program.
func TestADriverThisBinaryDoesNotHave(t *testing.T) {
	for _, name := range []string{"postgres", "mysql"} {
		_, err := hcldir.Open(hcldir.Block{
			Kind: "sql", Driver: name, DSNFile: write(t, "dsn", "whatever"),
			UsersQuery: "select 1",
		})
		if err == nil || !strings.Contains(err.Error(), "this binary registered no") {
			t.Errorf("%s: %v, want one saying the binary has no such driver", name, err)
		}
		if err != nil && !strings.Contains(err.Error(), "import one") {
			t.Errorf("%s: the message does not say what to do: %v", name, err)
		}
	}
	// A name nobody has is the other message, because it is a different
	// mistake with a different fix.
	_, err := hcldir.Open(hcldir.Block{Kind: "sql", Driver: "oracle", DSNFile: "/d", UsersQuery: "select 1"})
	if err == nil || !strings.Contains(err.Error(), `no "oracle" driver here`) {
		t.Errorf("oracle: %v", err)
	}
	// And no driver at all names the ones there are.
	_, err = hcldir.Open(hcldir.Block{Kind: "sql", DSNFile: "/d", UsersQuery: "select 1"})
	if err == nil || !strings.Contains(err.Error(), "a driver is needed") {
		t.Errorf("no driver: %v", err)
	}
}

// A DSN file that is not there is a refusal naming the file, not a database
// error naming nothing.
func TestASecretFileThatIsNotThere(t *testing.T) {
	_, err := hcldir.Open(hcldir.Block{
		Kind: "sql", Driver: "sqlite", DSNFile: "/no/such/dsn", UsersQuery: "select 1",
	})
	if err == nil || !strings.Contains(err.Error(), "the DSN file") {
		t.Errorf("%v, want one about the DSN file", err)
	}
	_, err = hcldir.Open(hcldir.Block{
		Kind: "ldap", URL: "ldap://127.0.0.1:1", BaseDN: "dc=x", BindPasswordFile: "/no/such/pw",
	})
	if err == nil || !strings.Contains(err.Error(), "the bind password") {
		t.Errorf("%v, want one about the bind password", err)
	}
}

// A database that is not answering is refused at startup, not at the first
// login: a server that cannot authenticate anybody should say so before it
// listens, rather than accepting connections and refusing everybody.
func TestADatabaseThatIsNotAnswering(t *testing.T) {
	dsn := write(t, "dsn", "file:"+filepath.ToSlash(filepath.Join(t.TempDir(), "absent.db"))+"?mode=rw")
	_, err := hcldir.Open(hcldir.Block{
		Kind: "sql", Driver: "sqlite", DSNFile: dsn, UsersQuery: "select 1",
	})
	if err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Errorf("%v, want one saying the database is not answering", err)
	}
}

// OpenAll closes what it opened when a later block fails: a half-open set is a
// server holding a database it will never use.
func TestOpenAllClosesWhatItOpened(t *testing.T) {
	good := hcldir.Block{
		Kind: "sql", Driver: "sqlite", DSNFile: sqliteWith(t, `
create table staff (login text primary key);
insert into staff values ('dora');
`),
		UsersQuery: "select login from staff",
	}
	srcs, err := hcldir.OpenAll([]hcldir.Block{good, {Kind: "kerberos"}})
	if err == nil {
		t.Fatal("OpenAll accepted a block nobody can open")
	}
	if srcs != nil {
		t.Error("OpenAll returned sources it had already given up on")
	}
	if !strings.Contains(err.Error(), `users "kerberos"`) {
		t.Errorf("the error does not say which block: %v", err)
	}
	// The first one really was opened, and really was closed: opening the
	// same database again is the check that nothing is still holding it.
	src, err := hcldir.Open(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := src.Identities(); err != nil {
		t.Errorf("the database is still held by the set that gave up: %v", err)
	}
	src.(interface{ Close() error }).Close()

	// And nothing at all is an empty set, not an error.
	if srcs, err := hcldir.OpenAll(nil); err != nil || srcs != nil {
		t.Errorf("OpenAll(nil) = %v, %v", srcs, err)
	}
}

func sqliteWith(t *testing.T, schema string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "people.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return write(t, "dsn", path)
}

func write(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The LDAP half, against a real LDAP server.
//
// What is measured here is the WIRING -- a block, to a config, to a source
// that reads -- since ldapdir's own reading is tested against the same server
// next door. The two people are the two cases that decide what a protocol can
// do with somebody: one the directory publishes an NT hash for, and one it
// will only bind.
func TestAnLDAPBlockReadsADirectory(t *testing.T) {
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			"dora": {Password: "hunter2", NTHash: hex.EncodeToString(directory.NTHashOf("hunter2"))},
			"eli":  {Password: "swordfish"},
		},
		Groups: map[string][]string{"engineers": {"dora", "eli"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	src, err := hcldir.Open(hcldir.Block{
		Kind: "ldap", URL: d.URL, BaseDN: d.PeopleDN, GroupBaseDN: d.GroupsDN,
		BindDN: d.ReaderDN, BindPasswordFile: write(t, "bind.pw", d.ReaderPassword),
	})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("%d people, want 2", len(ids))
	}
	for _, id := range ids {
		switch id.Name() {
		case "dora":
			if !id.Can(directory.NTHash) {
				t.Error("dora's sambaNTPassword did not arrive: SMB could not serve her")
			}
		case "eli":
			if id.Can(directory.NTHash) {
				t.Error("eli has an NT hash, and the directory published none")
			}
			// What a bind CAN answer, which is the other half of the honesty.
			if !id.Can(directory.Verifier) || id.Verify("swordfish") != nil {
				t.Error("eli cannot be checked by a bind")
			}
			if id.Verify("wrong") == nil {
				t.Error("a wrong password bound successfully")
			}
			// Never the password itself: the directory holds it and does not
			// give it up, which is the whole point of a directory.
			if id.Can(directory.Password) {
				t.Error("a password came out of LDAP, which LDAP does not do")
			}
		}
	}
	if members, err := src.Members("engineers"); err != nil || len(members) != 2 {
		t.Errorf("Members(engineers) = %v, %v", members, err)
	}
	// The LDAP source is not wrapped today, and it still has to be able to
	// list: what a block opens is what a server publishes, whichever kind.
	lister, ok := src.(directory.GroupLister)
	if !ok {
		t.Fatal("the opened source cannot list its groups")
	}
	if names, err := lister.GroupNames(); err != nil || len(names) != 1 || names[0] != "engineers" {
		t.Errorf("GroupNames() = %v, %v", names, err)
	}
	// A bind really happened, rather than a comparison somewhere in here.
	if d.Binds() < 2 {
		t.Errorf("%d binds: the passwords were checked somewhere else", d.Binds())
	}
}

// A directory that is not there is refused at startup, with the url named --
// it holds no secret, since one carrying credentials is refused outright.
func TestAnLDAPDirectoryThatIsNotThere(t *testing.T) {
	_, err := hcldir.Open(hcldir.Block{Kind: "ldap", URL: "ldap://127.0.0.1:1", BaseDN: "dc=x"})
	if err == nil || !strings.Contains(err.Error(), "not answering") {
		t.Errorf("%v, want one saying the directory is not answering", err)
	}
}
