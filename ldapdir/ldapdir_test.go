package ldapdir_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/directory/ldaptest"
)

// The directory under test is somebody else's LDAP SERVER, driven by
// go-authn/directory/ldaptest: an independent implementation of the protocol.
// A fake built from my own reading of it could only confirm that reading -- if
// I have misunderstood how a search is answered, the fake misunderstands it
// the same way and the test passes.
func directoryUnderTest(t *testing.T) (*ldapdir.Source, *ldaptest.Server) {
	t.Helper()
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			// alice has everything a directory can publish.
			"alice": {
				Password: "hunter2",
				NTHash:   "8846f7eaee8fb117ad06bdd830b7586c",
				SSHKeys:  []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH alice@laptop"},
			},
			// bob has only what LDAP holds by default: a password nobody can
			// read, which is the whole reason SMB cannot serve him.
			"bob": {Password: "swordfish"},
		},
		Groups: map[string][]string{"staff": {"alice", "bob"}, "admins": {"alice"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	src, err := ldapdir.New(ldapdir.Config{
		URL:          d.URL,
		BaseDN:       d.PeopleDN,
		GroupBaseDN:  d.GroupsDN,
		BindDN:       d.ReaderDN,
		BindPassword: d.ReaderPassword,
	})
	if err != nil {
		t.Fatal(err)
	}
	return src, d
}

func TestReadingPeopleFromLDAP(t *testing.T) {
	src, _ := directoryUnderTest(t)
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 {
		t.Fatalf("%d people, want 2", len(ids))
	}
	for _, id := range ids {
		switch id.Name() {
		case "alice":
			// The directory published enough for every protocol.
			if !id.Can(directory.NTHash) {
				t.Error("alice's sambaNTPassword was not read: SMB cannot serve her")
			}
			if !id.Can(directory.PublicKeys) || len(id.Keys()) != 1 {
				t.Errorf("alice's sshPublicKey was not read: %v", id.Keys())
			}
			if !id.Can(directory.Verifier) {
				t.Error("alice cannot be asked for a password")
			}
			// And never the password itself: the directory holds it and does
			// not give it up, which is the point of a directory.
			if id.Can(directory.Password) {
				t.Error("a password was taken out of LDAP, which LDAP does not do")
			}
		case "bob":
			// The honest half: a bind can answer WebDAV and cannot answer
			// NTLMv2, so bob cannot use SMB and a server must say so.
			if id.Can(directory.NTHash) {
				t.Error("bob looks like he can serve SMB, and he cannot")
			}
			if !id.Can(directory.Verifier) {
				t.Error("bob cannot be asked for a password")
			}
		default:
			t.Errorf("who is %q", id.Name())
		}
	}
}

// The password check is a BIND, against the directory, one at a time.
func TestVerifyingAPasswordByBinding(t *testing.T) {
	src, _ := directoryUnderTest(t)
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		want := map[string]string{"alice": "hunter2", "bob": "swordfish"}[id.Name()]
		if err := id.Verify(want); err != nil {
			t.Errorf("%s with the right password: %v", id.Name(), err)
		}
		if err := id.Verify("wrong"); err == nil {
			t.Errorf("%s with the wrong password was accepted", id.Name())
		}
		// ⛔ The unauthenticated bind: an empty password makes a real
		// directory answer SUCCESS while nobody has proved anything. The
		// fixture does that too -- so this test fails if the package ever
		// stops refusing it first.
		if err := id.Verify(""); err == nil {
			t.Errorf("%s was let in with an empty password (the unauthenticated bind)", id.Name())
		}
	}
}

func TestGroupsFromLDAP(t *testing.T) {
	src, _ := directoryUnderTest(t)
	members, err := src.Members("staff")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(members, ",") != "alice,bob" && strings.Join(members, ",") != "bob,alice" {
		t.Errorf("staff = %v", members)
	}
	if _, err := src.Members("nobody"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("an unknown group gave %v", err)
	}
}

// A directory that is not there is a server that cannot authenticate anybody,
// and it says so before it listens rather than at the first login.
func TestADirectoryThatIsNotThere(t *testing.T) {
	if _, err := ldapdir.New(ldapdir.Config{URL: "ldap://127.0.0.1:1", BaseDN: "dc=example,dc=org"}); err == nil {
		t.Error("a directory nothing is listening on was accepted")
	}
	if _, err := ldapdir.New(ldapdir.Config{BaseDN: "dc=example,dc=org"}); err == nil {
		t.Error("a config with no url was accepted")
	}
	d, err := ldaptest.NewServer(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := ldapdir.New(ldapdir.Config{
		URL: d.URL, BaseDN: d.BaseDN, BindDN: d.ReaderDN, BindPassword: "wrong",
	}); err == nil {
		t.Error("a bad bind password was accepted")
	}
}

// A group holding DNs rather than names: groupOfNames is what a directory
// that is not a small site's OpenLDAP uses, and a server comparing "alice"
// against "uid=alice,ou=people,dc=example,dc=org" tells alice she is not in
// her own group.
func TestAGroupThatHoldsDNs(t *testing.T) {
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		Groups: map[string][]string{"staff": {
			"uid=alice,ou=people,dc=example,dc=org",
			"cn=bob,ou=people,dc=example,dc=org",
			"carol",                        // a name, in the same group
			"not a dn = but has an equals", // and something that parses as neither
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	src, err := ldapdir.New(ldapdir.Config{
		URL: d.URL, BaseDN: d.PeopleDN, GroupBaseDN: d.GroupsDN,
	})
	if err != nil {
		t.Fatal(err)
	}
	members, err := src.Members("staff")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(members, ",")
	if !strings.Contains(got, "alice") || !strings.Contains(got, "bob") || !strings.Contains(got, "carol") {
		t.Errorf("members = %q -- a DN must reduce to the name everything else uses", got)
	}
	if src.Describe() == "" {
		t.Error("a source with no description")
	}
}

// A URL is printed -- by Describe, by errors, by callers' logs -- so one
// carrying a password is refused before anything can print it.
func TestAURLWithAPasswordInItIsRefused(t *testing.T) {
	_, err := ldapdir.New(ldapdir.Config{
		URL:    "ldap://cn=reader:hunter2@127.0.0.1:389",
		BaseDN: "ou=people,dc=example,dc=org",
	})
	if err == nil {
		t.Fatal("a url carrying a password was accepted")
	}
	if !strings.Contains(err.Error(), "carries credentials") {
		t.Errorf("the refusal reads %q", err)
	}
	// And the refusal itself does not repeat the secret, which would defeat
	// the whole point of refusing.
	if strings.Contains(err.Error(), "hunter2") {
		t.Error("the refusal printed the password it was refusing")
	}
}

// Listing the groups: the same filter Members uses, without the name.
func TestGroupNamesFromLDAP(t *testing.T) {
	src, _ := directoryUnderTest(t)
	names, err := src.GroupNames()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(names, ",") != "admins,staff" {
		t.Errorf("GroupNames() = %v", names)
	}
}
