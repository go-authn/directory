package ldapdir_test

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"

	server "github.com/glauth/ldap"
)

// The fixture is somebody else's LDAP SERVER.
//
// A fake built from my own reading of the protocol could only confirm that
// reading: if I have misunderstood how a search is answered, my fake
// misunderstands it the same way and the test passes. glauth/ldap is an
// independent implementation, and driving it is what makes "this reads an LDAP
// directory" a measurement rather than an opinion.
type fixture struct {
	people map[string]person // by uid
	groups map[string][]string
}

type person struct {
	dn       string
	password string
	ntHash   string
	sshKeys  []string
}

func (f *fixture) Bind(bindDN, password string, _ net.Conn) (server.LDAPResultCode, error) {
	// The service account this server reads with, and then each person for
	// the password check.
	if bindDN == "cn=reader,dc=example,dc=org" && password == "let me read" {
		return server.LDAPResultSuccess, nil
	}
	for _, p := range f.people {
		if p.dn == bindDN && p.password != "" && password == p.password {
			return server.LDAPResultSuccess, nil
		}
	}
	// An empty password binds SUCCESSFULLY in a real directory -- the
	// unauthenticated bind -- and this fixture does the same, so the test can
	// prove the package refuses it before it ever gets here.
	if password == "" {
		return server.LDAPResultSuccess, nil
	}
	return server.LDAPResultInvalidCredentials, nil
}

func (f *fixture) Search(_ string, req server.SearchRequest, _ net.Conn) (server.ServerSearchResult, error) {
	var entries []*server.Entry
	switch {
	case strings.Contains(req.Filter, "posixAccount"):
		for uid, p := range f.people {
			attrs := []*server.EntryAttribute{{Name: "uid", Values: []string{uid}}}
			if p.ntHash != "" {
				attrs = append(attrs, &server.EntryAttribute{Name: "sambaNTPassword", Values: []string{p.ntHash}})
			}
			if len(p.sshKeys) > 0 {
				attrs = append(attrs, &server.EntryAttribute{Name: "sshPublicKey", Values: p.sshKeys})
			}
			entries = append(entries, &server.Entry{DN: p.dn, Attributes: attrs})
		}
	case strings.Contains(req.Filter, "posixGroup"):
		for name, members := range f.groups {
			if !strings.Contains(req.Filter, "cn="+name+")") {
				continue
			}
			entries = append(entries, &server.Entry{
				DN: "cn=" + name + ",ou=groups,dc=example,dc=org",
				Attributes: []*server.EntryAttribute{
					{Name: "memberUid", Values: members},
				},
			})
		}
	}
	return server.ServerSearchResult{Entries: entries, ResultCode: server.LDAPResultSuccess}, nil
}

func serveLDAP(t *testing.T, f *fixture) string {
	t.Helper()
	s := server.NewServer()
	s.BindFunc("", f)
	s.SearchFunc("", f)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve(ln) }()
	t.Cleanup(func() { ln.Close() })
	// Bind first, announce second: the address a client dials is the one the
	// listener got, not the one asked for.
	addr := ln.Addr().String()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing is listening on %s", addr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return "ldap://" + addr
}

func directoryUnderTest(t *testing.T) (*ldapdir.Source, *fixture) {
	t.Helper()
	f := &fixture{
		people: map[string]person{
			// alice has everything a directory can publish.
			"alice": {
				dn:       "uid=alice,ou=people,dc=example,dc=org",
				password: "hunter2",
				ntHash:   "8846f7eaee8fb117ad06bdd830b7586c",
				sshKeys:  []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH alice@laptop"},
			},
			// bob has only what LDAP holds by default: a password nobody can
			// read, which is the whole reason SMB cannot serve him.
			"bob": {dn: "uid=bob,ou=people,dc=example,dc=org", password: "swordfish"},
		},
		groups: map[string][]string{"staff": {"alice", "bob"}, "admins": {"alice"}},
	}
	src, err := ldapdir.New(ldapdir.Config{
		URL:          serveLDAP(t, f),
		BaseDN:       "ou=people,dc=example,dc=org",
		GroupBaseDN:  "ou=groups,dc=example,dc=org",
		BindDN:       "cn=reader,dc=example,dc=org",
		BindPassword: "let me read",
	})
	if err != nil {
		t.Fatal(err)
	}
	return src, f
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
	f := &fixture{people: map[string]person{}}
	if _, err := ldapdir.New(ldapdir.Config{
		URL: serveLDAP(t, f), BaseDN: "dc=example,dc=org",
		BindDN: "cn=reader,dc=example,dc=org", BindPassword: "wrong",
	}); err == nil {
		t.Error("a bad bind password was accepted")
	}
	_ = fmt.Sprint()
}

// A group holding DNs rather than names: groupOfNames is what a directory
// that is not a small site's OpenLDAP uses, and a server comparing "alice"
// against "uid=alice,ou=people,dc=example,dc=org" tells alice she is not in
// her own group.
func TestAGroupThatHoldsDNs(t *testing.T) {
	f := &fixture{
		people: map[string]person{},
		groups: map[string][]string{"staff": {
			"uid=alice,ou=people,dc=example,dc=org",
			"cn=bob,ou=people,dc=example,dc=org",
			"carol",                        // a name, in the same group
			"not a dn = but has an equals", // and something that parses as neither
		}},
	}
	src, err := ldapdir.New(ldapdir.Config{
		URL: serveLDAP(t, f), BaseDN: "ou=people,dc=example,dc=org",
		GroupBaseDN: "ou=groups,dc=example,dc=org",
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
