package ldapdir_test

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/ldap"
)

// hostile is an LDAP server whose answers a test writes by hand: what a
// compromised or merely sloppy directory sends. It accepts EVERY simple bind
// that carries a password, as a server does that maps an empty name to the
// anonymous association, and counts them.
type hostile struct {
	entries []*ldap.Entry
	binds   atomic.Int32
}

func (h *hostile) Search(_ context.Context, _ ldap.Session, _ *ldap.SearchRequest, w ldap.EntryWriter) (ldap.Result, error) {
	for _, e := range h.entries {
		if err := w.Entry(e); err != nil {
			return ldap.Result{}, err
		}
	}
	return ldap.Result{Code: ldap.Success}, nil
}

func (h *hostile) Bind(context.Context, ldap.Session, *ldap.BindRequest) (ldap.Result, error) {
	h.binds.Add(1)
	return ldap.Result{Code: ldap.Success}, nil
}

func person(dn string, uids ...string) *ldap.Entry {
	return &ldap.Entry{DN: dn, Attributes: []*ldap.Attribute{
		ldap.StringAttribute("objectClass", "posixAccount"),
		ldap.StringAttribute("uid", uids...),
	}}
}

func hostileSource(t *testing.T, h *hostile) *ldapdir.Source {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &ldap.Server{Bind: h, Search: h}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	t.Cleanup(func() {
		srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("the server did not stop")
		}
	})
	src, err := ldapdir.New(ldapdir.Config{URL: "ldap://" + ln.Addr().String(), BaseDN: "dc=example,dc=org"})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// Suspicion 11: an entry may carry several uid values, and the source used
// only the first (which one that is is the directory's to choose: values are a
// set, RFC 4511 4.1.7). The other values are names too -- (uid=bob) finds the
// entry -- so an entry holding "bob" next to the entry that IS bob is two
// people under one name, and it went unnoticed.
func TestASecondUIDValueCountsAsAName(t *testing.T) {
	src := hostileSource(t, &hostile{entries: []*ldap.Entry{
		person("uid=alice,dc=example,dc=org", "alice", "bob"),
		person("uid=bob,dc=example,dc=org", "bob"),
	}})
	if ids, err := src.Identities(); !errors.Is(err, directory.ErrAmbiguous) {
		t.Errorf("%d people, err = %v; want ErrAmbiguous", len(ids), err)
	}

	// The same name written differently is still the same name (caseIgnoreMatch).
	src = hostileSource(t, &hostile{entries: []*ldap.Entry{
		person("uid=alice,dc=example,dc=org", "alice", "Bob"),
		person("uid=bob,dc=example,dc=org", "bob"),
	}})
	if ids, err := src.Identities(); !errors.Is(err, directory.ErrAmbiguous) {
		t.Errorf("Bob / bob: %d people, err = %v; want ErrAmbiguous", len(ids), err)
	}

	// Controls: several values that collide with nobody, and one value twice in
	// one entry, are one person each.
	src = hostileSource(t, &hostile{entries: []*ldap.Entry{
		person("uid=alice,dc=example,dc=org", "alice", "alicia", "Alice"),
		person("uid=bob,dc=example,dc=org", "bob"),
	}})
	if ids, err := src.Identities(); err != nil || len(ids) != 2 {
		t.Errorf("%d people, err = %v; want 2, nil", len(ids), err)
	}
}

// Suspicion 12: Identities hands out a verifier that binds as the entry's DN.
// An entry with no DN would be verified by a bind with an EMPTY name and a
// password -- which a server that maps the empty name to the anonymous
// association answers Success to, for any password at all.
func TestAnEntryWithNoDNIsNotSomebody(t *testing.T) {
	h := &hostile{entries: []*ldap.Entry{person("", "mallory")}}
	src := hostileSource(t, h)
	ids, err := src.Identities()
	if err == nil {
		for _, id := range ids {
			if verr := id.Verify("whatever"); verr == nil {
				t.Errorf("%s was verified by a bind with an empty name", id.Name())
			}
		}
		t.Errorf("an entry with no DN was imported (%d identities)", len(ids))
	}
	if n := h.binds.Load(); n != 0 {
		t.Errorf("%d binds reached the server for an entry with no DN", n)
	}
}
