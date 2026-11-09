package ldapdir_test

// A differential test: the client go-authn/ldap provides and go-ldap/ldap/v3
// read the SAME recorded server answers -- the bytes ldaptest sent, replayed --
// and must come back with identical entries: the same DNs, in the same order,
// the same attributes under the same spellings, the same values.

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory/ldaptest"
	ldap "github.com/go-authn/ldap"
	goldap "github.com/go-ldap/ldap/v3"
)

// shape is an entry as both clients can be made to say it.
type shape struct {
	DN    string
	Attrs []string // "name=value", in the order the server sent them
}

func shapesOurs(entries []*ldap.Entry) []shape {
	var out []shape
	for _, e := range entries {
		s := shape{DN: e.DN}
		for _, a := range e.Attributes {
			for _, v := range a.Values {
				s.Attrs = append(s.Attrs, a.Name+"="+string(v))
			}
		}
		out = append(out, s)
	}
	return out
}

func shapesGoLDAP(entries []*goldap.Entry) []shape {
	var out []shape
	for _, e := range entries {
		s := shape{DN: e.DN}
		for _, a := range e.Attributes {
			for _, v := range a.Values {
				s.Attrs = append(s.Attrs, a.Name+"="+v)
			}
		}
		out = append(out, s)
	}
	return out
}

func TestOurClientReadsWhatGoLDAPReads(t *testing.T) {
	d := &ldaptest.Directory{
		People:        map[string]ldaptest.Person{},
		Groups:        map[string][]string{},
		GroupExtra:    map[string]map[string][]string{},
		GroupsOfNames: map[string][]string{},
	}
	for i := 0; i < 120; i++ {
		p := ldaptest.Person{Password: "pw"}
		if i%3 == 0 {
			p.NTHash = strings.Repeat("ab", 16)
		}
		for k := 0; k < i%4; k++ {
			p.SSHKeys = append(p.SSHKeys, fmt.Sprintf("ssh-ed25519 AAAA%d%d key%d", i, k, k))
		}
		d.People[fmt.Sprintf("user%03d", i)] = p
	}
	d.People["héloïse"] = ldaptest.Person{Password: "pw"}
	d.Groups["staff"] = []string{"user001", "user002"}
	d.GroupExtra["staff"] = map[string][]string{"gidNumber": {"100"}, "description": {"équipe", "second value"}}
	var many []string
	for i := 0; i < 300; i++ {
		many = append(many, fmt.Sprintf("uid=user%03d,ou=people,dc=example,dc=org", i%120))
	}
	d.GroupsOfNames["big"] = many
	d.GroupsOfNames["odd"] = []string{`uid=a\,b,ou=people,dc=example,dc=org`, "uid=héloïse,ou=people,dc=example,dc=org", "not a dn", ""}
	srv, err := ldaptest.NewServer(d)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	rs := newReplayServer(t, srv.URL[len("ldap://"):])
	url := "ldap://" + rs.ln.Addr().String()

	type search struct {
		name, base, filter string
		attrs              []string
	}
	searches := []search{
		{"people", srv.PeopleDN, "(|(objectClass=posixAccount)(objectClass=account)(objectClass=uidObject))", []string{"uid", "sambaNTPassword", "sshPublicKey"}},
		{"people, every attribute", srv.PeopleDN, "(uid=user0*)", nil},
		{"groups", srv.GroupsDN, "(|(objectClass=posixGroup)(objectClass=groupOfNames))", []string{"cn", "memberUid", "member", "gidNumber", "description"}},
		{"groups, no attribute", srv.GroupsDN, "(objectClass=groupOfNames)", []string{"1.1"}},
		{"nothing", srv.PeopleDN, "(uid=nobody-has-this)", []string{"uid"}},
		{"a substring and a negation", srv.PeopleDN, "(&(uid=user01*)(!(uid=user011)))", []string{"uid"}},
	}

	run := func() (ours, theirs map[string][]shape) {
		ours, theirs = map[string][]shape{}, map[string][]shape{}
		c, err := ldap.Dial(context.Background(), url, ldap.DialOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if err := c.Bind(srv.ReaderDN, srv.ReaderPassword); err != nil {
			t.Fatal(err)
		}
		g, err := goldap.DialURL(url)
		if err != nil {
			t.Fatal(err)
		}
		defer g.Close()
		if err := g.Bind(srv.ReaderDN, srv.ReaderPassword); err != nil {
			t.Fatal(err)
		}
		for _, s := range searches {
			f, err := ldap.ParseFilter(s.filter)
			if err != nil {
				t.Fatalf("%s: %v", s.name, err)
			}
			got, err := c.Search(&ldap.SearchRequest{BaseObject: s.base, Scope: ldap.ScopeWholeSubtree, Filter: f, Attributes: s.attrs}, 0)
			if err != nil {
				t.Fatalf("%s: ours: %v", s.name, err)
			}
			ours[s.name] = shapesOurs(got)
			res, err := g.Search(goldap.NewSearchRequest(s.base, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases, 0, 0, false, s.filter, s.attrs, nil))
			if err != nil {
				t.Fatalf("%s: go-ldap: %v", s.name, err)
			}
			theirs[s.name] = shapesGoLDAP(res.Entries)
		}
		return ours, theirs
	}

	// The first run goes through the real server and records what it sent. Its
	// own answers are not compared: the server orders entries as it pleases,
	// differently for each request, and the two clients asked separately. The
	// second run is served the recorded bytes alone (both clients ask in the
	// same bytes, so both are served the same answer), and from the same bytes
	// the two must read the same entries.
	run()
	rs.mu.Lock()
	rs.recording = false
	rs.mu.Unlock()
	ours, theirs := run()

	for _, s := range searches {
		a, b := ours[s.name], theirs[s.name]
		if len(a) != len(b) {
			t.Errorf("%s: %d entries against %d", s.name, len(a), len(b))
			continue
		}
		for i := range a {
			if a[i].DN != b[i].DN || !slices.Equal(a[i].Attrs, b[i].Attrs) {
				t.Errorf("%s: entry %d differs:\n  ours    %+v\n  go-ldap %+v", s.name, i, a[i], b[i])
				break
			}
		}
	}
	for _, e := range ours["groups"] {
		if strings.HasPrefix(e.DN, "cn=staff,") && !slices.Contains(e.Attrs, "description=équipe") {
			t.Errorf("a non-ASCII value did not survive: %+v", e)
		}
	}
	if n := len(ours["people"]); n != 121 {
		t.Errorf("the people search returned %d entries, want 121", n)
	}
	if n := len(ours["nothing"]); n != 0 {
		t.Errorf("a search with no match returned %d", n)
	}
}
