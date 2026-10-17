package ldaptest_test

import (
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-authn/directory/ldaptest"
	"github.com/go-ldap/ldap/v3"
)

// A fixture that lies is worse than no fixture: every test built on it would
// pass while measuring nothing. So this one is read by OPENLDAP's own client,
// which knows nothing about this module.
func TestOpenLDAPCanReadIt(t *testing.T) {
	ldapsearch := needLDAPSearch(t)
	d := serve(t, &ldaptest.Directory{
		People: map[string]ldaptest.Person{
			"dora": {Password: "hunter2", NTHash: "8846f7eaee8fb117ad06bdd830b7586c"},
			"eli":  {Password: "swordfish"},
		},
		Groups:     map[string][]string{"engineers": {"dora", "eli"}},
		GroupExtra: map[string]map[string][]string{"engineers": {"gidNumber": {"500"}}},
	})

	out, err := run(ldapsearch, "-x", "-H", d.URL, "-D", d.ReaderDN, "-w", d.ReaderPassword,
		"-b", d.PeopleDN, "(objectClass=posixAccount)", "uid", "sambaNTPassword")
	if err != nil {
		t.Fatalf("ldapsearch: %v\n%s", err, out)
	}
	for _, want := range []string{
		"dn: uid=dora,ou=people,dc=example,dc=org",
		"uid: dora",
		"sambaNTPassword: 8846f7eaee8fb117ad06bdd830b7586c",
		"uid: eli",
		"result: 0 Success",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ldapsearch did not report %q:\n%s", want, out)
		}
	}
	// eli has no NT hash, and an attribute a directory does not hold is one
	// it does not send -- not an empty one.
	if strings.Count(out, "sambaNTPassword:") != 1 {
		t.Errorf("sambaNTPassword appears %d times, want once:\n%s", strings.Count(out, "sambaNTPassword:"), out)
	}

	// The groups, in the search a reader actually makes for them.
	out, err = run(ldapsearch, "-x", "-H", d.URL, "-D", d.ReaderDN, "-w", d.ReaderPassword,
		"-b", d.GroupsDN, "(&(objectClass=posixGroup)(cn=engineers))", "memberUid", "gidNumber")
	if err != nil {
		t.Fatalf("ldapsearch: %v\n%s", err, out)
	}
	if !strings.Contains(out, "memberUid: dora") || !strings.Contains(out, "memberUid: eli") {
		t.Errorf("the group did not come back:\n%s", out)
	}
	// A group's other attributes, which ldapdir copies as GroupAttributes.
	if !strings.Contains(out, "gidNumber: 500") {
		t.Errorf("the group's gidNumber did not come back:\n%s", out)
	}
}

// A bind, judged by a client this module did not write. ldapwhoami would be
// the obvious tool and asks for an extended operation the server does not
// implement, so the bind is judged by a search that has to get past it.
func TestOpenLDAPBindsAsAPerson(t *testing.T) {
	ldapsearch := needLDAPSearch(t)
	d := serve(t, &ldaptest.Directory{
		People: map[string]ldaptest.Person{"dora": {Password: "hunter2"}},
	})
	if out, err := run(ldapsearch, "-x", "-H", d.URL, "-D", d.DN("dora"), "-w", "hunter2",
		"-b", d.PeopleDN, "(objectClass=posixAccount)", "uid"); err != nil {
		t.Errorf("dora with the right password: %v\n%s", err, out)
	}
	out, err := run(ldapsearch, "-x", "-H", d.URL, "-D", d.DN("dora"), "-w", "wrong",
		"-b", d.PeopleDN, "(objectClass=posixAccount)", "uid")
	if err == nil {
		t.Error("a wrong password was accepted")
	}
	if !strings.Contains(out, "Invalid credentials (49)") {
		t.Errorf("the refusal reads:\n%s", out)
	}
}

// ⛔ The unauthenticated bind succeeds HERE, and that is a choice about
// testing rather than a copy of what a directory does.
//
// RFC 4513 §5.1.2 says the opposite of what this comment used to: servers
// "SHOULD by default fail Unauthenticated Bind requests with a resultCode of
// unwillingToPerform". A fixture that mirrored that would be useless for the
// thing this fixture is FOR -- a server treating a bind as proof must be
// shown to refuse an empty password itself, and against a fixture that
// refused it first that test passes no matter what the server does.
//
// So the fixture says yes so the code under test has to say no. The name is
// no longer "LikeARealDirectory", because it is not like one, and the old
// name is how the false claim spread to four other places.
func TestAnEmptyPasswordBindsSoTheSubjectMustRefuseIt(t *testing.T) {
	ldapsearch := needLDAPSearch(t)
	d := serve(t, &ldaptest.Directory{People: map[string]ldaptest.Person{"dora": {Password: "hunter2"}}})
	if out, err := run(ldapsearch, "-x", "-H", d.URL, "-D", d.DN("dora"), "-w", "",
		"-b", d.PeopleDN, "(objectClass=posixAccount)", "uid"); err != nil {
		t.Errorf("the fixture refused an empty password, so nothing downstream can be shown to refuse it: %v\n%s", err, out)
	}
}

// Binds counts what happened, so a test can show a password was checked
// against the DIRECTORY rather than against something in the caller.
func TestBindsAreCounted(t *testing.T) {
	d := serve(t, &ldaptest.Directory{People: map[string]ldaptest.Person{"dora": {Password: "hunter2"}}})
	if n := d.Binds(); n != 0 {
		t.Errorf("%d binds before anybody connected", n)
	}
	if ldapsearch, ok := lookLDAPSearch(); ok {
		run(ldapsearch, "-x", "-H", d.URL, "-D", d.DN("dora"), "-w", "hunter2", "-b", d.PeopleDN, "(uid=dora)")
		if n := d.Binds(); n == 0 {
			t.Error("a bind happened and was not counted")
		}
	}
}

// A person with a DN of their own keeps it, and one without gets the obvious
// one -- so a test that does not care about DNs never writes one.
func TestDNsAreTheirsOrTheObviousOne(t *testing.T) {
	d := serve(t, &ldaptest.Directory{
		People: map[string]ldaptest.Person{
			"dora": {},
			"eli":  {DN: "cn=Eli,ou=contractors,dc=example,dc=org"},
		},
		BaseDN: "dc=example,dc=org",
	})
	if got := d.DN("dora"); got != "uid=dora,ou=people,dc=example,dc=org" {
		t.Errorf("dora's DN = %q", got)
	}
	if got := d.DN("eli"); got != "cn=Eli,ou=contractors,dc=example,dc=org" {
		t.Errorf("eli's DN = %q", got)
	}
	// Somebody who is not there at all still has a place their entry would be.
	if got := d.DN("nobody"); got != "uid=nobody,ou=people,dc=example,dc=org" {
		t.Errorf("nobody's DN = %q", got)
	}
	// And an empty directory is a directory, not a crash.
	if e := serve(t, nil); e.BaseDN != "dc=example,dc=org" {
		t.Errorf("the default base = %q", e.BaseDN)
	}
}

func serve(t *testing.T, d *ldaptest.Directory) *ldaptest.Server {
	t.Helper()
	s, err := ldaptest.NewServer(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func run(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

func lookLDAPSearch() (string, bool) {
	// Named absolutely on macOS, where it ships with the system, and found on
	// the PATH elsewhere: a runner installs ldap-utils.
	if runtime.GOOS == "darwin" {
		return "/usr/bin/ldapsearch", true
	}
	p, err := exec.LookPath("ldapsearch")
	return p, err == nil
}

func needLDAPSearch(t *testing.T) string {
	t.Helper()
	p, ok := lookLDAPSearch()
	if !ok {
		t.Skip("no ldapsearch here: the foreign judge is OpenLDAP's own client")
	}
	return p
}

// A search gets back what it asked for, and only that (RFC 4511 §4.5.1.8):
// a client that forgot to ASK for an attribute must not be handed it, or its
// tests pass on a directory that does not exist.
func TestASearchGetsTheAttributesItAskedFor(t *testing.T) {
	d := serve(t, &ldaptest.Directory{
		People: map[string]ldaptest.Person{"dora": {
			Password: "hunter2", NTHash: "8846f7eaee8fb117ad06bdd830b7586c",
			Extra: map[string][]string{"mail": {"dora@example.org"}, "description;lang-fr": {"une personne"}},
		}},
	})
	c, err := ldap.DialURL(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Bind(d.ReaderDN, d.ReaderPassword); err != nil {
		t.Fatal(err)
	}
	names := func(attrs ...string) string {
		t.Helper()
		res, err := c.Search(ldap.NewSearchRequest(d.PeopleDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			0, 0, false, "(objectClass=posixAccount)", attrs, nil))
		if err != nil || len(res.Entries) != 1 {
			t.Fatalf("%v: %v", attrs, err)
		}
		var got []string
		for _, a := range res.Entries[0].Attributes {
			got = append(got, a.Name)
		}
		slices.Sort(got)
		return strings.Join(got, ",")
	}
	for _, tc := range []struct {
		ask  []string
		want string
	}{
		{[]string{"UID"}, "uid"},
		{[]string{"uid", "mail"}, "mail,uid"},
		{[]string{"description"}, "description;lang-fr"},
		{[]string{"description;lang-de"}, ""},
		{[]string{"1.1"}, ""},
		{[]string{"*"}, "description;lang-fr,mail,sambaNTPassword,uid"},
		{nil, "description;lang-fr,mail,sambaNTPassword,uid"},
	} {
		if got := names(tc.ask...); got != tc.want {
			t.Errorf("asked for %v, got %q, want %q", tc.ask, got, tc.want)
		}
	}
}
