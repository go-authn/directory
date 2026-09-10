package directory

import (
	"errors"
	"strings"
	"testing"
)

func TestTheFirstSourceThatKnowsANameOwnsIt(t *testing.T) {
	local := &Static{
		Name:   "the configuration file",
		People: []*Identity{NewIdentity("alice", WithPassword("local")), NewIdentity("service")},
		Groups: map[string][]string{"staff": {"alice"}},
	}
	remote := &Static{
		Name:   "a database",
		People: []*Identity{NewIdentity("alice", WithPassword("remote")), NewIdentity("bob")},
		Groups: map[string][]string{"staff": {"bob"}, "admins": {"bob"}},
	}
	set := NewSet(local, remote)

	ids, err := set.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 {
		t.Fatalf("%d people, want 3", len(ids))
	}
	// alice is the local one: adding somebody to the database must not break
	// a server that has them written down.
	for _, id := range ids {
		if id.Name() != "alice" {
			continue
		}
		if err := id.Verify("local"); err != nil {
			t.Errorf("alice is the one from %s", id.Where())
		}
		if id.Where() != "the configuration file" {
			t.Errorf("alice came from %q", id.Where())
		}
	}

	// A group can have people from both, and a set that returned only the
	// first source's half would silently exclude the rest.
	members, err := set.Members("staff")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(members, ",") != "alice,bob" {
		t.Errorf("staff is %v", members)
	}
	// A group only one source has.
	if members, err := set.Members("admins"); err != nil || strings.Join(members, ",") != "bob" {
		t.Errorf("admins is %v (%v)", members, err)
	}
	// A group nobody has is an error, not an empty list: an empty list grants
	// nothing to nobody, which reads exactly like a working configuration.
	if _, err := set.Members("nobody"); !errors.Is(err, ErrNoSuchGroup) {
		t.Errorf("an unknown group gave %v", err)
	}
}

// A source that is BROKEN is not a source that lacks the group, and the
// difference decides whether a configuration is wrong or a database is down.
func TestABrokenSourceIsNotAMissingGroup(t *testing.T) {
	broken := &failing{err: errors.New("the database is down")}
	set := NewSet(&Static{Groups: map[string][]string{}}, broken)
	_, err := set.Members("staff")
	if err == nil || errors.Is(err, ErrNoSuchGroup) {
		t.Errorf("a broken source read as a missing group: %v", err)
	}
	if !strings.Contains(err.Error(), "the database is down") {
		t.Errorf("the reason was lost: %v", err)
	}
	// And one bad source fails the whole read of the people, because a
	// server that starts with half its users is a server that will refuse
	// somebody for no reason they can see.
	if _, err := set.Identities(); err == nil {
		t.Error("the people were read from a broken source")
	}
}

type failing struct{ err error }

func (f *failing) Describe() string                 { return "a broken source" }
func (f *failing) Identities() ([]*Identity, error) { return nil, f.err }
func (f *failing) Members(string) ([]string, error) { return nil, f.err }

func TestExpandingGroups(t *testing.T) {
	src := &Static{Groups: map[string][]string{
		"staff": {"alice", "bob"},
		"empty": {},
		"both":  {"bob", "carol"},
	}}
	got, err := Expand([]string{"@staff", "carol", "@both", "alice"}, src)
	if err != nil {
		t.Fatal(err)
	}
	// Order kept, repeats dropped: a list a person can read back.
	if strings.Join(got, ",") != "alice,bob,carol" {
		t.Errorf("expanded to %v", got)
	}
	if _, err := Expand([]string{"@empty"}, src); err == nil {
		t.Error("a group with nobody in it expanded to nothing instead of being refused")
	}
	if _, err := Expand([]string{"@nobody"}, src); !errors.Is(err, ErrNoSuchGroup) {
		t.Errorf("an unknown group gave %v", err)
	}
	if !IsGroup("@staff") || IsGroup("alice") {
		t.Error("a group is spelled @name")
	}
}

func TestTheSmallSurface(t *testing.T) {
	// The bits a caller uses to build a set and to print what it built.
	set := NewSet(&Static{Name: "one"})
	set.Add(&Static{Name: "two"})
	if len(set.Sources()) != 2 {
		t.Errorf("%d sources", len(set.Sources()))
	}
	if set.Describe() != "one, then two" {
		t.Errorf("Describe = %q", set.Describe())
	}
	if (&Static{}).Describe() != "a list held in memory" {
		t.Error("an unnamed static source has no description")
	}
	// Close reaches whichever sources hold something open, and tolerates the
	// ones that do not.
	if err := set.Close(); err != nil {
		t.Error(err)
	}

	id := NewIdentity("alice", WithGroups("staff", "admins"), From("a test"))
	if strings.Join(id.Groups(), ",") != "staff,admins" {
		t.Errorf("groups = %v", id.Groups())
	}
	if id.Where() != "a test" {
		t.Errorf("where = %q", id.Where())
	}
	// A credential nobody has heard of is not one this identity has.
	if id.Can(Credential(99)) {
		t.Error("an unknown credential was claimed")
	}
	if Credential(99).String() != "an unknown credential" {
		t.Errorf("unknown credential prints as %q", Credential(99))
	}
	// Each one names itself, so a server can say what it has and what a
	// protocol wanted in the same sentence.
	for c, want := range map[Credential]string{
		Password: "a password", NTHash: "an NT hash",
		Verifier: "a password check", PublicKeys: "public keys",
	} {
		if c.String() != want {
			t.Errorf("%d prints as %q, want %q", c, c, want)
		}
	}
}
