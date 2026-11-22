package directory

import (
	"errors"
	"slices"
	"testing"
)

// corpus: ASCII case, Unicode case, compatibility forms and the whitespace
// variants caseIgnoreMatch folds (RFC 4518).
var equivCorpus = []string{
	"alice", "Alice", "ALICE", "aLiCe",
	"alice ", " alice", "  alice  ", "alice ", // trailing/leading space, NBSP
	"al ice", "al  ice", "Al   Ice", "al ice", // internal space compression
	"ａlice", "ＡＬＩＣＥ", // fullwidth (compatibility folding)
	"ſam", "sam", "SAM", // long s
	"s­am",                                   // soft hyphen is mapped to nothing
	"Straße", "STRASSE", "strasse", "straße", // sharp s folds to ss
	"ǅ", "ǆ", "Ǆ", // titlecase digraph
	"I", "i", "İ", "ı", "İ", // Turkish dotted/dotless i
	"k", "K", "K", // KELVIN SIGN folds to k
	"é", "é", "É", // composed and decomposed
	"bob", "Bob", "carol", "x",
}

func TestNameKeyIsCanonical(t *testing.T) {
	keys := make([]string, len(equivCorpus))
	for i, n := range equivCorpus {
		k, err := nameKey(n)
		if err != nil {
			t.Fatalf("nameKey(%q): %v", n, err)
		}
		keys[i] = k
		// Idempotent: the key is itself a name of the same class.
		kk, err := nameKey(k)
		if err != nil || kk != k {
			t.Errorf("k(k(%q)) = %q, %v; k(%q) = %q", n, kk, err, n, k)
		}
	}
	// x ~ y exactly when k(x) == k(y): symmetric, and every pair agrees with
	// the class it is in (transitivity follows from comparing keys).
	classes := map[string][]string{}
	for i, k := range keys {
		classes[k] = append(classes[k], equivCorpus[i])
	}
	for i, a := range equivCorpus {
		for j, b := range equivCorpus {
			if (keys[i] == keys[j]) != (keys[j] == keys[i]) {
				t.Fatalf("asymmetric on %q, %q", a, b)
			}
		}
	}
	// The classes the LDAP rule must make, and the ones it must not.
	same := [][]string{
		{"alice", "Alice", "ALICE", "alice ", " alice", "ａlice", "ＡＬＩＣＥ"},
		{"al ice", "al  ice", "Al   Ice", "al ice"},
		{"sam", "ſam", "SAM", "s­am"},
		{"Straße", "STRASSE", "strasse", "straße"},
		{"k", "K", "K"},
		{"é", "é", "É"},
	}
	for _, g := range same {
		k0, _ := nameKey(g[0])
		for _, n := range g[1:] {
			if k, _ := nameKey(n); k != k0 {
				t.Errorf("%q and %q should be one name", g[0], n)
			}
		}
	}
	apart := [][2]string{{"alice", "bob"}, {"alice", "al ice"}, {"i", "ı"}, {"i", "İ"}, {"x", "k"}}
	for _, p := range apart {
		a, _ := nameKey(p[0])
		b, _ := nameKey(p[1])
		if a == b {
			t.Errorf("%q and %q should be two names", p[0], p[1])
		}
	}
}

func TestNameKeyFailureRefusesTheName(t *testing.T) {
	for _, bad := range []string{"\xff\xfe", "al\xc3(ice", "   ", ""} {
		if k, err := nameKey(bad); err == nil {
			t.Errorf("nameKey(%q) = %q, nil; want ErrBadName", bad, k)
		} else if !errors.Is(err, ErrBadName) {
			t.Errorf("nameKey(%q): %v, want ErrBadName", bad, err)
		}
	}
	// And a Set refuses it everywhere, never falling back to the bytes.
	bad := NewIdentity("\xff\xfe")
	src := &Static{Name: "s", People: []*Identity{bad}, Groups: map[string][]string{"g": {"alice", "\xff\xfe"}}}
	set := NewSet(src)
	if _, err := set.Identities(); !errors.Is(err, ErrBadName) {
		t.Errorf("Identities: %v, want ErrBadName", err)
	}
	if _, err := set.Members("g"); !errors.Is(err, ErrBadName) {
		t.Errorf("Members: %v, want ErrBadName", err)
	}
	if _, err := Expand([]string{"alice", "\xff\xfe"}, set); !errors.Is(err, ErrBadName) {
		t.Errorf("Expand: %v, want ErrBadName", err)
	}
	// a bad name arriving through a group, from a source that is not a Set
	if _, err := Expand([]string{"@g"}, src); !errors.Is(err, ErrBadName) {
		t.Errorf("Expand of a group with a bad member: %v, want ErrBadName", err)
	}
}

func TestSetShadowsLaterCaseVariantAndReportsIt(t *testing.T) {
	first := &Static{Name: "local", People: []*Identity{NewIdentity("alice")}}
	second := &Static{Name: "ldap", People: []*Identity{NewIdentity("Alice"), NewIdentity("bob")}}
	third := &Static{Name: "file", People: []*Identity{NewIdentity("alice"), NewIdentity("Bob")}}
	set := NewSet(first, second, third)
	if got := set.Shadowed(); len(got) != 0 {
		t.Fatalf("Shadowed before Identities = %v", got)
	}
	ids, err := set.Identities()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, id := range ids {
		names = append(names, id.Name())
	}
	if want := []string{"alice", "bob"}; !slices.Equal(names, want) {
		t.Fatalf("names = %v, want %v (original spelling of the owning source)", names, want)
	}
	if ids[0].Where() != "local" || ids[1].Where() != "ldap" {
		t.Errorf("where = %q, %q", ids[0].Where(), ids[1].Where())
	}
	want := []Shadow{
		{Name: "Alice", Source: "ldap", Owner: "alice", By: "local"},
		{Name: "Bob", Source: "file", Owner: "bob", By: "ldap"},
	}
	// third's "alice" is spelled as the owner spells it: the documented
	// override, not listed.
	if got := set.Shadowed(); !slices.Equal(got, want) {
		t.Errorf("Shadowed = %v, want %v", got, want)
	}
}

func TestSetRefusesACaseVariantWithinASource(t *testing.T) {
	for _, pair := range [][2]string{{"Alice", "alice"}, {"alice", "alice "}, {"K", "K"}, {"ſam", "sam"}} {
		src := &Static{Name: "ldap", People: []*Identity{NewIdentity(pair[0]), NewIdentity(pair[1])}}
		if _, err := NewSet(src).Identities(); !errors.Is(err, ErrAmbiguous) {
			t.Errorf("%q and %q: err = %v, want ErrAmbiguous", pair[0], pair[1], err)
		}
	}
}

func TestSetMembersAndExpandUseTheClass(t *testing.T) {
	a := &Static{Name: "a", Groups: map[string][]string{"g": {"alice", "Bob", "ALICE"}}}
	b := &Static{Name: "b", Groups: map[string][]string{"g": {"Alice", "bob", "carol"}}}
	got, err := NewSet(a, b).Members("g")
	if want := []string{"alice", "Bob", "carol"}; err != nil || !slices.Equal(got, want) {
		t.Errorf("Members = %v, %v; want %v", got, err, want)
	}
	// Past the 64 members the old code switched to a map; the class must
	// still hold there.
	var many []string
	for i := range 200 {
		many = append(many, string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	big := &Static{Name: "big", Groups: map[string][]string{"g": append(slices.Clone(many), "AA", "Ab")}}
	got, err = NewSet(big).Members("g")
	if err != nil || len(got) != 200 {
		t.Errorf("big group: %d members, %v; want 200", len(got), err)
	}
	exp, err := Expand([]string{"Alice", "@g", "alice", "ALICE ", "dave"}, NewSet(a, b))
	if want := []string{"Alice", "Bob", "carol", "dave"}; err != nil || !slices.Equal(exp, want) {
		t.Errorf("Expand = %v, %v; want %v", exp, err, want)
	}
}
