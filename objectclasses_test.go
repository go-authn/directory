// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func mustClasses(t *testing.T, names ...string) ObjectClasses {
	t.Helper()
	c, err := NewObjectClasses(names...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The order declared, each class once whatever its case, spelled the first
// way it was written.
func TestObjectClassesKeepTheirOrderAndDropRepeats(t *testing.T) {
	c := mustClasses(t, "supannPerson", "eduPerson", "EDUPERSON", "supannperson", "schacContactLocation", "eduPerson")
	want := []string{"supannPerson", "eduPerson", "schacContactLocation"}
	if got := c.Names(); !slices.Equal(got, want) || c.Len() != 3 {
		t.Errorf("Names = %v (Len %d), want %v", got, c.Len(), want)
	}
	// A copy: changing it changes nothing.
	c.Names()[0] = "changed"
	if c.Names()[0] != "supannPerson" {
		t.Error("Names handed out the list itself")
	}
	if z := (ObjectClasses{}); z.Len() != 0 || len(z.Names()) != 0 {
		t.Error("the zero value declares something")
	}
	if e := mustClasses(t); e.Len() != 0 {
		t.Error("no names declared something")
	}
}

// Every name the standard schemas, SUPANN and eduPerson give an auxiliary
// class is a descr, and passes.
func TestTheClassNamesInUseAreAccepted(t *testing.T) {
	for _, n := range []string{"eduPerson", "eduOrg", "supannPerson", "supannOrg", "supannGroupe",
		"schacPersonalCharacteristics", "inetLocalMailRecipient", "x", "a-b-1"} {
		if err := CheckObjectClassName(n); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
}

// What is refused, and why: the names reach an LDAP server's output, so
// nothing but a descr gets through.
func TestWhatIsRefusedAsAnObjectClass(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"", "needs a name"},
		{"1.3.6.1.4.1.5923.1.1.2", "is an OID"},
		{"2.5.6.6", "is an OID"},
		{"0", "is an OID"},
		{"edu person", "not a descriptor"},
		{" eduPerson", "not a descriptor"},
		{"eduPerson ", "not a descriptor"},
		{`"eduPerson"`, "not a descriptor"},
		{"'eduPerson'", "not a descriptor"},
		{"eduPerson)", "not a descriptor"},
		{"( 1.2.3 NAME 'x' )", "not a descriptor"},
		{"-eduPerson", "not a descriptor"},
		{"edu_person", "not a descriptor"},
		{"eduPerson;x", "not a descriptor"},
		{"édu", "not a descriptor"},
		{"edu\x00Person", "not a descriptor"},
		{"edu\nPerson", "not a descriptor"},
		{"edu$Person", "not a descriptor"},
	} {
		err := CheckObjectClassName(tc.name)
		if !errors.Is(err, ErrObjectClassName) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want %q", tc.name, err, tc.want)
		}
		// And the whole declaration goes with it, rather than the rest
		// being kept.
		c, err := NewObjectClasses("eduPerson", tc.name)
		if err == nil || c.Len() != 0 {
			t.Errorf("%q: NewObjectClasses kept %v, %v", tc.name, c.Names(), err)
		}
	}
}

func TestAnIdentityCarriesItsDeclaredClasses(t *testing.T) {
	id := NewIdentity("alice",
		WithObjectClasses(mustClasses(t, "supannPerson", "eduPerson")),
		WithObjectClasses(mustClasses(t, "EDUPERSON", "schacContactLocation")))
	want := []string{"supannPerson", "eduPerson", "schacContactLocation"}
	if got := id.ObjectClasses(); !slices.Equal(got, want) {
		t.Errorf("ObjectClasses = %v, want %v", got, want)
	}
	id.ObjectClasses()[0] = "changed"
	if id.ObjectClasses()[0] != "supannPerson" {
		t.Error("ObjectClasses handed out the list itself")
	}
	if got := NewIdentity("bob").ObjectClasses(); len(got) != 0 {
		t.Errorf("an identity nobody declared anything for has %v", got)
	}
	// Classes and attributes are separate: declaring one adds none of the
	// other.
	if id.Attributes().Len() != 0 {
		t.Errorf("declaring classes added attributes %v", id.Attributes().Names())
	}
}

type brokenClasses struct{ membersOnly }

func (brokenClasses) GroupObjectClasses(string) (ObjectClasses, error) {
	return ObjectClasses{}, errors.New("down")
}

// The first source that has the group and declares classes decides, whole;
// one that declares nothing does not; a disagreement is the first one's.
func TestASetTakesAGroupsClassesFromTheFirstSourceThatDeclares(t *testing.T) {
	local := &Static{Name: "the file", Groups: map[string][]string{"staff": {"alice"}, "ops": {"bob"}}}
	dir := &Static{Name: "the directory",
		Groups: map[string][]string{"staff": {"carol"}, "ops": nil, "lab": {"dora"}},
		GroupClasses: map[string]ObjectClasses{
			"staff": mustClasses(t, "supannGroupe"),
			"lab":   mustClasses(t, "supannGroupe", "eduOrg"),
		}}
	other := &Static{Name: "another directory",
		Groups:       map[string][]string{"lab": {"eve"}},
		GroupClasses: map[string]ObjectClasses{"lab": mustClasses(t, "groupOfUniqueNames")}}
	old := membersOnly{groups: map[string][]string{"staff": {"alice"}, "legacy": {"x"}}}

	s := NewSet(old, local, dir, other)
	for _, tc := range []struct {
		group string
		want  []string
	}{
		// old and local have it and declare nothing; dir decides.
		{"staff", []string{"supannGroupe"}},
		// dir and other disagree: dir is first, and other is ignored, not merged.
		{"lab", []string{"supannGroupe", "eduOrg"}},
		// Had by several, declared by none.
		{"ops", nil},
		// Had only by a source that cannot declare.
		{"legacy", nil},
	} {
		got, err := s.GroupObjectClasses(tc.group)
		if err != nil || !slices.Equal(got.Names(), tc.want) {
			t.Errorf("%s = %v, %v; want %v", tc.group, got.Names(), err, tc.want)
		}
	}
	if _, err := s.GroupObjectClasses("nobody"); !errors.Is(err, ErrNoSuchGroup) {
		t.Errorf("a group no source has: %v", err)
	}

	// A Static's entry for a group it does not have declares nothing.
	stray := &Static{GroupClasses: map[string]ObjectClasses{"ghost": mustClasses(t, "eduOrg")}}
	if _, err := stray.GroupObjectClasses("ghost"); !errors.Is(err, ErrNoSuchGroup) {
		t.Errorf("a stray entry answered: %v", err)
	}
}

// A broken source BEFORE the one that decides is an error -- it may be the
// one that should have decided. After it, it is never asked.
func TestABrokenSourceAndAGroupsClasses(t *testing.T) {
	dir := &Static{Name: "the directory", Groups: map[string][]string{"staff": {"a"}},
		GroupClasses: map[string]ObjectClasses{"staff": mustClasses(t, "supannGroupe")}}
	broken := brokenClasses{membersOnly{groups: map[string][]string{"staff": {"a"}}}}
	down := &failing{err: errors.New("down")}

	for _, s := range []*Set{NewSet(broken, dir), NewSet(down, dir)} {
		if _, err := s.GroupObjectClasses("staff"); err == nil || errors.Is(err, ErrNoSuchGroup) {
			t.Errorf("%s: a broken source first gave %v", s.Describe(), err)
		}
	}
	for _, s := range []*Set{NewSet(dir, broken), NewSet(dir, down)} {
		got, err := s.GroupObjectClasses("staff")
		if err != nil || !slices.Equal(got.Names(), []string{"supannGroupe"}) {
			t.Errorf("%s: %v, %v", s.Describe(), got.Names(), err)
		}
	}
}

// A person's classes ride on the person, so the source that owns the person
// owns the classes: a later source's declaration for the same name is not
// added.
func TestAPersonsClassesComeFromTheSourceThatOwnsThem(t *testing.T) {
	first := &Static{People: []*Identity{NewIdentity("alice", WithObjectClasses(mustClasses(t, "eduPerson")))}}
	second := &Static{People: []*Identity{
		NewIdentity("alice", WithObjectClasses(mustClasses(t, "supannPerson"))),
		NewIdentity("bob", WithObjectClasses(mustClasses(t, "supannPerson"))),
	}}
	ids, err := NewSet(first, second).Identities()
	if err != nil || len(ids) != 2 {
		t.Fatal(ids, err)
	}
	if got := ids[0].ObjectClasses(); !slices.Equal(got, []string{"eduPerson"}) {
		t.Errorf("alice = %v", got)
	}
	if got := ids[1].ObjectClasses(); !slices.Equal(got, []string{"supannPerson"}) {
		t.Errorf("bob = %v", got)
	}
}

// Whatever the input, an accepted name is a descr -- a letter, then letters,
// digits and hyphens -- and so carries nothing that could break out of the
// schema syntax or a filter around it.
func FuzzCheckObjectClassName(f *testing.F) {
	for _, s := range []string{"eduPerson", "supannPerson", "1.3.6.1", "edu person", `"x"`, "a(b)", "", "a-", "é"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		err := CheckObjectClassName(name)
		if err != nil {
			if !errors.Is(err, ErrObjectClassName) {
				t.Fatalf("%q: an error that is not ErrObjectClassName: %v", name, err)
			}
			if _, nerr := NewObjectClasses(name); nerr == nil {
				t.Fatalf("%q: refused by the check and accepted by NewObjectClasses", name)
			}
			return
		}
		if name == "" || !(name[0] >= 'A' && name[0] <= 'Z' || name[0] >= 'a' && name[0] <= 'z') {
			t.Fatalf("%q accepted without a letter first", name)
		}
		for i := 0; i < len(name); i++ {
			b := name[i]
			if !(b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				t.Fatalf("%q accepted with byte %q", name, b)
			}
		}
		c, err := NewObjectClasses(name, strings.ToUpper(name))
		if err != nil || !slices.Equal(c.Names(), []string{name}) {
			t.Fatalf("%q: NewObjectClasses = %v, %v", name, c.Names(), err)
		}
	})
}
