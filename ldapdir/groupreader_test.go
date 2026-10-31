// SPDX-License-Identifier: BSD-3-Clause

package ldapdir_test

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
)

func sameKind(a, b error) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || errors.Is(a, directory.ErrNoSuchGroup) == errors.Is(b, directory.ErrNoSuchGroup)
}

// differences asks a set and its frozen copy the same questions about every
// group and reports each answer that differs.
func differences(t *testing.T, s *directory.Set, names []string) []string {
	t.Helper()
	f, err := s.Frozen()
	if err != nil {
		t.Fatalf("Frozen: %v", err)
	}
	var out []string
	gn1, e1 := s.GroupNames()
	gn2, e2 := f.GroupNames()
	if !sameKind(e1, e2) || !reflect.DeepEqual(gn1, gn2) {
		out = append(out, fmt.Sprintf("GroupNames: %v %v / %v %v", gn1, e1, gn2, e2))
	}
	for _, g := range append(append([]string(nil), names...), "no-such-group") {
		m1, e1 := s.Members(g)
		m2, e2 := f.Members(g)
		if !sameKind(e1, e2) || !reflect.DeepEqual(m1, m2) {
			out = append(out, fmt.Sprintf("Members(%s): %v %v / %v %v", g, m1, e1, m2, e2))
		}
		a1, e1 := s.GroupAttributes(g)
		a2, e2 := f.GroupAttributes(g)
		if !sameKind(e1, e2) || !reflect.DeepEqual(a1, a2) {
			out = append(out, fmt.Sprintf("GroupAttributes(%s): %v %v / %v %v", g, a1, e1, a2, e2))
		}
		c1, e1 := s.GroupObjectClasses(g)
		c2, e2 := f.GroupObjectClasses(g)
		if !sameKind(e1, e2) || !reflect.DeepEqual(c1, c2) {
			out = append(out, fmt.Sprintf("GroupObjectClasses(%s): %v %v / %v %v", g, c1, e1, c2, e2))
		}
	}
	return out
}

// The bulk read gives what the per-group methods give, on the fixture whose
// member DNs name the imported, the not imported, a spoof and nobody.
func TestBulkReadEqualsPerGroupRead(t *testing.T) {
	d := groupsDirectory(t)
	for name, cfg := range map[string]ldapdir.Config{
		"defaults":         {},
		"member attribute": {MemberAttribute: "member"},
		"memberUid":        {MemberAttribute: "memberUid"},
		"group attributes": {GroupAttributes: []string{"description", "gidNumber"}},
		"declared classes": {GroupObjectClasses: []string{"posixGroup"}},
	} {
		t.Run(name, func(t *testing.T) {
			src := groupsSource(t, d, cfg)
			if diff := differences(t, directory.NewSet(src), []string{"staff", "team", "forged"}); len(diff) > 0 {
				t.Fatal(diff)
			}
		})
	}
}

// One search for the groups, however many there are.
func TestFrozenReadsOnce(t *testing.T) {
	d := groupsDirectory(t)
	src := groupsSource(t, d, ldapdir.Config{})
	groups, err := src.ReadGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 3 {
		t.Fatalf("%d groups: %v", len(groups), groups)
	}
}

// A directory that is not there is an error, not an empty answer.
func TestReadGroupsFromADirectoryThatIsGone(t *testing.T) {
	d := groupsDirectory(t)
	src := groupsSource(t, d, ldapdir.Config{})
	d.Close()
	if _, err := src.ReadGroups(); err == nil {
		t.Fatal("a directory that is down read as having no groups")
	}
	if _, err := directory.NewSet(src).Frozen(); err == nil {
		t.Fatal("Frozen hid it")
	}
}
