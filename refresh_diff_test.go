package directory

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"testing"
)

// referenceMembers is Set.Members' merge as it was before the set was
// introduced for long groups: first appearance wins, by linear search.
func referenceMembers(lists [][]string) []string {
	var members []string
	for _, got := range lists {
		for _, m := range got {
			if !slices.Contains(members, m) {
				members = append(members, m)
			}
		}
	}
	return members
}

func randomLists(r *rand.Rand) [][]string {
	var lists [][]string
	for i := r.IntN(4); i >= 0; i-- {
		n := r.IntN(200) // crosses the point where the merge switches to a set
		var l []string
		for j := 0; j < n; j++ {
			l = append(l, fmt.Sprint("m", r.IntN(150)))
		}
		lists = append(lists, l)
	}
	return lists
}

func setOf(lists [][]string) *Set {
	var srcs []Source
	for i, l := range lists {
		srcs = append(srcs, &Static{Name: fmt.Sprint("s", i), Groups: map[string][]string{"g": l}})
	}
	return NewSet(srcs...)
}

// The merge answers as the linear one did: same members, same order.
func TestSetMembersMatchesReference(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for round := 0; round < 500; round++ {
		lists := randomLists(r)
		want := referenceMembers(lists)
		got, err := setOf(lists).Members("g")
		if err != nil {
			t.Fatal(err)
		}
		if len(want) == 0 {
			if len(got) != 0 {
				t.Fatalf("round %d: %v, want none", round, got)
			}
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d: merge differs\n got %v\nwant %v", round, got, want)
		}
	}
}

// The planted fault: a merge that drops the order of first appearance (it
// returns the members sorted). The comparison above must see it.
func TestSetMembersDifferentialSeesAFault(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for round := 0; round < 500; round++ {
		lists := randomLists(r)
		want := referenceMembers(lists)
		bad := slices.Clone(want)
		slices.Sort(bad)
		if len(want) > 1 && !reflect.DeepEqual(bad, want) {
			return // noticed
		}
	}
	t.Fatal("the comparison could not tell a reordered merge from the right one")
}

// NewAttributes: an attribute given twice, in different case and with its
// options reordered, is one attribute holding the values of both, an exact
// repeat kept once, order kept.
func TestNewAttributesMergeUnchanged(t *testing.T) {
	a, err := NewAttributes(
		Attribute{Name: "description", Values: []string{"a", "b", "a"}},
		Attribute{Name: "mail", Values: []string{"x@example.org"}},
		Attribute{Name: "DESCRIPTION", Values: []string{"b", "c"}},
		Attribute{Name: "title;lang-fr;x", Values: []string{"n"}},
		Attribute{Name: "title;x;lang-fr", Values: []string{"m"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.Names(); !reflect.DeepEqual(got, []string{"description", "mail", "title;lang-fr;x"}) {
		t.Errorf("names %v", got)
	}
	if got := a.Get("description"); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("description %v", got)
	}
	if got := a.Get("TITLE;x;lang-fr"); !reflect.DeepEqual(got, []string{"n", "m"}) {
		t.Errorf("cn %v", got)
	}
	// The values of the result must not alias the caller's slice.
	in := []string{"v"}
	b, _ := NewAttributes(Attribute{Name: "o", Values: in})
	in[0] = "changed"
	if b.Get("o")[0] != "v" {
		t.Error("the attribute aliases the caller's values")
	}
	if z, _ := NewAttributes(); !reflect.DeepEqual(z, Attributes{}) {
		t.Errorf("no attributes is not the zero value: %#v", z)
	}
}
