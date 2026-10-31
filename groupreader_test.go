package directory_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/go-authn/directory"
)

// reader is a source that reads its groups in bulk, and counts how.
type reader struct {
	groups map[string]directory.GroupData
	err    error
	reads  int
}

func (r *reader) Describe() string                           { return "the reader" }
func (r *reader) Identities() ([]*directory.Identity, error) { return nil, nil }
func (r *reader) Members(string) ([]string, error)           { panic("asked per group") }
func (r *reader) ReadGroups() (map[string]directory.GroupData, error) {
	r.reads++
	return r.groups, r.err
}

func TestFrozenAnswersFromOneRead(t *testing.T) {
	attrs, err := directory.NewAttributes(directory.Attribute{Name: "gidNumber", Values: []string{"7"}})
	if err != nil {
		t.Fatal(err)
	}
	classes, _ := directory.NewObjectClasses("posixGroup")
	r := &reader{groups: map[string]directory.GroupData{
		"b": {Members: []string{"x"}, Attributes: attrs, Classes: classes},
		"a": {Members: []string{}},
	}}
	local := &directory.Static{Name: "local", Groups: map[string][]string{"c": {"y"}}}
	f, err := directory.NewSet(r, local).Frozen()
	if err != nil {
		t.Fatal(err)
	}
	for range 3 { // however often it is asked
		if m, err := f.Members("b"); err != nil || !slices.Equal(m, []string{"x"}) {
			t.Fatalf("Members(b) = %v, %v", m, err)
		}
		if _, err := f.GroupAttributes("b"); err != nil {
			t.Fatal(err)
		}
		if c, err := f.GroupObjectClasses("b"); err != nil || c.Len() != 1 {
			t.Fatalf("classes: %v %v", c, err)
		}
	}
	if r.reads != 1 {
		t.Fatalf("%d reads, want 1", r.reads)
	}
	if names, err := f.GroupNames(); err != nil || !slices.Equal(names, []string{"a", "b", "c"}) {
		t.Fatalf("GroupNames = %v, %v", names, err)
	}
	// A group the reader does not have is ErrNoSuchGroup from all three; the
	// other source still answers for its own.
	for _, ask := range []func() error{
		func() error { _, err := f.Members("zzz"); return err },
		func() error { _, err := f.GroupAttributes("zzz"); return err },
		func() error { _, err := f.GroupObjectClasses("zzz"); return err },
	} {
		if err := ask(); !errors.Is(err, directory.ErrNoSuchGroup) {
			t.Errorf("a group nobody has: %v", err)
		}
	}
	if m, err := f.Members("c"); err != nil || !slices.Equal(m, []string{"y"}) {
		t.Fatalf("Members(c) = %v, %v", m, err)
	}
}

func TestFrozenNamesTheSourceThatFailed(t *testing.T) {
	boom := errors.New("boom")
	_, err := directory.NewSet(&reader{err: boom}).Frozen()
	if !errors.Is(err, boom) || err.Error()[:10] != "the reader" {
		t.Fatalf("got %v", err)
	}
}
