// SPDX-License-Identifier: BSD-3-Clause

package hcldir

import (
	"testing"

	"github.com/go-authn/directory"
)

// The four things a source can be, and the wrapper keeping each of them. A
// case missing here is a server that silently stops publishing groups, or
// their attributes.
type plain struct{}

func (p *plain) Identities() ([]*directory.Identity, error) { return nil, nil }
func (p *plain) Members(string) ([]string, error)           { return []string{}, nil }
func (p *plain) Describe() string                           { return "plain" }

type lists struct{ plain }

func (lists) GroupNames() ([]string, error) { return []string{"g"}, nil }

type describes struct{ plain }

func (describes) GroupAttributes(string) (directory.Attributes, error) {
	return directory.NewAttributes(directory.Attribute{Name: "gidNumber", Values: []string{"7"}})
}

type both struct{ plain }

func (both) GroupNames() ([]string, error) { return []string{"g"}, nil }
func (both) GroupAttributes(string) (directory.Attributes, error) {
	return directory.NewAttributes(directory.Attribute{Name: "gidNumber", Values: []string{"7"}})
}

func TestTheClosingWrapperKeepsWhatTheSourceCanDo(t *testing.T) {
	closed := 0
	done := func() error { closed++; return nil }
	for _, tc := range []struct {
		src                  directory.Source
		canList, canDescribe bool
	}{
		{&plain{}, false, false},
		{&lists{}, true, false},
		{&describes{}, false, true},
		{&both{}, true, true},
	} {
		w := closing(tc.src, done)
		l, isLister := w.(directory.GroupLister)
		a, isAttributer := w.(directory.GroupAttributer)
		if isLister != tc.canList || isAttributer != tc.canDescribe {
			t.Errorf("%T: lister %v attributer %v, want %v %v", tc.src, isLister, isAttributer, tc.canList, tc.canDescribe)
		}
		if isLister {
			if n, err := l.GroupNames(); err != nil || len(n) != 1 {
				t.Errorf("%T: GroupNames %v %v", tc.src, n, err)
			}
		}
		if isAttributer {
			if g, err := a.GroupAttributes("g"); err != nil || g.Get("gidNumber")[0] != "7" {
				t.Errorf("%T: GroupAttributes %v %v", tc.src, g.Names(), err)
			}
		}
		if err := w.(interface{ Close() error }).Close(); err != nil {
			t.Fatal(err)
		}
	}
	if closed != 4 {
		t.Errorf("%d closes, want 4", closed)
	}
}
