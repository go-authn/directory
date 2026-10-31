// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"fmt"
	"slices"
)

// GroupData is everything one source says about one group: what Members,
// GroupAttributes and GroupObjectClasses would each answer for it.
type GroupData struct {
	Members    []string
	Attributes Attributes
	Classes    ObjectClasses
}

// A GroupReader is a source that can say everything about every group in one
// pass.
//
// It is optional, for the reason [GroupLister] is. A server that publishes
// every group asks each one three questions (Members, GroupAttributes,
// GroupObjectClasses), and a source whose answer to a question about ONE group
// costs a scan of all of them -- a database whose memberships come from one
// query, a directory that is dialled and searched for each call -- makes that
// O(groups x rows). ReadGroups is the same answers for the cost of reading
// each query once.
//
// The map is keyed by group name and holds exactly the groups the source has
// (those GroupNames lists). For each, the three fields are what the per-group
// methods return for it; a group not in the map is [ErrNoSuchGroup] for all
// three. The result is the caller's to keep: the source does not read it
// again.
type GroupReader interface {
	ReadGroups() (map[string]GroupData, error)
}

// Frozen is this set with the groups of every [GroupReader] source read now,
// once, and answered from memory by Members, GroupAttributes,
// GroupObjectClasses and GroupNames. Other sources are asked as they always
// are.
//
// The answers are the ones the set gives (the same merging, the same
// precedence, the same errors), because it is the same Set code asking sources
// that answer from what was read. A source that cannot be read is an error
// here, not a group missing later.
//
// The sources are shared with the receiver and still belong to it: close the
// receiver, never the result.
func (s *Set) Frozen() (*Set, error) {
	out := make([]Source, len(s.sources))
	for i, src := range s.sources {
		r, ok := src.(GroupReader)
		if !ok {
			out[i] = src
			continue
		}
		groups, err := r.ReadGroups()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Describe(), err)
		}
		out[i] = &frozenSource{Source: src, groups: groups}
	}
	return &Set{sources: out}, nil
}

// A frozenSource answers the group questions from what ReadGroups returned,
// and the others (Describe, Identities, Members' siblings) from the source.
type frozenSource struct {
	Source
	groups map[string]GroupData
}

func (f *frozenSource) GroupNames() ([]string, error) {
	names := make([]string, 0, len(f.groups))
	for n := range f.groups {
		names = append(names, n)
	}
	slices.Sort(names)
	return names, nil
}

func (f *frozenSource) Members(group string) ([]string, error) {
	g, ok := f.groups[group]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoSuchGroup, group)
	}
	return g.Members, nil
}

func (f *frozenSource) GroupAttributes(group string) (Attributes, error) {
	g, ok := f.groups[group]
	if !ok {
		return Attributes{}, fmt.Errorf("%w: %q", ErrNoSuchGroup, group)
	}
	return g.Attributes, nil
}

func (f *frozenSource) GroupObjectClasses(group string) (ObjectClasses, error) {
	g, ok := f.groups[group]
	if !ok {
		return ObjectClasses{}, fmt.Errorf("%w: %q", ErrNoSuchGroup, group)
	}
	return g.Classes, nil
}

var (
	_ GroupLister        = (*frozenSource)(nil)
	_ GroupAttributer    = (*frozenSource)(nil)
	_ GroupObjectClasser = (*frozenSource)(nil)
)
