// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// A Source is somewhere people are kept.
//
// The three questions are the whole interface, and they are the three a file
// server actually asks: who is here, who is in this group, and where did that
// come from.
type Source interface {
	// Identities is everybody this source knows, with whatever credentials it
	// has for them.
	Identities() ([]*Identity, error)

	// Members expands one group. A group the source has never heard of is an
	// ERROR, not an empty list: an empty list quietly grants nothing to
	// nobody, which reads exactly like a working configuration.
	Members(group string) ([]string, error)

	// Describe says what this is, for a server to print: "a postgres
	// database", "ldaps://ldap.example.org", "the configuration file".
	Describe() string
}

// A GroupLister is a source that can say WHICH groups it has, rather than only
// answering about one by name.
//
// It is a separate, optional interface because not every source can. Members
// asks a question with the name in hand -- an LDAP filter, a WHERE clause --
// and a source that answers those need not be able to enumerate: a query that
// lists people says nothing about groups at all, and a directory may permit
// one and refuse the other.
//
// A server that PUBLISHES groups needs this; one that only checks membership
// does not, which is why adding it did not change the Source interface.
type GroupLister interface {
	GroupNames() ([]string, error)
}

// A GroupAttributer is a source that can say what a group IS beyond who is in
// it: a gidNumber, a description.
//
// Optional for the reason [GroupLister] is: a source that implements nothing
// new still compiles and still answers Members, and a [Set] asks it only
// whether it has the group.
//
// It answers like Members: [ErrNoSuchGroup] for a group the source does not
// have, and an empty Attributes, with no error, for one it has and says
// nothing about.
type GroupAttributer interface {
	GroupAttributes(group string) (Attributes, error)
}

// ErrNoSuchGroup is what a source returns for a name it does not have.
var ErrNoSuchGroup = errors.New("directory: no such group")

// ErrEmptyGroup is what Expand returns for a group a source HAS, with nobody
// in it: not ErrNoSuchGroup, because the remedy differs -- a typo or a
// deleted group on one side, a group to fill on the other. A caller that
// tolerates a group that grants nothing tests for both.
var ErrEmptyGroup = errors.New("directory: the group has no members")

// A Set is several sources read as one.
//
// A site with its people in LDAP and one service account written down locally
// should not have to put the service account in LDAP. So the sources are asked
// in the order they were given and the FIRST one that knows a name owns it —
// which is the rule a person can hold in their head, and the one that lets a
// local file override a directory rather than the other way round.
type Set struct {
	sources []Source
}

// NewSet reads these sources, in this order.
func NewSet(sources ...Source) *Set { return &Set{sources: sources} }

// Add appends a source, which will be asked after the ones already there.
func (s *Set) Add(src Source) { s.sources = append(s.sources, src) }

// Sources are the sources, in order.
func (s *Set) Sources() []Source { return slices.Clone(s.sources) }

func (s *Set) Describe() string {
	names := make([]string, 0, len(s.sources))
	for _, src := range s.sources {
		names = append(names, src.Describe())
	}
	return strings.Join(names, ", then ")
}

func (s *Set) Identities() ([]*Identity, error) {
	var out []*Identity
	seen := map[string]bool{}
	for _, src := range s.sources {
		ids, err := src.Identities()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Describe(), err)
		}
		for _, id := range ids {
			if seen[id.name] {
				// Deliberately not an error: adding somebody to LDAP must not
				// break a server that has them written down locally.
				continue
			}
			seen[id.name] = true
			if id.where == "" {
				id.where = src.Describe()
			}
			out = append(out, id)
		}
	}
	return out, nil
}

// Members asks every source and puts the answers together: a group can have
// people from a database and from a file, and a server that returned only the
// first source's half would silently exclude the rest.
func (s *Set) Members(group string) ([]string, error) {
	var members []string
	var missing int
	var firstErr error
	for _, src := range s.sources {
		got, err := src.Members(group)
		if err != nil {
			if errors.Is(err, ErrNoSuchGroup) {
				missing++
				continue
			}
			// A source that is BROKEN is not a source that lacks the group,
			// and the difference decides whether a configuration is wrong or a
			// database is down.
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", src.Describe(), err)
			}
			continue
		}
		for _, m := range got {
			if !slices.Contains(members, m) {
				members = append(members, m)
			}
		}
	}
	switch {
	case len(members) > 0:
		return members, nil
	case firstErr != nil:
		return nil, firstErr
	case missing == len(s.sources):
		return nil, fmt.Errorf("%w: %q, in %s", ErrNoSuchGroup, group, s.Describe())
	}
	// ⛔ A source HAS the group, and nobody is in it. This said
	// ErrNoSuchGroup before v0.12.0, so Expand's "has no members" could never
	// be reached through a Set, a group listed by GroupNames was then "no such
	// group" when asked about, and a server listing groups failed on it.
	return []string{}, nil
}

// GroupAttributes asks every source about one group and puts the answers
// together, one attribute at a time: the first source to give an attribute
// owns it, so a gidNumber written in a local file overrides the directory's,
// and a description only the directory has still comes through. Values are
// never merged across sources -- two sources giving a group two gidNumbers is
// a disagreement, and taking the union would publish both.
//
// A source that cannot describe groups (no [GroupAttributer]) is asked
// Members instead, to learn whether it HAS the group: a group that exists
// only there is answered with no attributes, not with ErrNoSuchGroup.
//
// ⛔ Unlike Members, a broken source is an error even when another answered.
// Members can return the half it has, because more people is the only thing
// the missing half could add. Here the missing source may be the one whose
// gidNumber should have WON, and answering without it would publish a
// different group id -- which decides who may read which files -- with
// nothing saying so.
func (s *Set) GroupAttributes(group string) (Attributes, error) {
	var out Attributes
	var found bool
	for _, src := range s.sources {
		var got Attributes
		var err error
		if ga, ok := src.(GroupAttributer); ok {
			got, err = ga.GroupAttributes(group)
		} else {
			_, err = src.Members(group)
		}
		if err != nil {
			if errors.Is(err, ErrNoSuchGroup) {
				continue
			}
			return Attributes{}, fmt.Errorf("%s: %w", src.Describe(), err)
		}
		found = true
		out = out.under(got)
	}
	if !found {
		return Attributes{}, fmt.Errorf("%w: %q, in %s", ErrNoSuchGroup, group, s.Describe())
	}
	return out, nil
}

// GroupNames is every group the sources can name, sorted and without repeats.
//
// Sources that cannot list groups are skipped rather than refused, so this can
// legitimately return FEWER groups than [Set.Members] would answer for: an
// LDAP directory that will not enumerate still answers about a group somebody
// names. A caller publishing a list should say where it came from, and a
// caller checking membership should keep asking Members.
func (s *Set) GroupNames() ([]string, error) {
	var names []string
	var firstErr error
	for _, src := range s.sources {
		lister, ok := src.(GroupLister)
		if !ok {
			continue
		}
		got, err := lister.GroupNames()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", src.Describe(), err)
			}
			continue
		}
		names = append(names, got...)
	}
	if len(names) == 0 && firstErr != nil {
		return nil, firstErr
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

// Close closes whichever sources hold something open.
func (s *Set) Close() error {
	var err error
	for _, src := range s.sources {
		if c, ok := src.(interface{ Close() error }); ok {
			if cerr := c.Close(); err == nil {
				err = cerr
			}
		}
	}
	return err
}

// GroupPrefix is how a group is written where a person could be: @staff. It is
// Samba's spelling (`valid users = @staff`) and what anybody administering a
// file server types without being told.
const GroupPrefix = "@"

// IsGroup reports whether a name is a group's.
func IsGroup(name string) bool { return strings.HasPrefix(name, GroupPrefix) }

// Expand turns a list of names — people and groups — into the people in it,
// keeping the order and dropping repeats.
//
// A group with nobody in it is refused rather than expanded to nothing: a
// configuration that grants nothing to nobody reads exactly like one that
// works.
func Expand(names []string, src Source) ([]string, error) {
	var out []string
	add := func(name string) {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	for _, name := range names {
		if !IsGroup(name) {
			add(name)
			continue
		}
		group := strings.TrimPrefix(name, GroupPrefix)
		members, err := src.Members(group)
		if err != nil {
			return nil, err
		}
		if len(members) == 0 {
			return nil, fmt.Errorf("%w: %q: nobody would be allowed", ErrEmptyGroup, group)
		}
		for _, m := range members {
			add(m)
		}
	}
	return out, nil
}

// Static is a source held in memory: what a program's own configuration file
// becomes once it is read, and what a test uses.
type Static struct {
	Name   string
	People []*Identity
	Groups map[string][]string

	// GroupAttrs describe the groups in Groups. A group is one of this
	// source's because it is in Groups: an entry here for a group that is not
	// there describes nothing, and is answered as no such group.
	GroupAttrs map[string]Attributes
}

// GroupAttributes is what this list says about a group.
func (s *Static) GroupAttributes(group string) (Attributes, error) {
	if _, ok := s.Groups[group]; !ok {
		return Attributes{}, fmt.Errorf("%w: %q", ErrNoSuchGroup, group)
	}
	return s.GroupAttrs[group], nil
}

func (s *Static) Describe() string {
	if s.Name == "" {
		return "a list held in memory"
	}
	return s.Name
}

func (s *Static) Identities() ([]*Identity, error) { return slices.Clone(s.People), nil }

// GroupNames is the groups this list holds, which it knows exactly.
func (s *Static) GroupNames() ([]string, error) {
	names := make([]string, 0, len(s.Groups))
	for name := range s.Groups {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, nil
}

func (s *Static) Members(group string) ([]string, error) {
	members, ok := s.Groups[group]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoSuchGroup, group)
	}
	return slices.Clone(members), nil
}
