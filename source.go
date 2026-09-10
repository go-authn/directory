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

// ErrNoSuchGroup is what a source returns for a name it does not have.
var ErrNoSuchGroup = errors.New("directory: no such group")

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
	return nil, fmt.Errorf("%w: %q", ErrNoSuchGroup, group)
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
			return nil, fmt.Errorf("directory: group %q has no members: nobody would be allowed", group)
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
