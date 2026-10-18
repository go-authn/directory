// SPDX-License-Identifier: BSD-3-Clause

package ldapdir_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/directory/ldaptest"
)

// groupsDirectory has people under ou=people, one entry elsewhere that holds
// a uid, one person the default filter does not import, and groups of both
// kinds whose member DNs name the imported, the not-imported, a spoof and
// nobody at all.
func groupsDirectory(t *testing.T) *ldaptest.Server {
	t.Helper()
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			"alice": {Password: "a"},
			"bob":   {Password: "b"},
			"carol": {Password: "c"},
			// An entry with uid=alice, OUTSIDE the people base: a part of
			// the tree somebody else may write. Its own uid is "mallory".
			"mallory": {Password: "m", DN: "uid=alice,ou=elsewhere,dc=example,dc=org"},
			// Under the people base, but no class the default filter reads.
			"plain": {Password: "p", ObjectClasses: []string{"top", "person", "organizationalPerson", "inetOrgPerson"},
				Extra: map[string][]string{"sn": {"Plain"}, "cn": {"plain"}}},
		},
		Groups: map[string][]string{"team": {"carol"}},
		GroupsOfNames: map[string][]string{"staff": {
			"uid=alice,ou=people,dc=example,dc=org",
			// The same DN as bob's, written differently: types and values
			// in another case, spaces after the commas (RFC 4514 §3).
			"UID=Bob, OU=People, DC=Example, DC=Org",
			// The spoof: uid=alice, but not the entry alice was imported
			// from.
			"uid=alice,ou=elsewhere,dc=example,dc=org",
			// A DN naming nobody at all.
			"uid=zed,ou=people,dc=example,dc=org",
			// alice's name under another naming attribute: not her DN.
			"cn=alice,ou=people,dc=example,dc=org",
			// Somebody who exists, and is not imported.
			"uid=plain,ou=people,dc=example,dc=org",
			// Not a DN at all.
			"not a dn",
		},
			// ⛔ Only forgeries of alice, and alice herself NOT listed: in
			// staff the real alice hides a spoof that maps to her, so a test
			// of staff alone passes against a mapping that reads uid= out of
			// any DN. Here a correct mapping finds nobody.
			"forged": {
				"uid=alice,ou=elsewhere,dc=example,dc=org",
				"cn=alice,ou=people,dc=example,dc=org",
				"uid=alice,ou=people,dc=example,dc=net",
			}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func groupsSource(t *testing.T, d *ldaptest.Server, cfg ldapdir.Config) *ldapdir.Source {
	t.Helper()
	cfg.URL, cfg.BaseDN, cfg.GroupBaseDN = d.URL, d.PeopleDN, d.GroupsDN
	cfg.BindDN, cfg.BindPassword = d.ReaderDN, d.ReaderPassword
	src, err := ldapdir.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return src
}

// By default a groupOfNames is a group, and its member DNs map to the people
// this source imported -- by their DN, and only by their DN.
func TestAGroupOfNamesByDefault(t *testing.T) {
	d := groupsDirectory(t)
	src := groupsSource(t, d, ldapdir.Config{})

	members, err := src.Members("staff")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(members)
	if !slices.Equal(members, []string{"alice", "bob"}) {
		t.Errorf("staff = %v, want [alice bob]: only the DNs the people search returned map to anybody", members)
	}
	// The spoof, said on its own: uid=alice under ou=elsewhere is not alice.
	if slices.Contains(members, "mallory") {
		t.Error("the entry under ou=elsewhere, never imported, became a member")
	}

	// posixGroups are still read, from memberUid.
	team, err := src.Members("team")
	if err != nil || !slices.Equal(team, []string{"carol"}) {
		t.Errorf("team = %v, %v", team, err)
	}
	// The forgeries on their own: no DN in it is one the people search
	// returned, so the group exists and grants nobody.
	forged, err := src.Members("forged")
	if err != nil || len(forged) != 0 {
		t.Errorf("forged = %v, %v; want nobody: uid=alice under another branch, or alice under another naming attribute, is not alice", forged, err)
	}
	names, err := src.GroupNames()
	if err != nil || !slices.Equal(names, []string{"forged", "staff", "team"}) {
		t.Errorf("GroupNames = %v, %v", names, err)
	}
	if ldapdir.DefaultGroupFilter != "(|(objectClass=posixGroup)(objectClass=groupOfNames))" {
		t.Errorf("DefaultGroupFilter is %q", ldapdir.DefaultGroupFilter)
	}
}

// ⛔ The widening adds groups, never people: the identities are the same
// whatever the group filter, and no group yields a name that is not one of
// them (memberUid aside, which names whoever it names, as before).
func TestTheGroupFilterAddsNoIdentity(t *testing.T) {
	d := groupsDirectory(t)
	names := func(src *ldapdir.Source) []string {
		ids, err := src.Identities()
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, id := range ids {
			out = append(out, id.Name())
		}
		slices.Sort(out)
		return out
	}
	wide := groupsSource(t, d, ldapdir.Config{})
	narrow := groupsSource(t, d, ldapdir.Config{GroupFilter: "(objectClass=posixGroup)"})
	if a, b := names(wide), names(narrow); !slices.Equal(a, b) {
		t.Errorf("identities with the default group filter %v, with posixGroup alone %v", a, b)
	}
	imported := names(wide)
	if !slices.Equal(imported, []string{"alice", "bob", "carol"}) {
		t.Errorf("imported %v, want [alice bob carol]", imported)
	}
	members, err := wide.Members("staff")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if !slices.Contains(imported, m) {
			t.Errorf("staff names %q, who is not among the people imported", m)
		}
	}
	// And under the old filter a groupOfNames is not a group at all.
	if _, err := narrow.Members("staff"); !errors.Is(err, directory.ErrNoSuchGroup) {
		t.Errorf("with (objectClass=posixGroup), staff: %v, want ErrNoSuchGroup", err)
	}
}

// An explicit MemberAttribute is the one attribute read, and a DN in it maps
// the same way: to an imported person, or to nobody.
func TestAnExplicitMemberAttribute(t *testing.T) {
	d := groupsDirectory(t)

	member := groupsSource(t, d, ldapdir.Config{MemberAttribute: "member"})
	got, err := member.Members("staff")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"alice", "bob"}) {
		t.Errorf("with MemberAttribute member, staff = %v, want [alice bob]", got)
	}
	// team has no member attribute: it exists and has nobody, since memberUid
	// is not read when member was asked for.
	if team, err := member.Members("team"); err != nil || len(team) != 0 {
		t.Errorf("with MemberAttribute member, team = %v, %v; want nobody", team, err)
	}

	memberUid := groupsSource(t, d, ldapdir.Config{MemberAttribute: "memberUid"})
	if team, err := memberUid.Members("team"); err != nil || !slices.Equal(team, []string{"carol"}) {
		t.Errorf("with MemberAttribute memberUid, team = %v, %v", team, err)
	}
	if staff, err := memberUid.Members("staff"); err != nil || len(staff) != 0 {
		t.Errorf("with MemberAttribute memberUid, staff = %v, %v; want nobody", staff, err)
	}
}

// A memberUid holding a DN under an explicit MemberAttribute -- somebody
// else's layout -- is mapped like member: the spoof maps to nobody there too.
func TestADNInAConfiguredMemberAttribute(t *testing.T) {
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{"alice": {Password: "a"}},
		Groups: map[string][]string{"staff": {
			"uid=alice,ou=people,dc=example,dc=org",
			"uid=alice,ou=elsewhere,dc=example,dc=org",
			"carol", // a name, in the same group
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	src := groupsSource(t, d, ldapdir.Config{MemberAttribute: "memberUid"})
	got, err := src.Members("staff")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"alice", "carol"}) {
		t.Errorf("staff = %v, want [alice carol]", got)
	}
}

// The same forgery in a configured memberUid, with the real alice absent:
// nothing else in the group can hide it.
func TestAForgedDNInAConfiguredMemberAttributeMapsToNobody(t *testing.T) {
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{"alice": {Password: "a"}},
		Groups: map[string][]string{"staff": {"uid=alice,ou=elsewhere,dc=example,dc=org"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	src := groupsSource(t, d, ldapdir.Config{MemberAttribute: "memberUid"})
	if got, err := src.Members("staff"); err != nil || len(got) != 0 {
		t.Errorf("staff = %v, %v; want nobody", got, err)
	}
}
