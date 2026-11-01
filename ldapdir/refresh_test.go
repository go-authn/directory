package ldapdir_test

import (
	"fmt"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/directory/ldaptest"
)

// bigDirectory is the shape of a large site: people, and groups of
// groupSize members given as DNs (groupOfNames), every person in some group.
func bigDirectory(tb testing.TB, people, groups, groupSize int) *ldaptest.Server {
	tb.Helper()
	d := &ldaptest.Directory{
		People:        map[string]ldaptest.Person{},
		GroupsOfNames: map[string][]string{},
	}
	const base = "dc=example,dc=org"
	for i := 0; i < people; i++ {
		d.People[fmt.Sprintf("user%05d", i)] = ldaptest.Person{Password: "pw"}
	}
	for g := 0; g < groups; g++ {
		var m []string
		for j := 0; j < groupSize; j++ {
			m = append(m, fmt.Sprintf("uid=user%05d,ou=people,%s", (g*groupSize+j)%people, base))
		}
		d.GroupsOfNames[fmt.Sprintf("group%04d", g)] = m
	}
	srv, err := ldaptest.NewServer(d)
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { srv.Close() })
	return srv
}

func refreshSource(tb testing.TB, srv *ldaptest.Server) *ldapdir.Source {
	tb.Helper()
	src, err := ldapdir.New(ldapdir.Config{
		URL: srv.URL, BaseDN: srv.PeopleDN, GroupBaseDN: srv.GroupsDN,
		BindDN: srv.ReaderDN, BindPassword: srv.ReaderPassword,
		GroupFilter: "(objectClass=groupOfNames)", GroupAttribute: "cn",
	})
	if err != nil {
		tb.Fatal(err)
	}
	return src
}

// BenchmarkRefresh is what a server does to refresh: read the people, then
// every group once through Frozen, then answer for each group from memory.
// Sized by -args or the defaults below.
func BenchmarkRefresh(b *testing.B) {
	const people, groups, size = 10000, 2000, 50
	srv := bigDirectory(b, people, groups, size)
	src := refreshSource(b, srv)
	set := directory.NewSet(src)
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ids, err := set.Identities()
		if err != nil || len(ids) != people {
			b.Fatal(len(ids), err)
		}
		f, err := set.Frozen()
		if err != nil {
			b.Fatal(err)
		}
		names, _ := f.GroupNames()
		if len(names) != groups {
			b.Fatal(len(names))
		}
		for _, n := range names {
			m, err := f.Members(n)
			if err != nil || len(m) != size {
				b.Fatal(n, len(m), err)
			}
			f.GroupAttributes(n)
			f.GroupObjectClasses(n)
		}
	}
}
