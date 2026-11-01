package sqldir_test

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/sqldir"
)

// BenchmarkRefresh is what a server does to refresh: read the people, then
// every group once through Frozen, then answer for each group from memory.
func BenchmarkRefresh(b *testing.B) {
	const people, groups, size = 10000, 2000, 50
	db, err := sql.Open("sqlite", "file:"+b.TempDir()+"/big.db")
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { db.Close() })
	tx, err := db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	for _, s := range []string{
		`create table people (name text, password text)`,
		`create table pattrs (name text, mail text, description text)`,
		`create table memberships (g text, member text)`,
		`create table gattrs (g text, gid text, descr text)`,
	} {
		if _, err := tx.Exec(s); err != nil {
			b.Fatal(err)
		}
	}
	for i := 0; i < people; i++ {
		n := fmt.Sprintf("user%05d", i)
		tx.Exec(`insert into people values (?, ?)`, n, "pw")
		tx.Exec(`insert into pattrs values (?, ?, ?)`, n, n+"@example.org", "person "+n)
	}
	for g := 0; g < groups; g++ {
		gn := fmt.Sprintf("group%04d", g)
		for j := 0; j < size; j++ {
			tx.Exec(`insert into memberships values (?, ?)`, gn, fmt.Sprintf("user%05d", (g*size+j)%people))
		}
		tx.Exec(`insert into gattrs values (?, ?, ?)`, gn, fmt.Sprint(2000+g), "group "+gn)
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
	src, err := sqldir.New(db, sqldir.Queries{
		People:           `select name, password from people`,
		PeopleAttributes: `select name, mail, description from pattrs`,
		Groups:           `select g, member from memberships`,
		GroupAttributes:  `select g, gid as gidNumber, descr as description from gattrs`,
	})
	if err != nil {
		b.Fatal(err)
	}
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
