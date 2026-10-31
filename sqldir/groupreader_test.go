package sqldir_test

import (
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/sqldir"
)

// The bulk read must give EXACTLY the answers the per-group methods give.
// differences asks the set and its frozen copy the same questions about every
// group name there is, and a name there is not, and reports each answer that
// differs: the value, or whether it is an error and which kind.

func sameErr(a, b error) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || errors.Is(a, directory.ErrNoSuchGroup) == errors.Is(b, directory.ErrNoSuchGroup)
}

func differences(t *testing.T, s *directory.Set, names []string) []string {
	t.Helper()
	f, err := s.Frozen()
	if err != nil {
		t.Fatalf("Frozen: %v", err)
	}
	var out []string
	gn1, e1 := s.GroupNames()
	gn2, e2 := f.GroupNames()
	if !sameErr(e1, e2) || !reflect.DeepEqual(gn1, gn2) {
		out = append(out, fmt.Sprintf("GroupNames: %v %v / %v %v", gn1, e1, gn2, e2))
	}
	for _, g := range append(append([]string(nil), names...), "no-such-group") {
		m1, e1 := s.Members(g)
		m2, e2 := f.Members(g)
		if !sameErr(e1, e2) || !reflect.DeepEqual(m1, m2) {
			out = append(out, fmt.Sprintf("Members(%s): %v %v / %v %v", g, m1, e1, m2, e2))
		}
		a1, e1 := s.GroupAttributes(g)
		a2, e2 := f.GroupAttributes(g)
		if !sameErr(e1, e2) || !reflect.DeepEqual(a1, a2) {
			out = append(out, fmt.Sprintf("GroupAttributes(%s): %v %v / %v %v", g, a1, e1, a2, e2))
		}
		c1, e1 := s.GroupObjectClasses(g)
		c2, e2 := f.GroupObjectClasses(g)
		if !sameErr(e1, e2) || !reflect.DeepEqual(c1, c2) {
			out = append(out, fmt.Sprintf("GroupObjectClasses(%s): %v %v / %v %v", g, c1, e1, c2, e2))
		}
	}
	return out
}

// randomDB is a database of random groups: some with members only, some with
// attributes only, some with both, duplicate rows, NULL cells.
func randomDB(t testing.TB, seed int64) (db *sql.DB, names []string) {
	t.Helper()
	rng := rand.New(rand.NewSource(seed))
	db, err := sql.Open("sqlite", "file:"+t.TempDir()+"/g.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`create table people (name text)`,
		`create table memberships (g text, member text)`,
		`create table gattrs (g text, gid text, descr text)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	n := rng.Intn(12)
	for i := 0; i < n; i++ {
		g := fmt.Sprintf("g%02d", i)
		names = append(names, g)
		if rng.Intn(4) > 0 {
			for j := rng.Intn(6); j >= 0; j-- {
				db.Exec(`insert into memberships values (?, ?)`, g, fmt.Sprintf("p%d", rng.Intn(5)))
			}
		}
		if rng.Intn(3) > 0 {
			var gid, d any
			if rng.Intn(3) > 0 {
				gid = fmt.Sprint(1000 + i)
			}
			if rng.Intn(2) > 0 {
				d = "group " + g
			}
			db.Exec(`insert into gattrs values (?, ?, ?)`, g, gid, d)
		}
	}
	return db, names
}

func queriesFor(seed int64) sqldir.Queries {
	q := sqldir.Queries{People: `select name from people`}
	if seed%4 != 0 {
		q.Groups = `select g, member from memberships`
	}
	if seed%4 != 1 {
		q.GroupAttributes = `select g, gid as gidNumber, descr as description from gattrs`
	}
	return q
}

func TestBulkReadEqualsPerGroupReadOnRandomDatabases(t *testing.T) {
	for seed := int64(0); seed < 80; seed++ {
		db, names := randomDB(t, seed)
		var opts []sqldir.Option
		if seed%3 == 0 {
			opts = append(opts, sqldir.WithGroupObjectClasses("posixGroup"))
		}
		src, err := sqldir.New(db, queriesFor(seed), opts...)
		if err != nil {
			t.Fatal(err)
		}
		if d := differences(t, directory.NewSet(src), names); len(d) > 0 {
			t.Fatalf("seed %d: %v", seed, d)
		}
		// And beside another source that has some of the same groups.
		other := &directory.Static{Name: "local", Groups: map[string][]string{"g00": {"zed"}, "local-only": {"zed"}}}
		if d := differences(t, directory.NewSet(other, src), append(names, "local-only")); len(d) > 0 {
			t.Fatalf("seed %d with a second source: %v", seed, d)
		}
	}
}

func TestBulkReadEqualsPerGroupReadOnTheFixture(t *testing.T) {
	src, err := sqldir.New(withDB(t), sqldir.Queries{
		People: `select name from people`,
		Groups: `select group_name, member from memberships`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if d := differences(t, directory.NewSet(src), []string{"staff", "admins"}); len(d) > 0 {
		t.Fatal(d)
	}
}

// A source that cannot be read is an error when the set is frozen.
func TestFrozenReportsASourceThatCannotBeRead(t *testing.T) {
	db := withDB(t)
	src, err := sqldir.New(db, sqldir.Queries{People: `select name from people`, Groups: `select a, b from no_such_table`}, sqldir.Named("the db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := directory.NewSet(src).Frozen(); err == nil || err.Error()[:6] != "the db" {
		t.Fatalf("got %v", err)
	}
	src, _ = sqldir.New(db, sqldir.Queries{People: `select name from people`, Groups: `select group_name, member from memberships`, GroupAttributes: `select x from no_such_table`})
	if _, err := directory.NewSet(src).Frozen(); err == nil {
		t.Fatal("a failing group-attributes query was not reported")
	}
}

// ⛔ The planted fault: a bulk read that drops the last member of every group.
// The comparison must see it, or it proves nothing.
type droppingReader struct{ *sqldir.Source }

func (d droppingReader) ReadGroups() (map[string]directory.GroupData, error) {
	m, err := d.Source.ReadGroups()
	for g, data := range m {
		if len(data.Members) > 0 {
			data.Members = data.Members[:len(data.Members)-1]
			m[g] = data
		}
	}
	return m, err
}

func TestTheComparisonSeesAPlantedFault(t *testing.T) {
	src, err := sqldir.New(withDB(t), sqldir.Queries{People: `select name from people`, Groups: `select group_name, member from memberships`})
	if err != nil {
		t.Fatal(err)
	}
	if d := differences(t, directory.NewSet(droppingReader{src}), []string{"staff", "admins"}); len(d) == 0 {
		t.Fatal("the comparison did not see a dropped member")
	}
}

// A database given no groups query and no group-attributes query has no groups.
func TestBulkReadOfADatabaseWithoutGroups(t *testing.T) {
	src, err := sqldir.New(withDB(t), sqldir.Queries{People: `select name from people`})
	if err != nil {
		t.Fatal(err)
	}
	if d := differences(t, directory.NewSet(src), []string{"staff"}); len(d) > 0 {
		t.Fatal(d)
	}
	if g, err := src.ReadGroups(); err != nil || len(g) != 0 {
		t.Fatalf("%v %v", g, err)
	}
}

// A source that cannot read in bulk is frozen unchanged.
func TestFrozenLeavesOtherSourcesAlone(t *testing.T) {
	static := &directory.Static{Name: "s", Groups: map[string][]string{"a": {"x"}}}
	if d := differences(t, directory.NewSet(static), []string{"a"}); len(d) > 0 {
		t.Fatal(d)
	}
}
