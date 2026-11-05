package ldapdir_test

import (
	"errors"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/directory/ldaptest"
)

// Security audit 2026-11-05. Two entries that share a uid are two people under
// one name: whichever the server listed first used to win, silently (the other
// was dropped by Set.Identities), and which that was depended on the order the
// directory answered in. A name that is not one person is an error.
func ambiguousDirectory(t *testing.T, a, b string) *ldapdir.Source {
	t.Helper()
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{
			"alice-staff":   {UID: a, Password: "staff-pw"},
			"alice-student": {UID: b, Password: "student-pw"},
			"bob":           {Password: "swordfish"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	src, err := ldapdir.New(ldapdir.Config{URL: d.URL, BaseDN: d.PeopleDN, BindDN: d.ReaderDN, BindPassword: d.ReaderPassword})
	if err != nil {
		t.Fatal(err)
	}
	return src
}

func TestTwoEntriesSharingAUIDAreRefused(t *testing.T) {
	for _, c := range []struct{ name, a, b string }{
		{"same", "alice", "alice"},
		{"case-insensitive (uid is caseIgnoreMatch, RFC 4519)", "alice", "Alice"},
	} {
		t.Run(c.name, func(t *testing.T) {
			src := ambiguousDirectory(t, c.a, c.b)
			if ids, err := src.Identities(); !errors.Is(err, directory.ErrAmbiguous) {
				t.Errorf("Source.Identities picked among %d people, err = %v; want ErrAmbiguous", len(ids), err)
			}
			if ids, err := directory.NewSet(src).Identities(); !errors.Is(err, directory.ErrAmbiguous) {
				t.Errorf("Set.Identities picked among %d people, err = %v; want ErrAmbiguous", len(ids), err)
			}
		})
	}
}

func TestDistinctUIDsAreNotAmbiguous(t *testing.T) {
	ids, err := ambiguousDirectory(t, "alice", "alicia").Identities()
	if err != nil || len(ids) != 3 {
		t.Fatalf("%d people, %v; want 3, nil", len(ids), err)
	}
}
