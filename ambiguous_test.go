package directory

import (
	"errors"
	"testing"
)

// One source holding a name twice is ambiguous; two sources holding it is the
// override the Set documents (the first owns it).
func TestSetRefusesAnAmbiguousNameWithinASource(t *testing.T) {
	twice := &Static{Name: "ldap", People: []*Identity{NewIdentity("alice"), NewIdentity("alice")}}
	if _, err := NewSet(twice).Identities(); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("err = %v, want ErrAmbiguous", err)
	}
	local := &Static{Name: "local", People: []*Identity{NewIdentity("alice")}}
	other := &Static{Name: "ldap", People: []*Identity{NewIdentity("alice"), NewIdentity("bob")}}
	ids, err := NewSet(local, other).Identities()
	if err != nil || len(ids) != 2 {
		t.Fatalf("%d identities, %v; want 2, nil (the first source owns alice)", len(ids), err)
	}
}
