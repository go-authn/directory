package ldapdir

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// Whatever two strings parse as DNs, their keys are equal exactly when the
// DNs are EqualFold.
func FuzzDNKey(f *testing.F) {
	f.Add("uid=alice,ou=people,dc=example,dc=org", "UID=ALICE,OU=People,DC=Example,DC=Org")
	f.Add("cn=a+sn=b,dc=x", "sn=b+cn=a,dc=x")
	f.Add("cn=\\K,dc=x", "cn=k,dc=x")
	f.Add("cn=a,dc=x", "cn=a,dc=x,dc=y")
	f.Add("", "dc=x")
	f.Fuzz(func(t *testing.T, a, b string) {
		da, err := ldap.ParseDN(a)
		if err != nil {
			return
		}
		db, err := ldap.ParseDN(b)
		if err != nil {
			return
		}
		if (dnKey(da) == dnKey(db)) != da.EqualFold(db) {
			t.Fatalf("key equal=%v EqualFold=%v for %q and %q", dnKey(da) == dnKey(db), da.EqualFold(db), a, b)
		}
	})
}
