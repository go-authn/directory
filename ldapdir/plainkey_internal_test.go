package ldapdir

import (
	"math/rand/v2"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// viaParse is the key the way it was made before the plain path: ParseDN,
// then appendDNKey.
func viaParse(s string) (string, bool) {
	dn, err := ldap.ParseDN(s)
	if err != nil || len(dn.RDNs) == 0 {
		return "", false
	}
	return dnKey(dn), true
}

func checkKeyOf(t testing.TB, s string) {
	t.Helper()
	want, wok := viaParse(s)
	got, gok := appendKeyOf(nil, s)
	if wok != gok || (wok && want != string(got)) {
		t.Fatalf("%q: appendKeyOf = %q, %v; ParseDN path = %q, %v", s, got, gok, want, wok)
	}
}

func TestAppendKeyOfIsTheParsedKey(t *testing.T) {
	for _, s := range []string{
		"", " ", "uid=alice,ou=people,dc=example,dc=org", "UID=Alice,OU=People,DC=Example,DC=ORG",
		"uid=a.b-c_d@e,dc=x", "cn=a b,dc=x", `cn=a\,b,dc=x`, "cn=a+sn=b,dc=x", "cn=,dc=x", "=a", "a=",
		"a=b,", ",a=b", "a=b,,c=d", "1.2.3=#0403414243", "cn=\"x\",dc=y", "cn=é,dc=x", "cn=a=b", "cn",
		"cn=a;dc=b", "k=K", "cn=a\x00b", "cn=a,dc=b ", " cn=a",
	} {
		checkKeyOf(t, s)
	}
	// The plain path must actually be taken for the common shape.
	if _, ok := appendPlainKey(nil, "uid=user00001,ou=people,dc=example,dc=org"); !ok {
		t.Fatal("a plain DN did not take the plain path")
	}
	r := rand.New(rand.NewPCG(1, 2))
	const alphabet = "abcAZ09-_.@=,+;\\ #\"é\x00K"
	for range 200000 {
		b := make([]byte, r.IntN(24))
		for i := range b {
			b[i] = alphabet[r.IntN(len(alphabet))]
		}
		checkKeyOf(t, string(b))
	}
}

func FuzzAppendKeyOf(f *testing.F) {
	for _, s := range []string{
		"uid=alice,ou=people,dc=example,dc=org", "cn=a+sn=b,dc=x", `cn=a\,b`, "1.2.3=#04", "a=b,", "UID=Ä", "k=K,s=ſ",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { checkKeyOf(t, s) })
}

func BenchmarkKeyOfPlainDN(b *testing.B) {
	const s = "uid=user00001,ou=people,dc=example,dc=org"
	var buf [160]byte
	b.ReportAllocs()
	for range b.N {
		appendKeyOf(buf[:0], s)
	}
}

func BenchmarkKeyOfViaParseDN(b *testing.B) {
	const s = "uid=user00001,ou=people,dc=example,dc=org"
	b.ReportAllocs()
	for range b.N {
		viaParse(s)
	}
}
