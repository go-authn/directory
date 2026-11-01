package ldapdir

import (
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// whoIsLinear is the lookup dnKey replaced, kept as the oracle: the first
// person whose DN is EqualFold to dn.
type linearPerson struct {
	dn   *ldap.DN
	name string
}

func whoIsLinear(ps []linearPerson, dn *ldap.DN) (string, bool) {
	if len(dn.RDNs) == 0 {
		return "", false
	}
	for _, p := range ps {
		if p.dn.EqualFold(dn) {
			return p.name, true
		}
	}
	return "", false
}

// Pieces chosen to hurt a lazy fold: ASCII case, the Kelvin sign (folds with
// k), the long s (folds with s), a sigma, an invalid byte, digits, a
// separator-looking value.
var types = []string{"uid", "UID", "Uid", "cn", "CN", "ou", "dc", "o", "Ky", "ky", "KY"}
var values = []string{"alice", "ALICE", "Alice", "bob", "a,b", "a=b", "x|1:y", "1:a", "",
	"k", "K", "K", "s", "S", "ſ", "σ", "ς", "Σ", "\xff", "\xfe", "\x00", "\x01", "\x01\x02", "\x00\x00", "ǆ", "ǅ", "Ǆ"}

func randomDN(r *rand.Rand) *ldap.DN {
	dn := &ldap.DN{}
	for i := r.IntN(4); i >= 0; i-- {
		rdn := &ldap.RelativeDN{}
		for j := r.IntN(3); j >= 0; j-- {
			rdn.Attributes = append(rdn.Attributes, &ldap.AttributeTypeAndValue{
				Type: types[r.IntN(len(types))], Value: values[r.IntN(len(values))]})
		}
		dn.RDNs = append(dn.RDNs, rdn)
	}
	return dn
}

// shuffled is the same DN with each RDN's attributes in another order, which
// distinguishedNameMatch ignores.
func shuffled(r *rand.Rand, dn *ldap.DN) *ldap.DN {
	out := &ldap.DN{}
	for _, rdn := range dn.RDNs {
		n := &ldap.RelativeDN{Attributes: append([]*ldap.AttributeTypeAndValue(nil), rdn.Attributes...)}
		r.Shuffle(len(n.Attributes), func(i, j int) { n.Attributes[i], n.Attributes[j] = n.Attributes[j], n.Attributes[i] })
		out.RDNs = append(out.RDNs, n)
	}
	return out
}

// agrees checks key(a)==key(b) against a.EqualFold(b) on random pairs, and
// returns the first disagreement.
func agrees(key func(*ldap.DN) string, seed uint64) string {
	r := rand.New(rand.NewPCG(seed, 1))
	for i := 0; i < 200000; i++ {
		a := randomDN(r)
		var b *ldap.DN
		if r.IntN(2) == 0 {
			b = shuffled(r, a)
		} else {
			b = randomDN(r)
		}
		if (key(a) == key(b)) != a.EqualFold(b) {
			return fmt.Sprintf("key equal=%v EqualFold=%v for %s and %s", key(a) == key(b), a.EqualFold(b), show(a), show(b))
		}
	}
	return ""
}

func show(d *ldap.DN) string {
	var parts []string
	for _, rdn := range d.RDNs {
		var as []string
		for _, a := range rdn.Attributes {
			as = append(as, fmt.Sprintf("%q=%q", a.Type, a.Value))
		}
		parts = append(parts, strings.Join(as, "+"))
	}
	return strings.Join(parts, ",")
}

// dnKey and EqualFold are the same relation.
func TestDNKeyIsEqualFold(t *testing.T) {
	if msg := agrees(dnKey, 1); msg != "" {
		t.Fatal(msg)
	}
}

// The planted fault: a key that folds with strings.ToLower, which does not
// fold the long s. The measurement above must be able to see that, or its
// silence means nothing.
func TestDifferentialSeesAFault(t *testing.T) {
	lower := func(dn *ldap.DN) string { return strings.ToLower(show(dn)) }
	if msg := agrees(lower, 1); msg == "" {
		t.Fatal("the differential did not notice a key that is not EqualFold")
	}
}

// The lookup answers as the linear search did, on random directories: same
// person (the first, among duplicates), same absence.
func TestWhoIsMatchesLinear(t *testing.T) {
	r := rand.New(rand.NewPCG(7, 2))
	for round := 0; round < 300; round++ {
		var lin []linearPerson
		idx := peopleIndex{}
		for i := r.IntN(30); i > 0; i-- {
			dn := randomDN(r)
			name := fmt.Sprintf("p%d", i)
			lin = append(lin, linearPerson{dn, name})
			if k := dnKey(dn); idx[k] == "" {
				idx[k] = name
			}
		}
		for q := 0; q < 100; q++ {
			var dn *ldap.DN
			if len(lin) > 0 && r.IntN(2) == 0 {
				dn = shuffled(r, lin[r.IntN(len(lin))].dn)
			} else {
				dn = randomDN(r)
			}
			wn, wok := whoIsLinear(lin, dn)
			gn, gok := whoIs(idx, dn)
			if wn != gn || wok != gok {
				t.Fatalf("linear says (%q,%v), index says (%q,%v) for %s", wn, wok, gn, gok, show(dn))
			}
		}
	}
	if _, ok := whoIs(peopleIndex{"": "x"}, &ldap.DN{}); ok {
		t.Error("an empty DN named somebody")
	}
}

func BenchmarkMapMembers(b *testing.B) {
	const n = 10000
	idx := make(peopleIndex, n)
	dns := make([]*ldap.DN, n)
	for i := range dns {
		dns[i], _ = ldap.ParseDN(fmt.Sprintf("uid=user%d,ou=people,dc=example,dc=org", i))
		idx[dnKey(dns[i])] = fmt.Sprint("user", i)
	}
	b.Run("index", func(b *testing.B) {
		for range b.N {
			for _, dn := range dns[:1000] {
				whoIs(idx, dn)
			}
		}
	})
	lin := make([]linearPerson, n)
	for i := range lin {
		lin[i] = linearPerson{dns[i], fmt.Sprint("user", i)}
	}
	b.Run("linear", func(b *testing.B) {
		for range b.N {
			for _, dn := range dns[:1000] {
				whoIsLinear(lin, dn)
			}
		}
	})
}
