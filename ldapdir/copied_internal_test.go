// SPDX-License-Identifier: BSD-3-Clause

package ldapdir

import (
	"slices"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// What an entry answers, read by RFC 4512 §2.5's equivalence: the same type
// and the same set of options, case-insensitively. Tested on an entry built
// here because a server filters what it returns, and a filtering server would
// hide a reader that matched too much.
func TestCopiedMatchesDescriptionsExactly(t *testing.T) {
	e := &ldap.Entry{Attributes: []*ldap.EntryAttribute{
		{Name: "description", Values: []string{"a person"}},
		{Name: "Description;Lang-FR;x-a", Values: []string{"une personne"}},
		{Name: "description;lang-fr", Values: []string{"pas celle-ci"}},
		{Name: "MAIL", Values: []string{"a@x.example", ""}},
		{Name: "mail", Values: []string{"b@x.example"}},
	}}
	a, err := copied(e, []string{"description;x-a;lang-fr", "mail", "gecos"})
	if err != nil {
		t.Fatal(err)
	}
	if v := a.Get("description;lang-fr;x-a"); !slices.Equal(v, []string{"une personne"}) {
		t.Errorf("tagged = %v", v)
	}
	if a.Get("description") != nil {
		t.Error("the untagged description was copied under the tagged one's name")
	}
	if v := a.Get("mail"); !slices.Equal(v, []string{"a@x.example", "b@x.example"}) {
		t.Errorf("mail = %v: both spellings, without the empty value", v)
	}
	if a.Len() != 2 {
		t.Errorf("%v", a.Names())
	}
	if sameDescription("mail", "mail;x") || sameDescription("mail;x", "cn;x") {
		t.Error("different descriptions compared equal")
	}
}
