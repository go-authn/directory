// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

func mustAttrs(t *testing.T, attrs ...Attribute) Attributes {
	t.Helper()
	a, err := NewAttributes(attrs...)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// The shape a server publishing posixAccount needs, end to end through an
// identity: in order, case-insensitive, multi-valued, copied out.
func TestAnIdentityCarriesItsAttributes(t *testing.T) {
	a := mustAttrs(t,
		Attribute{"uidNumber", []string{"1000"}},
		Attribute{"homeDirectory", []string{"/home/alice"}},
		Attribute{"mail", []string{"alice@example.org", "a.liddell@example.org"}},
	)
	id := NewIdentity("alice", WithPassword("s3cret"), WithAttributes(a))

	got := id.Attributes()
	if n := strings.Join(got.Names(), ","); n != "uidNumber,homeDirectory,mail" {
		t.Errorf("names = %s, want the order they were given", n)
	}
	if v := got.Get("UIDNUMBER"); !slices.Equal(v, []string{"1000"}) {
		t.Errorf("Get is case-insensitive: %v", v)
	}
	if v := got.Get("mail"); len(v) != 2 {
		t.Errorf("mail = %v, want both values", v)
	}
	if got.Get("loginShell") != nil {
		t.Error("an attribute nobody gave was found")
	}
	if got.Len() != 3 {
		t.Errorf("Len = %d", got.Len())
	}

	// A copy: changing what Get returned changes nothing.
	got.Get("mail")[0] = "mallory@example.org"
	for _, v := range id.Attributes().All() {
		if slices.Contains(v, "mallory@example.org") {
			t.Fatal("a caller changed what the directory said")
		}
	}

	// Credentials and attributes do not leak into each other.
	if !id.Can(Password) || id.Attributes().Get("userPassword") != nil {
		t.Error("the password is a credential, not an attribute")
	}

	// A second WithAttributes adds to the first.
	more := mustAttrs(t, Attribute{"MAIL", []string{"alice@example.org", "third@example.org"}}, Attribute{"loginShell", []string{"/bin/sh"}})
	id = NewIdentity("alice", WithAttributes(a), WithAttributes(more))
	if v := id.Attributes().Get("mail"); len(v) != 3 {
		t.Errorf("mail = %v: an exact repeat once, the new one added", v)
	}
	if n := strings.Join(id.Attributes().Names(), ","); n != "uidNumber,homeDirectory,mail,loginShell" {
		t.Errorf("names = %s: the first spelling wins, and new ones follow", n)
	}

	// Nobody said anything: nothing, and no nil to trip on.
	if NewIdentity("bob").Attributes().Len() != 0 {
		t.Error("an identity with no attributes has some")
	}
}

// RFC 4512 §2.5: the type and the options are case-insensitive, and the order
// of the options is irrelevant. Different options are a different
// description.
func TestDescriptionsAreComparedTheWayLDAPComparesThem(t *testing.T) {
	a := mustAttrs(t,
		Attribute{"description;lang-fr;x-a", []string{"bonjour"}},
		Attribute{"DESCRIPTION;X-A;LANG-FR", []string{"salut"}},
		Attribute{"description", []string{"hello"}},
		Attribute{"userCertificate;binary", []string{"\x30\x82"}},
	)
	if a.Len() != 3 {
		t.Fatalf("Len = %d (%v), want 3", a.Len(), a.Names())
	}
	if v := a.Get("Description;x-A;lang-FR"); !slices.Equal(v, []string{"bonjour", "salut"}) {
		t.Errorf("got %v", v)
	}
	if v := a.Get("description"); !slices.Equal(v, []string{"hello"}) {
		t.Errorf("got %v: options make a different description", v)
	}
	if a.Get("2.5.4.13") != nil || a.Get("not valid!") != nil {
		t.Error("a name that cannot be an attribute here was found")
	}
	// All stops when asked to.
	n := 0
	for range a.All() {
		n++
		break
	}
	if n != 1 {
		t.Error("All did not stop")
	}
}

// Every attribute a server publishing RFC 2307 and RFC 2798 entries needs, and
// the rest of the standard user schema: none may be refused by accident. The
// list was read off the RFCs; it is the test that the secret-fragment rule
// has not eaten something ordinary (it had: "secretary").
func TestTheStandardSchemaIsAccepted(t *testing.T) {
	for _, n := range []string{
		// RFC 2307
		"uidNumber", "gidNumber", "gecos", "homeDirectory", "loginShell",
		"shadowLastChange", "shadowMin", "shadowMax", "shadowWarning",
		"shadowInactive", "shadowExpire", "shadowFlag", "description",
		// RFC 2798
		"carLicense", "departmentNumber", "displayName", "employeeNumber",
		"employeeType", "jpegPhoto", "preferredLanguage", "userSMIMECertificate",
		"audio", "businessCategory", "givenName", "homePhone", "homePostalAddress",
		"initials", "labeledURI", "mail", "manager", "mobile", "o", "pager",
		"photo", "roomNumber", "secretary", "userCertificate", "x500UniqueIdentifier",
		"preferredDeliveryMethod",
		// RFC 4519
		"sn", "surname", "telephoneNumber", "title", "ou", "l", "st", "street",
		"postalAddress", "postalCode", "postOfficeBox", "physicalDeliveryOfficeName",
		"facsimileTelephoneNumber", "seeAlso", "owner", "serialNumber",
		"destinationIndicator", "internationalISDNNumber", "registeredAddress",
		"telexNumber", "x121Address", "generationQualifier", "dnQualifier",
		"houseIdentifier", "c", "dc", "name", "searchGuide", "enhancedSearchGuide",
		"teletexTerminalIdentifier", "businessCategory",
		// RFC 4524
		"info", "drink", "favouriteDrink", "personalTitle", "co", "friendlyCountryName",
		"organizationalStatus", "buildingName", "uniqueIdentifier", "userClass",
		"rfc822Mailbox", "associatedDomain", "host",
		// with options
		"displayName;lang-fr", "description;lang-de;lang-en", "userCertificate;binary",
	} {
		if err := CheckAttributeName(n); err != nil {
			t.Errorf("%s: %v", n, err)
		}
	}
}

// Each guard, one case at a time, and the reason it says.
func TestWhatIsRefusedAsAnAttribute(t *testing.T) {
	for _, tc := range []struct {
		name, want string
	}{
		// grammar, RFC 4512 §1.4 and §2.5
		{"", "needs a name"},
		{"2.5.4.35", "is an OID"},
		{"1mail", "is an OID"}, // a leading digit is the numeric form, or nothing
		{"-mail", "not an attribute description"},
		{"mail address", "not an attribute description"},
		{"e_mail", "not an attribute description"},
		{"courriél", "not an attribute description"},
		{"mail;", "has an option that is not"},
		{"mail;lang_fr", "has an option that is not"},
		{";lang-fr", "not an attribute description"},
		// 389-ds keeps the cleartext of a new password under this pseudo-name;
		// it is refused by the grammar before any list is consulted.
		{"unhashed#user#password", "not an attribute description"},

		// secrets, by name, whatever the case and the options
		{"userPassword", "holds a secret"},
		{"USERPASSWORD", "holds a secret"},
		{"userPassword;binary", "holds a secret"},
		{"authPassword", "holds a secret"},
		{"sambaNTPassword", "holds a secret"},
		{"sambaLMPassword", "holds a secret"},
		{"unicodePwd", "holds a secret"},
		{"krbPrincipalKey", "holds a secret"},
		{"userPKCS12", "holds a secret"},
		{"ipatokenOTPkey", "holds a secret"},
		{"krb5Key", "holds a secret"},
		{"msFVE-KeyPackage", "holds a secret"},
		{"oathTokenPIN", "holds a secret"},
		{"currentValue", "holds a secret"},

		// and by the fragments, for schemas no list has read
		{"acmeVpnPassword", `contains "password"`},
		{"otpSharedSecret", `contains "secret"`},
		{"localNtHash", `contains "hash"`},
		{"legacyPasswd", `contains "passwd"`},
		{"x-radiusCredential", `contains "credential"`},
		{"sitePrivateKey", `contains "privatekey"`},
		{"sambaPwdLastSet", `contains "pwd"`},

		// a credential with its own path
		{"sshPublicKey", "WithPublicKeys"},
		// what the server derives from the name
		{"uid", "derived by the server"},
		{"userid", "derived by the server"},
		{"cn", "derived by the server"},
		{"commonName;lang-fr", "derived by the server"},
		{"objectClass", "derived by the server"},
		// membership
		{"memberUid", "is membership"},
		{"member", "is membership"},
		{"uniqueMember", "is membership"},
		{"memberOf", "is membership"},
		// what the server maintains
		{"createTimestamp", "maintained by the server"},
		{"entryUUID", "maintained by the server"},
	} {
		err := CheckAttributeName(tc.name)
		if !errors.Is(err, ErrAttributeName) {
			t.Errorf("%q: %v, want ErrAttributeName", tc.name, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: %v, want it to say %q", tc.name, err, tc.want)
		}
		// And the same refusal through every way in.
		if _, err := NewAttributes(Attribute{tc.name, []string{"x"}}); !errors.Is(err, ErrAttributeName) {
			t.Errorf("NewAttributes accepted %q: %v", tc.name, err)
		}
	}
}

// Every listed name is refused, and the published copy cannot change that.
func TestTheReservedListIsEnforcedAndCannotBeEdited(t *testing.T) {
	list := ReservedAttributes()
	if len(list) < 60 {
		t.Fatalf("%d reserved names: the list lost entries", len(list))
	}
	for name := range list {
		if CheckAttributeName(name) == nil {
			t.Errorf("%s is listed and accepted", name)
		}
	}
	delete(list, "userpassword")
	if CheckAttributeName("userPassword") == nil {
		t.Error("deleting from the copy unlocked userPassword")
	}
}

func TestAnAttributeHasValues(t *testing.T) {
	for _, tc := range []struct {
		at   Attribute
		want string
	}{
		{Attribute{"mail", nil}, "has no values"},
		{Attribute{"mail", []string{}}, "has no values"},
		{Attribute{"mail", []string{"a@x.example", ""}}, "has an empty value"},
	} {
		_, err := NewAttributes(Attribute{"gecos", []string{"fine"}}, tc.at)
		if !errors.Is(err, ErrAttributeValue) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v, want %q", tc.at, err, tc.want)
		}
	}
	// Numbers are strings, and are not interpreted: "0100" stays "0100".
	a := mustAttrs(t, Attribute{"uidNumber", []string{"0100"}})
	if v := a.Get("uidnumber"); v[0] != "0100" {
		t.Errorf("uidNumber = %v", v)
	}
}

// A source that knows nothing new still compiles, still answers, and does not
// make a group vanish from GroupAttributes: Members is asked instead.
type membersOnly struct{ groups map[string][]string }

func (m membersOnly) Identities() ([]*Identity, error) { return nil, nil }
func (m membersOnly) Describe() string                 { return "an old source" }
func (m membersOnly) Members(g string) ([]string, error) {
	if ms, ok := m.groups[g]; ok {
		return ms, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrNoSuchGroup, g)
}

type brokenAttrs struct{ membersOnly }

func (brokenAttrs) GroupAttributes(string) (Attributes, error) {
	return Attributes{}, errors.New("the database is down")
}

func TestASetDescribesAGroupFromEverySource(t *testing.T) {
	file := &Static{
		Name:   "the configuration file",
		Groups: map[string][]string{"staff": {"alice"}, "local": {}},
		GroupAttrs: map[string]Attributes{
			"staff": mustAttrs(t, Attribute{"gidNumber", []string{"100"}}),
			// an entry for a group that is not in Groups describes nothing
			"ghost": mustAttrs(t, Attribute{"gidNumber", []string{"666"}}),
		},
	}
	dir := &Static{
		Name:   "the directory",
		Groups: map[string][]string{"staff": {"bob"}, "remote": {"carol"}},
		GroupAttrs: map[string]Attributes{
			"staff": mustAttrs(t,
				Attribute{"GIDNUMBER", []string{"200"}},
				Attribute{"description", []string{"the people who work here"}}),
			"remote": mustAttrs(t, Attribute{"gidNumber", []string{"300"}}),
		},
	}
	old := membersOnly{groups: map[string][]string{"legacy": {"dave"}}}
	set := NewSet(file, dir, old)

	// First source wins per attribute; names are united; values are not.
	staff, err := set.GroupAttributes("staff")
	if err != nil {
		t.Fatal(err)
	}
	if v := staff.Get("gidNumber"); !slices.Equal(v, []string{"100"}) {
		t.Errorf("gidNumber = %v, want the file's alone: the first source owns it", v)
	}
	if v := staff.Get("description"); len(v) != 1 {
		t.Errorf("description = %v, want the directory's: the file has none", v)
	}
	if n := strings.Join(staff.Names(), ","); n != "gidNumber,description" {
		t.Errorf("names = %s", n)
	}

	for group, want := range map[string]int{"remote": 1, "local": 0, "legacy": 0} {
		a, err := set.GroupAttributes(group)
		if err != nil || a.Len() != want {
			t.Errorf("%s: %v attributes (%v), want %d", group, a.Names(), err, want)
		}
	}
	for _, group := range []string{"nobody", "ghost"} {
		if _, err := set.GroupAttributes(group); !errors.Is(err, ErrNoSuchGroup) {
			t.Errorf("%s: %v, want ErrNoSuchGroup", group, err)
		}
	}

	// A broken source is an error even though another one answered: it may
	// have been the one whose gidNumber should have won.
	broken := NewSet(file, brokenAttrs{membersOnly{groups: map[string][]string{}}})
	if _, err := broken.GroupAttributes("staff"); err == nil || !strings.Contains(err.Error(), "the database is down") {
		t.Errorf("a broken source gave %v", err)
	}
	brokenOld := NewSet(file, brokenMembers{})
	if _, err := brokenOld.GroupAttributes("staff"); err == nil || errors.Is(err, ErrNoSuchGroup) {
		t.Errorf("a source that cannot say whether it has the group gave %v", err)
	}

	// A Set is itself a GroupAttributer, so sets nest.
	var _ GroupAttributer = set
	nested := NewSet(NewSet(dir), file)
	if a, err := nested.GroupAttributes("staff"); err != nil || a.Get("gidNumber")[0] != "200" {
		t.Errorf("nested: %v %v", a.Names(), err)
	}
}

type brokenMembers struct{ membersOnly }

func (brokenMembers) Members(string) ([]string, error) { return nil, errors.New("down") }

// A person comes whole from the source that owns their name, attributes
// included: the Set does not assemble somebody out of two sources.
func TestAPersonsAttributesComeFromTheSourceThatOwnsThem(t *testing.T) {
	local := &Static{People: []*Identity{NewIdentity("alice",
		WithAttributes(mustAttrs(t, Attribute{"loginShell", []string{"/bin/zsh"}})))}}
	remote := &Static{People: []*Identity{NewIdentity("alice",
		WithAttributes(mustAttrs(t,
			Attribute{"loginShell", []string{"/bin/bash"}},
			Attribute{"mail", []string{"alice@example.org"}})))}}
	ids, err := NewSet(local, remote).Identities()
	if err != nil || len(ids) != 1 {
		t.Fatalf("%v %v", ids, err)
	}
	a := ids[0].Attributes()
	if a.Get("loginShell")[0] != "/bin/zsh" || a.Get("mail") != nil {
		t.Errorf("alice = %v: she belongs to the first source, whole", a.Names())
	}
}
