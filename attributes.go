// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
)

// Attributes are what a source says about somebody, or about a group, that is
// not proof of anything: a uidNumber, a home directory, a mail address, a
// display name.
//
// They are kept apart from credentials on purpose. A credential decides who
// may log in and is guarded accordingly -- [Identity.NTKey] and
// [Identity.TOTPSecret] say so in their own documentation. An attribute is
// published: a server turns it into an LDAP entry that anybody allowed to
// search may read. So the one thing this type will not hold is a secret, and
// [CheckAttributeName] is where that is refused.
//
// The names are LDAP attribute descriptions (RFC 4512 §2.5): a descriptor and
// optional options, such as "mail" or "description;lang-fr". They are
// case-insensitive, as LDAP's are, and the order of the options does not
// matter. Values are strings and are not interpreted -- "1000" is a uidNumber
// because a server's schema says so, not because this package parsed it.
//
// An Attributes is immutable once built, so one can be shared and copied
// freely. The zero value holds nothing.
type Attributes struct {
	list  []Attribute
	index map[string]int // canonical description -> position in list
}

// An Attribute is one name and its values, as given to [NewAttributes].
type Attribute struct {
	Name   string
	Values []string
}

// NewAttributes checks these attributes and puts them together.
//
// The order is kept. A name given twice -- or twice in different case, or
// with its options in a different order -- is one attribute, spelled the first
// way it was written, holding the values of both. A value repeated exactly is
// kept once: an LDAP attribute may not hold two equal values (RFC 4512 §2.2),
// and an exact repeat is equal under every matching rule there is. Values that
// are equal only under a schema's rule ("A" and "a" under caseIgnoreMatch) are
// kept, because this package does not know the schema.
//
// Refused, with an error naming the attribute:
//   - a name that is not an RFC 4512 attribute description, or that is an OID
//     rather than a descriptor (see [CheckAttributeName]);
//   - a name that holds a credential, or that a server derives itself;
//   - an attribute with no values, or with an empty one: an LDAP attribute has
//     at least one value, and nearly every syntax refuses an empty string.
func NewAttributes(attrs ...Attribute) (Attributes, error) {
	var a Attributes
	for _, at := range attrs {
		if err := CheckAttributeName(at.Name); err != nil {
			return Attributes{}, err
		}
		if len(at.Values) == 0 {
			return Attributes{}, fmt.Errorf("%w: %q has no values: an attribute without one is left out", ErrAttributeValue, at.Name)
		}
		for _, v := range at.Values {
			if v == "" {
				return Attributes{}, fmt.Errorf("%w: %q has an empty value: an attribute without one is left out", ErrAttributeValue, at.Name)
			}
		}
		a.add(at.Name, at.Values)
	}
	return a, nil
}

// add appends values under name, which has been checked.
func (a *Attributes) add(name string, values []string) {
	key := canonical(name)
	if a.index == nil {
		a.index = map[string]int{}
	}
	i, ok := a.index[key]
	if !ok {
		i = len(a.list)
		a.index[key] = i
		a.list = append(a.list, Attribute{Name: name})
	}
	for _, v := range values {
		if !slices.Contains(a.list[i].Values, v) {
			a.list[i].Values = append(a.list[i].Values, v)
		}
	}
}

// Len is how many attributes there are.
func (a Attributes) Len() int { return len(a.list) }

// Names are the attributes, in order, each spelled the first way it was
// given.
func (a Attributes) Names() []string {
	names := make([]string, len(a.list))
	for i, at := range a.list {
		names[i] = at.Name
	}
	return names
}

// Get is the values of one attribute, found whatever the case of name and the
// order of its options, or nil when there is no such attribute.
//
// A name that could never be an attribute here -- a refused one, or one that
// is not an attribute description -- is simply not found: asking is not
// configuring, and the question has an answer.
func (a Attributes) Get(name string) []string {
	if i, ok := a.index[canonical(name)]; ok {
		return slices.Clone(a.list[i].Values)
	}
	return nil
}

// All is every attribute, in order, with a copy of its values.
func (a Attributes) All() iter.Seq2[string, []string] {
	return func(yield func(string, []string) bool) {
		for _, at := range a.list {
			if !yield(at.Name, slices.Clone(at.Values)) {
				return
			}
		}
	}
}

// under is a with every attribute of b that a does not have, after a's: the
// first source to give an attribute owns it, which is the rule a [Set] applies
// to people, applied to one group's attributes.
func (a Attributes) under(b Attributes) Attributes {
	var out Attributes
	for _, at := range a.list {
		out.add(at.Name, at.Values)
	}
	for _, at := range b.list {
		if _, ok := out.index[canonical(at.Name)]; !ok {
			out.add(at.Name, at.Values)
		}
	}
	return out
}

// ErrAttributeName is a name that cannot be an attribute here: not an RFC 4512
// attribute description, or one this package refuses to carry. The message
// says which, and why.
var ErrAttributeName = errors.New("directory: not an attribute this package carries")

// ErrAttributeValue is an attribute with no value, or an empty one.
var ErrAttributeValue = errors.New("directory: not a value an attribute can hold")

// CheckAttributeName says whether name can be an attribute: nil, or an error
// wrapping [ErrAttributeName] that says why not.
//
// It is exported so that a configuration can be refused before anything is
// read -- ldapdir checks the attributes it is told to copy when it is built,
// rather than at the first search.
//
// A name is an attribute description (RFC 4512 §2.5), restricted to the
// descriptor form:
//
//	attributedescription = descr *( ";" option )
//	descr  = ALPHA *( ALPHA / DIGIT / "-" )      ; §1.4 keystring
//	option = 1*( ALPHA / DIGIT / "-" )
//
// The numeric form RFC 4512 also allows (2.5.4.35) is refused, because the
// refusals below are by NAME: 2.5.4.35 is userPassword, and a list of names
// cannot recognise it. Every attribute a server would publish has a
// descriptor.
//
// Then, whatever the case and whatever the options, it refuses:
//   - anything holding a secret: a password, a hash of one, a key, a one-time
//     code secret, a trust secret -- the list is in [ReservedAttributes], and
//     any name containing password, passwd, pwd, secret, credential, hash or
//     privatekey is refused with it, because a list of names only knows the
//     schemas somebody read;
//   - sshPublicKey, which has its own path through [WithPublicKeys], so that
//     [Identity.Can] keeps telling the truth about who can use SSH;
//   - uid, cn and objectClass (and their aliases userid and commonName),
//     which a server derives from the name it publishes an entry under;
//   - member, uniqueMember, memberUid and memberOf, which are membership --
//     [Source.Members] answers that, and a second answer would disagree;
//   - the operational attributes a server maintains (RFC 4512 §3.4, entryDN,
//     entryUUID), which a configuration could only forge.
func CheckAttributeName(name string) error {
	typ, _, err := parseDescription(name)
	if err != nil {
		return err
	}
	lower := strings.ToLower(typ)
	if why, ok := reserved[lower]; ok {
		return fmt.Errorf("%w: %q %s", ErrAttributeName, name, why)
	}
	if _, ok := notASecret[lower]; !ok {
		for _, frag := range secretFragments {
			if strings.Contains(lower, frag) {
				return fmt.Errorf("%w: %q looks like it holds a secret (its name contains %q), and attributes are published: "+
					"a credential has its own option or none", ErrAttributeName, name, frag)
			}
		}
	}
	return nil
}

// parseDescription splits an attribute description into its type and options,
// refusing anything that is not one.
func parseDescription(name string) (string, []string, error) {
	if name == "" {
		return "", nil, fmt.Errorf("%w: an attribute needs a name", ErrAttributeName)
	}
	parts := strings.Split(name, ";")
	typ, options := parts[0], parts[1:]
	if typ != "" && isDigit(typ[0]) {
		return "", nil, fmt.Errorf("%w: %q is an OID: name it by its descriptor, so that what is refused by name stays refused", ErrAttributeName, name)
	}
	if !isKeystring(typ) {
		return "", nil, fmt.Errorf("%w: %q is not an attribute description: "+
			"a letter, then letters, digits and hyphens, optionally with ;options (RFC 4512 §1.4, §2.5)", ErrAttributeName, name)
	}
	for _, o := range options {
		if o == "" || strings.IndexFunc(o, func(r rune) bool { return !isKeychar(r) }) >= 0 {
			return "", nil, fmt.Errorf("%w: %q has an option that is not letters, digits and hyphens (RFC 4512 §2.5)", ErrAttributeName, name)
		}
	}
	return typ, options, nil
}

// canonical is the form two equivalent descriptions share: RFC 4512 §2.5 makes
// the type and the options case-insensitive, and the order of the options
// irrelevant.
func canonical(name string) string {
	parts := strings.Split(strings.ToLower(name), ";")
	slices.Sort(parts[1:])
	return strings.Join(parts, ";")
}

func isKeystring(s string) bool {
	if s == "" || !isAlpha(rune(s[0])) {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return !isKeychar(r) }) < 0
}

func isAlpha(r rune) bool   { return r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' }
func isDigit(b byte) bool   { return b >= '0' && b <= '9' }
func isKeychar(r rune) bool { return isAlpha(r) || r >= '0' && r <= '9' || r == '-' }

// ReservedAttributes are the names [CheckAttributeName] refuses outright,
// whatever their case, each with the reason it gives. Names containing a
// secret-looking fragment are refused besides, without being listed.
//
// It returns a copy: the list is what this package enforces, and changing a
// copy changes nothing.
func ReservedAttributes() map[string]string {
	out := make(map[string]string, len(reserved))
	for k, v := range reserved {
		out[k] = v
	}
	return out
}

const (
	whySecret   = "holds a secret, and attributes are published: a credential has its own option or none"
	whySSH      = "has its own path, WithPublicKeys, so that Can(PublicKeys) stays true to it"
	whyNaming   = "is derived by the server from the name it publishes the entry under"
	whyMember   = "is membership, which Members answers: a second answer would disagree with it"
	whyOperated = "is maintained by the server itself, and a configuration could only forge it"
)

// reserved is keyed by the lower-case descriptor.
//
// The secrets are the ones the schemas in use actually define, read from
// their sources rather than remembered:
//
//	RFC 4519 §2.41      userPassword
//	RFC 3112            authPassword
//	RFC 2798            userPKCS12 (a PKCS #12 PFX: a PRIVATE key)
//	Samba samba.schema  sambaNTPassword, sambaLMPassword, sambaPasswordHistory,
//	                    sambaClearTextPassword, sambaPreviousClearTextPassword,
//	                    and the older lmPassword, ntPassword
//	Active Directory    unicodePwd, dBCSPwd, ntPwdHistory, lmPwdHistory,
//	                    supplementalCredentials, msDS-ManagedPassword,
//	                    ms-Mcs-AdmPwd, msLAPS-Password, msLAPS-EncryptedPassword,
//	                    msLAPS-EncryptedPasswordHistory, msLAPS-EncryptedDSRMPassword,
//	                    msLAPS-EncryptedDSRMPasswordHistory, msFVE-RecoveryPassword,
//	                    msFVE-KeyPackage, trustAuthIncoming, trustAuthOutgoing,
//	                    initialAuthIncoming, initialAuthOutgoing, currentValue,
//	                    priorValue, pekList, msPKIAccountCredentials,
//	                    msPKIDPAPIMasterKeys, msDS-KeyCredentialLink
//	MIT Kerberos        krbPrincipalKey, krbMKey, krbPwdHistory
//	Heimdal hdb.schema  krb5Key
//	FreeIPA             ipaNTHash, ipatokenOTPkey, ipaNTTrustAuthIncoming,
//	                    ipaNTTrustAuthOutgoing, ipatokenRadiusSecret,
//	                    ipaIdpClientSecret, ipaPrivateKey, ipaSecretKey
//	389-ds              nsDS5ReplicaCredentials, nsDS5ReplicaBootstrapCredentials,
//	                    nsBindPassword, nsSymmetricKey, nsslapd-rootpw,
//	                    passwordHistory (alias pwdHistory)
//	OpenLDAP            olcRootPW, pwdHistory (ppolicy), oathSecret and
//	                    oathTokenPIN (otp overlay)
var reserved = func() map[string]string {
	m := map[string]string{}
	for _, n := range []string{
		"userPassword", "authPassword", "userPKCS12",
		"sambaNTPassword", "sambaLMPassword", "sambaPasswordHistory",
		"sambaClearTextPassword", "sambaPreviousClearTextPassword",
		"lmPassword", "ntPassword",
		"unicodePwd", "dBCSPwd", "ntPwdHistory", "lmPwdHistory",
		"supplementalCredentials", "msDS-ManagedPassword",
		"ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword",
		"msLAPS-EncryptedPasswordHistory", "msLAPS-EncryptedDSRMPassword",
		"msLAPS-EncryptedDSRMPasswordHistory", "msFVE-RecoveryPassword",
		"msFVE-KeyPackage", "trustAuthIncoming", "trustAuthOutgoing",
		"initialAuthIncoming", "initialAuthOutgoing", "currentValue",
		"priorValue", "pekList", "msPKIAccountCredentials",
		"msPKIDPAPIMasterKeys", "msDS-KeyCredentialLink",
		"krbPrincipalKey", "krbMKey", "krbPwdHistory", "krb5Key",
		"ipaNTHash", "ipatokenOTPkey", "ipaNTTrustAuthIncoming",
		"ipaNTTrustAuthOutgoing", "ipatokenRadiusSecret",
		"ipaIdpClientSecret", "ipaPrivateKey", "ipaSecretKey",
		"nsDS5ReplicaCredentials", "nsDS5ReplicaBootstrapCredentials",
		"nsBindPassword", "nsSymmetricKey", "nsslapd-rootpw",
		"passwordHistory", "pwdHistory",
		"olcRootPW", "oathSecret", "oathTokenPIN",
	} {
		m[strings.ToLower(n)] = whySecret
	}
	m["sshpublickey"] = whySSH
	for _, n := range []string{"uid", "userid", "cn", "commonName", "objectClass"} {
		m[strings.ToLower(n)] = whyNaming
	}
	for _, n := range []string{"member", "uniqueMember", "memberUid", "memberOf"} {
		m[strings.ToLower(n)] = whyMember
	}
	for _, n := range []string{
		// RFC 4512 §3.4 and §4.2.
		"creatorsName", "createTimestamp", "modifiersName", "modifyTimestamp",
		"structuralObjectClass", "governingStructureRule", "subschemaSubentry",
		// RFC 5020, RFC 4530.
		"entryDN", "entryUUID",
	} {
		m[strings.ToLower(n)] = whyOperated
	}
	return m
}()

// secretFragments refuse what the list above has never heard of: a site's own
// schema, a vendor's next one. A false refusal costs an error at startup that
// names the rule; a false acceptance publishes a secret to everybody who may
// search.
var secretFragments = []string{"password", "passwd", "pwd", "secret", "credential", "hash", "privatekey"}

// notASecret are the names in the standard schemas (RFC 4519, 4524, 2798,
// 2307) that contain a fragment and hold nothing secret. There is one.
var notASecret = map[string]struct{}{
	"secretary": {}, // RFC 4524 §2.21: the DN of a person's secretary
}
