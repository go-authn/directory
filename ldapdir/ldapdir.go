// SPDX-License-Identifier: BSD-3-Clause

// Package ldapdir reads people and groups from an LDAP directory.
//
// # What LDAP can and cannot prove
//
// This is the thing to understand before choosing it, and it is a fact about
// protocols rather than about this package.
//
// An LDAP directory authenticates by BIND: you hand it a name and a password
// and it says yes or no, without ever giving the password up. That is exactly
// right for anything that RECEIVES a password from the client — HTTP Basic,
// an ordinary login form — and this package wires it up as a verifier.
//
// It is exactly wrong for NTLMv2, which Windows file sharing uses. There the
// client never sends the password: it sends a response computed from it, and
// the server must compute the same thing from MD4(UTF16LE(password)). There is
// nothing to bind WITH. So an LDAP user can be served over SMB only if the
// directory publishes `sambaNTPassword` — which is what Samba's own schema
// exists for — and over SSH only if it publishes `sshPublicKey`, which is
// OpenSSH's convention and what sssd reads.
//
// Both attributes are read here when they are there, and
// [github.com/go-authn/directory.Identity.Can] then reports, per person,
// which protocols their credentials can actually answer.
package ldapdir

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/go-authn/directory"
	"github.com/go-ldap/ldap/v3"
)

// Config is where the directory is and how it is laid out.
//
// The defaults are a small site's posixAccount/posixGroup, which is what an
// OpenLDAP put up for a team looks like. A directory using groupOfNames says
// so with MemberAttribute, and the DNs it holds are reduced to their first
// value so that a member reads as a name everywhere else.
type Config struct {
	URL    string // ldaps://host, or ldap://host for a plaintext one
	BaseDN string // where the people are

	// BindDN and BindPassword are how this server reads the directory. An
	// anonymous read is allowed by leaving them empty, which some directories
	// permit and most do not.
	BindDN       string
	BindPassword string

	UserFilter    string // default (objectClass=posixAccount)
	UserAttribute string // default uid

	// TOTPAttribute is where a one-time-code secret lives, in base32. It has
	// NO default on purpose: there is no standard attribute for it -- FreeIPA
	// has ipatokenOTPkey, other schemas have oathSecret or something local --
	// and a default that guessed wrong would read nothing while looking like
	// it had looked.
	TOTPAttribute string

	// Attributes are what to copy from each person's entry, as the directory
	// names them -- ["mail", "uidNumber", "homeDirectory"] -- into
	// [github.com/go-authn/directory.Identity.Attributes]. They describe and
	// prove nothing, and none of them may be a credential: [New] refuses
	// what [github.com/go-authn/directory.CheckAttributeName] refuses, and
	// TOTPAttribute, which holds a secret under a name only this
	// configuration knows. Nothing is copied by default.
	//
	// An attribute is copied under the spelling written here, whatever case
	// the directory answers in. Subtypes it returns besides -- description;
	// lang-fr, for description -- are not: ask for them by name.
	Attributes []string

	// GroupAttributes are the same for each group: ["gidNumber"]. The
	// member attribute is refused, since Members is how membership is read.
	GroupAttributes []string

	GroupBaseDN     string // default: BaseDN
	GroupFilter     string // default (objectClass=posixGroup)
	GroupAttribute  string // default cn
	MemberAttribute string // default memberUid

	// TLS is used for ldaps:// and for StartTLS. A nil one means TLS 1.2 and
	// the system roots, which is the right default and the one a caller
	// overrides to pin a private CA.
	TLS *tls.Config

	// StartTLS upgrades a plaintext connection before binding. A directory
	// reached over ldap:// without it sends the bind password in the clear,
	// so [New] refuses ldap:// to anything but loopback without it.
	StartTLS bool
}

// A Source reads an LDAP directory.
type Source struct {
	cfg Config
}

// New connects once, to find out whether the directory is there at all.
//
// It is done here rather than at the first login because a directory that is
// not answering is a server that cannot authenticate anybody, and that should
// be said before it starts listening.
func New(cfg Config) (*Source, error) {
	if cfg.URL == "" || cfg.BaseDN == "" {
		return nil, fmt.Errorf("ldapdir: a url and a base_dn are needed")
	}
	// ldap://cn=reader:secret@host is a valid URL and an unrecoverable
	// mistake: this one is printed by [Source.Describe], by every error
	// below, and then by whatever the caller logs those into. Refused rather
	// than redacted, because redaction is a promise every line that prints it
	// would have to keep, and this package cannot keep it on their behalf.
	//
	// The refusal does not quote the URL, for the same reason.
	if u, err := url.Parse(cfg.URL); err == nil && u.User != nil {
		return nil, fmt.Errorf("ldapdir: the url carries credentials in it, and a URL is printed: give BindDN and BindPassword instead")
	}
	if err := cleartext(cfg.URL, cfg.StartTLS); err != nil {
		return nil, err
	}
	if cfg.TLS == nil {
		cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.UserFilter = or(cfg.UserFilter, "(objectClass=posixAccount)")
	cfg.UserAttribute = or(cfg.UserAttribute, "uid")
	cfg.GroupBaseDN = or(cfg.GroupBaseDN, cfg.BaseDN)
	cfg.GroupFilter = or(cfg.GroupFilter, "(objectClass=posixGroup)")
	cfg.GroupAttribute = or(cfg.GroupAttribute, "cn")
	cfg.MemberAttribute = or(cfg.MemberAttribute, "memberUid")
	if err := checkCopied(cfg); err != nil {
		return nil, err
	}

	s := &Source{cfg: cfg}
	c, err := s.dial()
	if err != nil {
		return nil, err
	}
	c.Close()
	return s, nil
}

// checkCopied refuses, before connecting, an attribute this source must not
// copy: what the directory package refuses everywhere, and the names this
// configuration itself gives a meaning that is not description.
func checkCopied(cfg Config) error {
	for _, c := range []struct {
		field string
		names []string
		// own are the attributes this configuration reads for something
		// else, with what it reads them for.
		own map[string]string
	}{
		{"Attributes", cfg.Attributes, map[string]string{
			cfg.TOTPAttribute: "is TOTPAttribute: it holds a one-time-code secret",
		}},
		{"GroupAttributes", cfg.GroupAttributes, map[string]string{
			cfg.MemberAttribute: "is MemberAttribute: membership is what Members reads",
			cfg.GroupAttribute:  "is GroupAttribute: it names the group",
		}},
	} {
		for _, n := range c.names {
			if err := directory.CheckAttributeName(n); err != nil {
				return fmt.Errorf("ldapdir: %s: %w", c.field, err)
			}
			for own, why := range c.own {
				if own != "" && attrType(n) == attrType(own) {
					return fmt.Errorf("ldapdir: %s: %q %s, and is not copied as a description", c.field, n, why)
				}
			}
		}
	}
	return nil
}

// attrType is an attribute description's type, in lower case: what two
// spellings of one attribute share, options aside.
func attrType(desc string) string {
	t, _, _ := strings.Cut(desc, ";")
	return strings.ToLower(t)
}

// copied reads the attributes named in names out of an entry, each under the
// spelling configured, matching the directory's spelling without regard to
// case or to the order of options (RFC 4512 §2.5).
func copied(e *ldap.Entry, names []string) (directory.Attributes, error) {
	var list []directory.Attribute
	for _, n := range names {
		var values []string
		for _, a := range e.Attributes {
			if sameDescription(a.Name, n) {
				for _, v := range a.Values {
					if v != "" {
						values = append(values, v)
					}
				}
			}
		}
		if len(values) > 0 {
			list = append(list, directory.Attribute{Name: n, Values: values})
		}
	}
	return directory.NewAttributes(list...)
}

// sameDescription is RFC 4512 §2.5's equivalence: the same type and the same
// set of options, case-insensitively.
func sameDescription(a, b string) bool {
	pa, pb := strings.Split(strings.ToLower(a), ";"), strings.Split(strings.ToLower(b), ";")
	if len(pa) != len(pb) || pa[0] != pb[0] {
		return false
	}
	slices.Sort(pa[1:])
	slices.Sort(pb[1:])
	return slices.Equal(pa, pb)
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (s *Source) Describe() string { return s.cfg.URL }

func (s *Source) dial() (*ldap.Conn, error) {
	c, err := ldap.DialURL(s.cfg.URL, ldap.DialWithTLSConfig(s.cfg.TLS))
	if err != nil {
		return nil, fmt.Errorf("ldapdir: %s is not answering: %w", s.cfg.URL, err)
	}
	if s.cfg.StartTLS {
		if err := c.StartTLS(s.cfg.TLS); err != nil {
			c.Close()
			return nil, fmt.Errorf("ldapdir: StartTLS: %w", err)
		}
	}
	if s.cfg.BindDN != "" {
		if err := c.Bind(s.cfg.BindDN, s.cfg.BindPassword); err != nil {
			c.Close()
			return nil, fmt.Errorf("ldapdir: binding as %s: %w", s.cfg.BindDN, err)
		}
	}
	return c, nil
}

// Identities reads everybody under the base DN.
func (s *Source) Identities() ([]*directory.Identity, error) {
	c, err := s.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	res, err := c.Search(ldap.NewSearchRequest(
		s.cfg.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		s.cfg.UserFilter,
		s.attributes(),
		nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldapdir: searching for people: %w", err)
	}
	out := make([]*directory.Identity, 0, len(res.Entries))
	for _, e := range res.Entries {
		name := e.GetAttributeValue(s.cfg.UserAttribute)
		if name == "" {
			// An entry with no name is not somebody: it is a container, or a
			// schema object that matched the filter.
			continue
		}
		opts := []directory.Option{directory.From(s.cfg.URL)}
		if h := e.GetAttributeValue("sambaNTPassword"); h != "" {
			raw, err := directory.ParseNTHash(h)
			if err != nil {
				return nil, fmt.Errorf("ldapdir: %s: sambaNTPassword: %w", name, err)
			}
			opts = append(opts, directory.WithNTHash(raw))
		}
		for _, k := range e.GetAttributeValues("sshPublicKey") {
			if k = strings.TrimSpace(k); k != "" {
				opts = append(opts, directory.WithPublicKeys(k))
			}
		}
		if s.cfg.TOTPAttribute != "" {
			if v := strings.TrimSpace(e.GetAttributeValue(s.cfg.TOTPAttribute)); v != "" {
				secret, err := directory.ParseTOTPSecret(v)
				if err != nil {
					// Named, not quoted: the attribute holds a credential. And
					// refused rather than dropped, because dropping it turns
					// "this person has a second factor" into "this person has
					// none" without a word.
					return nil, fmt.Errorf("ldapdir: %s: %s: %w", name, s.cfg.TOTPAttribute, err)
				}
				opts = append(opts, directory.WithTOTPSecret(secret))
			}
		}
		if len(s.cfg.Attributes) > 0 {
			a, err := copied(e, s.cfg.Attributes)
			if err != nil {
				return nil, fmt.Errorf("ldapdir: %s: %w", name, err)
			}
			opts = append(opts, directory.WithAttributes(a))
		}
		// The password is never read: the directory holds it and will not give
		// it up, which is the point of a directory. What it will do is answer
		// "is this it", one bind at a time.
		opts = append(opts, directory.WithVerifier(s.bindAs(e.DN)))
		out = append(out, directory.NewIdentity(name, opts...))
	}
	return out, nil
}

// attributes is what to ask the directory for: the name, the two credentials
// this package knows the standard spelling of, the one whose spelling the
// caller had to supply, and the descriptions it asked to copy.
func (s *Source) attributes() []string {
	attrs := []string{s.cfg.UserAttribute, "sambaNTPassword", "sshPublicKey"}
	if s.cfg.TOTPAttribute != "" {
		attrs = append(attrs, s.cfg.TOTPAttribute)
	}
	return append(attrs, s.cfg.Attributes...)
}

// GroupAttributes copies the configured GroupAttributes from one group's
// entry -- from every entry, when the filter matches several, as Members
// reads the members of all of them.
func (s *Source) GroupAttributes(group string) (directory.Attributes, error) {
	c, err := s.dial()
	if err != nil {
		return directory.Attributes{}, err
	}
	defer c.Close()

	// Asked for even with nothing to copy: the answer is then whether the
	// group exists, and "1.1" is RFC 4511 §4.5.1.8's "no attributes".
	want := append([]string(nil), s.cfg.GroupAttributes...)
	if len(want) == 0 {
		want = []string{"1.1"}
	}
	filter := fmt.Sprintf("(&%s(%s=%s))", s.cfg.GroupFilter, s.cfg.GroupAttribute, ldap.EscapeFilter(group))
	res, err := c.Search(ldap.NewSearchRequest(
		s.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, want, nil,
	))
	if err != nil {
		return directory.Attributes{}, fmt.Errorf("ldapdir: searching for group %q: %w", group, err)
	}
	if len(res.Entries) == 0 {
		return directory.Attributes{}, fmt.Errorf("%w: %q, under %s", directory.ErrNoSuchGroup, group, s.cfg.GroupBaseDN)
	}
	merged := &ldap.Entry{}
	for _, e := range res.Entries {
		merged.Attributes = append(merged.Attributes, e.Attributes...)
	}
	a, err := copied(merged, s.cfg.GroupAttributes)
	if err != nil {
		return directory.Attributes{}, fmt.Errorf("ldapdir: group %q: %w", group, err)
	}
	return a, nil
}

// bindAs is the password check: a bind, on its OWN connection.
//
// Its own, because binding changes the state of the connection it happens on —
// a bind as somebody else on the connection this server reads the directory
// with would leave it reading as them.
func (s *Source) bindAs(dn string) func(string) error {
	return func(password string) error {
		if password == "" {
			// An empty password is an UNAUTHENTICATED BIND in LDAP: the server
			// answers success and nobody has proved anything. It is the oldest
			// hole in the protocol, it is still open in most directories, and
			// it is refused here.
			return directory.ErrWrongPassword
		}
		c, err := ldap.DialURL(s.cfg.URL, ldap.DialWithTLSConfig(s.cfg.TLS))
		if err != nil {
			return fmt.Errorf("ldapdir: %w", err)
		}
		defer c.Close()
		if s.cfg.StartTLS {
			if err := c.StartTLS(s.cfg.TLS); err != nil {
				return fmt.Errorf("ldapdir: StartTLS: %w", err)
			}
		}
		if err := c.Bind(dn, password); err != nil {
			// ⛔ Only invalidCredentials (49) says the password is wrong. Every
			// other failure -- a connection dropped mid-bind, a directory
			// answering busy (51) or unavailable (52) -- is the directory
			// failing, and was reported as a wrong password: a server in front
			// of this one then logged "wrong password" for people who typed it
			// right, while the real cause went unsaid. Still an error, so the
			// bind is refused either way: this changes what is SAID, not what
			// is let in.
			if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				return directory.ErrWrongPassword
			}
			return fmt.Errorf("ldapdir: the directory did not answer the bind: %w", err)
		}
		return nil
	}
}

// Members expands a group.
// GroupNames is every group under the group base, by the same filter Members
// uses -- without the name, which is the only difference between asking about
// one group and asking for all of them.
func (s *Source) GroupNames() ([]string, error) {
	c, err := s.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	res, err := c.Search(ldap.NewSearchRequest(
		s.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		s.cfg.GroupFilter, []string{s.cfg.GroupAttribute}, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldapdir: listing the groups under %s: %w", s.cfg.GroupBaseDN, err)
	}
	var names []string
	for _, e := range res.Entries {
		names = append(names, e.GetAttributeValues(s.cfg.GroupAttribute)...)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

func (s *Source) Members(group string) ([]string, error) {
	c, err := s.dial()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	filter := fmt.Sprintf("(&%s(%s=%s))", s.cfg.GroupFilter, s.cfg.GroupAttribute, ldap.EscapeFilter(group))
	res, err := c.Search(ldap.NewSearchRequest(
		s.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter, []string{s.cfg.MemberAttribute}, nil,
	))
	if err != nil {
		return nil, fmt.Errorf("ldapdir: searching for group %q: %w", group, err)
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("%w: %q, under %s", directory.ErrNoSuchGroup, group, s.cfg.GroupBaseDN)
	}
	var members []string
	for _, e := range res.Entries {
		for _, m := range e.GetAttributeValues(s.cfg.MemberAttribute) {
			members = append(members, memberName(m))
		}
	}
	return members, nil
}

// memberName reduces what a group holds to the name everything else uses.
//
// posixGroup holds names in memberUid; groupOfNames holds DNs in member. A
// server comparing "alice" against "uid=alice,ou=people,dc=example,dc=org"
// finds no match and tells alice she is not in her own group.
func memberName(m string) string {
	if !strings.Contains(m, "=") {
		return m
	}
	dn, err := ldap.ParseDN(m)
	if err != nil || len(dn.RDNs) == 0 || len(dn.RDNs[0].Attributes) == 0 {
		return m
	}
	return dn.RDNs[0].Attributes[0].Value
}

// cleartext refuses a plaintext ldap:// to another machine.
//
// ⛔ Every password [Source.Identities] hands out a verifier for is checked by
// a simple BIND, and a simple bind carries the password itself. RFC 4513
// §5.1.3: it "is not suitable for authentication in environments without
// confidentiality protection"; §6.3.3: implementations "SHOULD NOT by default
// support" it unless the session is protected by TLS. Over ldap:// without
// StartTLS every person who logs in sends their password across the network
// as typed.
//
// Loopback stays allowed -- the same rule the oidc package applies to a JWKS
// URL -- and so does ldapi://, a local socket: nobody is on the way. hcldir's
// Block.Check holds the same rule, written there again because hcldir builds
// without this package under -tags noldap.
func cleartext(raw string, startTLS bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ldap" || startTLS || loopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("ldapdir: would send every password to %q in the clear: "+
		"use ldaps://, or StartTLS (RFC 4513 §5.1.3)", u.Hostname())
}

// loopbackHost is a host that cannot be off this machine.
func loopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
