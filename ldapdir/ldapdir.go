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
	"net/url"
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
	// which is worth being asked for rather than assumed.
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
	if cfg.TLS == nil {
		cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	cfg.UserFilter = or(cfg.UserFilter, "(objectClass=posixAccount)")
	cfg.UserAttribute = or(cfg.UserAttribute, "uid")
	cfg.GroupBaseDN = or(cfg.GroupBaseDN, cfg.BaseDN)
	cfg.GroupFilter = or(cfg.GroupFilter, "(objectClass=posixGroup)")
	cfg.GroupAttribute = or(cfg.GroupAttribute, "cn")
	cfg.MemberAttribute = or(cfg.MemberAttribute, "memberUid")

	s := &Source{cfg: cfg}
	c, err := s.dial()
	if err != nil {
		return nil, err
	}
	c.Close()
	return s, nil
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
		[]string{s.cfg.UserAttribute, "sambaNTPassword", "sshPublicKey"},
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
		// The password is never read: the directory holds it and will not give
		// it up, which is the point of a directory. What it will do is answer
		// "is this it", one bind at a time.
		opts = append(opts, directory.WithVerifier(s.bindAs(e.DN)))
		out = append(out, directory.NewIdentity(name, opts...))
	}
	return out, nil
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
			return directory.ErrWrongPassword
		}
		return nil
	}
}

// Members expands a group.
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
