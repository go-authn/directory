// SPDX-License-Identifier: BSD-3-Clause

// Package ldaptest is an LDAP directory to test against.
//
//	d := ldaptest.NewServer(&ldaptest.Directory{
//	    People: map[string]ldaptest.Person{
//	        "dora": {Password: "hunter2", NTHash: hex.EncodeToString(directory.NTHashOf("hunter2"))},
//	        "eli":  {Password: "swordfish"},   // a bind, and nothing else
//	    },
//	    Groups: map[string][]string{"engineers": {"dora", "eli"}},
//	})
//	defer d.Close()
//	src, err := ldapdir.New(ldapdir.Config{URL: d.URL, BaseDN: d.BaseDN, …})
//
// It answers Bind and Search with glauth/ldap -- an independent
// implementation of the protocol, which is the point. A fake built from one
// reading of the specification can only ever confirm that reading: if the
// reading is wrong, the fake is wrong the same way and the test passes.
//
// It exists because three packages had written the same fixture, and one of
// them is a file server in another organisation entirely. A fixture copied
// three times is three fixtures that drift.
//
// # What it deliberately gets right
//
// An empty password binds SUCCESSFULLY here, because it does in a real
// directory -- the unauthenticated bind, RFC 4513 §5.1.2. A server that treats
// a bind as proof must refuse an empty password itself, and cannot be shown to
// do so against a fixture that quietly refuses it first.
package ldaptest

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	server "github.com/glauth/ldap"
)

// A Person is one entry: the credentials a directory could publish for them.
//
// The distinction the whole thing exists for: a person with a Password can be
// BOUND as, and a person with an NTHash can be served over NTLMv2. A directory
// that publishes only the first cannot serve SMB, however good it is.
type Person struct {
	// DN defaults to uid=<name>,<BaseDN>.
	DN string
	// Password is what a bind as this person accepts. Empty means no bind
	// succeeds -- except the unauthenticated one, which succeeds for anybody.
	Password string
	// NTHash is sambaNTPassword, in the 32 hex characters a directory
	// publishes. Use directory.NTHashOf and encoding/hex.
	NTHash string
	// SSHKeys are sshPublicKey values, in authorized_keys spelling.
	SSHKeys []string
	// Extra are any other attributes, for a schema that names things
	// differently.
	Extra map[string][]string
}

// A Directory is what the server answers with.
type Directory struct {
	// People, by the value of the uid attribute.
	People map[string]Person
	// Groups, by cn, holding uids.
	Groups map[string][]string

	// BaseDN defaults to dc=example,dc=org, with people under
	// ou=people and groups under ou=groups.
	BaseDN string
	// ReaderDN and ReaderPassword are the service account a client binds as
	// to read. They default to cn=reader,<BaseDN> and "let me read".
	ReaderDN       string
	ReaderPassword string
}

// A Server is a running directory. Close it when the test ends.
type Server struct {
	// URL is what to give a client: ldap://127.0.0.1:<port>.
	URL string
	// BaseDN, PeopleDN and GroupsDN are where the entries are, so a test does
	// not repeat the strings this package chose.
	BaseDN, PeopleDN, GroupsDN string
	// ReaderDN and ReaderPassword are the service account that may read.
	ReaderDN, ReaderPassword string

	// Binds counts every bind attempted, successful or not. A server that
	// claims to check a password against the directory can be SHOWN to do it.
	binds int
	mu    sync.Mutex

	d  *Directory
	ln net.Listener
}

// NewServer starts a directory on loopback.
func NewServer(d *Directory) (*Server, error) {
	if d == nil {
		d = &Directory{}
	}
	s := &Server{d: d, BaseDN: or(d.BaseDN, "dc=example,dc=org")}
	s.PeopleDN = "ou=people," + s.BaseDN
	s.GroupsDN = "ou=groups," + s.BaseDN
	s.ReaderDN = or(d.ReaderDN, "cn=reader,"+s.BaseDN)
	s.ReaderPassword = or(d.ReaderPassword, "let me read")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.ln = ln
	s.URL = "ldap://" + ln.Addr().String()

	srv := server.NewServer()
	srv.BindFunc("", s)
	srv.SearchFunc("", s)
	go func() { _ = srv.Serve(ln) }()

	// Dialled before returning: the address a client uses is the one the
	// listener got, and a test that races the accept loop fails in a way that
	// reads exactly like a bug in the code under test.
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			c.Close()
			return s, nil
		}
		if time.Now().After(deadline) {
			ln.Close()
			return nil, fmt.Errorf("ldaptest: nothing is listening on %s", s.URL)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Close stops the server.
func (s *Server) Close() error { return s.ln.Close() }

// Binds is how many binds have been attempted, successful or not.
func (s *Server) Binds() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binds
}

// DN is where a person's entry is, whether they set one or not.
func (s *Server) DN(uid string) string {
	if p, ok := s.d.People[uid]; ok && p.DN != "" {
		return p.DN
	}
	return "uid=" + uid + "," + s.PeopleDN
}

// Bind answers as a directory does, including the parts that are inconvenient.
func (s *Server) Bind(bindDN, password string, _ net.Conn) (server.LDAPResultCode, error) {
	s.mu.Lock()
	s.binds++
	s.mu.Unlock()

	// The unauthenticated bind: an empty password succeeds, for anybody. It is
	// here because it is there, in every real directory, and a server that
	// treats a bind as proof of a password must refuse it BEFORE binding.
	if password == "" {
		return server.LDAPResultSuccess, nil
	}
	if bindDN == s.ReaderDN && password == s.ReaderPassword {
		return server.LDAPResultSuccess, nil
	}
	for uid, p := range s.d.People {
		if s.DN(uid) == bindDN && p.Password != "" && password == p.Password {
			return server.LDAPResultSuccess, nil
		}
	}
	return server.LDAPResultInvalidCredentials, nil
}

// Search answers the two searches a directory reader makes: the people, and
// one group's members.
func (s *Server) Search(_ string, req server.SearchRequest, _ net.Conn) (server.ServerSearchResult, error) {
	var entries []*server.Entry
	switch {
	case strings.Contains(req.Filter, "posixGroup"):
		for name, members := range s.d.Groups {
			if !strings.Contains(req.Filter, "cn="+name+")") {
				continue
			}
			entries = append(entries, &server.Entry{
				DN:         "cn=" + name + "," + s.GroupsDN,
				Attributes: []*server.EntryAttribute{{Name: "memberUid", Values: members}},
			})
		}
	default:
		for uid, p := range s.d.People {
			attrs := []*server.EntryAttribute{{Name: "uid", Values: []string{uid}}}
			if p.NTHash != "" {
				attrs = append(attrs, &server.EntryAttribute{Name: "sambaNTPassword", Values: []string{p.NTHash}})
			}
			if len(p.SSHKeys) > 0 {
				attrs = append(attrs, &server.EntryAttribute{Name: "sshPublicKey", Values: p.SSHKeys})
			}
			for name, values := range p.Extra {
				attrs = append(attrs, &server.EntryAttribute{Name: name, Values: values})
			}
			entries = append(entries, &server.Entry{DN: s.DN(uid), Attributes: attrs})
		}
	}
	return server.ServerSearchResult{Entries: entries, ResultCode: server.LDAPResultSuccess}, nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
