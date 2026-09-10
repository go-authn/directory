// SPDX-License-Identifier: BSD-3-Clause

// Package hcldir is the `users` block: a directory named in a configuration
// file, opened.
//
//	users "sql" {
//	  driver   = "postgres"
//	  dsn_file = "/etc/authnd/dsn"
//	  users    = "select login, nt_hash, ssh_keys from staff"
//	  groups   = "select team, member from team_members"
//	}
//
//	users "ldap" {
//	  url                = "ldaps://ldap.example.org"
//	  base_dn            = "ou=people,dc=example,dc=org"
//	  bind_dn            = "cn=reader,dc=example,dc=org"
//	  bind_password_file = "/etc/authnd/bind.pw"
//	}
//
// It exists because two programs had written the same block: a file server
// deciding who may mount a share, and an authentication server answering for
// them both. A second spelling of the same idea is a second set of mistakes,
// and a person administering both would have had to learn it twice.
//
// # No HCL here
//
// The struct tags are inert strings, so this package imports no HCL library
// and neither does anybody who only wants the shape. The CALLER decodes --
// with gohcl, or by hand -- and hands the block over.
//
// # Secrets come from files
//
// A DSN and a bind password hold secrets, so they are named by a path and read
// here. Nothing takes one inline, and an LDAP url carrying credentials is
// refused rather than redacted: this url is printed by [directory.Set.Describe]
// and by every error underneath, and redaction would be a promise every one of
// those lines has to keep.
package hcldir

import (
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/go-authn/directory"
)

// A Block is one `users` block: a directory somewhere else, named.
//
// The fields belong to one KIND or the other and mixing them is refused by
// [Block.Check] -- a copy-paste that leaves `driver` in an ldap block is a
// mistake worth naming rather than ignoring.
type Block struct {
	// Kind is "sql" or "ldap". In HCL it is the block's label.
	Kind string `hcl:"kind,label"`

	// sql.
	Driver      string `hcl:"driver,optional"`
	DSNFile     string `hcl:"dsn_file,optional"`
	UsersQuery  string `hcl:"users,optional"`
	GroupsQuery string `hcl:"groups,optional"`

	// ldap.
	URL              string `hcl:"url,optional"`
	BindDN           string `hcl:"bind_dn,optional"`
	BindPasswordFile string `hcl:"bind_password_file,optional"`
	BaseDN           string `hcl:"base_dn,optional"`
	UserFilter       string `hcl:"user_filter,optional"`
	UserAttribute    string `hcl:"user_attribute,optional"`
	GroupBaseDN      string `hcl:"group_base_dn,optional"`
	GroupFilter      string `hcl:"group_filter,optional"`
	GroupAttribute   string `hcl:"group_attribute,optional"`
	// TOTPAttribute is where a one-time-code secret lives, in base32. There
	// is no standard attribute for it -- FreeIPA has ipatokenOTPkey, other
	// schemas have oathSecret -- so it has no default: a guess would read
	// nothing while looking like it had looked.
	TOTPAttribute   string `hcl:"totp_attribute,optional"`
	MemberAttribute string `hcl:"group_member_attribute,optional"`

	// StartTLS upgrades a plaintext LDAP connection before binding. A
	// directory reached over ldap:// without it sends the bind password in the
	// clear, which is worth being asked for rather than assumed.
	StartTLS bool `hcl:"start_tls,optional"`
}

// Kinds are the kinds a block can be, for a message that lists them.
var Kinds = []string{"ldap", "sql"}

// Check reads the block without opening anything.
//
// It is separate from [Open] so that a program can refuse a configuration
// before it touches a network: a directory that is unreachable and one that
// was described wrongly produce the same symptom -- a server that will not
// start -- and only one of them is fixed by looking at the network.
func (b Block) Check() error {
	switch b.Kind {
	case "sql":
		if bad := named(map[string]string{"url": b.URL, "bind_dn": b.BindDN,
			"base_dn": b.BaseDN, "bind_password_file": b.BindPasswordFile}); bad != "" {
			return fmt.Errorf(`users "sql" has %s in it, which belongs to an ldap block`, bad)
		}
		if b.DSNFile == "" {
			return fmt.Errorf("a dsn_file is needed: a DSN holds a password, so it lives in a file and not on a command line")
		}
		if strings.TrimSpace(b.UsersQuery) == "" {
			return fmt.Errorf(`users "sql" has no query for the people: the queries are yours, because your people are already in your shape`)
		}
	case "ldap":
		if bad := named(map[string]string{"driver": b.Driver, "dsn_file": b.DSNFile}); bad != "" {
			return fmt.Errorf(`users "ldap" has %s in it, which belongs to a sql block`, bad)
		}
		// A bind password in the url would be printed: by a server saying
		// where somebody came from, by the LDAP package's errors, and then by
		// whatever collects that output. Refused, and the refusal does not
		// quote the url either.
		if u, err := url.Parse(b.URL); err == nil && u.User != nil {
			return fmt.Errorf(`users "ldap" has credentials in its url, and a url is printed: use bind_dn with bind_password_file`)
		}
	default:
		return fmt.Errorf("there is no %q directory here: there are %s", b.Kind, strings.Join(Kinds, " and "))
	}
	return nil
}

// Open builds the source this block describes, checking it first.
//
// A block whose kind was left out of this build -- see the nosql and noldap
// tags -- is told THAT, which is a different thing from a kind that does not
// exist: the first is a binary chosen too small, the second a typo, and they
// are fixed differently.
func Open(b Block) (directory.Source, error) {
	if err := b.Check(); err != nil {
		return nil, err
	}
	switch b.Kind {
	case "sql":
		return openSQL(b)
	case "ldap":
		return openLDAP(b)
	}
	return nil, fmt.Errorf("there is no %q directory here: there are %s", b.Kind, strings.Join(Kinds, " and "))
}

// OpenAll opens every block, in order, and closes what it opened if one of
// them fails: a half-open set is a server holding a database it will never use.
func OpenAll(blocks []Block) ([]directory.Source, error) {
	var out []directory.Source
	for _, b := range blocks {
		src, err := Open(b)
		if err != nil {
			for _, o := range out {
				if c, ok := o.(interface{ Close() error }); ok {
					c.Close()
				}
			}
			return nil, fmt.Errorf("users %q: %w", b.Kind, err)
		}
		out = append(out, src)
	}
	return out, nil
}

// secretFile reads a file holding one secret, which is how every secret gets
// in here: never a field, never a flag, never an environment variable.
func secretFile(path, what string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", what, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// named is the fields of these that were written, for a message that says
// which ones to delete.
func named(fields map[string]string) string {
	var written []string
	for k, v := range fields {
		if v != "" {
			written = append(written, k)
		}
	}
	slices.Sort(written)
	switch len(written) {
	case 0:
		return ""
	case 1:
		return written[0]
	}
	return strings.Join(written[:len(written)-1], ", ") + " and " + written[len(written)-1]
}

// closing gives back a source that closes something when the set closes.
//
// ⛔ A wrapper that embeds an INTERFACE has exactly that interface's methods,
// and silently drops every optional one the concrete type had. Wrapping a
// *sqldir.Source in a plain struct made it stop being a
// [directory.GroupLister] -- so a server publishing this directory published
// no groups at all, with nothing anywhere saying why. It was found by a
// consumer's end-to-end test, which is the only place it CAN be found: every
// type still satisfied every interface it was declared against.
//
// So the wrapper is chosen by what the source can do. One more capability
// means one more case here, and a test that asks for it.
func closing(src directory.Source, close func() error) directory.Source {
	if lister, ok := src.(directory.GroupLister); ok {
		return closingLister{closer{src, close}, lister}
	}
	return closer{src, close}
}

type closer struct {
	directory.Source
	close func() error
}

func (c closer) Close() error { return c.close() }

// closingLister is a closer that can still list its groups.
type closingLister struct {
	closer
	lister directory.GroupLister
}

func (c closingLister) GroupNames() ([]string, error) { return c.lister.GroupNames() }
