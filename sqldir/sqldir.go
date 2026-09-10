// SPDX-License-Identifier: BSD-3-Clause

// Package sqldir reads people and groups from a database.
//
// It is a subpackage rather than a module of its own on purpose: a submodule
// would need a replace directive to build before its parent is tagged, and a
// replace in a library's go.mod is ignored by everybody who imports it. What
// a consumer actually carries is what it IMPORTS -- a program that never
// imports this package does not link it, whatever its go.sum says.
//
// It takes an [database/sql.DB] rather than a connection string, and queries
// rather than a schema. Both are deliberate:
//
//   - The DRIVER is the caller's choice. This package imports none, so a
//     program that wants SQLite does not carry PostgreSQL, and one that wants
//     PostgreSQL is not told which of the three PostgreSQL drivers to use.
//
//   - The QUERIES are the caller's too, because a site whose people are
//     already in a database has them in ITS shape. A schema this package
//     invented would mean copying them into a second one that goes stale.
//
//     db, err := sql.Open("pgx", dsn)
//     src := sqldir.New(db, sqldir.Queries{
//     People: `select name, password, nt_hash, ssh_keys from people`,
//     Groups: `select group_name, member from group_members`,
//     })
package sqldir

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/go-authn/directory"
)

// Queries are the two statements this package runs.
//
// People must return, in this order: a name, and then any of a password, an NT
// hash, and SSH keys. A column that is NULL is a credential that person does
// not have, which decides which protocols they can use — see
// [github.com/go-authn/directory.Identity.Can].
//
// Groups must return a group name and a member name, one row per membership.
type Queries struct {
	People string
	Groups string
}

// A Source reads a database.
type Source struct {
	db      *sql.DB
	q       Queries
	name    string
	verify  func(*sql.DB, string, string) error
	columns int
}

// Option changes how a source reads.
type Option func(*Source)

// Named says what to call this source when a server prints where somebody came
// from: "the staff database" reads better than "a database".
func Named(name string) Option { return func(s *Source) { s.name = name } }

// WithPasswordCheck hands password checking back to the caller — for a schema
// whose passwords are bcrypt, argon2 or anything else this package has no
// business knowing about. It is given the database, the name and the password,
// and answers nil or an error.
//
// Without it, a password column is compared as it stands, which is what a
// schema holding cleartext (the only kind SMB can serve) means.
func WithPasswordCheck(verify func(db *sql.DB, name, password string) error) Option {
	return func(s *Source) { s.verify = verify }
}

// New reads people and groups from db.
func New(db *sql.DB, q Queries, opts ...Option) (*Source, error) {
	if db == nil {
		return nil, fmt.Errorf("sqldir: no database")
	}
	if strings.TrimSpace(q.People) == "" {
		return nil, fmt.Errorf("sqldir: no query for the people")
	}
	s := &Source{db: db, q: q, name: "a database"}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

func (s *Source) Describe() string { return s.name }

func (s *Source) Identities() ([]*directory.Identity, error) {
	rows, err := s.db.Query(s.q.People)
	if err != nil {
		return nil, fmt.Errorf("sqldir: reading the people: %w", err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if len(cols) == 0 {
		return nil, fmt.Errorf("sqldir: the people query returns no columns")
	}
	var out []*directory.Identity
	for rows.Next() {
		var name string
		var password, ntHash, keys sql.NullString
		fields := []any{&name, &password, &ntHash, &keys}
		if len(cols) > len(fields) {
			return nil, fmt.Errorf("sqldir: the people query returns %d columns; it may return up to %d: name, password, nt_hash, ssh_keys", len(cols), len(fields))
		}
		if err := rows.Scan(fields[:len(cols)]...); err != nil {
			return nil, fmt.Errorf("sqldir: reading a person: %w", err)
		}
		opts := []directory.Option{directory.From(s.name)}
		if password.Valid && password.String != "" {
			if s.verify == nil {
				opts = append(opts, directory.WithPassword(password.String))
			} else {
				// The column is a hash this package will not look at: the
				// caller compares it, and the password never becomes something
				// this process holds.
				name := name
				opts = append(opts, directory.WithVerifier(func(given string) error {
					return s.verify(s.db, name, given)
				}))
			}
		}
		if ntHash.Valid && ntHash.String != "" {
			raw, err := directory.ParseNTHash(ntHash.String)
			if err != nil {
				return nil, fmt.Errorf("sqldir: %s: %w", name, err)
			}
			opts = append(opts, directory.WithNTHash(raw))
		}
		if keys.Valid && strings.TrimSpace(keys.String) != "" {
			for _, line := range strings.Split(keys.String, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					opts = append(opts, directory.WithPublicKeys(line))
				}
			}
		}
		out = append(out, directory.NewIdentity(name, opts...))
	}
	return out, rows.Err()
}

func (s *Source) Members(group string) ([]string, error) {
	if strings.TrimSpace(s.q.Groups) == "" {
		// No groups query is not "the group is empty": it is a source that
		// cannot answer the question, and saying which is what lets another
		// source in the set answer it instead.
		return nil, fmt.Errorf("%w: this database has no groups query", directory.ErrNoSuchGroup)
	}
	rows, err := s.db.Query(s.q.Groups)
	if err != nil {
		return nil, fmt.Errorf("sqldir: reading the groups: %w", err)
	}
	defer rows.Close()
	var members []string
	var found bool
	for rows.Next() {
		var g, member string
		if err := rows.Scan(&g, &member); err != nil {
			return nil, fmt.Errorf("sqldir: reading a membership: %w", err)
		}
		if g == group {
			found = true
			members = append(members, member)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %q", directory.ErrNoSuchGroup, group)
	}
	return members, nil
}
