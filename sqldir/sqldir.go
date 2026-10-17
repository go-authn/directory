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
	"slices"
	"strings"

	"github.com/go-authn/directory"
)

// Queries are the statements this package runs. Only People is required.
//
// People must return, in this order: a name, and then any of a password, an NT
// hash, SSH keys, and a one-time-code secret. A column that is NULL is a
// credential that person does not have, which decides which protocols they can
// use — see [github.com/go-authn/directory.Identity.Can].
//
// Groups must return a group name and a member name, one row per membership.
//
// PeopleAttributes and GroupAttributes describe, and prove nothing (see
// [github.com/go-authn/directory.Attributes]). They are read by NAME rather
// than by position, because there is no fixed list of them:
//
//	select login, uid_number as uidNumber, shell as loginShell from staff
//	select team, gid as gidNumber from teams
//
// The first column is the person's or the group's name, whatever it is
// called. Every other column is an attribute, named by its alias: a column
// whose name is not an attribute description -- an unaliased expression,
// typically -- or that names a credential, is refused with the column it is.
// NULL, and the empty string, are an attribute that row does not have; the
// empty string because that is what the credential columns above have always
// meant by it. A name may come back on several rows, and the values of every
// row are kept: a join to a table of mail addresses gives a person several.
// Numbers come back as their decimal text: an LDAP value is a string.
//
// ⛔ The CASE of an alias is the database's. PostgreSQL folds an unquoted
// alias to lower case, so `as uidNumber` comes back as uidnumber; SQLite keeps
// it as written (MySQL is documented to, and was not tested here). An
// attribute name is case-insensitive in LDAP, so
// both are the same attribute, and Get("uidNumber") finds either -- but the
// spelling a server prints is the one the database returned. Quote the alias
// (`as "uidNumber"`) where the spelling matters.
//
// A name in PeopleAttributes that the People query did not return is not
// somebody: that row is ignored, so the attributes query may be broader than
// the people query. A group named in GroupAttributes EXISTS, with or without
// members, which is how a posixGroup nobody is listed in -- a person's own
// primary group -- is written.
type Queries struct {
	People string
	Groups string

	PeopleAttributes string
	GroupAttributes  string
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
	// Read first, and to the end: holding the people query open while a
	// second one runs needs a second connection, and a pool of one -- SQLite
	// is often opened that way -- would wait on itself.
	attrs, err := s.attributes(s.q.PeopleAttributes, "people's attributes")
	if err != nil {
		return nil, err
	}

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
		var password, ntHash, keys, totp sql.NullString
		fields := []any{&name, &password, &ntHash, &keys, &totp}
		if len(cols) > len(fields) {
			return nil, fmt.Errorf("sqldir: the people query returns %d columns; it may return up to %d: name, password, nt_hash, ssh_keys, totp_secret", len(cols), len(fields))
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
		if totp.Valid && strings.TrimSpace(totp.String) != "" {
			secret, err := directory.ParseTOTPSecret(totp.String)
			if err != nil {
				// Named, not quoted: the column holds a credential. A secret
				// that does not parse is refused rather than dropped, because
				// dropping it turns "this person has a second factor" into
				// "this person has none" without a word.
				return nil, fmt.Errorf("sqldir: %s: %w", name, err)
			}
			opts = append(opts, directory.WithTOTPSecret(secret))
		}
		if a, ok := attrs[name]; ok {
			opts = append(opts, directory.WithAttributes(a))
		}
		out = append(out, directory.NewIdentity(name, opts...))
	}
	return out, rows.Err()
}

// attributes runs one of the attributes queries: the first column a name, the
// others attributes named by their aliases. An empty query is no attributes.
func (s *Source) attributes(query, what string) (map[string]directory.Attributes, error) {
	if strings.TrimSpace(query) == "" {
		return nil, nil
	}
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("sqldir: reading the %s: %w", what, err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if len(cols) < 2 {
		return nil, fmt.Errorf("sqldir: the %s query returns %d column(s): it needs a name, then one column per attribute, named by its alias", what, len(cols))
	}
	// Checked before a single row is read: a column naming a credential is a
	// query that would publish it, and that is a configuration to refuse, not
	// a row to skip.
	for i, c := range cols[1:] {
		if err := directory.CheckAttributeName(c); err != nil {
			return nil, fmt.Errorf("sqldir: the %s query, column %d: %w", what, i+2, err)
		}
	}

	var order []string
	values := map[string][][]string{} // name -> one []string per attribute column
	cells := make([]sql.NullString, len(cols))
	dest := make([]any, len(cols))
	for i := range cells {
		dest[i] = &cells[i]
	}
	for rows.Next() {
		if err := rows.Scan(dest...); err != nil {
			return nil, fmt.Errorf("sqldir: reading the %s: %w", what, err)
		}
		if !cells[0].Valid || cells[0].String == "" {
			return nil, fmt.Errorf("sqldir: the %s query returned a row with no name in its first column", what)
		}
		name := cells[0].String
		per, ok := values[name]
		if !ok {
			per = make([][]string, len(cols)-1)
			order = append(order, name)
		}
		for i, c := range cells[1:] {
			if c.Valid && c.String != "" {
				per[i] = append(per[i], c.String)
			}
		}
		values[name] = per
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make(map[string]directory.Attributes, len(order))
	for _, name := range order {
		var list []directory.Attribute
		for i, v := range values[name] {
			if len(v) > 0 {
				list = append(list, directory.Attribute{Name: cols[i+1], Values: v})
			}
		}
		a, err := directory.NewAttributes(list...)
		if err != nil {
			return nil, fmt.Errorf("sqldir: %s: %w", name, err)
		}
		out[name] = a
	}
	return out, nil
}

// memberships runs the groups query: who is in which group, and the groups in
// the order they first appear.
func (s *Source) memberships() (map[string][]string, []string, error) {
	if strings.TrimSpace(s.q.Groups) == "" {
		return nil, nil, nil
	}
	rows, err := s.db.Query(s.q.Groups)
	if err != nil {
		return nil, nil, fmt.Errorf("sqldir: reading the groups: %w", err)
	}
	defer rows.Close()
	members := map[string][]string{}
	var order []string
	for rows.Next() {
		var g, member string
		if err := rows.Scan(&g, &member); err != nil {
			return nil, nil, fmt.Errorf("sqldir: reading a membership: %w", err)
		}
		if _, ok := members[g]; !ok {
			order = append(order, g)
		}
		members[g] = append(members[g], member)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return members, order, nil
}

// noGroups is whether this source was given no way to know any group.
func (s *Source) noGroups() bool {
	return strings.TrimSpace(s.q.Groups) == "" && strings.TrimSpace(s.q.GroupAttributes) == ""
}

// GroupNames is every group the groups query names, and every group the
// group-attributes query describes, sorted and without repeats.
func (s *Source) GroupNames() ([]string, error) {
	if s.noGroups() {
		// A source with no groups query cannot list groups. Reported as
		// nothing rather than as an error, because [directory.Set.GroupNames]
		// asks every source and a database that was never given a groups
		// query is not a broken one.
		return nil, nil
	}
	_, names, err := s.memberships()
	if err != nil {
		return nil, err
	}
	attrs, err := s.attributes(s.q.GroupAttributes, "groups' attributes")
	if err != nil {
		return nil, err
	}
	for g := range attrs {
		names = append(names, g)
	}
	slices.Sort(names)
	return slices.Compact(names), nil
}

func (s *Source) Members(group string) ([]string, error) {
	if s.noGroups() {
		// No groups query is not "the group is empty": it is a source that
		// cannot answer the question, and saying which is what lets another
		// source in the set answer it instead.
		return nil, fmt.Errorf("%w: this database has no groups query", directory.ErrNoSuchGroup)
	}
	members, _, err := s.memberships()
	if err != nil {
		return nil, err
	}
	if m, ok := members[group]; ok {
		return m, nil
	}
	attrs, err := s.attributes(s.q.GroupAttributes, "groups' attributes")
	if err != nil {
		return nil, err
	}
	if _, ok := attrs[group]; ok {
		// Described and nobody in it: a group, and an empty one.
		return []string{}, nil
	}
	return nil, fmt.Errorf("%w: %q", directory.ErrNoSuchGroup, group)
}

// GroupAttributes is what the group-attributes query says about one group:
// nothing, for a group only the groups query names, and ErrNoSuchGroup for a
// group neither names.
func (s *Source) GroupAttributes(group string) (directory.Attributes, error) {
	attrs, err := s.attributes(s.q.GroupAttributes, "groups' attributes")
	if err != nil {
		return directory.Attributes{}, err
	}
	if a, ok := attrs[group]; ok {
		return a, nil
	}
	if _, err := s.Members(group); err != nil {
		return directory.Attributes{}, err
	}
	return directory.Attributes{}, nil
}
