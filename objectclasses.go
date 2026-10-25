// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ObjectClasses are the auxiliary object classes a configuration DECLARES that
// a source's people, or its groups, carry: ["supannPerson", "eduPerson"].
//
// ⛔ They are declared, never inferred and never read. Not from the attributes
// a person happens to have -- a column added to a database, or a value filled
// in for one person, must not change what a server publishes everybody as --
// and not from the data either: there is no column and no upstream objectClass
// value that sets one. A class is a promise about the shape of every entry
// (RFC 4512 §4.1.1: it lists the attributes an entry MUST and MAY hold), and a
// promise belongs to whoever writes the configuration, next to the queries
// that produce those attributes.
//
// This package checks the SPELLING only: each name is an RFC 4512 descr (see
// [CheckObjectClassName]). Whether a class exists, is AUXILIARY, and is not
// one a server derives itself is a question about a schema, and the server
// that publishes the entries holds the schema: go-authn/authnd checks it.
//
// The order is the order declared, and a name given twice -- in any case -- is
// kept once, spelled the first way it was written: RFC 4512 §2.5 makes the
// names case-insensitive. An ObjectClasses is immutable once built. The zero
// value declares nothing.
type ObjectClasses struct {
	list []string
}

// ErrObjectClassName is a name that cannot be an object class here: not an
// RFC 4512 descr. The message says why.
var ErrObjectClassName = errors.New("directory: not an object class name")

// NewObjectClasses checks these names and puts them together, in order and
// without repeats. The first name refused is the error.
func NewObjectClasses(names ...string) (ObjectClasses, error) {
	var c ObjectClasses
	for _, n := range names {
		if err := CheckObjectClassName(n); err != nil {
			return ObjectClasses{}, err
		}
		c.add(n)
	}
	return c, nil
}

// add appends a checked name, unless it is there already in any case.
func (c *ObjectClasses) add(name string) {
	if !slices.ContainsFunc(c.list, func(have string) bool { return strings.EqualFold(have, name) }) {
		c.list = append(c.list, name)
	}
}

// Len is how many classes are declared.
func (c ObjectClasses) Len() int { return len(c.list) }

// Names are the classes, in the order declared, each spelled the first way it
// was given. The slice is a copy.
func (c ObjectClasses) Names() []string { return slices.Clone(c.list) }

// CheckObjectClassName says whether name can be declared as an object class:
// nil, or an error wrapping [ErrObjectClassName] that says why not.
//
// A name is a descr, RFC 4512 §1.4:
//
//	descr       = keystring
//	keystring   = leadkeychar *keychar
//	leadkeychar = ALPHA
//	keychar     = ALPHA / DIGIT / HYPHEN
//
// The numeric form an oid may also take (§1.4, numericoid, 1.3.6.1.4.1...) is
// refused, for the reason [CheckAttributeName] gives: the server's checks on a
// class -- not one it derives, not a STRUCTURAL one -- are by NAME, and a list
// of names cannot recognise an OID.
//
// ⛔ The names reach an LDAP server's output -- the objectClass values of every
// entry, and the filters a client builds from them. Nothing but letters, digits
// and hyphens gets through: no space, no quote, no parenthesis, no NUL, which
// is what would let a configuration write into the schema syntax around it.
func CheckObjectClassName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: an object class needs a name", ErrObjectClassName)
	case isDigit(name[0]):
		return fmt.Errorf("%w: %q is an OID: name the class by its descriptor, so that what is refused by name stays refused", ErrObjectClassName, name)
	case !isKeystring(name):
		return fmt.Errorf("%w: %q is not a descriptor: a letter, then letters, digits and hyphens (RFC 4512 §1.4)", ErrObjectClassName, name)
	}
	return nil
}
