// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"errors"
	"fmt"
	"sync"

	"github.com/go-authn/ldap/schema"
)

// ErrBadName is what a [Set] returns for a name that has no equivalence key:
// the LDAP equality rule of uid (caseIgnoreMatch, RFC 4519 section 2.39) cannot
// prepare it, as with bytes that are not UTF-8 or a name of nothing but
// insignificant spaces.
//
// Such a name is REFUSED, never compared byte for byte: a name that cannot be
// placed in an equivalence class could be the same person as another one, and
// treating it as a stranger would hand it a second identity.
var ErrBadName = errors.New("directory: the name has no equivalence key")

var uidKey = sync.OnceValues(func() (*schema.Schema, *schema.AttributeType) {
	std := schema.Standard()
	return std, std.AttributeType("uid")
})

// nameKey is the one equivalence relation on names a [Set] uses: two names are
// the same person exactly when their keys are equal. It is the key of the LDAP
// equality rule of uid, caseIgnoreMatch (RFC 4518 preparation: case folding,
// compatibility folding, space compression, characters mapped to nothing), the
// rule go-authn/ldapdir applies inside one directory.
func nameKey(name string) (string, error) {
	std, uid := uidKey()
	key, ok := std.EqualityKey(uid, []byte(name))
	if blank, _ := std.EqualityKey(uid, nil); ok && key == blank {
		ok = false // RFC 4518 gives "" and "   " the same key: nobody is named that
	}
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrBadName, name)
	}
	return key, nil
}

// A Shadow is a person a later source knows under a spelling that the
// [Set] resolved to an earlier source's person: "Alice" in the second source
// and "alice" in the first are one class, the first source owns it, and the
// second's entry is not in [Set.Identities].
type Shadow struct {
	Name   string // the spelling that was shadowed, as its source wrote it
	Source string // Describe of the source that wrote it
	Owner  string // the spelling that owns the class, as its source wrote it
	By     string // Describe of the source that owns it
}

// Shadowed lists the case-variants (or other spellings of one equivalence
// class) that the last successful [Set.Identities] left out because an earlier
// source owns the person. A name spelled the same way by two sources is the
// documented override and is not listed: only a DIFFERENT spelling is a
// surprise worth a line in a server's log.
//
// It is empty until Identities has run, and is replaced by every call.
func (s *Set) Shadowed() []Shadow {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Shadow(nil), s.shadowed...)
}
