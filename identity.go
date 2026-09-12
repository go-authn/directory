// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"
)

// An Identity is one person, and what a source could give to prove them.
//
// The zero value is nobody. Build one with [NewIdentity] or take one from a
// [Source].
type Identity struct {
	name   string
	groups []string
	where  string

	password string
	ntHash   []byte
	verify   func(password string) error
	keys     []string
	totp     []byte
}

// A Credential is one way of proving somebody. They are named so that a server
// can SAY which it has and which a protocol needs, rather than discovering the
// mismatch when somebody fails to log in.
type Credential int

const (
	// Password is the password itself, which this process then holds. It
	// answers everything, and is the only thing that does.
	Password Credential = iota
	// NTHash is MD4(UTF16LE(password)) — Samba's sambaNTPassword. It answers
	// NTLMv2 and nothing else: it cannot be compared against a password a
	// client sent, because it IS the thing derived from it.
	NTHash
	// Verifier answers "is this the right password" without this process
	// knowing it: a hash comparison, or a bind against the directory that
	// holds it.
	Verifier
	// PublicKeys are SSH public keys, in authorized_keys spelling.
	PublicKeys
	// TOTPSecret is the shared secret behind the six digits on a phone (RFC
	// 6238). It is a SECOND factor and never a first: it proves the person
	// holds the thing it was enrolled into, and says nothing about who they
	// are. A server asking for two factors needs to know who has one — which
	// is the same question Can() answers for every other credential.
	TOTPSecret
)

var credentialNames = map[Credential]string{
	Password: "a password", NTHash: "an NT hash",
	Verifier: "a password check", PublicKeys: "public keys",
	TOTPSecret: "a one-time-code secret",
}

func (c Credential) String() string {
	if s, ok := credentialNames[c]; ok {
		return s
	}
	return "an unknown credential"
}

// NewIdentity names somebody. Credentials are added with the With… options,
// and a person with none can be named but proved by nothing — which is a
// legitimate state (a directory listing everybody, with the secrets somewhere
// else) and one [Identity.Can] reports honestly.
func NewIdentity(name string, opts ...Option) *Identity {
	id := &Identity{name: name}
	for _, o := range opts {
		o(id)
	}
	return id
}

// An Option adds something to an identity.
type Option func(*Identity)

// WithPassword gives the password itself, which answers every protocol.
func WithPassword(password string) Option {
	return func(i *Identity) { i.password = password }
}

// WithNTHash gives MD4(UTF16LE(password)) — 16 bytes, as a directory publishes
// it. Anybody holding this can authenticate as that person exactly as if they
// held the password: it is not a password hash in the sense a login form
// means, and storing it does not make a leak less bad.
func WithNTHash(hash []byte) Option {
	return func(i *Identity) { i.ntHash = append([]byte(nil), hash...) }
}

// WithVerifier gives a way to check a password without holding it: a hash
// comparison, or a bind. The error it returns is reported to the SERVER, never
// to the client — a client is told only that authentication failed, which is
// the right amount to tell somebody who has not proved who they are.
func WithVerifier(verify func(password string) error) Option {
	return func(i *Identity) { i.verify = verify }
}

// WithPublicKeys gives SSH public keys, each in authorized_keys spelling.
func WithPublicKeys(keys ...string) Option {
	return func(i *Identity) { i.keys = append(i.keys, keys...) }
}

// WithTOTPSecret gives the shared secret behind a one-time code (RFC 6238), as
// the raw bytes — github.com/go-authn/totp's ParseSecret reads the base32
// spelling a directory usually stores.
//
// ⛔ It is the credential, not a hash of one: anybody holding it produces every
// future code, and it does not expire. A source that publishes it has
// published the second factor, exactly as with an NT hash.
func WithTOTPSecret(secret []byte) Option {
	return func(i *Identity) { i.totp = append([]byte(nil), secret...) }
}

// WithGroups says which groups this person is in, when the source knows
// without being asked.
func WithGroups(groups ...string) Option {
	return func(i *Identity) { i.groups = append(i.groups, groups...) }
}

// From records where this identity came from, for a server to print.
func From(where string) Option {
	return func(i *Identity) { i.where = where }
}

// Name is who they are.
func (i *Identity) Name() string { return i.name }

// Where is the source that knew them.
func (i *Identity) Where() string { return i.where }

// Groups are the groups this source said they are in.
func (i *Identity) Groups() []string { return slices.Clone(i.groups) }

// Keys are their SSH public keys, in authorized_keys spelling.
func (i *Identity) Keys() []string { return slices.Clone(i.keys) }

// TOTPSecret is the shared secret behind this person's one-time codes, or nil.
//
// ⛔ Like [Identity.NTKey], this hands out a credential: whoever holds it
// produces every future code. It is here because a server that must CHECK a
// code has to have it, and a copy is returned so that the caller cannot change
// what a directory said.
func (i *Identity) TOTPSecret() []byte { return slices.Clone(i.totp) }

// Can reports whether this identity carries a given credential — which is what
// lets a server say "you can use WebDAV and not SMB" before somebody finds out
// the hard way.
func (i *Identity) Can(c Credential) bool {
	switch c {
	case Password:
		return i.password != ""
	case NTHash:
		return len(i.ntHash) == 16 || i.password != ""
	case Verifier:
		return i.verify != nil || i.password != ""
	case PublicKeys:
		return len(i.keys) > 0
	case TOTPSecret:
		return len(i.totp) > 0
	}
	return false
}

// ErrNoCredential says this identity cannot answer that question at all, which
// is a different thing from answering it wrongly: one is a configuration to
// fix, the other is somebody typing the wrong password.
var ErrNoCredential = errors.New("directory: this identity has no such credential")

// ErrWrongPassword is what a failed check returns.
var ErrWrongPassword = errors.New("directory: wrong password")

// Verify answers "is this the right password".
//
// It prefers the verifier a source gave — that is the one that may reach an
// LDAP server, and the one that exists precisely so this process need not hold
// the secret. Falling back to a held password is a constant-time comparison:
// the difference between "wrong at byte 1" and "wrong at byte 12" is
// measurable over a network.
func (i *Identity) Verify(password string) error {
	switch {
	case i.verify != nil:
		return i.verify(password)
	case i.password != "":
		if subtle.ConstantTimeCompare([]byte(password), []byte(i.password)) == 1 {
			return nil
		}
		return ErrWrongPassword
	}
	return ErrNoCredential
}

// NTKey is the key NTLMv2 is computed with: MD4(UTF16LE(password)).
//
// It comes from the hash when the source published one, and is derived from
// the password when the source gave that instead. A source with neither cannot
// serve SMB, and this says so rather than returning something that will fail
// every login with "wrong password".
func (i *Identity) NTKey() ([]byte, error) {
	if len(i.ntHash) == 16 {
		return slices.Clone(i.ntHash), nil
	}
	if i.password == "" {
		return nil, ErrNoCredential
	}
	return NTHashOf(i.password), nil
}

// NTHashOf is MD4(UTF16LE(password)), the value Samba stores as
// sambaNTPassword and Windows calls the NT hash.
//
// MD4 is broken as a hash function and is used here anyway, because NTLMv2 is
// DEFINED over it: this is not a choice about security, it is the arithmetic
// the protocol specifies, and a server that used anything else would refuse
// every correct password.
func NTHashOf(password string) []byte { return md4sum(utf16le(password)) }

// ParseNTHash reads the hex a directory publishes.
//
// A hash that is not 16 bytes is refused rather than padded or truncated: a
// mangled one would fail every login with "wrong password", which is the least
// useful thing a server could say.
func ParseNTHash(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("directory: an NT hash is hex: %w", err)
	}
	if len(raw) != 16 {
		return nil, fmt.Errorf("directory: an NT hash is 16 bytes, not %d", len(raw))
	}
	return raw, nil
}

// ParseTOTPSecret reads the base32 a directory stores a one-time-code secret
// as: upper or lower case, spaces and padding optional, which is how people
// copy them out of an authenticator.
//
// github.com/go-authn/totp reads the same shape and neither package imports
// the other: this one is about who somebody IS, that one is about one way of
// checking, and a dependency either way would make every consumer of one
// carry the other. Eight lines of encoding/base32 is the cheaper of the two
// prices, and it is written down here so that the next reader knows it was a
// choice.
func ParseTOTPSecret(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(s)))
	if pad := len(clean) % 8; pad != 0 {
		clean += strings.Repeat("=", 8-pad)
	}
	raw, err := base32.StdEncoding.DecodeString(clean)
	if err != nil {
		// Not quoting it: it is the credential.
		return nil, fmt.Errorf("directory: a one-time-code secret is base32")
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("directory: an empty one-time-code secret")
	}
	return raw, nil
}

// utf16le encodes the way NTLM does, without a byte-order mark.
func utf16le(s string) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(units)*2)
	for _, u := range units {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

// KerberosKey derives this identity's Kerberos long-term key.
//
// The derivation is the CALLER's, and that is the whole design. A Kerberos key
// is string2key(password, salt, enctype) — arithmetic this package has no
// business carrying, since it would drag a Kerberos library into everything
// that merely wants to list users. Passing the function in means the password
// never leaves here and the enctype table stays where enctypes are understood.
//
// It answers only for an identity that carries the PASSWORD. A Verifier — a
// bind against somebody else's directory, or a hash comparison — cannot serve
// Kerberos at all: a KDC has to DECRYPT the client's pre-authentication with
// this key, and "is this the right password" does not produce one. That is a
// property of Kerberos, not a limitation here, and a server should say so at
// configuration time rather than at the first kinit.
func (i *Identity) KerberosKey(derive func(password string) ([]byte, error)) ([]byte, error) {
	if i.password == "" {
		return nil, ErrNoCredential
	}
	if derive == nil {
		return nil, errors.New("directory: KerberosKey needs a derivation function")
	}
	return derive(i.password)
}
