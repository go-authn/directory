// SPDX-License-Identifier: BSD-3-Clause

package hcldir

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-authn/secretsource"
)

// secretTimeout bounds the resolution of one reference: a manager that waits
// for somebody to unlock it must not hold a server's startup forever.
const secretTimeout = 30 * time.Second

// resolveSecret is how every secret of this package gets in: a
// go-authn/secretsource reference ("systemd-creds:NAME", "file:PATH",
// "keychain:SERVICE/ACCOUNT", ...), which never holds the secret, so the
// configuration can be read, copied and put under version control without it.
//
// The three spellings of one secret are exclusive:
//
//	field_from   a reference, the way to write it
//	field_file   the deprecated spelling of field_from = "file:PATH"
//	field        the secret itself, written in the configuration (deprecated)
//
// Two of them is refused, naming the field: which one wins is a question a
// reader of the configuration could not answer. field_file is a path, and
// secretsource's `file:` is stricter than os.ReadFile was -- a regular file
// of the current user, never a symlink, 4096 bytes at most -- so a file that
// was readable before may now be refused, with the reason.
//
// The secret is one line: a single trailing newline (what echo adds) is not
// part of it, and a NUL or any other line break is refused. A DSN, a password,
// a base32 secret and a 32-character hash are all that, and none is binary or
// near 4096 bytes; a field that could be would keep its own file field.
func resolveSecret(who, field, inline, file, from string) (string, error) {
	if n := count(inline, file, from); n > 1 {
		return "", fmt.Errorf("%s: give only one of %s, %s_file and %s_from (%s_file is the deprecated spelling of %s_from = \"file:PATH\")",
			who, field, field, field, field, field)
	}
	ref := from
	if file != "" {
		ref = "file:" + file
	}
	if ref == "" {
		return inline, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), secretTimeout)
	defer cancel()
	s, err := secretsource.Open(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("%s: %s_from: %w", who, field, err)
	}
	defer s.Close()
	v := strings.TrimSuffix(strings.TrimSuffix(string(s.Bytes()), "\n"), "\r")
	if v == "" || strings.ContainsAny(v, "\x00\r\n") {
		return "", fmt.Errorf("%s: %s_from: %w", who, field, errors.New("one non-empty line without NUL"))
	}
	return v, nil
}

// resolveFrom is the field with no inline spelling: the DSN and the bind
// password were never written in the configuration, only named by a path.
func resolveFrom(who, field, file, from string) (string, error) {
	return resolveSecret(who, field, "", file, from)
}

// count is how many of these were written.
func count(v ...string) int {
	n := 0
	for _, s := range v {
		if s != "" {
			n++
		}
	}
	return n
}

// Deprecations lists, one sentence each, the spellings this person's block
// uses that a secret reference replaces, for a caller to log at startup. The
// package has no logger of its own, and a caller that prints them says where
// they came from. The sentences hold names and paths, never a secret.
func (u UserBlock) Deprecations() []string {
	return deprecations("user "+u.Name, []deprecated{
		{"password", u.Password, u.PasswordFile},
		{"nt_hash", u.NTHash, ""},
		{"totp_secret", u.TOTPSecret, ""},
	})
}

// Deprecations is [UserBlock.Deprecations] for a `users` block.
func (b Block) Deprecations() []string {
	return deprecations(fmt.Sprintf("users %q", b.Kind), []deprecated{
		{"dsn", "", b.DSNFile},
		{"bind_password", "", b.BindPasswordFile},
	})
}

type deprecated struct{ field, inline, file string }

func deprecations(who string, fields []deprecated) []string {
	var out []string
	for _, f := range fields {
		if f.inline != "" {
			out = append(out, fmt.Sprintf("%s: %s is a secret written in the configuration (deprecated): use %s_from = \"systemd-creds:NAME\" or \"file:PATH\"", who, f.field, f.field))
		}
		if f.file != "" {
			out = append(out, fmt.Sprintf("%s: %s_file is deprecated: use %s_from = \"file:%s\"", who, f.field, f.field, f.file))
		}
	}
	return out
}
