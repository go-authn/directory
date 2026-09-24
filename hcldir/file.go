// SPDX-License-Identifier: BSD-3-Clause

package hcldir

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-authn/directory"
	"golang.org/x/crypto/ssh"
)

// A UserBlock is somebody written down in the configuration file itself,
// rather than in a database or an LDAP server:
//
//	user "alice" {
//	  password_file        = "/etc/authnd/alice.pw"
//	  nt_hash              = "8846f7eaee8fb117ad06bdd830b7586c"
//	  totp_secret          = "JBSWY3DPEHPK3PXP"
//	  authorized_keys_file = "/etc/authnd/alice.keys"
//	}
//
// ⛔ This block, and Group below, lived TWICE: once in go-authn/authnd and
// once in go-fileshare/fileshare, each with its own spelling. They had already
// drifted -- authnd's carried nt_hash and totp_secret and fileshare's did not,
// so a person written inline in a fileshare configuration could never be
// served over SMB, because NTLMv2 works from the password or its MD4 and
// nothing else. The same argument that put the `users` block here applies to
// this one, and it is the argument this package was created for.
type UserBlock struct {
	Name string `hcl:"name,label"`

	// Password is the secret itself; PasswordFile reads it from a file, which
	// is how a deployment keeps it out of the configuration and out of a
	// backup of it. Give one or neither, never both.
	Password     string `hcl:"password,optional"`
	PasswordFile string `hcl:"password_file,optional"`

	// NTHash is MD4(UTF16LE(password)), in the 32 hex characters a directory
	// publishes it as -- for a site that holds THAT and not the password.
	NTHash string `hcl:"nt_hash,optional"`

	// TOTPSecret is the base32 secret behind this person's one-time codes.
	// ⛔ It IS the second factor: whoever holds it produces every future code.
	TOTPSecret string `hcl:"totp_secret,optional"`

	// AuthorizedKeys are this person's SSH public keys, written the way an
	// authorized_keys file writes them, either inline or in a file.
	AuthorizedKeys     []string `hcl:"authorized_keys,optional"`
	AuthorizedKeysFile string   `hcl:"authorized_keys_file,optional"`
}

// A GroupBlock names people, and is published as a posixGroup.
type GroupBlock struct {
	Name    string   `hcl:"name,label"`
	Members []string `hcl:"members"`
}

// File is the third source, beside a database and an LDAP server: the people
// written in the configuration file. Describe() answers "the configuration
// file", which is the example the Source interface itself gives.
//
// Both a password and a password_file is refused rather than resolved. Two
// spellings of one secret is a question about which one wins, and a
// configuration that answers it silently is one a reader cannot check.
func File(users []UserBlock, groups []GroupBlock) (directory.Source, error) {
	const where = "the configuration file"
	src := &directory.Static{Name: where, Groups: map[string][]string{}}
	for _, g := range groups {
		src.Groups[g.Name] = g.Members
	}
	seen := map[string]bool{}
	for _, u := range users {
		if u.Name == "" {
			return nil, fmt.Errorf("hcldir: a user block has no name")
		}
		if seen[u.Name] {
			return nil, fmt.Errorf("hcldir: user %q is declared twice", u.Name)
		}
		seen[u.Name] = true

		opts := []directory.Option{directory.From(where)}
		pw, err := userSecret(u)
		if err != nil {
			return nil, err
		}
		if pw != "" {
			opts = append(opts, directory.WithPassword(pw))
		}
		if u.NTHash != "" {
			h, err := directory.ParseNTHash(u.NTHash)
			if err != nil {
				return nil, fmt.Errorf("user %q: %w", u.Name, err)
			}
			opts = append(opts, directory.WithNTHash(h))
		}
		if u.TOTPSecret != "" {
			s, err := directory.ParseTOTPSecret(u.TOTPSecret)
			if err != nil {
				return nil, fmt.Errorf("user %q: %w", u.Name, err)
			}
			opts = append(opts, directory.WithTOTPSecret(s))
		}
		keys, err := AuthorizedKeys(u)
		if err != nil {
			return nil, err
		}
		if len(keys) > 0 {
			opts = append(opts, directory.WithPublicKeys(keys...))
		}
		src.People = append(src.People, directory.NewIdentity(u.Name, opts...))
	}
	return src, nil
}

// userSecret reads the password from the block or from its file, refusing
// both.
func userSecret(u UserBlock) (string, error) {
	switch {
	case u.Password != "" && u.PasswordFile != "":
		return "", fmt.Errorf("user %q: give password or password_file, not both", u.Name)
	case u.PasswordFile != "":
		return secretFile(u.PasswordFile, "user "+u.Name)
	default:
		return u.Password, nil
	}
}

// AuthorizedKeys is this person's keys, from the block or from the file it
// names, each one PARSED rather than copied: a line that is not an
// authorized_keys line is a configuration error, and finding it at startup
// beats finding it when somebody cannot log in.
func AuthorizedKeys(u UserBlock) ([]string, error) {
	text := strings.Join(u.AuthorizedKeys, "\n")
	if u.AuthorizedKeysFile != "" {
		b, err := os.ReadFile(u.AuthorizedKeysFile)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Name, err)
		}
		text = string(b)
	}
	if strings.TrimSpace(text) == "" {
		return nil, nil
	}
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line)); err != nil {
			return nil, fmt.Errorf("user %q: %q is not an authorized_keys line: %w", u.Name, line, err)
		}
		lines = append(lines, line)
	}
	return lines, nil
}
