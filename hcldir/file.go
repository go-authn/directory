// SPDX-License-Identifier: BSD-3-Clause

package hcldir

import (
	"fmt"
	"os"
	"strings"

	"github.com/go-authn/directory"
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/crypto/ssh"
)

// A UserBlock is somebody written down in the configuration file itself,
// rather than in a database or an LDAP server:
//
//	user "alice" {
//	  password_from        = "systemd-creds:alice-pw"
//	  totp_secret_from     = "systemd-creds:alice-totp"
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

	// PasswordFrom is a go-authn/secretsource reference to the password
	// ("systemd-creds:alice", "file:/etc/authnd/alice.pw", ...): the way to
	// write it, so the configuration holds no secret.
	//
	// PasswordFile is the DEPRECATED spelling of password_from = "file:PATH",
	// and Password, the secret itself written in the configuration, is
	// deprecated too: see [UserBlock.Deprecations]. Give one of the three,
	// never two: the error names the field.
	PasswordFrom string `hcl:"password_from,optional"`
	Password     string `hcl:"password,optional"`
	PasswordFile string `hcl:"password_file,optional"`

	// NTHash is MD4(UTF16LE(password)), in the 32 hex characters a directory
	// publishes it as -- for a site that holds THAT and not the password.
	// NTHashFrom is a reference to it, and the inline spelling is deprecated;
	// give one. It moves an existing field out of the configuration, and
	// nothing else.
	NTHashFrom string `hcl:"nt_hash_from,optional"`
	NTHash     string `hcl:"nt_hash,optional"`

	// TOTPSecret is the base32 secret behind this person's one-time codes.
	// ⛔ It IS the second factor: whoever holds it produces every future code.
	// TOTPSecretFrom is a reference to it, and the inline spelling is
	// deprecated; give one.
	TOTPSecretFrom string `hcl:"totp_secret_from,optional"`
	TOTPSecret     string `hcl:"totp_secret,optional"`

	// AuthorizedKeys are this person's SSH public keys, written the way an
	// authorized_keys file writes them, either inline or in a file.
	AuthorizedKeys     []string `hcl:"authorized_keys,optional"`
	AuthorizedKeysFile string   `hcl:"authorized_keys_file,optional"`

	// Attributes describe this person and prove nothing:
	//
	//	attributes = { uidNumber = "1000", mail = ["alice@example.org"] }
	//
	// A cty.Value, which is what gohcl hands over for a map whose values
	// are a string or a list of strings; build one by hand with cty.ObjectVal.
	// A name holding a credential is refused (see
	// [directory.CheckAttributeName]): the password, the NT hash, the keys and
	// the one-time-code secret have their fields above.
	Attributes cty.Value `hcl:"attributes,optional"`

	// ObjectClasses DECLARE the auxiliary object classes this person is
	// published with -- object_classes = ["eduPerson"] -- and are never
	// inferred from the attributes above: see [directory.ObjectClasses]. A
	// name that is not an RFC 4512 descriptor is refused, at the position
	// ObjectClassesRange records (gohcl fills it in).
	ObjectClasses      []string  `hcl:"object_classes,optional"`
	ObjectClassesRange hcl.Range `hcl:"object_classes,attr_value_range"`
}

// A GroupBlock names people, and is published as a posixGroup.
//
// A posixGroup needs a gidNumber (RFC 2307), which is an attribute:
//
//	group "staff" {
//	  members    = ["alice", "bob"]
//	  attributes = { gidNumber = "100", description = "the people who work here" }
//	}
//
// This package does not insist on it -- it does not know what the group will
// be published as -- and a server that publishes posixGroups does.
//
// Its object_classes declare what else the group is published as, by the
// rules of [UserBlock.ObjectClasses].
type GroupBlock struct {
	Name       string    `hcl:"name,label"`
	Members    []string  `hcl:"members"`
	Attributes cty.Value `hcl:"attributes,optional"`

	ObjectClasses      []string  `hcl:"object_classes,optional"`
	ObjectClassesRange hcl.Range `hcl:"object_classes,attr_value_range"`
}

// File is the third source, beside a database and an LDAP server: the people
// written in the configuration file. Describe() answers "the configuration
// file", which is the example the Source interface itself gives.
//
// Two spellings of one secret -- a password and a password_file, a totp_secret
// and a totp_secret_from -- are refused rather than resolved. Two spellings of
// one secret is a question about which one wins, and a configuration that
// answers it silently is one a reader cannot check.
func File(users []UserBlock, groups []GroupBlock) (directory.Source, error) {
	const where = "the configuration file"
	src := &directory.Static{Name: where, Groups: map[string][]string{},
		GroupAttrs: map[string]directory.Attributes{}, GroupClasses: map[string]directory.ObjectClasses{}}
	for _, g := range groups {
		src.Groups[g.Name] = g.Members
		a, err := attributesOf(g.Attributes)
		if err != nil {
			return nil, fmt.Errorf("group %q: %w", g.Name, err)
		}
		src.GroupAttrs[g.Name] = a
		c, err := checkClasses(g.ObjectClassesRange, fmt.Sprintf("group %q", g.Name), "object_classes", g.ObjectClasses)
		if err != nil {
			return nil, err
		}
		src.GroupClasses[g.Name] = c
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
		who := fmt.Sprintf("user %q", u.Name)
		pw, err := resolveSecret(who, "password", u.Password, u.PasswordFile, u.PasswordFrom)
		if err != nil {
			return nil, err
		}
		if pw != "" {
			opts = append(opts, directory.WithPassword(pw))
		}
		nt, err := resolveSecret(who, "nt_hash", u.NTHash, "", u.NTHashFrom)
		if err != nil {
			return nil, err
		}
		if nt != "" {
			h, err := directory.ParseNTHash(nt)
			if err != nil {
				return nil, fmt.Errorf("user %q: %w", u.Name, err)
			}
			opts = append(opts, directory.WithNTHash(h))
		}
		totp, err := resolveSecret(who, "totp_secret", u.TOTPSecret, "", u.TOTPSecretFrom)
		if err != nil {
			return nil, err
		}
		if totp != "" {
			s, err := directory.ParseTOTPSecret(totp)
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
		attrs, err := attributesOf(u.Attributes)
		if err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Name, err)
		}
		classes, err := checkClasses(u.ObjectClassesRange, fmt.Sprintf("user %q", u.Name), "object_classes", u.ObjectClasses)
		if err != nil {
			return nil, err
		}
		opts = append(opts, directory.WithAttributes(attrs), directory.WithObjectClasses(classes))
		src.People = append(src.People, directory.NewIdentity(u.Name, opts...))
	}
	return src, nil
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

// attributesOf reads an `attributes = { ... }` map: each value a string, or a
// list of strings for an attribute with several.
//
//	attributes = {
//	  uidNumber     = "1000"
//	  homeDirectory = "/home/alice"
//	  mail          = ["alice@example.org", "a.liddell@example.org"]
//	}
//
// A number is refused rather than converted: LDAP values are strings, and
// this package does not decide how 1e3 or 0100 is spelled. Quoting it says
// which string was meant. An attribute set to null is left out, as a block
// leaves out any optional field. The attributes come in the order HCL gives
// an object's keys, which is sorted; LDAP gives the order of an entry's
// attributes no meaning.
func attributesOf(v cty.Value) (directory.Attributes, error) {
	if v == cty.NilVal || v.IsNull() {
		return directory.Attributes{}, nil
	}
	if !v.IsWhollyKnown() {
		return directory.Attributes{}, fmt.Errorf("attributes: a value is not known until something else is evaluated")
	}
	if t := v.Type(); !t.IsObjectType() && !t.IsMapType() {
		return directory.Attributes{}, fmt.Errorf(`attributes is a map of names to values, such as { mail = "alice@example.org" }, not %s`, t.FriendlyName())
	}
	var list []directory.Attribute
	for it := v.ElementIterator(); it.Next(); {
		k, val := it.Element()
		name := k.AsString()
		if val.IsNull() {
			continue
		}
		var values []string
		switch t := val.Type(); {
		case t == cty.String:
			values = []string{val.AsString()}
		case t.IsTupleType() || t.IsListType() || t.IsSetType():
			for vi := val.ElementIterator(); vi.Next(); {
				_, e := vi.Element()
				s, err := attributeString(name, e)
				if err != nil {
					return directory.Attributes{}, err
				}
				values = append(values, s)
			}
		default:
			if _, err := attributeString(name, val); err != nil {
				return directory.Attributes{}, err
			}
		}
		list = append(list, directory.Attribute{Name: name, Values: values})
	}
	a, err := directory.NewAttributes(list...)
	if err != nil {
		return directory.Attributes{}, fmt.Errorf("attributes: %w", err)
	}
	return a, nil
}

// attributeString is one value, which must be a string.
func attributeString(name string, v cty.Value) (string, error) {
	switch {
	case v.IsNull():
		return "", fmt.Errorf("attributes: %s has a null among its values", name)
	case v.Type() == cty.String:
		return v.AsString(), nil
	case v.Type() == cty.Number:
		return "", fmt.Errorf(`attributes: %s is the number %s: write it as a string, "%[2]s" -- an LDAP value is a string, and this does not choose how a number is spelled`,
			name, v.AsBigFloat().Text('f', -1))
	}
	return "", fmt.Errorf("attributes: %s is %s: an attribute's value is a string, or a list of strings", name, v.Type().FriendlyName())
}
