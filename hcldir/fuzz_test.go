// SPDX-License-Identifier: BSD-3-Clause

package hcldir_test

import (
	"testing"

	"github.com/go-authn/directory/hcldir"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// FuzzDecode is the entry point of this package for untrusted input: a
// configuration file, decoded the way authnd and fileshare decode it, then
// checked and built. It must never panic, whatever the file says.
//
// ⛔ A reference is NOT resolved here: `file:` would read whatever path the
// input names, and the fuzzer would then be reading the host. The fields that
// name a secret are cleared before File runs; Check, Deprecations and the
// decoding see them as written.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		`users "sql" { driver = "sqlite"` + "\n" + `dsn_from = "systemd-creds:dsn"` + "\n" + `users = "select 1" }`,
		`users "sql" { driver = "sqlite"` + "\n" + `dsn_file = "/d"` + "\n" + `dsn_from = "file:/d"` + "\n" + `users = "select 1" }`,
		`users "ldap" { url = "ldaps://x"` + "\n" + `base_dn = "dc=x"` + "\n" + `bind_dn = "cn=r"` + "\n" + `bind_password_from = "file:/p" }`,
		`users "ldap" { url = "ldap://x"` + "\n" + `bind_password_file = "/p"` + "\n" + `bind_password_from = "keychain:a/b" }`,
		`user "alice" { password_from = "systemd-creds:a"` + "\n" + `nt_hash_from = "file:/h"` + "\n" + `totp_secret_from = "file:/t" }`,
		`user "bob" { password = "x"` + "\n" + `password_file = "/p"` + "\n" + `nt_hash = "8846f7eaee8fb117ad06bdd830b7586c"` + "\n" + `totp_secret = "JBSWY3DPEHPK3PXP" }`,
		`user "carol" { attributes = { mail = ["a@x"], uidNumber = "1" }` + "\n" + `object_classes = ["eduPerson"]` + "\n" + `authorized_keys = ["not a key"] }`,
		`group "staff" { members = ["alice"]` + "\n" + `attributes = { gidNumber = "100" } }`,
		`user "x" { password_from = "` + "\x00" + `" }`,
		``,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		file, diags := hclsyntax.ParseConfig(src, "fuzz.hcl", hcl.InitialPos)
		if diags.HasErrors() {
			return
		}
		var cfg struct {
			Users  []hcldir.UserBlock  `hcl:"user,block"`
			Dirs   []hcldir.Block      `hcl:"users,block"`
			Groups []hcldir.GroupBlock `hcl:"group,block"`
		}
		if gohcl.DecodeBody(file.Body, nil, &cfg).HasErrors() {
			return
		}
		for _, b := range cfg.Dirs {
			_ = b.Check()
			_ = b.Deprecations()
		}
		for i := range cfg.Users {
			u := &cfg.Users[i]
			_ = u.Deprecations()
			u.PasswordFrom, u.PasswordFile, u.NTHashFrom, u.TOTPSecretFrom = "", "", "", ""
			u.AuthorizedKeysFile = ""
		}
		_, _ = hcldir.File(cfg.Users, cfg.Groups)
	})
}
