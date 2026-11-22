// SPDX-License-Identifier: BSD-3-Clause

package hcldir_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
	"github.com/go-authn/secretsource"
	_ "modernc.org/sqlite"
)

// secret writes a secret readable by its owner alone, the shape secretsource's
// file: reference requires, and returns the reference to it.
func secret(t *testing.T, name string, content []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatal(err)
	}
	ownerOnly(t, p)
	return p
}

const (
	hash32 = "8846f7eaee8fb117ad06bdd830b7586c"
	totp32 = "JBSWY3DPEHPK3PXP"
)

// A reference resolves, for every secret a user block carries.
func TestUserSecretReferencesResolve(t *testing.T) {
	src, err := hcldir.File([]hcldir.UserBlock{{
		Name:           "alice",
		PasswordFrom:   "file:" + secret(t, "pw", []byte("s3cret\n")),
		NTHashFrom:     "file:" + secret(t, "nt", []byte(hash32+"\n")),
		TOTPSecretFrom: "file:" + secret(t, "totp", []byte(totp32)),
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	people, err := src.Identities()
	if err != nil || len(people) != 1 {
		t.Fatalf("%v, %v", people, err)
	}
	for _, kind := range []directory.Credential{directory.Password, directory.NTHash, directory.TOTPSecret} {
		if !people[0].Can(kind) {
			t.Errorf("alice cannot %v: the reference did not reach the identity", kind)
		}
	}
}

// The secret reaching the identity is the one in the file, newline stripped:
// the same identity as the inline spelling, so nothing depends on how it was
// written.
func TestAReferencedSecretIsTheInlineOne(t *testing.T) {
	from, err := hcldir.File([]hcldir.UserBlock{{Name: "a", PasswordFrom: "file:" + secret(t, "pw", []byte("s3cret\n")), NTHashFrom: "file:" + secret(t, "nt", []byte(hash32))}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	inline, err := hcldir.File([]hcldir.UserBlock{{Name: "a", Password: "s3cret", NTHash: hash32}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := from.Identities()
	b, _ := inline.Identities()
	if a[0].Verify("s3cret") != nil || b[0].Verify("s3cret") != nil {
		t.Error("the referenced password is not the file's content without its newline")
	}
	if a[0].Verify("s3cret\n") == nil {
		t.Error("the newline stayed part of the password")
	}
}

// Two spellings of one secret is refused, and the refusal names the field.
func TestTwoSpellingsOfOneSecretAreRefused(t *testing.T) {
	ref := "file:" + secret(t, "x", []byte("x"))
	for name, c := range map[string]struct {
		u    hcldir.UserBlock
		want string
	}{
		"password from and inline": {hcldir.UserBlock{Password: "x", PasswordFrom: ref}, "password"},
		"password from and file":   {hcldir.UserBlock{PasswordFile: "/x", PasswordFrom: ref}, "password_file and password_from"},
		"nt_hash from and inline":  {hcldir.UserBlock{NTHash: hash32, NTHashFrom: ref}, "nt_hash"},
		"totp from and inline":     {hcldir.UserBlock{TOTPSecret: totp32, TOTPSecretFrom: ref}, "totp_secret_from"},
	} {
		c.u.Name = "alice"
		_, err := hcldir.File([]hcldir.UserBlock{c.u}, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), `"alice"`) {
			t.Errorf("%s: %v, want a refusal naming %q", name, err, c.want)
		}
	}
	for name, c := range map[string]struct {
		b    hcldir.Block
		want string
	}{
		"dsn":           {hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFile: "/d", DSNFrom: ref, UsersQuery: "select 1"}, "dsn_file and dsn_from"},
		"bind password": {hcldir.Block{Kind: "ldap", URL: "ldaps://x", BaseDN: "dc=x", BindPasswordFile: "/p", BindPasswordFrom: ref}, "bind_password_file and bind_password_from"},
	} {
		if err := c.b.Check(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Check() = %v, want a refusal naming %q", name, err, c.want)
		}
	}
}

// A field of the other kind is still refused when it is the new spelling.
func TestAFromFieldOfTheOtherKindIsRefused(t *testing.T) {
	if err := (hcldir.Block{Kind: "ldap", URL: "ldaps://x", BaseDN: "dc=x", DSNFrom: "file:/d"}).Check(); err == nil || !strings.Contains(err.Error(), "dsn_from") {
		t.Errorf("an ldap block with dsn_from: %v", err)
	}
	if err := (hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFrom: "file:/d", BindPasswordFrom: "file:/p", UsersQuery: "select 1"}).Check(); err == nil || !strings.Contains(err.Error(), "bind_password_from") {
		t.Errorf("a sql block with bind_password_from: %v", err)
	}
}

// The deprecated spellings still work, and say they are deprecated.
func TestTheDeprecatedSpellingsStillWork(t *testing.T) {
	pw := secret(t, "pw", []byte("s3cret"))
	u := hcldir.UserBlock{Name: "alice", PasswordFile: pw, NTHash: hash32, TOTPSecret: totp32}
	src, err := hcldir.File([]hcldir.UserBlock{u}, nil)
	if err != nil {
		t.Fatal(err)
	}
	people, _ := src.Identities()
	if people[0].Verify("s3cret") != nil || !people[0].Can(directory.NTHash) || !people[0].Can(directory.TOTPSecret) {
		t.Error("an alias did not reach the identity")
	}
	got := strings.Join(u.Deprecations(), "\n")
	for _, want := range []string{"password_file is deprecated: use password_from = \"file:" + pw, "nt_hash is a secret written in the configuration", "totp_secret is a secret written in the configuration"} {
		if !strings.Contains(got, want) {
			t.Errorf("Deprecations() lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "s3cret") || strings.Contains(got, hash32) || strings.Contains(got, totp32) {
		t.Errorf("a deprecation notice holds a secret:\n%s", got)
	}
	if d := (hcldir.UserBlock{Name: "bob", PasswordFrom: "file:/x"}).Deprecations(); len(d) != 0 {
		t.Errorf("a reference was flagged: %v", d)
	}
	bd := strings.Join(hcldir.Block{Kind: "sql", DSNFile: "/d"}.Deprecations(), "\n")
	if !strings.Contains(bd, `dsn_file is deprecated: use dsn_from = "file:/d"`) {
		t.Errorf("Block.Deprecations() = %q", bd)
	}
}

// More than secretsource.MaxSize bytes is refused, for every field, and the
// refusal says why.
func TestAnOversizedSecretIsRefused(t *testing.T) {
	big := "file:" + secret(t, "big", make([]byte, secretsource.MaxSize+1))
	for name, u := range map[string]hcldir.UserBlock{
		"password": {PasswordFrom: big}, "nt_hash": {NTHashFrom: big}, "totp_secret": {TOTPSecretFrom: big},
	} {
		u.Name = "alice"
		if _, err := hcldir.File([]hcldir.UserBlock{u}, nil); err == nil || !strings.Contains(err.Error(), "4096") {
			t.Errorf("%s: %v, want a refusal naming 4096", name, err)
		}
	}
	_, err := hcldir.Open(hcldir.Block{Kind: "sql", Driver: "sqlite", DSNFrom: big, UsersQuery: "select 1"})
	if err == nil || !strings.Contains(err.Error(), "4096") || !strings.Contains(err.Error(), "dsn_from") {
		t.Errorf("dsn: %v", err)
	}
	_, err = hcldir.Open(hcldir.Block{Kind: "ldap", URL: "ldaps://127.0.0.1:1", BaseDN: "dc=x", BindPasswordFrom: big})
	if err == nil || !strings.Contains(err.Error(), "4096") {
		t.Errorf("bind password: %v", err)
	}
}

// A secret that is not one line, or is empty, is refused.
func TestASecretThatIsNotOneLineIsRefused(t *testing.T) {
	for name, content := range map[string]string{"two lines": "a\nb\n", "empty": "", "nul": "a\x00b", "only a newline": "\n"} {
		_, err := hcldir.File([]hcldir.UserBlock{{Name: "alice", PasswordFrom: "file:" + secret(t, "s", []byte(content))}}, nil)
		if err == nil || !strings.Contains(err.Error(), "password_from") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// secretsource's rules are the ones that apply: a file open to its group or
// everybody, or a reference of a kind that does not exist, is refused.
func TestSecretsourceRulesApply(t *testing.T) {
	loose := secret(t, "loose", []byte("x"))
	if err := os.Chmod(loose, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := hcldir.File([]hcldir.UserBlock{{Name: "a", PasswordFrom: "file:" + loose}}, nil); err == nil && os.PathSeparator == '/' {
		t.Error("a world-readable secret file was accepted")
	}
	if _, err := hcldir.File([]hcldir.UserBlock{{Name: "a", PasswordFrom: "nonsense:x"}}, nil); err == nil {
		t.Error("an unknown reference scheme was accepted")
	}
}

// A dsn_from opens the database; so does the deprecated dsn_file.
func TestDSNFromOpensTheDatabase(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "db.sqlite")
	for name, b := range map[string]hcldir.Block{
		"dsn_from": {DSNFrom: "file:" + secret(t, "dsn", []byte(dsn+"\n"))},
		"dsn_file": {DSNFile: secret(t, "dsn", []byte(dsn+"\n"))},
	} {
		b.Kind, b.Driver, b.UsersQuery = "sql", "sqlite", "select 'alice', 'pw'"
		src, err := hcldir.Open(b)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		people, err := src.Identities()
		if err != nil || len(people) != 1 || people[0].Name() != "alice" {
			t.Errorf("%s: %v, %v", name, people, err)
		}
		src.(interface{ Close() error }).Close()
	}
}

// A password named by a reference is not written through by SetPassword, and
// a hash named by a reference cannot be recomputed: both are refused, and the
// configuration is untouched.
func TestSetPasswordRefusesReferences(t *testing.T) {
	for name, block := range map[string]string{
		"password_from": `user "alice" { password_from = "file:/x" }`,
		"nt_hash_from":  `user "alice" {` + "\n" + `  password = "old"` + "\n" + `  nt_hash_from = "file:/x"` + "\n}",
	} {
		path := filepath.Join(t.TempDir(), "c.hcl")
		if err := os.WriteFile(path, []byte(block+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := hcldir.SetPassword([]string{path}, "alice", "new")
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: %v", name, err)
		}
		if got, _ := os.ReadFile(path); string(got) != block+"\n" {
			t.Errorf("%s: the configuration changed:\n%s", name, got)
		}
	}
}
