// SPDX-License-Identifier: BSD-3-Clause

package hcldir_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
)

func writeHCL(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ⛔ The password has to land where THAT person's block keeps it. Writing an
// inline password into a block that named a password_file would quietly undo
// the reason the file exists -- the secret is not in something somebody
// prints, pastes or commits -- and the configuration would still parse.
func TestAPasswordGoesWhereTheBlockKeepsIt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pw := filepath.Join(dir, "bob.pw")
	if err := os.WriteFile(pw, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// ⛔ ToSlash: this path goes into HCL SOURCE, and a Windows path holds
	// backslashes, where \U is an escape sequence and the file stops parsing.
	path := writeHCL(t, dir, "c.hcl", `
# a comment that must survive a write
user "alice" { password = "hunter2" }

user "bob" {
  password_file = "`+filepath.ToSlash(pw)+`"
}
`)

	if err := hcldir.SetPassword([]string{path}, "alice", "correct horse"); err != nil {
		t.Fatalf("alice: %v", err)
	}
	if err := hcldir.SetPassword([]string{path}, "bob", "stapler battery"); err != nil {
		t.Fatalf("bob: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `password = "correct horse"`) {
		t.Errorf("alice's new password is not in the file:\n%s", got)
	}
	if strings.Contains(string(got), "stapler battery") {
		t.Errorf("bob's password was written INTO the configuration:\n%s", got)
	}
	if !strings.Contains(string(got), "# a comment that must survive a write") {
		t.Errorf("the write lost a comment:\n%s", got)
	}
	held, err := os.ReadFile(pw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(held)) != "stapler battery" {
		t.Errorf("the password file holds %q", held)
	}
	if fi, err := os.Stat(pw); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("the password file is mode %v, not 0600", fi.Mode().Perm())
	}
}

// ⛔ THE CASE go-authn/authnd CANNOT REACH. authnd refuses a block carrying
// both a password and an nt_hash; fileshare does not, and this package serves
// both. A password written without recomputing the hash leaves SMB accepting
// the OLD password while WebDAV and S3 take the new one, and nothing says so.
func TestAnNTHashBesideAPasswordIsRecomputed(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	// The hash of "hunter2", so the fixture starts consistent.
	before := fmt.Sprintf("%x", directory.NTHashOf("hunter2"))
	path := writeHCL(t, dir, "c.hcl", `
user "alice" {
  password = "hunter2"
  nt_hash  = "`+before+`"
}
`)
	if err := hcldir.SetPassword([]string{path}, "alice", "correct horse"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%x", directory.NTHashOf("correct horse"))
	if !strings.Contains(string(got), want) {
		t.Errorf("the nt_hash was not recomputed:\n%s", got)
	}
	if strings.Contains(string(got), before) {
		t.Errorf("the OLD nt_hash is still there, so SMB would take the old password:\n%s", got)
	}

	// And the two credentials agree, read back through the package that
	// builds identities from these blocks.
	src, err := hcldir.File([]hcldir.UserBlock{{
		Name: "alice", Password: "correct horse", NTHash: want,
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil || len(ids) != 1 {
		t.Fatalf("%d identities: %v", len(ids), err)
	}
}

// The same case with the password in a FILE: the hash lives in the
// configuration, the password does not, so BOTH are written.
func TestAnNTHashIsRecomputedBesideAPasswordFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pw := filepath.Join(dir, "alice.pw")
	if err := os.WriteFile(pw, []byte("hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeHCL(t, dir, "c.hcl", `
user "alice" {
  password_file = "`+filepath.ToSlash(pw)+`"
  nt_hash       = "`+fmt.Sprintf("%x", directory.NTHashOf("hunter2"))+`"
}
`)
	if err := hcldir.SetPassword([]string{path}, "alice", "correct horse"); err != nil {
		t.Fatal(err)
	}
	cfg, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), fmt.Sprintf("%x", directory.NTHashOf("correct horse"))) {
		t.Errorf("the nt_hash was not recomputed:\n%s", cfg)
	}
	if strings.Contains(string(cfg), "correct horse") {
		t.Errorf("the password reached the configuration:\n%s", cfg)
	}
	held, _ := os.ReadFile(pw)
	if strings.TrimSpace(string(held)) != "correct horse" {
		t.Errorf("the password file holds %q", held)
	}
}

func TestWhatSetPasswordRefuses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := writeHCL(t, dir, "c.hcl", `
user "alice" { password = "hunter2" }

# somebody a site holds only the SMB hash for.
user "hash" { nt_hash = "8846f7eaee8fb117ad06bdd830b7586c" }

# a path this cannot read back safely.
user "computed" { password_file = "/tmp/x${""}" }
`)
	for _, tc := range []struct {
		name, who, password, want string
	}{
		{"an empty password", "alice", "", "would let anybody in"},
		{"somebody not written down", "carol", "x", "not written down"},
		{"held only as an nt_hash", "hash", "x", "would change what can prove them"},
		{"a password_file that is not a literal", "computed", "x", "not a plain quoted path"},
	} {
		err := hcldir.SetPassword([]string{path}, tc.who, tc.password)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if err := hcldir.SetPassword([]string{path}, "carol", "x"); !errors.Is(err, hcldir.ErrNotDeclared) {
		t.Errorf("a person from another source should be ErrNotDeclared: %v", err)
	}
	if err := hcldir.SetPassword([]string{filepath.Join(dir, "gone.hcl")}, "alice", "x"); err == nil {
		t.Error("a file that is not there was not reported")
	}
	bad := writeHCL(t, dir, "bad.hcl", "user \"alice\" {\n")
	if err := hcldir.SetPassword([]string{bad}, "alice", "x"); err == nil {
		t.Error("a file that does not parse was not reported")
	}
}

// Several files, which is what -c repeated and a directory of .hcl files give.
func TestThePersonIsFoundInWhicheverFileDeclaresThem(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	first := writeHCL(t, dir, "a.hcl", "user \"alice\" { password = \"hunter2\" }\n")
	second := writeHCL(t, dir, "b.hcl", "user \"bob\" { password = \"hunter2\" }\n")
	if err := hcldir.SetPassword([]string{first, second}, "bob", "correct horse"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(second)
	if !strings.Contains(string(got), "correct horse") {
		t.Errorf("bob's file was not the one written:\n%s", got)
	}
	untouched, _ := os.ReadFile(first)
	if strings.Contains(string(untouched), "correct horse") {
		t.Errorf("the wrong file was written:\n%s", untouched)
	}
}
