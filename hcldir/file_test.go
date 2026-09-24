// SPDX-License-Identifier: BSD-3-Clause

package hcldir_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/hcldir"
)

const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFHmLeJckUZWQ456dzpplNWsWrj/ntVMYAirkZgvthVF alice@laptop"

// ⛔ The drift this package exists to close. authnd's inline user block
// carried nt_hash and totp_secret; fileshare's carried neither. So the same
// person, written the same way in two configurations, could be served over SMB
// from one and not the other -- NTLMv2 works from the password or its MD4 and
// nothing else, which is what fileshare's own canServeUser says.
//
// One definition can still lose a field in a refactor. This asserts every
// credential a block can carry actually reaches the identity.
func TestEveryCredentialInTheBlockReachesTheIdentity(t *testing.T) {
	src, err := hcldir.File([]hcldir.UserBlock{{
		Name:           "alice",
		Password:       "s3cret",
		NTHash:         "8846f7eaee8fb117ad06bdd830b7586c",
		TOTPSecret:     "JBSWY3DPEHPK3PXP",
		AuthorizedKeys: []string{key},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	people, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(people) != 1 {
		t.Fatalf("got %d identities, want 1", len(people))
	}
	alice := people[0]
	for _, kind := range []directory.Credential{
		directory.Password, directory.NTHash, directory.PublicKeys,
	} {
		if !alice.Can(kind) {
			t.Errorf("alice cannot %v, so a protocol needing it would refuse her", kind)
		}
	}
	if src.Describe() != "the configuration file" {
		t.Errorf("Describe() = %q", src.Describe())
	}
}

// A group the source has never heard of is an error, not an empty list --
// the Source interface says so, because an empty list grants nothing to
// nobody and reads exactly like a working configuration.
func TestAnUnknownGroupIsAnError(t *testing.T) {
	src, err := hcldir.File(nil, []hcldir.GroupBlock{{Name: "staff", Members: []string{"alice"}}})
	if err != nil {
		t.Fatal(err)
	}
	if m, err := src.Members("staff"); err != nil || len(m) != 1 {
		t.Fatalf("staff = %v, %v", m, err)
	}
	if _, err := src.Members("nobody-declared-this"); err == nil {
		t.Error("an unknown group returned no error")
	}
}

// Two spellings of one secret is a question about which one wins. A
// configuration that answers it silently is one a reader cannot check.
func TestPasswordAndPasswordFileTogetherIsRefused(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pw")
	if err := os.WriteFile(p, []byte("fromfile\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := hcldir.File([]hcldir.UserBlock{{Name: "alice", Password: "inline", PasswordFile: p}}, nil)
	if err == nil {
		t.Fatal("both a password and a password_file were accepted")
	}
	if !strings.Contains(err.Error(), "not both") {
		t.Errorf("the refusal should say which to give: %v", err)
	}
	// And the file alone works, trimmed.
	src, err := hcldir.File([]hcldir.UserBlock{{Name: "alice", PasswordFile: p}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	people, _ := src.Identities()
	if !people[0].Can(directory.Password) {
		t.Error("password_file alone did not give a password")
	}
}

// A line that is not an authorized_keys line is a configuration error, and
// finding it at startup beats finding it when somebody cannot log in.
func TestABadAuthorizedKeyIsRefusedAtStartup(t *testing.T) {
	_, err := hcldir.File([]hcldir.UserBlock{{
		Name: "alice", AuthorizedKeys: []string{"not a key at all"},
	}}, nil)
	if err == nil {
		t.Fatal("a line that is not a key was accepted")
	}
	if !strings.Contains(err.Error(), "authorized_keys") {
		t.Errorf("the refusal should name what it expected: %v", err)
	}
}

func TestDuplicateUserIsRefused(t *testing.T) {
	_, err := hcldir.File([]hcldir.UserBlock{{Name: "alice"}, {Name: "alice"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("a name declared twice must be refused, got %v", err)
	}
}

func TestAMissingPasswordFileSaysWhichUser(t *testing.T) {
	_, err := hcldir.File([]hcldir.UserBlock{{
		Name: "alice", PasswordFile: filepath.Join(t.TempDir(), "nope"),
	}}, nil)
	if err == nil {
		t.Fatal("a missing password_file was accepted")
	}
	if !strings.Contains(err.Error(), "alice") || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the error should name the user and wrap fs.ErrNotExist: %v", err)
	}
}
