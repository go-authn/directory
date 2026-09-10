package directory

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// What proves somebody is not one thing, and a server has to be able to ask
// which it has BEFORE somebody fails to log in.
func TestWhichCredentialsAnIdentityHas(t *testing.T) {
	hash, err := ParseNTHash("8846f7eaee8fb117ad06bdd830b7586c")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		id   *Identity
		can  map[Credential]bool
	}{
		{
			"a password answers everything",
			NewIdentity("alice", WithPassword("hunter2")),
			map[Credential]bool{Password: true, NTHash: true, Verifier: true, PublicKeys: false},
		},
		{
			"an NT hash answers NTLMv2 and nothing else",
			NewIdentity("bob", WithNTHash(hash)),
			map[Credential]bool{Password: false, NTHash: true, Verifier: false, PublicKeys: false},
		},
		{
			"a verifier answers a password question and cannot answer NTLMv2",
			NewIdentity("carol", WithVerifier(func(string) error { return nil })),
			map[Credential]bool{Password: false, NTHash: false, Verifier: true, PublicKeys: false},
		},
		{
			"keys answer SSH and nothing else",
			NewIdentity("dave", WithPublicKeys("ssh-ed25519 AAAA")),
			map[Credential]bool{Password: false, NTHash: false, Verifier: false, PublicKeys: true},
		},
		{
			"somebody a directory only NAMES",
			NewIdentity("erin"),
			map[Credential]bool{Password: false, NTHash: false, Verifier: false, PublicKeys: false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for c, want := range tc.can {
				if got := tc.id.Can(c); got != want {
					t.Errorf("Can(%v) = %v, want %v", c, got, want)
				}
			}
		})
	}
}

func TestVerifyingAPassword(t *testing.T) {
	alice := NewIdentity("alice", WithPassword("hunter2"))
	if err := alice.Verify("hunter2"); err != nil {
		t.Errorf("the right password: %v", err)
	}
	if err := alice.Verify("wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("the wrong password: %v", err)
	}

	// A verifier is PREFERRED over a held password: it is the one that may
	// reach the directory, and a source giving both means the directory is
	// the authority.
	asked := 0
	both := NewIdentity("bob", WithPassword("stale"), WithVerifier(func(p string) error {
		asked++
		if p == "current" {
			return nil
		}
		return ErrWrongPassword
	}))
	if err := both.Verify("current"); err != nil || asked != 1 {
		t.Errorf("the verifier was not asked: %v, asked %d times", err, asked)
	}
	if err := both.Verify("stale"); err == nil {
		t.Error("the held password answered while a verifier was there")
	}

	// Somebody with nothing cannot answer, which is a different thing from
	// answering wrongly: one is a configuration to fix, the other is a typo.
	if err := NewIdentity("erin").Verify("anything"); !errors.Is(err, ErrNoCredential) {
		t.Errorf("somebody with no credential: %v", err)
	}
}

// NTLMv2 needs MD4(UTF16LE(password)), and it must come out the same whether
// the source published the hash or the password.
func TestTheNTKeyIsTheSameFromEitherSide(t *testing.T) {
	fromPassword := NewIdentity("alice", WithPassword("password"))
	hash, _ := ParseNTHash("8846f7eaee8fb117ad06bdd830b7586c")
	fromHash := NewIdentity("alice", WithNTHash(hash))

	a, err := fromPassword.NTKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := fromHash.NTKey()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Errorf("the two paths give different keys: %x and %x", a, b)
	}
	if _, err := NewIdentity("nobody").NTKey(); !errors.Is(err, ErrNoCredential) {
		t.Errorf("somebody with neither: %v", err)
	}
}

// A mangled hash is refused rather than padded: it would fail every login with
// "wrong password", the least useful thing a server could say.
func TestAMangledNTHashIsRefused(t *testing.T) {
	for _, tc := range []string{"", "zz", "8846f7eaee8fb117ad06bdd830b758", "8846f7eaee8fb117ad06bdd830b7586c00", "not hex at all!!"} {
		if _, err := ParseNTHash(tc); err == nil {
			t.Errorf("%q was accepted as an NT hash", tc)
		}
	}
}

// A one-time-code secret is a credential like the others: a source can hold
// it, Can() reports it, and it is handed out as a copy.
func TestATOTPSecretIsACredential(t *testing.T) {
	secret := []byte{1, 2, 3, 4, 5}
	id := NewIdentity("dora", WithPassword("hunter2"), WithTOTPSecret(secret))
	if !id.Can(TOTPSecret) {
		t.Error("dora has a one-time-code secret and Can says otherwise")
	}
	got := id.TOTPSecret()
	if !bytes.Equal(got, secret) {
		t.Errorf("TOTPSecret() = %v", got)
	}
	// A copy: what the caller does with it cannot change what the directory
	// said, and cannot change it for the next caller either.
	got[0] = 99
	if again := id.TOTPSecret(); again[0] != 1 {
		t.Error("the secret handed out is the one held")
	}
	// The source is not changed underneath us either.
	secret[1] = 99
	if again := id.TOTPSecret(); again[1] != 2 {
		t.Error("the identity kept a reference to the caller's slice")
	}

	// ⛔ A second factor is not a first: somebody with ONLY a code secret
	// cannot be authenticated by anything else here, and Can says exactly that.
	only := NewIdentity("eli", WithTOTPSecret(secret))
	if only.Can(Password) || only.Can(NTHash) || only.Can(Verifier) || only.Can(PublicKeys) {
		t.Error("a one-time-code secret was read as some other credential")
	}
	if !only.Can(TOTPSecret) {
		t.Error("eli's secret is not reported")
	}
	// And somebody without one says so, rather than returning an empty secret
	// that would verify nothing while looking like a credential.
	none := NewIdentity("frank", WithPassword("x"))
	if none.Can(TOTPSecret) || none.TOTPSecret() != nil {
		t.Error("frank has no second factor and something said he does")
	}
	if got := TOTPSecret.String(); got != "a one-time-code secret" {
		t.Errorf("the credential is named %q", got)
	}
}

// The base32 a directory stores, read as people copy it.
func TestParsingAOneTimeCodeSecret(t *testing.T) {
	want, err := ParseTOTPSecret("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"jbswy3dpehpk3pxp", "JBSW Y3DP EHPK 3PXP", "JBSW-Y3DP-EHPK-3PXP", " JBSWY3DPEHPK3PXP "} {
		got, err := ParseTOTPSecret(spelling)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%q: %v, %v", spelling, got, err)
		}
	}
	for _, bad := range []string{"not base 32!", "", "   ", "========"} {
		if _, err := ParseTOTPSecret(bad); err == nil {
			t.Errorf("%q was accepted as a secret", bad)
		} else if strings.Contains(err.Error(), "not base 32") {
			t.Errorf("the refusal quotes the secret: %q", err)
		}
	}
}
