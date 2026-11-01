package ldapdir_test

import (
	"errors"
	"net"
	"testing"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/directory/ldaptest"
)

func verifierOf(t *testing.T, src *ldapdir.Source, name string) *directory.Identity {
	t.Helper()
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if id.Name() == name {
			return id
		}
	}
	t.Fatalf("%s not imported", name)
	return nil
}

// RFC 4511 §4.1.9: only invalidCredentials (49) says the password is wrong;
// busy (51), unavailable (52) and other (80) say the directory is failing.
// Both directions are tested: an outage must not read as a wrong password,
// and a wrong password must not read as an outage.
func TestBindResultCodes(t *testing.T) {
	cases := []struct {
		name        string
		code        uint16
		wrong, down bool
	}{
		{"invalidCredentials", 49, true, false},
		{"busy", 51, false, true},
		{"unavailable", 52, false, true},
		{"other", 80, false, true},
		{"timeLimitExceeded", 3, false, true},
		// An answer that is neither: refused, not an outage, not a wrong password.
		{"unwillingToPerform", 53, false, false},
		{"inappropriateAuthentication", 48, false, false},
	}
	src, srv := directoryUnderTest(t)
	alice := verifierOf(t, src, "alice")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv.FailBindsWith(c.code)
			defer srv.FailBindsWith(0)
			err := alice.Verify("hunter2")
			if err == nil {
				t.Fatal("a failing bind let somebody in")
			}
			if got := errors.Is(err, directory.ErrWrongPassword); got != c.wrong {
				t.Errorf("ErrWrongPassword = %v, want %v: %v", got, c.wrong, err)
			}
			if got := errors.Is(err, directory.ErrUnavailable); got != c.down {
				t.Errorf("ErrUnavailable = %v, want %v: %v", got, c.down, err)
			}
		})
	}
}

// The normal answers still work either way round.
func TestRightAndWrongPasswordUnchanged(t *testing.T) {
	src, _ := directoryUnderTest(t)
	alice := verifierOf(t, src, "alice")
	if err := alice.Verify("hunter2"); err != nil {
		t.Errorf("right password: %v", err)
	}
	err := alice.Verify("nope")
	if !errors.Is(err, directory.ErrWrongPassword) || errors.Is(err, directory.ErrUnavailable) {
		t.Errorf("wrong password: %v", err)
	}
}

// A directory that is gone: the connection is refused.
func TestDirectoryGone(t *testing.T) {
	src, srv := directoryUnderTest(t)
	alice := verifierOf(t, src, "alice")
	srv.Close()
	err := alice.Verify("hunter2")
	if !errors.Is(err, directory.ErrUnavailable) || errors.Is(err, directory.ErrWrongPassword) {
		t.Errorf("verify against a closed directory: %v", err)
	}
	if _, err := src.Identities(); !errors.Is(err, directory.ErrUnavailable) {
		t.Errorf("Identities against a closed directory: %v", err)
	}
	if _, err := src.ReadGroups(); !errors.Is(err, directory.ErrUnavailable) {
		t.Errorf("ReadGroups against a closed directory: %v", err)
	}
	if _, err := src.Members("staff"); !errors.Is(err, directory.ErrUnavailable) {
		t.Errorf("Members against a closed directory: %v", err)
	}
}

// A directory that accepts and hangs up, and a wrong service-account
// password, which is a configuration error and not an outage.
func TestHangUpIsUnavailableBadServiceAccountIsNot(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	cfg := ldapdir.Config{URL: "ldap://" + ln.Addr().String(), BaseDN: "dc=example,dc=org",
		BindDN: "cn=r,dc=example,dc=org", BindPassword: "x"}
	// New probes the directory, so a hang-up is already visible there.
	if _, err := ldapdir.New(cfg); !errors.Is(err, directory.ErrUnavailable) {
		t.Errorf("hang-up: %v", err)
	}

	d, err := ldaptest.NewServer(&ldaptest.Directory{People: map[string]ldaptest.Person{"a": {Password: "p"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	_, err = ldapdir.New(ldapdir.Config{URL: d.URL, BaseDN: d.PeopleDN, BindDN: d.ReaderDN, BindPassword: "wrong"})
	if err == nil || errors.Is(err, directory.ErrUnavailable) {
		t.Errorf("a refused service account is a configuration error, not an outage: %v", err)
	}
}
