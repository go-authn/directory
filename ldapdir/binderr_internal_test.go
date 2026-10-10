package ldapdir

import (
	"errors"
	"net"
	"testing"

	"github.com/go-authn/directory"
)

// A directory that accepts the connection and drops it during the bind is a
// directory failing, not a wrong password. v0.11.1 said ErrWrongPassword for
// it, so a server in front logged "wrong password" for a person who had
// typed it right.
func TestADirectoryFailingMidBindIsNotAWrongPassword(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close() // hang up before answering anything
		}
	}()
	s := &Source{cfg: Config{URL: "ldap://" + ln.Addr().String()}}
	err = s.bindAs("uid=alice,ou=people,dc=example,dc=org")("hunter2")
	if err == nil {
		t.Fatal("a bind nobody answered succeeded")
	}
	if errors.Is(err, directory.ErrWrongPassword) {
		t.Errorf("a dropped connection was reported as a wrong password: %v", err)
	}
}
