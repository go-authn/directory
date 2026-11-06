package ldapdir_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/directory"
	"github.com/go-authn/directory/ldapdir"
	"github.com/go-authn/directory/ldaptest"
)

// proxy forwards to upstream until hang is set; then it accepts, reads and
// never answers, and counts the connections the CLIENT hung up.
type proxy struct {
	ln     net.Listener
	hang   atomic.Bool
	hungUp atomic.Int32
}

func newProxy(t *testing.T, upstream string) *proxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &proxy{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if p.hang.Load() {
					_, _ = io.Copy(io.Discard, c) // returns when the client hangs up
					p.hungUp.Add(1)
					return
				}
				u, err := net.Dial("tcp", upstream)
				if err != nil {
					return
				}
				defer u.Close()
				go io.Copy(u, c)
				io.Copy(c, u)
			}()
		}
	}()
	return p
}

// A password check against an upstream that accepts the connection and never
// answers must be CANCELLABLE: when the caller's context ends, the upstream
// connection is closed and the check returns ErrUnavailable, rather than the
// goroutine and the connection living until the library's own timeout.
func TestVerifyContextCancelsAHungUpstreamBind(t *testing.T) {
	d, err := ldaptest.NewServer(&ldaptest.Directory{
		People: map[string]ldaptest.Person{"alice": {Password: "hunter2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	p := newProxy(t, d.URL[len("ldap://"):])

	src, err := ldapdir.New(ldapdir.Config{URL: "ldap://" + p.ln.Addr().String(), BaseDN: d.PeopleDN, BindDN: d.ReaderDN, BindPassword: d.ReaderPassword})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil || len(ids) != 1 {
		t.Fatalf("%d identities, %v", len(ids), err)
	}
	alice := ids[0]
	if err := alice.VerifyContext(context.Background(), "hunter2"); err != nil {
		t.Fatalf("a good password: %v", err)
	}
	if err := alice.VerifyContext(context.Background(), "wrong"); !errors.Is(err, directory.ErrWrongPassword) {
		t.Fatalf("a wrong password: %v", err)
	}

	p.hang.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	begin := time.Now()
	err = alice.VerifyContext(ctx, "hunter2")
	if !errors.Is(err, directory.ErrUnavailable) {
		t.Fatalf("a hung upstream: err = %v, want ErrUnavailable", err)
	}
	if took := time.Since(begin); took > 3*time.Second {
		t.Errorf("returned after %s, the context ended after 300ms", took)
	}
	// The upstream operation was cancelled: the connection is closed by us.
	deadline := time.Now().Add(3 * time.Second)
	for p.hungUp.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if p.hungUp.Load() == 0 {
		t.Error("the upstream connection was left open after the context ended")
	}
}

func TestVerifyContextOnAnIdentityWithoutOne(t *testing.T) {
	id := directory.NewIdentity("bob", directory.WithPassword("x"))
	if err := id.VerifyContext(context.Background(), "x"); err != nil {
		t.Fatal(err)
	}
	if err := id.VerifyContext(context.Background(), "y"); !errors.Is(err, directory.ErrWrongPassword) {
		t.Fatalf("err = %v", err)
	}
	if err := directory.NewIdentity("c").VerifyContext(context.Background(), "x"); !errors.Is(err, directory.ErrNoCredential) {
		t.Fatalf("err = %v", err)
	}
}

func TestWithContextVerifierAlsoServesVerify(t *testing.T) {
	var got context.Context
	id := directory.NewIdentity("d", directory.WithContextVerifier(func(ctx context.Context, pw string) error {
		got = ctx
		if pw == "ok" {
			return nil
		}
		return directory.ErrWrongPassword
	}))
	if err := id.Verify("ok"); err != nil || got == nil {
		t.Fatalf("Verify through a context verifier: %v", err)
	}
	if !id.Can(directory.Verifier) {
		t.Error("a context verifier is a verifier")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := id.VerifyContext(ctx, "ok"); err != nil || got != ctx {
		t.Errorf("the caller's context was not passed through: %v", err)
	}
}

func TestVerifyContextWithACancelledContextAsksNobody(t *testing.T) {
	d, err := ldaptest.NewServer(&ldaptest.Directory{People: map[string]ldaptest.Person{"alice": {Password: "hunter2"}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	src, err := ldapdir.New(ldapdir.Config{URL: d.URL, BaseDN: d.PeopleDN, BindDN: d.ReaderDN, BindPassword: d.ReaderPassword})
	if err != nil {
		t.Fatal(err)
	}
	ids, err := src.Identities()
	if err != nil {
		t.Fatal(err)
	}
	before := d.Binds()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ids[0].VerifyContext(ctx, "hunter2"); !errors.Is(err, directory.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
	if d.Binds() != before {
		t.Errorf("a cancelled check still bound upstream")
	}
}
