// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

func TestAsUnavailable(t *testing.T) {
	cause := errors.New("boom")
	got := AsUnavailable(fmt.Errorf("wrapped: %w", cause))
	if !errors.Is(got, ErrUnavailable) || !errors.Is(got, cause) {
		t.Fatalf("lost a link: %v", got)
	}
	if got.Error() != "wrapped: boom" {
		t.Errorf("message changed: %q", got)
	}
	if AsUnavailable(nil) != nil {
		t.Error("nil became an error")
	}
	// Exclusive: a wrong password stays a wrong password.
	wp := fmt.Errorf("x: %w", ErrWrongPassword)
	if r := AsUnavailable(wp); errors.Is(r, ErrUnavailable) || !errors.Is(r, ErrWrongPassword) {
		t.Errorf("a wrong password was turned into an outage: %v", r)
	}
	if errors.Is(ErrWrongPassword, ErrUnavailable) || errors.Is(ErrUnavailable, ErrWrongPassword) {
		t.Error("the two sentinels are not exclusive")
	}
}

func TestTransportFailure(t *testing.T) {
	yes := []error{
		io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, driver.ErrBadConn,
		context.DeadlineExceeded, &net.OpError{Op: "dial", Err: errors.New("refused")},
		fmt.Errorf("wrapped: %w", io.EOF),
	}
	for _, e := range yes {
		if !TransportFailure(e) {
			t.Errorf("%v is a transport failure", e)
		}
	}
	for _, e := range []error{nil, errors.New("syntax error"), ErrWrongPassword, ErrNoSuchGroup} {
		if TransportFailure(e) {
			t.Errorf("%v is not a transport failure", e)
		}
	}
}
