// SPDX-License-Identifier: BSD-3-Clause

package directory

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"net"
	"os"
)

// ErrUnavailable says the source could not be asked: the server is down, busy
// or shutting down, the connection dropped, a deadline passed. It is a
// different thing from "no" -- ErrWrongPassword says the source answered and
// the password was not the right one -- and a caller must tell them apart:
// a server in front of a source counts a wrong password as a failed guess
// (lockout, throttling, "invalid credentials"), and counting an outage as one
// punishes people for the directory's failure. RFC 4511 §4.1.9 and appendix
// A.2 give the LDAP side its own answers: busy (51) and unavailable (52) are
// "the server is too busy" and "shutting down or a subsystem necessary ... is
// offline", while invalidCredentials (49) is the only code that says the
// credentials are wrong.
//
// Test with errors.Is(err, directory.ErrUnavailable). The error also wraps
// the underlying cause, which errors.Is and errors.As still reach, and it is
// never also ErrWrongPassword: the two are exclusive by construction.
var ErrUnavailable = errors.New("directory: the source is unavailable")

type unavailableError struct{ err error }

func (e *unavailableError) Error() string   { return e.err.Error() }
func (e *unavailableError) Unwrap() []error { return []error{e.err, ErrUnavailable} }

// AsUnavailable marks err as ErrUnavailable without changing its message.
// nil stays nil, and an error that is already ErrWrongPassword is returned as
// it is: a source that answered "wrong password" was available.
func AsUnavailable(err error) error {
	if err == nil || errors.Is(err, ErrWrongPassword) || errors.Is(err, ErrUnavailable) {
		return err
	}
	return &unavailableError{err: err}
}

// TransportFailure reports whether err is the network or the connection
// failing rather than a source answering: a dial that was refused or timed
// out, a connection closed or reset mid-request, a deadline, a pooled
// connection database/sql found dead. It is conservative: an error that is
// none of these (a bad query, a bad filter, a refused credential) is not one.
func TransportFailure(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || errors.Is(err, driver.ErrBadConn) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)
}
