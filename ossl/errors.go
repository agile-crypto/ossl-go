package ossl

/*
#include <openssl/err.h>

// ERR_set_error is variadic (it takes a printf-style format string), and
// cgo cannot call variadic C functions directly -- the call fails at
// compile time with "unexpected type: ...". This shim fixes the signature
// to exactly the no-format-arguments case this package needs, giving cgo a
// concrete, non-variadic declaration to bind to.
static void ossl_err_set_error_simple(int lib, int reason) {
    ERR_set_error(lib, reason, NULL);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
)

// Error is an OpenSSL failure, carrying every entry that was on the
// thread-local error queue when the failure was detected.
//
// OpenSSL does not use errno. It pushes structured codes onto a per-thread
// queue and returns 0 or NULL. A wrapper that only reports "call failed"
// throws away the entire diagnosis, so every failure path in this package
// routes through newError.
type Error struct {
	Op    string   // the Go-level operation, e.g. "EVP_DigestInit_ex2"
	Codes []uint64 // raw ERR_get_error codes, useful for programmatic checks
	Msgs  []string // human-readable strings from ERR_error_string_n
}

func (e *Error) Error() string {
	if len(e.Msgs) == 0 {
		return fmt.Sprintf("ossl: %s failed (no detail on error queue)", e.Op)
	}
	return fmt.Sprintf("ossl: %s: %s", e.Op, strings.Join(e.Msgs, "; "))
}

// Reason reports whether any queued error has the given reason code, letting
// callers distinguish specific conditions without string matching.
func (e *Error) Reason(reason int) bool {
	for _, c := range e.Codes {
		if int(c&0xfff) == reason {
			return true
		}
	}
	return false
}

// newError drains the error queue and builds an *Error.
//
// Draining is mandatory, not merely tidy: the queue is thread-local and
// unbounded, so a leftover entry from an earlier ignored failure will be
// reported against an unrelated later call and send you chasing a ghost.
func newError(op string) error {
	e := &Error{Op: op}
	for {
		code := uint64(C.ERR_get_error())
		if code == 0 {
			break
		}
		var buf [256]C.char
		C.ERR_error_string_n(C.ulong(code), &buf[0], C.size_t(len(buf)))
		e.Codes = append(e.Codes, code)
		e.Msgs = append(e.Msgs, C.GoString(&buf[0]))
	}
	return e
}

// clearErrors empties the queue without reporting.
//
// Call this before an operation whose failure you intend to interpret, so a
// stale entry from earlier code cannot contaminate the diagnosis. Several
// OpenSSL routines also push informational entries on paths that ultimately
// succeed.
func clearErrors() { C.ERR_clear_error() }

// ErrVerification is returned by Verify and Open when the input is
// well-formed but does not authenticate. It is deliberately distinct from an
// *Error: a bad signature is an expected outcome, not a library failure, and
// callers routinely branch on it.
var ErrVerification = errors.New("ossl: verification failed")

// ErrClosed is returned by methods on a resource whose Close has run.
var ErrClosed = errors.New("ossl: resource is closed")

// raiseSyntheticError pushes one well-formed entry onto the error queue
// under ERR_LIB_USER, which OpenSSL reserves for exactly this: application
// code raising its own errors rather than a library reporting one. It exists
// to give this package's own tests a deterministic queue entry to drain,
// independent of any particular algorithm's fetch behaviour.
//
// It lives here, in a regular file, rather than in errors_test.go, because
// this Go toolchain rejects cgo in _test.go files outright ("use of cgo in
// test errors_test.go not supported") -- any cgo call a test needs has to be
// reached through a helper defined outside the _test.go files.
func raiseSyntheticError(reason int) {
	C.ERR_new()
	C.ossl_err_set_error_simple(C.ERR_LIB_USER, C.int(reason))
}

// peekError reports the most recent queued error code without removing it,
// for the same reason raiseSyntheticError exists: a _test.go file cannot
// call C.ERR_peek_error itself.
func peekError() uint64 {
	return uint64(C.ERR_peek_error())
}
