package ossl

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
//
// This type and the sentinels below carry no cgo, so they exist in the
// non-cgo build too: code that handles this package's errors compiles either
// way, and only the calls that need OpenSSL are absent.
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

// ErrVerification is returned by Verify, Open and Decrypt when the input is
// well-formed but does not authenticate. It is deliberately distinct from an
// *Error: a bad signature is an expected outcome, not a library failure, and
// callers routinely branch on it.
var ErrVerification = errors.New("ossl: verification failed")

// ErrClosed is returned by methods on a resource whose Close has run.
var ErrClosed = errors.New("ossl: resource is closed")

// ErrUnavailable is returned by every operation in a build made without cgo,
// where there is no libcrypto to call. It exists so that a program can be
// compiled and its non-cryptographic paths tested on a machine with no
// OpenSSL, and so that the failure names the reason rather than surfacing as
// a link error.
var ErrUnavailable = errors.New("ossl: built without cgo; OpenSSL is unavailable")
