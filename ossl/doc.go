// Package ossl is a Go binding for OpenSSL 3.x libcrypto.
//
// All cgo and unsafe usage in a program should be confined to this package.
// Callers see ordinary Go types: []byte, string, error, io.Writer.
//
// # Lifetimes
//
// Every type that owns C memory has a Close method (Provider has Unload).
// Use defer. None of them install a garbage-collector finalizer as a
// backstop, which is a deliberate choice rather than an omission: a
// finalizer would free the underlying object at a point the runtime picks,
// which is precisely the wrong property for a handle that may be in use by C
// code the collector cannot see. The consequence is that a missed Close
// leaks the C allocation for the life of the process, so treat these types
// the way you would an *os.File.
//
// # Concurrency
//
// Types are not safe for concurrent use unless their documentation says
// otherwise. AEAD is, including against a concurrent Close. Hash, MAC,
// Signer and Verifier accumulate state across calls and are not.
//
// # FIPS
//
// NewFIPSContext builds a Context restricted to the FIPS 140-3 validated
// module. Use it rather than loading the "fips" provider by hand: a FIPS
// provider load that fails its self-test puts the module into an error state
// that persists for the life of the process and cannot be recovered by any
// later, correct activation.
//
// # Errors
//
// A failure inside OpenSSL is reported as an *Error carrying the whole
// thread-local error queue. Two outcomes are deliberately not *Error, as
// they are expected results rather than faults: ErrVerification for a
// signature or an authentication tag that does not check out, and ErrClosed
// for use of a closed handle. Both compare with errors.Is.
//
// hash.Hash gives Sum no error return, so Hash and MAC latch failures and
// report them from Err. The one-shot helpers (Digest, DigestXOF, HMACSum)
// check that for you; if you drive Hash or MAC directly, check Err before
// trusting the bytes.
package ossl
