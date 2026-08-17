//go:build cgo

package ossl

/*
#include <openssl/kdf.h>
#include <openssl/evp.h>
#include <openssl/thread.h>
*/
import "C"

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// threadBudget serialises the read-then-raise of a library context's thread
// budget. It is package-wide rather than per-Context because it guards an
// operation that is cheap and rare; contention is not a concern.
var threadBudget sync.Mutex

// deriveKDF is the generic path: fetch a KDF by name through this context,
// apply parameters, produce n bytes. Every named helper below is a thin
// wrapper over it, and it is exported as DeriveKDF so callers can reach KDFs
// this package has not grown a helper for (SSKDF, KBKDF, X963KDF, TLS13-KDF,
// KRB5KDF ...) without forking the layer.
func (c *Context) deriveKDF(name string, p *params, n int) ([]byte, error) {
	if c == nil {
		return nil, ErrClosed
	}
	if n <= 0 {
		return nil, fmt.Errorf("ossl: output length must be positive")
	}
	if n > maxOutputLength {
		return nil, fmt.Errorf("ossl: output length %d exceeds the maximum of %d bytes", n, maxOutputLength)
	}
	clearErrors()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	kdf := C.EVP_KDF_fetch(c.ptr(), cname, nil)
	if kdf == nil {
		return nil, newError("EVP_KDF_fetch(" + name + ")")
	}
	defer C.EVP_KDF_free(kdf)

	ctx := C.EVP_KDF_CTX_new(kdf)
	if ctx == nil {
		return nil, newError("EVP_KDF_CTX_new")
	}
	defer C.EVP_KDF_CTX_free(ctx)

	out := make([]byte, n)
	rc := C.EVP_KDF_derive(ctx, (*C.uchar)(unsafe.Pointer(&out[0])), C.size_t(n), p.c())
	runtime.KeepAlive(out)
	runtime.KeepAlive(p)
	if rc != 1 {
		return nil, newError("EVP_KDF_derive(" + name + ")")
	}
	return out, nil
}

// KDFParams is the caller-facing form of an OSSL_PARAM set for DeriveKDF.
// Keys are OpenSSL parameter names; values may be string, []byte, int or uint.
type KDFParams map[string]any

// DeriveKDF runs any KDF the provider offers.
//
//	key, err := ctx.DeriveKDF("SSKDF", ossl.KDFParams{
//	    "digest": "SHA2-256",
//	    "key":    sharedSecret,
//	    "info":   []byte("context"),
//	}, 32)
func (c *Context) DeriveKDF(name string, kp KDFParams, n int) ([]byte, error) {
	p := newParams()
	defer p.free()
	for k, v := range kp {
		switch t := v.(type) {
		case string:
			p.UTF8(k, t)
		case []byte:
			p.Octets(k, t)
		case int:
			p.Int(k, t)
		case uint:
			p.UInt(k, t)
		default:
			return nil, fmt.Errorf("ossl: unsupported parameter type %T for %q", v, k)
		}
	}
	return c.deriveKDF(name, p, n)
}

// HKDF performs RFC 5869 extract-and-expand.
//
// info is the domain separator: derive an encryption key and a MAC key from
// one secret by varying it. Reusing the same info for two purposes silently
// yields the same key twice.
func (c *Context) HKDF(digest string, secret, salt, info []byte, n int) ([]byte, error) {
	p := newParams().
		UTF8(pKeyDigest, digest).
		Octets(pKeyKey, secret).
		Octets(pKeySalt, salt).
		Octets(pKeyInfo, info).
		Int(pKeyMode, int(C.EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND))
	defer p.free()
	return c.deriveKDF("HKDF", p, n)
}

// HKDFExpand performs expand-only, for when the secret is already uniform
// (a KEM output that has been extracted, a PRK from a prior extract step).
func (c *Context) HKDFExpand(digest string, prk, info []byte, n int) ([]byte, error) {
	p := newParams().
		UTF8(pKeyDigest, digest).
		Octets(pKeyKey, prk).
		Octets(pKeyInfo, info).
		Int(pKeyMode, int(C.EVP_KDF_HKDF_MODE_EXPAND_ONLY))
	defer p.free()
	return c.deriveKDF("HKDF", p, n)
}

// maxPBKDF2Iterations bounds the work one PBKDF2 call may request.
//
// The bound exists because the cost is unbounded, uninterruptible and holds
// an OS thread: a cgo call cannot be cancelled, so an over-large count is a
// hang rather than a slow answer. Anywhere the iteration count arrives in a
// request, that is a denial of service with a four-byte payload. Ten million
// is well over an order of magnitude above OWASP's current guidance and
// still returns in seconds.
const maxPBKDF2Iterations = 10_000_000

// PBKDF2 derives a key from a password. iterations is a cost parameter;
// OWASP currently suggests at least 600000 for PBKDF2-HMAC-SHA256.
//
// iterations must be positive and no greater than ten million. A negative
// value is rejected rather than converted: OpenSSL takes an unsigned count,
// so -1 would silently become 4294967295 iterations and never return.
func (c *Context) PBKDF2(digest string, password, salt []byte, iterations, n int) ([]byte, error) {
	if iterations <= 0 {
		return nil, fmt.Errorf("ossl: PBKDF2 iterations must be positive, got %d", iterations)
	}
	if iterations > maxPBKDF2Iterations {
		return nil, fmt.Errorf("ossl: PBKDF2 iterations %d exceeds the maximum of %d",
			iterations, maxPBKDF2Iterations)
	}
	p := newParams().
		UTF8(pKeyDigest, digest).
		Octets(pKeyPassword, password).
		Octets(pKeySalt, salt).
		UInt(pKeyIter, uint(iterations))
	defer p.free()
	return c.deriveKDF("PBKDF2", p, n)
}

// Bounds on Argon2id's cost parameters, for the reason given on
// maxPBKDF2Iterations. The limits are far above any sensible configuration:
// 4 GiB of memory, 1024 lanes and ten thousand passes each cost far more
// than a real deployment would choose.
const (
	maxArgon2Iterations = 10_000
	maxArgon2MemoryKiB  = 4 * 1024 * 1024
	maxArgon2Lanes      = 1024
)

// Argon2idParams configures Argon2id. Zero fields take library defaults.
type Argon2idParams struct {
	Iterations uint // time cost
	MemoryKiB  uint // memory cost in kibibytes
	Lanes      uint // parallelism
}

// Argon2id derives a key from a password using Argon2id, which is preferable
// to PBKDF2 for new designs because its memory cost resists GPU attack.
//
// Note the threads parameter: requesting more than one thread requires the
// library context's thread budget to already allow it, checked here against
// this build directly rather than assumed. Asking EVP_KDF_derive for
// threads=2 with no budget raised fails with "invalid thread pool size:
// requested 2 threads, available: 0" -- threads=1 needs no budget at all,
// which is why the failure only shows up once Lanes > 1. The fix, per
// OSSL_set_max_threads's own manual, is to raise the context's budget
// before deriving.
//
// This only ever raises the budget, never lowers it, and never resets it
// back down afterward. OSSL_set_max_threads is context-wide, not scoped to
// this call: a caller sharing one Context across goroutines could have a
// concurrent Argon2id (or any other threaded KDF) relying on a budget this
// call would otherwise clobber by resetting it to 0 on the way out. Leaving
// the budget raised has no correctness cost -- it is a ceiling, and every
// other operation on the context just has more headroom than it strictly
// needs.
//
// The read and the raise are held under threadBudget for the same reason:
// separately they are a check-then-act, and two goroutines arriving together
// can each observe the old budget and the smaller request can then overwrite
// the larger one, dropping the ceiling below what the other call already
// depends on.
func (c *Context) Argon2id(password, salt []byte, ap Argon2idParams, n int) ([]byte, error) {
	if c == nil {
		return nil, ErrClosed
	}
	// Same reasoning as maxPBKDF2Iterations: these are cost parameters, the
	// call cannot be interrupted, and memcost is an allocation request as
	// well as a delay. Unbounded values taken from a request are a hang or
	// an out-of-memory kill, not a slow reply.
	if ap.Iterations > maxArgon2Iterations {
		return nil, fmt.Errorf("ossl: Argon2id iterations %d exceeds the maximum of %d",
			ap.Iterations, maxArgon2Iterations)
	}
	if ap.MemoryKiB > maxArgon2MemoryKiB {
		return nil, fmt.Errorf("ossl: Argon2id memory %d KiB exceeds the maximum of %d KiB",
			ap.MemoryKiB, maxArgon2MemoryKiB)
	}
	if ap.Lanes > maxArgon2Lanes {
		return nil, fmt.Errorf("ossl: Argon2id lanes %d exceeds the maximum of %d",
			ap.Lanes, maxArgon2Lanes)
	}
	if ap.Iterations == 0 {
		ap.Iterations = 3
	}
	if ap.MemoryKiB == 0 {
		ap.MemoryKiB = 64 * 1024
	}
	if ap.Lanes == 0 {
		ap.Lanes = 1
	}

	if ap.Lanes > 1 {
		threadBudget.Lock()
		raise := uint64(C.OSSL_get_max_threads(c.ptr())) < uint64(ap.Lanes)
		var err error
		if raise && C.OSSL_set_max_threads(c.ptr(), C.uint64_t(ap.Lanes)) != 1 {
			err = newError("OSSL_set_max_threads")
		}
		threadBudget.Unlock()
		if err != nil {
			return nil, err
		}
	}

	p := newParams().
		Octets(pKeyPassword, password).
		Octets(pKeySalt, salt).
		UInt(pKeyIter, ap.Iterations).
		UInt(pKeyArgonMem, ap.MemoryKiB).
		UInt(pKeyArgonLane, ap.Lanes).
		UInt(pKeyThreads, ap.Lanes).
		SizeT(pKeySize, n)
	defer p.free()
	return c.deriveKDF("ARGON2ID", p, n)
}
