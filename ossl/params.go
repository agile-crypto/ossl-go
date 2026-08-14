//go:build cgo

package ossl

/*
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// params builds an OSSL_PARAM array for passing to OpenSSL 3.x.
//
// # Why this type exists
//
// OSSL_PARAM is how every algorithm-specific option is expressed in OpenSSL
// 3.x -- the digest for an HMAC, the curve for an EC key, the tag for an
// AEAD. Constructing one from Go runs straight into the cgo pointer rule:
//
//	Go memory passed to C must not itself contain Go pointers.
//
// An OSSL_PARAM is a struct of pointers. Building the array in Go and
// pointing its fields at Go variables is therefore forbidden.
// Go memory will contain Go pointers and the runtime pointer checker will
// abort the program. Building it with a Go pointer that the checker happens
// not to reach is worse: it is a live use-after-free waiting on the next GC
// cycle.
//
// So every referent -- key names, string values, octet blobs, and even plain
// integers, because the constructors store their address -- is copied into a
// C arena owned by this builder. The array itself may stay in Go memory: its
// fields then point only at C memory, which the checker permits and the GC
// cannot disturb.
//
// The second problem this solves is lifetime. A parameter array is a
// scattering of separate allocations, and freeing them individually at every
// error return can cause memory leaks if not handled properly.
// The arena collapses that to a single deferred call:
//
//	p := newParams()
//	defer p.free()
//	p.UTF8("digest", "SHA2-256").Octets("salt", salt)
//	C.EVP_KDF_derive(ctx, out, n, p.c())
type params struct {
	list  []C.OSSL_PARAM
	arena []unsafe.Pointer
	ended bool
	freed bool
}

func newParams() *params {
	return &params{list: make([]C.OSSL_PARAM, 0, 8)}
}

// alloc returns n zeroed bytes of C memory owned by the arena.
func (p *params) alloc(n int) unsafe.Pointer {
	if n <= 0 {
		n = 1
	}
	q := C.calloc(1, C.size_t(n))
	if q == nil {
		panic("ossl: C.calloc failed")
	}
	p.arena = append(p.arena, q)
	return q
}

// cstr copies a Go string into arena-owned C memory as a NUL-terminated
// string. Unlike C.CString the result needs no individual free.
func (p *params) cstr(s string) *C.char {
	q := p.alloc(len(s) + 1)
	if len(s) > 0 {
		C.memcpy(q, unsafe.Pointer(unsafe.StringData(s)), C.size_t(len(s)))
	}
	return (*C.char)(q)
}

// cbytes copies a Go byte slice into arena-owned C memory.
func (p *params) cbytes(b []byte) unsafe.Pointer {
	q := p.alloc(len(b))
	if len(b) > 0 {
		C.memcpy(q, unsafe.Pointer(&b[0]), C.size_t(len(b)))
	}
	return q
}

// UTF8 adds a string parameter, e.g. ("digest", "SHA2-256").
func (p *params) UTF8(key, val string) *params {
	p.list = append(p.list, C.OSSL_PARAM_construct_utf8_string(
		p.cstr(key), p.cstr(val), 0))
	return p
}

// Octets adds a binary parameter. The bytes are copied; the caller's slice
// may be reused or collected immediately.
func (p *params) Octets(key string, b []byte) *params {
	p.list = append(p.list, C.OSSL_PARAM_construct_octet_string(
		p.cstr(key), p.cbytes(b), C.size_t(len(b))))
	return p
}

// Int adds a signed integer parameter.
func (p *params) Int(key string, v int) *params {
	q := (*C.int)(p.alloc(C.sizeof_int))
	*q = C.int(v)
	p.list = append(p.list, C.OSSL_PARAM_construct_int(p.cstr(key), q))
	return p
}

// UInt adds an unsigned integer parameter.
func (p *params) UInt(key string, v uint) *params {
	q := (*C.uint)(p.alloc(C.sizeof_uint))
	*q = C.uint(v)
	p.list = append(p.list, C.OSSL_PARAM_construct_uint(p.cstr(key), q))
	return p
}

// SizeT adds a size_t parameter.
func (p *params) SizeT(key string, v int) *params {
	q := (*C.size_t)(p.alloc(C.sizeof_size_t))
	*q = C.size_t(v)
	p.list = append(p.list, C.OSSL_PARAM_construct_size_t(p.cstr(key), q))
	return p
}

// OctetsOut adds an output parameter of n bytes and returns the arena buffer
// backing it, for use with *_CTX_get_params. Read it with readOut after the
// call; do not retain the pointer past p.free.
func (p *params) OctetsOut(key string, n int) unsafe.Pointer {
	q := p.alloc(n)
	p.list = append(p.list, C.OSSL_PARAM_construct_octet_string(
		p.cstr(key), q, C.size_t(n)))
	return q
}

// readOut copies n bytes out of an arena buffer into a fresh Go slice.
func readOut(q unsafe.Pointer, n int) []byte {
	return C.GoBytes(q, C.int(n))
}

// OctetsNilData adds an octet-string parameter with a NULL data pointer and
// a declared size but no bytes to copy -- OpenSSL's convention (inherited
// from the ctrl-based API this replaces) for "set the desired length, there
// is nothing to supply yet", as distinct from a real value. CCM's tag-length
// declaration at encrypt time needs exactly this shape; a zeroed N-byte
// buffer from Octets is not equivalent and is silently ignored. No arena
// allocation is needed here: NULL is not a Go pointer, so the cgo pointer
// rule the rest of this file exists to satisfy does not apply to it.
func (p *params) OctetsNilData(key string, n int) *params {
	p.list = append(p.list, C.OSSL_PARAM_construct_octet_string(p.cstr(key), nil, C.size_t(n)))
	return p
}

// c terminates the array and returns a pointer to its first element.
//
// The returned pointer is valid only until free. Callers keep the builder
// reachable across the C call, which "defer p.free()" already guarantees.
func (p *params) c() *C.OSSL_PARAM {
	// Every referent this array points at lives in the freed arena, so the
	// array is not merely empty afterward -- it is dangling. Failing loudly
	// beats the alternatives: an index-out-of-range panic from deep inside
	// an unrelated call, or, once the array is repopulated, handing OpenSSL
	// pointers into memory that has already been returned to the allocator.
	if p.freed {
		panic("ossl: params used after free")
	}
	if !p.ended {
		p.list = append(p.list, C.OSSL_PARAM_construct_end())
		p.ended = true
	}
	return &p.list[0]
}

// free releases the whole arena. Idempotent.
func (p *params) free() {
	for _, q := range p.arena {
		C.free(q)
	}
	p.arena = nil
	p.list = nil
	p.freed = true
	runtime.KeepAlive(p)
}

// Canonical OSSL_PARAM key names.
//
// These are string constants in <openssl/core_names.h>. Restating them here as
// typed Go constants means a typo is a compile error rather than a parameter
// OpenSSL silently ignores -- which is the actual failure mode, and it
// presents as a wrong-looking result rather than an error.
const (
	pKeyDigest     = "digest"
	pKeyCipher     = "cipher"
	pKeyKey        = "key"
	pKeySalt       = "salt"
	pKeyInfo       = "info"
	pKeyMode       = "mode"
	pKeyIter       = "iter"
	pKeyPassword   = "pass"
	pKeySize       = "size"
	pKeyCustom     = "custom"
	pKeyRSABits    = "bits"
	pKeyGroupName  = "group"
	pKeyAEADTag    = "tag"
	pKeyAEADTagLen = "taglen"
	pKeyIVLen      = "ivlen"
	pKeyArgonLane  = "lanes"
	pKeyArgonMem   = "memcost"
	pKeyThreads    = "threads"
	pKeyEarlyClean = "early_clean"
	pKeyContext    = "context-string"
	pKeyInstance   = "instance"
	pKeyNonceType  = "nonce-type"
)
