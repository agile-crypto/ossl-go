//go:build cgo

package ossl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"fmt"
	"hash"
	"runtime"
	"unsafe"
)

// Hash is a message digest. It satisfies hash.Hash, so it drops into
// io.Copy, hmac.Equal, and anything else in the standard library that
// accepts one.
//
// Design note: hash.Hash has no error returns, but EVP calls do. Rather than
// panic or invent a parallel API, failures are latched and reported by Err.
// Write is effectively infallible once init has succeeded, but Sum is not --
// it rejects an XOF outright -- so Err is a result to check after Sum, not
// merely a safety net. The one-shot Digest does that for you.
//
// Not safe for concurrent use. Call Close when finished.
type Hash struct {
	ctx  *C.EVP_MD_CTX
	md   *C.EVP_MD
	name string
	size int
	bs   int
	xof  bool
	err  error
}

var _ hash.Hash = (*Hash)(nil)

// NewHash fetches a digest by OpenSSL name through this context: "SHA2-256",
// "SHA3-256", "SHAKE-256", "BLAKE2S-256", "SM3", and so on. Names are
// case-insensitive and aliased ("SHA256" and "SHA-256" both work).
func (c *Context) NewHash(name string) (*Hash, error) {
	if c == nil {
		return nil, ErrClosed
	}
	clearErrors()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	md := C.EVP_MD_fetch(c.ptr(), cname, nil)
	if md == nil {
		return nil, newError("EVP_MD_fetch(" + name + ")")
	}
	ctx := C.EVP_MD_CTX_new()
	if ctx == nil {
		C.EVP_MD_free(md)
		return nil, newError("EVP_MD_CTX_new")
	}
	if C.EVP_DigestInit_ex2(ctx, md, nil) != 1 {
		C.EVP_MD_CTX_free(ctx)
		C.EVP_MD_free(md)
		return nil, newError("EVP_DigestInit_ex2")
	}
	return &Hash{
		ctx:  ctx,
		md:   md,
		name: name,
		size: int(C.EVP_MD_get_size(md)),
		bs:   int(C.EVP_MD_get_block_size(md)),
		xof:  C.EVP_MD_xof(md) != 0,
	}, nil
}

// IsXOF reports whether this is an extendable-output function (SHAKE-128,
// SHAKE-256), which must be finalised with SumXOF rather than Sum.
func (h *Hash) IsXOF() bool {
	if h == nil {
		return false
	}
	return h.xof
}

func (h *Hash) Write(p []byte) (int, error) {
	if h == nil || h.ctx == nil {
		return 0, ErrClosed
	}
	if len(p) == 0 {
		return 0, nil // &p[0] would panic
	}
	// Zero-copy: C reads the Go slice for the duration of the call only.
	rc := C.EVP_DigestUpdate(h.ctx, unsafe.Pointer(&p[0]), C.size_t(len(p)))
	runtime.KeepAlive(p)
	if rc != 1 {
		h.err = newError("EVP_DigestUpdate")
		return 0, h.err
	}
	return len(p), nil
}

// Sum appends the digest to b without changing the hash state, as hash.Hash
// requires. The state is preserved by finalising a copy of the context.
//
// hash.Hash gives Sum no error return, so a failure is latched and reported
// by Err. Check it, or use the one-shot Digest, which checks for you: a
// silently empty return from this method would otherwise compare equal to
// every other empty return.
//
// An XOF (SHAKE-128, SHAKE-256) has no natural fixed-length digest and is
// rejected here rather than finalised at some arbitrary default length. Use
// SumXOF, which requires the caller to say how many bytes they want.
func (h *Hash) Sum(b []byte) []byte {
	if h == nil {
		return b
	}
	if h.ctx == nil {
		h.err = ErrClosed
		return b
	}
	if h.xof {
		h.err = fmt.Errorf("ossl: %s is an extendable-output function; use SumXOF(n), not Sum", h.name)
		return b
	}
	tmp := C.EVP_MD_CTX_new()
	if tmp == nil {
		h.err = newError("EVP_MD_CTX_new")
		return b
	}
	defer C.EVP_MD_CTX_free(tmp)

	if C.EVP_MD_CTX_copy_ex(tmp, h.ctx) != 1 {
		h.err = newError("EVP_MD_CTX_copy_ex")
		return b
	}
	out := make([]byte, C.EVP_MAX_MD_SIZE)
	var n C.uint
	rc := C.EVP_DigestFinal_ex(tmp, (*C.uchar)(unsafe.Pointer(&out[0])), &n)
	runtime.KeepAlive(out)
	if rc != 1 {
		h.err = newError("EVP_DigestFinal_ex")
		return b
	}
	return append(b, out[:n]...)
}

// SumXOF finalises an extendable-output function (SHAKE-128, SHAKE-256) to n
// bytes. Unlike Sum it consumes the state; the Hash must be Reset before
// reuse.
func (h *Hash) SumXOF(n int) ([]byte, error) {
	if h == nil || h.ctx == nil {
		return nil, ErrClosed
	}
	if n <= 0 {
		return nil, nil
	}
	if n > maxOutputLength {
		return nil, fmt.Errorf("ossl: XOF output length %d exceeds the maximum of %d bytes", n, maxOutputLength)
	}
	out := make([]byte, n)
	rc := C.EVP_DigestFinalXOF(h.ctx, (*C.uchar)(unsafe.Pointer(&out[0])), C.size_t(n))
	runtime.KeepAlive(out)
	if rc != 1 {
		return nil, newError("EVP_DigestFinalXOF")
	}
	return out, nil
}

// Reset returns the hash to its initial state.
func (h *Hash) Reset() {
	if h == nil || h.ctx == nil {
		return
	}
	if C.EVP_DigestInit_ex2(h.ctx, h.md, nil) != 1 {
		h.err = newError("EVP_DigestInit_ex2")
	}
}

func (h *Hash) Size() int {
	if h == nil {
		return 0
	}
	return h.size
}

func (h *Hash) BlockSize() int {
	if h == nil {
		return 0
	}
	return h.bs
}

func (h *Hash) Name() string {
	if h == nil {
		return ""
	}
	return h.name
}

// Err reports the first error latched by Write, Sum or Reset.
func (h *Hash) Err() error {
	if h == nil {
		return ErrClosed
	}
	return h.err
}

// Close releases the C context. Safe to call more than once.
func (h *Hash) Close() error {
	if h == nil {
		return nil
	}
	if h.ctx != nil {
		C.EVP_MD_CTX_free(h.ctx)
		h.ctx = nil
	}
	if h.md != nil {
		C.EVP_MD_free(h.md)
		h.md = nil
	}
	return nil
}

// Digest is the one-shot form against the global default context: fetch,
// hash, free. Use Context.NewHash directly for an isolated context.
//
// Sum latches its errors rather than returning them, so they are collected
// here explicitly. Returning a digest and a nil error without this check
// would mean handing back an empty slice that compares equal to every other
// failed digest.
func Digest(name string, data []byte) ([]byte, error) {
	h, err := Default.NewHash(name)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	sum := h.Sum(nil)
	if err := h.Err(); err != nil {
		return nil, err
	}
	return sum, nil
}

// DigestXOF is the one-shot form for SHAKE-128 / SHAKE-256 against the
// global default context.
func DigestXOF(name string, data []byte, n int) ([]byte, error) {
	h, err := Default.NewHash(name)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	return h.SumXOF(n)
}
