//go:build cgo

package ossl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"crypto/subtle"
	"hash"
	"runtime"
	"unsafe"
)

// MAC is a message authentication code. One type covers HMAC, CMAC, KMAC,
// GMAC, Poly1305 and SipHash, because OpenSSL 3.x unified them behind
// EVP_MAC: the key goes to init, and everything else -- which digest, which
// cipher, what output length -- is an OSSL_PARAM.
//
// It satisfies hash.Hash, so hmac.Equal and io.Copy work on it directly.
type MAC struct {
	mac  *C.EVP_MAC
	ctx  *C.EVP_MAC_CTX
	key  []byte
	p    *params // retained so Reset can re-init with the same options
	size int
	bs   int
	err  error
}

var _ hash.Hash = (*MAC)(nil)

// newMAC is the single constructor the public ones funnel into.
func (c *Context) newMAC(algorithm string, key []byte, p *params) (*MAC, error) {
	clearErrors()
	calg := C.CString(algorithm)
	defer C.free(unsafe.Pointer(calg))

	m := C.EVP_MAC_fetch(c.ptr(), calg, nil)
	if m == nil {
		p.free()
		return nil, newError("EVP_MAC_fetch(" + algorithm + ")")
	}
	ctx := C.EVP_MAC_CTX_new(m)
	if ctx == nil {
		C.EVP_MAC_free(m)
		p.free()
		return nil, newError("EVP_MAC_CTX_new")
	}

	// Copy the key so Reset can re-init with it after the caller has moved
	// on, and so a caller mutating their slice cannot change this MAC's key
	// underneath it.
	//
	// The copy is still Go memory and is still passed to C as a Go pointer,
	// which is permitted only because EVP_MAC_init copies the key into the
	// context rather than retaining the pointer. Anything that did retain it
	// would need C-owned memory instead, the way params does.
	k := append([]byte(nil), key...)

	mm := &MAC{mac: m, ctx: ctx, key: k, p: p}
	if err := mm.init(); err != nil {
		mm.Close()
		return nil, err
	}
	mm.size = int(C.EVP_MAC_CTX_get_mac_size(ctx))
	mm.bs = int(C.EVP_MAC_CTX_get_block_size(ctx))
	return mm, nil
}

func (m *MAC) init() error {
	var kp *C.uchar
	if len(m.key) > 0 {
		kp = (*C.uchar)(unsafe.Pointer(&m.key[0]))
	}
	rc := C.EVP_MAC_init(m.ctx, kp, C.size_t(len(m.key)), m.p.c())
	runtime.KeepAlive(m.key)
	runtime.KeepAlive(m.p)
	if rc != 1 {
		return newError("EVP_MAC_init")
	}
	return nil
}

// NewHMAC returns an HMAC using the named digest, e.g. NewHMAC("SHA2-256", k).
func (c *Context) NewHMAC(digest string, key []byte) (*MAC, error) {
	p := newParams().UTF8(pKeyDigest, digest)
	return c.newMAC("HMAC", key, p)
}

// NewCMAC returns a CMAC over the named block cipher, e.g. "AES-256-CBC".
func (c *Context) NewCMAC(cipher string, key []byte) (*MAC, error) {
	p := newParams().UTF8(pKeyCipher, cipher)
	return c.newMAC("CMAC", key, p)
}

// NewKMAC returns a KMAC-128 or KMAC-256 producing outLen bytes. custom is an
// optional domain-separation string and may be nil.
func (c *Context) NewKMAC(bits int, key []byte, outLen int, custom []byte) (*MAC, error) {
	alg := "KMAC-128"
	if bits == 256 {
		alg = "KMAC-256"
	}
	p := newParams().SizeT(pKeySize, outLen)
	if len(custom) > 0 {
		p = p.Octets(pKeyCustom, custom)
	}
	return c.newMAC(alg, key, p)
}

func (m *MAC) Write(b []byte) (int, error) {
	if m.ctx == nil {
		return 0, ErrClosed
	}
	if len(b) == 0 {
		return 0, nil
	}
	rc := C.EVP_MAC_update(m.ctx, (*C.uchar)(unsafe.Pointer(&b[0])), C.size_t(len(b)))
	runtime.KeepAlive(b)
	if rc != 1 {
		m.err = newError("EVP_MAC_update")
		return 0, m.err
	}
	return len(b), nil
}

// Sum appends the tag to b, leaving the MAC state intact.
func (m *MAC) Sum(b []byte) []byte {
	if m.ctx == nil {
		m.err = ErrClosed
		return b
	}
	dup := C.EVP_MAC_CTX_dup(m.ctx)
	if dup == nil {
		m.err = newError("EVP_MAC_CTX_dup")
		return b
	}
	defer C.EVP_MAC_CTX_free(dup)

	size := m.size
	if size <= 0 {
		size = 64
	}
	out := make([]byte, size)
	var n C.size_t
	rc := C.EVP_MAC_final(dup, (*C.uchar)(unsafe.Pointer(&out[0])), &n, C.size_t(len(out)))
	runtime.KeepAlive(out)
	if rc != 1 {
		m.err = newError("EVP_MAC_final")
		return b
	}
	return append(b, out[:n]...)
}

// Reset restores the initial state, reusing the key and options.
func (m *MAC) Reset() {
	if m.ctx == nil {
		return
	}
	if err := m.init(); err != nil {
		m.err = err
	}
}

func (m *MAC) Size() int      { return m.size }
func (m *MAC) BlockSize() int { return m.bs }
func (m *MAC) Err() error     { return m.err }

// Close releases C resources and cleanses the retained key copy.
func (m *MAC) Close() error {
	if m.ctx != nil {
		C.EVP_MAC_CTX_free(m.ctx)
		m.ctx = nil
	}
	if m.mac != nil {
		C.EVP_MAC_free(m.mac)
		m.mac = nil
	}
	if m.p != nil {
		m.p.free()
		m.p = nil
	}
	Zero(m.key)
	m.key = nil
	return nil
}

// HMACSum is the one-shot form against the global default context.
//
// As in Digest, Sum's latched error is collected explicitly: an unchecked
// Sum can return an empty tag, and an empty tag compares equal to every
// other empty tag.
func HMACSum(digest string, key, data []byte) ([]byte, error) {
	m, err := Default.NewHMAC(digest, key)
	if err != nil {
		return nil, err
	}
	defer m.Close()
	if _, err := m.Write(data); err != nil {
		return nil, err
	}
	sum := m.Sum(nil)
	if err := m.Err(); err != nil {
		return nil, err
	}
	return sum, nil
}

// EqualMAC compares two tags in constant time.
//
// Exported deliberately: a wrapper that hands back tags without also handing
// back a safe comparison invites callers to reach for bytes.Equal, whose
// early return leaks the position of the first differing byte and permits
// forging a tag one byte at a time.
func EqualMAC(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
