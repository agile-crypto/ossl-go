//go:build cgo

package ossl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"crypto/subtle"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// PaddingScheme selects how a block cipher's final partial block is filled.
//
// Only PKCS#7 is implemented by OpenSSL itself; the others are applied and
// removed here with OpenSSL's own padding switched off. They exist because
// interoperating with an existing system means matching whatever it does,
// not whatever is fashionable.
type PaddingScheme int

const (
	// PaddingPKCS7 is the default and the only one worth choosing for new
	// designs (RFC 5652 §6.3).
	PaddingPKCS7 PaddingScheme = iota
	// PaddingNone requires the plaintext to be a whole number of blocks.
	PaddingNone
	// PaddingISO7816 appends 0x80 then zeros (ISO/IEC 7816-4).
	PaddingISO7816
	// PaddingX923 appends zeros then a length byte (ANSI X9.23).
	PaddingX923
	// PaddingZero appends zeros only.
	//
	// This scheme is not reversible: trailing zero bytes that were part of
	// the plaintext are indistinguishable from padding, so Decrypt cannot
	// remove it and returns the padded plaintext as-is. Use it only where a
	// counterpart system requires it and the plaintext length is known by
	// other means.
	PaddingZero
)

func (p PaddingScheme) String() string {
	switch p {
	case PaddingPKCS7:
		return "PKCS#7"
	case PaddingNone:
		return "none"
	case PaddingISO7816:
		return "ISO/IEC 7816-4"
	case PaddingX923:
		return "ANSI X9.23"
	case PaddingZero:
		return "zero"
	default:
		return "unknown"
	}
}

// Cipher is a non-AEAD symmetric cipher: CBC, CTR, OFB, CFB, ECB.
//
// It provides no authentication. A ciphertext produced here can be modified
// undetectably, and CBC in particular is a padding oracle waiting for a
// caller who reports decryption failures. Prefer AEAD; reach for this only
// to interoperate with something that already exists.
//
// Safe for concurrent Encrypt and Decrypt, and against a concurrent Close,
// on the same terms as AEAD.
type Cipher struct {
	mu      sync.RWMutex
	cipher  *C.EVP_CIPHER
	key     []byte
	name    string
	ivLen   int
	blockSz int
	padding PaddingScheme
	stream  bool
	closed  bool
}

// CipherOption configures NewCipher.
type CipherOption func(*cipherConfig)

type cipherConfig struct {
	padding PaddingScheme
	ivLen   int
	ivSet   bool
}

// WithPadding selects the padding scheme. Ignored by stream modes, which
// have no blocks to pad.
func WithPadding(p PaddingScheme) CipherOption {
	return func(c *cipherConfig) { c.padding = p }
}

// WithCipherIVSize overrides the IV length, for the modes that allow one.
func WithCipherIVSize(n int) CipherOption {
	return func(c *cipherConfig) { c.ivLen = n; c.ivSet = true }
}

// NewCipher fetches a non-AEAD symmetric cipher: "AES-256-CBC",
// "AES-128-CTR", "AES-256-OFB", "AES-256-CFB", "ChaCha20".
//
// AEAD modes are refused here and belong to NewAEAD, which is the type that
// can carry associated data and a tag.
func (c *Context) NewCipher(name string, key []byte, opts ...CipherOption) (*Cipher, error) {
	if c == nil {
		return nil, ErrClosed
	}
	clearErrors()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	ci := C.EVP_CIPHER_fetch(c.ptr(), cname, nil)
	if ci == nil {
		return nil, newError("EVP_CIPHER_fetch(" + name + ")")
	}
	mode := C.EVP_CIPHER_get_mode(ci)
	if mode == C.EVP_CIPH_GCM_MODE || mode == C.EVP_CIPH_CCM_MODE ||
		mode == C.EVP_CIPH_OCB_MODE ||
		C.EVP_CIPHER_get_flags(ci)&C.EVP_CIPH_FLAG_AEAD_CIPHER != 0 {
		C.EVP_CIPHER_free(ci)
		return nil, fmt.Errorf("ossl: %s is an AEAD cipher; use NewAEAD so the tag and AAD are not silently dropped", name)
	}
	want := int(C.EVP_CIPHER_get_key_length(ci))
	if len(key) != want {
		C.EVP_CIPHER_free(ci)
		return nil, fmt.Errorf("ossl: %s needs a %d-byte key, got %d", name, want, len(key))
	}

	cfg := cipherConfig{padding: PaddingPKCS7, ivLen: int(C.EVP_CIPHER_get_iv_length(ci))}
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.ivSet && (cfg.ivLen < 0 || cfg.ivLen > 1024) {
		C.EVP_CIPHER_free(ci)
		return nil, fmt.Errorf("ossl: %s IV size %d is out of range", name, cfg.ivLen)
	}
	if cfg.padding < PaddingPKCS7 || cfg.padding > PaddingZero {
		C.EVP_CIPHER_free(ci)
		return nil, fmt.Errorf("ossl: unknown padding scheme %d", int(cfg.padding))
	}

	blockSz := int(C.EVP_CIPHER_get_block_size(ci))
	return &Cipher{
		cipher:  ci,
		key:     append([]byte(nil), key...),
		name:    name,
		ivLen:   cfg.ivLen,
		blockSz: blockSz,
		padding: cfg.padding,
		stream:  blockSz == 1,
	}, nil
}

// IVSize is the IV length in bytes, 0 for modes that take none (ECB).
func (x *Cipher) IVSize() int {
	if x == nil {
		return 0
	}
	return x.ivLen
}

// BlockSize is the cipher's block size, 1 for stream modes.
func (x *Cipher) BlockSize() int {
	if x == nil {
		return 0
	}
	return x.blockSz
}

// Name reports the algorithm name.
func (x *Cipher) Name() string {
	if x == nil {
		return ""
	}
	return x.name
}

// Padding reports the configured padding scheme.
func (x *Cipher) Padding() PaddingScheme {
	if x == nil {
		return PaddingPKCS7
	}
	return x.padding
}

func (x *Cipher) checkIV(iv []byte) error {
	if len(iv) != x.ivLen {
		return fmt.Errorf("ossl: %s needs a %d-byte IV, got %d", x.name, x.ivLen, len(iv))
	}
	return nil
}

// Encrypt encrypts plaintext, appending the result to dst.
func (x *Cipher) Encrypt(dst, iv, plaintext []byte) ([]byte, error) {
	if x == nil {
		return nil, ErrClosed
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.closed {
		return nil, ErrClosed
	}
	if err := x.checkIV(iv); err != nil {
		return nil, err
	}

	in := plaintext
	// OpenSSL only knows PKCS#7. Everything else is applied here with its
	// padding disabled, which also means the input must already be a whole
	// number of blocks by the time it reaches EVP.
	if !x.stream && x.padding != PaddingPKCS7 {
		padded, err := applyPadding(x.padding, plaintext, x.blockSz)
		if err != nil {
			return nil, err
		}
		in = padded
	}
	if !x.stream && x.padding == PaddingNone && len(in)%x.blockSz != 0 {
		return nil, fmt.Errorf("ossl: %s with no padding needs a multiple of %d bytes, got %d",
			x.name, x.blockSz, len(plaintext))
	}

	out, err := x.run(iv, in, true)
	if err != nil {
		return nil, err
	}
	return append(dst, out...), nil
}

// Decrypt decrypts ciphertext, appending the plaintext to dst.
//
// A padding failure is reported as ErrVerification with no further detail.
// That is deliberate: CBC padding errors are the classic padding oracle, and
// a caller who forwards a distinguishable error to a peer rebuilds it.
func (x *Cipher) Decrypt(dst, iv, ciphertext []byte) ([]byte, error) {
	if x == nil {
		return nil, ErrClosed
	}
	x.mu.RLock()
	defer x.mu.RUnlock()
	if x.closed {
		return nil, ErrClosed
	}
	if err := x.checkIV(iv); err != nil {
		return nil, err
	}
	if !x.stream && len(ciphertext)%x.blockSz != 0 {
		return nil, ErrVerification
	}

	out, err := x.run(iv, ciphertext, false)
	if err != nil {
		// A CBC decrypt failure here is almost always bad PKCS#7 padding.
		clearErrors()
		return nil, ErrVerification
	}
	if !x.stream && x.padding != PaddingPKCS7 {
		out, err = removePadding(x.padding, out, x.blockSz)
		if err != nil {
			return nil, err
		}
	}
	return append(dst, out...), nil
}

// run performs one complete Init/Update/Final cycle in a fresh context, so
// that concurrent calls share nothing but the immutable cipher and key.
func (x *Cipher) run(iv, in []byte, encrypt bool) ([]byte, error) {
	clearErrors()
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, newError("EVP_CIPHER_CTX_new")
	}
	defer C.EVP_CIPHER_CTX_free(ctx)

	var ivp *C.uchar
	if len(iv) > 0 {
		ivp = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}
	keyp := (*C.uchar)(unsafe.Pointer(&x.key[0]))

	var rc C.int
	if encrypt {
		rc = C.EVP_EncryptInit_ex2(ctx, x.cipher, keyp, ivp, nil)
	} else {
		rc = C.EVP_DecryptInit_ex2(ctx, x.cipher, keyp, ivp, nil)
	}
	runtime.KeepAlive(x.key)
	runtime.KeepAlive(iv)
	if rc != 1 {
		return nil, newError("cipher init")
	}

	// Padding other than PKCS#7 is handled in Go, so EVP must not also add
	// or strip a block of its own.
	pad := C.int(1)
	if x.padding != PaddingPKCS7 {
		pad = 0
	}
	if !x.stream {
		if C.EVP_CIPHER_CTX_set_padding(ctx, pad) != 1 {
			return nil, newError("EVP_CIPHER_CTX_set_padding")
		}
	}

	buf := make([]byte, len(in)+x.blockSz+C.EVP_MAX_BLOCK_LENGTH)
	var n C.int
	total := 0
	if len(in) > 0 {
		if encrypt {
			rc = C.EVP_EncryptUpdate(ctx, (*C.uchar)(unsafe.Pointer(&buf[0])), &n,
				(*C.uchar)(unsafe.Pointer(&in[0])), C.int(len(in)))
		} else {
			rc = C.EVP_DecryptUpdate(ctx, (*C.uchar)(unsafe.Pointer(&buf[0])), &n,
				(*C.uchar)(unsafe.Pointer(&in[0])), C.int(len(in)))
		}
		runtime.KeepAlive(in)
		if rc != 1 {
			Zero(buf)
			return nil, newError("cipher update")
		}
		total = int(n)
	}
	if encrypt {
		rc = C.EVP_EncryptFinal_ex(ctx, (*C.uchar)(unsafe.Pointer(&buf[total])), &n)
	} else {
		rc = C.EVP_DecryptFinal_ex(ctx, (*C.uchar)(unsafe.Pointer(&buf[total])), &n)
	}
	if rc != 1 {
		Zero(buf)
		return nil, newError("cipher final")
	}
	total += int(n)
	runtime.KeepAlive(buf)
	return buf[:total], nil
}

// Close releases the cipher and cleanses the retained key.
func (x *Cipher) Close() error {
	if x == nil {
		return nil
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if !x.closed {
		C.EVP_CIPHER_free(x.cipher)
		x.cipher = nil
		Zero(x.key)
		x.key = nil
		x.closed = true
	}
	return nil
}

// applyPadding fills the final block per the named scheme.
func applyPadding(p PaddingScheme, in []byte, block int) ([]byte, error) {
	switch p {
	case PaddingNone:
		return in, nil
	case PaddingZero:
		n := block - len(in)%block
		if n == block {
			n = 0
		}
		return append(append([]byte(nil), in...), make([]byte, n)...), nil
	case PaddingISO7816:
		n := block - len(in)%block
		out := append(append([]byte(nil), in...), 0x80)
		return append(out, make([]byte, n-1)...), nil
	case PaddingX923:
		n := block - len(in)%block
		out := append(append([]byte(nil), in...), make([]byte, n-1)...)
		return append(out, byte(n)), nil
	default:
		return nil, fmt.Errorf("ossl: padding scheme %v is applied by OpenSSL, not here", p)
	}
}

// removePadding strips the final block's padding.
//
// The checks are written to run in constant time with respect to the padding
// bytes, and every failure returns the same bare ErrVerification, for the
// padding-oracle reason given on Decrypt.
func removePadding(p PaddingScheme, in []byte, block int) ([]byte, error) {
	switch p {
	case PaddingNone:
		return in, nil
	case PaddingZero:
		// Not reversible; see the PaddingZero doc.
		return in, nil
	case PaddingISO7816:
		if len(in) == 0 {
			return nil, ErrVerification
		}
		i := len(in) - 1
		for i >= 0 && in[i] == 0x00 {
			i--
		}
		if i < 0 || in[i] != 0x80 {
			return nil, ErrVerification
		}
		return in[:i], nil
	case PaddingX923:
		if len(in) == 0 || len(in)%block != 0 {
			return nil, ErrVerification
		}
		n := int(in[len(in)-1])
		if n == 0 || n > block || n > len(in) {
			return nil, ErrVerification
		}
		var acc byte
		for _, b := range in[len(in)-n : len(in)-1] {
			acc |= b
		}
		if subtle.ConstantTimeByteEq(acc, 0) != 1 {
			return nil, ErrVerification
		}
		return in[:len(in)-n], nil
	default:
		return in, nil
	}
}

// ---------------------------------------------------------------------------
// Key wrapping
// ---------------------------------------------------------------------------

// KeyWrap encrypts key material under a key-encryption key using the NIST
// AES Key Wrap construction.
//
// This is not a general-purpose cipher and must not be used as one. It takes
// no nonce, is deterministic, and is defined only for wrapping keys, which
// is exactly why it needs no IV to be safe: the inputs are high-entropy and
// wrapped once.
//
// Safe for concurrent use. Close when done.
type KeyWrap struct {
	mu     sync.RWMutex
	cipher *C.EVP_CIPHER
	kek    []byte
	name   string
	padded bool
	closed bool
}

// NewKeyWrap creates an AES Key Wrap under the given key-encryption key.
//
// withPadding selects AES-KWP (RFC 5649), which accepts key material of any
// length; without it, AES-KW (RFC 3394) requires a multiple of 8 bytes and
// at least 16. The KEK length determines AES-128/192/256.
func (c *Context) NewKeyWrap(kek []byte, withPadding bool) (*KeyWrap, error) {
	if c == nil {
		return nil, ErrClosed
	}
	var name string
	switch len(kek) {
	case 16:
		name = "AES-128-WRAP"
	case 24:
		name = "AES-192-WRAP"
	case 32:
		name = "AES-256-WRAP"
	default:
		return nil, fmt.Errorf("ossl: key wrap needs a 16, 24 or 32-byte KEK, got %d", len(kek))
	}
	if withPadding {
		name += "-PAD"
	}

	clearErrors()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	ci := C.EVP_CIPHER_fetch(c.ptr(), cname, nil)
	if ci == nil {
		return nil, newError("EVP_CIPHER_fetch(" + name + ")")
	}
	return &KeyWrap{
		cipher: ci,
		kek:    append([]byte(nil), kek...),
		name:   name,
		padded: withPadding,
	}, nil
}

// Name reports the wrapping algorithm.
func (w *KeyWrap) Name() string {
	if w == nil {
		return ""
	}
	return w.name
}

func (w *KeyWrap) run(in []byte, wrap bool) ([]byte, error) {
	clearErrors()
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, newError("EVP_CIPHER_CTX_new")
	}
	defer C.EVP_CIPHER_CTX_free(ctx)

	// Without this flag EVP refuses wrap-mode ciphers outright, which is a
	// deliberate guard against them being used as ordinary ciphers.
	C.EVP_CIPHER_CTX_set_flags(ctx, C.EVP_CIPHER_CTX_FLAG_WRAP_ALLOW)

	keyp := (*C.uchar)(unsafe.Pointer(&w.kek[0]))
	var rc C.int
	if wrap {
		rc = C.EVP_EncryptInit_ex2(ctx, w.cipher, keyp, nil, nil)
	} else {
		rc = C.EVP_DecryptInit_ex2(ctx, w.cipher, keyp, nil, nil)
	}
	runtime.KeepAlive(w.kek)
	if rc != 1 {
		return nil, newError("key wrap init")
	}

	// Wrapping adds at most one block plus eight bytes of integrity check.
	buf := make([]byte, len(in)+C.EVP_MAX_BLOCK_LENGTH+16)
	var n C.int
	total := 0
	if wrap {
		rc = C.EVP_EncryptUpdate(ctx, (*C.uchar)(unsafe.Pointer(&buf[0])), &n,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.int(len(in)))
	} else {
		rc = C.EVP_DecryptUpdate(ctx, (*C.uchar)(unsafe.Pointer(&buf[0])), &n,
			(*C.uchar)(unsafe.Pointer(&in[0])), C.int(len(in)))
	}
	runtime.KeepAlive(in)
	if rc != 1 {
		Zero(buf)
		return nil, newError("key wrap update")
	}
	total = int(n)

	if wrap {
		rc = C.EVP_EncryptFinal_ex(ctx, (*C.uchar)(unsafe.Pointer(&buf[total])), &n)
	} else {
		rc = C.EVP_DecryptFinal_ex(ctx, (*C.uchar)(unsafe.Pointer(&buf[total])), &n)
	}
	if rc != 1 {
		Zero(buf)
		return nil, newError("key wrap final")
	}
	total += int(n)
	runtime.KeepAlive(buf)
	return buf[:total], nil
}

// Wrap encrypts key material under the KEK.
func (w *KeyWrap) Wrap(keyMaterial []byte) ([]byte, error) {
	if w == nil {
		return nil, ErrClosed
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return nil, ErrClosed
	}
	if len(keyMaterial) == 0 {
		return nil, fmt.Errorf("ossl: nothing to wrap")
	}
	if !w.padded && (len(keyMaterial) < 16 || len(keyMaterial)%8 != 0) {
		return nil, fmt.Errorf(
			"ossl: AES-KW needs at least 16 bytes in multiples of 8, got %d; use padding for arbitrary lengths",
			len(keyMaterial))
	}
	return w.run(keyMaterial, true)
}

// Unwrap recovers key material.
//
// The integrity check built into the construction is what makes a wrong KEK
// or a tampered blob detectable. A failure is ErrVerification with no
// detail, for the same reason AEAD.Open gives none.
func (w *KeyWrap) Unwrap(wrapped []byte) ([]byte, error) {
	if w == nil {
		return nil, ErrClosed
	}
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return nil, ErrClosed
	}
	if len(wrapped) < 16 || len(wrapped)%8 != 0 {
		return nil, ErrVerification
	}
	out, err := w.run(wrapped, false)
	if err != nil {
		clearErrors()
		return nil, ErrVerification
	}
	return out, nil
}

// Close releases the cipher and cleanses the retained KEK.
func (w *KeyWrap) Close() error {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		C.EVP_CIPHER_free(w.cipher)
		w.cipher = nil
		Zero(w.kek)
		w.kek = nil
		w.closed = true
	}
	return nil
}
