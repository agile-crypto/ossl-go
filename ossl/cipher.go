//go:build cgo

package ossl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"crypto/cipher"
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// AEAD is an authenticated cipher. It implements crypto/cipher.AEAD, so it is
// a drop-in for crypto/aes + crypto/cipher.NewGCM at the call site:
//
//	aead, err := ctx.NewAEAD("AES-256-GCM", key)
//	defer aead.Close()
//	ct := aead.Seal(nil, nonce, plaintext, aad)
//
// Switching to "ChaCha20-Poly1305" is a change of one string, which is the
// practical shape of algorithm agility at this layer.
//
// The IV length defaults to the algorithm's own (12 bytes for GCM, CCM and
// ChaCha20-Poly1305) and the tag length defaults to 16 for every algorithm,
// which is the maximum each of them supports. Both can be overridden with
// WithIVSize and WithTagSize -- CCM in particular needs this, since NIST SP
// 800-38C defines valid nonce lengths as 7-13 bytes and tag lengths as even
// values 4-16.
//
// Safe for concurrent Seal and Open: each operation builds its own
// EVP_CIPHER_CTX, at the cost of an allocation per call. Close is serialised
// against in-flight operations, so closing an AEAD another goroutine is
// still using is safe -- that goroutine gets ErrClosed rather than a
// use-after-free on the underlying EVP_CIPHER.
type AEAD struct {
	mu     sync.RWMutex
	cipher *C.EVP_CIPHER
	key    []byte
	name   string
	nonce  int
	tag    int
	ccm    bool
	closed bool
}

var _ cipher.AEAD = (*AEAD)(nil)

// AEADOption configures NewAEAD beyond the algorithm's own defaults.
type AEADOption func(*aeadConfig)

type aeadConfig struct {
	ivLen  int
	tagLen int
}

// WithIVSize overrides the nonce/IV length in bytes. Only some algorithms
// accept a non-default length -- ChaCha20-Poly1305 has none, GCM allows a
// wide range, CCM requires 7-13 bytes per NIST SP 800-38C.
//
// NewAEAD rejects a length outside the range the mode permits. A length that
// is in range but that the specific algorithm still refuses surfaces at the
// first Seal or Open, from EVP_EncryptInit_ex2/EVP_DecryptInit_ex2.
func WithIVSize(n int) AEADOption {
	return func(c *aeadConfig) { c.ivLen = n }
}

// WithTagSize overrides the authentication tag length in bytes. CCM requires
// an even value from 4 to 16 and treats it as a real cryptographic parameter
// of the MAC computation, not mere truncation; GCM and OCB compute a full
// 16-byte tag regardless and accept a shorter declared length only as a
// truncation, for protocols that expect one (e.g. 12 bytes instead of 16).
//
// Because truncation is pure strength reduction, NewAEAD holds those modes
// to a 12-byte floor: a tag short enough to guess is not a failure any test
// of this package's own round trip would surface, since encrypt and decrypt
// agree on the weak parameter perfectly well.
func WithTagSize(n int) AEADOption {
	return func(c *aeadConfig) { c.tagLen = n }
}

// NewAEAD fetches an AEAD cipher by OpenSSL name through this context:
// "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-OCB",
// "AES-256-CCM".
func (c *Context) NewAEAD(name string, key []byte, opts ...AEADOption) (*AEAD, error) {
	clearErrors()
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))

	ci := C.EVP_CIPHER_fetch(c.ptr(), cname, nil)
	if ci == nil {
		return nil, newError("EVP_CIPHER_fetch(" + name + ")")
	}
	want := int(C.EVP_CIPHER_get_key_length(ci))
	if len(key) != want {
		C.EVP_CIPHER_free(ci)
		return nil, fmt.Errorf("ossl: %s needs a %d-byte key, got %d", name, want, len(key))
	}
	mode := C.EVP_CIPHER_get_mode(ci)
	if mode != C.EVP_CIPH_GCM_MODE &&
		mode != C.EVP_CIPH_OCB_MODE &&
		mode != C.EVP_CIPH_CCM_MODE &&
		C.EVP_CIPHER_get_flags(ci)&C.EVP_CIPH_FLAG_AEAD_CIPHER == 0 {
		C.EVP_CIPHER_free(ci)
		return nil, fmt.Errorf("ossl: %s is not an AEAD cipher", name)
	}

	cfg := aeadConfig{
		ivLen:  int(C.EVP_CIPHER_get_iv_length(ci)),
		tagLen: 16,
	}
	for _, o := range opts {
		o(&cfg)
	}
	if err := validateAEADSizes(name, mode == C.EVP_CIPH_CCM_MODE, cfg); err != nil {
		C.EVP_CIPHER_free(ci)
		return nil, err
	}

	return &AEAD{
		cipher: ci,
		key:    append([]byte(nil), key...),
		name:   name,
		nonce:  cfg.ivLen,
		tag:    cfg.tagLen,
		ccm:    mode == C.EVP_CIPH_CCM_MODE,
	}, nil
}

// validateAEADSizes rejects nonce and tag lengths that the standards do not
// permit, at construction time rather than at first use.
//
// Without this, WithTagSize(1) produced a working AEAD with an 8-bit
// authentication tag, and WithIVSize(0) reached a zero-length nonce slice
// and panicked inside the init path instead of returning an error. Neither
// is something a caller can be expected to catch by inspection: both round
// trip cleanly against themselves, so a test that only checks Seal-then-Open
// passes while the construction is worthless.
//
// CCM's range is wider than everything else's on purpose: SP 800-38C defines
// tags down to 32 bits as valid parameters of the MAC, and citius-server's
// AesCcmParams accepts exactly that range. GCM, OCB and ChaCha20-Poly1305
// truncate a full 16-byte tag instead, where a short tag is pure strength
// reduction, so the floor there is the 96 bits SP 800-38D calls for.
func validateAEADSizes(name string, ccm bool, cfg aeadConfig) error {
	if ccm {
		if cfg.ivLen < 7 || cfg.ivLen > 13 {
			return fmt.Errorf("ossl: %s nonce must be 7-13 bytes per NIST SP 800-38C, got %d", name, cfg.ivLen)
		}
		if cfg.tagLen < 4 || cfg.tagLen > 16 || cfg.tagLen%2 != 0 {
			return fmt.Errorf("ossl: %s tag must be an even 4-16 bytes per NIST SP 800-38C, got %d", name, cfg.tagLen)
		}
		return nil
	}
	if cfg.ivLen < 1 {
		return fmt.Errorf("ossl: %s nonce must be at least 1 byte, got %d", name, cfg.ivLen)
	}
	if cfg.tagLen < 12 || cfg.tagLen > 16 {
		return fmt.Errorf("ossl: %s tag must be 12-16 bytes, got %d", name, cfg.tagLen)
	}
	return nil
}

func (a *AEAD) NonceSize() int { return a.nonce }
func (a *AEAD) Overhead() int  { return a.tag }
func (a *AEAD) Name() string   { return a.name }

// Seal encrypts and authenticates, appending ciphertext||tag to dst.
//
// It panics on a wrong-sized nonce, matching crypto/cipher.AEAD. Every other
// failure is a library fault and also panics, because the interface has no
// error return; use SealErr if you need one.
func (a *AEAD) Seal(dst, nonce, plaintext, aad []byte) []byte {
	out, err := a.SealErr(dst, nonce, plaintext, aad)
	if err != nil {
		panic(err)
	}
	return out
}

// SealErr is Seal with an error return.
//
// NEVER reuse a nonce with the same key. For GCM this does not merely leak
// the XOR of two plaintexts, it exposes the authentication subkey and permits
// arbitrary forgery. A random 96-bit nonce is safe to roughly 2^32 messages
// per key; a strictly increasing counter is safer.
func (a *AEAD) SealErr(dst, nonce, plaintext, aad []byte) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return nil, ErrClosed
	}
	if len(nonce) != a.nonce {
		return nil, fmt.Errorf("ossl: nonce must be %d bytes, got %d", a.nonce, len(nonce))
	}
	clearErrors()

	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, newError("EVP_CIPHER_CTX_new")
	}
	defer C.EVP_CIPHER_CTX_free(ctx)

	if err := initEncrypt(ctx, a, nonce); err != nil {
		return nil, err
	}
	runtime.KeepAlive(a.key)
	runtime.KeepAlive(nonce)

	var n C.int
	if a.ccm {
		// CCM must be told the total plaintext length before AAD: unlike
		// GCM/OCB/ChaCha20-Poly1305, it needs the length upfront to compute
		// the MAC, not just to size an output buffer. NULL in, NULL out,
		// the length itself in inl -- the same "declare, don't transfer"
		// shape AAD already uses, one parameter further.
		if C.EVP_EncryptUpdate(ctx, nil, &n, nil, C.int(len(plaintext))) != 1 {
			return nil, newError("EVP_EncryptUpdate(length hint)")
		}
	}
	if len(aad) > 0 {
		// AAD goes through Update with a NULL output pointer.
		if C.EVP_EncryptUpdate(ctx, nil, &n,
			(*C.uchar)(unsafe.Pointer(&aad[0])), C.int(len(aad))) != 1 {
			return nil, newError("EVP_EncryptUpdate(aad)")
		}
		runtime.KeepAlive(aad)
	}

	buf := make([]byte, len(plaintext)+C.EVP_MAX_BLOCK_LENGTH)
	total := 0
	if len(plaintext) > 0 {
		if C.EVP_EncryptUpdate(ctx, (*C.uchar)(unsafe.Pointer(&buf[0])), &n,
			(*C.uchar)(unsafe.Pointer(&plaintext[0])), C.int(len(plaintext))) != 1 {
			return nil, newError("EVP_EncryptUpdate")
		}
		runtime.KeepAlive(plaintext)
		total = int(n)
	} else if a.ccm {
		// CCM needs an explicit data Update call even for empty plaintext,
		// not just the length hint above -- verified directly: without
		// this, the tag came back unfinalized ("tag not set") on the
		// encrypt side, and on decrypt a tampered AAD was silently
		// accepted at Final instead of being rejected. Length 0 means
		// neither pointer is actually dereferenced, so reusing buf (always
		// at least EVP_MAX_BLOCK_LENGTH bytes) for both is safe.
		if C.EVP_EncryptUpdate(ctx, (*C.uchar)(unsafe.Pointer(&buf[0])), &n,
			(*C.uchar)(unsafe.Pointer(&buf[0])), 0) != 1 {
			return nil, newError("EVP_EncryptUpdate(empty)")
		}
	}
	if C.EVP_EncryptFinal_ex(ctx, (*C.uchar)(unsafe.Pointer(&buf[total])), &n) != 1 {
		return nil, newError("EVP_EncryptFinal_ex")
	}
	total += int(n)
	runtime.KeepAlive(buf)

	// The tag only exists after Final.
	p := newParams()
	defer p.free()
	tagBuf := p.OctetsOut(pKeyAEADTag, a.tag)
	if C.EVP_CIPHER_CTX_get_params(ctx, p.c()) != 1 {
		return nil, newError("EVP_CIPHER_CTX_get_params(tag)")
	}

	dst = append(dst, buf[:total]...)
	dst = append(dst, readOut(tagBuf, a.tag)...)
	return dst, nil
}

// initEncrypt installs the cipher, IV length, tag length, key and nonce.
//
// CCM needs this split into two EVP_EncryptInit_ex2 calls -- sizes first
// (cipher + params, no key/IV), key and IV second (no cipher, no params) --
// verified directly: declaring a non-default tag length in the same call as
// the key/IV, which is what GCM/OCB/ChaCha20-Poly1305 all accept, was
// silently ignored for CCM. Every non-default length came back unreadable
// afterward; only CCM-AES's own built-in default (12 bytes) ever worked
// that way. GCM/OCB/ChaCha20-Poly1305 take the single-call form, which is
// simpler and was already confirmed working before CCM support existed.
//
// CCM's tag length is declared with a NULL-data, size-only octet string
// (OctetsNilData) rather than the "taglen" scalar param GCM/OCB accept:
// EVP_CIPHER_CTX_settable_params for AES-256-CCM lists "tag", not "taglen"
// -- confirmed by querying it directly, not assumed from the GCM behaviour.
func initEncrypt(ctx *C.EVP_CIPHER_CTX, a *AEAD, nonce []byte) error {
	if a.ccm {
		sizeParams := newParams().
			SizeT(pKeyIVLen, a.nonce).
			OctetsNilData(pKeyAEADTag, a.tag)
		defer sizeParams.free()
		if C.EVP_EncryptInit_ex2(ctx, a.cipher, nil, nil, sizeParams.c()) != 1 {
			return newError("EVP_EncryptInit_ex2(sizes)")
		}
		if C.EVP_EncryptInit_ex2(ctx, nil,
			(*C.uchar)(unsafe.Pointer(&a.key[0])),
			(*C.uchar)(unsafe.Pointer(&nonce[0])), nil) != 1 {
			return newError("EVP_EncryptInit_ex2(key+iv)")
		}
		return nil
	}

	initParams := newParams().
		SizeT(pKeyIVLen, a.nonce).
		SizeT(pKeyAEADTagLen, a.tag)
	defer initParams.free()
	if C.EVP_EncryptInit_ex2(ctx, a.cipher,
		(*C.uchar)(unsafe.Pointer(&a.key[0])),
		(*C.uchar)(unsafe.Pointer(&nonce[0])), initParams.c()) != 1 {
		return newError("EVP_EncryptInit_ex2")
	}
	return nil
}

// Open authenticates and decrypts, appending the plaintext to dst.
//
// A failed tag check returns ErrVerification and no plaintext. Nothing
// partially decrypted is ever returned: the bytes EVP_DecryptUpdate already
// wrote are discarded with the scratch buffer.
//
// For CCM, the authentication check can surface as a failure from
// EVP_DecryptUpdate rather than only from EVP_DecryptFinal_ex -- verified
// directly by tampering with a CCM ciphertext and its AAD independently:
// each failure showed up at whichever Update call was processing the
// tampered data, not at Final. Every such failure is therefore treated as
// ErrVerification for CCM, the same ambiguous-on-purpose failure this
// package already uses elsewhere (RSA-OAEP) rather than a detailed *Error,
// since distinguishing "which call noticed" from a remote party would leak
// more than a decrypt failure should.
func (a *AEAD) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		return nil, ErrClosed
	}
	if len(nonce) != a.nonce {
		return nil, fmt.Errorf("ossl: nonce must be %d bytes, got %d", a.nonce, len(nonce))
	}
	if len(ciphertext) < a.tag {
		return nil, ErrVerification
	}
	body, tag := ciphertext[:len(ciphertext)-a.tag], ciphertext[len(ciphertext)-a.tag:]
	clearErrors()

	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, newError("EVP_CIPHER_CTX_new")
	}
	defer C.EVP_CIPHER_CTX_free(ctx)

	if err := initDecrypt(ctx, a, nonce, tag); err != nil {
		return nil, err
	}
	runtime.KeepAlive(a.key)
	runtime.KeepAlive(nonce)

	var n C.int
	if a.ccm {
		if C.EVP_DecryptUpdate(ctx, nil, &n, nil, C.int(len(body))) != 1 {
			clearErrors()
			return nil, ErrVerification
		}
	}
	if len(aad) > 0 {
		rc := C.EVP_DecryptUpdate(ctx, nil, &n,
			(*C.uchar)(unsafe.Pointer(&aad[0])), C.int(len(aad)))
		runtime.KeepAlive(aad)
		if rc != 1 {
			if a.ccm {
				clearErrors()
				return nil, ErrVerification
			}
			return nil, newError("EVP_DecryptUpdate(aad)")
		}
	}

	buf := make([]byte, len(body)+C.EVP_MAX_BLOCK_LENGTH)
	total := 0
	if len(body) > 0 {
		rc := C.EVP_DecryptUpdate(ctx, (*C.uchar)(unsafe.Pointer(&buf[0])), &n,
			(*C.uchar)(unsafe.Pointer(&body[0])), C.int(len(body)))
		runtime.KeepAlive(body)
		if rc != 1 {
			Zero(buf)
			clearErrors()
			if a.ccm {
				return nil, ErrVerification
			}
			return nil, newError("EVP_DecryptUpdate")
		}
		total = int(n)
	} else if a.ccm {
		// Mirrors SealErr's empty-plaintext CCM handling: without this
		// explicit call, a tampered AAD was accepted at Final instead of
		// being rejected here, where CCM actually notices it.
		rc := C.EVP_DecryptUpdate(ctx, (*C.uchar)(unsafe.Pointer(&buf[0])), &n,
			(*C.uchar)(unsafe.Pointer(&buf[0])), 0)
		if rc != 1 {
			Zero(buf)
			clearErrors()
			return nil, ErrVerification
		}
	}

	// This return value IS the authentication check.
	if C.EVP_DecryptFinal_ex(ctx, (*C.uchar)(unsafe.Pointer(&buf[total])), &n) != 1 {
		Zero(buf)
		clearErrors() // the queue entry is noise; the caller gets ErrVerification
		return nil, ErrVerification
	}
	total += int(n)
	runtime.KeepAlive(buf)
	return append(dst, buf[:total]...), nil
}

// initDecrypt is initEncrypt's decrypt-side counterpart. CCM's ordering
// requirement is stricter here than GCM/OCB's ("the tag needs to be set
// before passing in data to be decrypted", per EVP_EncryptInit's own
// manual) but the two-call split already satisfies it: the tag is supplied
// in the sizes-only first call, strictly before any Update.
func initDecrypt(ctx *C.EVP_CIPHER_CTX, a *AEAD, nonce, tag []byte) error {
	if a.ccm {
		sizeParams := newParams().
			SizeT(pKeyIVLen, a.nonce).
			Octets(pKeyAEADTag, tag)
		defer sizeParams.free()
		if C.EVP_DecryptInit_ex2(ctx, a.cipher, nil, nil, sizeParams.c()) != 1 {
			return newError("EVP_DecryptInit_ex2(sizes)")
		}
		if C.EVP_DecryptInit_ex2(ctx, nil,
			(*C.uchar)(unsafe.Pointer(&a.key[0])),
			(*C.uchar)(unsafe.Pointer(&nonce[0])), nil) != 1 {
			return newError("EVP_DecryptInit_ex2(key+iv)")
		}
		return nil
	}

	initParams := newParams().
		SizeT(pKeyIVLen, a.nonce).
		Octets(pKeyAEADTag, tag)
	defer initParams.free()
	if C.EVP_DecryptInit_ex2(ctx, a.cipher,
		(*C.uchar)(unsafe.Pointer(&a.key[0])),
		(*C.uchar)(unsafe.Pointer(&nonce[0])), initParams.c()) != 1 {
		return newError("EVP_DecryptInit_ex2")
	}
	return nil
}

// Close releases the cipher and cleanses the retained key. Safe to call more
// than once, and safe to call while other goroutines are in Seal or Open:
// it waits for them to finish first, and any that start afterward get
// ErrClosed.
func (a *AEAD) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.closed {
		C.EVP_CIPHER_free(a.cipher)
		a.cipher = nil
		Zero(a.key)
		a.key = nil
		a.closed = true
	}
	return nil
}
