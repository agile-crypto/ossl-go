package ossl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"crypto/cipher"
	"fmt"
	"runtime"
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
// Safe for concurrent use: each operation builds its own EVP_CIPHER_CTX.
// That costs an allocation per call.
type AEAD struct {
	cipher *C.EVP_CIPHER
	key    []byte
	name   string
	nonce  int
	tag    int
	closed bool
}

var _ cipher.AEAD = (*AEAD)(nil)

// NewAEAD fetches an AEAD cipher by OpenSSL name through this context:
// "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305", "AES-256-OCB",
// "AES-256-CCM".
func (c *Context) NewAEAD(name string, key []byte) (*AEAD, error) {
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
	if C.EVP_CIPHER_get_mode(ci) != C.EVP_CIPH_GCM_MODE &&
		C.EVP_CIPHER_get_mode(ci) != C.EVP_CIPH_OCB_MODE &&
		C.EVP_CIPHER_get_mode(ci) != C.EVP_CIPH_CCM_MODE &&
		C.EVP_CIPHER_get_flags(ci)&C.EVP_CIPH_FLAG_AEAD_CIPHER == 0 {
		C.EVP_CIPHER_free(ci)
		return nil, fmt.Errorf("ossl: %s is not an AEAD cipher", name)
	}
	return &AEAD{
		cipher: ci,
		key:    append([]byte(nil), key...),
		name:   name,
		nonce:  int(C.EVP_CIPHER_get_iv_length(ci)),
		tag:    16,
	}, nil
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

	if C.EVP_EncryptInit_ex2(ctx, a.cipher,
		(*C.uchar)(unsafe.Pointer(&a.key[0])),
		(*C.uchar)(unsafe.Pointer(&nonce[0])), nil) != 1 {
		return nil, newError("EVP_EncryptInit_ex2")
	}
	runtime.KeepAlive(a.key)
	runtime.KeepAlive(nonce)

	var n C.int
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

// Open authenticates and decrypts, appending the plaintext to dst.
//
// A failed tag check returns ErrVerification and no plaintext. Nothing
// partially decrypted is ever returned: the bytes EVP_DecryptUpdate already
// wrote are discarded with the scratch buffer.
func (a *AEAD) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
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

	// On decrypt the expected tag is an input and must be set before Final.
	p := newParams().Octets(pKeyAEADTag, tag)
	defer p.free()

	if C.EVP_DecryptInit_ex2(ctx, a.cipher,
		(*C.uchar)(unsafe.Pointer(&a.key[0])),
		(*C.uchar)(unsafe.Pointer(&nonce[0])), p.c()) != 1 {
		return nil, newError("EVP_DecryptInit_ex2")
	}
	runtime.KeepAlive(a.key)
	runtime.KeepAlive(nonce)

	var n C.int
	if len(aad) > 0 {
		if C.EVP_DecryptUpdate(ctx, nil, &n,
			(*C.uchar)(unsafe.Pointer(&aad[0])), C.int(len(aad))) != 1 {
			return nil, newError("EVP_DecryptUpdate(aad)")
		}
		runtime.KeepAlive(aad)
	}

	buf := make([]byte, len(body)+C.EVP_MAX_BLOCK_LENGTH)
	total := 0
	if len(body) > 0 {
		if C.EVP_DecryptUpdate(ctx, (*C.uchar)(unsafe.Pointer(&buf[0])), &n,
			(*C.uchar)(unsafe.Pointer(&body[0])), C.int(len(body))) != 1 {
			return nil, newError("EVP_DecryptUpdate")
		}
		runtime.KeepAlive(body)
		total = int(n)
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

// Close releases the cipher and cleanses the retained key.
func (a *AEAD) Close() error {
	if !a.closed {
		C.EVP_CIPHER_free(a.cipher)
		a.cipher = nil
		Zero(a.key)
		a.key = nil
		a.closed = true
	}
	return nil
}
