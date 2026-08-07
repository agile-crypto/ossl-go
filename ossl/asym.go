package ossl

/*
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// OAEPOptions configures RSA-OAEP. A nil *OAEPOptions means SHA2-256 with an
// empty label, which is what interoperable protocols use.
type OAEPOptions struct {
	// Hash is the OAEP digest and, unless MGF1Hash is set, the MGF1 digest.
	Hash string

	// MGF1Hash overrides the mask-generation digest. Almost always leave
	// empty: the two digests match in every mainstream profile, and this
	// package sets both explicitly from whatever is supplied rather than
	// leaving the MGF1 digest to a default.
	MGF1Hash string

	// Label is bound into the padding but not transmitted. Both sides must
	// supply the same bytes or decryption fails. Known as the label in
	// PKCS#1 v2.2 and as pSourceData in PKCS#11.
	Label []byte
}

func (o *OAEPOptions) resolve() (hash, mgf1 string, label []byte) {
	hash, mgf1 = "SHA2-256", ""
	if o != nil {
		if o.Hash != "" {
			hash = o.Hash
		}
		mgf1 = o.MGF1Hash
		label = o.Label
	}
	if mgf1 == "" {
		mgf1 = hash
	}
	return hash, mgf1, label
}

// applyOAEP installs the padding mode, both digests, and the label.
func applyOAEP(ctx *C.EVP_PKEY_CTX, o *OAEPOptions) error {
	hash, mgf1, label := o.resolve()
	if C.EVP_PKEY_CTX_set_rsa_padding(ctx, C.RSA_PKCS1_OAEP_PADDING) <= 0 {
		return newError("EVP_PKEY_CTX_set_rsa_padding(OAEP)")
	}
	ch := C.CString(hash)
	defer C.free(unsafe.Pointer(ch))
	if C.EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, ch, nil) <= 0 {
		return newError("EVP_PKEY_CTX_set_rsa_oaep_md_name(" + hash + ")")
	}
	cm := C.CString(mgf1)
	defer C.free(unsafe.Pointer(cm))
	if C.EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, cm, nil) <= 0 {
		return newError("EVP_PKEY_CTX_set_rsa_mgf1_md_name(" + mgf1 + ")")
	}
	if len(label) > 0 {
		// set0 takes ownership: on success the context frees this buffer, so
		// it must not be freed here, and it must not be Go memory. On
		// failure ownership does not transfer and the caller still owns it.
		// Getting either half backwards is a leak or a double free, which is
		// the whole reason this is wrapped rather than open-coded per call.
		buf := C.malloc(C.size_t(len(label)))
		if buf == nil {
			return fmt.Errorf("ossl: malloc failed for OAEP label")
		}
		C.memcpy(buf, unsafe.Pointer(&label[0]), C.size_t(len(label)))
		if C.EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, buf, C.int(len(label))) <= 0 {
			C.free(buf)
			return newError("EVP_PKEY_CTX_set0_rsa_oaep_label")
		}
		runtime.KeepAlive(label)
	}
	return nil
}

// requireRSA rejects a key that cannot do OAEP at all, so the caller gets the
// reason rather than whatever EVP reports several calls later. RSA-PSS keys
// are excluded on purpose: the key's own parameters restrict it to signing.
func (k *Key) requireRSA(op string) error {
	if t := k.Type(); t != "RSA" {
		return fmt.Errorf("ossl: %s requires an RSA key, got %s", op, t)
	}
	return nil
}

// Encrypt performs RSA-OAEP encryption under the public part of k.
//
// The plaintext limit is modulus_bytes - 2*hash_len - 2, so 190 bytes for
// RSA-2048 with SHA2-256 and 318 for RSA-3072. RSA encrypts keys, not
// messages: for anything larger, encrypt a fresh symmetric key here and the
// message itself with an AEAD under that key.
func (k *Key) Encrypt(plaintext []byte, opts *OAEPOptions) ([]byte, error) {
	if k.pkey == nil {
		return nil, ErrClosed
	}
	if err := k.requireRSA("Encrypt"); err != nil {
		return nil, err
	}
	clearErrors()
	ctx := C.EVP_PKEY_CTX_new_from_pkey(k.context().ptr(), k.pkey, nil)
	if ctx == nil {
		return nil, newError("EVP_PKEY_CTX_new_from_pkey")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_encrypt_init(ctx) <= 0 {
		return nil, newError("EVP_PKEY_encrypt_init")
	}
	if err := applyOAEP(ctx, opts); err != nil {
		return nil, err
	}

	var pp *C.uchar
	if len(plaintext) > 0 {
		pp = (*C.uchar)(unsafe.Pointer(&plaintext[0]))
	}
	var n C.size_t
	if C.EVP_PKEY_encrypt(ctx, nil, &n, pp, C.size_t(len(plaintext))) <= 0 {
		return nil, newError("EVP_PKEY_encrypt(size)")
	}
	out := make([]byte, int(n))
	rc := C.EVP_PKEY_encrypt(ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &n,
		pp, C.size_t(len(plaintext)))
	runtime.KeepAlive(plaintext)
	runtime.KeepAlive(out)
	if rc <= 0 {
		return nil, newError("EVP_PKEY_encrypt")
	}
	return out[:n], nil
}

// Decrypt performs RSA-OAEP decryption.
//
// Every failure returns ErrVerification with no further detail, deliberately.
// Distinguishing "the padding was malformed" from "the label did not match"
// from "this is not the right key" is exactly the padding oracle OAEP exists
// to close; a wrapper that reported the difference would let a caller
// reconstruct it just by forwarding the error. The OpenSSL error queue is
// drained rather than attached for the same reason.
func (k *Key) Decrypt(ciphertext []byte, opts *OAEPOptions) ([]byte, error) {
	if k.pkey == nil {
		return nil, ErrClosed
	}
	if err := k.requireRSA("Decrypt"); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, ErrVerification
	}
	clearErrors()
	ctx := C.EVP_PKEY_CTX_new_from_pkey(k.context().ptr(), k.pkey, nil)
	if ctx == nil {
		return nil, newError("EVP_PKEY_CTX_new_from_pkey")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_decrypt_init(ctx) <= 0 {
		return nil, newError("EVP_PKEY_decrypt_init")
	}
	if err := applyOAEP(ctx, opts); err != nil {
		return nil, err
	}

	cp := (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
	var n C.size_t
	if C.EVP_PKEY_decrypt(ctx, nil, &n, cp, C.size_t(len(ciphertext))) <= 0 {
		clearErrors()
		return nil, ErrVerification
	}
	out := make([]byte, int(n))
	rc := C.EVP_PKEY_decrypt(ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &n,
		cp, C.size_t(len(ciphertext)))
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(out)
	if rc <= 0 {
		Zero(out)
		clearErrors()
		return nil, ErrVerification
	}
	return out[:n], nil
}

// MaxOAEPPlaintext reports how many bytes Encrypt will accept for the given
// options, or an error if the key or digest cannot support OAEP at all.
//
// This is derived rather than guessed: callers splitting a payload need the
// exact bound, and computing it from the modulus and digest by hand is the
// kind of arithmetic that is wrong by two bytes for years.
func (k *Key) MaxOAEPPlaintext(opts *OAEPOptions) (int, error) {
	if k.pkey == nil {
		return 0, ErrClosed
	}
	if err := k.requireRSA("MaxOAEPPlaintext"); err != nil {
		return 0, err
	}
	hash, _, _ := opts.resolve()
	h, err := k.context().NewHash(hash)
	if err != nil {
		return 0, err
	}
	defer h.Close()

	n := k.Size() - 2*h.Size() - 2
	if n < 0 {
		return 0, fmt.Errorf("ossl: %s is too small for OAEP with %s", k.Type(), hash)
	}
	return n, nil
}
