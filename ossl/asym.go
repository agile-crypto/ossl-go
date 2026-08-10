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
	"strings"
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

// ---------------------------------------------------------------------------
// Key encapsulation
// ---------------------------------------------------------------------------

// Encapsulate generates a fresh shared secret and its encapsulation under the
// public part of k.
//
// Works for ML-KEM-512/768/1024, the IETF hybrids (X25519MLKEM768,
// SecP256r1MLKEM768, X448MLKEM1024, SecP384r1MLKEM1024), X25519 and X448, and
// RSA -- for which the RSASVE operation is selected automatically, since it
// is the only KEM operation OpenSSL offers for RSA and making callers name it
// serves nobody.
//
// The returned secret is NOT a key. For ML-KEM it is uniformly random, but
// for RSASVE it is a raw integer the size of the modulus, and for the hybrids
// it is a concatenation. Run it through a KDF bound to a protocol-specific
// context string before using it for anything.
func (k *Key) Encapsulate() (ciphertext, secret []byte, err error) {
	if k.pkey == nil {
		return nil, nil, ErrClosed
	}
	clearErrors()
	ctx := C.EVP_PKEY_CTX_new_from_pkey(k.context().ptr(), k.pkey, nil)
	if ctx == nil {
		return nil, nil, newError("EVP_PKEY_CTX_new_from_pkey")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_encapsulate_init(ctx, nil) <= 0 {
		return nil, nil, newError("EVP_PKEY_encapsulate_init(" + k.Type() + ")")
	}
	if err := setKEMOp(ctx, k.Type()); err != nil {
		return nil, nil, err
	}

	// Both output lengths come back from a single NULL/NULL query.
	var ctLen, ssLen C.size_t
	if C.EVP_PKEY_encapsulate(ctx, nil, &ctLen, nil, &ssLen) <= 0 {
		return nil, nil, newError("EVP_PKEY_encapsulate(size)")
	}
	ct := make([]byte, int(ctLen))
	ss := make([]byte, int(ssLen))
	rc := C.EVP_PKEY_encapsulate(ctx,
		(*C.uchar)(unsafe.Pointer(&ct[0])), &ctLen,
		(*C.uchar)(unsafe.Pointer(&ss[0])), &ssLen)
	runtime.KeepAlive(ct)
	runtime.KeepAlive(ss)
	if rc <= 0 {
		return nil, nil, newError("EVP_PKEY_encapsulate")
	}
	return ct[:ctLen], ss[:ssLen], nil
}

// Decapsulate recovers the shared secret from an encapsulation.
//
// A nil error does NOT mean the ciphertext was genuine. ML-KEM's
// Fujisaki-Okamoto transform uses implicit rejection: a corrupted
// encapsulation yields a pseudorandom secret derived from a per-key rejection
// value, and reports success. This was verified directly against every KEM
// here -- flipping a byte of the ciphertext returns rc=1 with a secret that
// simply differs from the sender's. There is no error for this wrapper to
// surface and none it could invent without breaking the security property,
// since revealing that decapsulation "failed" is precisely the oracle the
// transform exists to deny.
//
// The mismatch is therefore only detectable one layer up, when a key derived
// from the secret fails to authenticate something. Any protocol built on this
// must have such a check -- an AEAD open, a MAC, a confirmation message --
// or it will silently proceed with two different keys.
func (k *Key) Decapsulate(ciphertext []byte) ([]byte, error) {
	if k.pkey == nil {
		return nil, ErrClosed
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ossl: empty encapsulation")
	}
	clearErrors()
	ctx := C.EVP_PKEY_CTX_new_from_pkey(k.context().ptr(), k.pkey, nil)
	if ctx == nil {
		return nil, newError("EVP_PKEY_CTX_new_from_pkey")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_decapsulate_init(ctx, nil) <= 0 {
		return nil, newError("EVP_PKEY_decapsulate_init(" + k.Type() + ")")
	}
	if err := setKEMOp(ctx, k.Type()); err != nil {
		return nil, err
	}

	cp := (*C.uchar)(unsafe.Pointer(&ciphertext[0]))
	var n C.size_t
	if C.EVP_PKEY_decapsulate(ctx, nil, &n, cp, C.size_t(len(ciphertext))) <= 0 {
		return nil, newError("EVP_PKEY_decapsulate(size)")
	}
	ss := make([]byte, int(n))
	rc := C.EVP_PKEY_decapsulate(ctx, (*C.uchar)(unsafe.Pointer(&ss[0])), &n,
		cp, C.size_t(len(ciphertext)))
	runtime.KeepAlive(ciphertext)
	runtime.KeepAlive(ss)
	if rc <= 0 {
		Zero(ss)
		return nil, newError("EVP_PKEY_decapsulate")
	}
	return ss[:n], nil
}

// setKEMOp names the KEM operation for RSA. ML-KEM and the hybrids have
// exactly one operation and do not take the parameter.
//
// RSA encapsulation works on this build without it -- RSASVE is evidently
// already the default -- so this is explicitness rather than necessity. It
// stays because the operation determines the wire format, and a default is a
// worse thing to depend on than a name: if RSA ever gains a second KEM
// operation, code that named the one it wanted keeps working and code that
// relied on the default silently changes what it produces.
func setKEMOp(ctx *C.EVP_PKEY_CTX, keyType string) error {
	if !strings.EqualFold(keyType, "RSA") {
		return nil
	}
	op := C.CString("RSASVE")
	defer C.free(unsafe.Pointer(op))
	if C.EVP_PKEY_CTX_set_kem_op(ctx, op) <= 0 {
		return newError("EVP_PKEY_CTX_set_kem_op(RSASVE)")
	}
	return nil
}
