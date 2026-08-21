//go:build cgo

package ossl

/*
#include <openssl/evp.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"
)

// eddsaPrehashLen is RFC 8032's PH output length: SHA-512 for Ed25519ph,
// SHAKE256 with a 64-byte output for Ed448ph. Both land on the same 64.
const eddsaPrehashLen = 64

// applyDigestParam names the digest that produced a caller-supplied digest,
// for the algorithms that need to know rather than merely accept it.
//
// RSA embeds the digest identity in the signature: PKCS#1 v1.5 needs it for
// the DigestInfo OID, and PSS needs it for the MGF1 and salt-length
// defaults, so signing fails outright without this. EC does not need it --
// ECDSA treats the bytes as the value to sign regardless of what produced
// them, verified against this build to cross-verify identically with or
// without it set -- but accepts it harmlessly, so it is set uniformly for
// RSA and EC rather than special-cased away for EC alone.
func applyDigestParam(pctx *C.EVP_PKEY_CTX, digest DigestName) error {
	p := newParams()
	defer p.free()
	p.UTF8(pKeyDigest, string(digest))
	if C.EVP_PKEY_CTX_set_params(pctx, p.c()) <= 0 {
		return newError("EVP_PKEY_CTX_set_params(digest)")
	}
	runtime.KeepAlive(p)
	return nil
}

// checkDigestOptions applies checkSignOptions plus the rules specific to
// signing an already-computed digest instead of a message.
func checkDigestOptions(c *Context, keyType KeyAlgorithm, o *SignOptions, digestLen int) error {
	if err := checkSignOptions(keyType, o); err != nil {
		return err
	}
	switch keyType {
	case "RSA", "RSA-PSS", "EC":
		want, err := c.digestSize(o.Digest)
		if err != nil {
			return err
		}
		if digestLen != want {
			return fmt.Errorf("ossl: %s produces a %d-byte digest, got %d bytes", o.Digest, want, digestLen)
		}
	case "ED25519", "ED448":
		if !o.Prehash {
			return fmt.Errorf(
				"ossl: %s has no raw-digest form; set SignOptions.Prehash to select the ph variant, which does",
				keyType)
		}
		if digestLen != eddsaPrehashLen {
			return fmt.Errorf("ossl: %s expects a %d-byte prehash, got %d bytes",
				keyType, eddsaPrehashLen, digestLen)
		}
	default:
		return fmt.Errorf("ossl: %s has no raw-digest signing form; use Sign", keyType)
	}
	return nil
}

// SignDigest signs an already-computed digest directly, without hashing it
// again -- the counterpart to Sign for a caller who computed the hash
// themselves: streamed over data too large to hold at once via a plain
// hash.Hash, or produced across an HSM boundary that only returns a digest.
//
// For RSA and EC, digest must be the output of the hash SignOptions.Digest
// names (the key's default digest if opts is nil or Digest is empty) -- the
// same bytes Sign would have computed from the message itself, so a
// SignDigest signature and a Sign signature over the equivalent message
// verify identically and interchangeably.
//
// For Ed25519 and Ed448, this requires SignOptions.Prehash, which selects
// Ed25519ph/Ed448ph -- the only EdDSA variants defined over a digest rather
// than a message. digest must be exactly 64 bytes: SHA-512(message) for
// Ed25519ph, SHAKE256(message, 64) for Ed448ph, per RFC 8032. Pure Ed25519,
// Ed25519ctx and pure Ed448 have no raw-digest form at all -- the algorithm
// needs the actual message, hashed as part of signing, not a digest of it --
// so SignDigest without Prehash set is an error rather than a silent
// fallback that would sign over the wrong statement with no indication of
// it.
//
// ML-DSA and SLH-DSA have no raw-digest form in OpenSSL either; use Sign.
//
// This is a different EVP entry point from Sign (EVP_PKEY_sign rather than
// EVP_DigestSign), not a flag on it. Verified against this build: the two
// are not interchangeable by parameter alone. Under the ph instance,
// EVP_DigestSign always hashes whatever it is given -- so passing a
// caller-computed digest to Sign would sign SHA-512(digest) instead of
// SHA-512(message), a different and non-compliant statement -- while
// EVP_PKEY_sign trusts a 64-byte input as the digest itself.
func (k *Key) SignDigest(digest []byte, opts *SignOptions) ([]byte, error) {
	if k == nil || k.pkey == nil {
		return nil, ErrClosed
	}
	c := k.context()
	keyType := k.Type()
	o := k.signOpts(opts)
	if err := checkDigestOptions(c, keyType, o, len(digest)); err != nil {
		return nil, err
	}
	clearErrors()

	pctx := C.EVP_PKEY_CTX_new_from_pkey(c.ptr(), k.pkey, nil)
	if pctx == nil {
		return nil, newError("EVP_PKEY_CTX_new_from_pkey")
	}
	defer C.EVP_PKEY_CTX_free(pctx)

	if C.EVP_PKEY_sign_init(pctx) <= 0 {
		return nil, newError("EVP_PKEY_sign_init")
	}
	if keyType == "RSA" || keyType == "RSA-PSS" || keyType == "EC" {
		if err := applyDigestParam(pctx, o.Digest); err != nil {
			return nil, err
		}
	}
	if err := applySignOptions(pctx, keyType, o); err != nil {
		return nil, err
	}

	var dp *C.uchar
	if len(digest) > 0 {
		dp = (*C.uchar)(unsafe.Pointer(&digest[0]))
	}

	// Two-call size discovery, same as Sign.
	var n C.size_t
	if C.EVP_PKEY_sign(pctx, nil, &n, dp, C.size_t(len(digest))) <= 0 {
		return nil, newError("EVP_PKEY_sign(size)")
	}
	if n == 0 {
		return nil, newError("EVP_PKEY_sign reported a zero-length signature")
	}
	sig := make([]byte, int(n))
	rc := C.EVP_PKEY_sign(pctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &n, dp, C.size_t(len(digest)))
	runtime.KeepAlive(digest)
	runtime.KeepAlive(sig)
	if rc <= 0 {
		return nil, newError("EVP_PKEY_sign")
	}
	out := sig[:n]
	if o.Format == SignatureP1363 {
		return derToP1363(out, ecdsaCoordinateLen(k))
	}
	return out, nil
}

// VerifyDigest checks sig against an already-computed digest, mirroring
// SignDigest. Same three-way result as Verify: nil for a valid signature,
// ErrVerification for a well-formed rejection, an *Error if the call itself
// failed.
func (k *Key) VerifyDigest(digest, sig []byte, opts *SignOptions) error {
	if k == nil || k.pkey == nil {
		return ErrClosed
	}
	if len(sig) == 0 {
		return ErrVerification
	}
	c := k.context()
	keyType := k.Type()
	o := k.signOpts(opts)
	if err := checkDigestOptions(c, keyType, o, len(digest)); err != nil {
		return err
	}
	clearErrors()

	pctx := C.EVP_PKEY_CTX_new_from_pkey(c.ptr(), k.pkey, nil)
	if pctx == nil {
		return newError("EVP_PKEY_CTX_new_from_pkey")
	}
	defer C.EVP_PKEY_CTX_free(pctx)

	if C.EVP_PKEY_verify_init(pctx) <= 0 {
		return newError("EVP_PKEY_verify_init")
	}
	if keyType == "RSA" || keyType == "RSA-PSS" || keyType == "EC" {
		if err := applyDigestParam(pctx, o.Digest); err != nil {
			return err
		}
	}
	if err := applySignOptions(pctx, keyType, o); err != nil {
		return err
	}

	if o.Format == SignatureP1363 {
		der, err := p1363ToDER(sig, ecdsaCoordinateLen(k))
		if err != nil {
			// A malformed signature is a rejection, not a fault.
			return ErrVerification
		}
		sig = der
	}

	var dp *C.uchar
	if len(digest) > 0 {
		dp = (*C.uchar)(unsafe.Pointer(&digest[0]))
	}
	rc := C.EVP_PKEY_verify(pctx,
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		dp, C.size_t(len(digest)))
	runtime.KeepAlive(digest)
	runtime.KeepAlive(sig)

	switch {
	case rc == 1:
		return nil
	case rc == 0:
		clearErrors()
		return ErrVerification
	default:
		detail := newError("EVP_PKEY_verify")
		return fmt.Errorf("%w: %s", ErrVerification, detail)
	}
}
