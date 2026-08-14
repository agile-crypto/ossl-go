//go:build cgo

package ossl

/*
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"runtime"
	"strings"
	"unsafe"
)

// RSAPadding selects an RSA signature scheme.
type RSAPadding int

const (
	// RSAPSS is RSASSA-PSS. Use it for anything new.
	RSAPSS RSAPadding = iota
	// RSAPKCS1v15 is the legacy scheme, for interoperating with systems that
	// require it.
	RSAPKCS1v15
)

// PSSSaltLength selects the RSA-PSS salt length policy.
//
// The zero value, PSSSaltLengthHash, makes the salt as long as the digest --
// the usual choice. PSSSaltLengthMax uses the largest salt the modulus
// allows. Any positive value is an explicit salt length in bytes, and is
// enforced on Verify as well as used on Sign: a signature made with a
// different salt length is rejected, not silently accepted the way
// PSSSaltLengthAuto-style verification would.
type PSSSaltLength int

const (
	PSSSaltLengthHash PSSSaltLength = 0
	PSSSaltLengthMax  PSSSaltLength = -1
)

// SignOptions configures a signature. A nil *SignOptions selects sensible
// defaults for the key's algorithm, which is what most callers want:
//
//	sig, err := key.Sign(msg, nil)
//
// works whether key is RSA, EC, Ed25519 or ML-DSA.
type SignOptions struct {
	// Digest is the hash name, e.g. "SHA2-256". Leave empty to accept the
	// default for the key type; algorithms that hash internally (Ed25519,
	// ML-DSA, SLH-DSA) ignore it entirely.
	Digest string

	// Context is the domain-separation context for algorithms that use one:
	// Ed25519ctx and Ed25519ph, Ed448 (including Ed448ph), ML-DSA (FIPS 204
	// §3.2), and SLH-DSA (FIPS 205 §9.2). At most 255 bytes.
	//
	// For Ed25519 specifically, a non-nil Context (even a zero-length one)
	// selects the Ed25519ctx variant instead of pure Ed25519 -- the two are
	// cryptographically distinct even when the context is empty, so this
	// package cannot infer the variant from the byte content alone. Ed448,
	// ML-DSA, and SLH-DSA all accept an optional context without changing
	// variant, so nil there just means "no context set."
	Context []byte

	// Prehash selects the "ph" variant -- Ed25519ph or Ed448ph -- which signs
	// a SHA-512/SHAKE256 prehash of msg rather than msg itself. Setting it
	// for any other algorithm is an error.
	Prehash bool

	// Padding applies to RSA keys only. The zero value is RSAPSS.
	//
	// This default is deliberately not OpenSSL's. A raw "RSA" key signs with
	// PKCS#1 v1.5 unless told otherwise, so a wrapper that passes through
	// silently hands callers the legacy scheme. Opting in to the legacy path
	// should be explicit.
	Padding RSAPadding

	// PSSSaltLen applies to RSA-PSS only.
	PSSSaltLen PSSSaltLength

	// Deterministic selects RFC 6979 deterministic nonce generation for
	// ECDSA. Setting it for any other algorithm is an error.
	Deterministic bool
}

func (k *Key) signOpts(o *SignOptions) *SignOptions {
	if o == nil {
		o = &SignOptions{}
	}
	c := *o
	if c.Digest == "" {
		c.Digest = k.defaultDigest()
	}
	return &c
}

// applyRSA sets padding options on the borrowed EVP_PKEY_CTX handed back by
// EVP_DigestSignInit_ex/EVP_DigestVerifyInit_ex. That context belongs to the
// EVP_MD_CTX -- it must not be freed here.
func applyRSA(pctx *C.EVP_PKEY_CTX, o *SignOptions, digest string) error {
	if o.Padding == RSAPKCS1v15 {
		if C.EVP_PKEY_CTX_set_rsa_padding(pctx, C.RSA_PKCS1_PADDING) <= 0 {
			return newError("EVP_PKEY_CTX_set_rsa_padding")
		}
		return nil
	}
	if C.EVP_PKEY_CTX_set_rsa_padding(pctx, C.RSA_PKCS1_PSS_PADDING) <= 0 {
		return newError("EVP_PKEY_CTX_set_rsa_padding(PSS)")
	}
	var salt C.int
	switch {
	case o.PSSSaltLen > 0:
		salt = C.int(o.PSSSaltLen)
	case o.PSSSaltLen == PSSSaltLengthMax:
		salt = C.int(C.RSA_PSS_SALTLEN_MAX)
	default:
		salt = C.int(C.RSA_PSS_SALTLEN_DIGEST)
	}
	if C.EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, salt) <= 0 {
		return newError("EVP_PKEY_CTX_set_rsa_pss_saltlen")
	}
	cd := C.CString(digest)
	defer C.free(unsafe.Pointer(cd))
	if C.EVP_PKEY_CTX_set_rsa_mgf1_md_name(pctx, cd, nil) <= 0 {
		return newError("EVP_PKEY_CTX_set_rsa_mgf1_md_name")
	}
	return nil
}

// applyContext sets an optional domain-separation context. Used as-is by
// ML-DSA and SLH-DSA, which accept a context without it changing which
// signature variant is in play.
func applyContext(pctx *C.EVP_PKEY_CTX, context []byte) error {
	if context == nil {
		return nil
	}
	p := newParams()
	defer p.free()
	p.Octets(pKeyContext, context)
	if C.EVP_PKEY_CTX_set_params(pctx, p.c()) <= 0 {
		return newError("EVP_PKEY_CTX_set_params(context-string)")
	}
	runtime.KeepAlive(p)
	return nil
}

// applyEd25519 selects among pure Ed25519, Ed25519ctx, and Ed25519ph. Unlike
// Ed448, plain Ed25519 rejects a context-string param outright -- OpenSSL
// requires the "instance" param to name the ctx/ph variant before it will
// accept one, so the two settings have to move together.
func applyEd25519(pctx *C.EVP_PKEY_CTX, o *SignOptions) error {
	var instance string
	switch {
	case o.Prehash:
		instance = "Ed25519ph"
	case o.Context != nil:
		instance = "Ed25519ctx"
	default:
		return nil
	}
	p := newParams()
	defer p.free()
	p.UTF8(pKeyInstance, instance)
	if o.Context != nil {
		p.Octets(pKeyContext, o.Context)
	}
	if C.EVP_PKEY_CTX_set_params(pctx, p.c()) <= 0 {
		return newError("EVP_PKEY_CTX_set_params(" + instance + ")")
	}
	runtime.KeepAlive(p)
	return nil
}

// applyEd448 selects Ed448 or Ed448ph. Unlike Ed25519, plain Ed448 already
// accepts an optional context-string with no "instance" override needed --
// RFC 8032 gives every Ed448 signature a context, defaulting to empty.
func applyEd448(pctx *C.EVP_PKEY_CTX, o *SignOptions) error {
	if !o.Prehash {
		return applyContext(pctx, o.Context)
	}
	p := newParams()
	defer p.free()
	p.UTF8(pKeyInstance, "Ed448ph")
	if o.Context != nil {
		p.Octets(pKeyContext, o.Context)
	}
	if C.EVP_PKEY_CTX_set_params(pctx, p.c()) <= 0 {
		return newError("EVP_PKEY_CTX_set_params(Ed448ph)")
	}
	runtime.KeepAlive(p)
	return nil
}

// applyDeterministicECDSA selects RFC 6979 deterministic nonce generation.
func applyDeterministicECDSA(pctx *C.EVP_PKEY_CTX) error {
	p := newParams()
	defer p.free()
	p.Int(pKeyNonceType, 1)
	if C.EVP_PKEY_CTX_set_params(pctx, p.c()) <= 0 {
		return newError("EVP_PKEY_CTX_set_params(nonce-type)")
	}
	runtime.KeepAlive(p)
	return nil
}

// maxContextLength is the domain-separation context ceiling shared by every
// algorithm here: RFC 8032 §5.2.6 for Ed448, FIPS 204 §3.2 for ML-DSA, and
// FIPS 205 §9.2 for SLH-DSA all cap it at 255 bytes.
const maxContextLength = 255

// checkSignOptions rejects options the key's algorithm cannot honour.
//
// Silently dropping them is the dangerous alternative, and it is what this
// package did before: a Context set on an RSA or EC key was discarded, so a
// signature produced with what the caller believed was domain separation
// verified fine under any other context, or none. The same applied to an RSA
// padding choice on a non-RSA key. None of it produced an error, and a
// sign-then-verify test passes either way, because both halves drop the
// option identically.
//
// Every field is compared against its zero value, so "unset" and "explicitly
// the default" are deliberately the same thing -- there is no way to ask for
// PSS on an Ed25519 key by accident, only to leave the RSA fields alone.
func checkSignOptions(keyType string, o *SignOptions) error {
	rsa := keyType == "RSA" || keyType == "RSA-PSS"
	ec := keyType == "EC"
	ed25519 := keyType == "ED25519"
	ed448 := keyType == "ED448"
	pqc := strings.HasPrefix(keyType, "ML-DSA") || strings.HasPrefix(keyType, "SLH-DSA")

	if o.Context != nil && !(ed25519 || ed448 || pqc) {
		return fmt.Errorf("ossl: %s signatures have no domain-separation context; "+
			"SignOptions.Context is only valid for Ed25519, Ed448, ML-DSA and SLH-DSA", keyType)
	}
	if len(o.Context) > maxContextLength {
		return fmt.Errorf("ossl: signature context is %d bytes, the maximum is %d",
			len(o.Context), maxContextLength)
	}
	if o.Prehash && !(ed25519 || ed448) {
		return fmt.Errorf("ossl: %s has no prehash variant; "+
			"SignOptions.Prehash is only valid for Ed25519 and Ed448", keyType)
	}
	if o.Padding != RSAPSS && !rsa {
		return fmt.Errorf("ossl: SignOptions.Padding is only valid for RSA keys, got %s", keyType)
	}
	if o.PSSSaltLen != PSSSaltLengthHash && !rsa {
		return fmt.Errorf("ossl: SignOptions.PSSSaltLen is only valid for RSA keys, got %s", keyType)
	}
	if o.PSSSaltLen < 0 && o.PSSSaltLen != PSSSaltLengthMax {
		return fmt.Errorf("ossl: SignOptions.PSSSaltLen must be PSSSaltLengthHash, "+
			"PSSSaltLengthMax, or a positive byte count, got %d", o.PSSSaltLen)
	}
	if o.Deterministic && !ec {
		return fmt.Errorf("ossl: SignOptions.Deterministic (RFC 6979) is only valid for EC keys, got %s", keyType)
	}
	// An RSA-PSS key carries its scheme in the key itself and cannot sign
	// PKCS#1 v1.5, so a request for it is a caller error rather than
	// something to quietly ignore.
	if keyType == "RSA-PSS" && o.Padding == RSAPKCS1v15 {
		return fmt.Errorf("ossl: an RSA-PSS key cannot produce PKCS#1 v1.5 signatures; " +
			"generate a plain \"RSA\" key for that")
	}
	return nil
}

// applySignOptions applies whichever of the options above are relevant to
// keyType. Options that do not apply have already been rejected by
// checkSignOptions, so anything reaching here is either used or genuinely
// absent.
func applySignOptions(pctx *C.EVP_PKEY_CTX, keyType string, o *SignOptions) error {
	switch {
	case keyType == "RSA", keyType == "RSA-PSS":
		return applyRSA(pctx, o, o.Digest)
	case keyType == "EC":
		if o.Deterministic {
			return applyDeterministicECDSA(pctx)
		}
		return nil
	case keyType == "ED25519":
		return applyEd25519(pctx, o)
	case keyType == "ED448":
		return applyEd448(pctx, o)
	case strings.HasPrefix(keyType, "ML-DSA"), strings.HasPrefix(keyType, "SLH-DSA"):
		return applyContext(pctx, o.Context)
	default:
		return nil
	}
}

// Sign produces a signature over msg.
//
// The one-shot EVP_DigestSign path is used for every algorithm. That is not
// just simplicity: Ed25519, Ed448, ML-DSA and SLH-DSA reject streaming
// updates outright, so a single code path is also the only correct one that
// covers them.
func (k *Key) Sign(msg []byte, opts *SignOptions) ([]byte, error) {
	if k.pkey == nil {
		return nil, ErrClosed
	}
	o := k.signOpts(opts)
	if err := checkSignOptions(k.Type(), o); err != nil {
		return nil, err
	}
	clearErrors()

	mdctx := C.EVP_MD_CTX_new()
	if mdctx == nil {
		return nil, newError("EVP_MD_CTX_new")
	}
	defer C.EVP_MD_CTX_free(mdctx)

	var cd *C.char
	if o.Digest != "" {
		cd = C.CString(o.Digest)
		defer C.free(unsafe.Pointer(cd))
	}
	var pctx *C.EVP_PKEY_CTX
	if C.EVP_DigestSignInit_ex(mdctx, &pctx, cd, nil, nil, k.pkey, nil) <= 0 {
		return nil, newError("EVP_DigestSignInit_ex")
	}
	if err := applySignOptions(pctx, k.Type(), o); err != nil {
		return nil, err
	}

	var mp *C.uchar
	if len(msg) > 0 {
		mp = (*C.uchar)(unsafe.Pointer(&msg[0]))
	}

	// Two-call size discovery.
	var n C.size_t
	if C.EVP_DigestSign(mdctx, nil, &n, mp, C.size_t(len(msg))) <= 0 {
		return nil, newError("EVP_DigestSign(size)")
	}
	sig := make([]byte, int(n))
	rc := C.EVP_DigestSign(mdctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &n,
		mp, C.size_t(len(msg)))
	runtime.KeepAlive(msg)
	runtime.KeepAlive(sig)
	if rc <= 0 {
		return nil, newError("EVP_DigestSign")
	}
	// n may shrink: ECDSA signatures are DER and vary by a byte or two.
	return sig[:n], nil
}

// Verify checks a signature. It returns nil if the signature is valid,
// ErrVerification if it is well-formed but wrong, and an *Error if the call
// itself failed.
//
// The three-way distinction matters. EVP_DigestVerify returns 1, 0 and
// negative for exactly these cases, and collapsing them -- treating any
// non-zero as success, say -- turns a broken call into an accepted
// signature. A negative return in particular does not mean the call failed
// in the "programming fault" sense: a DER-encoded ECDSA signature with a
// flipped leading byte returns negative, because it no longer parses, not
// because anything about the key or algorithm was wrong. That case belongs
// with the ordinary rejections, so it maps to ErrVerification too, with the
// library detail preserved in the wrapped error for logs.
func (k *Key) Verify(msg, sig []byte, opts *SignOptions) error {
	if k.pkey == nil {
		return ErrClosed
	}
	if len(sig) == 0 {
		return ErrVerification
	}
	o := k.signOpts(opts)
	if err := checkSignOptions(k.Type(), o); err != nil {
		return err
	}
	clearErrors()

	mdctx := C.EVP_MD_CTX_new()
	if mdctx == nil {
		return newError("EVP_MD_CTX_new")
	}
	defer C.EVP_MD_CTX_free(mdctx)

	var cd *C.char
	if o.Digest != "" {
		cd = C.CString(o.Digest)
		defer C.free(unsafe.Pointer(cd))
	}
	var pctx *C.EVP_PKEY_CTX
	if C.EVP_DigestVerifyInit_ex(mdctx, &pctx, cd, nil, nil, k.pkey, nil) <= 0 {
		return newError("EVP_DigestVerifyInit_ex")
	}
	if err := applySignOptions(pctx, k.Type(), o); err != nil {
		return err
	}

	var mp *C.uchar
	if len(msg) > 0 {
		mp = (*C.uchar)(unsafe.Pointer(&msg[0]))
	}
	rc := C.EVP_DigestVerify(mdctx,
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)),
		mp, C.size_t(len(msg)))
	runtime.KeepAlive(msg)
	runtime.KeepAlive(sig)

	switch {
	case rc == 1:
		return nil
	case rc == 0:
		clearErrors()
		return ErrVerification
	default:
		detail := newError("EVP_DigestVerify")
		return fmt.Errorf("%w: %s", ErrVerification, detail)
	}
}
