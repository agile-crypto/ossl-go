//go:build cgo

package ossl

/*
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/crypto.h>
#include <stdlib.h>

// OPENSSL_free is a macro that stamps in __FILE__/__LINE__, which cgo cannot
// call directly. This shim gives it a real address.
static void ossl_free(void *p) { OPENSSL_free(p); }
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// OSSL_ENCODER/OSSL_DECODER structure names. "type-specific" is OpenSSL's
// name for each algorithm's own legacy/native encoding -- SEC1 for EC,
// PKCS#1 for RSA -- as opposed to the algorithm-agnostic PKCS#8 wrapper.
//
// This package uses the encoder/decoder API rather than PEM_write_bio_*/
// PEM_read_bio_* because the latter picks a format implicitly per key type
// with no way to request PKCS#8 vs SEC1 for an EC key, or to reject a
// private-key blob when a public key was expected. Both are required here:
// callers need to produce and consume exactly the encoding a peer or a
// storage format demands, not whatever OpenSSL happens to prefer.
const (
	structPKCS8 = "PrivateKeyInfo"
	structSEC1  = "type-specific"
	structSPKI  = "SubjectPublicKeyInfo"
)

func (k *Key) encode(selection C.int, outType, structure string) ([]byte, error) {
	if k == nil || k.pkey == nil {
		return nil, ErrClosed
	}
	clearErrors()
	ot := C.CString(outType)
	defer C.free(unsafe.Pointer(ot))
	st := C.CString(structure)
	defer C.free(unsafe.Pointer(st))

	ctx := C.OSSL_ENCODER_CTX_new_for_pkey(k.pkey, selection, ot, st, nil)
	if ctx == nil {
		return nil, newError("OSSL_ENCODER_CTX_new_for_pkey(" + structure + ")")
	}
	defer C.OSSL_ENCODER_CTX_free(ctx)

	var data *C.uchar
	var n C.size_t
	if C.OSSL_ENCODER_to_data(ctx, &data, &n) != 1 {
		return nil, newError("OSSL_ENCODER_to_data(" + structure + ")")
	}
	defer C.ossl_free(unsafe.Pointer(data))
	return C.GoBytes(unsafe.Pointer(data), C.int(n)), nil
}

// MarshalPKCS8 returns the DER-encoded PKCS#8 PrivateKeyInfo.
func (k *Key) MarshalPKCS8() ([]byte, error) {
	return k.encode(C.EVP_PKEY_KEYPAIR, "DER", structPKCS8)
}

// MarshalPKCS8PEM returns the PEM-armored PKCS#8 PrivateKeyInfo.
func (k *Key) MarshalPKCS8PEM() ([]byte, error) {
	return k.encode(C.EVP_PKEY_KEYPAIR, "PEM", structPKCS8)
}

// MarshalSEC1 returns the DER-encoded SEC1 ECPrivateKey. EC keys only: unlike
// PKCS#8 and SPKI, structSEC1 ("type-specific") is not inherently EC-specific
// -- OpenSSL happily encodes an RSA key's own native PKCS#1 format under the
// same structure name -- so the EC check has to happen here rather than by
// relying on the encoder to reject the wrong key type.
func (k *Key) MarshalSEC1() ([]byte, error) {
	if k.Type() != "EC" {
		return nil, fmt.Errorf("ossl: MarshalSEC1 requires an EC key, got %s", k.Type())
	}
	return k.encode(C.EVP_PKEY_KEYPAIR, "DER", structSEC1)
}

// MarshalSEC1PEM returns the PEM-armored SEC1 ECPrivateKey. EC keys only.
func (k *Key) MarshalSEC1PEM() ([]byte, error) {
	if k.Type() != "EC" {
		return nil, fmt.Errorf("ossl: MarshalSEC1PEM requires an EC key, got %s", k.Type())
	}
	return k.encode(C.EVP_PKEY_KEYPAIR, "PEM", structSEC1)
}

// MarshalPKCS1 returns the DER-encoded PKCS#1 RSAPrivateKey. RSA keys only.
//
// This is the "type-specific" structure for RSA, the counterpart of SEC1 for
// EC, and is what citius-server's WrapFormat calls PKCS1.
func (k *Key) MarshalPKCS1() ([]byte, error) {
	if t := k.Type(); t != "RSA" {
		return nil, fmt.Errorf("ossl: MarshalPKCS1 requires an RSA key, got %s", t)
	}
	return k.encode(C.EVP_PKEY_KEYPAIR, "DER", structSEC1)
}

// MarshalPKCS1PEM returns the PEM-armored PKCS#1 RSAPrivateKey.
func (k *Key) MarshalPKCS1PEM() ([]byte, error) {
	if t := k.Type(); t != "RSA" {
		return nil, fmt.Errorf("ossl: MarshalPKCS1PEM requires an RSA key, got %s", t)
	}
	return k.encode(C.EVP_PKEY_KEYPAIR, "PEM", structSEC1)
}

// ParsePKCS1PrivateKey parses a DER-encoded PKCS#1 RSAPrivateKey.
func (c *Context) ParsePKCS1PrivateKey(der []byte) (*Key, error) {
	return decodeKey(c, der, "DER", structSEC1, "RSA", C.EVP_PKEY_KEYPAIR)
}

// ParsePKCS1PrivateKeyPEM parses a PEM-armored PKCS#1 RSAPrivateKey.
func (c *Context) ParsePKCS1PrivateKeyPEM(pemBytes []byte) (*Key, error) {
	return decodeKey(c, pemBytes, "PEM", structSEC1, "RSA", C.EVP_PKEY_KEYPAIR)
}

// MarshalSPKI returns the DER-encoded X.509 SubjectPublicKeyInfo.
func (k *Key) MarshalSPKI() ([]byte, error) {
	return k.encode(C.EVP_PKEY_PUBLIC_KEY, "DER", structSPKI)
}

// MarshalSPKIPEM returns the PEM-armored SubjectPublicKeyInfo.
func (k *Key) MarshalSPKIPEM() ([]byte, error) {
	return k.encode(C.EVP_PKEY_PUBLIC_KEY, "PEM", structSPKI)
}

// MarshalRawPrivateKey returns the algorithm-native private key bytes.
// Supported for X25519, Ed25519, and (OpenSSL 3.5+) ML-KEM and ML-DSA. RSA
// and EC keys have no raw representation and return an error.
func (k *Key) MarshalRawPrivateKey() ([]byte, error) {
	if k == nil || k.pkey == nil {
		return nil, ErrClosed
	}
	clearErrors()
	var n C.size_t
	if C.EVP_PKEY_get_raw_private_key(k.pkey, nil, &n) != 1 {
		return nil, newError("EVP_PKEY_get_raw_private_key: no raw encoding for " + string(k.Type()))
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, int(n))
	if C.EVP_PKEY_get_raw_private_key(k.pkey, (*C.uchar)(unsafe.Pointer(&buf[0])), &n) != 1 {
		return nil, newError("EVP_PKEY_get_raw_private_key")
	}
	return buf[:n], nil
}

// MarshalRawPublicKey returns the algorithm-native public key bytes.
// Supported for the same algorithms as MarshalRawPrivateKey.
func (k *Key) MarshalRawPublicKey() ([]byte, error) {
	if k == nil || k.pkey == nil {
		return nil, ErrClosed
	}
	clearErrors()
	var n C.size_t
	if C.EVP_PKEY_get_raw_public_key(k.pkey, nil, &n) != 1 {
		return nil, newError("EVP_PKEY_get_raw_public_key: no raw encoding for " + string(k.Type()))
	}
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, int(n))
	if C.EVP_PKEY_get_raw_public_key(k.pkey, (*C.uchar)(unsafe.Pointer(&buf[0])), &n) != 1 {
		return nil, newError("EVP_PKEY_get_raw_public_key")
	}
	return buf[:n], nil
}

// decodeKey builds a Key from an encoded blob through ctx's library context.
// keytype narrows the search to one algorithm's decoder and is required for
// structSEC1, whose DER carries no AlgorithmIdentifier of its own; pass ""
// for structPKCS8 and structSPKI, which are self-describing.
func decodeKey(ctx *Context, in []byte, inType, structure, keytype string, selection C.int) (*Key, error) {
	if ctx == nil {
		return nil, ErrClosed
	}
	if len(in) == 0 {
		return nil, fmt.Errorf("ossl: empty key input")
	}
	clearErrors()
	it := C.CString(inType)
	defer C.free(unsafe.Pointer(it))
	st := C.CString(structure)
	defer C.free(unsafe.Pointer(st))
	var kt *C.char
	if keytype != "" {
		kt = C.CString(keytype)
		defer C.free(unsafe.Pointer(kt))
	}

	var pkey *C.EVP_PKEY
	dctx := C.OSSL_DECODER_CTX_new_for_pkey(&pkey, it, st, kt, selection, ctx.ptr(), nil)
	if dctx == nil {
		return nil, newError("OSSL_DECODER_CTX_new_for_pkey(" + structure + ")")
	}
	defer C.OSSL_DECODER_CTX_free(dctx)

	cdata := C.CBytes(in)
	defer C.free(cdata)
	p := (*C.uchar)(cdata)
	n := C.size_t(len(in))
	if C.OSSL_DECODER_from_data(dctx, (**C.uchar)(unsafe.Pointer(&p)), &n) != 1 {
		return nil, newError("OSSL_DECODER_from_data(" + structure + ")")
	}
	return &Key{pkey: pkey, ctx: ctx}, nil
}

// ParsePKCS8PrivateKey parses a DER-encoded PKCS#8 PrivateKeyInfo.
func (c *Context) ParsePKCS8PrivateKey(der []byte) (*Key, error) {
	return decodeKey(c, der, "DER", structPKCS8, "", C.EVP_PKEY_KEYPAIR)
}

// ParsePKCS8PrivateKeyPEM parses a PEM-armored PKCS#8 PrivateKeyInfo.
func (c *Context) ParsePKCS8PrivateKeyPEM(pemBytes []byte) (*Key, error) {
	return decodeKey(c, pemBytes, "PEM", structPKCS8, "", C.EVP_PKEY_KEYPAIR)
}

// ParseSEC1PrivateKey parses a DER-encoded EC private key. It rejects any
// other algorithm, but -- because OSSL_DECODER's structure hint is advisory
// and OpenSSL auto-detects the actual ASN.1 structure underneath it -- it
// also accepts a PKCS#8-wrapped EC key, not strictly SEC1 alone.
func (c *Context) ParseSEC1PrivateKey(der []byte) (*Key, error) {
	return decodeKey(c, der, "DER", structSEC1, "EC", C.EVP_PKEY_KEYPAIR)
}

// ParseSEC1PrivateKeyPEM is ParseSEC1PrivateKey for PEM-armored input.
func (c *Context) ParseSEC1PrivateKeyPEM(pemBytes []byte) (*Key, error) {
	return decodeKey(c, pemBytes, "PEM", structSEC1, "EC", C.EVP_PKEY_KEYPAIR)
}

// ParseSPKIPublicKey parses a DER-encoded X.509 SubjectPublicKeyInfo.
func (c *Context) ParseSPKIPublicKey(der []byte) (*Key, error) {
	return decodeKey(c, der, "DER", structSPKI, "", C.EVP_PKEY_PUBLIC_KEY)
}

// ParseSPKIPublicKeyPEM parses a PEM-armored SubjectPublicKeyInfo.
func (c *Context) ParseSPKIPublicKeyPEM(pemBytes []byte) (*Key, error) {
	return decodeKey(c, pemBytes, "PEM", structSPKI, "", C.EVP_PKEY_PUBLIC_KEY)
}

// ParseRawPrivateKey builds a key from algorithm-native private key bytes.
// algorithm selects the key type, e.g. "X25519", "ED25519", "ML-KEM-768".
func (c *Context) ParseRawPrivateKey(algorithm KeyAlgorithm, raw []byte) (*Key, error) {
	if c == nil {
		return nil, ErrClosed
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("ossl: empty raw key input")
	}
	clearErrors()
	kt := C.CString(string(algorithm))
	defer C.free(unsafe.Pointer(kt))
	pkey := C.EVP_PKEY_new_raw_private_key_ex(c.ptr(), kt, nil,
		(*C.uchar)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)))
	if pkey == nil {
		return nil, newError("EVP_PKEY_new_raw_private_key_ex(" + string(algorithm) + ")")
	}
	return &Key{pkey: pkey, ctx: c}, nil
}

// ParseRawPublicKey builds a key from algorithm-native public key bytes.
func (c *Context) ParseRawPublicKey(algorithm KeyAlgorithm, raw []byte) (*Key, error) {
	if c == nil {
		return nil, ErrClosed
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("ossl: empty raw key input")
	}
	clearErrors()
	kt := C.CString(string(algorithm))
	defer C.free(unsafe.Pointer(kt))
	pkey := C.EVP_PKEY_new_raw_public_key_ex(c.ptr(), kt, nil,
		(*C.uchar)(unsafe.Pointer(&raw[0])), C.size_t(len(raw)))
	if pkey == nil {
		return nil, newError("EVP_PKEY_new_raw_public_key_ex(" + string(algorithm) + ")")
	}
	return &Key{pkey: pkey, ctx: c}, nil
}

// Public returns the public-only half of k, discarding any private material
// in the returned Key. Implemented as an SPKI round trip, since that is the
// only representation every key type here can produce and re-parse.
//
// The round trip goes back through the Context k came from. Routing it
// through the implicit global context instead would resolve the algorithm
// against a different provider set than the one that produced the key, which
// fails outright for a key whose algorithm only exists in an isolated
// context -- a FIPS-only or PKCS#11 context being the cases that matter.
func (k *Key) Public() (*Key, error) {
	if k == nil || k.pkey == nil {
		return nil, ErrClosed
	}
	spki, err := k.MarshalSPKI()
	if err != nil {
		return nil, err
	}
	return k.context().ParseSPKIPublicKey(spki)
}

// context is the Context this key belongs to, falling back to the global
// default for a zero-value Key.
func (k *Key) context() *Context {
	if k == nil || k.ctx == nil {
		return Default
	}
	return k.ctx
}
