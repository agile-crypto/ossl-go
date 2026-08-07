package ossl

/*
#include <openssl/evp.h>
*/
import "C"

import (
	"runtime"
	"strings"
	"unsafe"
)

// Key holds an asymmetric key of any algorithm -- RSA, EC, Ed25519, ML-DSA,
// ML-KEM, or a hybrid KEM -- because that is how EVP_PKEY works. Operations
// that a particular key does not support return an error rather than being
// absent from the type, which is what makes algorithm-agnostic calling code
// possible.
//
// Not safe for concurrent use across operations that mutate. Close when done.
type Key struct {
	pkey *C.EVP_PKEY
}

// KeyOption configures key generation.
type KeyOption func(*params)

// WithRSABits sets the RSA modulus size. Default 2048.
func WithRSABits(bits int) KeyOption {
	return func(p *params) { p.SizeT(pKeyRSABits, bits) }
}

// WithGroup sets the elliptic curve group, e.g. "P-256", "P-384", "P-521".
func WithGroup(name string) KeyOption {
	return func(p *params) { p.UTF8(pKeyGroupName, name) }
}

// WithParam sets an arbitrary generation parameter, for algorithms this
// package has no named option for.
func WithParam(key string, value any) KeyOption {
	return func(p *params) {
		switch t := value.(type) {
		case string:
			p.UTF8(key, t)
		case []byte:
			p.Octets(key, t)
		case int:
			p.Int(key, t)
		case uint:
			p.UInt(key, t)
		}
	}
}

// GenerateKey creates a key of the named algorithm through this context.
//
//	ctx.GenerateKey("RSA", ossl.WithRSABits(3072))
//	ctx.GenerateKey("EC", ossl.WithGroup("P-256"))
//	ctx.GenerateKey("ED25519")
//	ctx.GenerateKey("ML-DSA-65")        // FIPS 204, OpenSSL 3.5+
//	ctx.GenerateKey("ML-KEM-768")       // FIPS 203, OpenSSL 3.5+
//	ctx.GenerateKey("X25519MLKEM768")   // IETF hybrid KEM, OpenSSL 3.5+
//
// The post-quantum algorithms take no options: the parameter set is part of
// the name.
func (c *Context) GenerateKey(algorithm string, opts ...KeyOption) (*Key, error) {
	clearErrors()
	calg := C.CString(algorithm)
	defer C.free(unsafe.Pointer(calg))

	ctx := C.EVP_PKEY_CTX_new_from_name(c.ptr(), calg, nil)
	if ctx == nil {
		return nil, newError("EVP_PKEY_CTX_new_from_name(" + algorithm + ")")
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_keygen_init(ctx) <= 0 {
		return nil, newError("EVP_PKEY_keygen_init")
	}

	if len(opts) > 0 {
		p := newParams()
		defer p.free()
		for _, o := range opts {
			o(p)
		}
		if C.EVP_PKEY_CTX_set_params(ctx, p.c()) <= 0 {
			return nil, newError("EVP_PKEY_CTX_set_params")
		}
		runtime.KeepAlive(p)
	}

	var pkey *C.EVP_PKEY
	if C.EVP_PKEY_generate(ctx, &pkey) <= 0 {
		return nil, newError("EVP_PKEY_generate(" + algorithm + ")")
	}
	return &Key{pkey: pkey}, nil
}

// Type reports the key's algorithm name, e.g. "RSA", "EC", "ML-DSA-65".
func (k *Key) Type() string {
	if k.pkey == nil {
		return ""
	}
	return C.GoString(C.EVP_PKEY_get0_type_name(k.pkey))
}

// Bits is the key size in bits. It is NOT comparable across algorithm
// families -- 15616 for ML-DSA-65 and 256 for Ed25519 measure different
// things. Use SecurityBits to compare strength.
func (k *Key) Bits() int {
	if k.pkey == nil {
		return 0
	}
	return int(C.EVP_PKEY_get_bits(k.pkey))
}

// SecurityBits is the estimated security level. This is the number to compare
// across algorithms: RSA-3072, P-256, Ed25519 and SLH-DSA-128s all report
// 128; ML-KEM-768 and ML-DSA-65 both report 192.
func (k *Key) SecurityBits() int {
	if k.pkey == nil {
		return 0
	}
	return int(C.EVP_PKEY_get_security_bits(k.pkey))
}

// Size is the maximum output size in bytes for a signature or an encryption
// under this key.
func (k *Key) Size() int {
	if k.pkey == nil {
		return 0
	}
	return int(C.EVP_PKEY_get_size(k.pkey))
}

// Close releases the key. Safe to call more than once.
func (k *Key) Close() error {
	if k.pkey != nil {
		C.EVP_PKEY_free(k.pkey)
		k.pkey = nil
	}
	return nil
}

// oneShotOnly reports whether the algorithm refuses streaming signature
// updates and must go through the single-call EVP_DigestSign.
func (k *Key) oneShotOnly() bool {
	t := strings.ToUpper(k.Type())
	return strings.HasPrefix(t, "ED") ||
		strings.HasPrefix(t, "ML-DSA") ||
		strings.HasPrefix(t, "SLH-DSA")
}

// defaultDigest picks a sensible hash for algorithms that need one, and the
// empty string for algorithms that hash internally.
//
// This is the small piece of policy that lets callers write key.Sign(msg,
// nil) and have it do the right thing whether the key is RSA or ML-DSA.
func (k *Key) defaultDigest() string {
	if k.oneShotOnly() {
		return ""
	}
	if k.SecurityBits() >= 192 {
		return "SHA2-384"
	}
	return "SHA2-256"
}
