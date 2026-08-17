//go:build cgo

package ossl

/*
#include <openssl/evp.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

// Signer streams a message into a signature, for data too large to hold in
// memory at once. It satisfies io.Writer, so io.Copy from a file or a
// network connection works directly:
//
//	s, err := ossl.NewSigner(key, nil)
//	defer s.Close()
//	io.Copy(s, f)
//	sig, err := s.Sign()
//
// Only available for algorithms that permit streaming. Ed25519, Ed448,
// ML-DSA and SLH-DSA hash the whole message internally as part of the
// signature construction and reject incremental updates outright, so
// NewSigner refuses them up front rather than letting the failure surface
// from some later Write; use Key.Sign for those.
//
// Not safe for concurrent use: the accumulated digest state is the point of
// the type, and interleaved writes would produce a signature over an
// undefined interleaving of the inputs.
type Signer struct {
	mdctx *C.EVP_MD_CTX
	pkey  *C.EVP_PKEY
	name  string
	done  bool
}

var _ io.Writer = (*Signer)(nil)

// Verifier streams a message and checks a signature over it, mirroring
// Signer. The signature is supplied at the end, to Verify, because that is
// when EVP has the whole message.
//
// Same restriction and same concurrency rules as Signer.
type Verifier struct {
	mdctx *C.EVP_MD_CTX
	pkey  *C.EVP_PKEY
	name  string
	done  bool
}

var _ io.Writer = (*Verifier)(nil)

// streamInit builds an EVP_MD_CTX ready for incremental signing or
// verifying, shared by NewSigner and NewVerifier because the two differ only
// in which Init they call.
//
// The returned context takes its own reference on the key with
// EVP_PKEY_up_ref, released by Close.
//
// This is deliberately redundant: EVP_DigestSignInit_ex evidently references
// the key as well, since closing the Key mid-stream and finalising afterward
// works with the up-ref removed. But "evidently" is the whole problem --
// that was established by observing that nothing broke, and a use-after-free
// that happens not to crash observes exactly the same way. Holding a
// reference this layer owns makes the lifetime a property of this code
// rather than an inference about OpenSSL's, at the cost of one atomic
// increment per stream.
func streamInit(k *Key, opts *SignOptions, verify bool) (*C.EVP_MD_CTX, *C.EVP_PKEY, error) {
	if k == nil || k.pkey == nil {
		return nil, nil, ErrClosed
	}
	if k.oneShotOnly() {
		return nil, nil, fmt.Errorf(
			"ossl: %s hashes the message internally and cannot be streamed; use Key.Sign or Key.Verify",
			k.Type())
	}
	o := k.signOpts(opts)
	if err := checkSignOptions(k.Type(), o); err != nil {
		return nil, nil, err
	}
	clearErrors()

	mdctx := C.EVP_MD_CTX_new()
	if mdctx == nil {
		return nil, nil, newError("EVP_MD_CTX_new")
	}
	if C.EVP_PKEY_up_ref(k.pkey) != 1 {
		C.EVP_MD_CTX_free(mdctx)
		return nil, nil, newError("EVP_PKEY_up_ref")
	}
	pkey := k.pkey

	var cd *C.char
	if o.Digest != "" {
		cd = C.CString(o.Digest)
		defer C.free(unsafe.Pointer(cd))
	}

	var pctx *C.EVP_PKEY_CTX
	var rc C.int
	op := "EVP_DigestSignInit_ex"
	if verify {
		op = "EVP_DigestVerifyInit_ex"
		rc = C.EVP_DigestVerifyInit_ex(mdctx, &pctx, cd, nil, nil, pkey, nil)
	} else {
		rc = C.EVP_DigestSignInit_ex(mdctx, &pctx, cd, nil, nil, pkey, nil)
	}
	if rc <= 0 {
		C.EVP_PKEY_free(pkey)
		C.EVP_MD_CTX_free(mdctx)
		return nil, nil, newError(op)
	}
	if err := applySignOptions(pctx, k.Type(), o); err != nil {
		C.EVP_PKEY_free(pkey)
		C.EVP_MD_CTX_free(mdctx)
		return nil, nil, err
	}
	return mdctx, pkey, nil
}

// NewSigner begins a streaming signature over key.
func NewSigner(k *Key, opts *SignOptions) (*Signer, error) {
	mdctx, pkey, err := streamInit(k, opts, false)
	if err != nil {
		return nil, err
	}
	return &Signer{mdctx: mdctx, pkey: pkey, name: k.Type()}, nil
}

// NewVerifier begins a streaming verification against key.
func NewVerifier(k *Key, opts *SignOptions) (*Verifier, error) {
	mdctx, pkey, err := streamInit(k, opts, true)
	if err != nil {
		return nil, err
	}
	return &Verifier{mdctx: mdctx, pkey: pkey, name: k.Type()}, nil
}

// Name reports the key algorithm this signer was built for.
func (s *Signer) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

// Name reports the key algorithm this verifier was built for.
func (v *Verifier) Name() string {
	if v == nil {
		return ""
	}
	return v.name
}

func (s *Signer) Write(p []byte) (int, error) {
	if s == nil || s.mdctx == nil {
		return 0, ErrClosed
	}
	if s.done {
		return 0, fmt.Errorf("ossl: Signer already finalised by Sign")
	}
	if len(p) == 0 {
		return 0, nil
	}
	rc := C.EVP_DigestSignUpdate(s.mdctx, unsafe.Pointer(&p[0]), C.size_t(len(p)))
	runtime.KeepAlive(p)
	if rc <= 0 {
		return 0, newError("EVP_DigestSignUpdate")
	}
	return len(p), nil
}

func (v *Verifier) Write(p []byte) (int, error) {
	if v == nil || v.mdctx == nil {
		return 0, ErrClosed
	}
	if v.done {
		return 0, fmt.Errorf("ossl: Verifier already finalised by Verify")
	}
	if len(p) == 0 {
		return 0, nil
	}
	rc := C.EVP_DigestVerifyUpdate(v.mdctx, unsafe.Pointer(&p[0]), C.size_t(len(p)))
	runtime.KeepAlive(p)
	if rc <= 0 {
		return 0, newError("EVP_DigestVerifyUpdate")
	}
	return len(p), nil
}

// Sign finalises and returns the signature. The Signer cannot be written to
// or signed again afterward; the EVP context is not in a defined state for
// reuse once finalised, so the restriction is enforced rather than left to
// produce a surprising second result.
func (s *Signer) Sign() ([]byte, error) {
	if s == nil || s.mdctx == nil {
		return nil, ErrClosed
	}
	if s.done {
		return nil, fmt.Errorf("ossl: Signer already finalised by Sign")
	}
	var n C.size_t
	if C.EVP_DigestSignFinal(s.mdctx, nil, &n) <= 0 {
		return nil, newError("EVP_DigestSignFinal(size)")
	}
	if n == 0 {
		return nil, newError("EVP_DigestSignFinal reported a zero-length signature")
	}
	sig := make([]byte, int(n))
	rc := C.EVP_DigestSignFinal(s.mdctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &n)
	runtime.KeepAlive(sig)
	if rc <= 0 {
		return nil, newError("EVP_DigestSignFinal")
	}
	s.done = true
	// n may shrink: ECDSA signatures are DER and vary by a byte or two.
	return sig[:n], nil
}

// Verify checks sig against everything written so far. It returns nil if the
// signature is valid, ErrVerification if it is not, and an *Error if the
// call itself failed -- the same three-way distinction Key.Verify draws, and
// for the same reason: a negative return from EVP means the signature did
// not parse, which is a rejection rather than a fault.
//
// Like Signer.Sign, this finalises the Verifier.
func (v *Verifier) Verify(sig []byte) error {
	if v == nil || v.mdctx == nil {
		return ErrClosed
	}
	if v.done {
		return fmt.Errorf("ossl: Verifier already finalised by Verify")
	}
	if len(sig) == 0 {
		v.done = true
		return ErrVerification
	}
	rc := C.EVP_DigestVerifyFinal(v.mdctx,
		(*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig)))
	runtime.KeepAlive(sig)
	v.done = true

	switch {
	case rc == 1:
		return nil
	case rc == 0:
		clearErrors()
		return ErrVerification
	default:
		detail := newError("EVP_DigestVerifyFinal")
		return fmt.Errorf("%w: %s", ErrVerification, detail)
	}
}

// Close releases the signer, including its reference on the key. Safe to
// call more than once.
func (s *Signer) Close() error {
	if s == nil {
		return nil
	}
	if s.mdctx != nil {
		C.EVP_MD_CTX_free(s.mdctx)
		s.mdctx = nil
	}
	if s.pkey != nil {
		C.EVP_PKEY_free(s.pkey)
		s.pkey = nil
	}
	return nil
}

// Close releases the verifier, including its reference on the key. Safe to
// call more than once.
func (v *Verifier) Close() error {
	if v == nil {
		return nil
	}
	if v.mdctx != nil {
		C.EVP_MD_CTX_free(v.mdctx)
		v.mdctx = nil
	}
	if v.pkey != nil {
		C.EVP_PKEY_free(v.pkey)
		v.pkey = nil
	}
	return nil
}
