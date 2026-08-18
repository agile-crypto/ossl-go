//go:build cgo

package ossl

/*
#include <openssl/ec.h>
*/
import "C"

import (
	"fmt"
	"strings"
	"sync"
)

// Capability describes something a caller wants to do, so that it can be
// checked before anything depends on it.
//
// # Why this is not a list of supported algorithms
//
// The obvious API here would be a flat list of names this build supports,
// which a caller intersects with its own catalogue. That gives wrong
// answers, because support is a property of the combination rather than of
// the parts. Measured against this build, all of the following have every
// component "available" and none of them work as a combination:
//
//	Ed25519 with an explicit SHA2-256 digest   (hashes internally; rejects one)
//	ML-DSA-65 with an explicit SHA2-256 digest (same)
//	ECDSA P-256 with SHAKE-256                 (an XOF cannot be a signature digest)
//	Ed448 with the IEEE P1363 format           (that encoding is ECDSA-only)
//
// A caller pre-validating against a parts list would advertise all four and
// fail at execution, which is the opposite of what pre-validation is for.
type Capability interface {
	// check applies structural rules and availability queries. No key
	// generation, no cryptographic operation.
	check(*Context) error
	// trial performs the real operation on ephemeral material.
	trial(*Context) error
	// describe names the capability for error messages.
	describe() string
}

// Supports reports whether this context can perform the described operation,
// returning nil if it can and an explanatory error if not.
//
// The check is structural: availability queries plus the same rules the
// operation itself would apply. It generates no keys and performs no
// cryptography, so it is cheap enough to run across a whole catalogue at
// startup.
//
// Structural checking cannot see a restriction that only appears when the
// operation actually runs -- a provider that advertises an algorithm and
// then refuses a particular parameter, say. VerifyCapability answers that
// question by doing the work.
func (c *Context) Supports(cap Capability) error {
	if c == nil {
		return ErrClosed
	}
	if cap == nil {
		return fmt.Errorf("ossl: nil capability")
	}
	return cap.check(c)
}

// VerifyCapability proves the capability by performing it: generating an
// ephemeral key where one is needed and running the operation end to end.
//
// This is authoritative where Supports is only well-informed, and costs a
// key generation -- seconds for RSA-4096 or SLH-DSA. Use it to confirm a
// configuration once, not on a request path.
func (c *Context) VerifyCapability(cap Capability) error {
	if c == nil {
		return ErrClosed
	}
	if cap == nil {
		return fmt.Errorf("ossl: nil capability")
	}
	if err := cap.check(c); err != nil {
		return err
	}
	if err := cap.trial(c); err != nil {
		return fmt.Errorf("ossl: %s passed the structural check but failed in practice: %w",
			cap.describe(), err)
	}
	return nil
}

// SignatureCapability is a signature configuration to check.
//
// Leave Digest empty for the algorithms that hash internally -- Ed25519,
// Ed448, ML-DSA, SLH-DSA -- which is also what Key.Sign does with a nil
// SignOptions.
type SignatureCapability struct {
	Key    KeyAlgorithm
	Curve  Curve // EC keys only
	Digest DigestName
	Format SignatureFormat

	Prehash       bool
	Deterministic bool
	// Context reports that the caller intends to pass a domain-separation
	// context, which only some algorithms accept.
	Context bool
}

func (s SignatureCapability) describe() string {
	parts := []string{string(s.Key)}
	if s.Curve != "" {
		parts = append(parts, string(s.Curve))
	}
	if s.Digest != "" {
		parts = append(parts, string(s.Digest))
	}
	if s.Format != SignatureDER {
		parts = append(parts, s.Format.String())
	}
	return strings.Join(parts, "/")
}

// options renders the capability as the SignOptions an operation would use,
// so that one set of rules governs both.
func (s SignatureCapability) options() *SignOptions {
	o := &SignOptions{
		Digest:        s.Digest,
		Format:        s.Format,
		Prehash:       s.Prehash,
		Deterministic: s.Deterministic,
	}
	if s.Context {
		o.Context = []byte("capability-probe")
	}
	return o
}

func (s SignatureCapability) check(c *Context) error {
	if s.Key == "" {
		return fmt.Errorf("ossl: SignatureCapability needs a key algorithm")
	}
	if !c.KeyAlgorithmAvailable(s.Key) {
		return fmt.Errorf("ossl: key algorithm %q is not available in this context", s.Key)
	}
	if s.Curve != "" && s.Key != EC {
		return fmt.Errorf("ossl: a curve is meaningful only for EC keys, not %s", s.Key)
	}
	if s.Key == EC && s.Curve == "" {
		return fmt.Errorf("ossl: an EC signature capability needs a curve")
	}
	if s.Curve != "" {
		ok, err := curveSupported(s.Curve)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("ossl: curve %q is not built into this libcrypto", s.Curve)
		}
	}

	// The digest rules. These are the ones a parts-availability check gets
	// wrong, so they are stated explicitly rather than left to the fetch.
	internal := hashesInternally(s.Key)
	switch {
	case internal && s.Digest != "":
		return fmt.Errorf(
			"ossl: %s hashes the message itself and rejects an explicit digest; leave Digest empty",
			s.Key)
	case !internal && s.Digest == "":
		// Permitted: Key.Sign picks a default for these.
	case s.Digest != "":
		if !c.DigestAvailable(s.Digest, "") {
			return fmt.Errorf("ossl: digest %q is not available in this context", s.Digest)
		}
		xof, err := c.digestIsXOF(s.Digest)
		if err != nil {
			return err
		}
		if xof {
			return fmt.Errorf(
				"ossl: %q is an extendable-output function and cannot be a signature digest", s.Digest)
		}
	}

	// Everything else -- format, prehash, determinism, context -- is already
	// governed by the rules the signing path applies, so reuse them rather
	// than restate them.
	return checkSignOptions(s.Key, s.options())
}

func (s SignatureCapability) trial(c *Context) error {
	var opts []KeyOption
	if s.Curve != "" {
		opts = append(opts, WithGroup(s.Curve))
	}
	k, err := c.GenerateKey(s.Key, opts...)
	if err != nil {
		return err
	}
	defer k.Close()

	msg := []byte("ossl capability probe")
	sig, err := k.Sign(msg, s.options())
	if err != nil {
		return err
	}
	return k.Verify(msg, sig, s.options())
}

// AEADCapability is an authenticated cipher configuration to check.
type AEADCapability struct {
	Cipher CipherName
	// KeyBytes is the key length. Zero means the algorithm's own.
	KeyBytes int
	// IVBytes and TagBytes are zero for the algorithm's defaults.
	IVBytes  int
	TagBytes int
}

func (a AEADCapability) describe() string {
	d := string(a.Cipher)
	if a.IVBytes > 0 || a.TagBytes > 0 {
		d += fmt.Sprintf(" (iv=%d tag=%d)", a.IVBytes, a.TagBytes)
	}
	return d
}

func (a AEADCapability) check(c *Context) error {
	if a.Cipher == "" {
		return fmt.Errorf("ossl: AEADCapability needs a cipher")
	}
	if !c.CipherAvailable(a.Cipher, "") {
		return fmt.Errorf("ossl: cipher %q is not available in this context", a.Cipher)
	}
	// Constructing the AEAD applies every size and mode rule this package
	// has, including that the cipher is actually an AEAD mode, without
	// encrypting anything.
	key := make([]byte, a.keyLen(c))
	var opts []AEADOption
	if a.IVBytes > 0 {
		opts = append(opts, WithIVSize(a.IVBytes))
	}
	if a.TagBytes > 0 {
		opts = append(opts, WithTagSize(a.TagBytes))
	}
	aead, err := c.NewAEAD(a.Cipher, key, opts...)
	if err != nil {
		return err
	}
	return aead.Close()
}

func (a AEADCapability) keyLen(c *Context) int {
	if a.KeyBytes > 0 {
		return a.KeyBytes
	}
	if n, err := c.cipherKeyLength(a.Cipher); err == nil {
		return n
	}
	return 32
}

func (a AEADCapability) trial(c *Context) error {
	key := make([]byte, a.keyLen(c))
	var opts []AEADOption
	if a.IVBytes > 0 {
		opts = append(opts, WithIVSize(a.IVBytes))
	}
	if a.TagBytes > 0 {
		opts = append(opts, WithTagSize(a.TagBytes))
	}
	aead, err := c.NewAEAD(a.Cipher, key, opts...)
	if err != nil {
		return err
	}
	defer aead.Close()

	nonce := make([]byte, aead.NonceSize())
	pt := []byte("ossl capability probe")
	aad := []byte("probe-aad")
	ct, err := aead.SealErr(nil, nonce, pt, aad)
	if err != nil {
		return err
	}
	got, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return err
	}
	if string(got) != string(pt) {
		return fmt.Errorf("round trip returned different plaintext")
	}
	return nil
}

// hashesInternally reports whether the algorithm computes its own message
// digest and therefore refuses an externally supplied one.
func hashesInternally(k KeyAlgorithm) bool {
	t := strings.ToUpper(string(k))
	return strings.HasPrefix(t, "ED25519") ||
		strings.HasPrefix(t, "ED448") ||
		strings.HasPrefix(t, "ML-DSA") ||
		strings.HasPrefix(t, "SLH-DSA")
}

var (
	curveOnce sync.Once
	curveNIDs map[int]bool
	curveErr  error
)

// curveSupported reports whether libcrypto was built with the named curve.
//
// The name is resolved to a NID first, so that every spelling EVP accepts is
// accepted here: "P-256" and "prime256v1" are the same curve, and rejecting
// one of them would make this check disagree with the operation it is
// supposed to predict. The built-in table is a compile-time property of the
// library, so it is read once.
func curveSupported(name Curve) (bool, error) {
	curveOnce.Do(func() {
		n := C.EC_get_builtin_curves(nil, 0)
		if n == 0 {
			curveNIDs = map[int]bool{}
			return
		}
		buf := make([]C.EC_builtin_curve, int(n))
		got := C.EC_get_builtin_curves(&buf[0], C.size_t(n))
		curveNIDs = make(map[int]bool, int(got))
		for i := 0; i < int(got); i++ {
			curveNIDs[int(buf[i].nid)] = true
		}
	})
	if curveErr != nil {
		return false, curveErr
	}
	nid := curveNID(name)
	if nid == 0 {
		return false, nil
	}
	return curveNIDs[nid], nil
}
