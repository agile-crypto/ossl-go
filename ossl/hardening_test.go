//go:build cgo

package ossl

import (
	"bytes"
	"errors"
	"strings"
	"sync"
	"testing"
)

// An XOF has no natural fixed-length digest. Finalising one through Sum used
// to fail internally, latch the error, and return the caller's slice
// unchanged -- so Digest handed back an empty slice with a nil error, and
// every SHAKE digest compared equal to every other one.
func TestDigestRejectsXOF(t *testing.T) {
	for _, name := range []string{"SHAKE-128", "SHAKE-256"} {
		out, err := Digest(name, []byte("abc"))
		if err == nil {
			t.Fatalf("Digest(%s) returned %d bytes and a nil error; want an error directing the caller to DigestXOF", name, len(out))
		}
		if out != nil {
			t.Fatalf("Digest(%s) returned bytes alongside an error", name)
		}
		if !strings.Contains(err.Error(), "SumXOF") {
			t.Fatalf("Digest(%s) error %q does not point at SumXOF", name, err)
		}
	}
}

// The property that actually matters: two different inputs must never
// produce the same "digest" with no error reported.
func TestDigestXOFDoesNotCollapseToEmpty(t *testing.T) {
	a, errA := Digest("SHAKE-256", []byte("input-one"))
	b, errB := Digest("SHAKE-256", []byte("input-two"))
	if errA == nil && errB == nil && bytes.Equal(a, b) {
		t.Fatal("distinct inputs produced equal digests with nil errors")
	}

	// The XOF path proper must still work and must still separate inputs.
	x, err := DigestXOF("SHAKE-256", []byte("input-one"), 32)
	if err != nil {
		t.Fatal(err)
	}
	y, err := DigestXOF("SHAKE-256", []byte("input-two"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(x, y) {
		t.Fatal("DigestXOF produced equal output for distinct inputs")
	}
}

func TestHashIsXOF(t *testing.T) {
	xof, err := Default.NewHash("SHAKE-256")
	if err != nil {
		t.Fatal(err)
	}
	defer xof.Close()
	if !xof.IsXOF() {
		t.Fatal("SHAKE-256 IsXOF() = false")
	}
	if sum := xof.Sum(nil); sum != nil || xof.Err() == nil {
		t.Fatal("Sum on an XOF should return nothing and latch an error")
	}

	fixed, err := Default.NewHash("SHA2-256")
	if err != nil {
		t.Fatal(err)
	}
	defer fixed.Close()
	if fixed.IsXOF() {
		t.Fatal("SHA2-256 IsXOF() = true")
	}
	if sum := fixed.Sum(nil); len(sum) != 32 || fixed.Err() != nil {
		t.Fatalf("Sum on a fixed-length digest: %d bytes, err=%v", len(sum), fixed.Err())
	}
}

// A tag short enough to brute-force is not a usable AEAD, and it round trips
// against itself perfectly, so nothing but an explicit bound catches it.
func TestAEADRejectsWeakTagSize(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	for _, n := range []int{0, 1, 4, 8, 11, 17, 32} {
		if _, err := Default.NewAEAD("AES-256-GCM", key, WithTagSize(n)); err == nil {
			t.Errorf("NewAEAD(AES-256-GCM, tag=%d) succeeded; want rejection", n)
		}
	}
	for _, n := range []int{12, 13, 14, 15, 16} {
		a, err := Default.NewAEAD("AES-256-GCM", key, WithTagSize(n))
		if err != nil {
			t.Errorf("NewAEAD(AES-256-GCM, tag=%d): %v", n, err)
			continue
		}
		a.Close()
	}
}

// CCM's tag is a real parameter of the MAC, and SP 800-38C defines a wider
// valid range than the truncation-based modes. That range must stay open.
func TestAEADCCMTagAndNonceBounds(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	for _, n := range []int{4, 6, 8, 10, 12, 14, 16} {
		a, err := Default.NewAEAD("AES-256-CCM", key, WithTagSize(n))
		if err != nil {
			t.Errorf("NewAEAD(AES-256-CCM, tag=%d): %v", n, err)
			continue
		}
		a.Close()
	}
	for _, n := range []int{2, 3, 5, 18} {
		if _, err := Default.NewAEAD("AES-256-CCM", key, WithTagSize(n)); err == nil {
			t.Errorf("NewAEAD(AES-256-CCM, tag=%d) succeeded; want rejection", n)
		}
	}
	for _, n := range []int{7, 10, 13} {
		a, err := Default.NewAEAD("AES-256-CCM", key, WithIVSize(n))
		if err != nil {
			t.Errorf("NewAEAD(AES-256-CCM, nonce=%d): %v", n, err)
			continue
		}
		a.Close()
	}
	for _, n := range []int{0, 6, 14, 16} {
		if _, err := Default.NewAEAD("AES-256-CCM", key, WithIVSize(n)); err == nil {
			t.Errorf("NewAEAD(AES-256-CCM, nonce=%d) succeeded; want rejection", n)
		}
	}
}

// A zero-length nonce used to slip past the length check in SealErr and then
// index an empty slice, panicking out of the documented error return.
func TestAEADRejectsZeroIVSize(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	if _, err := Default.NewAEAD("AES-256-GCM", key, WithIVSize(0)); err == nil {
		t.Fatal("NewAEAD with a zero-length IV succeeded")
	}
}

func TestAEADSealErrNeverPanics(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	a, err := Default.NewAEAD("AES-256-GCM", key)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SealErr panicked instead of returning an error: %v", r)
		}
	}()
	for _, nonce := range [][]byte{nil, {}, bytes.Repeat([]byte{2}, 11), bytes.Repeat([]byte{2}, 13)} {
		if _, err := a.SealErr(nil, nonce, []byte("data"), nil); err == nil {
			t.Fatalf("SealErr accepted a %d-byte nonce", len(nonce))
		}
	}
}

// AEAD documents itself as safe for concurrent use. Close is part of that
// surface: freeing the EVP_CIPHER out from under an in-flight Seal is a
// use-after-free, and the race detector reports it as a plain data race on
// the fields first. Meaningful under -race; harmless without it.
func TestAEADCloseIsSafeAgainstInFlightOperations(t *testing.T) {
	a, err := Default.NewAEAD("AES-256-GCM", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	nonce := bytes.Repeat([]byte{2}, 12)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				// Either outcome is correct; a panic or a torn read is not.
				if _, err := a.SealErr(nil, nonce, []byte("data"), nil); err != nil && !errors.Is(err, ErrClosed) {
					t.Errorf("SealErr: %v", err)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.Close()
	}()
	wg.Wait()

	if _, err := a.SealErr(nil, nonce, []byte("data"), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("SealErr after Close = %v, want ErrClosed", err)
	}
}

func TestAEADConcurrentSealOpen(t *testing.T) {
	a, err := Default.NewAEAD("AES-256-GCM", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	nonce := bytes.Repeat([]byte{2}, 12)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				ct, err := a.SealErr(nil, nonce, []byte("data"), []byte("aad"))
				if err != nil {
					t.Errorf("SealErr: %v", err)
					return
				}
				pt, err := a.Open(nil, nonce, ct, []byte("aad"))
				if err != nil {
					t.Errorf("Open: %v", err)
					return
				}
				if !bytes.Equal(pt, []byte("data")) {
					t.Error("round trip mismatch")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// An option the algorithm cannot honour must be an error. Dropping it
// silently is invisible to a sign-then-verify test, because both halves drop
// it identically -- which is exactly how a caller ends up believing they
// have domain separation they do not have.
func TestSignOptionsRejectsInapplicableOptions(t *testing.T) {
	rsa, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer rsa.Close()
	ec, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer ec.Close()
	ed, err := Default.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()
	mldsa, err := Default.GenerateKey("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	defer mldsa.Close()

	cases := []struct {
		name string
		key  *Key
		opts *SignOptions
	}{
		{"context on RSA", rsa, &SignOptions{Context: []byte("A")}},
		{"context on EC", ec, &SignOptions{Context: []byte("A")}},
		{"prehash on RSA", rsa, &SignOptions{Prehash: true}},
		{"prehash on ML-DSA", mldsa, &SignOptions{Prehash: true}},
		{"padding on EC", ec, &SignOptions{Padding: RSAPKCS1v15}},
		{"padding on Ed25519", ed, &SignOptions{Padding: RSAPKCS1v15}},
		{"salt length on EC", ec, &SignOptions{PSSSaltLen: 32}},
		{"deterministic on Ed25519", ed, &SignOptions{Deterministic: true}},
		{"deterministic on RSA", rsa, &SignOptions{Deterministic: true}},
		{"deterministic on ML-DSA", mldsa, &SignOptions{Deterministic: true}},
		{"unknown negative salt length", rsa, &SignOptions{PSSSaltLen: -7}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.key.Sign([]byte("m"), c.opts); err == nil {
				t.Error("Sign accepted an option the algorithm cannot honour")
			}
			if err := c.key.Verify([]byte("m"), []byte("sig"), c.opts); err == nil {
				t.Error("Verify accepted an option the algorithm cannot honour")
			}
		})
	}
}

// FIPS 204 §3.2, FIPS 205 §9.2 and RFC 8032 §5.2.6 all cap the context at
// 255 bytes. citius-server enforces the same bound before reaching its own
// backend, and this layer should not depend on that.
func TestSignContextLengthLimit(t *testing.T) {
	k, err := Default.GenerateKey("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	if _, err := k.Sign([]byte("m"), &SignOptions{Context: bytes.Repeat([]byte{1}, 255)}); err != nil {
		t.Fatalf("255-byte context rejected: %v", err)
	}
	for _, n := range []int{256, 1000} {
		_, err := k.Sign([]byte("m"), &SignOptions{Context: bytes.Repeat([]byte{1}, n)})
		if err == nil {
			t.Fatalf("%d-byte context accepted", n)
		}
		if !strings.Contains(err.Error(), "255") {
			t.Fatalf("error for %d-byte context does not name the limit: %v", n, err)
		}
	}
}

// An RSA-PSS key carries its scheme in the key. Routing it through the same
// option handling as a plain RSA key is what makes Padding meaningful for
// it; before, its type name missed the "RSA" comparison entirely and every
// RSA option was skipped without complaint.
func TestRSAPSSKeyHonoursOptions(t *testing.T) {
	k, err := Default.GenerateKey("RSA-PSS")
	if err != nil {
		t.Skipf("RSA-PSS keygen unavailable: %v", err)
	}
	defer k.Close()

	if k.Type() != "RSA-PSS" {
		t.Fatalf("Type() = %q, want RSA-PSS", k.Type())
	}
	if _, err := k.Sign([]byte("m"), &SignOptions{Padding: RSAPKCS1v15}); err == nil {
		t.Fatal("an RSA-PSS key accepted a PKCS#1 v1.5 request")
	}

	msg := []byte("m")
	sig, err := k.Sign(msg, &SignOptions{PSSSaltLen: PSSSaltLengthMax})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := k.Verify(msg, sig, &SignOptions{PSSSaltLen: PSSSaltLengthMax}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// The salt length reached OpenSSL rather than being dropped, so a
	// mismatched policy must reject.
	if err := k.Verify(msg, sig, &SignOptions{PSSSaltLen: PSSSaltLengthHash}); !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify under a mismatched salt policy = %v, want ErrVerification", err)
	}
}

func TestRSAPSSKeyIsNotOneShotOnly(t *testing.T) {
	k, err := Default.GenerateKey("RSA-PSS")
	if err != nil {
		t.Skipf("RSA-PSS keygen unavailable: %v", err)
	}
	defer k.Close()
	if k.oneShotOnly() {
		t.Fatal("RSA-PSS reported as one-shot-only")
	}
}

// A Key must resolve algorithms through the Context it came from. Routing
// Public through the global default silently reintroduces exactly the shared
// provider state that Context exists to avoid.
func TestKeyPublicUsesOriginatingContext(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	prov, err := c.LoadProvider("default")
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Unload()

	k, err := c.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if k.ctx != c {
		t.Fatal("GenerateKey did not record its Context on the Key")
	}

	pub, err := k.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	defer pub.Close()
	if pub.ctx != c {
		t.Fatal("Public() returned a Key bound to a different Context")
	}

	want, err := k.MarshalSPKI()
	if err != nil {
		t.Fatal(err)
	}
	got, err := pub.MarshalSPKI()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Fatal("Public() did not preserve the public key")
	}
}

func TestParsedKeysRecordTheirContext(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	prov, err := c.LoadProvider("default")
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Unload()

	seed, err := c.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Close()
	der, err := seed.MarshalPKCS8()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := seed.MarshalRawPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := c.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Close()
	if parsed.ctx != c {
		t.Error("ParsePKCS8PrivateKey did not record its Context")
	}

	fromRaw, err := c.ParseRawPrivateKey("ED25519", raw)
	if err != nil {
		t.Fatal(err)
	}
	defer fromRaw.Close()
	if fromRaw.ctx != c {
		t.Error("ParseRawPrivateKey did not record its Context")
	}
}

// Using a params arena after free would hand OpenSSL pointers into memory
// already returned to the allocator. Fail loudly instead.
func TestParamsUseAfterFreePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("params.c() after free did not panic")
		}
	}()
	p := newParams().UTF8(pKeyDigest, "SHA2-256")
	p.free()
	_ = p.c()
}

func TestParamsFreeRemainsIdempotent(t *testing.T) {
	p := newParams().UTF8(pKeyDigest, "SHA2-256")
	_ = p.c()
	p.free()
	p.free()
}
