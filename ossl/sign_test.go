//go:build cgo

package ossl

import (
	"bytes"
	"errors"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		alg  string
		opts []KeyOption
	}{
		{"RSA", "RSA", nil},
		{"EC", "EC", []KeyOption{WithGroup("P-256")}},
		{"ED25519", "ED25519", nil},
		{"ED448", "ED448", nil},
		{"ML-DSA-65", "ML-DSA-65", nil},
		{"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", nil},
	}
	msg := []byte("the quick brown fox jumps over the lazy dog")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, err := Default.GenerateKey(c.alg, c.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()

			sig, err := k.Sign(msg, nil)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(sig) == 0 {
				t.Fatal("Sign produced no bytes")
			}
			if err := k.Verify(msg, sig, nil); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	k, err := Default.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	sig, err := k.Sign([]byte("original"), nil)
	if err != nil {
		t.Fatal(err)
	}
	err = k.Verify([]byte("tampered"), sig, nil)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify(tampered message) = %v, want ErrVerification", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("message")
	sig, err := k.Sign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Flip a byte deep in the DER encoding: ECDSA signatures re-parse ASN.1,
	// so a flipped leading byte can make EVP_DigestVerify return negative
	// rather than 0. Both must still resolve to ErrVerification.
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xFF
	err = k.Verify(msg, tampered, nil)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify(corrupted DER prefix) = %v, want ErrVerification", err)
	}

	tampered2 := append([]byte(nil), sig...)
	tampered2[len(tampered2)-1] ^= 0xFF
	err = k.Verify(msg, tampered2, nil)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify(corrupted DER suffix) = %v, want ErrVerification", err)
	}
}

func TestVerifyRejectsEmptySignature(t *testing.T) {
	k, err := Default.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	err = k.Verify([]byte("msg"), nil, nil)
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify(nil sig) = %v, want ErrVerification", err)
	}
}

func TestRSAPKCS1v15(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("message")
	sig, err := k.Sign(msg, &SignOptions{Padding: RSAPKCS1v15})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(msg, sig, &SignOptions{Padding: RSAPKCS1v15}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// PKCS#1 v1.5 signatures are deterministic.
	sig2, err := k.Sign(msg, &SignOptions{Padding: RSAPKCS1v15})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, sig2) {
		t.Fatal("PKCS#1v1.5 signatures over the same message differ")
	}
}

func TestRSAPSSSaltLengthModes(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	msg := []byte("message")

	for _, mode := range []PSSSaltLength{PSSSaltLengthHash, PSSSaltLengthMax, 10} {
		sig, err := k.Sign(msg, &SignOptions{PSSSaltLen: mode})
		if err != nil {
			t.Fatalf("mode %d: Sign: %v", mode, err)
		}
		if err := k.Verify(msg, sig, &SignOptions{PSSSaltLen: mode}); err != nil {
			t.Fatalf("mode %d: Verify with matching mode: %v", mode, err)
		}
	}
}

func TestRSAPSSSaltLengthEnforcedOnVerify(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	msg := []byte("message")

	sig, err := k.Sign(msg, &SignOptions{PSSSaltLen: PSSSaltLengthMax})
	if err != nil {
		t.Fatal(err)
	}
	// A signature made with SALTLEN_MAX must not verify under a strict
	// digest-length policy: the salt lengths differ, so a caller enforcing
	// digest-length salt should reject it even though the signature is
	// otherwise valid.
	err = k.Verify(msg, sig, &SignOptions{PSSSaltLen: PSSSaltLengthHash})
	if !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify(mismatched salt length policy) = %v, want ErrVerification", err)
	}
}

func TestECDSADeterministic(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	msg := []byte("message")

	sig1, err := k.Sign(msg, &SignOptions{Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := k.Sign(msg, &SignOptions{Deterministic: true})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatal("deterministic ECDSA signatures over the same message differ")
	}
	if err := k.Verify(msg, sig1, &SignOptions{Deterministic: true}); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	sig3, err := k.Sign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig4, err := k.Sign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sig3, sig4) {
		t.Fatal("non-deterministic ECDSA signatures over the same message unexpectedly match")
	}
}

func TestEd25519Variants(t *testing.T) {
	k, err := Default.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	msg := []byte("message")

	pure, err := k.Sign(msg, nil)
	if err != nil {
		t.Fatalf("pure Sign: %v", err)
	}
	ctxA, err := k.Sign(msg, &SignOptions{Context: []byte("A")})
	if err != nil {
		t.Fatalf("ctx Sign: %v", err)
	}
	ph, err := k.Sign(msg, &SignOptions{Prehash: true, Context: []byte("A")})
	if err != nil {
		t.Fatalf("ph Sign: %v", err)
	}

	if err := k.Verify(msg, pure, nil); err != nil {
		t.Fatalf("pure Verify: %v", err)
	}
	if err := k.Verify(msg, ctxA, &SignOptions{Context: []byte("A")}); err != nil {
		t.Fatalf("ctx Verify: %v", err)
	}
	if err := k.Verify(msg, ph, &SignOptions{Prehash: true, Context: []byte("A")}); err != nil {
		t.Fatalf("ph Verify: %v", err)
	}

	// Cross-variant and cross-context verification must fail cleanly, not
	// crash or silently accept -- these are different signature schemes
	// sharing one key, not interchangeable encodings of the same one.
	if err := k.Verify(msg, ctxA, nil); !errors.Is(err, ErrVerification) {
		t.Fatalf("pure Verify of ctx signature = %v, want ErrVerification", err)
	}
	if err := k.Verify(msg, ctxA, &SignOptions{Context: []byte("B")}); !errors.Is(err, ErrVerification) {
		t.Fatalf("ctx Verify with wrong context = %v, want ErrVerification", err)
	}
	if err := k.Verify(msg, ph, &SignOptions{Context: []byte("A")}); !errors.Is(err, ErrVerification) {
		t.Fatalf("ctx Verify of ph signature = %v, want ErrVerification", err)
	}
}

func TestEd448Variants(t *testing.T) {
	k, err := Default.GenerateKey("ED448")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	msg := []byte("message")

	pure, err := k.Sign(msg, nil)
	if err != nil {
		t.Fatalf("pure Sign: %v", err)
	}
	if err := k.Verify(msg, pure, nil); err != nil {
		t.Fatalf("pure Verify: %v", err)
	}

	withCtx, err := k.Sign(msg, &SignOptions{Context: []byte("A")})
	if err != nil {
		t.Fatalf("context Sign: %v", err)
	}
	if err := k.Verify(msg, withCtx, &SignOptions{Context: []byte("A")}); err != nil {
		t.Fatalf("context Verify: %v", err)
	}
	if err := k.Verify(msg, withCtx, &SignOptions{Context: []byte("B")}); !errors.Is(err, ErrVerification) {
		t.Fatal("Verify with wrong context unexpectedly succeeded")
	}

	ph, err := k.Sign(msg, &SignOptions{Prehash: true})
	if err != nil {
		t.Fatalf("ph Sign: %v", err)
	}
	if err := k.Verify(msg, ph, &SignOptions{Prehash: true}); err != nil {
		t.Fatalf("ph Verify: %v", err)
	}
	if err := k.Verify(msg, ph, nil); !errors.Is(err, ErrVerification) {
		t.Fatal("pure Verify of ph signature unexpectedly succeeded")
	}
}

func TestMLDSAContextDomainSeparation(t *testing.T) {
	k, err := Default.GenerateKey("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	msg := []byte("message")

	sig, err := k.Sign(msg, &SignOptions{Context: []byte("citius")})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(msg, sig, &SignOptions{Context: []byte("citius")}); err != nil {
		t.Fatalf("Verify with matching context: %v", err)
	}
	if err := k.Verify(msg, sig, &SignOptions{Context: []byte("other")}); !errors.Is(err, ErrVerification) {
		t.Fatal("Verify with wrong context unexpectedly succeeded")
	}
	if err := k.Verify(msg, sig, nil); !errors.Is(err, ErrVerification) {
		t.Fatal("Verify with no context unexpectedly succeeded")
	}
}

func TestSLHDSAContextDomainSeparation(t *testing.T) {
	k, err := Default.GenerateKey("SLH-DSA-SHA2-128s")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	msg := []byte("message")

	sig, err := k.Sign(msg, &SignOptions{Context: []byte("citius")})
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(msg, sig, &SignOptions{Context: []byte("citius")}); err != nil {
		t.Fatalf("Verify with matching context: %v", err)
	}
	if err := k.Verify(msg, sig, &SignOptions{Context: []byte("other")}); !errors.Is(err, ErrVerification) {
		t.Fatal("Verify with wrong context unexpectedly succeeded")
	}
}

func TestSignClosedKey(t *testing.T) {
	k, err := Default.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	k.Close()

	if _, err := k.Sign([]byte("msg"), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Sign on closed key = %v, want ErrClosed", err)
	}
	if err := k.Verify([]byte("msg"), []byte("sig"), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Verify on closed key = %v, want ErrClosed", err)
	}
}

func TestDefaultDigestBySecurityLevel(t *testing.T) {
	rsa, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer rsa.Close()
	if got := rsa.defaultDigest(); got != "SHA2-256" {
		t.Fatalf("RSA-2048 defaultDigest() = %q, want SHA2-256", got)
	}

	p384, err := Default.GenerateKey("EC", WithGroup("P-384"))
	if err != nil {
		t.Fatal(err)
	}
	defer p384.Close()
	if got := p384.defaultDigest(); got != "SHA2-384" {
		t.Fatalf("P-384 defaultDigest() = %q, want SHA2-384", got)
	}

	ed, err := Default.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()
	if got := ed.defaultDigest(); got != "" {
		t.Fatalf("Ed25519 defaultDigest() = %q, want empty", got)
	}
}

func TestOneShotOnly(t *testing.T) {
	cases := map[string]bool{
		"RSA":               false,
		"EC":                false,
		"ED25519":           true,
		"ED448":             true,
		"ML-DSA-65":         true,
		"SLH-DSA-SHA2-128s": true,
	}
	for alg, want := range cases {
		var opts []KeyOption
		if alg == "EC" {
			opts = []KeyOption{WithGroup("P-256")}
		}
		k, err := Default.GenerateKey(alg, opts...)
		if err != nil {
			t.Fatal(err)
		}
		if got := k.oneShotOnly(); got != want {
			t.Errorf("%s: oneShotOnly() = %v, want %v", alg, got, want)
		}
		k.Close()
	}
}
