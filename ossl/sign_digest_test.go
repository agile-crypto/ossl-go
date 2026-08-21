//go:build cgo

package ossl

import (
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"
)

// The reason SignDigest exists: a caller-computed digest signed under
// Ed25519ph must be trusted as-is, not hashed again. A signature made from
// the digest via SignDigest and a signature made from the original message
// via Sign(msg, {Prehash:true}) sign the same RFC 8032 statement, so each
// must verify under the other's counterpart.
func TestSignDigestNoDoubleHashEd25519(t *testing.T) {
	k, err := Default.GenerateKey(Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("a message hashed once, by the caller")
	digest := sha512.Sum512(msg)

	viaDigest, err := k.SignDigest(digest[:], &SignOptions{Prehash: true})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if err := k.Verify(msg, viaDigest, &SignOptions{Prehash: true}); err != nil {
		t.Errorf("a SignDigest signature did not verify via the message-based Prehash Verify: %v", err)
	}

	viaMessage, err := k.Sign(msg, &SignOptions{Prehash: true})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := k.VerifyDigest(digest[:], viaMessage, &SignOptions{Prehash: true}); err != nil {
		t.Errorf("a Sign(Prehash) signature did not verify via VerifyDigest: %v", err)
	}

	// Negative control, proving the bug SignDigest fixes is real rather than
	// asserted: feeding the digest to the message-based Prehash path -- what
	// a caller without SignDigest would have had to do -- hashes it a second
	// time and must NOT verify against the real message. If this assertion
	// ever starts failing (the double-hashed signature verifies), the two
	// EVP entry points have stopped being different and the rest of this
	// test proves nothing.
	doubleHashed, err := k.Sign(digest[:], &SignOptions{Prehash: true})
	if err != nil {
		t.Fatalf("Sign(digest as message, Prehash): %v", err)
	}
	if err := k.Verify(msg, doubleHashed, &SignOptions{Prehash: true}); err == nil {
		t.Fatal("a signature over SHA-512(digest) verified against the original message; " +
			"Sign and SignDigest are no longer distinguishable and this test is vacuous")
	}
}

func TestSignDigestNoDoubleHashEd448(t *testing.T) {
	k, err := Default.GenerateKey(Ed448)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("a message hashed once, by the caller")
	digest, err := DigestXOF(SHAKE256, msg, eddsaPrehashLen)
	if err != nil {
		t.Fatal(err)
	}

	viaDigest, err := k.SignDigest(digest, &SignOptions{Prehash: true})
	if err != nil {
		t.Fatalf("SignDigest: %v", err)
	}
	if err := k.Verify(msg, viaDigest, &SignOptions{Prehash: true}); err != nil {
		t.Errorf("a SignDigest signature did not verify via the message-based Prehash Verify: %v", err)
	}
}

// RSA and EC: a SignDigest signature must verify against the equivalent
// message through the ordinary Sign/Verify path, and vice versa -- proving
// SignDigest signs the same statement Sign would have, not something the
// digest parameter silently changed.
func TestSignDigestInteroperatesWithSign(t *testing.T) {
	msg := []byte("interoperability probe")
	digest := sha256.Sum256(msg)

	t.Run("RSA-PSS", func(t *testing.T) {
		k, err := Default.GenerateKey(RSA, WithRSABits(2048))
		if err != nil {
			t.Fatal(err)
		}
		defer k.Close()

		viaDigest, err := k.SignDigest(digest[:], nil)
		if err != nil {
			t.Fatalf("SignDigest: %v", err)
		}
		if err := k.Verify(msg, viaDigest, nil); err != nil {
			t.Errorf("SignDigest signature did not verify via message-based Verify: %v", err)
		}

		viaMessage, err := k.Sign(msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := k.VerifyDigest(digest[:], viaMessage, nil); err != nil {
			t.Errorf("Sign signature did not verify via VerifyDigest: %v", err)
		}
	})

	t.Run("RSA-PKCS1v15", func(t *testing.T) {
		k, err := Default.GenerateKey(RSA, WithRSABits(2048))
		if err != nil {
			t.Fatal(err)
		}
		defer k.Close()
		opts := &SignOptions{Padding: RSAPKCS1v15}

		viaDigest, err := k.SignDigest(digest[:], opts)
		if err != nil {
			t.Fatalf("SignDigest: %v", err)
		}
		if err := k.Verify(msg, viaDigest, opts); err != nil {
			t.Errorf("SignDigest signature did not verify via message-based Verify: %v", err)
		}
	})

	t.Run("EC", func(t *testing.T) {
		k, err := Default.GenerateKey(EC, WithGroup(P256))
		if err != nil {
			t.Fatal(err)
		}
		defer k.Close()

		viaDigest, err := k.SignDigest(digest[:], nil)
		if err != nil {
			t.Fatalf("SignDigest: %v", err)
		}
		if err := k.Verify(msg, viaDigest, nil); err != nil {
			t.Errorf("SignDigest signature did not verify via message-based Verify: %v", err)
		}

		viaMessage, err := k.Sign(msg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := k.VerifyDigest(digest[:], viaMessage, nil); err != nil {
			t.Errorf("Sign signature did not verify via VerifyDigest: %v", err)
		}
	})

	t.Run("EC P1363", func(t *testing.T) {
		k, err := Default.GenerateKey(EC, WithGroup(P256))
		if err != nil {
			t.Fatal(err)
		}
		defer k.Close()
		opts := &SignOptions{Format: SignatureP1363}

		viaDigest, err := k.SignDigest(digest[:], opts)
		if err != nil {
			t.Fatalf("SignDigest: %v", err)
		}
		if err := k.Verify(msg, viaDigest, opts); err != nil {
			t.Errorf("SignDigest P1363 signature did not verify via message-based Verify: %v", err)
		}
		if err := k.VerifyDigest(digest[:], viaDigest, opts); err != nil {
			t.Errorf("SignDigest P1363 signature did not verify via VerifyDigest: %v", err)
		}
	})
}

// Pure Ed25519, Ed25519ctx and pure Ed448 have no raw-digest form: the
// algorithm hashes the actual message as part of signing, not a digest of
// it, so there is nothing SignDigest could correctly do with 64 bytes that
// happen to be the right length. Silently treating them as the message
// would produce a signature over the wrong statement.
func TestSignDigestRejectsPureEdDSA(t *testing.T) {
	digest := make([]byte, eddsaPrehashLen)

	k25519, err := Default.GenerateKey(Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	defer k25519.Close()
	if _, err := k25519.SignDigest(digest, nil); err == nil {
		t.Error("SignDigest accepted pure Ed25519 (Prehash unset)")
	}
	if _, err := k25519.SignDigest(digest, &SignOptions{Context: []byte("ctx")}); err == nil {
		t.Error("SignDigest accepted Ed25519ctx")
	}

	k448, err := Default.GenerateKey(Ed448)
	if err != nil {
		t.Fatal(err)
	}
	defer k448.Close()
	if _, err := k448.SignDigest(digest, nil); err == nil {
		t.Error("SignDigest accepted pure Ed448 (Prehash unset)")
	}
}

// ML-DSA and SLH-DSA have no raw-digest form in OpenSSL.
func TestSignDigestRejectsPQC(t *testing.T) {
	k, err := Default.GenerateKey(MLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if _, err := k.SignDigest(make([]byte, 32), nil); err == nil {
		t.Error("SignDigest accepted ML-DSA-65")
	}
}

func TestSignDigestRejectsWrongLength(t *testing.T) {
	k, err := Default.GenerateKey(EC, WithGroup(P256))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if _, err := k.SignDigest(make([]byte, 31), nil); err == nil {
		t.Error("SignDigest accepted a 31-byte digest against SHA2-256 (32 bytes)")
	}

	ked, err := Default.GenerateKey(Ed25519)
	if err != nil {
		t.Fatal(err)
	}
	defer ked.Close()
	if _, err := ked.SignDigest(make([]byte, 63), &SignOptions{Prehash: true}); err == nil {
		t.Error("SignDigest accepted a 63-byte prehash for Ed25519ph")
	}
}

// VerifyDigest must reject a forged or mismatched digest, not merely accept
// anything the right length.
func TestVerifyDigestRejectsWrongDigest(t *testing.T) {
	k, err := Default.GenerateKey(EC, WithGroup(P256))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	digest := sha256.Sum256([]byte("real message"))
	sig, err := k.SignDigest(digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}

	other := sha256.Sum256([]byte("different message"))
	if err := k.VerifyDigest(other[:], sig, nil); !errors.Is(err, ErrVerification) {
		t.Errorf("VerifyDigest accepted a signature against a different digest: %v", err)
	}
}
