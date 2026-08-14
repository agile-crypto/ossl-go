//go:build cgo

package ossl

import "testing"

func TestGenerateKeyAcrossAlgorithms(t *testing.T) {
	cases := []struct {
		name string
		alg  string
		opts []KeyOption
	}{
		{"RSA", "RSA", []KeyOption{WithRSABits(3072)}},
		{"EC", "EC", []KeyOption{WithGroup("P-256")}},
		{"ED25519", "ED25519", nil},
		{"X25519", "X25519", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, err := Default.GenerateKey(c.alg, c.opts...)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", c.alg, err)
			}
			defer k.Close()

			if k.Type() != c.alg {
				t.Fatalf("Type() = %q, want %q", k.Type(), c.alg)
			}
			if k.Bits() <= 0 {
				t.Fatalf("Bits() = %d, want > 0", k.Bits())
			}
			if k.SecurityBits() <= 0 {
				t.Fatalf("SecurityBits() = %d, want > 0", k.SecurityBits())
			}
		})
	}
}

// TestGenerateKeyPQC mirrors 05_keygen.c's post-quantum coverage: ML-KEM,
// ML-DSA, SLH-DSA, and the IETF hybrid KEM, all new in OpenSSL 3.5 and all
// taking no KeyOption since the parameter set is baked into the name.
func TestGenerateKeyPQC(t *testing.T) {
	for _, alg := range []string{
		"ML-KEM-768",
		"ML-DSA-65",
		"SLH-DSA-SHA2-128s",
		"X25519MLKEM768",
	} {
		t.Run(alg, func(t *testing.T) {
			k, err := Default.GenerateKey(alg)
			if err != nil {
				t.Fatalf("GenerateKey(%s): %v", alg, err)
			}
			defer k.Close()

			if k.Type() != alg {
				t.Fatalf("Type() = %q, want %q", k.Type(), alg)
			}
			t.Logf("%-18s bits=%-6d security-bits=%d", alg, k.Bits(), k.SecurityBits())
		})
	}
}

// TestSecurityBitsComparableAcrossFamilies pins the exact reason both Bits
// and SecurityBits are exported: Bits measures completely different things
// per algorithm family (a modulus size, a field size, a key encoding size)
// while SecurityBits is the number actually meant to be compared. Values
// independently confirmed by running 05_keygen.c against this same OpenSSL
// 3.5.2 build earlier in this project.
func TestSecurityBitsComparableAcrossFamilies(t *testing.T) {
	level128 := []struct {
		alg  string
		opts []KeyOption
	}{
		{"RSA", []KeyOption{WithRSABits(3072)}},
		{"EC", []KeyOption{WithGroup("P-256")}},
		{"ED25519", nil},
		{"SLH-DSA-SHA2-128s", nil},
	}
	for _, c := range level128 {
		k, err := Default.GenerateKey(c.alg, c.opts...)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", c.alg, err)
		}
		if k.SecurityBits() != 128 {
			t.Errorf("%s: SecurityBits() = %d, want 128", c.alg, k.SecurityBits())
		}
		k.Close()
	}

	level192 := []string{"ML-KEM-768", "ML-DSA-65"}
	for _, alg := range level192 {
		k, err := Default.GenerateKey(alg)
		if err != nil {
			t.Fatalf("GenerateKey(%s): %v", alg, err)
		}
		if k.SecurityBits() != 192 {
			t.Errorf("%s: SecurityBits() = %d, want 192", alg, k.SecurityBits())
		}
		k.Close()
	}

	// Bits() is NOT comparable the same way: ML-DSA-65's key encoding
	// (15616 bits) and Ed25519's field size (256 bits) do not measure the
	// same thing, despite both algorithms existing at real security levels.
	mldsa, err := Default.GenerateKey("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	defer mldsa.Close()
	ed25519, err := Default.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	defer ed25519.Close()

	if mldsa.Bits() == ed25519.Bits() {
		t.Fatal("ML-DSA-65 and Ed25519 unexpectedly report the same Bits() - the comparability claim needs re-checking")
	}
	if mldsa.Bits() != 15616 {
		t.Fatalf("ML-DSA-65 Bits() = %d, want 15616 (confirmed independently against this build)", mldsa.Bits())
	}
	if ed25519.Bits() != 256 {
		t.Fatalf("Ed25519 Bits() = %d, want 256", ed25519.Bits())
	}
}

func TestGenerateKeyUnknownAlgorithm(t *testing.T) {
	if _, err := Default.GenerateKey("TOTALLY-MADE-UP-ALGORITHM"); err == nil {
		t.Fatal("GenerateKey with a made-up algorithm name succeeded")
	}
}

func TestKeySize(t *testing.T) {
	k, err := Default.GenerateKey("RSA", WithRSABits(3072))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	if k.Size() != 384 { // 3072 bits / 8
		t.Fatalf("Size() = %d, want 384", k.Size())
	}
}

func TestKeyCloseIsIdempotent(t *testing.T) {
	k, err := Default.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := k.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if k.Type() != "" {
		t.Fatalf("Type() after Close = %q, want \"\"", k.Type())
	}
	if k.Bits() != 0 {
		t.Fatalf("Bits() after Close = %d, want 0", k.Bits())
	}
	if k.SecurityBits() != 0 {
		t.Fatalf("SecurityBits() after Close = %d, want 0", k.SecurityBits())
	}
	if k.Size() != 0 {
		t.Fatalf("Size() after Close = %d, want 0", k.Size())
	}
}
