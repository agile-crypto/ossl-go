package ossl

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestHKDFKAT pins RFC 5869 test case 1 (independently recomputed with
// `openssl kdf ... HKDF`, not transcribed from memory).
func TestHKDFKAT(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	want := "3cb25f25faacd57a90434f64d0362f2a" +
		"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
		"34007208d5b887185865"

	out, err := Default.HKDF("SHA2-256", ikm, salt, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(out) != want {
		t.Fatalf("HKDF = %x\nwant  %s", out, want)
	}
}

func TestHKDFDomainSeparation(t *testing.T) {
	secret := []byte("a high-entropy shared secret, 32 bytes")

	encKey, err := Default.HKDF("SHA2-256", secret, nil, []byte("encryption key v1"), 32)
	if err != nil {
		t.Fatal(err)
	}
	macKey, err := Default.HKDF("SHA2-256", secret, nil, []byte("mac key v1"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encKey, macKey) {
		t.Fatal("two different info strings produced the same key")
	}

	// Same secret, same info, twice: must be deterministic.
	encKey2, err := Default.HKDF("SHA2-256", secret, nil, []byte("encryption key v1"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encKey, encKey2) {
		t.Fatal("HKDF with identical inputs produced different output")
	}
}

func TestHKDFExpand(t *testing.T) {
	// A PRK that is already uniform (as if freshly extracted); expand-only
	// must still be deterministic and info-separated the same way HKDF is.
	prk := bytes.Repeat([]byte{0x42}, 32)
	a, err := Default.HKDFExpand("SHA2-256", prk, []byte("a"), 16)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Default.HKDFExpand("SHA2-256", prk, []byte("b"), 16)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("HKDFExpand with different info produced the same output")
	}
}

// TestPBKDF2KAT pins the well-known RFC 6070 vector (password="password",
// salt="salt", c=1, dkLen=20; independently recomputed with `openssl kdf`).
// c=1 is deliberately weak - it is chosen only to keep the test fast, not as
// a usage recommendation (see the PBKDF2 doc comment: >= 600000 in practice).
func TestPBKDF2KAT(t *testing.T) {
	want := "0c60c80f961f0e71f3a9b524af6012062fe037a6"
	out, err := Default.PBKDF2("SHA1", []byte("password"), []byte("salt"), 1, 20)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(out) != want {
		t.Fatalf("PBKDF2 = %x\nwant   %s", out, want)
	}
}

func TestPBKDF2DifferentSaltDiffers(t *testing.T) {
	a, err := Default.PBKDF2("SHA2-256", []byte("password"), []byte("salt-a"), 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Default.PBKDF2("SHA2-256", []byte("password"), []byte("salt-b"), 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("PBKDF2 with different salts produced the same key")
	}
}

func TestArgon2idDefaults(t *testing.T) {
	out, err := Default.Argon2id([]byte("password"), []byte("somesalt12345678"), Argon2idParams{}, 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 32 {
		t.Fatalf("Argon2id output length = %d, want 32", len(out))
	}
}

// TestArgon2idLanesGreaterThanOne exercises the fix verified against this
// OpenSSL build directly: Lanes > 1 means threads > 1 is requested too, and
// that fails with "invalid thread pool size" unless the context's thread
// budget has been raised first via OSSL_set_max_threads. Without that fix,
// this test fails outright rather than merely running slowly.
func TestArgon2idLanesGreaterThanOne(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	out, err := c.Argon2id([]byte("password"), []byte("somesalt12345678"),
		Argon2idParams{Lanes: 4, MemoryKiB: 8 * 1024, Iterations: 1}, 32)
	if err != nil {
		t.Fatalf("Argon2id with Lanes=4: %v", err)
	}
	if len(out) != 32 {
		t.Fatalf("Argon2id output length = %d, want 32", len(out))
	}

	// The derivation is deterministic in Lanes, not just in whether it
	// succeeds: the same Lanes value on a fresh context must reproduce it.
	c2, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	out2, err := c2.Argon2id([]byte("password"), []byte("somesalt12345678"),
		Argon2idParams{Lanes: 4, MemoryKiB: 8 * 1024, Iterations: 1}, 32)
	if err != nil {
		t.Fatalf("Argon2id with Lanes=4 on a second context: %v", err)
	}
	if !bytes.Equal(out, out2) {
		t.Fatal("Argon2id with the same Lanes/params produced different output across contexts")
	}
}

func TestDeriveKDFGeneric(t *testing.T) {
	// The escape hatch, exercised against PBKDF2 rather than a named helper,
	// to prove the map[string]any -> OSSL_PARAM translation actually works
	// end to end and not just for the three algorithms with named wrappers.
	out, err := Default.DeriveKDF("PBKDF2", KDFParams{
		"digest": "SHA2-256",
		"pass":   []byte("password"),
		"salt":   []byte("salt"),
		"iter":   uint(1000),
	}, 32)
	if err != nil {
		t.Fatal(err)
	}

	want, err := Default.PBKDF2("SHA2-256", []byte("password"), []byte("salt"), 1000, 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("DeriveKDF(PBKDF2) = %x\nwant                %x", out, want)
	}
}

func TestDeriveKDFUnsupportedParamType(t *testing.T) {
	_, err := Default.DeriveKDF("PBKDF2", KDFParams{
		"iter": 3.14, // float64 is not one of the supported param value types
	}, 32)
	if err == nil {
		t.Fatal("DeriveKDF with an unsupported param value type succeeded")
	}
}

func TestDeriveKDFNonPositiveLength(t *testing.T) {
	if _, err := Default.HKDF("SHA2-256", []byte("secret"), nil, nil, 0); err == nil {
		t.Fatal("HKDF with n=0 succeeded")
	}
	if _, err := Default.HKDF("SHA2-256", []byte("secret"), nil, nil, -1); err == nil {
		t.Fatal("HKDF with n=-1 succeeded")
	}
}

func TestHKDFUnknownDigest(t *testing.T) {
	if _, err := Default.HKDF("TOTALLY-MADE-UP-DIGEST", []byte("secret"), nil, nil, 32); err == nil {
		t.Fatal("HKDF with a made-up digest name succeeded")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("mustHex(%q): %v", s, err)
	}
	return b
}
