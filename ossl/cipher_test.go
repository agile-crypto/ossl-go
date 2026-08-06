package ossl

import (
	"bytes"
	"testing"
)

func TestAEADRoundTrip(t *testing.T) {
	for _, alg := range []string{"AES-256-GCM", "ChaCha20-Poly1305"} {
		t.Run(alg, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x11}, 32)
			aead, err := Default.NewAEAD(alg, key)
			if err != nil {
				t.Fatal(err)
			}
			defer aead.Close()

			nonce := bytes.Repeat([]byte{0x22}, aead.NonceSize())
			plaintext := []byte("Attack at dawn. Bring coffee.")
			aad := []byte("msg-id:42;version:1")

			ct := aead.Seal(nil, nonce, plaintext, aad)
			if len(ct) != len(plaintext)+aead.Overhead() {
				t.Fatalf("ciphertext length = %d, want %d", len(ct), len(plaintext)+aead.Overhead())
			}

			pt, err := aead.Open(nil, nonce, ct, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("decrypted = %q, want %q", pt, plaintext)
			}
		})
	}
}

// The five negative paths below mirror 04_aead.c's tamper checks: everything
// that must make Open fail with ErrVerification and nothing else.

func TestAEADRejectsFlippedCiphertextByte(t *testing.T) {
	aead, ct, nonce, aad := sealForTamperTest(t)
	defer aead.Close()

	ct[0] ^= 0x01
	if _, err := aead.Open(nil, nonce, ct, aad); err != ErrVerification {
		t.Fatalf("Open with a flipped ciphertext byte = %v, want ErrVerification", err)
	}
}

func TestAEADRejectsFlippedTagByte(t *testing.T) {
	aead, ct, nonce, aad := sealForTamperTest(t)
	defer aead.Close()

	ct[len(ct)-1] ^= 0x01 // last byte is part of the tag
	if _, err := aead.Open(nil, nonce, ct, aad); err != ErrVerification {
		t.Fatalf("Open with a flipped tag byte = %v, want ErrVerification", err)
	}
}

func TestAEADRejectsAlteredAAD(t *testing.T) {
	aead, ct, nonce, aad := sealForTamperTest(t)
	defer aead.Close()

	altered := append([]byte(nil), aad...)
	altered[0] ^= 0x01
	if _, err := aead.Open(nil, nonce, ct, altered); err != ErrVerification {
		t.Fatalf("Open with altered AAD = %v, want ErrVerification", err)
	}
}

func TestAEADRejectsWrongNonce(t *testing.T) {
	aead, ct, nonce, aad := sealForTamperTest(t)
	defer aead.Close()

	wrongNonce := append([]byte(nil), nonce...)
	wrongNonce[0] ^= 0x01
	if _, err := aead.Open(nil, wrongNonce, ct, aad); err != ErrVerification {
		t.Fatalf("Open with the wrong nonce = %v, want ErrVerification", err)
	}
}

func TestAEADRejectsTruncatedInput(t *testing.T) {
	aead, ct, nonce, aad := sealForTamperTest(t)
	defer aead.Close()

	truncated := ct[:len(ct)-1]
	if _, err := aead.Open(nil, nonce, truncated, aad); err != ErrVerification {
		t.Fatalf("Open with truncated input = %v, want ErrVerification", err)
	}

	// Shorter than the tag alone must also be rejected, not just "shorter
	// than expected" - this exercises the length guard rather than a real
	// authentication failure inside OpenSSL.
	if _, err := aead.Open(nil, nonce, ct[:aead.Overhead()-1], aad); err != ErrVerification {
		t.Fatalf("Open with input shorter than the tag = %v, want ErrVerification", err)
	}
}

// sealForTamperTest returns a fresh AEAD (caller closes it) plus a valid
// sealed message, so each negative test tampers with exactly one thing.
func sealForTamperTest(t *testing.T) (aead *AEAD, ct, nonce, aad []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{0x33}, 32)
	a, err := Default.NewAEAD("AES-256-GCM", key)
	if err != nil {
		t.Fatal(err)
	}
	nonce = bytes.Repeat([]byte{0x44}, a.NonceSize())
	aad = []byte("header")
	plaintext := []byte("the eagle lands at midnight")
	ct = a.Seal(nil, nonce, plaintext, aad)
	return a, ct, nonce, aad
}

func TestAEADEmptyPlaintextAndAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	aead, err := Default.NewAEAD("AES-256-GCM", key)
	if err != nil {
		t.Fatal(err)
	}
	defer aead.Close()

	nonce := bytes.Repeat([]byte{0x66}, aead.NonceSize())
	ct := aead.Seal(nil, nonce, nil, nil)
	if len(ct) != aead.Overhead() {
		t.Fatalf("ciphertext of empty plaintext = %d bytes, want just the %d-byte tag", len(ct), aead.Overhead())
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("decrypted %d bytes, want 0", len(pt))
	}
}

func TestAEADWrongKeySize(t *testing.T) {
	if _, err := Default.NewAEAD("AES-256-GCM", make([]byte, 16)); err == nil {
		t.Fatal("NewAEAD(AES-256-GCM, 16-byte key) succeeded, want an error (needs 32 bytes)")
	}
}

func TestAEADNotAnAEADCipher(t *testing.T) {
	if _, err := Default.NewAEAD("AES-256-CBC", make([]byte, 32)); err == nil {
		t.Fatal("NewAEAD(AES-256-CBC) succeeded; CBC is not an AEAD mode")
	}
}

func TestAEADSealAppendsToDst(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, 32)
	aead, err := Default.NewAEAD("AES-256-GCM", key)
	if err != nil {
		t.Fatal(err)
	}
	defer aead.Close()

	nonce := bytes.Repeat([]byte{0x88}, aead.NonceSize())
	prefix := []byte("PREFIX:")
	out := aead.Seal(prefix, nonce, []byte("payload"), nil)

	if !bytes.HasPrefix(out, prefix) {
		t.Fatalf("Seal did not preserve dst's existing prefix: %q", out)
	}
	ct := out[len(prefix):]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("payload")) {
		t.Fatalf("decrypted = %q, want %q", pt, "payload")
	}
}

func TestAEADSealWrongNonceSizePanics(t *testing.T) {
	key := bytes.Repeat([]byte{0x99}, 32)
	aead, err := Default.NewAEAD("AES-256-GCM", key)
	if err != nil {
		t.Fatal(err)
	}
	defer aead.Close()

	defer func() {
		if recover() == nil {
			t.Fatal("Seal with a wrong-sized nonce did not panic")
		}
	}()
	aead.Seal(nil, []byte("too short"), []byte("x"), nil)
}

func TestAEADCloseIsIdempotent(t *testing.T) {
	aead, err := Default.NewAEAD("AES-256-GCM", bytes.Repeat([]byte{0xaa}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := aead.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := aead.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	nonce := bytes.Repeat([]byte{0xbb}, aead.NonceSize())
	if _, err := aead.SealErr(nil, nonce, []byte("x"), nil); err != ErrClosed {
		t.Fatalf("SealErr after Close = %v, want ErrClosed", err)
	}
}
