//go:build cgo

package ossl

import (
	"bytes"
	"testing"
)

func TestAEADRoundTrip(t *testing.T) {
	for _, alg := range []CipherName{"AES-256-GCM", "ChaCha20-Poly1305"} {
		t.Run(string(alg), func(t *testing.T) {
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

// TestAEADCustomIVAndTagSize exercises WithIVSize/WithTagSize against GCM
// with the exact non-default combinations citius-server's AesGcmParams
// allows (iv_size_bits: 64/96/128, tag_size_bits: 96-128 in steps of 8),
// proving the override actually changes NonceSize()/Overhead() and that a
// round trip still authenticates correctly at each size.
func TestAEADCustomIVAndTagSize(t *testing.T) {
	key := bytes.Repeat([]byte{0xcc}, 32)

	for _, tc := range []struct {
		ivBytes, tagBytes int
	}{
		{ivBytes: 8, tagBytes: 16},  // 64-bit IV, default tag
		{ivBytes: 12, tagBytes: 12}, // default IV, 96-bit (truncated) tag
		{ivBytes: 16, tagBytes: 13}, // 128-bit IV, 104-bit tag
	} {
		aead, err := Default.NewAEAD("AES-256-GCM", key, WithIVSize(tc.ivBytes), WithTagSize(tc.tagBytes))
		if err != nil {
			t.Fatalf("NewAEAD(iv=%d, tag=%d): %v", tc.ivBytes, tc.tagBytes, err)
		}

		if aead.NonceSize() != tc.ivBytes {
			t.Fatalf("NonceSize() = %d, want %d", aead.NonceSize(), tc.ivBytes)
		}
		if aead.Overhead() != tc.tagBytes {
			t.Fatalf("Overhead() = %d, want %d", aead.Overhead(), tc.tagBytes)
		}

		nonce := bytes.Repeat([]byte{0xdd}, tc.ivBytes)
		plaintext := []byte("configurable IV and tag size")
		ct, err := aead.SealErr(nil, nonce, plaintext, []byte("aad"))
		if err != nil {
			t.Fatalf("SealErr(iv=%d, tag=%d): %v", tc.ivBytes, tc.tagBytes, err)
		}
		if len(ct) != len(plaintext)+tc.tagBytes {
			t.Fatalf("ciphertext length = %d, want %d", len(ct), len(plaintext)+tc.tagBytes)
		}

		pt, err := aead.Open(nil, nonce, ct, []byte("aad"))
		if err != nil {
			t.Fatalf("Open(iv=%d, tag=%d): %v", tc.ivBytes, tc.tagBytes, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("decrypted = %q, want %q", pt, plaintext)
		}
		aead.Close()
	}
}

// TestAEADCCMRoundTrip exercises AES-CCM, which the default-only Seal/Open
// path from before this test could not have supported: CCM requires the
// plaintext length declared before AAD, and (unlike GCM) treats tag length
// as a real parameter of the MAC computation, not mere truncation.
func TestAEADCCMRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xee}, 32)
	aead, err := Default.NewAEAD("AES-256-CCM", key)
	if err != nil {
		t.Fatal(err)
	}
	defer aead.Close()

	nonce := bytes.Repeat([]byte{0xff}, aead.NonceSize())
	plaintext := []byte("CCM needs its length upfront")
	aad := []byte("ccm-aad")

	ct := aead.Seal(nil, nonce, plaintext, aad)
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("decrypted = %q, want %q", pt, plaintext)
	}

	// Tamper rejection must hold for CCM exactly as it does for GCM.
	ct[0] ^= 0x01
	if _, err := aead.Open(nil, nonce, ct, aad); err != ErrVerification {
		t.Fatalf("Open with a flipped byte = %v, want ErrVerification", err)
	}
}

// TestAEADCCMCustomNonceAndTagSize covers the exact range citius-server's
// AesCcmParams declares (nonce_size_bits: 56-104 i.e. 7-13 bytes,
// tag_size_bits: 32-128 in even steps i.e. 4-16 bytes), including the
// boundary values.
func TestAEADCCMCustomNonceAndTagSize(t *testing.T) {
	key := bytes.Repeat([]byte{0x12}, 32)

	for _, tc := range []struct{ nonceBytes, tagBytes int }{
		{nonceBytes: 7, tagBytes: 4},   // minimum nonce, minimum tag
		{nonceBytes: 13, tagBytes: 16}, // maximum nonce, maximum tag
		{nonceBytes: 12, tagBytes: 8},  // a middle value
	} {
		aead, err := Default.NewAEAD("AES-256-CCM", key, WithIVSize(tc.nonceBytes), WithTagSize(tc.tagBytes))
		if err != nil {
			t.Fatalf("NewAEAD(nonce=%d, tag=%d): %v", tc.nonceBytes, tc.tagBytes, err)
		}

		nonce := bytes.Repeat([]byte{0x34}, tc.nonceBytes)
		plaintext := []byte("CCM boundary parameters")
		ct, err := aead.SealErr(nil, nonce, plaintext, nil)
		if err != nil {
			t.Fatalf("SealErr(nonce=%d, tag=%d): %v", tc.nonceBytes, tc.tagBytes, err)
		}
		if len(ct) != len(plaintext)+tc.tagBytes {
			t.Fatalf("ciphertext length = %d, want %d", len(ct), len(plaintext)+tc.tagBytes)
		}

		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			t.Fatalf("Open(nonce=%d, tag=%d): %v", tc.nonceBytes, tc.tagBytes, err)
		}
		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("decrypted = %q, want %q", pt, plaintext)
		}
		aead.Close()
	}
}

func TestAEADCCMEmptyPlaintext(t *testing.T) {
	key := bytes.Repeat([]byte{0x56}, 32)
	aead, err := Default.NewAEAD("AES-256-CCM", key)
	if err != nil {
		t.Fatal(err)
	}
	defer aead.Close()

	nonce := bytes.Repeat([]byte{0x78}, aead.NonceSize())
	ct := aead.Seal(nil, nonce, nil, []byte("aad-only"))
	if len(ct) != aead.Overhead() {
		t.Fatalf("ciphertext of empty plaintext = %d bytes, want just the %d-byte tag", len(ct), aead.Overhead())
	}
	pt, err := aead.Open(nil, nonce, ct, []byte("aad-only"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("decrypted %d bytes, want 0", len(pt))
	}
}

// TestAEADCCMEmptyPlaintextRejectsTamperedAAD pins a real bug caught while
// building CCM support: with an empty plaintext, skipping the data Update
// call entirely (correct for GCM/OCB/ChaCha20-Poly1305, all confirmed by
// TestAEADEmptyPlaintextAndAAD) left CCM's tag unfinalized, and a tampered
// AAD was silently ACCEPTED at Final instead of being rejected. This is
// exactly the failure mode 04_aead.c's "tampered: ACCEPTED (this would be a
// bug)" check exists to catch, just for a case that only CCM can hit.
func TestAEADCCMEmptyPlaintextRejectsTamperedAAD(t *testing.T) {
	key := bytes.Repeat([]byte{0x9a}, 32)
	aead, err := Default.NewAEAD("AES-256-CCM", key)
	if err != nil {
		t.Fatal(err)
	}
	defer aead.Close()

	nonce := bytes.Repeat([]byte{0xbc}, aead.NonceSize())
	aad := []byte("aad-only-empty-pt")
	ct := aead.Seal(nil, nonce, nil, aad)

	tamperedAAD := append([]byte(nil), aad...)
	tamperedAAD[0] ^= 0x01
	if _, err := aead.Open(nil, nonce, ct, tamperedAAD); err != ErrVerification {
		t.Fatalf("Open with tampered AAD and empty plaintext = %v, want ErrVerification", err)
	}
}
