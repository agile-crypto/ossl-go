//go:build cgo

package ossl

import (
	"bytes"
	"testing"
)

// Coverage of the algorithm parameters citius-server's proto exposes. Each
// of these was unreachable through this package before: a symmetric mode
// with no AEAD, a padding scheme other than PKCS#7, key wrapping, a MAC
// outside the HMAC/CMAC/KMAC trio, a fixed-width ECDSA signature, an MGF1
// digest distinct from the signing digest, a deterministic ML-DSA signature,
// an Argon2 variant other than id, and RSA PKCS#1 v1.5.

func TestSymmetricCipherModesAndPadding(t *testing.T) {
	k := bytes.Repeat([]byte{1}, 32)
	for _, name := range []CipherName{"AES-256-CBC", "AES-256-CTR", "AES-256-OFB", "AES-256-CFB", "ChaCha20"} {
		for _, pad := range []PaddingScheme{PaddingPKCS7, PaddingNone, PaddingISO7816, PaddingX923, PaddingZero} {
			c, err := Default.NewCipher(name, k, WithPadding(pad))
			if err != nil {
				t.Errorf("%s/%v: %v", name, pad, err)
				continue
			}
			iv := bytes.Repeat([]byte{2}, c.IVSize())
			pt := []byte("sixteen bytes!!!") // exactly one block
			ct, err := c.Encrypt(nil, iv, pt)
			if err != nil {
				t.Errorf("%s/%v encrypt: %v", name, pad, err)
				c.Close()
				continue
			}
			got, err := c.Decrypt(nil, iv, ct)
			if err != nil {
				t.Errorf("%s/%v decrypt: %v", name, pad, err)
				c.Close()
				continue
			}
			ok := bytes.HasPrefix(got, pt)
			t.Logf("%-12s %-14s ct=%3d rt=%v", name, pad, len(ct), ok)
			if !ok {
				t.Errorf("%s/%v round trip mismatch: %q", name, pad, got)
			}
			c.Close()
		}
	}
	if _, err := Default.NewCipher("AES-256-GCM", k); err == nil {
		t.Error("NewCipher accepted an AEAD mode")
	}
}

func TestKeyWrapAllKEKSizes(t *testing.T) {
	for _, kekLen := range []int{16, 24, 32} {
		for _, padded := range []bool{false, true} {
			kek := bytes.Repeat([]byte{7}, kekLen)
			w, err := Default.NewKeyWrap(kek, padded)
			if err != nil {
				t.Errorf("kek=%d pad=%v: %v", kekLen, padded, err)
				continue
			}
			km := bytes.Repeat([]byte{0xAB}, 32)
			if padded {
				km = bytes.Repeat([]byte{0xAB}, 21) // not a multiple of 8
			}
			ct, err := w.Wrap(km)
			if err != nil {
				t.Errorf("%s wrap: %v", w.Name(), err)
				w.Close()
				continue
			}
			got, err := w.Unwrap(ct)
			if err != nil || !bytes.Equal(got, km) {
				t.Errorf("%s unwrap: err=%v equal=%v", w.Name(), err, bytes.Equal(got, km))
			}
			bad := append([]byte(nil), ct...)
			bad[0] ^= 0xFF
			if _, err := w.Unwrap(bad); err == nil {
				t.Errorf("%s accepted a tampered blob", w.Name())
			}
			t.Logf("%-16s in=%d wrapped=%d tamper-rejected", w.Name(), len(km), len(ct))
			w.Close()
		}
	}
}

func TestGenericMACAlgorithms(t *testing.T) {
	k32 := bytes.Repeat([]byte{1}, 32)
	k16 := bytes.Repeat([]byte{1}, 16)
	iv := bytes.Repeat([]byte{2}, 12)

	cases := []struct {
		name string
		fn   func() (*MAC, error)
	}{
		{"GMAC", func() (*MAC, error) { return Default.NewGMAC("AES-256-GCM", k32, iv) }},
		{"POLY1305", func() (*MAC, error) { return Default.NewMAC("POLY1305", k32, nil) }},
		{"SIPHASH", func() (*MAC, error) { return Default.NewMAC("SIPHASH", k16, nil) }},
		{"BLAKE2BMAC", func() (*MAC, error) { return Default.NewMAC("BLAKE2BMAC", k32, &MACParams{Size: 32}) }},
		{"BLAKE2SMAC", func() (*MAC, error) { return Default.NewMAC("BLAKE2SMAC", k32, &MACParams{Size: 32}) }},
		{"HMAC via NewMAC", func() (*MAC, error) { return Default.NewMAC("HMAC", k32, &MACParams{Digest: "SHA2-256"}) }},
		{"CMAC via NewMAC", func() (*MAC, error) { return Default.NewMAC("CMAC", k32, &MACParams{Cipher: "AES-256-CBC"}) }},
		{"KMAC via NewMAC", func() (*MAC, error) {
			return Default.NewMAC("KMAC-256", k32, &MACParams{Size: 32, Custom: []byte("app")})
		}},
	}
	for _, c := range cases {
		m, err := c.fn()
		if err != nil {
			t.Errorf("%-16s FAILED: %v", c.name, err)
			continue
		}
		m.Write([]byte("message"))
		sum := m.Sum(nil)
		t.Logf("%-16s ok, tag=%d bytes, Err=%v", c.name, len(sum), m.Err())
		if len(sum) == 0 {
			t.Errorf("%s produced an empty tag", c.name)
		}
		m.Close()
	}
}

func TestECDSASignatureFormats(t *testing.T) {
	for _, curve := range []Curve{P256, P384, P521} {
		k, err := Default.GenerateKey("EC", WithGroup(curve))
		if err != nil {
			t.Fatal(err)
		}
		msg := []byte("format")
		coord := ecdsaCoordinateLen(k)

		raw, err := k.Sign(msg, &SignOptions{Format: SignatureP1363})
		if err != nil {
			t.Errorf("%s sign P1363: %v", curve, err)
			k.Close()
			continue
		}
		if len(raw) != 2*coord {
			t.Errorf("%s: P1363 signature is %d bytes, want %d", curve, len(raw), 2*coord)
		}
		if err := k.Verify(msg, raw, &SignOptions{Format: SignatureP1363}); err != nil {
			t.Errorf("%s verify P1363: %v", curve, err)
		}
		// A P1363 signature must not verify as DER, and vice versa.
		if err := k.Verify(msg, raw, nil); err == nil {
			t.Errorf("%s: P1363 signature verified as DER", curve)
		}
		der, _ := k.Sign(msg, nil)
		if err := k.Verify(msg, der, &SignOptions{Format: SignatureP1363}); err == nil {
			t.Errorf("%s: DER signature verified as P1363", curve)
		}
		t.Logf("%-6s coord=%2d der=%3d p1363=%3d", curve, coord, len(der), len(raw))
		k.Close()
	}
}

func TestAlgorithmParameterCoverage(t *testing.T) {
	// Argon2 variants, associated data and secret.
	for _, v := range []Argon2Variant{Argon2ID, Argon2I, Argon2D} {
		out, err := Default.Argon2(v, []byte("pw"), bytes.Repeat([]byte{1}, 16),
			Argon2idParams{AssociatedData: []byte("ad"), Secret: []byte("pepper")}, 32)
		if err != nil {
			t.Errorf("Argon2 variant %d: %v", v, err)
			continue
		}
		plain, _ := Default.Argon2(v, []byte("pw"), bytes.Repeat([]byte{1}, 16), Argon2idParams{}, 32)
		t.Logf("Argon2 variant=%d out=%d differs-without-ad/secret=%v", v, len(out), !bytes.Equal(out, plain))
		if bytes.Equal(out, plain) {
			t.Errorf("variant %d: associated data and secret had no effect", v)
		}
	}

	// RSA PKCS#1 v1.5 encryption.
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	msg := []byte("legacy interop")
	ct, err := k.EncryptPKCS1v15(msg)
	if err != nil {
		t.Fatalf("EncryptPKCS1v15: %v", err)
	}
	got, err := k.DecryptPKCS1v15(ct)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("DecryptPKCS1v15: err=%v equal=%v", err, bytes.Equal(got, msg))
	}
	// A corrupted PKCS#1 v1.5 ciphertext must NOT be reported as an error:
	// OpenSSL rejects implicitly, returning pseudorandom bytes, because
	// reporting a padding failure is the Bleichenbacher oracle. What must
	// hold is that the caller does not get the original plaintext back.
	// Asserting an error here instead looks reasonable and fails
	// intermittently, which is how this behaviour was found.
	bad := append([]byte(nil), ct...)
	bad[0] ^= 0xFF
	other, err := k.DecryptPKCS1v15(bad)
	if err == nil && bytes.Equal(other, msg) {
		t.Error("a corrupted PKCS#1 v1.5 ciphertext recovered the original plaintext")
	}
	t.Logf("PKCS1v15 encrypt/decrypt ok, ct=%d; corrupted -> err=%v recovered-original=%v",
		len(ct), err != nil, err == nil && bytes.Equal(other, msg))

	// RSA PKCS#1 key marshalling round trip.
	der, err := k.MarshalPKCS1()
	if err != nil {
		t.Fatalf("MarshalPKCS1: %v", err)
	}
	k2, err := Default.ParsePKCS1PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey: %v", err)
	}
	defer k2.Close()
	a, _ := k.MarshalSPKI()
	b, _ := k2.MarshalSPKI()
	t.Logf("PKCS1 marshal round trip: %d bytes, same key=%v", len(der), bytes.Equal(a, b))
	if !bytes.Equal(a, b) {
		t.Error("PKCS1 round trip produced a different key")
	}

	// PSS MGF1 hash independent of the signing digest.
	sig, err := k.Sign(msg, &SignOptions{Digest: "SHA2-256", MGF1Hash: "SHA2-512"})
	if err != nil {
		t.Fatalf("Sign with split MGF1: %v", err)
	}
	if err := k.Verify(msg, sig, &SignOptions{Digest: "SHA2-256", MGF1Hash: "SHA2-512"}); err != nil {
		t.Fatalf("Verify with split MGF1: %v", err)
	}
	if err := k.Verify(msg, sig, &SignOptions{Digest: "SHA2-256"}); err == nil {
		t.Error("split-MGF1 signature verified under the default MGF1")
	}
	t.Log("PSS MGF1Hash independent of Digest: ok")

	// ML-DSA / SLH-DSA deterministic mode.
	for _, alg := range []KeyAlgorithm{"ML-DSA-65", "SLH-DSA-SHA2-128s"} {
		pk, err := Default.GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		d1, err := pk.Sign(msg, &SignOptions{Deterministic: true})
		if err != nil {
			t.Errorf("%s deterministic sign: %v", alg, err)
			pk.Close()
			continue
		}
		d2, _ := pk.Sign(msg, &SignOptions{Deterministic: true})
		h1, _ := pk.Sign(msg, nil)
		h2, _ := pk.Sign(msg, nil)
		t.Logf("%-18s deterministic-stable=%v hedged-differs=%v", alg,
			bytes.Equal(d1, d2), !bytes.Equal(h1, h2))
		if !bytes.Equal(d1, d2) {
			t.Errorf("%s: deterministic signatures differ", alg)
		}
		if err := pk.Verify(msg, d1, &SignOptions{Deterministic: true}); err != nil {
			t.Errorf("%s deterministic verify: %v", alg, err)
		}
		pk.Close()
	}
}
