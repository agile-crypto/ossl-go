//go:build cgo

package ossl

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOAEPRoundTrip(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("a symmetric key, which is all RSA should ever carry")
	ct, err := k.Encrypt(msg, nil)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Contains(ct, msg) {
		t.Fatal("ciphertext contains the plaintext")
	}
	pt, err := k.Decrypt(ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatalf("decrypted = %q, want %q", pt, msg)
	}
}

// OAEP is randomised: encrypting the same plaintext twice must not produce
// the same ciphertext, or the scheme leaks equality of plaintexts.
func TestOAEPIsRandomised(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("same plaintext")
	a, err := k.Encrypt(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.Encrypt(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext are identical")
	}
	for _, ct := range [][]byte{a, b} {
		pt, err := k.Decrypt(ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatal("round trip mismatch")
		}
	}
}

// Encryption needs only the public half, which is the whole point of the
// operation.
func TestOAEPEncryptWithPublicKeyOnly(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	pub, err := k.Public()
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	msg := []byte("to the holder of the private key")
	ct, err := pub.Encrypt(msg, nil)
	if err != nil {
		t.Fatalf("Encrypt with public key: %v", err)
	}
	pt, err := k.Decrypt(ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatal("round trip mismatch")
	}

	// The public half cannot decrypt, and the failure is the opaque one.
	if _, err := pub.Decrypt(ct, nil); !errors.Is(err, ErrVerification) {
		t.Fatalf("Decrypt with a public-only key = %v, want ErrVerification", err)
	}
}

// The label is bound into the padding: the same ciphertext must decrypt only
// under the identical label. This is what makes the label useful for domain
// separation, so it is worth pinning rather than assuming.
func TestOAEPLabelIsBinding(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("labelled")
	ct, err := k.Encrypt(msg, &OAEPOptions{Label: []byte("context-A")})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	pt, err := k.Decrypt(ct, &OAEPOptions{Label: []byte("context-A")})
	if err != nil {
		t.Fatalf("Decrypt with the matching label: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatal("round trip mismatch")
	}

	for _, wrong := range []*OAEPOptions{
		{Label: []byte("context-B")},
		{Label: []byte("context-AA")},
		{Label: nil},
		nil,
	} {
		if _, err := k.Decrypt(ct, wrong); !errors.Is(err, ErrVerification) {
			t.Fatalf("Decrypt with a non-matching label = %v, want ErrVerification", err)
		}
	}

	// And the reverse: a no-label ciphertext must not open under a label.
	plain, err := k.Encrypt(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Decrypt(plain, &OAEPOptions{Label: []byte("context-A")}); !errors.Is(err, ErrVerification) {
		t.Fatal("an unlabelled ciphertext opened under a label")
	}
}

// Repeated use with a label exercises the set0 ownership transfer many times
// over; a mismatched free there would show up as corruption or a crash.
func TestOAEPLabelRepeatedUse(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	opts := &OAEPOptions{Label: bytes.Repeat([]byte("L"), 64)}
	msg := []byte("repeat")
	for i := 0; i < 200; i++ {
		ct, err := k.Encrypt(msg, opts)
		if err != nil {
			t.Fatalf("iteration %d: Encrypt: %v", i, err)
		}
		pt, err := k.Decrypt(ct, opts)
		if err != nil {
			t.Fatalf("iteration %d: Decrypt: %v", i, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("iteration %d: round trip mismatch", i)
		}
	}
}

func TestOAEPDigestMustMatch(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("digest bound")
	ct, err := k.Encrypt(msg, &OAEPOptions{Hash: "SHA2-256"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.Decrypt(ct, &OAEPOptions{Hash: "SHA2-512"}); !errors.Is(err, ErrVerification) {
		t.Fatal("a SHA2-256 ciphertext decrypted under SHA2-512")
	}

	// A non-default digest still round trips when both sides agree.
	ct512, err := k.Encrypt(msg, &OAEPOptions{Hash: "SHA2-512"})
	if err != nil {
		t.Fatal(err)
	}
	pt, err := k.Decrypt(ct512, &OAEPOptions{Hash: "SHA2-512"})
	if err != nil {
		t.Fatalf("SHA2-512 round trip: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatal("round trip mismatch")
	}
}

// MGF1Hash defaults to Hash rather than to some independent library default,
// so an explicit MGF1Hash equal to Hash must be indistinguishable from
// leaving it empty.
func TestOAEPMGF1DefaultsToHash(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("mgf1")
	ct, err := k.Encrypt(msg, &OAEPOptions{Hash: "SHA2-256"})
	if err != nil {
		t.Fatal(err)
	}
	pt, err := k.Decrypt(ct, &OAEPOptions{Hash: "SHA2-256", MGF1Hash: "SHA2-256"})
	if err != nil {
		t.Fatalf("explicit MGF1Hash equal to Hash did not match the default: %v", err)
	}
	if !bytes.Equal(pt, msg) {
		t.Fatal("round trip mismatch")
	}

	// A genuinely different MGF1 digest is a different scheme.
	if _, err := k.Decrypt(ct, &OAEPOptions{Hash: "SHA2-256", MGF1Hash: "SHA2-512"}); !errors.Is(err, ErrVerification) {
		t.Fatal("a ciphertext decrypted under a different MGF1 digest")
	}
}

func TestOAEPMaxPlaintext(t *testing.T) {
	k, err := Default.GenerateKey("RSA", WithRSABits(2048))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	// 256 - 2*32 - 2
	n, err := k.MaxOAEPPlaintext(nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 190 {
		t.Fatalf("MaxOAEPPlaintext(SHA2-256) = %d, want 190", n)
	}

	// The bound is exact: at the limit it works, one byte over it does not.
	if _, err := k.Encrypt(bytes.Repeat([]byte{1}, n), nil); err != nil {
		t.Fatalf("Encrypt at the reported maximum: %v", err)
	}
	if _, err := k.Encrypt(bytes.Repeat([]byte{1}, n+1), nil); err == nil {
		t.Fatal("Encrypt one byte over the reported maximum succeeded")
	}

	// And it tracks the digest.
	n512, err := k.MaxOAEPPlaintext(&OAEPOptions{Hash: "SHA2-512"})
	if err != nil {
		t.Fatal(err)
	}
	if n512 != 256-2*64-2 {
		t.Fatalf("MaxOAEPPlaintext(SHA2-512) = %d, want %d", n512, 256-2*64-2)
	}
	if _, err := k.Encrypt(bytes.Repeat([]byte{1}, n512), &OAEPOptions{Hash: "SHA2-512"}); err != nil {
		t.Fatalf("Encrypt at the SHA2-512 maximum: %v", err)
	}
}

func TestOAEPEmptyPlaintext(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	ct, err := k.Encrypt(nil, nil)
	if err != nil {
		t.Fatalf("Encrypt(nil): %v", err)
	}
	pt, err := k.Decrypt(ct, nil)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("decrypted %d bytes, want 0", len(pt))
	}
}

// Every decryption failure must be the same opaque error, so that a caller
// forwarding it cannot turn this into a padding oracle.
func TestOAEPDecryptFailuresAreIndistinguishable(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	other, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()

	ct, err := k.Encrypt([]byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}

	corrupt := append([]byte(nil), ct...)
	corrupt[0] ^= 0xFF
	truncated := ct[:len(ct)-1]
	garbage := bytes.Repeat([]byte{0xAB}, len(ct))

	for name, bad := range map[string][]byte{
		"corrupted":  corrupt,
		"truncated":  truncated,
		"garbage":    garbage,
		"empty":      nil,
		"wrong-size": {1, 2, 3},
	} {
		_, err := k.Decrypt(bad, nil)
		if !errors.Is(err, ErrVerification) {
			t.Errorf("%s: Decrypt = %v, want ErrVerification", name, err)
			continue
		}
		if err.Error() != ErrVerification.Error() {
			t.Errorf("%s: error carries extra detail: %q", name, err)
		}
	}

	// A valid ciphertext under the wrong key must look identical too.
	err = func() error { _, e := other.Decrypt(ct, nil); return e }()
	if !errors.Is(err, ErrVerification) || err.Error() != ErrVerification.Error() {
		t.Fatalf("wrong-key Decrypt = %v, want a bare ErrVerification", err)
	}
}

func TestOAEPRejectsNonRSAKeys(t *testing.T) {
	for _, tc := range []struct {
		alg  string
		opts []KeyOption
	}{
		{"EC", []KeyOption{WithGroup("P-256")}},
		{"ED25519", nil},
		{"ML-KEM-768", nil},
	} {
		k, err := Default.GenerateKey(tc.alg, tc.opts...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := k.Encrypt([]byte("m"), nil); err == nil {
			t.Errorf("%s: Encrypt succeeded on a non-RSA key", tc.alg)
		}
		if _, err := k.Decrypt([]byte("c"), nil); err == nil {
			t.Errorf("%s: Decrypt succeeded on a non-RSA key", tc.alg)
		}
		if _, err := k.MaxOAEPPlaintext(nil); err == nil {
			t.Errorf("%s: MaxOAEPPlaintext succeeded on a non-RSA key", tc.alg)
		}
		k.Close()
	}
}

func TestOAEPClosedKey(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	k.Close()

	if _, err := k.Encrypt([]byte("m"), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Encrypt on a closed key = %v, want ErrClosed", err)
	}
	if _, err := k.Decrypt([]byte("c"), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Decrypt on a closed key = %v, want ErrClosed", err)
	}
	if _, err := k.MaxOAEPPlaintext(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("MaxOAEPPlaintext on a closed key = %v, want ErrClosed", err)
	}
}

func TestOAEPUnknownDigest(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if _, err := k.Encrypt([]byte("m"), &OAEPOptions{Hash: "NOT-A-DIGEST"}); err == nil {
		t.Fatal("Encrypt with an unknown digest succeeded")
	}
}

// opensslCLI locates the openssl binary matching the library this package is
// linked against, so the interop tests below compare against an independent
// implementation of the same spec rather than against this wrapper itself.
func opensslCLI(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/opt/openssl3.5.2/bin/openssl", "openssl"} {
		if path, err := exec.LookPath(p); err == nil {
			out, err := exec.Command(path, "version").Output()
			if err == nil && strings.HasPrefix(string(out), "OpenSSL 3.5") {
				return path
			}
		}
	}
	t.Skip("no OpenSSL 3.5 command-line tool available for interop")
	return ""
}

// TestOAEPInteropWithOpenSSLCLI is the test that self-consistency cannot
// provide. Encrypting and decrypting with this package alone still passes if
// the OAEP and MGF1 digests are wrong in the same way on both sides -- the
// scheme is simply a different, private one, and every round trip succeeds.
// What actually matters is that the bytes on the wire match what a
// conforming peer produces, so these cross-check both directions against the
// openssl tool, including the MGF1-follows-Hash default that a same-wrapper
// round trip is blind to.
func TestOAEPInteropWithOpenSSLCLI(t *testing.T) {
	cli := opensslCLI(t)
	dir := t.TempDir()

	k, err := Default.GenerateKey("RSA", WithRSABits(2048))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	privPEM, err := k.MarshalPKCS8PEM()
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := k.MarshalSPKIPEM()
	if err != nil {
		t.Fatal(err)
	}
	privPath := filepath.Join(dir, "priv.pem")
	pubPath := filepath.Join(dir, "pub.pem")
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	msg := []byte("interop payload")

	for _, tc := range []struct {
		name     string
		goHash   string
		cliMD    string
		label    []byte
		labelHex string
	}{
		{name: "SHA2-256", goHash: "SHA2-256", cliMD: "sha256"},
		{name: "SHA2-512", goHash: "SHA2-512", cliMD: "sha512"},
		{name: "SHA2-384", goHash: "SHA2-384", cliMD: "sha384"},
		{
			name: "SHA2-256 with label", goHash: "SHA2-256", cliMD: "sha256",
			label: []byte("context-A"), labelHex: hex.EncodeToString([]byte("context-A")),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := &OAEPOptions{Hash: tc.goHash, Label: tc.label}

			cliOpts := []string{
				"-pkeyopt", "rsa_padding_mode:oaep",
				"-pkeyopt", "rsa_oaep_md:" + tc.cliMD,
				"-pkeyopt", "rsa_mgf1_md:" + tc.cliMD,
			}
			if tc.labelHex != "" {
				cliOpts = append(cliOpts, "-pkeyopt", "rsa_oaep_label:"+tc.labelHex)
			}

			// Direction 1: this package encrypts, the CLI decrypts.
			ct, err := k.Encrypt(msg, opts)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			ctPath := filepath.Join(dir, "ct-"+tc.cliMD+tc.labelHex+".bin")
			if err := os.WriteFile(ctPath, ct, 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"pkeyutl", "-decrypt", "-inkey", privPath, "-in", ctPath}, cliOpts...)
			out, err := exec.Command(cli, args...).CombinedOutput()
			if err != nil {
				t.Fatalf("openssl could not decrypt what this package produced: %v\n%s", err, out)
			}
			if !bytes.Equal(out, msg) {
				t.Fatalf("openssl decrypted %q, want %q", out, msg)
			}

			// Direction 2: the CLI encrypts, this package decrypts.
			ptPath := filepath.Join(dir, "pt.bin")
			if err := os.WriteFile(ptPath, msg, 0o600); err != nil {
				t.Fatal(err)
			}
			cliCTPath := filepath.Join(dir, "clict-"+tc.cliMD+tc.labelHex+".bin")
			args = append([]string{
				"pkeyutl", "-encrypt", "-pubin", "-inkey", pubPath,
				"-in", ptPath, "-out", cliCTPath,
			}, cliOpts...)
			if out, err := exec.Command(cli, args...).CombinedOutput(); err != nil {
				t.Fatalf("openssl encrypt failed: %v\n%s", err, out)
			}
			cliCT, err := os.ReadFile(cliCTPath)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := k.Decrypt(cliCT, opts)
			if err != nil {
				t.Fatalf("this package could not decrypt what openssl produced: %v", err)
			}
			if !bytes.Equal(pt, msg) {
				t.Fatalf("decrypted %q, want %q", pt, msg)
			}
		})
	}
}

func TestKEMRoundTrip(t *testing.T) {
	for _, alg := range []string{
		"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024",
		"X25519MLKEM768", "X25519", "X448", "RSA",
	} {
		t.Run(alg, func(t *testing.T) {
			k, err := Default.GenerateKey(alg)
			if err != nil {
				t.Skipf("%s unavailable: %v", alg, err)
			}
			defer k.Close()

			ct, ss, err := k.Encapsulate()
			if err != nil {
				t.Fatalf("Encapsulate: %v", err)
			}
			if len(ct) == 0 || len(ss) == 0 {
				t.Fatalf("Encapsulate returned ct=%d ss=%d", len(ct), len(ss))
			}
			ss2, err := k.Decapsulate(ct)
			if err != nil {
				t.Fatalf("Decapsulate: %v", err)
			}
			if !bytes.Equal(ss, ss2) {
				t.Fatal("decapsulated secret differs from the encapsulated one")
			}
			t.Logf("%-16s ct=%d ss=%d", alg, len(ct), len(ss))
		})
	}
}

// Encapsulation needs only the public half.
func TestKEMEncapsulateWithPublicKeyOnly(t *testing.T) {
	k, err := Default.GenerateKey("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	pub, err := k.Public()
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	ct, ss, err := pub.Encapsulate()
	if err != nil {
		t.Fatalf("Encapsulate with public key: %v", err)
	}
	got, err := k.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ss, got) {
		t.Fatal("secret mismatch")
	}
}

// Two encapsulations under the same key must differ: the secret is fresh per
// call, not a property of the key.
func TestKEMEncapsulationIsFresh(t *testing.T) {
	k, err := Default.GenerateKey("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	ct1, ss1, err := k.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	ct2, ss2, err := k.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(ct1, ct2) {
		t.Fatal("two encapsulations produced identical ciphertexts")
	}
	if bytes.Equal(ss1, ss2) {
		t.Fatal("two encapsulations produced identical secrets")
	}
}

// This is the contract most likely to be misread, so it is pinned rather than
// merely documented: a corrupted encapsulation decapsulates *successfully*
// and yields a different secret. Callers who treat a nil error as proof of
// authenticity are wrong, and this test exists so that the day OpenSSL starts
// returning an error instead, somebody notices deliberately.
func TestKEMImplicitRejection(t *testing.T) {
	for _, alg := range []string{"ML-KEM-768", "X25519MLKEM768"} {
		t.Run(alg, func(t *testing.T) {
			k, err := Default.GenerateKey(alg)
			if err != nil {
				t.Skipf("%s unavailable: %v", alg, err)
			}
			defer k.Close()

			ct, ss, err := k.Encapsulate()
			if err != nil {
				t.Fatal(err)
			}
			corrupt := append([]byte(nil), ct...)
			corrupt[0] ^= 0xFF

			got, err := k.Decapsulate(corrupt)
			if err != nil {
				t.Fatalf("Decapsulate of a corrupted encapsulation returned an error (%v); "+
					"the documented implicit-rejection contract no longer holds", err)
			}
			if len(got) != len(ss) {
				t.Fatalf("rejection secret is %d bytes, the real one is %d", len(got), len(ss))
			}
			if bytes.Equal(got, ss) {
				t.Fatal("a corrupted encapsulation produced the original secret")
			}

			// Implicit rejection is deterministic per key and ciphertext: the
			// same corrupted input yields the same pseudorandom secret.
			again, err := k.Decapsulate(corrupt)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, again) {
				t.Fatal("rejection secret is not stable for the same input")
			}
		})
	}
}

// Two different keys must not agree on a secret for the same encapsulation.
func TestKEMWrongKeyYieldsDifferentSecret(t *testing.T) {
	a, err := Default.GenerateKey("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Default.GenerateKey("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	ct, ss, err := a.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := b.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate under the wrong key errored: %v", err)
	}
	if bytes.Equal(got, ss) {
		t.Fatal("a different key recovered the same secret")
	}
}

// A wrong-length encapsulation is a structural error, distinct from implicit
// rejection, and does surface as an error.
func TestKEMRejectsMalformedCiphertext(t *testing.T) {
	k, err := Default.GenerateKey("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	ct, _, err := k.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, {}, ct[:len(ct)-1], append(append([]byte(nil), ct...), 0)} {
		if _, err := k.Decapsulate(bad); err == nil {
			t.Errorf("Decapsulate accepted a %d-byte encapsulation (expected %d)", len(bad), len(ct))
		}
	}
}

func TestKEMClosedKey(t *testing.T) {
	k, err := Default.GenerateKey("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	ct, _, err := k.Encapsulate()
	if err != nil {
		t.Fatal(err)
	}
	k.Close()

	if _, _, err := k.Encapsulate(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Encapsulate on a closed key = %v, want ErrClosed", err)
	}
	if _, err := k.Decapsulate(ct); !errors.Is(err, ErrClosed) {
		t.Fatalf("Decapsulate on a closed key = %v, want ErrClosed", err)
	}
}

// A signature-only key has no KEM at all and must say so rather than
// producing something.
func TestKEMRejectsSignatureOnlyKeys(t *testing.T) {
	for _, alg := range []string{"ED25519", "ML-DSA-65"} {
		k, err := Default.GenerateKey(alg)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := k.Encapsulate(); err == nil {
			t.Errorf("%s: Encapsulate succeeded on a signature-only key", alg)
		}
		k.Close()
	}
}

// The defining property of key agreement: two parties independently reach
// the same secret from their own private key and the other's public key.
func TestDeriveAgreement(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  string
		opts []KeyOption
	}{
		{"EC-P-256", "EC", []KeyOption{WithGroup("P-256")}},
		{"EC-P-384", "EC", []KeyOption{WithGroup("P-384")}},
		{"EC-P-521", "EC", []KeyOption{WithGroup("P-521")}},
		{"X25519", "X25519", nil},
		{"X448", "X448", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alice, err := Default.GenerateKey(tc.alg, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer alice.Close()
			bob, err := Default.GenerateKey(tc.alg, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer bob.Close()

			alicePub, err := alice.Public()
			if err != nil {
				t.Fatal(err)
			}
			defer alicePub.Close()
			bobPub, err := bob.Public()
			if err != nil {
				t.Fatal(err)
			}
			defer bobPub.Close()

			ab, err := alice.Derive(bobPub, nil)
			if err != nil {
				t.Fatalf("alice.Derive: %v", err)
			}
			ba, err := bob.Derive(alicePub, nil)
			if err != nil {
				t.Fatalf("bob.Derive: %v", err)
			}
			if !bytes.Equal(ab, ba) {
				t.Fatal("the two parties did not agree on the same secret")
			}
			if len(ab) == 0 {
				t.Fatal("empty shared secret")
			}
		})
	}
}

// A third party's key must not reach the same secret.
func TestDeriveDiffersPerPeer(t *testing.T) {
	alice, err := Default.GenerateKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Close()
	bob, err := Default.GenerateKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Close()
	eve, err := Default.GenerateKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	defer eve.Close()

	bobPub, _ := bob.Public()
	defer bobPub.Close()
	evePub, _ := eve.Public()
	defer evePub.Close()

	withBob, err := alice.Derive(bobPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	withEve, err := alice.Derive(evePub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(withBob, withEve) {
		t.Fatal("agreement with two different peers produced the same secret")
	}
}

// A peer on a different curve, or of a different algorithm entirely, must be
// rejected rather than silently producing something.
func TestDeriveRejectsMismatchedPeers(t *testing.T) {
	p256, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer p256.Close()
	p384, err := Default.GenerateKey("EC", WithGroup("P-384"))
	if err != nil {
		t.Fatal(err)
	}
	defer p384.Close()
	x25519, err := Default.GenerateKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	defer x25519.Close()
	rsa, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer rsa.Close()

	if _, err := p256.Derive(p384, nil); err == nil {
		t.Error("derived across mismatched curves")
	}
	if _, err := p256.Derive(x25519, nil); err == nil {
		t.Error("derived between EC and X25519")
	}
	if _, err := x25519.Derive(p256, nil); err == nil {
		t.Error("derived between X25519 and EC")
	}
	if _, err := p256.Derive(rsa, nil); err == nil {
		t.Error("derived against an RSA peer")
	}
	if _, err := p256.Derive(nil, nil); err == nil {
		t.Error("derived against a nil peer")
	}
}

// Cofactor mode is a real ECDH parameter that citius-server's EcdhParams
// exposes; it must reach OpenSSL and be refused where it has no meaning.
func TestDeriveCofactorMode(t *testing.T) {
	alice, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Close()
	bob, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Close()
	bobPub, _ := bob.Public()
	defer bobPub.Close()
	alicePub, _ := alice.Public()
	defer alicePub.Close()

	opts := &DeriveOptions{CofactorMode: true}
	ab, err := alice.Derive(bobPub, opts)
	if err != nil {
		t.Fatalf("Derive with cofactor mode: %v", err)
	}
	ba, err := bob.Derive(alicePub, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatal("cofactor-mode agreement disagreed")
	}
	// P-256 has cofactor 1, so the result must match the plain mode.
	plain, err := alice.Derive(bobPub, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, plain) {
		t.Fatal("cofactor mode changed the result on a cofactor-1 curve")
	}

	// Montgomery curves have no such knob.
	x, err := Default.GenerateKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close()
	xPub, _ := x.Public()
	defer xPub.Close()
	if _, err := x.Derive(xPub, opts); err == nil {
		t.Fatal("CofactorMode accepted on an X25519 key")
	}
}

func TestDeriveClosedKey(t *testing.T) {
	a, err := Default.GenerateKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Default.GenerateKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	bPub, _ := b.Public()
	defer bPub.Close()
	a.Close()

	if _, err := a.Derive(bPub, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("Derive on a closed key = %v, want ErrClosed", err)
	}
}

func TestDeriveSharedKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)

	k1, err := DeriveSharedKey(secret, "session-v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 32 {
		t.Fatalf("got %d bytes, want 32", len(k1))
	}
	if bytes.Equal(k1, secret) {
		t.Fatal("DeriveSharedKey returned the raw secret")
	}

	// The context string is a domain separator: it must change the output.
	k2, err := DeriveSharedKey(secret, "session-v2", 32)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("two different context strings produced the same key")
	}

	// Deterministic for the same inputs.
	again, err := DeriveSharedKey(secret, "session-v1", 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, again) {
		t.Fatal("DeriveSharedKey is not deterministic")
	}

	if _, err := DeriveSharedKey(nil, "ctx", 32); err == nil {
		t.Fatal("DeriveSharedKey accepted an empty secret")
	}
}

// As with OAEP, a round trip through this package alone cannot show that the
// bytes match what a conforming peer computes: both sides would share any
// mistake. This derives against the openssl tool in both roles.
func TestDeriveInteropWithOpenSSLCLI(t *testing.T) {
	cli := opensslCLI(t)
	dir := t.TempDir()

	for _, tc := range []struct {
		name string
		alg  string
		opts []KeyOption
	}{
		{"EC-P-256", "EC", []KeyOption{WithGroup("P-256")}},
		{"EC-P-384", "EC", []KeyOption{WithGroup("P-384")}},
		{"X25519", "X25519", nil},
		{"X448", "X448", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ours, err := Default.GenerateKey(tc.alg, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer ours.Close()
			theirs, err := Default.GenerateKey(tc.alg, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer theirs.Close()

			oursPriv, err := ours.MarshalPKCS8PEM()
			if err != nil {
				t.Fatal(err)
			}
			theirsPriv, err := theirs.MarshalPKCS8PEM()
			if err != nil {
				t.Fatal(err)
			}
			oursPubKey, err := ours.Public()
			if err != nil {
				t.Fatal(err)
			}
			defer oursPubKey.Close()
			oursPub, err := oursPubKey.MarshalSPKIPEM()
			if err != nil {
				t.Fatal(err)
			}
			theirsPubKey, err := theirs.Public()
			if err != nil {
				t.Fatal(err)
			}
			defer theirsPubKey.Close()
			theirsPub, err := theirsPubKey.MarshalSPKIPEM()
			if err != nil {
				t.Fatal(err)
			}

			write := func(base string, b []byte) string {
				p := filepath.Join(dir, tc.name+"-"+base)
				if err := os.WriteFile(p, b, 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			}
			oursPrivPath := write("ours.key", oursPriv)
			theirsPrivPath := write("theirs.key", theirsPriv)
			oursPubPath := write("ours.pub", oursPub)
			theirsPubPath := write("theirs.pub", theirsPub)

			// This package derives; the CLI derives the mirror image.
			mine, err := ours.Derive(theirsPubKey, nil)
			if err != nil {
				t.Fatalf("Derive: %v", err)
			}

			outPath := filepath.Join(dir, tc.name+"-cli.bin")
			out, err := exec.Command(cli, "pkeyutl", "-derive",
				"-inkey", theirsPrivPath, "-peerkey", oursPubPath, "-out", outPath).CombinedOutput()
			if err != nil {
				t.Fatalf("openssl pkeyutl -derive failed: %v\n%s", err, out)
			}
			cliSecret, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(mine, cliSecret) {
				t.Fatalf("shared secret disagrees with openssl:\n  ours = %x\n  cli  = %x", mine, cliSecret)
			}

			// And the same in the other direction, so neither role is assumed.
			theirsSecret, err := theirs.Derive(oursPubKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			outPath2 := filepath.Join(dir, tc.name+"-cli2.bin")
			out, err = exec.Command(cli, "pkeyutl", "-derive",
				"-inkey", oursPrivPath, "-peerkey", theirsPubPath, "-out", outPath2).CombinedOutput()
			if err != nil {
				t.Fatalf("openssl pkeyutl -derive failed: %v\n%s", err, out)
			}
			cliSecret2, err := os.ReadFile(outPath2)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(theirsSecret, cliSecret2) {
				t.Fatal("reverse-direction shared secret disagrees with openssl")
			}
		})
	}
}
