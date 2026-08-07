package ossl

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSignerRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		alg  string
		opts []KeyOption
	}{
		{"RSA", nil},
		{"EC", []KeyOption{WithGroup("P-256")}},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			k, err := Default.GenerateKey(tc.alg, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()

			s, err := NewSigner(k, nil)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			defer s.Close()
			if _, err := s.Write([]byte("streamed ")); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Write([]byte("in pieces")); err != nil {
				t.Fatal(err)
			}
			sig, err := s.Sign()
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			v, err := NewVerifier(k, nil)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			defer v.Close()
			if _, err := v.Write([]byte("streamed in pieces")); err != nil {
				t.Fatal(err)
			}
			if err := v.Verify(sig); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

// The property that makes streaming trustworthy: a signature accumulated
// across many Writes must be interchangeable with a one-shot signature over
// the concatenation, in both directions. Chunk boundaries must not matter.
func TestSignerInteroperatesWithOneShot(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := bytes.Repeat([]byte("abcdefghij"), 500) // 5000 bytes

	// Streamed signature verifies with the one-shot Key.Verify.
	s, err := NewSigner(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for off := 0; off < len(msg); off += 7 { // deliberately uneven chunks
		end := off + 7
		if end > len(msg) {
			end = len(msg)
		}
		if _, err := s.Write(msg[off:end]); err != nil {
			t.Fatal(err)
		}
	}
	streamed, err := s.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(msg, streamed, nil); err != nil {
		t.Fatalf("one-shot Verify of a streamed signature: %v", err)
	}

	// One-shot signature verifies with the streaming Verifier.
	oneShot, err := k.Sign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err := io.Copy(v, bytes.NewReader(msg)); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(oneShot); err != nil {
		t.Fatalf("streaming Verify of a one-shot signature: %v", err)
	}
}

func TestSignerSatisfiesIOWriter(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	s, err := NewSigner(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	msg := bytes.Repeat([]byte{0xab}, 100000)
	n, err := io.Copy(s, bytes.NewReader(msg))
	if err != nil {
		t.Fatal(err)
	}
	if n != int64(len(msg)) {
		t.Fatalf("io.Copy wrote %d bytes, want %d", n, len(msg))
	}
	sig, err := s.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(msg, sig, nil); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifierRejectsTamperedInput(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	sig, err := k.Sign([]byte("the real message"), nil)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewVerifier(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if _, err := v.Write([]byte("the fake message")); err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(sig); !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify over tampered input = %v, want ErrVerification", err)
	}
}

func TestVerifierRejectsTamperedSignature(t *testing.T) {
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

	// A corrupted DER prefix makes EVP return negative rather than 0; both
	// must land on ErrVerification.
	for _, idx := range []int{0, len(sig) - 1} {
		bad := append([]byte(nil), sig...)
		bad[idx] ^= 0xFF

		v, err := NewVerifier(k, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Write(msg); err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(bad); !errors.Is(err, ErrVerification) {
			t.Fatalf("Verify with byte %d flipped = %v, want ErrVerification", idx, err)
		}
		v.Close()
	}
}

func TestVerifierRejectsEmptySignature(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	v, err := NewVerifier(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	v.Write([]byte("m"))
	if err := v.Verify(nil); !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify(nil) = %v, want ErrVerification", err)
	}
}

// Streaming is refused up front for the algorithms that cannot do it, rather
// than failing somewhere inside a later Write once the caller has already
// pushed data through.
func TestStreamingRefusedForOneShotOnlyAlgorithms(t *testing.T) {
	for _, alg := range []string{"ED25519", "ED448", "ML-DSA-65", "SLH-DSA-SHA2-128s"} {
		t.Run(alg, func(t *testing.T) {
			k, err := Default.GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()

			_, err = NewSigner(k, nil)
			if err == nil {
				t.Fatal("NewSigner accepted a one-shot-only algorithm")
			}
			if !strings.Contains(err.Error(), "Key.Sign") {
				t.Fatalf("error does not redirect to Key.Sign: %v", err)
			}
			if _, err := NewVerifier(k, nil); err == nil {
				t.Fatal("NewVerifier accepted a one-shot-only algorithm")
			}
		})
	}
}

// A Signer owns a reference on the key, so closing the Key underneath it is
// a supported thing to do rather than a use-after-free.
func TestSignerOutlivesItsKey(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := k.Public()
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()

	msg := []byte("outlives the key")
	s, err := NewSigner(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := s.Write(msg); err != nil {
		t.Fatal(err)
	}
	k.Close() // caller drops their handle mid-stream

	sig, err := s.Sign()
	if err != nil {
		t.Fatalf("Sign after the Key was closed: %v", err)
	}
	if err := pub.Verify(msg, sig, nil); err != nil {
		t.Fatalf("signature produced after Key.Close does not verify: %v", err)
	}
}

func TestSignerRejectsClosedKey(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	k.Close()
	if _, err := NewSigner(k, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("NewSigner on a closed key = %v, want ErrClosed", err)
	}
	if _, err := NewVerifier(k, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("NewVerifier on a closed key = %v, want ErrClosed", err)
	}
}

func TestSignerRejectsReuseAfterFinalise(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	s, err := NewSigner(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Write([]byte("m"))
	if _, err := s.Sign(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(); err == nil {
		t.Fatal("second Sign succeeded")
	}
	if _, err := s.Write([]byte("more")); err == nil {
		t.Fatal("Write after Sign succeeded")
	}

	v, err := NewVerifier(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	v.Write([]byte("m"))
	_ = v.Verify([]byte("bogus"))
	if err := v.Verify([]byte("bogus")); err == nil {
		t.Fatal("second Verify succeeded")
	}
	if _, err := v.Write([]byte("more")); err == nil {
		t.Fatal("Write after Verify succeeded")
	}
}

func TestSignerUsesSignOptions(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	msg := []byte("padding matters")
	s, err := NewSigner(k, &SignOptions{Padding: RSAPKCS1v15})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Write(msg)
	sig, err := s.Sign()
	if err != nil {
		t.Fatal(err)
	}

	// The option reached OpenSSL: the signature verifies as PKCS#1 v1.5 and
	// not as PSS.
	if err := k.Verify(msg, sig, &SignOptions{Padding: RSAPKCS1v15}); err != nil {
		t.Fatalf("Verify as PKCS#1 v1.5: %v", err)
	}
	if err := k.Verify(msg, sig, &SignOptions{Padding: RSAPSS}); !errors.Is(err, ErrVerification) {
		t.Fatalf("Verify as PSS = %v, want ErrVerification", err)
	}
}

// The streaming constructors go through the same option validation as the
// one-shot path, so an option the algorithm cannot honour is refused here
// too rather than silently dropped.
func TestStreamingRejectsInapplicableOptions(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	for _, opts := range []*SignOptions{
		{Context: []byte("domain")},
		{Prehash: true},
		{Padding: RSAPKCS1v15},
	} {
		if _, err := NewSigner(k, opts); err == nil {
			t.Errorf("NewSigner accepted %+v", opts)
		}
		if _, err := NewVerifier(k, opts); err == nil {
			t.Errorf("NewVerifier accepted %+v", opts)
		}
	}
}

func TestSignerCloseIsIdempotent(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	s, err := NewSigner(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write([]byte("m")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
	if _, err := s.Sign(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Sign after Close = %v, want ErrClosed", err)
	}

	v, err := NewVerifier(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	v.Close()
	if _, err := v.Write([]byte("m")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
	if err := v.Verify([]byte("sig")); !errors.Is(err, ErrClosed) {
		t.Fatalf("Verify after Close = %v, want ErrClosed", err)
	}
}

func TestSignerEmptyMessage(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	s, err := NewSigner(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Write(nil); err != nil {
		t.Fatal(err)
	}
	sig, err := s.Sign()
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Verify(nil, sig, nil); err != nil {
		t.Fatalf("one-shot Verify of an empty streamed message: %v", err)
	}
}
