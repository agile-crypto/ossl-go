//go:build cgo

package ossl

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

// TestDigestKAT pins against published FIPS 180-4 / FIPS 202 test vectors
// for "abc" (independently recomputed with the system sha256sum/sha512sum
// and this OpenSSL build's own `openssl dgst`, not transcribed from memory).
func TestDigestKAT(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"SHA2-256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"SHA2-512", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
		{"SHA3-256", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Digest(c.name, []byte("abc"))
			if err != nil {
				t.Fatalf("Digest(%s): %v", c.name, err)
			}
			if hex.EncodeToString(got) != c.want {
				t.Fatalf("%s(\"abc\") = %x\nwant %s", c.name, got, c.want)
			}
		})
	}
}

// TestDigestEmptyInputKAT pins the well-known empty-input SHA2-256 vector,
// exercising the Write(nil)/empty-slice path through a real digest.
func TestDigestEmptyInputKAT(t *testing.T) {
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got, err := Digest("SHA2-256", nil)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("SHA2-256(\"\") = %x\nwant %s", got, want)
	}
}

func TestDigestStreamingMatchesOneShot(t *testing.T) {
	h, err := Default.NewHash("SHA2-256")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	parts := []string{"The quick brown fox ", "jumps over ", "the lazy dog"}
	for _, p := range parts {
		if _, err := h.Write([]byte(p)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	streamed := h.Sum(nil)

	oneShot, err := Digest("SHA2-256", []byte("The quick brown fox jumps over the lazy dog"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(streamed, oneShot) {
		t.Fatalf("streamed = %x\noneShot  = %x", streamed, oneShot)
	}
}

// TestHashSumIsNonDestructive exercises the hash.Hash contract that Sum must
// not disturb state: two consecutive Sum calls must agree, and a Write
// interleaved between them must still count toward a later Sum.
func TestHashSumIsNonDestructive(t *testing.T) {
	h, err := Default.NewHash("SHA2-256")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if _, err := h.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	sum1 := h.Sum(nil)
	sum2 := h.Sum(nil)
	if !bytes.Equal(sum1, sum2) {
		t.Fatalf("two consecutive Sum calls disagree: %x vs %x", sum1, sum2)
	}

	if _, err := h.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	sum3 := h.Sum(nil)
	if bytes.Equal(sum2, sum3) {
		t.Fatal("Sum did not reflect a Write that happened after the previous Sum")
	}

	want, err := Digest("SHA2-256", []byte("firstsecond"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sum3, want) {
		t.Fatalf("Sum after interleaved Write = %x, want %x", sum3, want)
	}
}

// TestDigestXOF pins a SHAKE-256 vector independently recomputed with
// `openssl dgst -shake256 -xoflen 32`.
func TestDigestXOF(t *testing.T) {
	want := "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739"
	got, err := DigestXOF("SHAKE-256", []byte("abc"), 32)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("SHAKE-256(\"abc\", 32) = %x\nwant %s", got, want)
	}
}

func TestDigestUnknownAlgorithm(t *testing.T) {
	if _, err := Digest("TOTALLY-MADE-UP-DIGEST", []byte("x")); err == nil {
		t.Fatal("Digest with a made-up algorithm name succeeded")
	}
}

func TestHashEmptyWrite(t *testing.T) {
	h, err := Default.NewHash("SHA2-256")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	n, err := h.Write(nil)
	if n != 0 || err != nil {
		t.Fatalf("Write(nil) = (%d, %v), want (0, nil)", n, err)
	}
}

func TestHashCloseIsIdempotent(t *testing.T) {
	h, err := Default.NewHash("SHA2-256")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := h.Write([]byte("x")); err != ErrClosed {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
}

// TestHashSatisfiesHashHash exercises Hash through io.Copy, proving it
// behaves as a real hash.Hash rather than merely type-asserting as one.
func TestHashSatisfiesHashHash(t *testing.T) {
	h, err := Default.NewHash("SHA2-256")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	src := bytes.NewReader([]byte("data flowing through io.Copy"))
	if _, err := io.Copy(h, src); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}

	want, err := Digest("SHA2-256", []byte("data flowing through io.Copy"))
	if err != nil {
		t.Fatal(err)
	}
	if got := h.Sum(nil); !bytes.Equal(got, want) {
		t.Fatalf("Sum after io.Copy = %x, want %x", got, want)
	}
}

func TestHashSizeAndBlockSize(t *testing.T) {
	h, err := Default.NewHash("SHA2-256")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if h.Size() != 32 {
		t.Fatalf("Size() = %d, want 32", h.Size())
	}
	if h.BlockSize() != 64 {
		t.Fatalf("BlockSize() = %d, want 64", h.BlockSize())
	}
	if h.Name() != "SHA2-256" {
		t.Fatalf("Name() = %q, want %q", h.Name(), "SHA2-256")
	}
}
