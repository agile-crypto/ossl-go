package ossl

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"
)

// TestHMACKAT pins RFC 4231 test case 1 (independently recomputed with
// `openssl mac -digest SHA256 -macopt hexkey:... HMAC`, not transcribed from
// memory).
func TestHMACKAT(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	want := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"

	got, err := HMACSum("SHA2-256", key, []byte("Hi There"))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("HMAC-SHA256 = %x\nwant %s", got, want)
	}
}

func TestMACVariants(t *testing.T) {
	key := []byte("a 32-byte key for HMAC and KMAC")
	msg := []byte("authenticate me")

	t.Run("HMAC", func(t *testing.T) {
		m, err := Default.NewHMAC("SHA2-256", key)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		if _, err := m.Write(msg); err != nil {
			t.Fatal(err)
		}
		tag := m.Sum(nil)
		if len(tag) != 32 {
			t.Fatalf("HMAC-SHA256 tag length = %d, want 32", len(tag))
		}
	})

	t.Run("CMAC", func(t *testing.T) {
		cmacKey := bytes.Repeat([]byte{0x2b}, 32) // 32 bytes: AES-256
		m, err := Default.NewCMAC("AES-256-CBC", cmacKey)
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		if _, err := m.Write(msg); err != nil {
			t.Fatal(err)
		}
		tag := m.Sum(nil)
		if len(tag) != 16 {
			t.Fatalf("CMAC-AES-256 tag length = %d, want 16 (the AES block size)", len(tag))
		}
	})

	t.Run("KMAC", func(t *testing.T) {
		m, err := Default.NewKMAC(256, key, 32, []byte("my-app-v1"))
		if err != nil {
			t.Fatal(err)
		}
		defer m.Close()
		if _, err := m.Write(msg); err != nil {
			t.Fatal(err)
		}
		tag := m.Sum(nil)
		if len(tag) != 32 {
			t.Fatalf("KMAC256 tag length = %d, want the requested 32", len(tag))
		}
	})
}

// TestMACResetReusesKeyAndOptions confirms Reset puts the MAC back in its
// initial state using the same key/digest/etc it was constructed with,
// rather than requiring the caller to rebuild a new MAC.
func TestMACResetReusesKeyAndOptions(t *testing.T) {
	m, err := Default.NewHMAC("SHA2-256", []byte("a shared secret"))
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	if _, err := m.Write([]byte("first message")); err != nil {
		t.Fatal(err)
	}
	tag1 := m.Sum(nil)

	m.Reset()
	if _, err := m.Write([]byte("first message")); err != nil {
		t.Fatal(err)
	}
	tag2 := m.Sum(nil)

	if !bytes.Equal(tag1, tag2) {
		t.Fatalf("tag after Reset + same input = %x, want %x (same as before Reset)", tag2, tag1)
	}
}

// TestMACCloseCleansesRetainedKey verifies Close actually scrubs the
// retained key copy in place, not merely drops the reference to it: keyRef
// aliases the same backing array as m.key before Close nils that field, so
// if Zero() worked, the bytes reachable through keyRef read back as zero.
func TestMACCloseCleansesRetainedKey(t *testing.T) {
	m, err := Default.NewHMAC("SHA2-256", []byte("supersecretkey12"))
	if err != nil {
		t.Fatal(err)
	}
	keyRef := m.key

	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if m.key != nil {
		t.Fatal("key field not nil after Close")
	}
	for i, b := range keyRef {
		if b != 0 {
			t.Fatalf("retained key backing array not cleansed at byte %d: %x", i, keyRef)
		}
	}
}

func TestMACCloseIsIdempotent(t *testing.T) {
	m, err := Default.NewHMAC("SHA2-256", []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := m.Write([]byte("x")); err != ErrClosed {
		t.Fatalf("Write after Close = %v, want ErrClosed", err)
	}
}

func TestMACUnknownCipher(t *testing.T) {
	if _, err := Default.NewCMAC("TOTALLY-MADE-UP-CIPHER", []byte("k")); err == nil {
		t.Fatal("NewCMAC with a made-up cipher name succeeded")
	}
}

// TestMACSatisfiesHashHash exercises MAC through io.Copy, proving it behaves
// as a real hash.Hash rather than merely type-asserting as one.
func TestMACSatisfiesHashHash(t *testing.T) {
	key := []byte("a shared secret")
	m, err := Default.NewHMAC("SHA2-256", key)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	src := bytes.NewReader([]byte("data flowing through io.Copy"))
	if _, err := io.Copy(m, src); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}

	want, err := HMACSum("SHA2-256", key, []byte("data flowing through io.Copy"))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Sum(nil); !bytes.Equal(got, want) {
		t.Fatalf("Sum after io.Copy = %x, want %x", got, want)
	}
}

func TestEqualMAC(t *testing.T) {
	a := []byte{1, 2, 3, 4}
	b := append([]byte(nil), a...)
	c := []byte{1, 2, 3, 5}

	if !EqualMAC(a, b) {
		t.Fatal("EqualMAC(a, b) = false for identical tags")
	}
	if EqualMAC(a, c) {
		t.Fatal("EqualMAC(a, c) = true for tags differing in the last byte")
	}
	if EqualMAC(a, a[:3]) {
		t.Fatal("EqualMAC = true for tags of different lengths")
	}
}
