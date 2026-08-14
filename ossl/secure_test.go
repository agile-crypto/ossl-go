//go:build cgo

package ossl

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The secure heap is one process-wide arena, so these tests own its whole
// lifecycle inside a single function rather than relying on the order Go
// happens to run them in.

func TestInitSecureHeapValidatesArguments(t *testing.T) {
	for _, tc := range []struct{ size, min int }{
		{0, 64},      // non-positive size
		{65536, 0},   // non-positive minimum
		{-1, 64},     // negative
		{65535, 64},  // size not a power of two
		{65536, 100}, // minimum not a power of two
	} {
		if err := InitSecureHeap(tc.size, tc.min); err == nil {
			t.Errorf("InitSecureHeap(%d, %d) succeeded; want an error", tc.size, tc.min)
		}
	}
}

func TestSecureHeapLifecycle(t *testing.T) {
	if SecureHeapInitialized() {
		t.Skip("secure heap already initialised by another test")
	}
	if err := InitSecureHeap(1<<16, 64); err != nil {
		t.Skipf("cannot initialise the secure heap here (RLIMIT_MEMLOCK?): %v", err)
	}
	defer func() {
		if err := DoneSecureHeap(); err != nil {
			t.Errorf("DoneSecureHeap: %v", err)
		}
	}()

	if !SecureHeapInitialized() {
		t.Fatal("SecureHeapInitialized() is false after a successful init")
	}
	if used := SecureHeapUsed(); used != 0 {
		t.Fatalf("SecureHeapUsed() = %d on a fresh heap, want 0", used)
	}

	b, err := NewSecureBuffer(1024)
	if err != nil {
		t.Fatalf("NewSecureBuffer: %v", err)
	}
	if b.Len() != 1024 {
		t.Fatalf("Len() = %d, want 1024", b.Len())
	}
	if used := SecureHeapUsed(); used < 1024 {
		t.Fatalf("SecureHeapUsed() = %d after a 1024-byte allocation", used)
	}

	// Zeroed on allocation.
	buf := b.Bytes()
	if len(buf) != 1024 {
		t.Fatalf("Bytes() length = %d, want 1024", len(buf))
	}
	if !bytes.Equal(buf, make([]byte, 1024)) {
		t.Fatal("a fresh secure buffer is not zeroed")
	}

	// Bytes aliases the allocation rather than copying it.
	buf[0] = 0xAB
	buf[1023] = 0xCD
	again := b.Bytes()
	if again[0] != 0xAB || again[1023] != 0xCD {
		t.Fatal("Bytes() returned a copy, not a view of the allocation")
	}

	// It is real memory: usable as key material end to end.
	key := b.Bytes()[:32]
	for i := range key {
		key[i] = byte(i)
	}
	aead, err := Default.NewAEAD("AES-256-GCM", key)
	if err != nil {
		t.Fatalf("NewAEAD with a key held in the secure heap: %v", err)
	}
	defer aead.Close()
	nonce := make([]byte, aead.NonceSize())
	ct, err := aead.SealErr(nil, nonce, []byte("secret"), nil)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("secret")) {
		t.Fatal("round trip through a secure-heap key failed")
	}

	// Exhaustion is an error, not a silent fall back to ordinary heap.
	if _, err := NewSecureBuffer(1 << 20); err == nil {
		t.Fatal("allocating more than the whole arena succeeded")
	}

	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if b.Bytes() != nil {
		t.Fatal("Bytes() is non-nil after Close")
	}
	if b.Len() != 0 {
		t.Fatal("Len() is non-zero after Close")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if used := SecureHeapUsed(); used != 0 {
		t.Fatalf("SecureHeapUsed() = %d after closing every buffer, want 0", used)
	}

	if _, err := NewSecureBuffer(0); err == nil {
		t.Error("NewSecureBuffer(0) succeeded")
	}
	if _, err := NewSecureBuffer(-1); err == nil {
		t.Error("NewSecureBuffer(-1) succeeded")
	}
}

// Allocating before the heap exists must fail loudly. OpenSSL's own
// allocator returns ordinary swappable heap in that situation, which is
// indistinguishable to the caller, so this refusal is the whole reason
// NewSecureBuffer checks CRYPTO_secure_allocated.
//
// Runs in a subprocess because it needs a process where the heap has never
// been initialised, which cannot be arranged once another test has done it.
func TestSecureBufferRefusesBeforeInit(t *testing.T) {
	if os.Getenv("OSSL_SECURE_CHILD") == "1" {
		if SecureHeapInitialized() {
			t.Log("RESULT: already-initialised")
			return
		}
		if _, err := NewSecureBuffer(64); err == nil {
			t.Log("RESULT: allocated-anyway")
		} else {
			t.Logf("RESULT: refused (%v)", err)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestSecureBufferRefusesBeforeInit", "-test.v")
	cmd.Env = append(os.Environ(), "OSSL_SECURE_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	got := string(out)
	switch {
	case strings.Contains(got, "RESULT: refused"):
		// Correct: no secure heap, no secure buffer.
	case strings.Contains(got, "RESULT: allocated-anyway"):
		t.Error("NewSecureBuffer handed back memory with no secure heap initialised")
	default:
		t.Fatalf("subprocess produced no usable RESULT marker:\n%s", got)
	}
}

func TestSecureHeapUsedIsZeroWhenUninitialised(t *testing.T) {
	if SecureHeapInitialized() {
		t.Skip("secure heap is initialised")
	}
	if used := SecureHeapUsed(); used != 0 {
		t.Fatalf("SecureHeapUsed() = %d with no heap, want 0", used)
	}
}
