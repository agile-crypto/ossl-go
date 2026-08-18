//go:build cgo

package ossl

import (
	"bytes"
	"sync"
	"testing"
)

// These tests exist to be run under -race and under cgocheck2, which is what
// `make ci` does. Passing them without those flags proves very little; the
// point is that the race detector sees the shared C state and the pointer
// checker sees every Go pointer that crosses into C under contention.

const (
	concGoroutines = 8
	concIterations = 100
)

// parallel runs fn on several goroutines and waits for them.
func parallel(t *testing.T, fn func(worker int) error) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make([]error, concGoroutines)
	for i := 0; i < concGoroutines; i++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			errs[w] = fn(w)
		}(i)
	}
	wg.Wait()
	for w, err := range errs {
		if err != nil {
			t.Errorf("worker %d: %v", w, err)
		}
	}
}

// Hash is documented as not safe for concurrent use. What must hold is that
// separate Hash values on separate goroutines do not interfere -- the shared
// state underneath them is the fetched EVP_MD and the library context.
func TestConcurrentDigests(t *testing.T) {
	want, err := Digest("SHA2-256", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}

	parallel(t, func(w int) error {
		for i := 0; i < concIterations; i++ {
			h, err := Default.NewHash("SHA2-256")
			if err != nil {
				return err
			}
			if _, err := h.Write([]byte("abc")); err != nil {
				h.Close()
				return err
			}
			got := h.Sum(nil)
			if err := h.Err(); err != nil {
				h.Close()
				return err
			}
			h.Close()
			if !bytes.Equal(got, want) {
				t.Errorf("worker %d iteration %d: digest mismatch", w, i)
				return nil
			}
			// The one-shot path fetches and frees on every call, which is
			// the allocation pattern most likely to race.
			if _, err := Digest("SHA2-512", []byte("abc")); err != nil {
				return err
			}
		}
		return nil
	})
}

func TestConcurrentMACs(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 32)
	want, err := HMACSum("SHA2-256", key, []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	parallel(t, func(w int) error {
		for i := 0; i < concIterations; i++ {
			got, err := HMACSum("SHA2-256", key, []byte("data"))
			if err != nil {
				return err
			}
			if !EqualMAC(got, want) {
				t.Errorf("worker %d iteration %d: MAC mismatch", w, i)
				return nil
			}
		}
		return nil
	})
}

func TestConcurrentKDFs(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	want, err := Default.HKDF("SHA2-256", secret, nil, []byte("info"), 32)
	if err != nil {
		t.Fatal(err)
	}

	parallel(t, func(w int) error {
		for i := 0; i < concIterations; i++ {
			got, err := Default.HKDF("SHA2-256", secret, nil, []byte("info"), 32)
			if err != nil {
				return err
			}
			if !bytes.Equal(got, want) {
				t.Errorf("worker %d: HKDF mismatch", w)
				return nil
			}
		}
		return nil
	})
}

// AEAD documents itself as safe for concurrent Seal and Open. This exercises
// that against one shared instance, which is how a server would use it.
func TestConcurrentAEAD(t *testing.T) {
	a, err := Default.NewAEAD("AES-256-GCM", bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	parallel(t, func(w int) error {
		// A distinct nonce per worker: sharing one would be a nonce reuse
		// bug in the test rather than a property of the type.
		nonce := make([]byte, a.NonceSize())
		nonce[0] = byte(w)
		plaintext := []byte{byte(w), 'p', 'a', 'y'}
		aad := []byte{byte(w), 'a'}

		for i := 0; i < concIterations; i++ {
			nonce[1] = byte(i)
			ct, err := a.SealErr(nil, nonce, plaintext, aad)
			if err != nil {
				return err
			}
			pt, err := a.Open(nil, nonce, ct, aad)
			if err != nil {
				return err
			}
			if !bytes.Equal(pt, plaintext) {
				t.Errorf("worker %d: round trip mismatch", w)
				return nil
			}
		}
		return nil
	})
}

// Sign and Verify build their own EVP_MD_CTX per call and only read the
// EVP_PKEY, so one Key can serve many goroutines. That is worth pinning
// because the opposite -- a Key that must be cloned per request -- would
// change how every caller structures a server.
func TestConcurrentSignVerifyOnSharedKey(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	parallel(t, func(w int) error {
		msg := []byte{byte(w), 'm', 's', 'g'}
		for i := 0; i < concIterations; i++ {
			sig, err := k.Sign(msg, nil)
			if err != nil {
				return err
			}
			if err := k.Verify(msg, sig, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

func TestConcurrentKeyGeneration(t *testing.T) {
	parallel(t, func(w int) error {
		for i := 0; i < 5; i++ {
			for _, alg := range []KeyAlgorithm{"EC", "ED25519", "ML-KEM-768"} {
				var opts []KeyOption
				if alg == "EC" {
					opts = []KeyOption{WithGroup("P-256")}
				}
				k, err := Default.GenerateKey(alg, opts...)
				if err != nil {
					return err
				}
				k.Close()
			}
		}
		return nil
	})
}

func TestConcurrentKEMAndDerive(t *testing.T) {
	kem, err := Default.GenerateKey("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	defer kem.Close()

	dh, err := Default.GenerateKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	defer dh.Close()
	peer, err := Default.GenerateKey("X25519")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerPub, err := peer.Public()
	if err != nil {
		t.Fatal(err)
	}
	defer peerPub.Close()

	baseline, err := dh.Derive(peerPub, nil)
	if err != nil {
		t.Fatal(err)
	}

	parallel(t, func(w int) error {
		for i := 0; i < 20; i++ {
			ct, ss, err := kem.Encapsulate()
			if err != nil {
				return err
			}
			got, err := kem.Decapsulate(ct)
			if err != nil {
				return err
			}
			if !bytes.Equal(ss, got) {
				t.Errorf("worker %d: KEM secret mismatch", w)
				return nil
			}
			shared, err := dh.Derive(peerPub, nil)
			if err != nil {
				return err
			}
			if !bytes.Equal(shared, baseline) {
				t.Errorf("worker %d: ECDH result is not stable under concurrency", w)
				return nil
			}
		}
		return nil
	})
}

// One Context shared across goroutines is the intended deployment shape, so
// concurrent fetches through it must be safe.
func TestConcurrentContextFetches(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	prov, err := c.LoadProvider("default")
	if err != nil {
		t.Fatal(err)
	}
	defer prov.Unload()

	parallel(t, func(w int) error {
		for i := 0; i < concIterations; i++ {
			if !c.DigestAvailable("SHA2-256", "") {
				t.Errorf("worker %d: SHA2-256 unavailable", w)
				return nil
			}
			if !c.CipherAvailable("AES-256-GCM", "") {
				t.Errorf("worker %d: AES-256-GCM unavailable", w)
				return nil
			}
			if _, err := c.Providers(); err != nil {
				return err
			}
		}
		return nil
	})
}

// The error queue is thread-local. A failure on one goroutine must not be
// reported against an unrelated call on another, which is the bug that
// clearErrors on every entry point exists to prevent.
func TestConcurrentErrorsDoNotCrossGoroutines(t *testing.T) {
	parallel(t, func(w int) error {
		for i := 0; i < concIterations; i++ {
			if w%2 == 0 {
				// Deliberately fail, leaving entries on this thread's queue.
				if _, err := Default.NewHash("NO-SUCH-DIGEST"); err == nil {
					t.Errorf("worker %d: unknown digest succeeded", w)
					return nil
				}
			} else {
				// Must succeed regardless of what the other workers queued.
				if _, err := Digest("SHA2-256", []byte("x")); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Allocation balance, checked where it can actually be checked.
//
// An RSS-based leak test was tried here first and removed: with a mixed
// workload of 2000 iterations it could not detect a deliberately leaked
// EVP_CIPHER (that is a refcount leak on a cached provider object, which
// costs no memory at all) nor a deliberately leaked EVP_PKEY (too small
// against allocator noise to separate from a clean run). A check that stays
// green while the bug it names is present is worse than no check, because it
// reads as coverage.
//
// The secure heap does expose an exact byte counter, so allocation balance
// is a real assertion there rather than an inference from process memory.
func TestSecureHeapAllocationsBalance(t *testing.T) {
	if SecureHeapInitialized() {
		t.Skip("secure heap already initialised by another test")
	}
	if err := InitSecureHeap(1<<16, 64); err != nil {
		t.Skipf("cannot initialise the secure heap here: %v", err)
	}
	defer DoneSecureHeap()

	if used := SecureHeapUsed(); used != 0 {
		t.Fatalf("fresh heap reports %d bytes in use", used)
	}

	for i := 0; i < 500; i++ {
		b, err := NewSecureBuffer(256)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		copy(b.Bytes(), []byte("key material"))
		if used := SecureHeapUsed(); used == 0 {
			t.Fatalf("iteration %d: heap reports nothing in use while a buffer is open", i)
		}
		if err := b.Close(); err != nil {
			t.Fatal(err)
		}
		if used := SecureHeapUsed(); used != 0 {
			t.Fatalf("iteration %d: %d bytes still allocated after Close", i, used)
		}
	}

	// Many live at once, then all released.
	var bufs []*SecureBuffer
	for i := 0; i < 32; i++ {
		b, err := NewSecureBuffer(256)
		if err != nil {
			t.Fatalf("allocation %d: %v", i, err)
		}
		bufs = append(bufs, b)
	}
	if used := SecureHeapUsed(); used < 32*256 {
		t.Fatalf("32 live 256-byte buffers report only %d bytes in use", used)
	}
	for _, b := range bufs {
		b.Close()
	}
	if used := SecureHeapUsed(); used != 0 {
		t.Fatalf("%d bytes still allocated after closing every buffer", used)
	}
}
