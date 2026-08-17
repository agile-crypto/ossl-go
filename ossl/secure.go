//go:build cgo

package ossl

/*
#include <openssl/crypto.h>
#include <stdlib.h>

// The OPENSSL_secure_* names are macros that stamp in __FILE__/__LINE__,
// so cgo cannot call them. These shims give them real addresses.
static void *ossl_secure_zalloc(size_t n) { return OPENSSL_secure_zalloc(n); }
static void  ossl_secure_clear_free(void *p, size_t n) { OPENSSL_secure_clear_free(p, n); }
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

// secureHeapMu serialises initialisation and teardown of the secure heap,
// which is a single process-wide arena rather than per-context state.
var secureHeapMu sync.Mutex

// InitSecureHeap reserves the process-wide secure heap.
//
// The secure heap is a separate mmap'd arena that is mlock'd so its pages
// are never written to swap, and wiped on release. Key material held there
// cannot leak into a swap file or a core dump the way ordinary heap can.
//
// size is the total arena in bytes and minAlloc the smallest allocation
// unit; both must be powers of two, and size must be a multiple of minAlloc.
// The arena is reserved up front, so pick a size that covers the keys in
// flight rather than the largest imaginable workload.
//
// Call this once, early, before any secret is allocated. Allocation before
// initialisation does not fail -- it quietly returns ordinary heap memory --
// so a program that starts using NewSecureBuffer before this call gets no
// protection and no warning from OpenSSL. NewSecureBuffer in this package
// checks for that and refuses, but the ordering is still the caller's to get
// right.
//
// Requires the process to be allowed to lock memory (RLIMIT_MEMLOCK); a
// container with a small limit will fail here rather than silently degrade.
func InitSecureHeap(size, minAlloc int) error {
	if size <= 0 || minAlloc <= 0 {
		return fmt.Errorf("ossl: secure heap size and minimum allocation must be positive")
	}
	if size&(size-1) != 0 || minAlloc&(minAlloc-1) != 0 {
		return fmt.Errorf("ossl: secure heap size (%d) and minimum allocation (%d) must be powers of two",
			size, minAlloc)
	}
	secureHeapMu.Lock()
	defer secureHeapMu.Unlock()
	if C.CRYPTO_secure_malloc_initialized() == 1 {
		// A second init fails and leaves the existing arena untouched, but
		// reports it as a bare allocation failure. Say what actually
		// happened: the heap is process-wide and somebody already sized it.
		return fmt.Errorf("ossl: the secure heap is already initialised")
	}
	clearErrors()
	if C.CRYPTO_secure_malloc_init(C.size_t(size), C.size_t(minAlloc)) != 1 {
		return newError("CRYPTO_secure_malloc_init")
	}
	return nil
}

// DoneSecureHeap releases the secure heap.
//
// Every SecureBuffer must be closed first. Releasing the arena out from
// under a live buffer leaves that buffer pointing at unmapped memory, which
// is a segfault rather than an error return.
func DoneSecureHeap() error {
	secureHeapMu.Lock()
	defer secureHeapMu.Unlock()
	clearErrors()
	if C.CRYPTO_secure_malloc_done() != 1 {
		return newError("CRYPTO_secure_malloc_done")
	}
	return nil
}

// SecureHeapInitialized reports whether the secure heap is available.
func SecureHeapInitialized() bool {
	return C.CRYPTO_secure_malloc_initialized() == 1
}

// SecureHeapUsed is the number of bytes currently allocated from the secure
// heap, across the whole process. It reports 0 when there is no heap.
//
// The initialisation check is required and not jsut defensive tidiness:
// CRYPTO_secure_used dereferences the arena bookkeeping unconditionally and
// segfaults outright if the heap was never set up. A function that only
// reads a counter is the last place a caller would expect a crash, so the
// guard belongs here rather than in every call site.
func SecureHeapUsed() int {
	if !SecureHeapInitialized() {
		return 0
	}
	return int(C.CRYPTO_secure_used())
}

// SecureBuffer is a byte buffer held in the secure heap: not swapped out,
// and wiped when closed.
//
// Use it for key material with a lifetime -- a long-lived signing key, a
// master secret -- rather than for every transient byte slice. Bytes gives
// an ordinary []byte view for passing to the rest of this package.
//
// Not safe for concurrent use.
type SecureBuffer struct {
	ptr unsafe.Pointer
	n   int
}

// NewSecureBuffer allocates n zeroed bytes from the secure heap.
//
// It fails rather than falling back. OpenSSL's own allocator quietly returns
// ordinary heap memory when the secure heap is uninitialised, which would
// hand back something that looks identical and is swappable -- the exact
// failure this type exists to prevent. Every allocation is checked with
// CRYPTO_secure_allocated and released if it did not come from the arena.
func NewSecureBuffer(n int) (*SecureBuffer, error) {
	if n <= 0 {
		return nil, fmt.Errorf("ossl: secure buffer size must be positive, got %d", n)
	}
	if n > maxOutputLength {
		return nil, fmt.Errorf("ossl: secure buffer size %d exceeds the maximum of %d bytes", n, maxOutputLength)
	}
	if !SecureHeapInitialized() {
		return nil, fmt.Errorf("ossl: secure heap is not initialised; call InitSecureHeap first")
	}
	clearErrors()
	p := C.ossl_secure_zalloc(C.size_t(n))
	if p == nil {
		return nil, fmt.Errorf("ossl: secure heap exhausted allocating %d bytes (%d in use)",
			n, SecureHeapUsed())
	}
	if C.CRYPTO_secure_allocated(p) != 1 {
		// Ordinary heap wearing a secure buffer's clothes. Give it back.
		C.ossl_secure_clear_free(p, C.size_t(n))
		return nil, fmt.Errorf("ossl: allocation of %d bytes did not come from the secure heap", n)
	}
	return &SecureBuffer{ptr: p, n: n}, nil
}

// Bytes returns a slice aliasing the secure allocation. It is not a copy:
// writing to it writes to the secure heap, which is the point.
//
// The slice is invalid after Close, and appending to it copies the contents
// straight back onto the ordinary heap -- so treat it as a view to read and
// write in place, never as a value to grow or retain.
func (b *SecureBuffer) Bytes() []byte {
	if b == nil || b.ptr == nil {
		return nil
	}
	return unsafe.Slice((*byte)(b.ptr), b.n)
}

// Len is the buffer size in bytes.
func (b *SecureBuffer) Len() int {
	if b == nil {
		return 0
	}
	return b.n
}

// Close wipes the buffer and returns it to the secure heap. Safe to call
// more than once.
func (b *SecureBuffer) Close() error {
	if b == nil {
		return nil
	}
	if b.ptr != nil {
		C.ossl_secure_clear_free(b.ptr, C.size_t(b.n))
		b.ptr = nil
		b.n = 0
	}
	return nil
}
