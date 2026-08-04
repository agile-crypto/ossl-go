package ossl

import (
	"bytes"
	"encoding/binary"
	"testing"
	"unsafe"
)

// This package targets linux/amd64 (see the Makefile and the design
// document's own test environment). On that platform's C ABI, which cgo
// requires anyway for the two sides to agree on layout, int and unsigned int
// are 4 bytes and size_t is 8 bytes. These constants exist so the tests below
// can decode raw bytes read back from arena memory without needing cgo in
// this _test.go file, which this Go toolchain does not allow.
const (
	sizeCInt   = 4
	sizeCUint  = 4
	sizeCSizeT = 8
)

func TestUTF8ArenaLayout(t *testing.T) {
	p := newParams()
	defer p.free()

	p.UTF8("digest", "SHA2-256")

	if len(p.list) != 1 {
		t.Fatalf("len(p.list) = %d, want 1", len(p.list))
	}
	// UTF8 evaluates p.cstr(key) before p.cstr(val) as call arguments (Go
	// evaluates them left to right), so the arena holds the key first.
	if len(p.arena) != 2 {
		t.Fatalf("len(p.arena) = %d, want 2", len(p.arena))
	}

	gotKey := readOut(p.arena[0], len("digest")+1)
	if !bytes.Equal(gotKey, append([]byte("digest"), 0)) {
		t.Fatalf("key bytes = %q, want %q", gotKey, "digest\\x00")
	}
	gotVal := readOut(p.arena[1], len("SHA2-256")+1)
	if !bytes.Equal(gotVal, append([]byte("SHA2-256"), 0)) {
		t.Fatalf("value bytes = %q, want %q", gotVal, "SHA2-256\\x00")
	}
}

func TestOctetsArenaLayout(t *testing.T) {
	p := newParams()
	defer p.free()

	want := []byte{0xde, 0xad, 0xbe, 0xef}
	p.Octets("salt", want)

	if len(p.list) != 1 {
		t.Fatalf("len(p.list) = %d, want 1", len(p.list))
	}
	if len(p.arena) != 2 {
		t.Fatalf("len(p.arena) = %d, want 2 (key, then value)", len(p.arena))
	}

	gotVal := readOut(p.arena[1], len(want))
	if !bytes.Equal(gotVal, want) {
		t.Fatalf("octet value = %x, want %x", gotVal, want)
	}
}

func TestOctetsEmptyDoesNotPanic(t *testing.T) {
	p := newParams()
	defer p.free()

	// alloc(0) is forced up to 1 byte internally so the arena never holds a
	// NULL pointer, but the declared OSSL_PARAM length must stay 0 - callers
	// (and OpenSSL) need the true length, not the padded allocation size.
	p.Octets("empty", nil)
	if len(p.list) != 1 {
		t.Fatalf("len(p.list) = %d, want 1", len(p.list))
	}
}

func TestIntUIntSizeTArenaContent(t *testing.T) {
	p := newParams()
	defer p.free()

	p.Int("i", -7)
	p.UInt("u", 42)
	p.SizeT("s", 1<<20)

	if len(p.list) != 3 {
		t.Fatalf("len(p.list) = %d, want 3", len(p.list))
	}
	if len(p.arena) != 6 {
		t.Fatalf("len(p.arena) = %d, want 6", len(p.arena))
	}

	// Unlike UTF8/Octets, Int/UInt/SizeT allocate the *value* buffer in a
	// statement that runs before p.cstr(key) is evaluated as a call
	// argument, so each pair in the arena is (value, key) rather than
	// (key, value).
	iBytes := readOut(p.arena[0], sizeCInt)
	if got := int32(binary.NativeEndian.Uint32(iBytes)); got != -7 {
		t.Fatalf("Int value = %d, want -7", got)
	}

	uBytes := readOut(p.arena[2], sizeCUint)
	if got := binary.NativeEndian.Uint32(uBytes); got != 42 {
		t.Fatalf("UInt value = %d, want 42", got)
	}

	sBytes := readOut(p.arena[4], sizeCSizeT)
	if got := binary.NativeEndian.Uint64(sBytes); got != 1<<20 {
		t.Fatalf("SizeT value = %d, want %d", got, 1<<20)
	}
}

func TestOctetsOutAndReadOut(t *testing.T) {
	p := newParams()
	defer p.free()

	buf := p.OctetsOut("tag", 16)
	if len(p.list) != 1 {
		t.Fatalf("len(p.list) = %d, want 1", len(p.list))
	}

	// Simulate what an OpenSSL *_CTX_get_params call would do: write
	// directly into the arena buffer OctetsOut handed back.
	view := unsafe.Slice((*byte)(buf), 16)
	copy(view, []byte("0123456789abcdef"))

	got := readOut(buf, 16)
	if !bytes.Equal(got, []byte("0123456789abcdef")) {
		t.Fatalf("readOut = %q, want %q", got, "0123456789abcdef")
	}

	// readOut must hand back an independent copy, not a view: mutating the
	// arena buffer afterward must not retroactively change what was already
	// read out.
	view[0] = 'X'
	if got[0] == 'X' {
		t.Fatal("readOut aliases C memory; it must return an independent copy")
	}
}

func TestCTerminatesArrayExactlyOnce(t *testing.T) {
	p := newParams()
	defer p.free()

	p.UTF8("a", "1").UTF8("b", "2")
	if len(p.list) != 2 {
		t.Fatalf("len(p.list) before c() = %d, want 2", len(p.list))
	}

	p.c()
	afterFirst := len(p.list)
	if afterFirst != 3 {
		t.Fatalf("len(p.list) after first c() = %d, want 3 (2 real + 1 terminator)", afterFirst)
	}

	p.c()
	afterSecond := len(p.list)
	if afterSecond != afterFirst {
		t.Fatalf("len(p.list) after second c() = %d, want %d (idempotent)", afterSecond, afterFirst)
	}
}

func TestFreeIsIdempotentAndNilsState(t *testing.T) {
	p := newParams()
	p.UTF8("digest", "SHA2-256").Octets("salt", []byte{1, 2, 3})
	p.c()

	p.free()
	if p.arena != nil {
		t.Fatal("arena not nil after free")
	}
	if p.list != nil {
		t.Fatal("list not nil after free")
	}

	// Calling free again must not panic (double free of already-freed C
	// memory would be exactly the bug this guards against).
	p.free()
}
