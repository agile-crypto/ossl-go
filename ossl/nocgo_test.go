//go:build !cgo

package ossl

import (
	"errors"
	"testing"
)

// Without cgo there is nothing to test cryptographically. What must hold is
// that the package still builds, that every operation refuses rather than
// pretending, and that the refusal is identifiable with errors.Is so a
// caller can distinguish "no OpenSSL here" from a genuine crypto failure.
func TestEverythingReportsUnavailable(t *testing.T) {
	checks := map[string]error{
		"CheckVersion": CheckVersion(),
		"NewContext":   second(NewContext()),
		"NewHash":      second(Default.NewHash("SHA2-256")),
		"Digest":       second(Digest("SHA2-256", []byte("x"))),
		"DigestXOF":    second(DigestXOF("SHAKE-256", []byte("x"), 32)),
		"NewHMAC":      second(Default.NewHMAC("SHA2-256", []byte("k"))),
		"HMACSum":      second(HMACSum("SHA2-256", []byte("k"), []byte("m"))),
		"HKDF":         second(Default.HKDF("SHA2-256", []byte("s"), nil, nil, 32)),
		"PBKDF2":       second(Default.PBKDF2("SHA2-256", []byte("p"), []byte("s"), 1000, 32)),
		"NewAEAD":      second(Default.NewAEAD("AES-256-GCM", make([]byte, 32))),
		"GenerateKey":  second(Default.GenerateKey("EC")),
		"LoadKey":      second(Default.LoadKey("file:/nonexistent")),
		"ListStore":    second(Default.ListStore("file:/nonexistent")),
		"NewFIPS":      second(NewFIPSContext("/nonexistent")),
		"InitSecure":   InitSecureHeap(1<<16, 64),
		"NewSecureBuf": second(NewSecureBuffer(32)),
		"DeriveShared": second(DeriveSharedKey([]byte("s"), "ctx", 32)),
	}
	for name, err := range checks {
		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("%s returned %v, want ErrUnavailable", name, err)
		}
	}
}

// The pure-Go helpers keep working, because a caller's cleanup and
// comparison paths should not change shape with the build tag.
func TestPureGoHelpersStillWork(t *testing.T) {
	b := []byte{1, 2, 3, 4}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("Zero left byte %d = %d", i, v)
		}
	}
	if !EqualMAC([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("EqualMAC says equal slices differ")
	}
	if EqualMAC([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("EqualMAC says differing slices match")
	}
	if EqualMAC([]byte{1, 2, 3}, []byte{1, 2}) {
		t.Error("EqualMAC ignored a length difference")
	}
}

func TestSentinelsAreShared(t *testing.T) {
	// These are defined in the tag-free file, so callers can branch on them
	// in either build.
	for _, err := range []error{ErrVerification, ErrClosed, ErrUnavailable} {
		if err == nil {
			t.Fatal("a sentinel error is nil")
		}
	}
	e := &Error{Op: "test", Msgs: []string{"detail"}}
	if e.Error() == "" {
		t.Error("Error.Error() is empty")
	}
}

func second[T any](_ T, err error) error { return err }
