//go:build cgo

package ossl

import (
	"fmt"
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	t.Logf("runtime: %s", Version())
	t.Logf("build:   %s", BuildVersion())
	if err := CheckVersion(); err != nil {
		t.Fatal(err)
	}
}

func TestAtLeast(t *testing.T) {
	if !AtLeast(3, 0) {
		t.Fatalf("AtLeast(3, 0) = false, runtime is %s", Version())
	}
	if AtLeast(99, 0) {
		t.Fatalf("AtLeast(99, 0) = true, runtime is %s", Version())
	}
}

func TestVersionNumber(t *testing.T) {
	// The top byte of the packed version number is the major version; check
	// it agrees with the major version embedded in Version()'s string form,
	// which exercises the two independently rather than one via the other.
	n := VersionNumber()
	major := (n >> 28) & 0xff
	if major < 3 {
		t.Fatalf("VersionNumber() major = %d, want >= 3 (Version() = %s)", major, Version())
	}
	if !strings.HasPrefix(Version(), fmt.Sprintf("%d.", major)) {
		t.Fatalf("VersionNumber() major = %d does not match Version() = %s", major, Version())
	}
}
