package ossl

/*
#cgo pkg-config: libcrypto
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
*/
import "C"

import (
	"fmt"
	"strings"
)

// Version reports the libcrypto version actually linked at runtime.
// Compare it against BuildVersion: a mismatch means the headers this package
// was compiled against and the shared object loaded at runtime are different
// releases, which is the root cause of a large share of confusing OpenSSL
// failures.
func Version() string {
	return C.GoString(C.OpenSSL_version(C.OPENSSL_VERSION_STRING))
}

// BuildVersion reports the version of the headers this package was compiled
// against.
func BuildVersion() string {
	return C.OPENSSL_VERSION_TEXT
}

// VersionNumber is the numeric runtime version, e.g. 0x30500020 for 3.5.2.
func VersionNumber() uint64 {
	return uint64(C.OpenSSL_version_num())
}

// AtLeast reports whether the runtime libcrypto is at least major.minor.
func AtLeast(major, minor int) bool {
	v := VersionNumber()
	return (v>>28)&0xff > uint64(major) ||
		((v>>28)&0xff == uint64(major) && (v>>20)&0xff >= uint64(minor))
}

// CheckVersion reports an error if the libcrypto loaded at runtime is not the
// one this package was compiled against.
//
// Call it at startup, and assert it in a test. A header/library mismatch does
// not fail loudly on its own: the program links, runs, and simply lacks
// whatever the older library lacks. Algorithms added in newer releases fetch
// as "unsupported", version gates silently take the wrong branch, and tests
// gated on a version skip themselves. It is worth one line to rule out.
func CheckVersion() error {
	rt, bt := Version(), BuildVersion()
	// BuildVersion is "OpenSSL 3.5.2 5 Aug 2025"; Version is "3.5.2".
	if !strings.Contains(bt, rt) {
		return fmt.Errorf(
			"ossl: libcrypto mismatch: compiled against %q, loaded %q "+
				"(set LD_LIBRARY_PATH or link with -Wl,-rpath)", bt, rt)
	}
	return nil
}
