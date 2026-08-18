# ossl-go

A Go binding for OpenSSL 3.5 libcrypto, covering classical and post-quantum
algorithms behind one API.

All cgo and `unsafe` usage is confined to `package ossl`. Callers see ordinary
Go types, and the types satisfy the standard-library interfaces where they
can: `Hash` and `MAC` are `hash.Hash`, `AEAD` is `crypto/cipher.AEAD`,
`Signer` and `Verifier` are `io.Writer`.

## Requirements

- OpenSSL **3.5 or newer** — ML-KEM, ML-DSA and SLH-DSA do not exist before it
- Go 1.25+, cgo enabled (a `CGO_ENABLED=0` build compiles but every operation
  returns `ErrUnavailable`)

```sh
export PKG_CONFIG_PATH=/opt/openssl3.5.2/lib64/pkgconfig
export CGO_LDFLAGS=-Wl,-rpath,/opt/openssl3.5.2/lib64
```

The rpath matters. Without it the program can link against 3.5 headers and
load an older `libcrypto` at runtime, which does not fail loudly: algorithms
simply fetch as unsupported. `ossl.CheckVersion()` is one line at startup that
rules it out.

## What it covers

| Area | Algorithms |
|---|---|
| Digests | SHA-2, SHA-3, SHAKE (XOF), BLAKE2, SM3 |
| MACs | HMAC, CMAC, KMAC, GMAC, Poly1305, SipHash |
| KDFs | HKDF, PBKDF2, Argon2id, plus any provider KDF via `DeriveKDF` |
| AEAD | AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-OCB |
| Signatures | RSA-PSS, RSA-PKCS#1v1.5, ECDSA, Ed25519/ctx/ph, Ed448, ML-DSA, SLH-DSA |
| Encryption | RSA-OAEP |
| KEM | ML-KEM, X25519MLKEM768 and the other IETF hybrids, X25519/X448, RSASVE |
| Agreement | ECDH (incl. cofactor mode), X25519, X448 |
| Keys | PKCS#8, SEC1, SPKI, raw; PEM and DER; `file:` and `pkcs11:` URIs |
| Platform | isolated library contexts, provider loading, FIPS mode, secure heap |
| Introspection | typed algorithm names, capability checks, live enumeration |

Algorithm names are typed string constants (`ossl.SHA256`, `ossl.Ed25519`,
`ossl.AES256GCM`, ...) rather than bare strings, so valid values are
discoverable from the package. A `Context.Supports(capability)` check answers
whether a given combination of algorithm, curve, digest and format will
actually work before you rely on it — see the doc comments on `Capability`,
`SignatureCapability` and `AEADCapability` in `ossl/capability.go`.

## A first program

```go
package main

import (
	"fmt"
	"log"

	"github.com/agile-crypto/ossl-go/ossl"
)

func main() {
	if err := ossl.CheckVersion(); err != nil {
		log.Fatal(err)
	}

	// The same code signs with a classical or a post-quantum key.
	for _, alg := range []ossl.KeyAlgorithm{ossl.Ed25519, ossl.MLDSA65} {
		key, err := ossl.Default.GenerateKey(alg)
		if err != nil {
			log.Fatal(err)
		}
		defer key.Close()

		sig, err := key.Sign([]byte("message"), nil)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%-10s %5d-byte signature, verify=%v\n",
			alg, len(sig), key.Verify([]byte("message"), sig, nil) == nil)
	}
}
```

Runnable examples — AEAD, streaming signatures, KEM, ECDH, library contexts,
and running FIPS alongside the default provider — live in
`ossl/example_test.go`. Their output is checked by `go test`, so they cannot
drift from the API.

## Things worth knowing before you rely on this

Each of these was verified directly against this build rather than taken
from documentation.

- **`Decapsulate` returning `nil` does not mean the ciphertext was genuine.**
  ML-KEM rejects implicitly: a corrupted encapsulation yields a different
  pseudorandom secret and reports success. Whatever you build on top needs an
  authenticated step — an AEAD open, a MAC — or two parties will silently
  proceed with different keys.
- **Options that an algorithm cannot honour are errors, not no-ops.** A
  domain-separation `Context` on an RSA key is rejected. Dropping it silently,
  which is what a thin wrapper does, produces signatures with no domain
  separation and no indication of it.
- **A FIPS provider load that fails poisons the process.** Use
  `NewFIPSContext`; a bare `LoadProvider("fips")` without a config in scope
  puts the module into an error state that no later correct activation
  recovers from.
- **AEAD tag sizes are bounded.** An 8-bit GCM tag round-trips against itself
  perfectly well, so nothing but an explicit check catches it.
- **A fresh `Context` is not empty.** OpenSSL activates the default provider
  in it. Isolation means it has its own provider set and property query, not
  that it starts with nothing.
- **Nothing installs a GC finalizer.** A missed `Close` leaks the C allocation
  for the life of the process. Treat these types like `*os.File`.

## Building and testing

```sh
make ci            # the full gate
./scripts/ci.sh    # same, with an environment preflight first
```

The gate is `gofmt`, `go vet`, build, tests under the race detector, tests
under `cgocheck2` (the deep cgo pointer checker), the `CGO_ENABLED=0` build,
and an API-parity check that the cgo and non-cgo builds export the same
surface.

FIPS and PKCS#11 tests skip when the module or token is absent. `scripts/ci.sh`
reports which of them were skipped, because a green run without them covers
less than it appears to.

## Licence

See the repository for licence terms.
