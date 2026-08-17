//go:build cgo

package ossl_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/agile-crypto/ossl-go/ossl"
)

// These are compiled and run by `go test`, and their output is checked
// against the Output comment, so they cannot drift away from the API the way
// a README snippet can.

func ExampleDigest() {
	sum, err := ossl.Digest("SHA2-256", []byte("abc"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", sum)
	// Output:
	// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
}

// An extendable-output function has no natural fixed length, so it is
// finalised with an explicit size rather than through Sum.
func ExampleDigestXOF() {
	out, err := ossl.DigestXOF("SHAKE-256", []byte("abc"), 16)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%x\n", out)

	// Asking for a fixed-length digest of an XOF is refused rather than
	// answered at some arbitrary default length.
	if _, err := ossl.Digest("SHAKE-256", []byte("abc")); err != nil {
		fmt.Println("Digest on an XOF:", strings.Contains(err.Error(), "SumXOF"))
	}
	// Output:
	// 483366601360a8771c6863080cc4114d
	// Digest on an XOF: true
}

// AEAD satisfies crypto/cipher.AEAD, so it drops into code written against
// the standard library.
func ExampleContext_NewAEAD() {
	key := bytes.Repeat([]byte{0x01}, 32)
	aead, err := ossl.Default.NewAEAD("AES-256-GCM", key)
	if err != nil {
		log.Fatal(err)
	}
	defer aead.Close()

	// A nonce must never repeat under one key. A counter is the usual
	// answer; a fixed value is used here only to keep the output stable.
	nonce := make([]byte, aead.NonceSize())
	ct := aead.Seal(nil, nonce, []byte("attack at dawn"), []byte("header"))

	pt, err := aead.Open(nil, nonce, ct, []byte("header"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", pt)

	// Authentication is not optional: altering the associated data is
	// detected, and reported as ErrVerification rather than as a library
	// fault.
	_, err = aead.Open(nil, nonce, ct, []byte("tampered"))
	fmt.Println("tampered AAD:", errors.Is(err, ossl.ErrVerification))
	// Output:
	// attack at dawn
	// tampered AAD: true
}

// The same code signs with a classical or a post-quantum key; only the
// algorithm name changes.
func ExampleKey_Sign() {
	for _, alg := range []string{"ED25519", "ML-DSA-65"} {
		key, err := ossl.Default.GenerateKey(alg)
		if err != nil {
			log.Fatal(err)
		}
		msg := []byte("message")
		sig, err := key.Sign(msg, nil) // nil options: per-algorithm defaults
		if err != nil {
			log.Fatal(err)
		}
		err = key.Verify(msg, sig, nil)
		fmt.Printf("%-10s verified=%v\n", alg, err == nil)

		err = key.Verify([]byte("other"), sig, nil)
		fmt.Printf("%-10s wrong message rejected=%v\n", alg, errors.Is(err, ossl.ErrVerification))
		key.Close()
	}
	// Output:
	// ED25519    verified=true
	// ED25519    wrong message rejected=true
	// ML-DSA-65  verified=true
	// ML-DSA-65  wrong message rejected=true
}

// A domain-separation context makes two signatures over the same bytes
// unusable in each other's place.
func ExampleSignOptions_context() {
	key, err := ossl.Default.GenerateKey("ML-DSA-65")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	msg := []byte("transfer 100")
	sig, err := key.Sign(msg, &ossl.SignOptions{Context: []byte("payments-v1")})
	if err != nil {
		log.Fatal(err)
	}

	err = key.Verify(msg, sig, &ossl.SignOptions{Context: []byte("payments-v1")})
	fmt.Println("same context:", err == nil)
	err = key.Verify(msg, sig, &ossl.SignOptions{Context: []byte("refunds-v1")})
	fmt.Println("other context:", errors.Is(err, ossl.ErrVerification))

	// An algorithm with no notion of a context refuses the option instead of
	// ignoring it, so a caller cannot believe they have domain separation
	// they do not have.
	rsa, err := ossl.Default.GenerateKey("RSA")
	if err != nil {
		log.Fatal(err)
	}
	defer rsa.Close()
	_, err = rsa.Sign(msg, &ossl.SignOptions{Context: []byte("payments-v1")})
	fmt.Println("context on RSA rejected:", err != nil)
	// Output:
	// same context: true
	// other context: true
	// context on RSA rejected: true
}

// Signer streams, for data too large to hold at once.
func ExampleNewSigner() {
	key, err := ossl.Default.GenerateKey("EC", ossl.WithGroup("P-256"))
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	signer, err := ossl.NewSigner(key, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer signer.Close()

	if _, err := io.Copy(signer, strings.NewReader("a large document")); err != nil {
		log.Fatal(err)
	}
	sig, err := signer.Sign()
	if err != nil {
		log.Fatal(err)
	}

	// A streamed signature is an ordinary signature: the one-shot path
	// verifies it.
	err = key.Verify([]byte("a large document"), sig, nil)
	fmt.Println("verified:", err == nil)
	// Output:
	// verified: true
}

// Hybrid post-quantum key establishment, then a key derived from the shared
// secret rather than used directly.
func ExampleKey_Encapsulate() {
	key, err := ossl.Default.GenerateKey("X25519MLKEM768")
	if err != nil {
		log.Fatal(err)
	}
	defer key.Close()

	encapsulation, secret, err := key.Encapsulate()
	if err != nil {
		log.Fatal(err)
	}
	defer ossl.Zero(secret)

	recovered, err := key.Decapsulate(encapsulation)
	if err != nil {
		log.Fatal(err)
	}
	defer ossl.Zero(recovered)
	fmt.Println("secrets agree:", bytes.Equal(secret, recovered))

	// The raw secret is not a key. Bind it to a purpose before use.
	sessionKey, err := ossl.DeriveSharedKey(secret, "demo-session-v1", 32)
	if err != nil {
		log.Fatal(err)
	}
	defer ossl.Zero(sessionKey)
	fmt.Println("session key bytes:", len(sessionKey))

	// Decapsulation of a corrupted encapsulation does NOT report an error:
	// ML-KEM rejects implicitly, returning a different secret. Only a later
	// authenticated step reveals the mismatch, which is why one must exist.
	corrupted := append([]byte(nil), encapsulation...)
	corrupted[0] ^= 0xFF
	other, err := key.Decapsulate(corrupted)
	fmt.Println("corrupted encapsulation errored:", err != nil)
	fmt.Println("corrupted secret differs:", !bytes.Equal(secret, other))
	// Output:
	// secrets agree: true
	// session key bytes: 32
	// corrupted encapsulation errored: false
	// corrupted secret differs: true
}

// Diffie-Hellman agreement between two parties.
func ExampleKey_Derive() {
	alice, err := ossl.Default.GenerateKey("X25519")
	if err != nil {
		log.Fatal(err)
	}
	defer alice.Close()
	bob, err := ossl.Default.GenerateKey("X25519")
	if err != nil {
		log.Fatal(err)
	}
	defer bob.Close()

	alicePub, err := alice.Public()
	if err != nil {
		log.Fatal(err)
	}
	defer alicePub.Close()
	bobPub, err := bob.Public()
	if err != nil {
		log.Fatal(err)
	}
	defer bobPub.Close()

	ab, err := alice.Derive(bobPub, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ossl.Zero(ab)
	ba, err := bob.Derive(alicePub, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ossl.Zero(ba)

	fmt.Println("agreed:", bytes.Equal(ab, ba))
	// Output:
	// agreed: true
}

// An isolated Context has its own provider set and property query, so one
// part of a program cannot change what another part resolves.
func ExampleNewContext() {
	ctx, err := ossl.NewContext()
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.Close()

	// A fresh context is not empty: OpenSSL activates the default provider
	// in it, so algorithms resolve straight away.
	fmt.Println("default provider present:", ctx.ProviderAvailable("default"))
	fmt.Println("SHA2-256 available:      ", ctx.DigestAvailable("SHA2-256", ""))

	// Isolation shows up when a policy is pinned. Restricting this context
	// to the FIPS provider makes non-approved algorithms stop resolving
	// here, while the global default context is untouched.
	if err := ctx.SetDefaultProperties("provider=fips"); err != nil {
		log.Fatal(err)
	}
	fmt.Println("MD5 in this context:     ", ctx.DigestAvailable("MD5", ""))
	fmt.Println("MD5 in the default one:  ", ossl.Default.DigestAvailable("MD5", ""))
	// Output:
	// default provider present: true
	// SHA2-256 available:       true
	// MD5 in this context:      false
	// MD5 in the default one:   true
}
