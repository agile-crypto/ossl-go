package ossl

import (
	"bytes"
	"strings"
	"testing"
)

func TestPKCS8RoundTrip(t *testing.T) {
	for _, alg := range []string{"RSA", "EC", "ED25519", "ML-KEM-768", "ML-DSA-65"} {
		t.Run(alg, func(t *testing.T) {
			var opts []KeyOption
			if alg == "EC" {
				opts = []KeyOption{WithGroup("P-256")}
			}
			k, err := Default.GenerateKey(alg, opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()

			der, err := k.MarshalPKCS8()
			if err != nil {
				t.Fatalf("MarshalPKCS8: %v", err)
			}
			k2, err := Default.ParsePKCS8PrivateKey(der)
			if err != nil {
				t.Fatalf("ParsePKCS8PrivateKey: %v", err)
			}
			defer k2.Close()
			if k2.Type() != alg {
				t.Fatalf("round trip Type() = %q, want %q", k2.Type(), alg)
			}

			pemBytes, err := k.MarshalPKCS8PEM()
			if err != nil {
				t.Fatalf("MarshalPKCS8PEM: %v", err)
			}
			if !strings.HasPrefix(string(pemBytes), "-----BEGIN PRIVATE KEY-----") {
				t.Fatalf("PEM output missing expected header: %q", pemBytes[:40])
			}
			k3, err := Default.ParsePKCS8PrivateKeyPEM(pemBytes)
			if err != nil {
				t.Fatalf("ParsePKCS8PrivateKeyPEM: %v", err)
			}
			defer k3.Close()
			if k3.Type() != alg {
				t.Fatalf("PEM round trip Type() = %q, want %q", k3.Type(), alg)
			}
		})
	}
}

func TestSEC1RoundTrip(t *testing.T) {
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	der, err := k.MarshalSEC1()
	if err != nil {
		t.Fatalf("MarshalSEC1: %v", err)
	}
	k2, err := Default.ParseSEC1PrivateKey(der)
	if err != nil {
		t.Fatalf("ParseSEC1PrivateKey: %v", err)
	}
	defer k2.Close()
	if k2.Type() != "EC" {
		t.Fatalf("Type() = %q, want EC", k2.Type())
	}

	pemBytes, err := k.MarshalSEC1PEM()
	if err != nil {
		t.Fatalf("MarshalSEC1PEM: %v", err)
	}
	if !strings.HasPrefix(string(pemBytes), "-----BEGIN EC PRIVATE KEY-----") {
		t.Fatalf("PEM output missing expected SEC1 header: %q", pemBytes[:min(40, len(pemBytes))])
	}
	k3, err := Default.ParseSEC1PrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParseSEC1PrivateKeyPEM: %v", err)
	}
	defer k3.Close()
}

func TestSEC1RejectsNonECKey(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	if _, err := k.MarshalSEC1(); err == nil {
		t.Fatal("MarshalSEC1 on an RSA key succeeded")
	}
}

// TestParseSEC1PrivateKeyRejectsRSA pins the actual boundary OpenSSL
// enforces on the parse side: OSSL_DECODER's "structure" hint is advisory
// (the man page documents that decoders may disregard it and auto-detect
// the real structure), so ParseSEC1PrivateKey does not reject a PKCS#8 EC
// key the way its name might suggest. What it does reject is the algorithm
// mismatch, via the "EC" keytype hint -- an RSA key in any encoding fails.
func TestParseSEC1PrivateKeyRejectsRSA(t *testing.T) {
	k, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	der, err := k.MarshalPKCS8()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Default.ParseSEC1PrivateKey(der); err == nil {
		t.Fatal("ParseSEC1PrivateKey accepted an RSA key")
	}
}

func TestSPKIRoundTrip(t *testing.T) {
	for _, alg := range []string{"RSA", "EC", "ED25519", "ML-KEM-768", "ML-DSA-65"} {
		t.Run(alg, func(t *testing.T) {
			var opts []KeyOption
			if alg == "EC" {
				opts = []KeyOption{WithGroup("P-256")}
			}
			k, err := Default.GenerateKey(alg, opts...)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()

			der, err := k.MarshalSPKI()
			if err != nil {
				t.Fatalf("MarshalSPKI: %v", err)
			}
			pub, err := Default.ParseSPKIPublicKey(der)
			if err != nil {
				t.Fatalf("ParseSPKIPublicKey: %v", err)
			}
			defer pub.Close()
			if pub.Type() != alg {
				t.Fatalf("Type() = %q, want %q", pub.Type(), alg)
			}

			pemBytes, err := k.MarshalSPKIPEM()
			if err != nil {
				t.Fatalf("MarshalSPKIPEM: %v", err)
			}
			if !strings.HasPrefix(string(pemBytes), "-----BEGIN PUBLIC KEY-----") {
				t.Fatalf("PEM output missing expected header: %q", pemBytes[:40])
			}
			pub2, err := Default.ParseSPKIPublicKeyPEM(pemBytes)
			if err != nil {
				t.Fatalf("ParseSPKIPublicKeyPEM: %v", err)
			}
			defer pub2.Close()
		})
	}
}

func TestSPKIRejectsPKCS8Input(t *testing.T) {
	k, err := Default.GenerateKey("ED25519")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	der, err := k.MarshalPKCS8()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Default.ParseSPKIPublicKey(der); err == nil {
		t.Fatal("ParseSPKIPublicKey accepted a PKCS#8 private key blob")
	}
}

func TestRawKeyRoundTrip(t *testing.T) {
	for _, alg := range []string{"X25519", "ED25519", "ML-KEM-768", "ML-DSA-65"} {
		t.Run(alg, func(t *testing.T) {
			k, err := Default.GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			defer k.Close()

			rawPriv, err := k.MarshalRawPrivateKey()
			if err != nil {
				t.Fatalf("MarshalRawPrivateKey: %v", err)
			}
			if len(rawPriv) == 0 {
				t.Fatal("MarshalRawPrivateKey returned no bytes")
			}
			k2, err := Default.ParseRawPrivateKey(alg, rawPriv)
			if err != nil {
				t.Fatalf("ParseRawPrivateKey: %v", err)
			}
			defer k2.Close()
			rawPriv2, err := k2.MarshalRawPrivateKey()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(rawPriv, rawPriv2) {
				t.Fatal("raw private key round trip changed the key material")
			}

			rawPub, err := k.MarshalRawPublicKey()
			if err != nil {
				t.Fatalf("MarshalRawPublicKey: %v", err)
			}
			pub, err := Default.ParseRawPublicKey(alg, rawPub)
			if err != nil {
				t.Fatalf("ParseRawPublicKey: %v", err)
			}
			defer pub.Close()
			rawPub2, err := pub.MarshalRawPublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(rawPub, rawPub2) {
				t.Fatal("raw public key round trip changed the key material")
			}
		})
	}
}

func TestRawKeyUnsupportedForRSAAndEC(t *testing.T) {
	rsa, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer rsa.Close()
	if _, err := rsa.MarshalRawPrivateKey(); err == nil {
		t.Fatal("MarshalRawPrivateKey on RSA succeeded")
	}

	ec, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer ec.Close()
	if _, err := ec.MarshalRawPublicKey(); err == nil {
		t.Fatal("MarshalRawPublicKey on EC succeeded")
	}
}

func TestKeyPublic(t *testing.T) {
	k, err := Default.GenerateKey("ML-DSA-65")
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	pub, err := k.Public()
	if err != nil {
		t.Fatalf("Public: %v", err)
	}
	defer pub.Close()

	if pub.Type() != "ML-DSA-65" {
		t.Fatalf("Type() = %q, want ML-DSA-65", pub.Type())
	}

	wantSPKI, err := k.MarshalSPKI()
	if err != nil {
		t.Fatal(err)
	}
	gotSPKI, err := pub.MarshalSPKI()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wantSPKI, gotSPKI) {
		t.Fatal("Public() key does not re-encode to the same SPKI bytes")
	}
}

func TestParsePKCS8PrivateKeyRejectsGarbage(t *testing.T) {
	if _, err := Default.ParsePKCS8PrivateKey([]byte("not a key")); err == nil {
		t.Fatal("ParsePKCS8PrivateKey accepted garbage input")
	}
}

func TestParsePKCS8PrivateKeyRejectsEmpty(t *testing.T) {
	if _, err := Default.ParsePKCS8PrivateKey(nil); err == nil {
		t.Fatal("ParsePKCS8PrivateKey accepted empty input")
	}
}
