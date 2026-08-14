//go:build cgo

package ossl

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writePEM(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadKeyFromFileURI(t *testing.T) {
	dir := t.TempDir()
	for _, alg := range []string{"RSA", "EC", "ED25519"} {
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

			privPEM, err := k.MarshalPKCS8PEM()
			if err != nil {
				t.Fatal(err)
			}
			path := writePEM(t, dir, alg+"-priv.pem", privPEM)

			loaded, err := Default.LoadKey("file:" + path)
			if err != nil {
				t.Fatalf("LoadKey(file:): %v", err)
			}
			defer loaded.Close()

			if loaded.Type() != alg {
				t.Fatalf("Type() = %q, want %q", loaded.Type(), alg)
			}
			// It is the same key, not merely a key of the same kind.
			want, err := k.MarshalSPKI()
			if err != nil {
				t.Fatal(err)
			}
			got, err := loaded.MarshalSPKI()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, got) {
				t.Fatal("loaded key is not the one that was written")
			}
			// And it is usable, not just parseable.
			msg := []byte("loaded from a URI")
			sig, err := loaded.Sign(msg, nil)
			if err != nil {
				t.Fatalf("Sign with the loaded key: %v", err)
			}
			if err := k.Verify(msg, sig, nil); err != nil {
				t.Fatalf("original key could not verify the loaded key's signature: %v", err)
			}
		})
	}
}

func TestLoadPublicKeyFromFileURI(t *testing.T) {
	dir := t.TempDir()
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()

	pubPEM, err := k.MarshalSPKIPEM()
	if err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, dir, "pub.pem", pubPEM)

	pub, err := Default.LoadPublicKey("file:" + path)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	defer pub.Close()

	msg := []byte("verified by a loaded public key")
	sig, err := k.Sign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := pub.Verify(msg, sig, nil); err != nil {
		t.Fatalf("Verify with the loaded public key: %v", err)
	}
}

// OSSL_STORE_expect narrows the search. Without it, asking for a public key
// in a file whose first object is a private key would hand back the wrong
// thing rather than nothing.
func TestLoadKeyRespectsExpectedType(t *testing.T) {
	dir := t.TempDir()
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	pubPEM, err := k.MarshalSPKIPEM()
	if err != nil {
		t.Fatal(err)
	}
	pubPath := writePEM(t, dir, "only-public.pem", pubPEM)

	// A file holding only a public key has no private key to find.
	if _, err := Default.LoadKey("file:" + pubPath); err == nil {
		t.Fatal("LoadKey found a private key in a public-key-only file")
	}
}

func TestLoadKeyErrors(t *testing.T) {
	dir := t.TempDir()

	if _, err := Default.LoadKey(""); err == nil {
		t.Error("LoadKey accepted an empty URI")
	}
	if _, err := Default.LoadKey("file:" + filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("LoadKey accepted a nonexistent file")
	}
	garbage := writePEM(t, dir, "garbage.pem", []byte("this is not a PEM file\n"))
	if _, err := Default.LoadKey("file:" + garbage); err == nil {
		t.Error("LoadKey accepted a file that is not a key")
	}
	if _, err := Default.LoadKey("nosuchscheme:whatever"); err == nil {
		t.Error("LoadKey accepted an unknown URI scheme")
	}
}

// A loaded key must belong to the context that loaded it, or later
// operations on it resolve against the wrong provider set.
func TestLoadedKeyCarriesItsContext(t *testing.T) {
	dir := t.TempDir()
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

	seed, err := c.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Close()
	pem, err := seed.MarshalPKCS8PEM()
	if err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, dir, "ctx.pem", pem)

	k, err := c.LoadKey("file:" + path)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	if k.ctx != c {
		t.Fatal("LoadKey did not record the loading Context on the Key")
	}
}

func TestListStoreOnDirectory(t *testing.T) {
	dir := t.TempDir()
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	pem, err := k.MarshalPKCS8PEM()
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, dir, "one.pem", pem)
	writePEM(t, dir, "two.pem", pem)

	objs, err := Default.ListStore("file:" + dir)
	if err != nil {
		t.Fatalf("ListStore on a directory: %v", err)
	}
	if len(objs) < 2 {
		t.Fatalf("ListStore returned %d entries, want at least 2", len(objs))
	}
	for _, o := range objs {
		if o.Name == "" {
			t.Errorf("directory entry has no name: %+v", o)
		}
	}
}

func TestListStoreOnKeyFile(t *testing.T) {
	dir := t.TempDir()
	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	pem, err := k.MarshalPKCS8PEM()
	if err != nil {
		t.Fatal(err)
	}
	path := writePEM(t, dir, "key.pem", pem)

	objs, err := Default.ListStore("file:" + path)
	if err != nil {
		t.Fatalf("ListStore: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("ListStore returned %d objects, want 1", len(objs))
	}
	if objs[0].Type != StorePrivateKey {
		t.Fatalf("object type = %v, want %v", objs[0].Type, StorePrivateKey)
	}
}

func TestStoreObjectTypeString(t *testing.T) {
	for typ, want := range map[StoreObjectType]string{
		StorePrivateKey:  "private key",
		StorePublicKey:   "public key",
		StoreCertificate: "certificate",
		StoreUnknown:     "unknown",
	} {
		if got := typ.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", typ, got, want)
		}
	}
}

// pkcs11Config writes a config activating the pkcs11 provider against a
// SoftHSM token, or skips. The provider module and the PKCS#11 driver are
// two different .so files and are easy to confuse: `module` is the OpenSSL
// provider, `pkcs11-module-path` is the token driver it talks to.
func pkcs11Config(t *testing.T) string {
	t.Helper()
	const (
		provider = "/opt/openssl-pkcs11/lib/ossl-modules/pkcs11.so"
		driver   = "/usr/local/lib/softhsm/libsofthsm2.so"
	)
	for _, p := range []string{provider, driver} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("PKCS#11 not set up on this machine: %s missing", p)
		}
	}

	body := "openssl_conf = openssl_init\n\n" +
		"[openssl_init]\nproviders = provider_sect\n\n" +
		"[provider_sect]\ndefault = default_sect\npkcs11 = pkcs11_sect\n\n" +
		"[default_sect]\nactivate = 1\n\n" +
		"[pkcs11_sect]\n" +
		"module = " + provider + "\n" +
		"pkcs11-module-path = " + driver + "\n" +
		// SoftHSM2's C_CloseSession dereferences a NULL singleton when
		// called from OpenSSL's atexit teardown, which crashes the process
		// after every real operation has already completed. Skipping module
		// de-init avoids it.
		"pkcs11-module-quirks = no-deinit\n" +
		"activate = 1\n"

	path := filepath.Join(t.TempDir(), "pkcs11.cnf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The case URI-based loading exists for: a key that has no PEM because its
// private half never leaves the token. It must sign, and must refuse to
// export.
func TestLoadKeyFromPKCS11URI(t *testing.T) {
	cfg := pkcs11Config(t)
	const (
		privURI = "pkcs11:token=citius-examples;object=citius-example-ec;type=private?pin-value=1234"
		pubURI  = "pkcs11:token=citius-examples;object=citius-example-ec;type=public"
	)

	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.LoadConfig(cfg); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !c.ProviderAvailable("pkcs11") {
		t.Skip("pkcs11 provider did not activate")
	}

	priv, err := c.LoadKey(privURI)
	if err != nil {
		t.Skipf("no provisioned token key (run provision-softhsm.sh): %v", err)
	}
	defer priv.Close()

	if priv.Type() != "EC" {
		t.Fatalf("Type() = %q, want EC", priv.Type())
	}

	// The private half is non-extractable, so serialising it must fail.
	// This is the property that distinguishes a token key from a software
	// key that merely happens to have been loaded from a URI.
	if _, err := priv.MarshalPKCS8(); err == nil {
		t.Error("MarshalPKCS8 succeeded on a non-extractable token key")
	}

	// It still signs, on the token.
	msg := []byte("signed on the token")
	sig, err := priv.Sign(msg, nil)
	if err != nil {
		t.Fatalf("Sign with the token key: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	// And the matching public half verifies it. Loading that separately is
	// also the check that the URI selected the object it was asked for.
	pub, err := c.LoadPublicKey(pubURI)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}
	defer pub.Close()
	if err := pub.Verify(msg, sig, nil); err != nil {
		t.Fatalf("token public key could not verify the token signature: %v", err)
	}

	// A tampered message must still be rejected, so the verification above
	// is not vacuous.
	if err := pub.Verify([]byte("different"), sig, nil); err == nil {
		t.Fatal("verification accepted a tampered message")
	}
}

func TestLoadKeyPKCS11WrongObject(t *testing.T) {
	cfg := pkcs11Config(t)
	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.LoadConfig(cfg); err != nil {
		t.Fatal(err)
	}
	if !c.ProviderAvailable("pkcs11") {
		t.Skip("pkcs11 provider did not activate")
	}
	uri := "pkcs11:token=citius-examples;object=no-such-object;type=private?pin-value=1234"
	if _, err := c.LoadKey(uri); err == nil {
		t.Fatal("LoadKey found a key that does not exist on the token")
	}
}
