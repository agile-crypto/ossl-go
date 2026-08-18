//go:build cgo

package ossl

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fipsConfig writes a self-contained OpenSSL config that activates the FIPS
// provider, and returns its path. It includes the installation's own
// fipsmodule.cnf, which is where the module MAC lives; without that include
// the provider refuses to load at all.
//
// The config is written per-test into a temporary directory and reaches
// OpenSSL only through a private OSSL_LIB_CTX, so it cannot disturb the
// system-wide openssl.cnf or any other process using this installation.
func fipsConfig(t *testing.T) string {
	t.Helper()
	moduleCnf := DefaultFIPSModuleConfig()
	if _, err := os.Stat(moduleCnf); err != nil {
		t.Skipf("no FIPS module config at %s; run `openssl fipsinstall` to enable these tests", moduleCnf)
	}
	if _, err := os.Stat(filepath.Join(ModulesDir(), "fips.so")); err != nil {
		t.Skipf("no fips.so in %s", ModulesDir())
	}

	body := "openssl_conf = openssl_init\n" +
		".include " + moduleCnf + "\n\n" +
		"[openssl_init]\nproviders = provider_sect\n\n" +
		"[provider_sect]\nfips = fips_sect\ndefault = default_sect\n\n" +
		"[default_sect]\nactivate = 1\n"

	path := filepath.Join(t.TempDir(), "fips.cnf")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenSSLDirectories(t *testing.T) {
	if ConfigDir() == "" {
		t.Error("ConfigDir() is empty")
	}
	if ModulesDir() == "" {
		t.Error("ModulesDir() is empty")
	}
	if want := filepath.Join(ConfigDir(), "fipsmodule.cnf"); DefaultFIPSModuleConfig() != want {
		t.Errorf("DefaultFIPSModuleConfig() = %q, want %q", DefaultFIPSModuleConfig(), want)
	}
}

func TestNewFIPSContext(t *testing.T) {
	cfg := fipsConfig(t)
	c, err := NewFIPSContext(cfg)
	if err != nil {
		t.Fatalf("NewFIPSContext: %v", err)
	}
	defer c.Close()

	if !c.FIPSEnabled() {
		t.Fatal("FIPSEnabled() is false on a context built by NewFIPSContext")
	}
	if !c.ProviderAvailable("fips") {
		t.Fatal("the fips provider is not available in the context that loaded it")
	}
}

// The point of a FIPS context is what it refuses. An approved algorithm must
// resolve and a non-approved one must not -- if both work, the context is
// quietly falling through to the default provider and the whole exercise is
// decorative.
func TestFIPSContextRestrictsAlgorithms(t *testing.T) {
	cfg := fipsConfig(t)
	c, err := NewFIPSContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, name := range []DigestName{"SHA2-256", "SHA2-512", "SHA3-256"} {
		if !c.DigestAvailable(name, "") {
			t.Errorf("%s should be available in a FIPS context", name)
		}
	}
	// MD5 is not an approved algorithm and must not resolve.
	if c.DigestAvailable("MD5", "") {
		t.Error("MD5 resolved in a FIPS context; the restriction is not in effect")
	}

	if !c.CipherAvailable("AES-256-GCM", "") {
		t.Error("AES-256-GCM should be available in a FIPS context")
	}
	// ChaCha20-Poly1305 is not a NIST algorithm.
	if c.CipherAvailable("ChaCha20-Poly1305", "") {
		t.Error("ChaCha20-Poly1305 resolved in a FIPS context")
	}

	// A plain context must still allow everything, or the test above proves
	// nothing about FIPS and only that these names are unavailable generally.
	if !Default.DigestAvailable("MD5", "") {
		t.Error("MD5 is unavailable even in the default context; the FIPS check above is vacuous")
	}
	if !Default.CipherAvailable("ChaCha20-Poly1305", "") {
		t.Error("ChaCha20-Poly1305 is unavailable even by default; the FIPS check above is vacuous")
	}
}

// Real operations, not just fetch probes, must work through the validated
// module.
func TestFIPSContextPerformsOperations(t *testing.T) {
	cfg := fipsConfig(t)
	c, err := NewFIPSContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	h, err := c.NewHash("SHA2-256")
	if err != nil {
		t.Fatalf("NewHash in a FIPS context: %v", err)
	}
	h.Write([]byte("abc"))
	sum := h.Sum(nil)
	h.Close()
	if err := h.Err(); err != nil {
		t.Fatal(err)
	}
	// Same well-known value as the non-FIPS path: the validated module is a
	// different implementation, not a different algorithm.
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := hexString(sum); got != want {
		t.Fatalf("SHA2-256(abc) = %s, want %s", got, want)
	}

	k, err := c.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatalf("GenerateKey in a FIPS context: %v", err)
	}
	defer k.Close()
	msg := []byte("signed under the validated module")
	sig, err := k.Sign(msg, nil)
	if err != nil {
		t.Fatalf("Sign in a FIPS context: %v", err)
	}
	if err := k.Verify(msg, sig, nil); err != nil {
		t.Fatalf("Verify in a FIPS context: %v", err)
	}
}

// Loading a config that includes fipsmodule.cnf brings the provider up by
// itself. This is worth pinning because the opposite is easy to assume, and
// because it is the reason EnableFIPS can load the provider afterwards
// safely -- by then the config is already in scope.
func TestFIPSConfigAloneActivatesProvider(t *testing.T) {
	cfg := fipsConfig(t)
	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if c.ProviderAvailable("fips") {
		t.Fatal("the fips provider is available before any config was loaded")
	}
	if err := c.LoadConfig(cfg); err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !c.ProviderAvailable("fips") {
		t.Fatal("the fips provider is not available after loading a config that activates it")
	}
	// Active, but not yet restricting: that is EnableFIPS's job.
	if c.FIPSEnabled() {
		t.Error("FIPSEnabled() is true after LoadConfig alone; activation is not restriction")
	}
	if !c.DigestAvailable("MD5", "") {
		t.Error("MD5 is already blocked after LoadConfig alone")
	}
}

// A FIPS provider load that fails self-test poisons the FIPS module for the
// whole process, not just the context that attempted it. This runs in a
// subprocess precisely because the damage is unrecoverable: doing it in the
// test process would break every other FIPS test that ran afterwards.
func TestFIPSBareLoadPoisonsTheProcess(t *testing.T) {
	cfg := fipsConfig(t)

	if os.Getenv("OSSL_FIPS_POISON_CHILD") == "1" {
		child, err := NewContext()
		if err != nil {
			t.Fatal(err)
		}
		defer child.Close()
		// No config in scope: this is the mistake being demonstrated.
		if _, err := child.LoadProvider("fips"); err == nil {
			t.Log("RESULT: bare-load-succeeded")
			return
		}
		// Now do it correctly, in a brand new context.
		fresh, err := NewContext()
		if err != nil {
			t.Fatal(err)
		}
		defer fresh.Close()
		if err := fresh.LoadConfig(os.Getenv("OSSL_FIPS_POISON_CFG")); err != nil {
			t.Fatalf("LoadConfig in the child: %v", err)
		}
		if fresh.ProviderAvailable("fips") {
			t.Log("RESULT: recovered")
		} else {
			t.Log("RESULT: poisoned")
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestFIPSBareLoadPoisonsTheProcess", "-test.v")
	cmd.Env = append(os.Environ(),
		"OSSL_FIPS_POISON_CHILD=1",
		"OSSL_FIPS_POISON_CFG="+cfg,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	got := string(out)
	switch {
	case strings.Contains(got, "RESULT: poisoned"):
		// The documented behaviour, and the reason EnableFIPS exists.
	case strings.Contains(got, "RESULT: recovered"):
		t.Error("a failed bare FIPS load no longer poisons the process; " +
			"the warnings on EnableFIPS and LoadProvider should be revisited")
	case strings.Contains(got, "RESULT: bare-load-succeeded"):
		t.Skip("this build activates the fips provider without a config; nothing to poison")
	default:
		t.Fatalf("subprocess produced no RESULT marker:\n%s", got)
	}
}

func TestEnableFIPSRejectsDefaultContext(t *testing.T) {
	if err := Default.EnableFIPS(DefaultFIPSModuleConfig()); err == nil {
		t.Fatal("EnableFIPS on the global default context succeeded; " +
			"it would have made a process-wide change from a per-context API")
	}
}

func TestLoadConfigRejectsMissingFile(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.LoadConfig(filepath.Join(t.TempDir(), "nope.cnf")); err == nil {
		t.Fatal("LoadConfig accepted a nonexistent file")
	}
}

func TestFIPSContextCloseIsIdempotent(t *testing.T) {
	cfg := fipsConfig(t)
	c, err := NewFIPSContext(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestProviderSelfTest(t *testing.T) {
	cfg := fipsConfig(t)
	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.LoadConfig(cfg); err != nil {
		t.Fatal(err)
	}
	p, err := c.LoadProvider("fips")
	if err != nil {
		t.Fatalf("LoadProvider(fips): %v", err)
	}
	defer p.Unload()

	if err := p.SelfTest(); err != nil {
		t.Fatalf("SelfTest: %v", err)
	}
	p.Unload()
	if err := p.SelfTest(); err == nil {
		t.Fatal("SelfTest on an unloaded provider succeeded")
	}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// The example ExampleNewFIPSContext_alongsideDefault cannot carry an Output
// comment, because it needs an installed module. This asserts the claims it
// makes, so the pattern it shows is checked rather than merely compiled.
func TestDualProviderRouting(t *testing.T) {
	cfg := fipsConfig(t)
	strict, err := NewFIPSContext(cfg)
	if err != nil {
		t.Fatalf("NewFIPSContext: %v", err)
	}
	defer strict.Close()
	general := Default

	// Both contexts are live at once, and each answers for itself.
	if !strict.FIPSEnabled() {
		t.Fatal("the restricted context is not FIPS-enabled")
	}
	if general.FIPSEnabled() {
		t.Fatal("the default context became FIPS-enabled; the restriction leaked")
	}

	route := func(capability Capability) *Context {
		if err := strict.Supports(capability); err == nil {
			return strict
		}
		if err := general.Supports(capability); err == nil {
			return general
		}
		return nil
	}

	for _, tc := range []struct {
		name string
		cap  Capability
		want *Context
	}{
		{"ECDSA P-256/SHA2-256", SignatureCapability{Key: EC, Curve: P256, Digest: SHA256}, strict},
		{"ML-DSA-65", SignatureCapability{Key: MLDSA65}, strict},
		{"AES-256-GCM", AEADCapability{Cipher: AES256GCM}, strict},
		// Built into libcrypto but not offered by the module, so these must
		// route to the unrestricted context rather than be claimed by FIPS.
		{"ECDSA secp256k1", SignatureCapability{Key: EC, Curve: Secp256k1, Digest: SHA256}, general},
		{"ChaCha20-Poly1305", AEADCapability{Cipher: ChaCha20Poly1305}, general},
	} {
		got := route(tc.cap)
		if got != tc.want {
			gotName, wantName := "default", "default"
			if got == strict {
				gotName = "fips"
			} else if got == nil {
				gotName = "unsupported"
			}
			if tc.want == strict {
				wantName = "fips"
			}
			t.Errorf("%s routed to %s, want %s", tc.name, gotName, wantName)
			continue
		}
		// Routing is only worth anything if the chosen context can really
		// do the work.
		if err := got.VerifyCapability(tc.cap); err != nil {
			t.Errorf("%s routed to a context that then failed: %v", tc.name, err)
		}
	}

	// A signature made under the validated module verifies outside it: the
	// output is an ordinary ECDSA signature, not a FIPS-flavoured one.
	key, err := strict.GenerateKey(EC, WithGroup(P256))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	msg := []byte("compliance-scoped request")
	sig, err := key.Sign(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := key.MarshalSPKI()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := general.ParseSPKIPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Close()
	if err := pub.Verify(msg, sig, nil); err != nil {
		t.Errorf("a FIPS-produced signature did not verify in the default context: %v", err)
	}

	// And the restriction still bites, which is the point of the split.
	if _, err := strict.NewAEAD(ChaCha20Poly1305, make([]byte, 32)); err == nil {
		t.Error("the FIPS context produced a ChaCha20-Poly1305 AEAD")
	}
	if _, err := general.NewAEAD(ChaCha20Poly1305, make([]byte, 32)); err != nil {
		t.Errorf("the default context refused ChaCha20-Poly1305, making the check above vacuous: %v", err)
	}
}
