//go:build cgo

package ossl

import (
	"errors"
	"strings"
	"testing"
)

// The reason this API exists rather than a list of supported algorithm
// names. Every one of these has all of its parts available, and none of them
// works -- so a caller pre-validating by intersecting a parts list would
// advertise support and then fail at execution.
func TestSupportsRejectsCombinationsThatPartsWouldAccept(t *testing.T) {
	cases := []struct {
		desc string
		cap  SignatureCapability
		want string // substring of the explanation
	}{
		{
			"Ed25519 with an explicit digest",
			SignatureCapability{Key: Ed25519, Digest: SHA256},
			"hashes the message itself",
		},
		{
			"ML-DSA with an explicit digest",
			SignatureCapability{Key: MLDSA65, Digest: SHA256},
			"hashes the message itself",
		},
		{
			"ECDSA with an XOF digest",
			SignatureCapability{Key: EC, Curve: P256, Digest: SHAKE256},
			"extendable-output",
		},
		{
			"Ed448 with the P1363 format",
			SignatureCapability{Key: Ed448, Format: SignatureP1363},
			"only valid for EC keys",
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			// Every part is individually available; that is the trap.
			if !Default.KeyAlgorithmAvailable(c.cap.Key) {
				t.Fatalf("precondition: %s is unavailable, so this case proves nothing", c.cap.Key)
			}
			if c.cap.Digest != "" && !Default.DigestAvailable(c.cap.Digest, "") {
				t.Fatalf("precondition: %s is unavailable, so this case proves nothing", c.cap.Digest)
			}

			err := Default.Supports(c.cap)
			if err == nil {
				t.Fatalf("Supports accepted %s, which does not work", c.cap.describe())
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("explanation %q does not mention %q", err, c.want)
			}

			// And the structural verdict matches reality.
			if err := Default.VerifyCapability(c.cap); err == nil {
				t.Error("VerifyCapability accepted it too")
			}
		})
	}
}

// The combinations citius-server's catalogue actually contains must pass,
// both structurally and in practice -- a check that rejects everything would
// satisfy the test above while being useless.
func TestSupportsAcceptsRealTemplates(t *testing.T) {
	cases := []struct {
		desc string
		cap  SignatureCapability
	}{
		{"ecdsa-p256-sha256-der", SignatureCapability{Key: EC, Curve: P256, Digest: SHA256}},
		{"ecdsa-p384-sha384-der", SignatureCapability{Key: EC, Curve: P384, Digest: SHA384}},
		{"ecdsa-p256-sha256-p1363", SignatureCapability{Key: EC, Curve: P256, Digest: SHA256, Format: SignatureP1363}},
		{"ecdsa-p256-deterministic", SignatureCapability{Key: EC, Curve: P256, Digest: SHA256, Deterministic: true}},
		{"ed25519", SignatureCapability{Key: Ed25519}},
		{"ed25519ctx", SignatureCapability{Key: Ed25519, Context: true}},
		{"ed25519ph", SignatureCapability{Key: Ed25519, Prehash: true}},
		{"ed448", SignatureCapability{Key: Ed448}},
		{"ml-dsa-44", SignatureCapability{Key: MLDSA44}},
		{"ml-dsa-65", SignatureCapability{Key: MLDSA65}},
		{"ml-dsa-65-ctx", SignatureCapability{Key: MLDSA65, Context: true}},
		{"ml-dsa-87-deterministic", SignatureCapability{Key: MLDSA87, Deterministic: true}},
		{"slh-dsa-sha2-128s", SignatureCapability{Key: SLHDSASHA2128s}},
		{"rsa-pss-sha256", SignatureCapability{Key: RSA, Digest: SHA256}},
		{"rsa-pss-sha512", SignatureCapability{Key: RSA, Digest: SHA512}},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			if err := Default.Supports(c.cap); err != nil {
				t.Fatalf("Supports rejected a real template: %v", err)
			}
		})
	}
}

// The structural verdict has to agree with what actually happens, or it is
// just a differently-shaped guess. This runs the real operation for the
// cheap algorithms.
func TestStructuralVerdictMatchesReality(t *testing.T) {
	if testing.Short() {
		t.Skip("capability trials skipped in short mode")
	}
	caps := []SignatureCapability{
		{Key: EC, Curve: P256, Digest: SHA256},
		{Key: EC, Curve: P384, Digest: SHA384},
		{Key: EC, Curve: P256, Digest: SHA256, Format: SignatureP1363},
		{Key: EC, Curve: P256, Digest: SHA256, Deterministic: true},
		{Key: Ed25519},
		{Key: Ed25519, Context: true},
		{Key: Ed25519, Prehash: true},
		{Key: Ed448},
		{Key: MLDSA65},
		{Key: MLDSA65, Context: true},
		{Key: MLDSA65, Deterministic: true},
		// Rejections, to confirm agreement in both directions.
		{Key: Ed25519, Digest: SHA256},
		{Key: EC, Curve: P256, Digest: SHAKE256},
		{Key: EC, Curve: P256, Digest: SHA256, Prehash: true},
		{Key: MLDSA65, Format: SignatureP1363},
	}
	for _, c := range caps {
		structural := Default.Supports(c) == nil
		actual := c.trial(Default) == nil
		if structural != actual {
			t.Errorf("%s: Supports said %v but the real operation said %v",
				c.describe(), structural, actual)
		}
	}
}

func TestSupportsRejectsMalformedCapabilities(t *testing.T) {
	cases := map[string]SignatureCapability{
		"no key algorithm":      {},
		"EC without a curve":    {Key: EC, Digest: SHA256},
		"curve on a non-EC key": {Key: Ed25519, Curve: P256},
		"unknown key algorithm": {Key: "NOPE"},
		"unknown curve":         {Key: EC, Curve: "not-a-curve", Digest: SHA256},
		"unknown digest":        {Key: EC, Curve: P256, Digest: "NOPE"},
	}
	for desc, c := range cases {
		if err := Default.Supports(c); err == nil {
			t.Errorf("%s: accepted", desc)
		}
	}
	if err := Default.Supports(nil); err == nil {
		t.Error("Supports(nil) accepted")
	}
}

func TestAEADCapability(t *testing.T) {
	good := []AEADCapability{
		{Cipher: AES256GCM},
		{Cipher: AES128GCM},
		{Cipher: AES256GCM, IVBytes: 12, TagBytes: 16},
		{Cipher: AES256GCM, IVBytes: 8, TagBytes: 12},
		{Cipher: AES256CCM, IVBytes: 7, TagBytes: 4},
		{Cipher: AES256CCM, IVBytes: 13, TagBytes: 16},
		{Cipher: ChaCha20Poly1305},
	}
	for _, c := range good {
		if err := Default.Supports(c); err != nil {
			t.Errorf("Supports rejected %s: %v", c.describe(), err)
			continue
		}
		if err := Default.VerifyCapability(c); err != nil {
			t.Errorf("VerifyCapability rejected %s: %v", c.describe(), err)
		}
	}

	bad := []AEADCapability{
		{},                               // no cipher
		{Cipher: "NOPE"},                 // unknown
		{Cipher: AES256CBC},              // not an AEAD mode
		{Cipher: AES256GCM, TagBytes: 4}, // tag below the floor
		{Cipher: AES256CCM, IVBytes: 6},  // outside SP 800-38C
		{Cipher: AES256CCM, TagBytes: 5}, // odd CCM tag
		{Cipher: AES256GCM, IVBytes: 0, KeyBytes: 3}, // wrong key length
	}
	for _, c := range bad {
		if err := Default.Supports(c); err == nil {
			t.Errorf("Supports accepted %s", c.describe())
		}
	}
}

// A FIPS-restricted context must report a smaller capability set than an
// unrestricted one. This is the property that makes the check Context-scoped
// rather than a package-level function.
func TestCapabilityIsContextScoped(t *testing.T) {
	cfg := fipsConfig(t)
	fips, err := NewFIPSContext(cfg)
	if err != nil {
		t.Fatalf("NewFIPSContext: %v", err)
	}
	defer fips.Close()

	// Approved in both.
	approved := SignatureCapability{Key: EC, Curve: P256, Digest: SHA256}
	if err := Default.Supports(approved); err != nil {
		t.Fatalf("default context rejected ECDSA P-256: %v", err)
	}
	if err := fips.Supports(approved); err != nil {
		t.Fatalf("FIPS context rejected ECDSA P-256: %v", err)
	}

	// Not a NIST algorithm: available by default, absent under FIPS.
	chacha := AEADCapability{Cipher: ChaCha20Poly1305}
	if err := Default.Supports(chacha); err != nil {
		t.Fatalf("default context rejected ChaCha20-Poly1305: %v", err)
	}
	if err := fips.Supports(chacha); err == nil {
		t.Error("FIPS context accepted ChaCha20-Poly1305")
	}

	// And the enumeration narrows too.
	all, err := Default.ListDigests()
	if err != nil {
		t.Fatal(err)
	}
	restricted, err := fips.ListDigests()
	if err != nil {
		t.Fatal(err)
	}
	if len(restricted) >= len(all) {
		t.Errorf("FIPS context lists %d digests, default lists %d; expected fewer",
			len(restricted), len(all))
	}
}

// Whether a curve is usable is a property of the context, not of libcrypto.
// The built-in curve table lists secp256k1 and the Brainpool curves because
// the library was compiled with them, while the FIPS provider offers only the
// NIST prime curves -- so a check that consults the table alone reports a
// capability the operation then refuses.
//
// This sweeps both contexts and holds the structural verdict against the real
// operation, which is the only way to catch that class of disagreement.
func TestCurveSupportIsContextScoped(t *testing.T) {
	if testing.Short() {
		t.Skip("curve trials skipped in short mode")
	}
	cfg := fipsConfig(t)
	fips, err := NewFIPSContext(cfg)
	if err != nil {
		t.Fatalf("NewFIPSContext: %v", err)
	}
	defer fips.Close()

	curves := []Curve{P224, P256, P384, P521, Secp256k1, BrainpoolP256r1, BrainpoolP512r1}
	contexts := map[string]*Context{"default": Default, "fips": fips}

	disagreed := false
	for name, ctx := range contexts {
		for _, curve := range curves {
			cap := SignatureCapability{Key: EC, Curve: curve, Digest: SHA256}
			structural := ctx.Supports(cap) == nil
			actual := cap.trial(ctx) == nil
			if structural != actual {
				t.Errorf("%s context, %s: Supports said %v but the real operation said %v",
					name, curve, structural, actual)
			}
			if name == "fips" && (Default.Supports(cap) == nil) != structural {
				disagreed = true
			}
		}
	}
	// If the two contexts agreed on every curve the sweep proves nothing
	// about scoping, only that the curves all happen to work.
	if !disagreed {
		t.Error("no curve was accepted by one context and refused by the other; " +
			"this test is not exercising context scoping")
	}
}

// The probe runs once per question per context and is not shared between
// contexts, which is what makes it affordable to ask and correct to trust.
func TestProbeIsMemoisedPerContext(t *testing.T) {
	a, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	runs := 0
	count := func() error { runs++; return nil }

	for i := 0; i < 3; i++ {
		if err := a.probe("question", count); err != nil {
			t.Fatal(err)
		}
	}
	if runs != 1 {
		t.Errorf("probe ran %d times for one question in one context, want 1", runs)
	}

	// A second context must ask for itself: the answer depends on that
	// context's providers and property query, not on the library.
	if err := b.probe("question", count); err != nil {
		t.Fatal(err)
	}
	if runs != 2 {
		t.Errorf("probe ran %d times across two contexts, want 2", runs)
	}

	// A failure is remembered too, and reported verbatim rather than
	// flattened to a boolean.
	sentinel := errors.New("no")
	for i := 0; i < 2; i++ {
		if err := a.probe("failing", func() error { runs++; return sentinel }); !errors.Is(err, sentinel) {
			t.Errorf("probe returned %v, want the underlying error", err)
		}
	}
	if runs != 3 {
		t.Errorf("a failing probe ran %d times, want 1", runs-2)
	}
}

// Curve support must not be answered from a provider capability query.
// OSSL_PROVIDER_get_capabilities("TLS-GROUP") is the only mechanism OpenSSL
// offers and it describes TLS negotiation, not key generation: measured here,
// an unrestricted context generates keys on far more curves than it declares
// as groups. A future change that swapped the probe for that query would pass
// the FIPS tests and quietly start refusing working curves, so this pins the
// direction of the discrepancy.
func TestCurveSupportExceedsTLSGroups(t *testing.T) {
	if testing.Short() {
		t.Skip("curve sweep skipped in short mode")
	}
	curves, err := ListCurves()
	if err != nil {
		t.Fatal(err)
	}
	usable := 0
	for _, cv := range curves {
		if Default.curveUsable(cv) == nil {
			usable++
		}
	}
	// The default provider declares 28 curve TLS groups on this build.
	const tlsGroups = 28
	if usable <= tlsGroups {
		t.Errorf("only %d of %d built-in curves are usable, which no longer exceeds the %d "+
			"declared TLS groups; re-check whether a capability query would now be sound",
			usable, len(curves), tlsGroups)
	}
}

func TestEnumerationReportsRealAlgorithms(t *testing.T) {
	digests, err := Default.ListDigests()
	if err != nil {
		t.Fatal(err)
	}
	ciphers, err := Default.ListCiphers()
	if err != nil {
		t.Fatal(err)
	}
	macs, err := Default.ListMACs()
	if err != nil {
		t.Fatal(err)
	}
	kdfs, err := Default.ListKDFs()
	if err != nil {
		t.Fatal(err)
	}
	curves, err := ListCurves()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("digests=%d ciphers=%d macs=%d kdfs=%d curves=%d",
		len(digests), len(ciphers), len(macs), len(kdfs), len(curves))

	// Everything enumerated must actually resolve, or the list is misleading.
	for _, d := range digests {
		if !Default.DigestAvailable(d, "") {
			t.Errorf("ListDigests reported %q, which does not resolve", d)
		}
	}
	for _, c := range ciphers {
		if !Default.CipherAvailable(c, "") {
			t.Errorf("ListCiphers reported %q, which does not resolve", c)
		}
	}

	// And the curated constants must appear in the enumeration.
	has := func(list []DigestName, want DigestName) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}
	for _, want := range []DigestName{SHA256, SHA3_256, SHAKE256} {
		if !has(digests, want) {
			t.Errorf("ListDigests omitted the constant %q", want)
		}
	}
}

func TestParseValidators(t *testing.T) {
	if d, err := Default.ParseDigestName("SHA2-256"); err != nil || d != SHA256 {
		t.Errorf("ParseDigestName(SHA2-256) = %q, %v", d, err)
	}
	if _, err := Default.ParseDigestName("SHA-256-typo"); err == nil {
		t.Error("ParseDigestName accepted a typo")
	}
	if _, err := Default.ParseDigestName(""); err == nil {
		t.Error("ParseDigestName accepted an empty name")
	}
	if c, err := Default.ParseCipherName("AES-256-GCM"); err != nil || c != AES256GCM {
		t.Errorf("ParseCipherName = %q, %v", c, err)
	}
	if _, err := Default.ParseCipherName("AES-999-GCM"); err == nil {
		t.Error("ParseCipherName accepted a nonexistent cipher")
	}
	if a, err := Default.ParseKeyAlgorithm("ML-DSA-65"); err != nil || a != MLDSA65 {
		t.Errorf("ParseKeyAlgorithm = %q, %v", a, err)
	}
	if _, err := Default.ParseKeyAlgorithm("ML-DSA-66"); err == nil {
		t.Error("ParseKeyAlgorithm accepted a nonexistent parameter set")
	}
	if m, err := Default.ParseMACName("HMAC"); err != nil || m != HMAC {
		t.Errorf("ParseMACName = %q, %v", m, err)
	}
	if _, err := Default.ParseMACName("HMACX"); err == nil {
		t.Error("ParseMACName accepted a nonexistent MAC")
	}
	if k, err := Default.ParseKDFName("HKDF"); err != nil || k != KDFHKDF {
		t.Errorf("ParseKDFName = %q, %v", k, err)
	}
	if _, err := Default.ParseKDFName("HKDF2"); err == nil {
		t.Error("ParseKDFName accepted a nonexistent KDF")
	}
}
