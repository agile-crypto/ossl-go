//go:build cgo

package ossl

import "testing"

func TestEveryDigestConstantResolves(t *testing.T) {
	for _, d := range []DigestName{
		SHA224, SHA256, SHA384, SHA512, SHA512_224, SHA512_256,
		SHA3_224, SHA3_256, SHA3_384, SHA3_512,
		SHAKE128, SHAKE256,
		BLAKE2b512, BLAKE2s256,
		SM3, RIPEMD160, SHA1, MD5,
	} {
		if !Default.DigestAvailable(d, "") {
			t.Errorf("digest constant %q does not resolve", d)
		}
	}
}

func TestEveryCipherConstantResolves(t *testing.T) {
	aead := []CipherName{
		AES128GCM, AES192GCM, AES256GCM,
		AES128CCM, AES192CCM, AES256CCM,
		AES128OCB, AES192OCB, AES256OCB,
		ChaCha20Poly1305,
	}
	block := []CipherName{
		AES128CBC, AES192CBC, AES256CBC,
		AES128CTR, AES192CTR, AES256CTR,
		AES128OFB, AES256OFB, AES128CFB, AES256CFB,
		AES128ECB, AES256ECB,
		AES128XTS, AES256XTS,
		ChaCha20,
		Camellia128CBC, Camellia256CBC,
		ARIA128CBC, ARIA256CBC, ARIA128GCM, ARIA256GCM,
		SM4CBC, SM4GCM,
	}
	wrap := []CipherName{
		AES128Wrap, AES192Wrap, AES256Wrap,
		AES128WrapPad, AES192WrapPad, AES256WrapPad,
	}
	for _, group := range [][]CipherName{aead, block, wrap} {
		for _, c := range group {
			if !Default.CipherAvailable(c, "") {
				t.Errorf("cipher constant %q does not resolve", c)
			}
		}
	}
}

// The SEED constants are documented as needing the legacy provider. This
// pins both halves of that claim, because a constant that silently does not
// work in a default context is worse than no constant at all.
func TestLegacyCipherConstantsNeedTheLegacyProvider(t *testing.T) {
	legacyOnly := []CipherName{SEEDCBC, SEEDECB, SEEDCFB, SEEDOFB}

	for _, c := range legacyOnly {
		if Default.CipherAvailable(c, "") {
			t.Errorf("%q resolves without the legacy provider; the doc comment is wrong", c)
		}
	}

	ctx, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	defer ctx.Close()
	prov, err := ctx.LoadProvider(ProviderLegacy)
	if err != nil {
		t.Skipf("legacy provider not available here: %v", err)
	}
	defer prov.Unload()

	for _, c := range legacyOnly {
		if !ctx.CipherAvailable(c, "") {
			t.Errorf("%q does not resolve even with the legacy provider loaded", c)
		}
	}
}

func TestEveryMACConstantResolves(t *testing.T) {
	// Each MAC needs a key of a plausible size and its own parameters, so
	// resolution is checked by constructing one rather than by fetching.
	key32 := make([]byte, 32)
	key16 := make([]byte, 16)
	iv12 := make([]byte, 12)

	cases := map[MACName]func() (*MAC, error){
		HMAC: func() (*MAC, error) { return Default.NewMAC(HMAC, key32, &MACParams{Digest: SHA256}) },
		CMAC: func() (*MAC, error) {
			return Default.NewMAC(CMAC, key32, &MACParams{Cipher: AES256CBC})
		},
		GMAC:       func() (*MAC, error) { return Default.NewGMAC(AES256GCM, key32, iv12) },
		KMAC128:    func() (*MAC, error) { return Default.NewMAC(KMAC128, key32, &MACParams{Size: 32}) },
		KMAC256:    func() (*MAC, error) { return Default.NewMAC(KMAC256, key32, &MACParams{Size: 32}) },
		Poly1305:   func() (*MAC, error) { return Default.NewMAC(Poly1305, key32, nil) },
		SipHash:    func() (*MAC, error) { return Default.NewMAC(SipHash, key16, nil) },
		BLAKE2bMAC: func() (*MAC, error) { return Default.NewMAC(BLAKE2bMAC, key32, &MACParams{Size: 32}) },
		BLAKE2sMAC: func() (*MAC, error) { return Default.NewMAC(BLAKE2sMAC, key32, &MACParams{Size: 32}) },
	}
	for name, build := range cases {
		m, err := build()
		if err != nil {
			t.Errorf("MAC constant %q does not resolve: %v", name, err)
			continue
		}
		m.Close()
	}
}

func TestEveryKDFConstantResolves(t *testing.T) {
	for _, k := range []KDFName{
		KDFHKDF, KDFPBKDF2, KDFArgon2d, KDFArgon2i, KDFArgon2id, KDFScrypt,
		KDFSSKDF, KDFX963, KDFX942, KDFX942Concat, KDFKBKDF,
		KDFTLS1PRF, KDFTLS13, KDFSSH, KDFKrb5, KDFPKCS12, KDFHMACDRBG,
	} {
		// Deriving needs per-KDF parameters, so resolution is checked by
		// whether the fetch inside deriveKDF succeeds: an unknown name
		// fails with EVP_KDF_fetch, a known one gets far enough to complain
		// about missing parameters instead.
		_, err := Default.DeriveKDF(k, KDFParams{}, 32)
		if err != nil && containsFetchFailure(err.Error(), string(k)) {
			t.Errorf("KDF constant %q does not resolve: %v", k, err)
		}
	}
}

func containsFetchFailure(msg, name string) bool {
	return len(msg) >= len("EVP_KDF_fetch") &&
		(indexOf(msg, "EVP_KDF_fetch("+name+")") >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

func TestEveryKeyAlgorithmConstantResolves(t *testing.T) {
	classical := []KeyAlgorithm{RSA, RSAPSSKey, EC, Ed25519, Ed448, X25519, X448, DSA, DH}
	pqc := []KeyAlgorithm{
		MLKEM512, MLKEM768, MLKEM1024,
		MLDSA44, MLDSA65, MLDSA87,
		SLHDSASHA2128s, SLHDSASHA2128f, SLHDSASHA2192s, SLHDSASHA2192f,
		SLHDSASHA2256s, SLHDSASHA2256f,
		SLHDSASHAKE128s, SLHDSASHAKE128f, SLHDSASHAKE192s, SLHDSASHAKE192f,
		SLHDSASHAKE256s, SLHDSASHAKE256f,
	}
	hybrid := []KeyAlgorithm{X25519MLKEM768, X448MLKEM1024, SecP256r1MLKEM768, SecP384r1MLKEM1024}

	for _, group := range [][]KeyAlgorithm{classical, pqc, hybrid} {
		for _, a := range group {
			if !Default.KeyAlgorithmAvailable(a) {
				t.Errorf("key algorithm constant %q does not resolve", a)
			}
		}
	}
}

// The curve constants have to be usable for key generation, not merely
// spelled plausibly: OpenSSL accepts several aliases per curve and rejects
// others.
func TestEveryCurveConstantResolves(t *testing.T) {
	for _, c := range []Curve{
		P224, P256, P384, P521,
		Secp256k1,
		BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1,
	} {
		k, err := Default.GenerateKey(EC, WithGroup(c))
		if err != nil {
			t.Errorf("curve constant %q does not resolve: %v", c, err)
			continue
		}
		if got := k.Type(); got != "EC" {
			t.Errorf("curve %q produced a %s key", c, got)
		}
		k.Close()
	}
}

// Providers other than default are optional on a given installation, so this
// checks that the names are the ones OpenSSL uses rather than that each is
// present.
func TestProviderConstantNames(t *testing.T) {
	if !Default.ProviderAvailable(ProviderDefault) {
		t.Error("the default provider is not available under its constant name")
	}
	for _, p := range []ProviderName{ProviderLegacy, ProviderBase, ProviderNull} {
		c, err := NewContext()
		if err != nil {
			t.Fatal(err)
		}
		prov, err := c.LoadProvider(p)
		if err != nil {
			t.Logf("provider %q not loadable here: %v", p, err)
		} else {
			prov.Unload()
		}
		c.Close()
	}
}

// A property query must actually filter, or the constants are decorative.
func TestPropertyQueryConstants(t *testing.T) {
	if !Default.DigestAvailable(SHA256, PropDefaultProvider) {
		t.Error("SHA2-256 does not resolve under provider=default")
	}
	if Default.DigestAvailable(SHA256, PropFIPSProvider) {
		t.Error("SHA2-256 resolved under provider=fips in a context with no fips provider")
	}
	if got := PropFIPS.AND(PropDefaultProvider); got != "fips=yes,provider=default" {
		t.Errorf("AND produced %q", got)
	}
	if got := PropertyQuery("").AND(PropFIPS); got != PropFIPS {
		t.Errorf("AND with an empty query produced %q", got)
	}
	if got := PropFIPS.AND(""); got != PropFIPS {
		t.Errorf("AND with an empty operand produced %q", got)
	}
}

// The parameter names must match what OpenSSL matches on. A wrong one is
// ignored rather than rejected, so this checks the ones this package sends
// against the private constants the implementation already uses.
func TestParamKeyConstantsMatchImplementation(t *testing.T) {
	pairs := map[ParamKey]string{
		ParamDigest:        pKeyDigest,
		ParamCipher:        pKeyCipher,
		ParamKey_:          pKeyKey,
		ParamSalt:          pKeySalt,
		ParamInfo:          pKeyInfo,
		ParamPassword:      pKeyPassword,
		ParamSecret:        pKeySecret,
		ParamIter:          pKeyIter,
		ParamSize:          pKeySize,
		ParamMode:          pKeyMode,
		ParamCustom:        pKeyCustom,
		ParamIV:            pKeyIV,
		ParamArgon2Lanes:   pKeyArgonLane,
		ParamArgon2Memcost: pKeyArgonMem,
		ParamArgon2AD:      pKeyArgonAD,
		ParamThreads:       pKeyThreads,
		ParamContextString: pKeyContext,
		ParamInstance:      pKeyInstance,
		ParamNonceType:     pKeyNonceType,
		ParamDeterministic: pKeyDeterministic,
		ParamRSABits:       pKeyRSABits,
		ParamGroup:         pKeyGroupName,
	}
	for exported, internal := range pairs {
		if string(exported) != internal {
			t.Errorf("exported %q does not match the internal constant %q", exported, internal)
		}
	}
}

// The typed constants must remain usable wherever a plain string was before.
func TestConstantsAreUsableAsLiterals(t *testing.T) {
	h, err := Default.NewHash(SHA256)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()

	// An untyped literal is still accepted by the typed parameter.
	if got := DigestName("SHA2-256"); got != SHA256 {
		t.Errorf("literal conversion mismatch: %q", got)
	}
	// And the types stringify to exactly the OpenSSL name.
	if SHA256.String() != "SHA2-256" || AES256GCM.String() != "AES-256-GCM" ||
		MLDSA65.String() != "ML-DSA-65" || P256.String() != "P-256" {
		t.Error("a constant does not stringify to its OpenSSL name")
	}
}
