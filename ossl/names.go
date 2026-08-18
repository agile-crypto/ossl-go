package ossl

// Algorithm names, as typed constants.
//
// OpenSSL identifies everything by string. These types exist so that the valid
// values are discoverable from the package rather than from OpenSSL's source
// or a list command.
//
// They are named string types, so a literal still works:
//
//	ctx.NewHash(ossl.SHA256)
//	ctx.NewHash("SHA2-256")   // identical; untyped constants convert
//
//
// The types are deliberately open. Providers supply algorithms this package
// cannot know about -- a vendor PKCS#11 module, a future OpenSSL -- and any
// of them can be named directly. The constants are the curated set: the
// mainstream algorithms plus everything citius-server's proto references.
//
// Every constant below is checked against the linked libcrypto by
// TestEveryAlgorithmConstantResolves. A typo, or a name that this OpenSSL
// does not provide, fails the build gate rather than a caller's request.

// DigestName is a message digest algorithm name.
type DigestName string

func (d DigestName) String() string { return string(d) }

// Message digests. The SHA2-* spelling is OpenSSL's canonical form; "SHA256"
// is an alias for the same thing.
const (
	SHA224     DigestName = "SHA2-224"
	SHA256     DigestName = "SHA2-256"
	SHA384     DigestName = "SHA2-384"
	SHA512     DigestName = "SHA2-512"
	SHA512_224 DigestName = "SHA2-512/224"
	SHA512_256 DigestName = "SHA2-512/256"

	SHA3_224 DigestName = "SHA3-224"
	SHA3_256 DigestName = "SHA3-256"
	SHA3_384 DigestName = "SHA3-384"
	SHA3_512 DigestName = "SHA3-512"

	// Extendable-output functions. Finalise these with SumXOF or DigestXOF,
	// never with Sum, which has no length to produce.
	SHAKE128 DigestName = "SHAKE-128"
	SHAKE256 DigestName = "SHAKE-256"

	BLAKE2b512 DigestName = "BLAKE2B-512"
	BLAKE2s256 DigestName = "BLAKE2S-256"

	SM3       DigestName = "SM3"
	RIPEMD160 DigestName = "RIPEMD-160"

	// SHA1 and MD5 are broken for any use that depends on collision
	// resistance. They remain here because verifying an old signature or
	// speaking an old protocol still requires them.
	SHA1 DigestName = "SHA1"
	MD5  DigestName = "MD5"
)

// CipherName is a symmetric cipher name.
//
// The AEAD modes belong to NewAEAD, the rest to NewCipher, and the WRAP
// variants to NewKeyWrap; each constructor rejects a name meant for one of
// the others.
type CipherName string

func (c CipherName) String() string { return string(c) }

// AEAD ciphers, for NewAEAD.
const (
	AES128GCM CipherName = "AES-128-GCM"
	AES192GCM CipherName = "AES-192-GCM"
	AES256GCM CipherName = "AES-256-GCM"

	AES128CCM CipherName = "AES-128-CCM"
	AES192CCM CipherName = "AES-192-CCM"
	AES256CCM CipherName = "AES-256-CCM"

	AES128OCB CipherName = "AES-128-OCB"
	AES192OCB CipherName = "AES-192-OCB"
	AES256OCB CipherName = "AES-256-OCB"

	ChaCha20Poly1305 CipherName = "ChaCha20-Poly1305"
)

// Block and stream ciphers, for NewCipher. None of these authenticate.
const (
	AES128CBC CipherName = "AES-128-CBC"
	AES192CBC CipherName = "AES-192-CBC"
	AES256CBC CipherName = "AES-256-CBC"

	AES128CTR CipherName = "AES-128-CTR"
	AES192CTR CipherName = "AES-192-CTR"
	AES256CTR CipherName = "AES-256-CTR"

	AES128OFB CipherName = "AES-128-OFB"
	AES256OFB CipherName = "AES-256-OFB"
	AES128CFB CipherName = "AES-128-CFB"
	AES256CFB CipherName = "AES-256-CFB"

	// ECB encrypts every block independently and leaks plaintext structure.
	// It is here for key-derivation-style single-block uses and legacy
	// interoperability, not for encrypting messages.
	AES128ECB CipherName = "AES-128-ECB"
	AES256ECB CipherName = "AES-256-ECB"

	// XTS is for data at rest addressed by sector; the "key" is two keys.
	AES128XTS CipherName = "AES-128-XTS"
	AES256XTS CipherName = "AES-256-XTS"

	ChaCha20 CipherName = "ChaCha20"

	Camellia128CBC CipherName = "CAMELLIA-128-CBC"
	Camellia256CBC CipherName = "CAMELLIA-256-CBC"
	ARIA128CBC     CipherName = "ARIA-128-CBC"
	ARIA256CBC     CipherName = "ARIA-256-CBC"
	ARIA128GCM     CipherName = "ARIA-128-GCM"
	ARIA256GCM     CipherName = "ARIA-256-GCM"
	SM4CBC         CipherName = "SM4-CBC"
	SM4GCM         CipherName = "SM4-GCM"
)

// Ciphers that live in the legacy provider and do not resolve until it is
// loaded. Verified against this build: they are absent from a default
// context and present once LoadProvider("legacy") has run.
//
//	c, _ := ossl.NewContext()
//	c.LoadProvider(string(ossl.ProviderLegacy))
//	enc, _ := c.NewCipher(string(ossl.SEEDCBC), key)
const (
	SEEDCBC CipherName = "SEED-CBC"
	SEEDECB CipherName = "SEED-ECB"
	SEEDCFB CipherName = "SEED-CFB"
	SEEDOFB CipherName = "SEED-OFB"
)

// Key wrapping ciphers. NewKeyWrap selects these from the KEK length rather
// than by name; they are listed for CipherAvailable and for callers building
// their own property queries.
const (
	AES128Wrap    CipherName = "AES-128-WRAP"
	AES192Wrap    CipherName = "AES-192-WRAP"
	AES256Wrap    CipherName = "AES-256-WRAP"
	AES128WrapPad CipherName = "AES-128-WRAP-PAD"
	AES192WrapPad CipherName = "AES-192-WRAP-PAD"
	AES256WrapPad CipherName = "AES-256-WRAP-PAD"
)

// MACName is a message authentication code algorithm name, for NewMAC.
type MACName string

func (m MACName) String() string { return string(m) }

// Every MAC this build provides.
const (
	HMAC       MACName = "HMAC"
	CMAC       MACName = "CMAC"
	GMAC       MACName = "GMAC"
	KMAC128    MACName = "KMAC-128"
	KMAC256    MACName = "KMAC-256"
	Poly1305   MACName = "POLY1305"
	SipHash    MACName = "SIPHASH"
	BLAKE2bMAC MACName = "BLAKE2BMAC"
	BLAKE2sMAC MACName = "BLAKE2SMAC"
)

// KDFName is a key derivation function name, for DeriveKDF.
type KDFName string

func (k KDFName) String() string { return string(k) }

// Every KDF this build provides. HKDF, PBKDF2 and the Argon2 family have
// dedicated helpers; the rest are reached through DeriveKDF.
const (
	KDFHKDF     KDFName = "HKDF"
	KDFPBKDF2   KDFName = "PBKDF2"
	KDFArgon2d  KDFName = "ARGON2D"
	KDFArgon2i  KDFName = "ARGON2I"
	KDFArgon2id KDFName = "ARGON2ID"
	KDFScrypt   KDFName = "SCRYPT"

	// SSKDF and X963KDF are the SP 800-56A and ANSI X9.63 single-step
	// functions a key-agreement result is normally fed through.
	KDFSSKDF      KDFName = "SSKDF"
	KDFX963       KDFName = "X963KDF"
	KDFX942       KDFName = "X942KDF"
	KDFX942Concat KDFName = "X942KDF-CONCAT"
	KDFKBKDF      KDFName = "KBKDF"
	KDFTLS1PRF    KDFName = "TLS1-PRF"
	KDFTLS13      KDFName = "TLS13-KDF"
	KDFSSH        KDFName = "SSHKDF"
	KDFKrb5       KDFName = "KRB5KDF"
	KDFPKCS12     KDFName = "PKCS12KDF"
	KDFHMACDRBG   KDFName = "HMAC-DRBG-KDF"
)

// KeyAlgorithm is an asymmetric key algorithm name, for GenerateKey and the
// raw-key parsers.
type KeyAlgorithm string

func (k KeyAlgorithm) String() string { return string(k) }

// Classical asymmetric algorithms.
const (
	RSA       KeyAlgorithm = "RSA"
	RSAPSSKey KeyAlgorithm = "RSA-PSS"
	EC        KeyAlgorithm = "EC"
	Ed25519   KeyAlgorithm = "ED25519"
	Ed448     KeyAlgorithm = "ED448"
	X25519    KeyAlgorithm = "X25519"
	X448      KeyAlgorithm = "X448"
	DSA       KeyAlgorithm = "DSA"
	DH        KeyAlgorithm = "DH"
)

// Post-quantum algorithms. The parameter set is part of the name; these take
// no size option.
const (
	MLKEM512  KeyAlgorithm = "ML-KEM-512"
	MLKEM768  KeyAlgorithm = "ML-KEM-768"
	MLKEM1024 KeyAlgorithm = "ML-KEM-1024"

	MLDSA44 KeyAlgorithm = "ML-DSA-44"
	MLDSA65 KeyAlgorithm = "ML-DSA-65"
	MLDSA87 KeyAlgorithm = "ML-DSA-87"

	SLHDSASHA2128s  KeyAlgorithm = "SLH-DSA-SHA2-128s"
	SLHDSASHA2128f  KeyAlgorithm = "SLH-DSA-SHA2-128f"
	SLHDSASHA2192s  KeyAlgorithm = "SLH-DSA-SHA2-192s"
	SLHDSASHA2192f  KeyAlgorithm = "SLH-DSA-SHA2-192f"
	SLHDSASHA2256s  KeyAlgorithm = "SLH-DSA-SHA2-256s"
	SLHDSASHA2256f  KeyAlgorithm = "SLH-DSA-SHA2-256f"
	SLHDSASHAKE128s KeyAlgorithm = "SLH-DSA-SHAKE-128s"
	SLHDSASHAKE128f KeyAlgorithm = "SLH-DSA-SHAKE-128f"
	SLHDSASHAKE192s KeyAlgorithm = "SLH-DSA-SHAKE-192s"
	SLHDSASHAKE192f KeyAlgorithm = "SLH-DSA-SHAKE-192f"
	SLHDSASHAKE256s KeyAlgorithm = "SLH-DSA-SHAKE-256s"
	SLHDSASHAKE256f KeyAlgorithm = "SLH-DSA-SHAKE-256f"
)

// Hybrid KEMs, each pairing ML-KEM with a classical exchange so that
// breaking the result requires breaking both.
const (
	X25519MLKEM768     KeyAlgorithm = "X25519MLKEM768"
	X448MLKEM1024      KeyAlgorithm = "X448MLKEM1024"
	SecP256r1MLKEM768  KeyAlgorithm = "SecP256r1MLKEM768"
	SecP384r1MLKEM1024 KeyAlgorithm = "SecP384r1MLKEM1024"
)

// Curve is an elliptic curve group name, for WithGroup.
type Curve string

func (c Curve) String() string { return string(c) }

// Elliptic curves. The NIST prime curves are the interoperable choice;
// secp256k1 appears in blockchain protocols and Brainpool in some European
// standards. citius-server's EllipticCurve enum permits exactly this set.
const (
	P224 Curve = "P-224"
	P256 Curve = "P-256"
	P384 Curve = "P-384"
	P521 Curve = "P-521"

	Secp256k1 Curve = "secp256k1"

	BrainpoolP256r1 Curve = "brainpoolP256r1"
	BrainpoolP384r1 Curve = "brainpoolP384r1"
	BrainpoolP512r1 Curve = "brainpoolP512r1"
)

// ProviderName names a provider module, for LoadProvider.
type ProviderName string

func (p ProviderName) String() string { return string(p) }

const (
	// ProviderDefault holds the ordinary implementations and is active in a
	// fresh Context without being loaded.
	ProviderDefault ProviderName = "default"
	// ProviderFIPS is the validated module. Load it through
	// Context.EnableFIPS, never directly; see the warning there.
	ProviderFIPS ProviderName = "fips"
	// ProviderLegacy holds algorithms removed from the default set.
	ProviderLegacy ProviderName = "legacy"
	// ProviderBase holds encoders and serialisers without the algorithms.
	ProviderBase ProviderName = "base"
	// ProviderNull provides nothing, for proving a context is empty.
	ProviderNull ProviderName = "null"
	// ProviderPKCS11 is the third-party pkcs11-provider, present only if
	// configured; see Context.LoadConfig.
	ProviderPKCS11 ProviderName = "pkcs11"
)

// PropertyQuery filters which implementation a fetch resolves to.
//
// The syntax is a comma-separated list of name=value terms; a leading "?"
// makes a term a preference rather than a requirement. Combine them with
// AND.
type PropertyQuery string

func (q PropertyQuery) String() string { return string(q) }

// AND combines two property queries.
func (q PropertyQuery) AND(other PropertyQuery) PropertyQuery {
	switch {
	case q == "":
		return other
	case other == "":
		return q
	default:
		return q + "," + other
	}
}

const (
	// PropFIPS restricts a fetch to the validated module.
	PropFIPS PropertyQuery = "fips=yes"
	// PropNotFIPS excludes it.
	PropNotFIPS PropertyQuery = "fips=no"
	// PropDefaultProvider and friends pin the provider by name.
	PropDefaultProvider PropertyQuery = "provider=default"
	PropFIPSProvider    PropertyQuery = "provider=fips"
	PropLegacyProvider  PropertyQuery = "provider=legacy"
	PropPKCS11Provider  PropertyQuery = "provider=pkcs11"
)

// ParamKey is an OSSL_PARAM name, for DeriveKDF and WithParam.
//
// These are the strings OpenSSL matches parameters on. A name it does not
// recognise is ignored rather than rejected, which presents as a wrong
// result rather than an error -- the reason to use a constant.
type ParamKey string

func (p ParamKey) String() string { return string(p) }

const (
	ParamDigest     ParamKey = "digest"
	ParamCipher     ParamKey = "cipher"
	ParamKey_       ParamKey = "key"
	ParamSalt       ParamKey = "salt"
	ParamInfo       ParamKey = "info"
	ParamSeed       ParamKey = "seed"
	ParamLabel      ParamKey = "label"
	ParamPassword   ParamKey = "pass"
	ParamSecret     ParamKey = "secret"
	ParamIter       ParamKey = "iter"
	ParamSize       ParamKey = "size"
	ParamMode       ParamKey = "mode"
	ParamCustom     ParamKey = "custom"
	ParamIV         ParamKey = "iv"
	ParamProperties ParamKey = "properties"

	// Argon2.
	ParamArgon2Lanes   ParamKey = "lanes"
	ParamArgon2Memcost ParamKey = "memcost"
	ParamArgon2AD      ParamKey = "ad"
	ParamThreads       ParamKey = "threads"

	// Signatures.
	ParamContextString ParamKey = "context-string"
	ParamInstance      ParamKey = "instance"
	ParamNonceType     ParamKey = "nonce-type"
	ParamDeterministic ParamKey = "deterministic"

	// Key generation.
	ParamRSABits   ParamKey = "bits"
	ParamRSAPubExp ParamKey = "e"
	ParamGroup     ParamKey = "group"
)
