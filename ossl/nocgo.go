//go:build !cgo

// This file is the whole package when cgo is disabled. It exists so that a
// program depending on this package still compiles on a machine with no
// OpenSSL headers, and so that the failure is a named error at the call site
// rather than an incomprehensible link error at build time.
//
// Every operation returns ErrUnavailable.
//
// The API surface must mirror the cgo build exactly. `make ci` builds this
// configuration precisely so that drift is a build failure rather than
// something discovered by a downstream user.

package ossl

import (
	"crypto/cipher"
	"hash"
)

// --- version and utilities -------------------------------------------------

func Version() string       { return "" }
func BuildVersion() string  { return "" }
func VersionNumber() uint64 { return 0 }
func AtLeast(major, minor int) bool {
	return false
}
func CheckVersion() error { return ErrUnavailable }

// Zero still works: overwriting a Go slice needs no C. Keeping it functional
// means cleanup paths behave the same in both builds.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func ConfigDir() string               { return "" }
func ModulesDir() string              { return "" }
func DefaultFIPSModuleConfig() string { return "" }

// --- library context -------------------------------------------------------

type Context struct{}

var Default = &Context{}

func NewContext() (*Context, error)                      { return nil, ErrUnavailable }
func NewFIPSContext(configPath string) (*Context, error) { return nil, ErrUnavailable }

func (c *Context) Close() error                            { return nil }
func (c *Context) SetDefaultProperties(propq string) error { return ErrUnavailable }
func (c *Context) LoadConfig(path string) error            { return ErrUnavailable }
func (c *Context) EnableFIPS(configPath string) error      { return ErrUnavailable }
func (c *Context) FIPSEnabled() bool                       { return false }

// --- providers -------------------------------------------------------------

type Provider struct{}

type ProviderInfo struct {
	Name    string
	Version string
	Active  bool
}

func (c *Context) LoadProvider(name string) (*Provider, error) { return nil, ErrUnavailable }
func (c *Context) ProviderAvailable(name string) bool          { return false }
func (c *Context) Providers() ([]ProviderInfo, error)          { return nil, ErrUnavailable }
func (c *Context) DigestAvailable(name, propq string) bool     { return false }
func (c *Context) CipherAvailable(name, propq string) bool     { return false }

func (p *Provider) Unload() error   { return nil }
func (p *Provider) SelfTest() error { return ErrUnavailable }

// --- digests ---------------------------------------------------------------

type Hash struct{}

var _ hash.Hash = (*Hash)(nil)

func (c *Context) NewHash(name string) (*Hash, error) { return nil, ErrUnavailable }

func (h *Hash) Write(p []byte) (int, error)  { return 0, ErrUnavailable }
func (h *Hash) Sum(b []byte) []byte          { return b }
func (h *Hash) SumXOF(n int) ([]byte, error) { return nil, ErrUnavailable }
func (h *Hash) Reset()                       {}
func (h *Hash) Size() int                    { return 0 }
func (h *Hash) BlockSize() int               { return 0 }
func (h *Hash) Name() string                 { return "" }
func (h *Hash) IsXOF() bool                  { return false }
func (h *Hash) Err() error                   { return ErrUnavailable }
func (h *Hash) Close() error                 { return nil }

func Digest(name string, data []byte) ([]byte, error)           { return nil, ErrUnavailable }
func DigestXOF(name string, data []byte, n int) ([]byte, error) { return nil, ErrUnavailable }

// --- MACs ------------------------------------------------------------------

type MAC struct{}

var _ hash.Hash = (*MAC)(nil)

func (c *Context) NewHMAC(digest string, key []byte) (*MAC, error) { return nil, ErrUnavailable }
func (c *Context) NewCMAC(cipher string, key []byte) (*MAC, error) { return nil, ErrUnavailable }
func (c *Context) NewKMAC(bits int, key []byte, outLen int, custom []byte) (*MAC, error) {
	return nil, ErrUnavailable
}

func (m *MAC) Write(b []byte) (int, error) { return 0, ErrUnavailable }
func (m *MAC) Sum(b []byte) []byte         { return b }
func (m *MAC) Reset()                      {}
func (m *MAC) Size() int                   { return 0 }
func (m *MAC) BlockSize() int              { return 0 }
func (m *MAC) Err() error                  { return ErrUnavailable }
func (m *MAC) Close() error                { return nil }

func HMACSum(digest string, key, data []byte) ([]byte, error) { return nil, ErrUnavailable }

// EqualMAC is constant-time slice comparison and needs no C, so it keeps
// working: a caller comparing tags must not silently fall back to a
// variable-time comparison just because this build has no OpenSSL.
func EqualMAC(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// --- KDFs ------------------------------------------------------------------

type KDFParams map[string]any

type Argon2idParams struct {
	Iterations     uint
	MemoryKiB      uint
	Lanes          uint
	AssociatedData []byte
	Secret         []byte
}

func (c *Context) DeriveKDF(name string, kp KDFParams, n int) ([]byte, error) {
	return nil, ErrUnavailable
}
func (c *Context) HKDF(digest string, secret, salt, info []byte, n int) ([]byte, error) {
	return nil, ErrUnavailable
}
func (c *Context) HKDFExpand(digest string, prk, info []byte, n int) ([]byte, error) {
	return nil, ErrUnavailable
}
func (c *Context) PBKDF2(digest string, password, salt []byte, iterations, n int) ([]byte, error) {
	return nil, ErrUnavailable
}
func (c *Context) Argon2id(password, salt []byte, ap Argon2idParams, n int) ([]byte, error) {
	return nil, ErrUnavailable
}

// --- AEAD ------------------------------------------------------------------

type AEAD struct{}

var _ cipher.AEAD = (*AEAD)(nil)

type aeadConfig struct {
	ivLen  int
	tagLen int
}

type AEADOption func(*aeadConfig)

func WithIVSize(n int) AEADOption  { return func(c *aeadConfig) { c.ivLen = n } }
func WithTagSize(n int) AEADOption { return func(c *aeadConfig) { c.tagLen = n } }

func (c *Context) NewAEAD(name string, key []byte, opts ...AEADOption) (*AEAD, error) {
	return nil, ErrUnavailable
}

func (a *AEAD) NonceSize() int { return 0 }
func (a *AEAD) Overhead() int  { return 0 }
func (a *AEAD) Name() string   { return "" }
func (a *AEAD) Seal(dst, nonce, plaintext, aad []byte) []byte {
	panic(ErrUnavailable)
}
func (a *AEAD) SealErr(dst, nonce, plaintext, aad []byte) ([]byte, error) {
	return nil, ErrUnavailable
}
func (a *AEAD) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	return nil, ErrUnavailable
}
func (a *AEAD) Close() error { return nil }

// --- keys ------------------------------------------------------------------

type Key struct{}

// params mirrors the cgo build's builder type so that KeyOption keeps the
// same signature. It holds nothing here.
type params struct{}

type KeyOption func(*params)

func WithRSABits(bits int) KeyOption            { return func(*params) {} }
func WithGroup(name string) KeyOption           { return func(*params) {} }
func WithParam(key string, value any) KeyOption { return func(*params) {} }

func (c *Context) GenerateKey(algorithm string, opts ...KeyOption) (*Key, error) {
	return nil, ErrUnavailable
}

func (k *Key) Type() string          { return "" }
func (k *Key) Bits() int             { return 0 }
func (k *Key) SecurityBits() int     { return 0 }
func (k *Key) Size() int             { return 0 }
func (k *Key) Close() error          { return nil }
func (k *Key) Public() (*Key, error) { return nil, ErrUnavailable }

func (k *Key) MarshalPKCS8() ([]byte, error)         { return nil, ErrUnavailable }
func (k *Key) MarshalPKCS8PEM() ([]byte, error)      { return nil, ErrUnavailable }
func (k *Key) MarshalSEC1() ([]byte, error)          { return nil, ErrUnavailable }
func (k *Key) MarshalSEC1PEM() ([]byte, error)       { return nil, ErrUnavailable }
func (k *Key) MarshalSPKI() ([]byte, error)          { return nil, ErrUnavailable }
func (k *Key) MarshalSPKIPEM() ([]byte, error)       { return nil, ErrUnavailable }
func (k *Key) MarshalRawPrivateKey() ([]byte, error) { return nil, ErrUnavailable }
func (k *Key) MarshalRawPublicKey() ([]byte, error)  { return nil, ErrUnavailable }

func (c *Context) ParsePKCS8PrivateKey(der []byte) (*Key, error)         { return nil, ErrUnavailable }
func (c *Context) ParsePKCS8PrivateKeyPEM(pemBytes []byte) (*Key, error) { return nil, ErrUnavailable }
func (c *Context) ParseSEC1PrivateKey(der []byte) (*Key, error)          { return nil, ErrUnavailable }
func (c *Context) ParseSEC1PrivateKeyPEM(pemBytes []byte) (*Key, error)  { return nil, ErrUnavailable }
func (c *Context) ParseSPKIPublicKey(der []byte) (*Key, error)           { return nil, ErrUnavailable }
func (c *Context) ParseSPKIPublicKeyPEM(pemBytes []byte) (*Key, error)   { return nil, ErrUnavailable }
func (c *Context) ParseRawPrivateKey(algorithm string, raw []byte) (*Key, error) {
	return nil, ErrUnavailable
}
func (c *Context) ParseRawPublicKey(algorithm string, raw []byte) (*Key, error) {
	return nil, ErrUnavailable
}

// --- signatures ------------------------------------------------------------

type RSAPadding int

const (
	RSAPSS RSAPadding = iota
	RSAPKCS1v15
)

type PSSSaltLength int

const (
	PSSSaltLengthHash PSSSaltLength = 0
	PSSSaltLengthMax  PSSSaltLength = -1
)

type SignOptions struct {
	Digest        string
	Context       []byte
	Prehash       bool
	Padding       RSAPadding
	PSSSaltLen    PSSSaltLength
	MGF1Hash      string
	Format        SignatureFormat
	Deterministic bool
}

func (k *Key) Sign(msg []byte, opts *SignOptions) ([]byte, error) { return nil, ErrUnavailable }
func (k *Key) Verify(msg, sig []byte, opts *SignOptions) error    { return ErrUnavailable }

type Signer struct{}
type Verifier struct{}

func NewSigner(k *Key, opts *SignOptions) (*Signer, error)     { return nil, ErrUnavailable }
func NewVerifier(k *Key, opts *SignOptions) (*Verifier, error) { return nil, ErrUnavailable }

func (s *Signer) Write(p []byte) (int, error) { return 0, ErrUnavailable }
func (s *Signer) Sign() ([]byte, error)       { return nil, ErrUnavailable }
func (s *Signer) Name() string                { return "" }
func (s *Signer) Close() error                { return nil }

func (v *Verifier) Write(p []byte) (int, error) { return 0, ErrUnavailable }
func (v *Verifier) Verify(sig []byte) error     { return ErrUnavailable }
func (v *Verifier) Name() string                { return "" }
func (v *Verifier) Close() error                { return nil }

// --- asymmetric encryption, KEM, key agreement -----------------------------

type OAEPOptions struct {
	Hash     string
	MGF1Hash string
	Label    []byte
}

type DeriveOptions struct {
	CofactorMode bool
}

func (k *Key) Encrypt(plaintext []byte, opts *OAEPOptions) ([]byte, error) {
	return nil, ErrUnavailable
}
func (k *Key) Decrypt(ciphertext []byte, opts *OAEPOptions) ([]byte, error) {
	return nil, ErrUnavailable
}
func (k *Key) MaxOAEPPlaintext(opts *OAEPOptions) (int, error) { return 0, ErrUnavailable }
func (k *Key) Encapsulate() (ciphertext, secret []byte, err error) {
	return nil, nil, ErrUnavailable
}
func (k *Key) Decapsulate(ciphertext []byte) ([]byte, error) { return nil, ErrUnavailable }
func (k *Key) Derive(peer *Key, opts *DeriveOptions) ([]byte, error) {
	return nil, ErrUnavailable
}

func DeriveSharedKey(secret []byte, context string, n int) ([]byte, error) {
	return nil, ErrUnavailable
}

// --- stores ----------------------------------------------------------------

type StoreObjectType int

const (
	StoreUnknown StoreObjectType = iota
	StorePrivateKey
	StorePublicKey
	StoreCertificate
)

func (t StoreObjectType) String() string {
	switch t {
	case StorePrivateKey:
		return "private key"
	case StorePublicKey:
		return "public key"
	case StoreCertificate:
		return "certificate"
	default:
		return "unknown"
	}
}

type StoreObject struct {
	Type StoreObjectType
	Name string
}

func (c *Context) LoadKey(uri string) (*Key, error)            { return nil, ErrUnavailable }
func (c *Context) LoadPublicKey(uri string) (*Key, error)      { return nil, ErrUnavailable }
func (c *Context) ListStore(uri string) ([]StoreObject, error) { return nil, ErrUnavailable }

// --- secure heap -----------------------------------------------------------

type SecureBuffer struct{}

func InitSecureHeap(size, minAlloc int) error { return ErrUnavailable }
func DoneSecureHeap() error                   { return ErrUnavailable }
func SecureHeapInitialized() bool             { return false }
func SecureHeapUsed() int                     { return 0 }

func NewSecureBuffer(n int) (*SecureBuffer, error) { return nil, ErrUnavailable }

func (b *SecureBuffer) Bytes() []byte { return nil }
func (b *SecureBuffer) Len() int      { return 0 }
func (b *SecureBuffer) Close() error  { return nil }

// --- non-AEAD symmetric ciphers, key wrap -----------------------------------

type PaddingScheme int

const (
	PaddingPKCS7 PaddingScheme = iota
	PaddingNone
	PaddingISO7816
	PaddingX923
	PaddingZero
)

func (p PaddingScheme) String() string {
	switch p {
	case PaddingPKCS7:
		return "PKCS#7"
	case PaddingNone:
		return "none"
	case PaddingISO7816:
		return "ISO/IEC 7816-4"
	case PaddingX923:
		return "ANSI X9.23"
	case PaddingZero:
		return "zero"
	default:
		return "unknown"
	}
}

type Cipher struct{}

type cipherConfig struct {
	padding PaddingScheme
	ivLen   int
	ivSet   bool
}

type CipherOption func(*cipherConfig)

func WithPadding(p PaddingScheme) CipherOption { return func(c *cipherConfig) { c.padding = p } }
func WithCipherIVSize(n int) CipherOption {
	return func(c *cipherConfig) { c.ivLen = n; c.ivSet = true }
}

func (c *Context) NewCipher(name string, key []byte, opts ...CipherOption) (*Cipher, error) {
	return nil, ErrUnavailable
}

func (x *Cipher) IVSize() int            { return 0 }
func (x *Cipher) BlockSize() int         { return 0 }
func (x *Cipher) Name() string           { return "" }
func (x *Cipher) Padding() PaddingScheme { return PaddingPKCS7 }
func (x *Cipher) Encrypt(dst, iv, plaintext []byte) ([]byte, error) {
	return nil, ErrUnavailable
}
func (x *Cipher) Decrypt(dst, iv, ciphertext []byte) ([]byte, error) {
	return nil, ErrUnavailable
}
func (x *Cipher) Close() error { return nil }

type KeyWrap struct{}

func (c *Context) NewKeyWrap(kek []byte, withPadding bool) (*KeyWrap, error) {
	return nil, ErrUnavailable
}
func (w *KeyWrap) Name() string                            { return "" }
func (w *KeyWrap) Wrap(keyMaterial []byte) ([]byte, error) { return nil, ErrUnavailable }
func (w *KeyWrap) Unwrap(wrapped []byte) ([]byte, error)   { return nil, ErrUnavailable }
func (w *KeyWrap) Close() error                            { return nil }

// --- generic MAC ------------------------------------------------------------

type MACParams struct {
	Digest string
	Cipher string
	IV     []byte
	Custom []byte
	Size   int
}

func (c *Context) NewMAC(algorithm string, key []byte, p *MACParams) (*MAC, error) {
	return nil, ErrUnavailable
}
func (c *Context) NewGMAC(cipher string, key, iv []byte) (*MAC, error) {
	return nil, ErrUnavailable
}

// --- Argon2 variants --------------------------------------------------------

type Argon2Variant int

const (
	Argon2ID Argon2Variant = iota
	Argon2I
	Argon2D
)

func (c *Context) Argon2(variant Argon2Variant, password, salt []byte, ap Argon2idParams, n int) ([]byte, error) {
	return nil, ErrUnavailable
}

// --- signature format -------------------------------------------------------

type SignatureFormat int

const (
	SignatureDER SignatureFormat = iota
	SignatureP1363
)

func (f SignatureFormat) String() string {
	if f == SignatureP1363 {
		return "IEEE P1363"
	}
	return "DER"
}

// --- RSA PKCS#1 v1.5 encryption and PKCS#1 key encoding ---------------------

func (k *Key) EncryptPKCS1v15(plaintext []byte) ([]byte, error)  { return nil, ErrUnavailable }
func (k *Key) DecryptPKCS1v15(ciphertext []byte) ([]byte, error) { return nil, ErrUnavailable }
func (k *Key) MarshalPKCS1() ([]byte, error)                     { return nil, ErrUnavailable }
func (k *Key) MarshalPKCS1PEM() ([]byte, error)                  { return nil, ErrUnavailable }

func (c *Context) ParsePKCS1PrivateKey(der []byte) (*Key, error) { return nil, ErrUnavailable }
func (c *Context) ParsePKCS1PrivateKeyPEM(pemBytes []byte) (*Key, error) {
	return nil, ErrUnavailable
}
