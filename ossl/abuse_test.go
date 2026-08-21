//go:build cgo

package ossl

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// This suite exists for one reason: a library that a server links against
// must not be able to take the process down, however badly it is called.
// Every entry point is invoked here with the inputs a caller should never
// pass -- nil receivers, nil and empty slices, closed handles, absurd sizes,
// wrong types -- and the only assertion is that nothing panics. Returning an
// error is fine. Returning nonsense is fine for this test's purposes.
// Crashing is not.

// mustNotPanic runs fn and reports a panic as a test failure rather than
// letting it unwind.
func mustNotPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s panicked: %v", name, r)
		}
	}()
	fn()
}

func TestAbuseNilReceivers(t *testing.T) {
	var (
		nilKey    *Key
		nilCtx    *Context
		nilHash   *Hash
		nilMAC    *MAC
		nilAEAD   *AEAD
		nilProv   *Provider
		nilSigner *Signer
		nilVerif  *Verifier
		nilBuf    *SecureBuffer
	)

	cases := map[string]func(){
		"nilKey.Type":           func() { _ = nilKey.Type() },
		"nilKey.Bits":           func() { _ = nilKey.Bits() },
		"nilKey.SecurityBits":   func() { _ = nilKey.SecurityBits() },
		"nilKey.Size":           func() { _ = nilKey.Size() },
		"nilKey.Close":          func() { _ = nilKey.Close() },
		"nilKey.Public":         func() { _, _ = nilKey.Public() },
		"nilKey.Sign":           func() { _, _ = nilKey.Sign([]byte("m"), nil) },
		"nilKey.Verify":         func() { _ = nilKey.Verify([]byte("m"), []byte("s"), nil) },
		"nilKey.SignDigest":     func() { _, _ = nilKey.SignDigest([]byte("d"), nil) },
		"nilKey.VerifyDigest":   func() { _ = nilKey.VerifyDigest([]byte("d"), []byte("s"), nil) },
		"nilKey.Encrypt":        func() { _, _ = nilKey.Encrypt([]byte("m"), nil) },
		"nilKey.Decrypt":        func() { _, _ = nilKey.Decrypt([]byte("c"), nil) },
		"nilKey.MaxOAEP":        func() { _, _ = nilKey.MaxOAEPPlaintext(nil) },
		"nilKey.Encapsulate":    func() { _, _, _ = nilKey.Encapsulate() },
		"nilKey.Decapsulate":    func() { _, _ = nilKey.Decapsulate([]byte("c")) },
		"nilKey.Derive":         func() { _, _ = nilKey.Derive(nilKey, nil) },
		"nilKey.MarshalPKCS8":   func() { _, _ = nilKey.MarshalPKCS8() },
		"nilKey.MarshalSPKI":    func() { _, _ = nilKey.MarshalSPKI() },
		"nilKey.MarshalSEC1":    func() { _, _ = nilKey.MarshalSEC1() },
		"nilKey.MarshalRawPriv": func() { _, _ = nilKey.MarshalRawPrivateKey() },
		"nilKey.MarshalRawPub":  func() { _, _ = nilKey.MarshalRawPublicKey() },

		"nilCtx.Close":       func() { _ = nilCtx.Close() },
		"nilCtx.SetProps":    func() { _ = nilCtx.SetDefaultProperties("x") },
		"nilCtx.NewHash":     func() { _, _ = nilCtx.NewHash("SHA2-256") },
		"nilCtx.NewAEAD":     func() { _, _ = nilCtx.NewAEAD("AES-256-GCM", make([]byte, 32)) },
		"nilCtx.GenerateKey": func() { _, _ = nilCtx.GenerateKey("ED25519") },
		"nilCtx.LoadKey":     func() { _, _ = nilCtx.LoadKey("file:/nope") },
		"nilCtx.ListStore":   func() { _, _ = nilCtx.ListStore("file:/nope") },
		"nilCtx.Providers":   func() { _, _ = nilCtx.Providers() },
		"nilCtx.FIPSEnabled": func() { _ = nilCtx.FIPSEnabled() },
		"nilCtx.LoadConfig":  func() { _ = nilCtx.LoadConfig("/nope") },
		"nilCtx.EnableFIPS":  func() { _ = nilCtx.EnableFIPS("/nope") },
		"nilCtx.HKDF":        func() { _, _ = nilCtx.HKDF("SHA2-256", []byte("s"), nil, nil, 32) },
		"nilCtx.DigestAvail": func() { _ = nilCtx.DigestAvailable("SHA2-256", "") },

		"nilHash.Write":     func() { _, _ = nilHash.Write([]byte("x")) },
		"nilHash.Sum":       func() { _ = nilHash.Sum(nil) },
		"nilHash.SumXOF":    func() { _, _ = nilHash.SumXOF(32) },
		"nilHash.Reset":     func() { nilHash.Reset() },
		"nilHash.Size":      func() { _ = nilHash.Size() },
		"nilHash.BlockSize": func() { _ = nilHash.BlockSize() },
		"nilHash.Name":      func() { _ = nilHash.Name() },
		"nilHash.IsXOF":     func() { _ = nilHash.IsXOF() },
		"nilHash.Err":       func() { _ = nilHash.Err() },
		"nilHash.Close":     func() { _ = nilHash.Close() },

		"nilMAC.Write": func() { _, _ = nilMAC.Write([]byte("x")) },
		"nilMAC.Sum":   func() { _ = nilMAC.Sum(nil) },
		"nilMAC.Reset": func() { nilMAC.Reset() },
		"nilMAC.Size":  func() { _ = nilMAC.Size() },
		"nilMAC.Err":   func() { _ = nilMAC.Err() },
		"nilMAC.Close": func() { _ = nilMAC.Close() },

		"nilAEAD.NonceSize": func() { _ = nilAEAD.NonceSize() },
		"nilAEAD.Overhead":  func() { _ = nilAEAD.Overhead() },
		"nilAEAD.Name":      func() { _ = nilAEAD.Name() },
		"nilAEAD.SealErr":   func() { _, _ = nilAEAD.SealErr(nil, nil, nil, nil) },
		"nilAEAD.Open":      func() { _, _ = nilAEAD.Open(nil, nil, nil, nil) },
		"nilAEAD.Close":     func() { _ = nilAEAD.Close() },

		"nilProv.Unload":   func() { _ = nilProv.Unload() },
		"nilProv.SelfTest": func() { _ = nilProv.SelfTest() },

		"nilSigner.Write": func() { _, _ = nilSigner.Write([]byte("x")) },
		"nilSigner.Sign":  func() { _, _ = nilSigner.Sign() },
		"nilSigner.Name":  func() { _ = nilSigner.Name() },
		"nilSigner.Close": func() { _ = nilSigner.Close() },

		"nilVerif.Write":  func() { _, _ = nilVerif.Write([]byte("x")) },
		"nilVerif.Verify": func() { _ = nilVerif.Verify([]byte("s")) },
		"nilVerif.Name":   func() { _ = nilVerif.Name() },
		"nilVerif.Close":  func() { _ = nilVerif.Close() },

		"nilBuf.Bytes": func() { _ = nilBuf.Bytes() },
		"nilBuf.Len":   func() { _ = nilBuf.Len() },
		"nilBuf.Close": func() { _ = nilBuf.Close() },

		"NewSigner(nil)":   func() { _, _ = NewSigner(nil, nil) },
		"NewVerifier(nil)": func() { _, _ = NewVerifier(nil, nil) },
	}

	for name, fn := range cases {
		mustNotPanic(t, name, fn)
	}
}

func TestAbuseEmptyAndNilArguments(t *testing.T) {
	cases := map[string]func(){
		"Zero(nil)":         func() { Zero(nil) },
		"Zero(empty)":       func() { Zero([]byte{}) },
		"EqualMAC(nil)":     func() { _ = EqualMAC(nil, nil) },
		"Digest(empty)":     func() { _, _ = Digest("SHA2-256", nil) },
		"Digest(noname)":    func() { _, _ = Digest("", nil) },
		"DigestXOF(0)":      func() { _, _ = DigestXOF("SHAKE-256", nil, 0) },
		"DigestXOF(-1)":     func() { _, _ = DigestXOF("SHAKE-256", nil, -1) },
		"DigestXOF(huge)":   func() { _, _ = DigestXOF("SHAKE-256", nil, 1<<20) },
		"HMACSum(nilkey)":   func() { _, _ = HMACSum("SHA2-256", nil, nil) },
		"HMACSum(noname)":   func() { _, _ = HMACSum("", nil, nil) },
		"HKDF(0)":           func() { _, _ = Default.HKDF("SHA2-256", nil, nil, nil, 0) },
		"HKDF(-1)":          func() { _, _ = Default.HKDF("SHA2-256", nil, nil, nil, -1) },
		"HKDF(nilsecret)":   func() { _, _ = Default.HKDF("SHA2-256", nil, nil, nil, 32) },
		"PBKDF2(0 iter)":    func() { _, _ = Default.PBKDF2("SHA2-256", nil, nil, 0, 32) },
		"PBKDF2(neg)":       func() { _, _ = Default.PBKDF2("SHA2-256", nil, nil, -1, 32) },
		"Argon2id(zero)":    func() { _, _ = Default.Argon2id(nil, nil, Argon2idParams{}, 32) },
		"Argon2id(huge)":    func() { _, _ = Default.Argon2id(nil, nil, Argon2idParams{Lanes: 1 << 20}, 32) },
		"DeriveKDF(nil)":    func() { _, _ = Default.DeriveKDF("HKDF", nil, 32) },
		"DeriveKDF(bad)":    func() { _, _ = Default.DeriveKDF("HKDF", KDFParams{"x": 1.5}, 32) },
		"DeriveShared(0)":   func() { _, _ = DeriveSharedKey([]byte("s"), "c", 0) },
		"DeriveShared(-1)":  func() { _, _ = DeriveSharedKey([]byte("s"), "c", -1) },
		"NewAEAD(nilkey)":   func() { _, _ = Default.NewAEAD("AES-256-GCM", nil) },
		"NewAEAD(noname)":   func() { _, _ = Default.NewAEAD("", nil) },
		"NewHash(noname)":   func() { _, _ = Default.NewHash("") },
		"NewHMAC(noname)":   func() { _, _ = Default.NewHMAC("", nil) },
		"NewCMAC(noname)":   func() { _, _ = Default.NewCMAC("", nil) },
		"NewKMAC(0)":        func() { _, _ = Default.NewKMAC(0, nil, 0, nil) },
		"NewKMAC(neg)":      func() { _, _ = Default.NewKMAC(128, nil, -1, nil) },
		"GenKey(noname)":    func() { _, _ = Default.GenerateKey("") },
		"GenKey(negbits)":   func() { _, _ = Default.GenerateKey("RSA", WithRSABits(-1)) },
		"GenKey(nogroup)":   func() { _, _ = Default.GenerateKey("EC", WithGroup("")) },
		"GenKey(badparam)":  func() { _, _ = Default.GenerateKey("EC", WithParam("nope", 1.5)) },
		"ParsePKCS8(nil)":   func() { _, _ = Default.ParsePKCS8PrivateKey(nil) },
		"ParseSPKI(nil)":    func() { _, _ = Default.ParseSPKIPublicKey(nil) },
		"ParseSEC1(nil)":    func() { _, _ = Default.ParseSEC1PrivateKey(nil) },
		"ParseRawPriv(nil)": func() { _, _ = Default.ParseRawPrivateKey("ED25519", nil) },
		"ParseRawPub(nil)":  func() { _, _ = Default.ParseRawPublicKey("ED25519", nil) },
		"ParseRawPriv(bad)": func() { _, _ = Default.ParseRawPrivateKey("", []byte{1}) },
		"LoadKey(empty)":    func() { _, _ = Default.LoadKey("") },
		"ListStore(empty)":  func() { _, _ = Default.ListStore("") },
		"LoadProvider(no)":  func() { _, _ = Default.LoadProvider("") },
		"InitSecure(0)":     func() { _ = InitSecureHeap(0, 0) },
		"InitSecure(neg)":   func() { _ = InitSecureHeap(-1, -1) },
		"NewSecureBuf(0)":   func() { _, _ = NewSecureBuffer(0) },
		"NewSecureBuf(neg)": func() { _, _ = NewSecureBuffer(-1) },
		"NewFIPSCtx(empty)": func() { _, _ = NewFIPSContext("") },
	}
	for name, fn := range cases {
		mustNotPanic(t, name, fn)
	}
}

// Every handle, used after Close.
func TestAbuseUseAfterClose(t *testing.T) {
	h, err := Default.NewHash("SHA2-256")
	if err != nil {
		t.Fatal(err)
	}
	h.Close()

	m, err := Default.NewHMAC("SHA2-256", []byte("k"))
	if err != nil {
		t.Fatal(err)
	}
	m.Close()

	a, err := Default.NewAEAD("AES-256-GCM", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	a.Close()

	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSigner(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(k, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	v.Close()
	k.Close()
	peer.Close()

	c, err := NewContext()
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.LoadProvider("default")
	if err != nil {
		t.Fatal(err)
	}
	p.Unload()
	c.Close()

	cases := map[string]func(){
		"hash.Write":  func() { _, _ = h.Write([]byte("x")) },
		"hash.Sum":    func() { _ = h.Sum(nil) },
		"hash.SumXOF": func() { _, _ = h.SumXOF(32) },
		"hash.Reset":  func() { h.Reset() },
		"hash.Close2": func() { _ = h.Close() },

		"mac.Write":  func() { _, _ = m.Write([]byte("x")) },
		"mac.Sum":    func() { _ = m.Sum(nil) },
		"mac.Reset":  func() { m.Reset() },
		"mac.Close2": func() { _ = m.Close() },

		"aead.SealErr": func() { _, _ = a.SealErr(nil, make([]byte, 12), []byte("p"), nil) },
		"aead.Open":    func() { _, _ = a.Open(nil, make([]byte, 12), make([]byte, 32), nil) },
		"aead.Nonce":   func() { _ = a.NonceSize() },
		"aead.Close2":  func() { _ = a.Close() },

		"key.Sign":    func() { _, _ = k.Sign([]byte("m"), nil) },
		"key.Verify":  func() { _ = k.Verify([]byte("m"), []byte("s"), nil) },
		"key.Type":    func() { _ = k.Type() },
		"key.Public":  func() { _, _ = k.Public() },
		"key.Marshal": func() { _, _ = k.MarshalPKCS8() },
		"key.Derive":  func() { _, _ = k.Derive(peer, nil) },
		"key.Encaps":  func() { _, _, _ = k.Encapsulate() },
		"key.Decaps":  func() { _, _ = k.Decapsulate([]byte("c")) },
		"key.Encrypt": func() { _, _ = k.Encrypt([]byte("m"), nil) },
		"key.MaxOAEP": func() { _, _ = k.MaxOAEPPlaintext(nil) },
		"key.Close2":  func() { _ = k.Close() },

		"signer.Write":  func() { _, _ = s.Write([]byte("x")) },
		"signer.Sign":   func() { _, _ = s.Sign() },
		"signer.Close2": func() { _ = s.Close() },
		"verif.Write":   func() { _, _ = v.Write([]byte("x")) },
		"verif.Verify":  func() { _ = v.Verify([]byte("s")) },
		"verif.Close2":  func() { _ = v.Close() },

		"prov.Unload2":    func() { _ = p.Unload() },
		"prov.SelfTest":   func() { _ = p.SelfTest() },
		"ctx.NewHash":     func() { _, _ = c.NewHash("SHA2-256") },
		"ctx.Providers":   func() { _, _ = c.Providers() },
		"ctx.GenerateKey": func() { _, _ = c.GenerateKey("ED25519") },
		"ctx.Close2":      func() { _ = c.Close() },
	}
	for name, fn := range cases {
		mustNotPanic(t, name, fn)
	}
}

// Wrong sizes and shapes at every operation that takes them.
func TestAbuseWrongSizes(t *testing.T) {
	a, err := Default.NewAEAD("AES-256-GCM", make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	k, err := Default.GenerateKey("EC", WithGroup("P-256"))
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	rsa, err := Default.GenerateKey("RSA")
	if err != nil {
		t.Fatal(err)
	}
	defer rsa.Close()
	mlkem, err := Default.GenerateKey("ML-KEM-768")
	if err != nil {
		t.Fatal(err)
	}
	defer mlkem.Close()

	huge := make([]byte, 1<<16)

	cases := map[string]func(){
		"seal short nonce": func() { _, _ = a.SealErr(nil, make([]byte, 1), []byte("p"), nil) },
		"seal long nonce":  func() { _, _ = a.SealErr(nil, huge, []byte("p"), nil) },
		"seal nil nonce":   func() { _, _ = a.SealErr(nil, nil, []byte("p"), nil) },
		"open short ct":    func() { _, _ = a.Open(nil, make([]byte, 12), []byte{1}, nil) },
		"open nil ct":      func() { _, _ = a.Open(nil, make([]byte, 12), nil, nil) },
		"open huge ct":     func() { _, _ = a.Open(nil, make([]byte, 12), huge, nil) },

		"verify empty sig":  func() { _ = k.Verify([]byte("m"), nil, nil) },
		"verify huge sig":   func() { _ = k.Verify([]byte("m"), huge, nil) },
		"verify nil msg":    func() { _ = k.Verify(nil, huge, nil) },
		"sign nil msg":      func() { _, _ = k.Sign(nil, nil) },
		"sign huge context": func() { _, _ = k.Sign(nil, &SignOptions{Context: huge}) },
		"sign bad digest":   func() { _, _ = k.Sign(nil, &SignOptions{Digest: "NOPE"}) },
		"sign bad saltlen":  func() { _, _ = rsa.Sign(nil, &SignOptions{PSSSaltLen: -99}) },
		"sign huge saltlen": func() { _, _ = rsa.Sign(nil, &SignOptions{PSSSaltLen: 1 << 20}) },

		"oaep huge pt":      func() { _, _ = rsa.Encrypt(huge, nil) },
		"oaep huge label":   func() { _, _ = rsa.Encrypt([]byte("m"), &OAEPOptions{Label: huge}) },
		"oaep bad hash":     func() { _, _ = rsa.Encrypt([]byte("m"), &OAEPOptions{Hash: "NOPE"}) },
		"oaep decrypt junk": func() { _, _ = rsa.Decrypt(huge, nil) },
		"oaep max bad hash": func() { _, _ = rsa.MaxOAEPPlaintext(&OAEPOptions{Hash: "NOPE"}) },

		"decaps short": func() { _, _ = mlkem.Decapsulate([]byte{1}) },
		"decaps huge":  func() { _, _ = mlkem.Decapsulate(huge) },
		"derive self":  func() { _, _ = k.Derive(k, nil) },
		"derive rsa":   func() { _, _ = k.Derive(rsa, nil) },
		"derive cofac": func() { _, _ = mlkem.Derive(mlkem, &DeriveOptions{CofactorMode: true}) },

		"parse junk pkcs8": func() { _, _ = Default.ParsePKCS8PrivateKey(huge) },
		"parse junk spki":  func() { _, _ = Default.ParseSPKIPublicKey(huge) },
		"parse raw wrong":  func() { _, _ = Default.ParseRawPrivateKey("ED25519", huge) },
		"loadkey junk uri": func() { _, _ = Default.LoadKey(string(huge)) },
	}
	for name, fn := range cases {
		mustNotPanic(t, name, fn)
	}
}

// Options applied to every algorithm, including where they make no sense.
func TestAbuseCrossAlgorithmOptions(t *testing.T) {
	algs := []struct {
		name KeyAlgorithm
		opts []KeyOption
	}{
		{"RSA", nil},
		{"EC", []KeyOption{WithGroup("P-256")}},
		{"ED25519", nil},
		{"ED448", nil},
		{"ML-DSA-65", nil},
		{"ML-KEM-768", nil},
		{"X25519", nil},
	}
	signOpts := []*SignOptions{
		nil,
		{},
		{Digest: "SHA2-512"},
		{Context: []byte("ctx")},
		{Prehash: true},
		{Padding: RSAPKCS1v15},
		{PSSSaltLen: PSSSaltLengthMax},
		{Deterministic: true},
		{Context: []byte("ctx"), Prehash: true, Deterministic: true, Padding: RSAPKCS1v15},
	}

	for _, a := range algs {
		k, err := Default.GenerateKey(a.name, a.opts...)
		if err != nil {
			t.Fatalf("%s: %v", a.name, err)
		}
		for i, o := range signOpts {
			mustNotPanic(t, fmt.Sprintf("%s sign opts[%d]", a.name, i), func() {
				sig, err := k.Sign([]byte("m"), o)
				if err == nil {
					_ = k.Verify([]byte("m"), sig, o)
				}
			})
			mustNotPanic(t, fmt.Sprintf("%s newsigner opts[%d]", a.name, i), func() {
				if s, err := NewSigner(k, o); err == nil {
					s.Write([]byte("m"))
					s.Sign()
					s.Close()
				}
			})
		}
		// Operations the algorithm has no business supporting.
		mustNotPanic(t, string(a.name)+" encrypt", func() { _, _ = k.Encrypt([]byte("m"), nil) })
		mustNotPanic(t, string(a.name)+" decrypt", func() { _, _ = k.Decrypt([]byte("cccccccc"), nil) })
		mustNotPanic(t, string(a.name)+" encapsulate", func() { _, _, _ = k.Encapsulate() })
		mustNotPanic(t, string(a.name)+" decapsulate", func() { _, _ = k.Decapsulate([]byte("cccccccc")) })
		mustNotPanic(t, string(a.name)+" derive-self", func() { _, _ = k.Derive(k, nil) })
		mustNotPanic(t, string(a.name)+" marshalSEC1", func() { _, _ = k.MarshalSEC1() })
		mustNotPanic(t, string(a.name)+" marshalRaw", func() { _, _ = k.MarshalRawPrivateKey() })
		mustNotPanic(t, string(a.name)+" public", func() { _, _ = k.Public() })
		k.Close()
	}
}

// AEAD option combinations, including ones that must be rejected.
func TestAbuseAEADConstruction(t *testing.T) {
	names := []CipherName{"AES-256-GCM", "AES-256-CCM", "ChaCha20-Poly1305", "AES-256-OCB", "AES-256-CBC", "NOPE"}
	sizes := []int{-1, 0, 1, 7, 12, 16, 17, 1 << 20}

	for _, n := range names {
		for _, iv := range sizes {
			for _, tag := range sizes {
				mustNotPanic(t, fmt.Sprintf("NewAEAD(%s,iv=%d,tag=%d)", n, iv, tag), func() {
					a, err := Default.NewAEAD(n, make([]byte, 32), WithIVSize(iv), WithTagSize(tag))
					if err != nil {
						return
					}
					defer a.Close()
					nonce := make([]byte, a.NonceSize())
					ct, err := a.SealErr(nil, nonce, []byte("p"), []byte("a"))
					if err != nil {
						return
					}
					_, _ = a.Open(nil, nonce, ct, []byte("a"))
				})
			}
		}
	}
}

// Cost and size parameters that arrive as integers are the ones an attacker
// controls most cheaply. Each of these was a real way to take the process
// down before it was bounded: a negative PBKDF2 count became 4294967295
// uninterruptible iterations, and a large output length was a multi-gigabyte
// Go allocation made before OpenSSL was ever called.
func TestAbuseCostAndSizeParametersAreBounded(t *testing.T) {
	const huge = 1 << 34 // 16 GiB

	t.Run("pbkdf2 negative iterations", func(t *testing.T) {
		if _, err := Default.PBKDF2("SHA2-256", []byte("p"), make([]byte, 16), -1, 32); err == nil {
			t.Fatal("accepted a negative iteration count")
		}
	})
	t.Run("pbkdf2 zero iterations", func(t *testing.T) {
		if _, err := Default.PBKDF2("SHA2-256", []byte("p"), make([]byte, 16), 0, 32); err == nil {
			t.Fatal("accepted a zero iteration count")
		}
	})
	t.Run("pbkdf2 excessive iterations", func(t *testing.T) {
		if _, err := Default.PBKDF2("SHA2-256", []byte("p"), make([]byte, 16), maxPBKDF2Iterations+1, 32); err == nil {
			t.Fatal("accepted an iteration count above the maximum")
		}
	})
	t.Run("pbkdf2 accepts a sane count", func(t *testing.T) {
		if _, err := Default.PBKDF2("SHA2-256", []byte("p"), make([]byte, 16), 1000, 32); err != nil {
			t.Fatalf("rejected a legitimate iteration count: %v", err)
		}
	})

	t.Run("argon2id excessive cost", func(t *testing.T) {
		for _, ap := range []Argon2idParams{
			{Iterations: maxArgon2Iterations + 1},
			{MemoryKiB: maxArgon2MemoryKiB + 1},
			{Lanes: maxArgon2Lanes + 1},
		} {
			if _, err := Default.Argon2id([]byte("p"), make([]byte, 16), ap, 32); err == nil {
				t.Errorf("accepted %+v", ap)
			}
		}
	})

	t.Run("output lengths bounded", func(t *testing.T) {
		checks := map[string]func() error{
			"DigestXOF":  func() error { _, e := DigestXOF("SHAKE-256", []byte("x"), huge); return e },
			"HKDF":       func() error { _, e := Default.HKDF("SHA2-256", []byte("s"), nil, nil, huge); return e },
			"HKDFExpand": func() error { _, e := Default.HKDFExpand("SHA2-256", []byte("s"), nil, huge); return e },
			"PBKDF2":     func() error { _, e := Default.PBKDF2("SHA2-256", []byte("p"), make([]byte, 16), 1000, huge); return e },
			"DeriveKDF": func() error {
				_, e := Default.DeriveKDF("HKDF", KDFParams{"digest": "SHA2-256", "key": []byte("s")}, huge)
				return e
			},
			"DeriveSharedKey": func() error { _, e := DeriveSharedKey([]byte("s"), "c", huge); return e },
			"NewSecureBuffer": func() error { _, e := NewSecureBuffer(huge); return e },
		}
		for name, fn := range checks {
			if err := fn(); err == nil {
				t.Errorf("%s accepted a %d-byte output length", name, huge)
			}
		}
	})
}

// A failed provider load must not take the context's existing algorithms
// down with it.
//
// OSSL_PROVIDER_load turns off a context's implicit fallback to the default
// provider, and does so even when the load fails. On a context that had not
// yet activated anything -- which Default has not, until its first
// successful fetch -- one failed load left every later fetch returning
// "unsupported" for the life of the process. It surfaced as most of this
// suite failing depending on Go's randomised map iteration order, because
// whether anything had fetched first decided whether the damage was visible.
//
// This runs in a subprocess so the probe happens before any other test has
// warmed the global context, which is the only state in which the bug
// reproduces.
func TestFailedProviderLoadDoesNotKillTheContext(t *testing.T) {
	if os.Getenv("OSSL_PROVIDER_POISON_CHILD") == "1" {
		// Deliberately first: no successful fetch has run yet.
		if _, err := Default.LoadProvider("no-such-provider"); err == nil {
			t.Log("RESULT: load-unexpectedly-succeeded")
			return
		}
		if _, err := Digest(SHA256, []byte("x")); err != nil {
			t.Logf("RESULT: context-killed (%v)", err)
		} else {
			t.Log("RESULT: context-survived")
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestFailedProviderLoadDoesNotKillTheContext", "-test.v")
	cmd.Env = append(os.Environ(), "OSSL_PROVIDER_POISON_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	got := string(out)
	switch {
	case strings.Contains(got, "RESULT: context-survived"):
	case strings.Contains(got, "RESULT: context-killed"):
		t.Error("a failed provider load disabled the default provider for the whole process")
	default:
		t.Fatalf("subprocess produced no usable RESULT marker:\n%s", got)
	}
}
