//go:build cgo

package ossl

/*
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <stdlib.h>
#include <string.h>

// Collecting names from OpenSSL's do_all_provided iterators.
//
// Each iterator takes a C callback. Rather than route those back into Go --
// which needs an //export'd function in a file that may hold no other
// preamble, awkward for a package this size -- the callback stays on the C
// side and appends into a fixed-capacity array. Go walks the result after
// the iteration returns, so no Go pointer is ever live inside the callback.
//
// The names are strdup'd because EVP_MD_get0_name and friends return storage
// owned by the algorithm object, which is only guaranteed for the duration
// of the callback.
#define OSSL_MAX_NAMES 512

typedef struct {
    char *items[OSSL_MAX_NAMES];
    int   count;
    int   overflow;
} ossl_name_list;

static void ossl_name_append(ossl_name_list *l, const char *name) {
    if (name == NULL) return;
    if (l->count >= OSSL_MAX_NAMES) { l->overflow = 1; return; }
    for (int i = 0; i < l->count; i++)
        if (strcmp(l->items[i], name) == 0) return;   // one entry per algorithm
    l->items[l->count++] = strdup(name);
}

// Deliberately non-static, for the same linkage reason as
// ossl_collect_provider: cgo takes the address of these from Go.
void ossl_collect_md(EVP_MD *md, void *arg) {
    ossl_name_append((ossl_name_list *)arg, EVP_MD_get0_name(md));
}
void ossl_collect_cipher(EVP_CIPHER *c, void *arg) {
    ossl_name_append((ossl_name_list *)arg, EVP_CIPHER_get0_name(c));
}
void ossl_collect_mac(EVP_MAC *m, void *arg) {
    ossl_name_append((ossl_name_list *)arg, EVP_MAC_get0_name(m));
}
void ossl_collect_kdf(EVP_KDF *k, void *arg) {
    ossl_name_append((ossl_name_list *)arg, EVP_KDF_get0_name(k));
}

static char *ossl_name_at(ossl_name_list *l, int i) { return l->items[i]; }

// Resolving a curve name to a NID, accepting every spelling EVP does: the
// NIST name ("P-256"), the OpenSSL short name ("prime256v1"), or an OID.
static int ossl_curve_nid(const char *name) {
    int nid = EC_curve_nist2nid(name);
    if (nid != NID_undef) return nid;
    nid = OBJ_sn2nid(name);
    if (nid != NID_undef) return nid;
    return OBJ_txt2nid(name);
}

// The name to report for a curve: the NIST one where it has it, since that
// is what standards and this package's constants use.
static const char *ossl_curve_display_name(int nid) {
    const char *nist = EC_curve_nid2nist(nid);
    if (nist != NULL) return nist;
    return OBJ_nid2sn(nid);
}

static void ossl_name_list_free(ossl_name_list *l) {
    for (int i = 0; i < l->count; i++) free(l->items[i]);
    l->count = 0;
}
*/
import "C"

import (
	"fmt"
	"sort"
	"unsafe"
)

// collect runs one of the do_all_provided iterators and returns the names it
// produced, sorted.
func (c *Context) collect(run func(*C.ossl_name_list)) ([]string, error) {
	var list C.ossl_name_list
	run(&list)
	defer C.ossl_name_list_free(&list)

	if list.overflow != 0 {
		return nil, fmt.Errorf("ossl: more than %d algorithms provided; the enumeration would be truncated",
			C.OSSL_MAX_NAMES)
	}
	out := make([]string, 0, int(list.count))
	for i := 0; i < int(list.count); i++ {
		out = append(out, C.GoString(C.ossl_name_at(&list, C.int(i))))
	}
	sort.Strings(out)
	return out, nil
}

// ListDigests reports every digest this context can actually fetch.
//
// Two things are going on, and conflating them produces a list that lies.
// OpenSSL's iterator walks what the loaded providers *supply*, which ignores
// the context's default property query entirely: a FIPS-restricted context
// that also has the default provider loaded enumerates MD5 quite happily,
// and then refuses to fetch it. So each name is confirmed with a real fetch
// before being reported, which makes the list mean "usable here" rather than
// "present somewhere".
//
// The result is therefore narrower than the constants in this package for a
// restricted context, and wider for one with a vendor provider loaded.
func (c *Context) ListDigests() ([]DigestName, error) {
	if c == nil {
		return nil, ErrClosed
	}
	names, err := c.collect(func(l *C.ossl_name_list) {
		C.EVP_MD_do_all_provided(c.ptr(), (*[0]byte)(C.ossl_collect_md), unsafe.Pointer(l))
	})
	if err != nil {
		return nil, err
	}
	out := make([]DigestName, 0, len(names))
	for _, n := range names {
		if d := DigestName(n); c.DigestAvailable(d, "") {
			out = append(out, d)
		}
	}
	return out, nil
}

// ListCiphers reports every symmetric cipher this context can actually
// fetch, AEAD and otherwise. Filtered the same way as ListDigests.
func (c *Context) ListCiphers() ([]CipherName, error) {
	if c == nil {
		return nil, ErrClosed
	}
	names, err := c.collect(func(l *C.ossl_name_list) {
		C.EVP_CIPHER_do_all_provided(c.ptr(), (*[0]byte)(C.ossl_collect_cipher), unsafe.Pointer(l))
	})
	if err != nil {
		return nil, err
	}
	out := make([]CipherName, 0, len(names))
	for _, n := range names {
		if v := CipherName(n); c.CipherAvailable(v, "") {
			out = append(out, v)
		}
	}
	return out, nil
}

// ListMACs reports every MAC reachable through this context.
func (c *Context) ListMACs() ([]MACName, error) {
	if c == nil {
		return nil, ErrClosed
	}
	names, err := c.collect(func(l *C.ossl_name_list) {
		C.EVP_MAC_do_all_provided(c.ptr(), (*[0]byte)(C.ossl_collect_mac), unsafe.Pointer(l))
	})
	if err != nil {
		return nil, err
	}
	out := make([]MACName, len(names))
	for i, n := range names {
		out[i] = MACName(n)
	}
	return out, nil
}

// ListKDFs reports every key derivation function reachable through this
// context.
func (c *Context) ListKDFs() ([]KDFName, error) {
	if c == nil {
		return nil, ErrClosed
	}
	names, err := c.collect(func(l *C.ossl_name_list) {
		C.EVP_KDF_do_all_provided(c.ptr(), (*[0]byte)(C.ossl_collect_kdf), unsafe.Pointer(l))
	})
	if err != nil {
		return nil, err
	}
	out := make([]KDFName, len(names))
	for i, n := range names {
		out[i] = KDFName(n)
	}
	return out, nil
}

// ListCurves reports the elliptic curves this build was compiled with.
//
// Unlike the other lists this is a property of the library rather than of a
// context: curves come from libcrypto's built-in table, and a provider
// restricts which are usable rather than which exist. Use SupportsSignature
// or Supports to find out whether a particular curve is usable here.
func ListCurves() ([]Curve, error) {
	n := C.EC_get_builtin_curves(nil, 0)
	if n == 0 {
		return nil, nil
	}
	buf := make([]C.EC_builtin_curve, int(n))
	got := C.EC_get_builtin_curves(&buf[0], C.size_t(n))

	out := make([]Curve, 0, int(got))
	for i := 0; i < int(got); i++ {
		// Report the NIST spelling where the curve has one -- "P-256"
		// rather than "prime256v1" -- because that is what standards, this
		// package's constants and citius-server's EllipticCurve enum use.
		// EVP accepts either.
		if s := C.ossl_curve_display_name(buf[i].nid); s != nil {
			out = append(out, Curve(C.GoString(s)))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// ParseDigestName validates a digest name against this context.
//
// Converting a string to DigestName is an ordinary Go conversion and cannot
// fail, so a name that arrived from a config file or a request is only found
// to be wrong several calls later, inside a fetch. This is the boundary
// check: it asks the context whether the name resolves here, which is the
// same question the eventual operation will ask.
func (c *Context) ParseDigestName(s string) (DigestName, error) {
	if c == nil {
		return "", ErrClosed
	}
	d := DigestName(s)
	if s == "" || !c.DigestAvailable(d, "") {
		return "", fmt.Errorf("ossl: %q is not a digest available in this context", s)
	}
	return d, nil
}

// ParseCipherName validates a cipher name against this context.
func (c *Context) ParseCipherName(s string) (CipherName, error) {
	if c == nil {
		return "", ErrClosed
	}
	n := CipherName(s)
	if s == "" || !c.CipherAvailable(n, "") {
		return "", fmt.Errorf("ossl: %q is not a cipher available in this context", s)
	}
	return n, nil
}

// ParseKeyAlgorithm validates an asymmetric algorithm name against this
// context.
func (c *Context) ParseKeyAlgorithm(s string) (KeyAlgorithm, error) {
	if c == nil {
		return "", ErrClosed
	}
	a := KeyAlgorithm(s)
	if s == "" || !c.KeyAlgorithmAvailable(a) {
		return "", fmt.Errorf("ossl: %q is not a key algorithm available in this context", s)
	}
	return a, nil
}

// ParseMACName validates a MAC name against this context.
func (c *Context) ParseMACName(s string) (MACName, error) {
	if c == nil {
		return "", ErrClosed
	}
	if s == "" {
		return "", fmt.Errorf("ossl: empty MAC name")
	}
	names, err := c.ListMACs()
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if string(n) == s {
			return n, nil
		}
	}
	return "", fmt.Errorf("ossl: %q is not a MAC available in this context", s)
}

// ParseKDFName validates a KDF name against this context.
func (c *Context) ParseKDFName(s string) (KDFName, error) {
	if c == nil {
		return "", ErrClosed
	}
	if s == "" {
		return "", fmt.Errorf("ossl: empty KDF name")
	}
	names, err := c.ListKDFs()
	if err != nil {
		return "", err
	}
	for _, n := range names {
		if string(n) == s {
			return n, nil
		}
	}
	return "", fmt.Errorf("ossl: %q is not a KDF available in this context", s)
}

// digestIsXOF reports whether the named digest is an extendable-output
// function, which cannot serve as a signature digest and must be finalised
// with SumXOF rather than Sum.
func (c *Context) digestIsXOF(name DigestName) (bool, error) {
	cname := C.CString(string(name))
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_MD_fetch(c.ptr(), cname, nil)
	if md == nil {
		clearErrors()
		return false, fmt.Errorf("ossl: digest %q is not available in this context", name)
	}
	defer C.EVP_MD_free(md)
	return C.EVP_MD_xof(md) != 0, nil
}

// digestSize reports the digest's output size in bytes.
func (c *Context) digestSize(name DigestName) (int, error) {
	cname := C.CString(string(name))
	defer C.free(unsafe.Pointer(cname))
	md := C.EVP_MD_fetch(c.ptr(), cname, nil)
	if md == nil {
		clearErrors()
		return 0, fmt.Errorf("ossl: digest %q is not available in this context", name)
	}
	defer C.EVP_MD_free(md)
	return int(C.EVP_MD_get_size(md)), nil
}

// cipherKeyLength reports the cipher's key size in bytes.
func (c *Context) cipherKeyLength(name CipherName) (int, error) {
	cname := C.CString(string(name))
	defer C.free(unsafe.Pointer(cname))
	ci := C.EVP_CIPHER_fetch(c.ptr(), cname, nil)
	if ci == nil {
		clearErrors()
		return 0, fmt.Errorf("ossl: cipher %q is not available in this context", name)
	}
	defer C.EVP_CIPHER_free(ci)
	return int(C.EVP_CIPHER_get_key_length(ci)), nil
}

// curveNID resolves a curve name to its NID, accepting any spelling EVP
// accepts, and reports NID_undef (0) for a name libcrypto does not know.
func curveNID(name Curve) int {
	cname := C.CString(string(name))
	defer C.free(unsafe.Pointer(cname))
	return int(C.ossl_curve_nid(cname))
}
