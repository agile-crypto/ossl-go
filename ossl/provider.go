//go:build cgo

package ossl

/*
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <stdlib.h>

// OSSL_PROVIDER_do_all wants a C callback, and cgo callbacks that call back
// into Go require an //export'd function whose file may contain no other
// preamble definitions -- awkward for a package with many files. Since all
// this needs is a bounded list of *currently loaded* providers, the
// callback instead stays entirely on the C side: it appends into a
// fixed-capacity C array, and Go only walks the result after
// OSSL_PROVIDER_do_all returns. No Go pointer ever crosses into the
// callback, so none of the cgo pointer-passing rules are even in play here.
#define MAX_PROVIDERS 64

typedef struct {
    OSSL_PROVIDER *items[MAX_PROVIDERS];
    int count;
} ossl_provider_list;

// Deliberately not "static": cgo's "take the address of this C function as
// a Go value" mechanism needs the symbol to have external linkage so the Go
// linker can resolve it across cgo's per-file object compilation. A static
// function here links fine when *called* from C, but fails at link time
// with "undefined reference" the moment its address is taken from Go.
int ossl_collect_provider(OSSL_PROVIDER *provider, void *cbdata) {
    ossl_provider_list *list = (ossl_provider_list *)cbdata;
    if (list->count < MAX_PROVIDERS)
        list->items[list->count++] = provider;
    return 1;
}

// ossl_provider_info queries a provider's name, version and active status in
// one call, keeping the OSSL_PARAM array itself entirely on the C side --
// its output-pointer entries (OSSL_PARAM_construct_utf8_ptr) write into the
// name/version out-parameters here, never into anything Go-owned.
static int ossl_provider_info(OSSL_PROVIDER *prov, const char **name,
                               const char **version, int *status) {
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_NAME, (char **)name, 0);
    params[1] = OSSL_PARAM_construct_utf8_ptr(OSSL_PROV_PARAM_VERSION, (char **)version, 0);
    params[2] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_STATUS, status);
    params[3] = OSSL_PARAM_construct_end();
    return OSSL_PROVIDER_get_params(prov, params);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// Provider is a loaded OpenSSL provider: "default", "legacy", "fips", or a
// third-party module such as a PKCS#11 provider. It supplies the actual
// algorithm implementations every EVP_*_fetch call resolves against.
type Provider struct {
	prov *C.OSSL_PROVIDER
}

// LoadProvider loads a provider module by name into this context. Loading an
// already-active provider returns the existing instance with its reference
// count incremented, not a second copy.
//
// Do not call this with "fips" unless a config carrying the module MAC is
// already in scope for the context. A FIPS load that fails self-test puts
// the module into a process-wide error state that no later, correct
// activation can recover from. Context.EnableFIPS orders the steps so that
// cannot happen.
func (c *Context) LoadProvider(name ProviderName) (*Provider, error) {
	if c == nil {
		return nil, ErrClosed
	}
	clearErrors()
	cname := C.CString(string(name))
	defer C.free(unsafe.Pointer(cname))
	// A failed load must not take the context's existing algorithms with it.
	//
	// OSSL_PROVIDER_load turns off a context's implicit fallback to the
	// default provider, and does so even when the load fails. Verified
	// directly: on a context that had not yet activated anything -- which
	// Default has not, until its first successful fetch -- one failed
	// LoadProvider("") left every later fetch returning "unsupported" for
	// the life of the process. A caller probing whether a provider exists
	// would lose all cryptography.
	//
	// Loading with retain_fallbacks set avoids disabling the fallback, but
	// changes the success path too: the context then holds both the implicit
	// and the explicit provider, and freeing it aborted inside
	// OSSL_LIB_CTX_free. So the fallback is restored only on the failure
	// path, and only when it was there to begin with -- a context
	// deliberately narrowed to one provider keeps its narrowing.
	hadDefault := c.providerAvailable(ProviderDefault)
	prov := C.OSSL_PROVIDER_load(c.ptr(), cname)
	if prov == nil {
		err := newError("OSSL_PROVIDER_load(" + string(name) + ")")
		if hadDefault && !c.providerAvailable(ProviderDefault) {
			cdef := C.CString(string(ProviderDefault))
			defer C.free(unsafe.Pointer(cdef))
			// retain_fallbacks here so restoring does not itself disable
			// anything further.
			if p := C.OSSL_PROVIDER_try_load(c.ptr(), cdef, 1); p != nil {
				C.OSSL_PROVIDER_unload(p)
			}
			clearErrors()
		}
		return nil, err
	}
	return &Provider{prov: prov}, nil
}

// Unload releases this provider reference. Safe to call more than once: the
// pointer is cleared before the C call runs, so a second call is always a
// no-op regardless of whether the first call succeeded.
func (p *Provider) Unload() error {
	if p == nil || p.prov == nil {
		return nil
	}
	prov := p.prov
	p.prov = nil
	if C.OSSL_PROVIDER_unload(prov) != 1 {
		return newError("OSSL_PROVIDER_unload")
	}
	return nil
}

// ProviderAvailable reports whether a provider by that name is currently
// active in this context, without loading it.
func (c *Context) ProviderAvailable(name ProviderName) bool {
	if c == nil {
		return false
	}
	return c.providerAvailable(name)
}

func (c *Context) providerAvailable(name ProviderName) bool {
	cname := C.CString(string(name))
	defer C.free(unsafe.Pointer(cname))
	return C.OSSL_PROVIDER_available(c.ptr(), cname) == 1
}

// ProviderInfo describes one currently-loaded provider.
type ProviderInfo struct {
	Name    string
	Version string
	Active  bool
}

// Providers enumerates every provider currently loaded into this context.
//
// The collecting callback holds a fixed-capacity array, so a context with an
// implausible number of providers is reported as an error rather than
// silently returning a truncated list that a caller could mistake for the
// whole set.
func (c *Context) Providers() ([]ProviderInfo, error) {
	if c == nil {
		return nil, ErrClosed
	}
	clearErrors()
	var list C.ossl_provider_list
	if C.OSSL_PROVIDER_do_all(c.ptr(), (*[0]byte)(C.ossl_collect_provider), unsafe.Pointer(&list)) != 1 {
		return nil, newError("OSSL_PROVIDER_do_all")
	}
	if int(list.count) >= C.MAX_PROVIDERS {
		return nil, fmt.Errorf("ossl: more than %d providers loaded; enumeration would be truncated", C.MAX_PROVIDERS)
	}

	infos := make([]ProviderInfo, 0, int(list.count))
	for i := 0; i < int(list.count); i++ {
		prov := list.items[i]
		var name, version *C.char
		var status C.int
		if C.ossl_provider_info(prov, &name, &version, &status) != 1 {
			return nil, newError("OSSL_PROVIDER_get_params")
		}
		infos = append(infos, ProviderInfo{
			Name:    C.GoString(name),
			Version: C.GoString(version),
			Active:  status != 0,
		})
	}
	return infos, nil
}

// KeyAlgorithmAvailable reports whether an asymmetric algorithm can be used
// through this context, without generating a key.
//
// Key algorithms are not fetched like digests and ciphers; the check is
// whether a key-management context can be constructed for the name, which is
// what GenerateKey and every parser do first.
func (c *Context) KeyAlgorithmAvailable(algorithm KeyAlgorithm) bool {
	if c == nil || algorithm == "" {
		return false
	}
	calg := C.CString(string(algorithm))
	defer C.free(unsafe.Pointer(calg))
	kctx := C.EVP_PKEY_CTX_new_from_name(c.ptr(), calg, nil)
	ok := kctx != nil
	if kctx != nil {
		C.EVP_PKEY_CTX_free(kctx)
	}
	clearErrors()
	return ok
}

// DigestAvailable reports whether a digest algorithm can be fetched through
// this context, without constructing anything durable for the check. propq
// is an optional property query overriding any default properties pinned on
// the context via SetDefaultProperties; pass "" to use the context's own
// default.
func (c *Context) DigestAvailable(name DigestName, propq PropertyQuery) bool {
	if c == nil {
		return false
	}
	cname := C.CString(string(name))
	defer C.free(unsafe.Pointer(cname))
	var cq *C.char
	if propq != "" {
		cq = C.CString(string(propq))
		defer C.free(unsafe.Pointer(cq))
	}
	md := C.EVP_MD_fetch(c.ptr(), cname, cq)
	ok := md != nil
	if md != nil {
		C.EVP_MD_free(md)
	}
	clearErrors()
	return ok
}

// CipherAvailable reports whether a symmetric cipher can be fetched through
// this context. propq behaves as in DigestAvailable.
func (c *Context) CipherAvailable(name CipherName, propq PropertyQuery) bool {
	if c == nil {
		return false
	}
	cname := C.CString(string(name))
	defer C.free(unsafe.Pointer(cname))
	var cq *C.char
	if propq != "" {
		cq = C.CString(string(propq))
		defer C.free(unsafe.Pointer(cq))
	}
	cipher := C.EVP_CIPHER_fetch(c.ptr(), cname, cq)
	ok := cipher != nil
	if cipher != nil {
		C.EVP_CIPHER_free(cipher)
	}
	clearErrors()
	return ok
}
