package ossl

/*
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

// Context is an isolated OSSL_LIB_CTX: its own provider set, default
// property query, and RNG/DRBG state, independent of every other Context and
// of the implicit global default that a NULL libctx means in the C API.
//
// A library embedding OpenSSL should not rely on that global default: two
// unrelated consumers sharing a process (two callers of this package, a
// plugin loaded into a larger binary) would otherwise fight over the same
// global provider list and property defaults. Context gives each one its own
// sandbox. Every later fetch in this package threads a *Context through for
// exactly this reason.
type Context struct {
	ctx *C.OSSL_LIB_CTX
}

// Default is the implicit global library context -- what a NULL libctx means
// throughout the C API. It is what this package uses unless a caller
// supplies a Context of their own.
var Default = &Context{}

// NewContext creates a new, isolated library context with no providers
// loaded and no default properties set.
func NewContext() (*Context, error) {
	clearErrors()
	ctx := C.OSSL_LIB_CTX_new()
	if ctx == nil {
		return nil, newError("OSSL_LIB_CTX_new")
	}
	return &Context{ctx: ctx}, nil
}

// SetDefaultProperties pins a property query onto this context, so every
// fetch made through it is filtered without repeating the query at each call
// site. This is the mechanism that lets a context become, for example,
// "FIPS-only" (propq "fips=yes") or restricted to one provider (propq
// "provider=default") by construction, rather than by caller discipline at
// every call site.
//
// Calling this on Default affects the process-wide global context, exactly
// as EVP_set_default_properties(NULL, ...) does in the C API -- which is
// precisely the shared-state hazard Context exists to let callers avoid by
// using a context of their own instead.
func (c *Context) SetDefaultProperties(propq string) error {
	clearErrors()
	cq := C.CString(propq)
	defer C.free(unsafe.Pointer(cq))
	if C.EVP_set_default_properties(c.ptr(), cq) != 1 {
		return newError("EVP_set_default_properties")
	}
	return nil
}

// Close releases the context. Safe to call more than once. Closing Default
// is a no-op: its underlying pointer is already NULL, so there is nothing to
// free.
func (c *Context) Close() error {
	if c.ctx != nil {
		C.OSSL_LIB_CTX_free(c.ctx)
		c.ctx = nil
	}
	return nil
}

// ptr returns the underlying *C.OSSL_LIB_CTX, or NULL for both a nil
// *Context and Default -- exactly what every EVP_*_fetch call expects for
// "use the implicit global context". This is the accessor every later
// file's fetch calls thread a *Context through.
func (c *Context) ptr() *C.OSSL_LIB_CTX {
	if c == nil {
		return nil
	}
	return c.ctx
}
