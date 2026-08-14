//go:build cgo

package ossl

/*
#include <openssl/store.h>
#include <openssl/evp.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// StoreObjectType identifies what a URI yielded.
type StoreObjectType int

const (
	// StoreUnknown is an object this package does not model.
	StoreUnknown StoreObjectType = iota
	// StorePrivateKey is a key pair, possibly one whose private half never
	// leaves a token.
	StorePrivateKey
	// StorePublicKey is a public key on its own.
	StorePublicKey
	// StoreCertificate is an X.509 certificate.
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

// LoadKey loads a private key from a URI through this context.
//
// The URI is anything the OSSL_STORE loaders installed in this context
// understand. Two matter in practice:
//
//	file:/etc/keys/server.pem
//	pkcs11:token=prod;object=signing-key;type=private?pin-value=...
//
// The second is the point of routing key loading through a URI at all. A
// key on an HSM is generally non-extractable: there is no PEM to parse and
// no bytes to hold, only a handle whose private operations happen on the
// token. The Key returned here signs and derives exactly like a software
// key -- MarshalPKCS8 on it fails, which is the intended behaviour rather
// than a limitation of this wrapper.
//
// Loading a pkcs11 URI requires the pkcs11 provider to be active in this
// context; see Context.LoadConfig.
func (c *Context) LoadKey(uri string) (*Key, error) {
	return c.loadKey(uri, C.OSSL_STORE_INFO_PKEY, "private key")
}

// LoadPublicKey loads a public key from a URI. Same URI forms as LoadKey.
func (c *Context) LoadPublicKey(uri string) (*Key, error) {
	return c.loadKey(uri, C.OSSL_STORE_INFO_PUBKEY, "public key")
}

// loadKey opens the URI, narrows the search to one object type, and returns
// the first match.
func (c *Context) loadKey(uri string, expect C.int, what string) (*Key, error) {
	if uri == "" {
		return nil, fmt.Errorf("ossl: empty store URI")
	}
	clearErrors()
	curi := C.CString(uri)
	defer C.free(unsafe.Pointer(curi))

	// A NULL UI_METHOD means no interactive prompting: a URI that needs a
	// passphrase or PIN must carry it (pin-value=) or come from a provider
	// configured with one. A library has no business reading a terminal.
	sctx := C.OSSL_STORE_open_ex(curi, c.ptr(), nil, nil, nil, nil, nil, nil)
	if sctx == nil {
		return nil, newError("OSSL_STORE_open_ex(" + uri + ")")
	}
	defer C.OSSL_STORE_close(sctx)

	// Narrowing up front matters for files holding several objects: without
	// it the first object wins even when it is the wrong kind.
	if C.OSSL_STORE_expect(sctx, expect) != 1 {
		return nil, newError("OSSL_STORE_expect")
	}

	for C.OSSL_STORE_eof(sctx) != 1 {
		info := C.OSSL_STORE_load(sctx)
		if info == nil {
			// A NULL that is not EOF is a real error; a NULL at EOF just
			// ends the loop on the next check.
			if C.OSSL_STORE_eof(sctx) == 1 {
				break
			}
			return nil, newError("OSSL_STORE_load")
		}

		var pkey *C.EVP_PKEY
		switch C.OSSL_STORE_INFO_get_type(info) {
		case C.OSSL_STORE_INFO_PKEY:
			pkey = C.OSSL_STORE_INFO_get1_PKEY(info)
		case C.OSSL_STORE_INFO_PUBKEY:
			pkey = C.OSSL_STORE_INFO_get1_PUBKEY(info)
		}
		C.OSSL_STORE_INFO_free(info)

		if pkey != nil {
			return &Key{pkey: pkey, ctx: c}, nil
		}
	}
	return nil, fmt.Errorf("ossl: no %s found at %s", what, uri)
}

// StoreObject is one item produced by ListStore.
type StoreObject struct {
	Type StoreObjectType
	// Name is set for StoreUnknown entries that are directory listings: a
	// file: URI naming a directory yields the URIs of its contents.
	Name string
}

// ListStore reports what a URI contains without loading any of it.
//
// Useful for a file: URI naming a directory, which yields the URIs of its
// entries, and for inspecting a token before deciding what to load.
func (c *Context) ListStore(uri string) ([]StoreObject, error) {
	if uri == "" {
		return nil, fmt.Errorf("ossl: empty store URI")
	}
	clearErrors()
	curi := C.CString(uri)
	defer C.free(unsafe.Pointer(curi))

	sctx := C.OSSL_STORE_open_ex(curi, c.ptr(), nil, nil, nil, nil, nil, nil)
	if sctx == nil {
		return nil, newError("OSSL_STORE_open_ex(" + uri + ")")
	}
	defer C.OSSL_STORE_close(sctx)

	var out []StoreObject
	for C.OSSL_STORE_eof(sctx) != 1 {
		info := C.OSSL_STORE_load(sctx)
		if info == nil {
			if C.OSSL_STORE_eof(sctx) == 1 {
				break
			}
			return nil, newError("OSSL_STORE_load")
		}
		obj := StoreObject{}
		switch C.OSSL_STORE_INFO_get_type(info) {
		case C.OSSL_STORE_INFO_PKEY:
			obj.Type = StorePrivateKey
		case C.OSSL_STORE_INFO_PUBKEY:
			obj.Type = StorePublicKey
		case C.OSSL_STORE_INFO_CERT:
			obj.Type = StoreCertificate
		case C.OSSL_STORE_INFO_NAME:
			obj.Type = StoreUnknown
			obj.Name = C.GoString(C.OSSL_STORE_INFO_get0_NAME(info))
		default:
			obj.Type = StoreUnknown
		}
		C.OSSL_STORE_INFO_free(info)
		out = append(out, obj)
	}
	return out, nil
}
