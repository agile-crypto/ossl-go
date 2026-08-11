package ossl

/*
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"path/filepath"
	"unsafe"
)

// ConfigDir is the OPENSSLDIR of the linked library -- where openssl.cnf and
// fipsmodule.cnf live.
func ConfigDir() string {
	return C.GoString(C.OPENSSL_info(C.OPENSSL_INFO_CONFIG_DIR))
}

// ModulesDir is where provider modules (fips.so, legacy.so) are loaded from.
func ModulesDir() string {
	return C.GoString(C.OPENSSL_info(C.OPENSSL_INFO_MODULES_DIR))
}

// DefaultFIPSModuleConfig is the conventional path of fipsmodule.cnf, the
// file `openssl fipsinstall` writes. It records the module's HMAC over
// fips.so, which is the integrity check that stops a patched module being
// swapped in, and the FIPS provider will not activate without it.
//
// This is a path, not a promise: the file exists only if fipsinstall has
// been run on this installation.
func DefaultFIPSModuleConfig() string {
	return filepath.Join(ConfigDir(), "fipsmodule.cnf")
}

// LoadConfig applies an OpenSSL configuration file to this context.
//
// A config whose provider section says activate = 1 does bring that provider
// up: after loading a config that includes fipsmodule.cnf,
// ProviderAvailable("fips") is true and fips=yes fetches resolve, with no
// further call. What it does not do is restrict anything -- see EnableFIPS.
func (c *Context) LoadConfig(path string) error {
	clearErrors()
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))
	if C.OSSL_LIB_CTX_load_config(c.ptr(), cpath) != 1 {
		return newError("OSSL_LIB_CTX_load_config(" + path + ")")
	}
	return nil
}

// SelfTest runs the provider's self-test. The FIPS provider runs its
// power-on self-tests at load time; this re-runs them on demand, which
// FIPS 140-3 operational guidance expects to be available.
func (p *Provider) SelfTest() error {
	if p.prov == nil {
		return ErrClosed
	}
	clearErrors()
	if C.OSSL_PROVIDER_self_test(p.prov) != 1 {
		return newError("OSSL_PROVIDER_self_test")
	}
	return nil
}

// EnableFIPS makes this context FIPS-only: every fetch through it resolves
// against the validated module, with no per-call property query.
//
// "FIPS mode" in OpenSSL 3.x is not a global switch. It is a config file
// that carries the module's recorded MAC, plus a property query restricting
// fetches to the validated module. Loading the config activates the provider
// on its own; the explicit load here is for the handle, so the self-test can
// be run and so the reference lives exactly as long as the context.
//
// Restricting the context is the step that must not be skipped. A FIPS
// provider that is loaded but never property-queried changes nothing at all,
// because fetches quietly resolve to the default provider's unvalidated
// implementations instead -- a context that looks FIPS-enabled and is not.
//
// # Never load the FIPS provider without a config
//
// A bare LoadProvider("fips") with no config in scope does not simply fail.
// It fails with "missing config data" and takes the FIPS module into an
// error state that is process-wide and permanent:
//
//	error:1C8000D5:Provider routines::missing config data
//	error:1C8000E0:Provider routines::fips module entering error state
//
// Verified in a clean process: after that one failed attempt, a correct
// config-based activation in a brand new OSSL_LIB_CTX still reports the
// provider unavailable and every fips=yes fetch still fails. The damage is
// not scoped to the context that caused it and nothing short of restarting
// the process undoes it. Route every activation through here.
//
// The context keeps the provider reference and releases it on Close.
func (c *Context) EnableFIPS(configPath string) error {
	if c == nil || c.ctx == nil {
		return fmt.Errorf("ossl: EnableFIPS requires a Context from NewContext, " +
			"not the implicit global default")
	}
	if err := c.LoadConfig(configPath); err != nil {
		return err
	}
	prov, err := c.LoadProvider("fips")
	if err != nil {
		return fmt.Errorf("ossl: loading the fips provider after %s: %w", configPath, err)
	}
	if err := prov.SelfTest(); err != nil {
		prov.Unload()
		return err
	}
	clearErrors()
	if C.EVP_default_properties_enable_fips(c.ptr(), 1) != 1 {
		prov.Unload()
		return newError("EVP_default_properties_enable_fips")
	}
	c.fips = prov
	return nil
}

// FIPSEnabled reports whether this context has been restricted to the FIPS
// provider.
func (c *Context) FIPSEnabled() bool {
	return C.EVP_default_properties_is_fips_enabled(c.ptr()) == 1
}

// NewFIPSContext creates a context restricted to the FIPS provider.
//
// configPath must name an OpenSSL config that includes fipsmodule.cnf and
// activates the fips provider; DefaultFIPSModuleConfig gives the path of the
// former. Close it when done.
func NewFIPSContext(configPath string) (*Context, error) {
	c, err := NewContext()
	if err != nil {
		return nil, err
	}
	if err := c.EnableFIPS(configPath); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}
