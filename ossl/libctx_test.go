package ossl

import "testing"

// TestContextProviderIsolation mirrors 11_libctx.c part (a): loading a
// provider into one context must not make its algorithms visible through
// any other context, including Default.
func TestContextProviderIsolation(t *testing.T) {
	a, err := NewContext()
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer a.Close()

	b, err := NewContext()
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer b.Close()

	if mdAvailableForTest(a, "MD4", "") {
		t.Fatal("MD4 unexpectedly available in a fresh context before loading legacy")
	}

	if !loadProviderForTest(a, "legacy") {
		t.Fatal("failed to load the legacy provider into context a")
	}

	if !mdAvailableForTest(a, "MD4", "") {
		t.Fatal("MD4 not available in context a after loading legacy into it")
	}
	if mdAvailableForTest(b, "MD4", "") {
		t.Fatal("MD4 available in context b, which never had legacy loaded - isolation broken")
	}
	if mdAvailableForTest(Default, "MD4", "") {
		t.Fatal("MD4 available via Default, which never had legacy loaded - isolation broken")
	}
}

// TestContextSetDefaultPropertiesFiltersFetches mirrors 11_libctx.c part
// (b): pinning a default property query restricts every subsequent fetch
// through that context unless the call site overrides it explicitly.
func TestContextSetDefaultPropertiesFiltersFetches(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer c.Close()

	if !loadProviderForTest(c, "legacy") {
		t.Fatal("failed to load legacy")
	}
	if !loadProviderForTest(c, "default") {
		t.Fatal("failed to load default")
	}
	if !mdAvailableForTest(c, "MD4", "") {
		t.Fatal("MD4 should be available before pinning default properties")
	}

	if err := c.SetDefaultProperties("provider=default"); err != nil {
		t.Fatalf("SetDefaultProperties: %v", err)
	}

	if mdAvailableForTest(c, "MD4", "") {
		t.Fatal("MD4 still available after pinning provider=default - legacy should no longer match by default")
	}
	if !mdAvailableForTest(c, "MD4", "provider=legacy") {
		t.Fatal("MD4 not available with an explicit override query - explicit propq should win over the pinned default")
	}
	if !mdAvailableForTest(c, "SHA2-256", "") {
		t.Fatal("SHA2-256 should still be available: it matches provider=default")
	}
}

func TestContextCloseIsIdempotent(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestDefaultCloseIsNoOp(t *testing.T) {
	if err := Default.Close(); err != nil {
		t.Fatalf("Default.Close: %v", err)
	}
	// Default must still resolve to the implicit global context (a NULL
	// pointer at the C level) after Close, not become unusable.
	if Default.ptr() != nil {
		t.Fatal("Default.ptr() is not nil after Close")
	}
	if !mdAvailableForTest(Default, "SHA2-256", "") {
		t.Fatal("Default is unusable after Close - it never owned anything to free")
	}
}

func TestNilContextPtrIsNULL(t *testing.T) {
	var c *Context
	if c.ptr() != nil {
		t.Fatal("(*Context)(nil).ptr() is not nil")
	}
}
