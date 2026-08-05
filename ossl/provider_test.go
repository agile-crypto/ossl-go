package ossl

import "testing"

// TestLoadUnloadRoundTrip mirrors 10_providers.c part (b): loading "legacy"
// makes MD4 fetchable, unloading it removes that availability again.
func TestLoadUnloadRoundTrip(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer c.Close()

	if c.DigestAvailable("MD4", "") {
		t.Fatal("MD4 available before legacy was ever loaded")
	}

	prov, err := c.LoadProvider("legacy")
	if err != nil {
		t.Fatalf("LoadProvider(legacy): %v", err)
	}
	if !c.DigestAvailable("MD4", "") {
		t.Fatal("MD4 not available after loading legacy")
	}

	if err := prov.Unload(); err != nil {
		t.Fatalf("Unload: %v", err)
	}
	if c.DigestAvailable("MD4", "") {
		t.Fatal("MD4 still available after unloading legacy")
	}
}

func TestProviderUnloadIsIdempotent(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer c.Close()

	prov, err := c.LoadProvider("legacy")
	if err != nil {
		t.Fatalf("LoadProvider(legacy): %v", err)
	}
	if err := prov.Unload(); err != nil {
		t.Fatalf("first Unload: %v", err)
	}
	if err := prov.Unload(); err != nil {
		t.Fatalf("second Unload: %v", err)
	}
}

func TestProviderAvailable(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer c.Close()

	if c.ProviderAvailable("legacy") {
		t.Fatal("legacy reported available before it was loaded")
	}
	if _, err := c.LoadProvider("legacy"); err != nil {
		t.Fatalf("LoadProvider(legacy): %v", err)
	}
	if !c.ProviderAvailable("legacy") {
		t.Fatal("legacy reported unavailable after it was loaded")
	}
}

// TestProvidersEnumeration mirrors 10_providers.c part (a): the currently
// loaded providers can be listed with their name, version and active status.
func TestProvidersEnumeration(t *testing.T) {
	c, err := NewContext()
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	defer c.Close()

	if _, err := c.LoadProvider("default"); err != nil {
		t.Fatalf("LoadProvider(default): %v", err)
	}

	infos, err := c.Providers()
	if err != nil {
		t.Fatalf("Providers: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("Providers() = %d entries, want 1: %+v", len(infos), infos)
	}
	if infos[0].Name == "" {
		t.Fatal("provider Name is empty")
	}
	if infos[0].Version == "" {
		t.Fatal("provider Version is empty")
	}
	if !infos[0].Active {
		t.Fatal("provider Active = false, want true for a just-loaded provider")
	}

	if _, err := c.LoadProvider("legacy"); err != nil {
		t.Fatalf("LoadProvider(legacy): %v", err)
	}
	infos, err = c.Providers()
	if err != nil {
		t.Fatalf("Providers: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("Providers() = %d entries after loading legacy, want 2: %+v", len(infos), infos)
	}
}

func TestCipherAvailable(t *testing.T) {
	if !Default.CipherAvailable("AES-256-GCM", "") {
		t.Fatal("AES-256-GCM should be available via Default")
	}
	if Default.CipherAvailable("FOOBAR-1234", "") {
		t.Fatal("a made-up cipher name reported available")
	}
}

func TestDigestAvailableUnknownName(t *testing.T) {
	if Default.DigestAvailable("FOOBAR-1234", "") {
		t.Fatal("a made-up digest name reported available")
	}
}
