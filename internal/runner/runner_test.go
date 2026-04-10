package runner_test

import (
	"testing"

	"github.com/1lo1lo1/subsurge/internal/sources"
)

// TestSourcesRegistry ensures every registered source implements the interface
// and returns a non-empty name.
func TestSourcesRegistry(t *testing.T) {
	all := sources.All()
	if len(all) == 0 {
		t.Fatal("no sources registered")
	}
	for name, src := range all {
		if src.Name() == "" {
			t.Errorf("source %q has empty Name()", name)
		}
		if src.Name() != name {
			t.Errorf("source key %q != Name() %q", name, src.Name())
		}
	}
}

// TestSourcesSelect ensures include/exclude/free/key filters work.
func TestSourcesSelect(t *testing.T) {
	// All sources
	all := sources.Select(nil, nil, false, false)
	if len(all) == 0 {
		t.Fatal("Select() returned no sources")
	}

	// Only free sources
	free := sources.Select(nil, nil, true, false)
	for _, s := range free {
		if s.NeedsKey() {
			t.Errorf("free-only selection includes keyed source %q", s.Name())
		}
	}

	// Only keyed sources
	keyed := sources.Select(nil, nil, false, true)
	for _, s := range keyed {
		if !s.NeedsKey() {
			t.Errorf("key-only selection includes free source %q", s.Name())
		}
	}

	// Include specific
	inc := sources.Select([]string{"crtsh", "hackertarget"}, nil, false, false)
	if len(inc) != 2 {
		t.Errorf("expected 2 sources from include list, got %d", len(inc))
	}

	// Exclude
	excl := sources.Select(nil, []string{"crtsh"}, false, false)
	for _, s := range excl {
		if s.Name() == "crtsh" {
			t.Error("crtsh should be excluded")
		}
	}
}
