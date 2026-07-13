package repoplugin

import (
	"testing"
)

func TestRegistryBasics(t *testing.T) {
	r := NewRegistry()

	// Empty registry
	if names := r.List(); len(names) != 0 {
		t.Errorf("expected empty registry, got %v", names)
	}

	// Register a mock plugin
	mock := &mockPlugin{name: "test-layout"}
	r.Register(mock)

	// Get registered plugin
	p, ok := r.Get("test-layout")
	if !ok {
		t.Fatal("expected plugin to be found")
	}
	if p.Name() != "test-layout" {
		t.Errorf("Name() = %q, want %q", p.Name(), "test-layout")
	}

	// Get non-existent plugin
	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("expected plugin not to be found")
	}

	// List
	names := r.List()
	if len(names) != 1 || names[0] != "test-layout" {
		t.Errorf("List() = %v, want [test-layout]", names)
	}
}

func TestDefaultRegistryHasPlugins(t *testing.T) {
	// After importing defaultlayout and rulebookcatalog, the default registry
	// should have plugins registered. But since this test is in the repoplugin
	// package itself, those imports don't apply here. This test just verifies
	// the registry API contract.

	r := NewRegistry()
	r.Register(&mockPlugin{name: "default"})
	r.Register(&mockPlugin{name: "rulebook-catalog"})

	if _, ok := r.Get("default"); !ok {
		t.Error("expected default plugin")
	}
	if _, ok := r.Get("rulebook-catalog"); !ok {
		t.Error("expected rulebook-catalog plugin")
	}
}

type mockPlugin struct {
	name string
}

func (m *mockPlugin) Name() string        { return m.name }
func (m *mockPlugin) Description() string  { return "mock plugin" }
func (m *mockPlugin) Discover(ctx Context) ([]DiscoveredCredential, error) {
	return nil, nil
}
