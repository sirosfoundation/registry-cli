package formats

import (
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
)

// mockGenerator is a test implementation of Generator
type mockGenerator struct {
	name        string
	description string
	extension   string
}

func (m *mockGenerator) Name() string        { return m.name }
func (m *mockGenerator) Description() string { return m.description }
func (m *mockGenerator) FileExtension() string { return m.extension }
func (m *mockGenerator) Generate(parsed *ParsedCredential, cfg *config.Config) ([]byte, error) {
	return []byte(`{"test": true}`), nil
}
func (m *mockGenerator) DeriveIdentifier(parsed *ParsedCredential, cfg *config.Config) string {
	return parsed.ID
}

func TestNewRegistry(t *testing.T) {
	r := NewRegistry()
	if r == nil {
		t.Fatal("NewRegistry returned nil")
	}
	if r.generators == nil {
		t.Error("generators map should be initialized")
	}
	if len(r.List()) != 0 {
		t.Errorf("New registry should be empty, got %d generators", len(r.List()))
	}
}

func TestRegistry_Register(t *testing.T) {
	r := NewRegistry()
	gen := &mockGenerator{name: "test", description: "Test format", extension: "test"}

	r.Register(gen)

	if len(r.List()) != 1 {
		t.Errorf("Expected 1 generator, got %d", len(r.List()))
	}

	g, ok := r.Get("test")
	if !ok {
		t.Error("Generator should be retrievable after registration")
	}
	if g.Name() != "test" {
		t.Errorf("Generator name = %q, want test", g.Name())
	}
}

func TestRegistry_Register_Overwrite(t *testing.T) {
	r := NewRegistry()
	gen1 := &mockGenerator{name: "fmt", description: "First", extension: "v1"}
	gen2 := &mockGenerator{name: "fmt", description: "Second", extension: "v2"}

	r.Register(gen1)
	r.Register(gen2)

	// Should have replaced the first one
	if len(r.List()) != 1 {
		t.Errorf("Expected 1 generator after overwrite, got %d", len(r.List()))
	}

	g, _ := r.Get("fmt")
	if g.Description() != "Second" {
		t.Errorf("Description = %q, want 'Second' (should be overwritten)", g.Description())
	}
}

func TestRegistry_Get(t *testing.T) {
	r := NewRegistry()
	gen := &mockGenerator{name: "myformat", description: "My format", extension: "my"}
	r.Register(gen)

	// Existing generator
	g, ok := r.Get("myformat")
	if !ok {
		t.Error("Should find registered generator")
	}
	if g.Name() != "myformat" {
		t.Errorf("Name = %q, want myformat", g.Name())
	}

	// Non-existent generator
	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("Should not find non-existent generator")
	}
}

func TestRegistry_List(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockGenerator{name: "zebra", description: "Z", extension: "z"})
	r.Register(&mockGenerator{name: "alpha", description: "A", extension: "a"})
	r.Register(&mockGenerator{name: "beta", description: "B", extension: "b"})

	names := r.List()

	if len(names) != 3 {
		t.Fatalf("Expected 3 names, got %d", len(names))
	}

	// Should be sorted alphabetically
	expected := []string{"alpha", "beta", "zebra"}
	for i, name := range names {
		if name != expected[i] {
			t.Errorf("names[%d] = %q, want %q", i, name, expected[i])
		}
	}
}

func TestRegistry_All(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockGenerator{name: "one", description: "One", extension: "1"})
	r.Register(&mockGenerator{name: "two", description: "Two", extension: "2"})

	all := r.All()

	if len(all) != 2 {
		t.Errorf("Expected 2 generators, got %d", len(all))
	}

	names := make(map[string]bool)
	for _, g := range all {
		names[g.Name()] = true
	}
	if !names["one"] || !names["two"] {
		t.Error("All() should return all registered generators")
	}
}

func TestRegistry_ParseFormats(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockGenerator{name: "vctm", description: "VCTM", extension: "vctm.json"})
	r.Register(&mockGenerator{name: "mddl", description: "MDDL", extension: "mddl.json"})
	r.Register(&mockGenerator{name: "w3c", description: "W3C", extension: "vc.json"})

	tests := []struct {
		name      string
		input     string
		want      []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:  "empty string returns all",
			input: "",
			want:  []string{"mddl", "vctm", "w3c"},
		},
		{
			name:  "all keyword returns all",
			input: "all",
			want:  []string{"mddl", "vctm", "w3c"},
		},
		{
			name:  "single format",
			input: "vctm",
			want:  []string{"vctm"},
		},
		{
			name:  "multiple formats",
			input: "vctm,mddl",
			want:  []string{"vctm", "mddl"},
		},
		{
			name:  "formats with spaces",
			input: " vctm , mddl ",
			want:  []string{"vctm", "mddl"},
		},
		{
			name:      "unknown format",
			input:     "unknown",
			wantErr:   true,
			errSubstr: "unknown format",
		},
		{
			name:      "mixed known and unknown",
			input:     "vctm,unknown",
			wantErr:   true,
			errSubstr: "unknown",
		},
		{
			name:    "empty parts ignored",
			input:   "vctm,,mddl",
			want:    []string{"vctm", "mddl"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.ParseFormats(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error containing %q", tt.errSubstr)
				} else if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("Error = %q, want to contain %q", err.Error(), tt.errSubstr)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if len(got) != len(tt.want) {
				t.Errorf("len(got) = %d, want %d", len(got), len(tt.want))
				return
			}

			for i, w := range tt.want {
				if got[i] != w {
					t.Errorf("got[%d] = %q, want %q", i, got[i], w)
				}
			}
		})
	}
}

func TestRegistry_ParseFormats_EmptyResult(t *testing.T) {
	r := NewRegistry()
	r.Register(&mockGenerator{name: "vctm", description: "VCTM", extension: "vctm.json"})

	// Only whitespace/commas
	_, err := r.ParseFormats(",  ,  ")
	if err == nil {
		t.Error("Expected error for no valid formats")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestFormatJSON(t *testing.T) {
	data := map[string]interface{}{
		"name": "test",
		"value": 42,
	}

	output, err := FormatJSON(data)
	if err != nil {
		t.Fatalf("FormatJSON() error = %v", err)
	}

	// Should be valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}

	// Should be indented (contains newlines)
	if !contains(string(output), "\n") {
		t.Error("Output should be indented with newlines")
	}

	// Should contain the data
	if parsed["name"] != "test" {
		t.Errorf("name = %v, want 'test'", parsed["name"])
	}
}

func TestFormatJSON_InvalidData(t *testing.T) {
	// Channels cannot be marshaled to JSON
	data := make(chan int)
	_, err := FormatJSON(data)
	if err == nil {
		t.Error("Expected error for unmarshallable data")
	}
}

// Test the global DefaultRegistry functions
func TestGlobalRegistry(t *testing.T) {
	// The global registry should have formats registered from init()
	// This tests that the global functions work with DefaultRegistry

	// List should return at least one format if any format packages are imported
	names := List()
	// Note: This test may need adjustment based on which formats are registered
	// For now, just verify it doesn't panic

	// Get for non-existent should return false
	_, ok := Get("definitely-not-a-format")
	if ok {
		t.Error("Get should return false for non-existent format")
	}

	// ParseFormats should work
	if len(names) > 0 {
		formats, err := ParseFormats(names[0])
		if err != nil {
			t.Errorf("ParseFormats failed: %v", err)
		}
		if len(formats) != 1 {
			t.Errorf("Expected 1 format, got %d", len(formats))
		}
	}
}

func TestParsedCredential_Fields(t *testing.T) {
	// Test that ParsedCredential struct fields work correctly
	cred := &ParsedCredential{
		ID:          "test-id",
		Name:        "Test Credential",
		VCT:         "https://example.com/vct",
		DocType:     "org.example.test",
		Namespace:   "org.example",
		Description: "A test credential",
		Claims: []ClaimDefinition{
			{
				Name:        "given_name",
				Path:        []string{"given_name"},
				DisplayName: "Given Name",
				Type:        "string",
				Mandatory:   true,
				Localizations: map[string]ClaimLocalization{
					"de-DE": {Label: "Vorname"},
				},
			},
		},
		Localizations: map[string]DisplayLocalization{
			"en-US": {Name: "Test", Description: "A test"},
		},
		Images: []ImageRef{
			{Path: "logo.png", AltText: "Logo"},
		},
	}

	if cred.ID != "test-id" {
		t.Errorf("ID = %q", cred.ID)
	}
	if len(cred.Claims) != 1 {
		t.Errorf("len(Claims) = %d", len(cred.Claims))
	}
	if cred.Claims[0].Mandatory != true {
		t.Error("Claim should be mandatory")
	}
	if cred.Claims[0].Localizations["de-DE"].Label != "Vorname" {
		t.Error("German localization missing")
	}
}
