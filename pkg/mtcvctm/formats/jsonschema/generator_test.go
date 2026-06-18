package jsonschema

import (
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
)

func TestGenerator_Metadata(t *testing.T) {
	g := NewGenerator()
	if g.Name() != "jsonschema" {
		t.Errorf("Name() = %q, want %q", g.Name(), "jsonschema")
	}
	if g.FileExtension() != "schema.json" {
		t.Errorf("FileExtension() = %q, want %q", g.FileExtension(), "schema.json")
	}
}

func TestGenerator_DeriveIdentifier(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{}

	t.Run("uses VCT when present", func(t *testing.T) {
		parsed := &formats.ParsedCredential{VCT: "https://example.com/cred/v1"}
		if id := g.DeriveIdentifier(parsed, cfg); id != "https://example.com/cred/v1" {
			t.Errorf("DeriveIdentifier() = %q, want VCT", id)
		}
	})

	t.Run("falls back to ID", func(t *testing.T) {
		parsed := &formats.ParsedCredential{ID: "my-credential"}
		if id := g.DeriveIdentifier(parsed, cfg); id != "my-credential" {
			t.Errorf("DeriveIdentifier() = %q, want ID", id)
		}
	})
}

func TestGenerator_Generate_Basic(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{}

	parsed := &formats.ParsedCredential{
		Name:        "Test Credential",
		Description: "A test credential",
		VCT:         "https://example.com/test/v1",
		Claims: []formats.ClaimDefinition{
			{Name: "given_name", Type: "string", DisplayName: "Given Name", Mandatory: true},
			{Name: "birth_date", Type: "date", DisplayName: "Date of Birth"},
			{Name: "age", Type: "integer", DisplayName: "Age"},
		},
	}

	output, err := g.Generate(parsed, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var doc JSONSchema
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if doc.Schema != "http://json-schema.org/draft-07/schema#" {
		t.Errorf("$schema = %q", doc.Schema)
	}
	if doc.ID != "https://example.com/test/v1" {
		t.Errorf("$id = %q, want VCT", doc.ID)
	}
	if doc.Title != "Test Credential" {
		t.Errorf("title = %q", doc.Title)
	}
	if doc.Type != "object" {
		t.Errorf("type = %q, want 'object'", doc.Type)
	}

	// Check properties
	if len(doc.Properties) != 3 {
		t.Fatalf("properties count = %d, want 3", len(doc.Properties))
	}
	if doc.Properties["given_name"] == nil || doc.Properties["given_name"].Type != "string" {
		t.Error("given_name property missing or wrong type")
	}
	if doc.Properties["birth_date"] == nil || doc.Properties["birth_date"].Format != "date" {
		t.Error("birth_date property missing or wrong format")
	}
	if doc.Properties["age"] == nil || doc.Properties["age"].Type != "integer" {
		t.Error("age property missing or wrong type")
	}

	// Check required
	if len(doc.Required) != 1 || doc.Required[0] != "given_name" {
		t.Errorf("required = %v, want [given_name]", doc.Required)
	}
}

func TestGenerator_Generate_NoClaims(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{}

	parsed := &formats.ParsedCredential{
		Name:        "Empty Credential",
		Description: "No claims",
	}

	output, err := g.Generate(parsed, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var doc JSONSchema
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	if doc.Properties != nil {
		t.Errorf("properties should be nil for empty claims, got %v", doc.Properties)
	}
	if doc.Required != nil {
		t.Errorf("required should be nil for empty claims, got %v", doc.Required)
	}
}

func TestGenerator_Generate_NestedObject(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{}

	parsed := &formats.ParsedCredential{
		Name: "Address Credential",
		Claims: []formats.ClaimDefinition{
			{
				Name: "address", Type: "object", DisplayName: "Address", Mandatory: true,
				Children: []formats.ClaimDefinition{
					{Name: "street", Type: "string", DisplayName: "Street", Mandatory: true},
					{Name: "city", Type: "string", DisplayName: "City", Mandatory: true},
					{Name: "zip", Type: "string", DisplayName: "Zip Code"},
				},
			},
		},
	}

	output, err := g.Generate(parsed, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var doc JSONSchema
	if err := json.Unmarshal(output, &doc); err != nil {
		t.Fatalf("Failed to unmarshal output: %v", err)
	}

	addr := doc.Properties["address"]
	if addr == nil {
		t.Fatal("address property missing")
	}
	if addr.Type != "object" {
		t.Errorf("address.type = %q, want 'object'", addr.Type)
	}
	if len(addr.Properties) != 3 {
		t.Errorf("address.properties count = %d, want 3", len(addr.Properties))
	}
	if len(addr.Required) != 2 {
		t.Errorf("address.required = %v, want [street city]", addr.Required)
	}
}

func TestGenerator_FormatAlias(t *testing.T) {
	// Verify the format alias resolves correctly
	resolved := formats.ResolveAlias("json-schema")
	if resolved != "jsonschema" {
		t.Fatalf("ResolveAlias('json-schema') = %q, want 'jsonschema'", resolved)
	}
	gen, ok := formats.Get(resolved)
	if !ok || gen == nil {
		t.Fatal("formats.Get('jsonschema') returned nil — not registered")
	}
	if gen.Name() != "jsonschema" {
		t.Errorf("Name() = %q, want 'jsonschema'", gen.Name())
	}
}
