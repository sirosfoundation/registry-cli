// Package jsonschema provides a standalone JSON Schema format generator.
// It produces draft-07 JSON Schema documents suitable for payload validation.
package jsonschema

import (
	"encoding/json"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats/schema"
)

func init() {
	formats.Register(NewGenerator())
}

// Generator implements the standalone JSON Schema format generator.
type Generator struct{}

// NewGenerator creates a new JSON Schema generator.
func NewGenerator() *Generator {
	return &Generator{}
}

func (g *Generator) Name() string        { return "jsonschema" }
func (g *Generator) Description() string  { return "Standalone JSON Schema (draft-07) for credential payload validation" }
func (g *Generator) FileExtension() string { return "schema.json" }

func (g *Generator) DeriveIdentifier(parsed *formats.ParsedCredential, cfg *config.Config) string {
	if parsed.VCT != "" {
		return parsed.VCT
	}
	return parsed.ID
}

// JSONSchema represents a standalone JSON Schema document.
type JSONSchema struct {
	Schema      string                  `json:"$schema"`
	ID          string                  `json:"$id,omitempty"`
	Title       string                  `json:"title,omitempty"`
	Description string                  `json:"description,omitempty"`
	Type        string                  `json:"type"`
	Properties  map[string]*schema.Property `json:"properties,omitempty"`
	Required    []string                `json:"required,omitempty"`
}

func (g *Generator) Generate(parsed *formats.ParsedCredential, cfg *config.Config) ([]byte, error) {
	doc := &JSONSchema{
		Schema:      "http://json-schema.org/draft-07/schema#",
		Title:       parsed.Name,
		Description: parsed.Description,
		Type:        "object",
	}

	// Use VCT as $id if available
	if parsed.VCT != "" {
		doc.ID = parsed.VCT
	}

	if len(parsed.Claims) > 0 {
		doc.Properties, doc.Required = schema.BuildProperties(parsed.Claims, parsed.ClaimMappings, "jsonschema")
	}

	return json.MarshalIndent(doc, "", "  ")
}
