// Package w3c provides the W3C VC format generator for W3C VCDM 2.0 credentials
package w3c

import (
	"encoding/json"
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
)

func init() {
	formats.Register(NewGenerator())
}

// Generator implements the W3C VC format generator
type Generator struct{}

// NewGenerator creates a new W3C VC generator
func NewGenerator() *Generator {
	return &Generator{}
}

// Name returns the format identifier
func (g *Generator) Name() string {
	return "w3c"
}

// Description returns a human-readable description
func (g *Generator) Description() string {
	return "W3C Verifiable Credential Data Model 2.0 schema"
}

// FileExtension returns the output file extension
func (g *Generator) FileExtension() string {
	return "vc.json"
}

// DeriveIdentifier derives the W3C type array from the parsed credential
func (g *Generator) DeriveIdentifier(parsed *formats.ParsedCredential, cfg *config.Config) string {
	types := g.deriveTypes(parsed, cfg)
	if len(types) > 1 {
		return types[len(types)-1] // Return the specific type (not VerifiableCredential)
	}
	return ""
}

// deriveTypes derives the full type array
func (g *Generator) deriveTypes(parsed *formats.ParsedCredential, cfg *config.Config) []string {
	// Check for explicit types
	if len(parsed.W3CTypes) > 0 {
		// Ensure VerifiableCredential is first
		hasVC := false
		for _, t := range parsed.W3CTypes {
			if t == "VerifiableCredential" {
				hasVC = true
				break
			}
		}
		if !hasVC {
			return append([]string{"VerifiableCredential"}, parsed.W3CTypes...)
		}
		return parsed.W3CTypes
	}

	// Check format-specific override
	if overrides, ok := parsed.FormatOverrides["w3c"]; ok {
		if types, ok := overrides["type"].([]interface{}); ok {
			result := make([]string, 0, len(types)+1)
			hasVC := false
			for _, t := range types {
				if s, ok := t.(string); ok {
					if s == "VerifiableCredential" {
						hasVC = true
					}
					result = append(result, s)
				}
			}
			if !hasVC && len(result) > 0 {
				result = append([]string{"VerifiableCredential"}, result...)
			}
			if len(result) > 0 {
				return result
			}
		}
	}

	// Derive from name
	types := []string{"VerifiableCredential"}
	if parsed.Name != "" {
		// Convert "Person Identification Data" to "PersonIdentificationData"
		typeName := strings.ReplaceAll(parsed.Name, " ", "")
		typeName = strings.ReplaceAll(typeName, "-", "")
		types = append(types, typeName)
	} else if parsed.ID != "" {
		// Convert "pid" to "Pid"
		types = append(types, strings.Title(parsed.ID))
	}

	return types
}

// deriveContext derives the @context array
func (g *Generator) deriveContext(parsed *formats.ParsedCredential, cfg *config.Config) []string {
	// Check for explicit context
	if len(parsed.W3CContext) > 0 {
		return parsed.W3CContext
	}

	// Check format-specific override
	if overrides, ok := parsed.FormatOverrides["w3c"]; ok {
		if ctx, ok := overrides["context"].([]interface{}); ok {
			result := make([]string, 0, len(ctx)+1)
			for _, c := range ctx {
				if s, ok := c.(string); ok {
					result = append(result, s)
				}
			}
			if len(result) > 0 {
				return result
			}
		}
	}

	// Default context
	contexts := []string{"https://www.w3.org/2018/credentials/v1"}

	// Add custom context based on base URL
	if cfg.BaseURL != "" && parsed.ID != "" {
		baseURL := strings.TrimSuffix(cfg.BaseURL, "/")
		contexts = append(contexts, baseURL+"/contexts/"+parsed.ID+"/v1")
	}

	return contexts
}

// W3CCredentialSchema represents a W3C VC credential schema
type W3CCredentialSchema struct {
	Type             []string           `json:"type"`
	Context          []string           `json:"@context"`
	Name             string             `json:"name,omitempty"`
	Description      string             `json:"description,omitempty"`
	Display          *DisplayProperties `json:"display,omitempty"`
	CredentialSchema *CredentialSchema  `json:"credentialSchema,omitempty"`
}

// DisplayProperties for credential display
type DisplayProperties struct {
	BackgroundColor string `json:"backgroundColor,omitempty"`
	TextColor       string `json:"textColor,omitempty"`
}

// CredentialSchema represents the JSON Schema for the credential
type CredentialSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

// SchemaProperty represents a JSON Schema property
type SchemaProperty struct {
	Type            string                     `json:"type"`
	Title           string                     `json:"title,omitempty"`
	Description     string                     `json:"description,omitempty"`
	Format          string                     `json:"format,omitempty"`
	ContentEncoding string                     `json:"contentEncoding,omitempty"`
	Items           *SchemaProperty            `json:"items,omitempty"`
	Properties      map[string]*SchemaProperty `json:"properties,omitempty"`
	Required        []string                   `json:"required,omitempty"`
}

// CredentialSubjectSchema represents the credentialSubject part of the schema
type CredentialSubjectSchema struct {
	Type       string                     `json:"type"`
	Properties map[string]*SchemaProperty `json:"properties,omitempty"`
	Required   []string                   `json:"required,omitempty"`
}

// Generate produces the W3C VC schema output
func (g *Generator) Generate(parsed *formats.ParsedCredential, cfg *config.Config) ([]byte, error) {
	schema := &W3CCredentialSchema{
		Type:        g.deriveTypes(parsed, cfg),
		Context:     g.deriveContext(parsed, cfg),
		Name:        parsed.Name,
		Description: parsed.Description,
	}

	// Add display properties
	if parsed.BackgroundColor != "" || parsed.TextColor != "" {
		schema.Display = &DisplayProperties{
			BackgroundColor: parsed.BackgroundColor,
			TextColor:       parsed.TextColor,
		}
	}

	// Build credential schema
	if len(parsed.Claims) > 0 {
		credSubject := &CredentialSubjectSchema{
			Type:       "object",
			Properties: make(map[string]*SchemaProperty),
		}

		for _, claim := range parsed.Claims {
			// Get claim name, applying format mapping if present
			claimName := claim.Name
			if mapping, ok := claim.FormatMappings["w3c"]; ok {
				claimName = mapping
			}
			// Also check ClaimMappings from parsed credential
			if mappings, ok := parsed.ClaimMappings["w3c"]; ok {
				if mapped, ok := mappings[claim.Name]; ok {
					claimName = mapped
				}
			}

			prop := mapTypeToJSONSchema(claim.Type)
			prop.Title = claim.DisplayName
			if prop.Title == "" {
				prop.Title = claim.Name
			}
			prop.Description = claim.Description

			credSubject.Properties[claimName] = prop

			if claim.Mandatory {
				credSubject.Required = append(credSubject.Required, claimName)
			}
		}

		schema.CredentialSchema = &CredentialSchema{
			Type: "JsonSchema",
			Properties: map[string]interface{}{
				"credentialSubject": credSubject,
			},
		}
	}

	return json.MarshalIndent(schema, "", "  ")
}

// mapTypeToJSONSchema maps markdown types to JSON Schema properties
func mapTypeToJSONSchema(mdType string) *SchemaProperty {
	switch strings.ToLower(mdType) {
	case "string":
		return &SchemaProperty{Type: "string"}
	case "number":
		return &SchemaProperty{Type: "number"}
	case "integer":
		return &SchemaProperty{Type: "integer"}
	case "boolean", "bool":
		return &SchemaProperty{Type: "boolean"}
	case "date":
		return &SchemaProperty{Type: "string", Format: "date"}
	case "datetime":
		return &SchemaProperty{Type: "string", Format: "date-time"}
	case "image":
		return &SchemaProperty{Type: "string", ContentEncoding: "base64"}
	case "object":
		return &SchemaProperty{Type: "object"}
	case "array":
		return &SchemaProperty{Type: "array", Items: &SchemaProperty{Type: "string"}}
	default:
		return &SchemaProperty{Type: "string"}
	}
}
