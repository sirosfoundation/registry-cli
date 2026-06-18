// Package w3c provides the W3C VC format generator for W3C VCDM 2.0 credentials
package w3c

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
	jsonschema "github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats/schema"
)

func init() {
	formats.Register(NewGenerator())
}

// schemaFormatName is the format name used for claim mapping lookups.
const schemaFormatName = "w3c"

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
		r := []rune(parsed.ID)
		r[0] = unicode.ToUpper(r[0])
		types = append(types, string(r))
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

// CredentialSubjectSchema represents the credentialSubject part of the schema
type CredentialSubjectSchema struct {
	Type       string                          `json:"type"`
	Properties map[string]*jsonschema.Property `json:"properties,omitempty"`
	Required   []string                        `json:"required,omitempty"`
}

// Generate produces the W3C VC schema output
func (g *Generator) Generate(parsed *formats.ParsedCredential, cfg *config.Config) ([]byte, error) {
	output := &W3CCredentialSchema{
		Type:        g.deriveTypes(parsed, cfg),
		Context:     g.deriveContext(parsed, cfg),
		Name:        parsed.Name,
		Description: parsed.Description,
	}

	// Add display properties
	if parsed.BackgroundColor != "" || parsed.TextColor != "" {
		output.Display = &DisplayProperties{
			BackgroundColor: parsed.BackgroundColor,
			TextColor:       parsed.TextColor,
		}
	}

	// Build credential schema
	if len(parsed.Claims) > 0 {
		props, required := jsonschema.BuildProperties(parsed.Claims, parsed.ClaimMappings, schemaFormatName)
		credSubject := &CredentialSubjectSchema{
			Type:       "object",
			Properties: props,
			Required:   required,
		}

		output.CredentialSchema = &CredentialSchema{
			Type: "JsonSchema",
			Properties: map[string]interface{}{
				"credentialSubject": credSubject,
			},
		}
	}

	return json.MarshalIndent(output, "", "  ")
}
