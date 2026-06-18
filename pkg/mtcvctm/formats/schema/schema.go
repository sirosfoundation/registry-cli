// Package schema provides shared JSON Schema building utilities used by
// format generators that produce JSON Schema output.
package schema

import (
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
)

// Property represents a JSON Schema property.
type Property struct {
	Type            string               `json:"type"`
	Title           string               `json:"title,omitempty"`
	Description     string               `json:"description,omitempty"`
	Format          string               `json:"format,omitempty"`
	ContentEncoding string               `json:"contentEncoding,omitempty"`
	Items           *Property            `json:"items,omitempty"`
	Properties      map[string]*Property `json:"properties,omitempty"`
	Required        []string             `json:"required,omitempty"`
}

// BuildProperties converts a slice of ClaimDefinitions into a map of JSON Schema
// properties and a required list, applying format-specific claim mappings for the
// given formatName (e.g. "w3c", "jsonschema").
func BuildProperties(claims []formats.ClaimDefinition, claimMappings map[string]map[string]string, formatName string) (map[string]*Property, []string) {
	props := make(map[string]*Property)
	var required []string

	for _, claim := range claims {
		name := resolveName(claim, claimMappings, formatName)
		props[name] = ClaimToProperty(claim, claimMappings, formatName)
		if claim.Mandatory {
			required = append(required, name)
		}
	}

	return props, required
}

// ClaimToProperty converts a single ClaimDefinition to a JSON Schema Property,
// recursively building nested properties for object and array types.
func ClaimToProperty(claim formats.ClaimDefinition, claimMappings map[string]map[string]string, formatName string) *Property {
	prop := MapType(claim.Type)
	prop.Title = claim.DisplayName
	if prop.Title == "" {
		prop.Title = claim.Name
	}
	prop.Description = claim.Description

	if len(claim.Children) > 0 {
		switch strings.ToLower(claim.Type) {
		case "object":
			if prop.Properties == nil {
				prop.Properties = make(map[string]*Property)
			}
			for _, child := range claim.Children {
				childName := resolveName(child, claimMappings, formatName)
				prop.Properties[childName] = ClaimToProperty(child, claimMappings, formatName)
				if child.Mandatory {
					prop.Required = append(prop.Required, childName)
				}
			}
		case "array":
			itemSchema := &Property{
				Type:       "object",
				Properties: make(map[string]*Property),
			}
			for _, child := range claim.Children {
				childName := resolveName(child, claimMappings, formatName)
				itemSchema.Properties[childName] = ClaimToProperty(child, claimMappings, formatName)
				if child.Mandatory {
					itemSchema.Required = append(itemSchema.Required, childName)
				}
			}
			prop.Items = itemSchema
		}
	}

	return prop
}

// resolveName determines the output claim name by checking format-specific mappings.
func resolveName(claim formats.ClaimDefinition, claimMappings map[string]map[string]string, formatName string) string {
	name := claim.Name
	if mapping, ok := claim.FormatMappings[formatName]; ok {
		name = mapping
	}
	if mappings, ok := claimMappings[formatName]; ok {
		if mapped, ok := mappings[claim.Name]; ok {
			name = mapped
		}
	}
	return name
}

// MapType maps a markdown type string to a JSON Schema Property with appropriate type/format.
func MapType(mdType string) *Property {
	switch strings.ToLower(mdType) {
	case "string":
		return &Property{Type: "string"}
	case "number":
		return &Property{Type: "number"}
	case "integer":
		return &Property{Type: "integer"}
	case "boolean", "bool":
		return &Property{Type: "boolean"}
	case "date":
		return &Property{Type: "string", Format: "date"}
	case "datetime":
		return &Property{Type: "string", Format: "date-time"}
	case "image":
		return &Property{Type: "string", ContentEncoding: "base64"}
	case "object":
		return &Property{Type: "object", Properties: make(map[string]*Property)}
	case "array":
		return &Property{Type: "array", Items: &Property{Type: "string"}}
	default:
		return &Property{Type: "string"}
	}
}
