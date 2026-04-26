// Package attributes implements the TS11 §2 Catalogue of Attributes.
// It infers Attribute objects from VCTM claim definitions and supports
// optional manual overrides via *.attr.json files.
package attributes

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Attribute represents a TS11 §2.1 Attribute object.
type Attribute struct {
	Identifier                string               `json:"identifier"`
	Name                      []LangValue          `json:"name"`
	Description               []LangValue          `json:"description,omitempty"`
	NameSpace                 string               `json:"nameSpace,omitempty"`
	Distributions             []SchemaDistribution `json:"distributions"`
	ContactInfo               []string             `json:"contactInfo,omitempty"`
	LegalBasis                []string             `json:"legalBasis,omitempty"`
	SemanticDataSpecification string               `json:"semanticDataSpecification,omitempty"`
	AuthenticSources          []DataService        `json:"authenticSources,omitempty"`
	UsedBy                    []AttestationRef     `json:"x-usedBy,omitempty"` // cross-reference to attestations
}

// LangValue holds a language-tagged string value.
type LangValue struct {
	Value string `json:"value"`
	Lang  string `json:"lang"`
}

// SchemaDistribution holds a TS11 §2.1 distribution reference.
type SchemaDistribution struct {
	AccessURL string `json:"accessURL"`
	MediaType string `json:"mediaType"`
}

// DataService holds a TS11 §2.1 authentic source endpoint.
type DataService struct {
	Country             string `json:"country"`
	NationalSubID       string `json:"nationalSubID,omitempty"`
	EndpointURL         string `json:"endpointURL"`
	EndpointDescription string `json:"endpointDescription,omitempty"`
}

// AttestationRef links an attribute back to an attestation that uses it.
// This is a SIROS extension (x-usedBy) not in the TS11 spec.
type AttestationRef struct {
	SchemaID string `json:"schemaId"`
	Org      string `json:"org"`
	Slug     string `json:"slug"`
	Name     string `json:"name,omitempty"`
}

// ClaimInput is the minimal claim information needed to infer an Attribute.
type ClaimInput struct {
	Path        []string // claim path segments
	DisplayName string   // first non-empty display name (any locale)
	DisplayLang string   // locale of the display name
}

// CredentialInput is the minimal credential information needed for inference.
type CredentialInput struct {
	SchemaID string       // SchemaMeta UUID
	Org      string       // organization slug
	Slug     string       // credential slug
	Name     string       // credential display name
	VCT      string       // vct URI from VCTM (used to derive namespace)
	Claims   []ClaimInput // claims extracted from VCTM
}

// InferFromCredentials builds a catalogue of attributes by extracting claims
// from credentials and deduplicating by identifier. Claims with the same
// namespace+path produce a single Attribute with multiple UsedBy references.
func InferFromCredentials(credentials []CredentialInput, baseURL string) []Attribute {
	index := make(map[string]*Attribute)
	var order []string

	for _, cred := range credentials {
		ns := namespaceFromVCT(cred.VCT)

		for _, claim := range cred.Claims {
			path := strings.Join(claim.Path, ".")
			id := attributeIdentifier(ns, path)

			if _, exists := index[id]; !exists {
				attr := &Attribute{
					Identifier: id,
					NameSpace:  ns,
					Distributions: []SchemaDistribution{
						{
							AccessURL: baseURL + "/api/v1/attributes/schemas/" + slugFromPath(path) + ".json",
							MediaType: "application/schema+json",
						},
					},
				}
				if claim.DisplayName != "" {
					lang := claim.DisplayLang
					if lang == "" {
						lang = "en"
					}
					attr.Name = []LangValue{{Value: claim.DisplayName, Lang: lang}}
				} else {
					attr.Name = []LangValue{{Value: path, Lang: "en"}}
				}
				index[id] = attr
				order = append(order, id)
			}

			a := index[id]
			a.UsedBy = append(a.UsedBy, AttestationRef{
				SchemaID: cred.SchemaID,
				Org:      cred.Org,
				Slug:     cred.Slug,
				Name:     cred.Name,
			})

			// Merge display name if current attribute has no good name
			if len(a.Name) == 1 && a.Name[0].Value == path && claim.DisplayName != "" {
				lang := claim.DisplayLang
				if lang == "" {
					lang = "en"
				}
				a.Name = []LangValue{{Value: claim.DisplayName, Lang: lang}}
			}
		}
	}

	result := make([]Attribute, 0, len(order))
	for _, id := range order {
		result = append(result, *index[id])
	}
	return result
}

// GenerateSchemas generates a minimal JSON Schema for each attribute.
// Returns a map from schema filename to JSON content.
func GenerateSchemas(attrs []Attribute) map[string]json.RawMessage {
	schemas := make(map[string]json.RawMessage)
	for _, attr := range attrs {
		path := pathFromIdentifier(attr.Identifier)
		filename := slugFromPath(path) + ".json"

		name := path
		if len(attr.Name) > 0 {
			name = attr.Name[0].Value
		}

		schema := map[string]any{
			"$schema":     "https://json-schema.org/draft/2020-12/schema",
			"$id":         attr.Identifier,
			"title":       name,
			"description": fmt.Sprintf("Schema for attribute %s", name),
			"type":        "object",
			"properties": map[string]any{
				path: map[string]any{
					"type":        "string",
					"description": name,
				},
			},
		}
		data, _ := json.MarshalIndent(schema, "", "  ")
		schemas[filename] = json.RawMessage(data)
	}
	return schemas
}

// namespaceFromVCT extracts a namespace URI from a VCT URI.
// For example, "https://credentials.example.com/identity" → "https://credentials.example.com"
func namespaceFromVCT(vct string) string {
	if vct == "" {
		return ""
	}
	u, err := url.Parse(vct)
	if err != nil {
		return vct
	}
	return u.Scheme + "://" + u.Host
}

// attributeIdentifier generates a deterministic identifier for an attribute.
func attributeIdentifier(namespace, path string) string {
	if namespace == "" {
		namespace = "urn:siros"
	}
	// Create a short hash to make the identifier unique and stable
	h := sha256.Sum256([]byte(namespace + "/" + path))
	short := fmt.Sprintf("%x", h[:4])
	return fmt.Sprintf("urn:siros:attr:%s:%s", slugFromPath(path), short)
}

// slugFromPath converts a dot-path claim name to a URL-safe slug.
func slugFromPath(path string) string {
	return strings.ReplaceAll(strings.ReplaceAll(path, ".", "-"), "/", "-")
}

// pathFromIdentifier extracts the claim path from an attribute identifier.
func pathFromIdentifier(id string) string {
	// urn:siros:attr:<slug>:<hash> → extract slug, convert dashes back to dots
	parts := strings.Split(id, ":")
	if len(parts) >= 4 {
		slug := parts[3]
		return strings.ReplaceAll(slug, "-", ".")
	}
	return id
}
