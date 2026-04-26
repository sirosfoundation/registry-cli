package attributes

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInferFromCredentials_Empty(t *testing.T) {
	attrs := InferFromCredentials(nil, "https://registry.example.org")
	assert.Empty(t, attrs)
}

func TestInferFromCredentials_SingleCredential(t *testing.T) {
	creds := []CredentialInput{
		{
			SchemaID: "uuid-1",
			Org:      "org1",
			Slug:     "identity",
			Name:     "Identity Credential",
			VCT:      "https://credentials.example.com/identity",
			Claims: []ClaimInput{
				{Path: []string{"given_name"}, DisplayName: "Given Name", DisplayLang: "en"},
				{Path: []string{"family_name"}, DisplayName: "Family Name", DisplayLang: "en"},
			},
		},
	}

	attrs := InferFromCredentials(creds, "https://registry.example.org")

	assert.Len(t, attrs, 2)
	assert.Equal(t, "Given Name", attrs[0].Name[0].Value)
	assert.Equal(t, "en", attrs[0].Name[0].Lang)
	assert.Equal(t, "https://credentials.example.com", attrs[0].NameSpace)
	assert.Len(t, attrs[0].Distributions, 1)
	assert.Equal(t, "application/schema+json", attrs[0].Distributions[0].MediaType)
	assert.Contains(t, attrs[0].Distributions[0].AccessURL, "given_name")
	assert.Len(t, attrs[0].UsedBy, 1)
	assert.Equal(t, "uuid-1", attrs[0].UsedBy[0].SchemaID)
}

func TestInferFromCredentials_Deduplication(t *testing.T) {
	creds := []CredentialInput{
		{
			SchemaID: "uuid-1",
			Org:      "org1",
			Slug:     "identity",
			Name:     "Identity",
			VCT:      "https://creds.example.com/identity",
			Claims:   []ClaimInput{{Path: []string{"given_name"}, DisplayName: "Given Name"}},
		},
		{
			SchemaID: "uuid-2",
			Org:      "org2",
			Slug:     "diploma",
			Name:     "Diploma",
			VCT:      "https://creds.example.com/diploma",
			Claims:   []ClaimInput{{Path: []string{"given_name"}, DisplayName: "Given Name"}},
		},
	}

	attrs := InferFromCredentials(creds, "https://registry.example.org")

	// Same namespace + path → deduplicated into one attribute
	assert.Len(t, attrs, 1)
	assert.Len(t, attrs[0].UsedBy, 2)
	assert.Equal(t, "uuid-1", attrs[0].UsedBy[0].SchemaID)
	assert.Equal(t, "uuid-2", attrs[0].UsedBy[1].SchemaID)
}

func TestInferFromCredentials_DifferentNamespaces(t *testing.T) {
	creds := []CredentialInput{
		{
			SchemaID: "uuid-1",
			Org:      "org1",
			Slug:     "identity",
			VCT:      "https://ns-a.example.com/identity",
			Claims:   []ClaimInput{{Path: []string{"name"}, DisplayName: "Name"}},
		},
		{
			SchemaID: "uuid-2",
			Org:      "org2",
			Slug:     "diploma",
			VCT:      "https://ns-b.example.com/diploma",
			Claims:   []ClaimInput{{Path: []string{"name"}, DisplayName: "Name"}},
		},
	}

	attrs := InferFromCredentials(creds, "https://registry.example.org")

	// Different namespaces → different attributes even with same path
	assert.Len(t, attrs, 2)
	assert.Equal(t, "https://ns-a.example.com", attrs[0].NameSpace)
	assert.Equal(t, "https://ns-b.example.com", attrs[1].NameSpace)
}

func TestInferFromCredentials_FallbackDisplayName(t *testing.T) {
	creds := []CredentialInput{
		{
			SchemaID: "uuid-1",
			Org:      "org1",
			Slug:     "identity",
			VCT:      "https://creds.example.com/identity",
			Claims:   []ClaimInput{{Path: []string{"birth_date"}}}, // no display name
		},
	}

	attrs := InferFromCredentials(creds, "https://registry.example.org")

	assert.Len(t, attrs, 1)
	assert.Equal(t, "birth_date", attrs[0].Name[0].Value, "should fall back to path")
}

func TestInferFromCredentials_NestedPath(t *testing.T) {
	creds := []CredentialInput{
		{
			SchemaID: "uuid-1",
			Org:      "org1",
			Slug:     "identity",
			VCT:      "https://creds.example.com/identity",
			Claims:   []ClaimInput{{Path: []string{"address", "street"}, DisplayName: "Street"}},
		},
	}

	attrs := InferFromCredentials(creds, "https://registry.example.org")

	assert.Len(t, attrs, 1)
	assert.Contains(t, attrs[0].Identifier, "address-street")
	assert.Contains(t, attrs[0].Distributions[0].AccessURL, "address-street")
}

func TestGenerateSchemas(t *testing.T) {
	attrs := []Attribute{
		{
			Identifier: "urn:siros:attr:given-name:abc123",
			Name:       []LangValue{{Value: "Given Name", Lang: "en"}},
		},
		{
			Identifier: "urn:siros:attr:family-name:def456",
			Name:       []LangValue{{Value: "Family Name", Lang: "en"}},
		},
	}

	schemas := GenerateSchemas(attrs)

	assert.Len(t, schemas, 2)
	assert.Contains(t, schemas, "given-name.json")
	assert.Contains(t, schemas, "family-name.json")

	// Verify it's valid JSON
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(schemas["given-name.json"], &parsed))
	assert.Equal(t, "Given Name", parsed["title"])
	assert.Equal(t, "https://json-schema.org/draft/2020-12/schema", parsed["$schema"])
}

func TestNamespaceFromVCT(t *testing.T) {
	tests := []struct {
		vct    string
		expect string
	}{
		{"https://credentials.example.com/identity", "https://credentials.example.com"},
		{"https://example.org/path/to/cred", "https://example.org"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.vct, func(t *testing.T) {
			assert.Equal(t, tt.expect, namespaceFromVCT(tt.vct))
		})
	}
}

func TestAttributeIdentifier_Deterministic(t *testing.T) {
	id1 := attributeIdentifier("https://example.com", "given_name")
	id2 := attributeIdentifier("https://example.com", "given_name")
	assert.Equal(t, id1, id2, "same inputs should produce same identifier")

	id3 := attributeIdentifier("https://other.com", "given_name")
	assert.NotEqual(t, id1, id3, "different namespace should produce different identifier")
}

func TestSlugFromPath(t *testing.T) {
	assert.Equal(t, "given_name", slugFromPath("given_name"))
	assert.Equal(t, "address-street", slugFromPath("address.street"))
}
