package schema

import (
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
)

func TestMapType(t *testing.T) {
	tests := []struct {
		input    string
		wantType string
		wantFmt  string
	}{
		{"string", "string", ""},
		{"STRING", "string", ""},
		{"number", "number", ""},
		{"integer", "integer", ""},
		{"boolean", "boolean", ""},
		{"bool", "boolean", ""},
		{"date", "string", "date"},
		{"datetime", "string", "date-time"},
		{"image", "string", ""},
		{"object", "object", ""},
		{"array", "array", ""},
		{"unknown", "string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			prop := MapType(tt.input)
			if prop.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", prop.Type, tt.wantType)
			}
			if prop.Format != tt.wantFmt {
				t.Errorf("Format = %q, want %q", prop.Format, tt.wantFmt)
			}
		})
	}
}

func TestMapType_ImageEncoding(t *testing.T) {
	prop := MapType("image")
	if prop.ContentEncoding != "base64" {
		t.Errorf("ContentEncoding = %q, want 'base64'", prop.ContentEncoding)
	}
}

func TestMapType_ArrayItems(t *testing.T) {
	prop := MapType("array")
	if prop.Items == nil {
		t.Fatal("Items should not be nil for array type")
	}
	if prop.Items.Type != "string" {
		t.Errorf("Items.Type = %q, want 'string'", prop.Items.Type)
	}
}

func TestMapType_ObjectProperties(t *testing.T) {
	prop := MapType("object")
	if prop.Properties == nil {
		t.Fatal("Properties should not be nil for object type")
	}
}

func TestBuildProperties_Basic(t *testing.T) {
	claims := []formats.ClaimDefinition{
		{Name: "name", Type: "string", DisplayName: "Name", Mandatory: true},
		{Name: "age", Type: "integer", DisplayName: "Age"},
	}

	props, required := BuildProperties(claims, nil, "test")

	if len(props) != 2 {
		t.Fatalf("got %d properties, want 2", len(props))
	}
	if props["name"] == nil || props["name"].Type != "string" {
		t.Error("name property missing or wrong type")
	}
	if props["age"] == nil || props["age"].Type != "integer" {
		t.Error("age property missing or wrong type")
	}
	if len(required) != 1 || required[0] != "name" {
		t.Errorf("required = %v, want [name]", required)
	}
}

func TestBuildProperties_WithClaimMappings(t *testing.T) {
	claims := []formats.ClaimDefinition{
		{Name: "given_name", Type: "string", DisplayName: "Given Name"},
	}
	mappings := map[string]map[string]string{
		"w3c": {"given_name": "givenName"},
	}

	props, _ := BuildProperties(claims, mappings, "w3c")

	if props["givenName"] == nil {
		t.Error("expected claim mapped to 'givenName'")
	}
	if props["given_name"] != nil {
		t.Error("original name should not be present when mapped")
	}
}

func TestBuildProperties_WithFormatMappings(t *testing.T) {
	claims := []formats.ClaimDefinition{
		{
			Name:           "birth_date",
			Type:           "date",
			DisplayName:    "Date of Birth",
			FormatMappings: map[string]string{"w3c": "birthDate"},
		},
	}

	props, _ := BuildProperties(claims, nil, "w3c")

	if props["birthDate"] == nil {
		t.Error("expected claim mapped to 'birthDate' via FormatMappings")
	}
}

func TestClaimToProperty_TitleFallback(t *testing.T) {
	claim := formats.ClaimDefinition{
		Name:        "field",
		Type:        "string",
		Description: "desc",
	}
	prop := ClaimToProperty(claim, nil, "test")
	if prop.Title != "field" {
		t.Errorf("Title = %q, want 'field' (fallback to Name)", prop.Title)
	}
	if prop.Description != "desc" {
		t.Errorf("Description = %q, want 'desc'", prop.Description)
	}
}

func TestClaimToProperty_NestedObject(t *testing.T) {
	claim := formats.ClaimDefinition{
		Name: "address", Type: "object", DisplayName: "Address",
		Children: []formats.ClaimDefinition{
			{Name: "street", Type: "string", DisplayName: "Street", Mandatory: true},
			{Name: "city", Type: "string", DisplayName: "City"},
		},
	}

	prop := ClaimToProperty(claim, nil, "test")

	if prop.Type != "object" {
		t.Fatalf("Type = %q, want 'object'", prop.Type)
	}
	if len(prop.Properties) != 2 {
		t.Fatalf("got %d nested properties, want 2", len(prop.Properties))
	}
	if prop.Properties["street"] == nil {
		t.Error("street property missing")
	}
	if len(prop.Required) != 1 || prop.Required[0] != "street" {
		t.Errorf("Required = %v, want [street]", prop.Required)
	}
}

func TestClaimToProperty_NestedArray(t *testing.T) {
	claim := formats.ClaimDefinition{
		Name: "items", Type: "array", DisplayName: "Items",
		Children: []formats.ClaimDefinition{
			{Name: "label", Type: "string", DisplayName: "Label", Mandatory: true},
			{Name: "value", Type: "number", DisplayName: "Value"},
		},
	}

	prop := ClaimToProperty(claim, nil, "test")

	if prop.Type != "array" {
		t.Fatalf("Type = %q, want 'array'", prop.Type)
	}
	if prop.Items == nil {
		t.Fatal("Items should not be nil for array with children")
	}
	if prop.Items.Type != "object" {
		t.Errorf("Items.Type = %q, want 'object'", prop.Items.Type)
	}
	if len(prop.Items.Properties) != 2 {
		t.Fatalf("got %d item properties, want 2", len(prop.Items.Properties))
	}
	if len(prop.Items.Required) != 1 || prop.Items.Required[0] != "label" {
		t.Errorf("Items.Required = %v, want [label]", prop.Items.Required)
	}
}

func TestResolveName_ClaimMappingsOverrideFormatMappings(t *testing.T) {
	claim := formats.ClaimDefinition{
		Name:           "field",
		FormatMappings: map[string]string{"fmt": "formatMapped"},
	}
	claimMappings := map[string]map[string]string{
		"fmt": {"field": "claimMapped"},
	}

	// ClaimMappings should take precedence (applied second)
	props, _ := BuildProperties([]formats.ClaimDefinition{claim}, claimMappings, "fmt")

	if props["claimMapped"] == nil {
		t.Error("expected claimMappings to override FormatMappings")
	}
}

func TestBuildProperties_Empty(t *testing.T) {
	props, required := BuildProperties(nil, nil, "test")
	if len(props) != 0 {
		t.Errorf("expected empty properties, got %d", len(props))
	}
	if required != nil {
		t.Errorf("expected nil required, got %v", required)
	}
}
