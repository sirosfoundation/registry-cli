package w3c

import (
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
)

func TestNewGenerator(t *testing.T) {
	g := NewGenerator()
	if g == nil {
		t.Fatal("NewGenerator returned nil")
	}
}

func TestGenerator_Name(t *testing.T) {
	g := NewGenerator()
	if g.Name() != "w3c" {
		t.Errorf("Name() = %q, want 'w3c'", g.Name())
	}
}

func TestGenerator_Description(t *testing.T) {
	g := NewGenerator()
	desc := g.Description()
	if desc == "" {
		t.Error("Description should not be empty")
	}
	if !contains(desc, "W3C") {
		t.Errorf("Description = %q, should mention W3C", desc)
	}
}

func TestGenerator_FileExtension(t *testing.T) {
	g := NewGenerator()
	if g.FileExtension() != "vc.json" {
		t.Errorf("FileExtension() = %q, want 'vc.json'", g.FileExtension())
	}
}

func TestGenerator_DeriveIdentifier(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		name string
		cred *formats.ParsedCredential
		cfg  *config.Config
		want string
	}{
		{
			name: "derives from name",
			cred: &formats.ParsedCredential{
				Name: "Person Identification Data",
			},
			cfg:  &config.Config{},
			want: "PersonIdentificationData",
		},
		{
			name: "uses explicit W3CTypes",
			cred: &formats.ParsedCredential{
				W3CTypes: []string{"VerifiableCredential", "DriverLicense"},
			},
			cfg:  &config.Config{},
			want: "DriverLicense",
		},
		{
			name: "falls back to ID",
			cred: &formats.ParsedCredential{
				ID: "pid",
			},
			cfg:  &config.Config{},
			want: "Pid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := g.DeriveIdentifier(tt.cred, tt.cfg)
			if got != tt.want {
				t.Errorf("DeriveIdentifier() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerator_deriveTypes(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		name     string
		cred     *formats.ParsedCredential
		cfg      *config.Config
		wantLen  int
		wantType string
	}{
		{
			name: "explicit types with VerifiableCredential",
			cred: &formats.ParsedCredential{
				W3CTypes: []string{"VerifiableCredential", "IdentityCredential"},
			},
			cfg:      &config.Config{},
			wantLen:  2,
			wantType: "IdentityCredential",
		},
		{
			name: "explicit types without VerifiableCredential",
			cred: &formats.ParsedCredential{
				W3CTypes: []string{"DriverLicense"},
			},
			cfg:      &config.Config{},
			wantLen:  2, // VerifiableCredential added
			wantType: "DriverLicense",
		},
		{
			name: "from format overrides",
			cred: &formats.ParsedCredential{
				FormatOverrides: map[string]map[string]interface{}{
					"w3c": {
						"type": []interface{}{"CustomCredential"},
					},
				},
			},
			cfg:      &config.Config{},
			wantLen:  2, // VerifiableCredential added
			wantType: "CustomCredential",
		},
		{
			name: "derived from name",
			cred: &formats.ParsedCredential{
				Name: "Student Card",
			},
			cfg:      &config.Config{},
			wantLen:  2,
			wantType: "StudentCard",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			types := g.deriveTypes(tt.cred, tt.cfg)
			if len(types) != tt.wantLen {
				t.Errorf("len(types) = %d, want %d", len(types), tt.wantLen)
			}
			if types[0] != "VerifiableCredential" {
				t.Errorf("types[0] = %q, want 'VerifiableCredential'", types[0])
			}
			if len(types) > 1 && types[len(types)-1] != tt.wantType {
				t.Errorf("types[last] = %q, want %q", types[len(types)-1], tt.wantType)
			}
		})
	}
}

func TestGenerator_deriveContext(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		name    string
		cred    *formats.ParsedCredential
		cfg     *config.Config
		wantLen int
		want0   string
	}{
		{
			name: "explicit context",
			cred: &formats.ParsedCredential{
				W3CContext: []string{"https://www.w3.org/2018/credentials/v1", "https://example.com/context"},
			},
			cfg:     &config.Config{},
			wantLen: 2,
			want0:   "https://www.w3.org/2018/credentials/v1",
		},
		{
			name: "from format overrides",
			cred: &formats.ParsedCredential{
				FormatOverrides: map[string]map[string]interface{}{
					"w3c": {
						"context": []interface{}{"https://custom.example/v1"},
					},
				},
			},
			cfg:     &config.Config{},
			wantLen: 1,
			want0:   "https://custom.example/v1",
		},
		{
			name: "default with base URL",
			cred: &formats.ParsedCredential{
				ID: "identity",
			},
			cfg: &config.Config{
				BaseURL: "https://registry.example.com",
			},
			wantLen: 2,
			want0:   "https://www.w3.org/2018/credentials/v1",
		},
		{
			name:    "default without base URL",
			cred:    &formats.ParsedCredential{},
			cfg:     &config.Config{},
			wantLen: 1,
			want0:   "https://www.w3.org/2018/credentials/v1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := g.deriveContext(tt.cred, tt.cfg)
			if len(ctx) != tt.wantLen {
				t.Errorf("len(context) = %d, want %d", len(ctx), tt.wantLen)
			}
			if ctx[0] != tt.want0 {
				t.Errorf("context[0] = %q, want %q", ctx[0], tt.want0)
			}
		})
	}
}

func TestGenerator_Generate_Minimal(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name: "Test Credential",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed W3CCredentialSchema
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if len(parsed.Type) < 2 {
		t.Errorf("Type should have at least 2 entries")
	}
	if parsed.Type[0] != "VerifiableCredential" {
		t.Errorf("Type[0] = %q, want 'VerifiableCredential'", parsed.Type[0])
	}
	if parsed.Name != "Test Credential" {
		t.Errorf("Name = %q", parsed.Name)
	}
}

func TestGenerator_Generate_WithDescription(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:        "Test",
		Description: "A test credential",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed W3CCredentialSchema
	json.Unmarshal(output, &parsed)

	if parsed.Description != "A test credential" {
		t.Errorf("Description = %q", parsed.Description)
	}
}

func TestGenerator_Generate_WithColors(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:            "Test",
		BackgroundColor: "#ff0000",
		TextColor:       "#ffffff",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed W3CCredentialSchema
	json.Unmarshal(output, &parsed)

	if parsed.Display == nil {
		t.Fatal("Display should not be nil")
	}
	if parsed.Display.BackgroundColor != "#ff0000" {
		t.Errorf("BackgroundColor = %q", parsed.Display.BackgroundColor)
	}
	if parsed.Display.TextColor != "#ffffff" {
		t.Errorf("TextColor = %q", parsed.Display.TextColor)
	}
}

func TestGenerator_Generate_WithClaims(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name: "Test",
		Claims: []formats.ClaimDefinition{
			{
				Name:        "given_name",
				DisplayName: "Given Name",
				Description: "The holder's given name",
				Type:        "string",
				Mandatory:   true,
			},
			{
				Name: "birth_date",
				Type: "date",
			},
			{
				Name:      "is_adult",
				Type:      "boolean",
				Mandatory: true,
			},
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed W3CCredentialSchema
	json.Unmarshal(output, &parsed)

	if parsed.CredentialSchema == nil {
		t.Fatal("CredentialSchema should not be nil")
	}
	if parsed.CredentialSchema.Type != "JsonSchema" {
		t.Errorf("CredentialSchema.Type = %q", parsed.CredentialSchema.Type)
	}

	// Check credentialSubject properties
	csRaw, ok := parsed.CredentialSchema.Properties["credentialSubject"]
	if !ok {
		t.Fatal("Missing credentialSubject")
	}

	cs, ok := csRaw.(*CredentialSubjectSchema)
	if !ok {
		// Parse from raw JSON
		csJSON, _ := json.Marshal(csRaw)
		var csMap map[string]interface{}
		json.Unmarshal(csJSON, &csMap)

		// Check properties exist
		props, ok := csMap["properties"].(map[string]interface{})
		if !ok {
			t.Fatal("Missing credentialSubject.properties")
		}
		if props["given_name"] == nil {
			t.Error("Missing given_name property")
		}
		if props["birth_date"] == nil {
			t.Error("Missing birth_date property")
		}

		// Check required
		required, ok := csMap["required"].([]interface{})
		if !ok {
			t.Fatal("Missing credentialSubject.required")
		}
		requiredSet := make(map[string]bool)
		for _, r := range required {
			if s, ok := r.(string); ok {
				requiredSet[s] = true
			}
		}
		if !requiredSet["given_name"] {
			t.Error("given_name should be required")
		}
		if !requiredSet["is_adult"] {
			t.Error("is_adult should be required")
		}
		return
	}

	if cs.Properties["given_name"] == nil {
		t.Error("Missing given_name property")
	}
}

func TestGenerator_Generate_WithClaimMappings(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name: "Test",
		Claims: []formats.ClaimDefinition{
			{
				Name: "given_name",
				Type: "string",
				FormatMappings: map[string]string{
					"w3c": "givenName",
				},
			},
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should use mapped name "givenName" instead of "given_name"
	if !contains(string(output), "givenName") {
		t.Error("Output should contain 'givenName' (mapped)")
	}
}

func TestMapTypeToJSONSchema(t *testing.T) {
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
		{"image", "string", ""}, // has contentEncoding
		{"object", "object", ""},
		{"array", "array", ""},
		{"unknown", "string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			prop := mapTypeToJSONSchema(tt.input)
			if prop.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", prop.Type, tt.wantType)
			}
			if prop.Format != tt.wantFmt {
				t.Errorf("Format = %q, want %q", prop.Format, tt.wantFmt)
			}
		})
	}
}

func TestMapTypeToJSONSchema_ImageEncoding(t *testing.T) {
	prop := mapTypeToJSONSchema("image")
	if prop.ContentEncoding != "base64" {
		t.Errorf("ContentEncoding = %q, want 'base64'", prop.ContentEncoding)
	}
}

func TestMapTypeToJSONSchema_ArrayItems(t *testing.T) {
	prop := mapTypeToJSONSchema("array")
	if prop.Items == nil {
		t.Fatal("Items should not be nil for array type")
	}
	if prop.Items.Type != "string" {
		t.Errorf("Items.Type = %q, want 'string'", prop.Items.Type)
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
