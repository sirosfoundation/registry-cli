package mddl

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
	if g.Name() != "mddl" {
		t.Errorf("Name() = %q, want 'mddl'", g.Name())
	}
}

func TestGenerator_Description(t *testing.T) {
	g := NewGenerator()
	desc := g.Description()
	if desc == "" {
		t.Error("Description should not be empty")
	}
	if !contains(desc, "mso_mdoc") && !contains(desc, "ISO 18013") {
		t.Errorf("Description = %q, should mention mso_mdoc or ISO 18013", desc)
	}
}

func TestGenerator_FileExtension(t *testing.T) {
	g := NewGenerator()
	if g.FileExtension() != "mdoc.json" {
		t.Errorf("FileExtension() = %q, want 'mdoc.json'", g.FileExtension())
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
			name: "explicit doctype",
			cred: &formats.ParsedCredential{
				ID:      "fallback",
				DocType: "org.iso.18013.5.1.mDL",
			},
			cfg:  &config.Config{},
			want: "org.iso.18013.5.1.mDL",
		},
		{
			name: "from format overrides",
			cred: &formats.ParsedCredential{
				ID: "test",
				FormatOverrides: map[string]map[string]interface{}{
					"mddl": {"doctype": "org.example.custom"},
				},
			},
			cfg:  &config.Config{},
			want: "org.example.custom",
		},
		{
			name: "derived from base URL",
			cred: &formats.ParsedCredential{
				ID: "pid",
			},
			cfg: &config.Config{
				BaseURL: "https://registry.siros.org",
			},
			want: "org.siros.registry.credentials.pid",
		},
		{
			name: "empty when no source",
			cred: &formats.ParsedCredential{
				ID: "test",
			},
			cfg:  &config.Config{},
			want: "",
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

func TestGenerator_DeriveNamespace(t *testing.T) {
	g := NewGenerator()

	tests := []struct {
		name string
		cred *formats.ParsedCredential
		cfg  *config.Config
		want string
	}{
		{
			name: "explicit namespace",
			cred: &formats.ParsedCredential{
				Namespace: "org.iso.18013.5.1",
				DocType:   "org.iso.18013.5.1.mDL",
			},
			cfg:  &config.Config{},
			want: "org.iso.18013.5.1",
		},
		{
			name: "from format overrides",
			cred: &formats.ParsedCredential{
				DocType: "org.example.test",
				FormatOverrides: map[string]map[string]interface{}{
					"mddl": {"namespace": "org.example.custom.ns"},
				},
			},
			cfg:  &config.Config{},
			want: "org.example.custom.ns",
		},
		{
			name: "defaults to doctype",
			cred: &formats.ParsedCredential{
				DocType: "org.example.credentials.identity",
			},
			cfg:  &config.Config{},
			want: "org.example.credentials.identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := g.deriveNamespace(tt.cred, tt.cfg)
			if got != tt.want {
				t.Errorf("deriveNamespace() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerator_Generate_Minimal(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:    "Test Credential",
		DocType: "org.example.test",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed MDDL
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	if parsed.Format != "mso_mdoc" {
		t.Errorf("format = %q, want 'mso_mdoc'", parsed.Format)
	}
	if parsed.DocType != "org.example.test" {
		t.Errorf("doctype = %q, want 'org.example.test'", parsed.DocType)
	}
}

func TestGenerator_Generate_DoctypeRequired(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name: "Test",
		// No doctype and no base_url
	}

	_, err := g.Generate(cred, cfg)
	if err == nil {
		t.Error("Expected error for missing doctype")
	}
	if !contains(err.Error(), "doctype") {
		t.Errorf("Error = %q, should mention 'doctype'", err.Error())
	}
}

func TestGenerator_Generate_WithDisplay(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:            "Identity Card",
		Description:     "A digital identity card",
		DocType:         "org.example.identity",
		BackgroundColor: "#0000ff",
		TextColor:       "#ffffff",
		LogoPath:        "logo.png",
		LogoAltText:     "ID Logo",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed MDDL
	json.Unmarshal(output, &parsed)

	if len(parsed.Display) != 1 {
		t.Fatalf("len(Display) = %d, want 1", len(parsed.Display))
	}

	d := parsed.Display[0]
	if d.Locale != "en-US" {
		t.Errorf("Display.Locale = %q", d.Locale)
	}
	if d.Name != "Identity Card" {
		t.Errorf("Display.Name = %q", d.Name)
	}
	if d.Description != "A digital identity card" {
		t.Errorf("Display.Description = %q", d.Description)
	}
	if d.BackgroundColor != "#0000ff" {
		t.Errorf("Display.BackgroundColor = %q", d.BackgroundColor)
	}
	if d.Logo == nil {
		t.Fatal("Display.Logo is nil")
	}
	if d.Logo.URI != "logo.png" {
		t.Errorf("Display.Logo.URI = %q", d.Logo.URI)
	}
}

func TestGenerator_Generate_WithLocalizations(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:    "Driver License",
		DocType: "org.iso.18013.5.1.mDL",
		Localizations: map[string]formats.DisplayLocalization{
			"de-DE": {Name: "Führerschein", Description: "Ein digitaler Führerschein"},
			"sv":    {Name: "Körkort", Description: "Ett digitalt körkort"},
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed MDDL
	json.Unmarshal(output, &parsed)

	// Should have 3 display entries (en-US + de-DE + sv)
	if len(parsed.Display) != 3 {
		t.Errorf("len(Display) = %d, want 3", len(parsed.Display))
	}

	locales := make(map[string]bool)
	for _, d := range parsed.Display {
		locales[d.Locale] = true
	}
	if !locales["en-US"] || !locales["de-DE"] || !locales["sv"] {
		t.Errorf("Missing locales, got: %v", locales)
	}
}

func TestGenerator_Generate_WithClaims(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:      "Test",
		DocType:   "org.example.test",
		Namespace: "org.example.ns",
		Claims: []formats.ClaimDefinition{
			{
				Name:        "given_name",
				DisplayName: "Given Name",
				Type:        "string",
				Mandatory:   true,
			},
			{
				Name:        "birth_date",
				DisplayName: "Birth Date",
				Type:        "date",
				Mandatory:   false,
			},
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed MDDL
	json.Unmarshal(output, &parsed)

	if parsed.Claims == nil {
		t.Fatal("Claims is nil")
	}

	nsClaims, ok := parsed.Claims["org.example.ns"]
	if !ok {
		t.Fatal("Missing namespace in claims")
	}

	givenName, ok := nsClaims["given_name"]
	if !ok {
		t.Fatal("Missing given_name claim")
	}
	if !givenName.Mandatory {
		t.Error("given_name should be mandatory")
	}
	if givenName.ValueType != "tstr" {
		t.Errorf("given_name.ValueType = %q, want 'tstr'", givenName.ValueType)
	}
	if len(givenName.Display) == 0 {
		t.Error("given_name.Display should not be empty")
	}

	birthDate, ok := nsClaims["birth_date"]
	if !ok {
		t.Fatal("Missing birth_date claim")
	}
	if birthDate.ValueType != "full-date" {
		t.Errorf("birth_date.ValueType = %q, want 'full-date'", birthDate.ValueType)
	}
}

func TestGenerator_Generate_WithClaimMappings(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:      "Test",
		DocType:   "org.example.test",
		Namespace: "org.example.ns",
		Claims: []formats.ClaimDefinition{
			{
				Name: "given_name",
				Type: "string",
				FormatMappings: map[string]string{
					"mddl": "first_name",
				},
			},
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed MDDL
	json.Unmarshal(output, &parsed)

	nsClaims := parsed.Claims["org.example.ns"]

	// Should use mapped name "first_name" instead of "given_name"
	if _, ok := nsClaims["first_name"]; !ok {
		t.Error("Claim should be mapped to 'first_name'")
	}
	if _, ok := nsClaims["given_name"]; ok {
		t.Error("Should not have 'given_name', should be mapped")
	}
}

func TestGenerator_Generate_WithOrder(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:    "Test",
		DocType: "org.example.test",
		FormatOverrides: map[string]map[string]interface{}{
			"mddl": {"order": 5},
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed MDDL
	json.Unmarshal(output, &parsed)

	if parsed.Order == nil {
		t.Fatal("Order should be set")
	}
	if *parsed.Order != 5 {
		t.Errorf("Order = %d, want 5", *parsed.Order)
	}
}

func TestMapTypeToCDDL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"string", "tstr"},
		{"STRING", "tstr"},
		{"number", "int"},
		{"integer", "uint"},
		{"boolean", "bool"},
		{"bool", "bool"},
		{"date", "full-date"},
		{"datetime", "tdate"},
		{"image", "bstr"},
		{"object", ""},
		{"array", ""},
		{"unknown", "tstr"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := mapTypeToCDDL(tt.input)
			if got != tt.want {
				t.Errorf("mapTypeToCDDL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
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

func TestGenerator_Generate_NestedObjectClaims(t *testing.T) {
	g := NewGenerator()
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:      "Test",
		DocType:   "org.example.test",
		Namespace: "org.example.test",
		Claims: []formats.ClaimDefinition{
			{
				Name:        "address",
				DisplayName: "Address",
				Type:        "object",
				Children: []formats.ClaimDefinition{
					{Name: "street", DisplayName: "Street", Type: "string"},
					{Name: "city", DisplayName: "City", Type: "string", Mandatory: true},
				},
			},
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(output, &raw); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}

	claims := raw["claims"].(map[string]interface{})
	ns := claims["org.example.test"].(map[string]interface{})

	// Object children should be flattened with dot notation
	if ns["address.street"] == nil {
		t.Error("missing address.street (flattened claim)")
	}
	if ns["address.city"] == nil {
		t.Error("missing address.city (flattened claim)")
	}
	// Parent "address" should NOT be emitted directly
	if ns["address"] != nil {
		t.Error("container 'address' should not be emitted as a leaf claim")
	}
}
