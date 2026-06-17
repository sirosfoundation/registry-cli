package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"

	// Import format packages to trigger their init() registration
	_ "github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats/vctmfmt"
)

func TestParser_ToCredential(t *testing.T) {
	cfg := &config.Config{
		Language:  "en-US",
		BaseURL:   "https://registry.example.com",
		InputFile: "/test/path/identity.md",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Title:       "Test Credential",
		Description: "A test credential description",
		Sections:    map[string]string{},
		Images: []ImageRef{
			{Path: "images/logo.png", AltText: "Logo"},
		},
		Claims: map[string]ClaimDef{
			"given_name": {
				Name:        "given_name",
				DisplayName: "Given Name",
				Type:        "string",
				Description: "The given name of the holder",
				Mandatory:   true,
				SD:          "always",
				SvgId:       "givenName",
				Localizations: map[string]ClaimLocalization{
					"de-DE": {Label: "Vorname", Description: "Der Vorname"},
				},
			},
			"address.city": {
				Name:        "address.city",
				DisplayName: "City",
				Type:        "string",
				Description: "City name",
			},
		},
		DisplayLocalizations: map[string]DisplayLocalization{
			"de-DE": {Name: "Test Beleg", Description: "Ein Test-Beleg"},
		},
		Metadata: map[string]string{
			"vct":                    "https://example.com/credentials/test",
			"doctype":                "org.example.test",
			"namespace":              "org.example.test",
			"background_color":       "\"#ffffff\"",
			"text_color":             "\"#000000\"",
			"logo":                   "\"images/logo.png\"",
			"svg_template":           "\"template.svg\"",
			"svg_template_uri":       "\"https://example.com/template.svg\"",
			"svg_template_integrity": "\"sha256-abc123\"",
		},
	}

	cred := p.ToCredential(parsed)

	// Test basic fields
	if cred.Name != "Test Credential" {
		t.Errorf("Name = %q, want %q", cred.Name, "Test Credential")
	}
	if cred.Description != "A test credential description" {
		t.Errorf("Description = %q, want %q", cred.Description, "A test credential description")
	}

	// Test ID derived from input file
	if cred.ID != "identity" {
		t.Errorf("ID = %q, want %q", cred.ID, "identity")
	}

	// Test source paths
	if cred.SourcePath != "/test/path/identity.md" {
		t.Errorf("SourcePath = %q", cred.SourcePath)
	}
	if cred.SourceDir != "/test/path" {
		t.Errorf("SourceDir = %q", cred.SourceDir)
	}

	// Test metadata extraction
	if cred.VCT != "https://example.com/credentials/test" {
		t.Errorf("VCT = %q", cred.VCT)
	}
	if cred.DocType != "org.example.test" {
		t.Errorf("DocType = %q", cred.DocType)
	}
	if cred.Namespace != "org.example.test" {
		t.Errorf("Namespace = %q", cred.Namespace)
	}
	if cred.BackgroundColor != "#ffffff" {
		t.Errorf("BackgroundColor = %q, want #ffffff", cred.BackgroundColor)
	}
	if cred.TextColor != "#000000" {
		t.Errorf("TextColor = %q, want #000000", cred.TextColor)
	}
	if cred.LogoPath != "images/logo.png" {
		t.Errorf("LogoPath = %q", cred.LogoPath)
	}
	if cred.SVGTemplatePath != "template.svg" {
		t.Errorf("SVGTemplatePath = %q", cred.SVGTemplatePath)
	}
	if cred.SVGTemplateURI != "https://example.com/template.svg" {
		t.Errorf("SVGTemplateURI = %q", cred.SVGTemplateURI)
	}
	if cred.SVGTemplateIntegrity != "sha256-abc123" {
		t.Errorf("SVGTemplateIntegrity = %q", cred.SVGTemplateIntegrity)
	}

	// Test localizations
	if len(cred.Localizations) != 1 {
		t.Errorf("len(Localizations) = %d, want 1", len(cred.Localizations))
	}
	if loc, ok := cred.Localizations["de-DE"]; ok {
		if loc.Name != "Test Beleg" {
			t.Errorf("Localization name = %q", loc.Name)
		}
	} else {
		t.Error("Missing de-DE localization")
	}

	// Test claims
	if len(cred.Claims) != 2 {
		t.Errorf("len(Claims) = %d, want 2", len(cred.Claims))
	}

	var foundGivenName, foundAddressCity bool
	for _, claim := range cred.Claims {
		if claim.Name == "given_name" {
			foundGivenName = true
			if claim.DisplayName != "Given Name" {
				t.Errorf("given_name DisplayName = %q", claim.DisplayName)
			}
			if !claim.Mandatory {
				t.Error("given_name should be mandatory")
			}
			if claim.SD != "always" {
				t.Errorf("given_name SD = %q", claim.SD)
			}
			if claim.SvgId != "givenName" {
				t.Errorf("given_name SvgId = %q", claim.SvgId)
			}
			if len(claim.Path) != 1 || claim.Path[0] != "given_name" {
				t.Errorf("given_name Path = %v", claim.Path)
			}
			if loc, ok := claim.Localizations["de-DE"]; ok {
				if loc.Label != "Vorname" {
					t.Errorf("claim localization label = %q", loc.Label)
				}
			} else {
				t.Error("Missing de-DE claim localization")
			}
		}
		if claim.Name == "address.city" {
			foundAddressCity = true
			if len(claim.Path) != 2 || claim.Path[0] != "address" || claim.Path[1] != "city" {
				t.Errorf("address.city Path = %v", claim.Path)
			}
		}
	}
	if !foundGivenName {
		t.Error("Missing given_name claim")
	}
	if !foundAddressCity {
		t.Error("Missing address.city claim")
	}

	// Test images
	if len(cred.Images) != 1 {
		t.Errorf("len(Images) = %d, want 1", len(cred.Images))
	} else {
		if cred.Images[0].Path != "images/logo.png" {
			t.Errorf("Image path = %q", cred.Images[0].Path)
		}
		if cred.Images[0].AltText != "Logo" {
			t.Errorf("Image alt = %q", cred.Images[0].AltText)
		}
	}
}

func TestParser_ToCredential_NoInputFile(t *testing.T) {
	cfg := &config.Config{
		Language: "en-US",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Title:       "Test",
		Description: "Test description",
		Sections:    map[string]string{},
		Images:      []ImageRef{},
		Claims:      map[string]ClaimDef{},
		Metadata:    map[string]string{},
	}

	cred := p.ToCredential(parsed)

	// ID should be empty when no input file
	if cred.ID != "" {
		t.Errorf("ID = %q, want empty", cred.ID)
	}
	if cred.SourcePath != "" {
		t.Errorf("SourcePath = %q, want empty", cred.SourcePath)
	}
}

func TestParser_ToCredential_MetadataID(t *testing.T) {
	cfg := &config.Config{
		Language:  "en-US",
		InputFile: "/test/default.md",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Title:    "Test",
		Sections: map[string]string{},
		Images:   []ImageRef{},
		Claims:   map[string]ClaimDef{},
		Metadata: map[string]string{
			"id": "custom-id",
		},
	}

	cred := p.ToCredential(parsed)

	// ID from metadata should override derived ID
	if cred.ID != "custom-id" {
		t.Errorf("ID = %q, want custom-id", cred.ID)
	}
}

func TestParser_ParseContentToCredential(t *testing.T) {
	cfg := &config.Config{
		Language: "en-US",
		BaseURL:  "https://example.com",
	}
	p := NewParser(cfg)

	content := []byte(`---
vct: https://example.com/test
---

# Test Credential

This is a test.

## Claims

- ` + "`name`" + ` (string): The name
`)

	cred, err := p.ParseContentToCredential(content, "/test/cred.md")
	if err != nil {
		t.Fatalf("ParseContentToCredential() error = %v", err)
	}

	if cred.Name != "Test Credential" {
		t.Errorf("Name = %q", cred.Name)
	}
	if cred.Description != "This is a test." {
		t.Errorf("Description = %q", cred.Description)
	}
	if len(cred.Claims) != 1 {
		t.Errorf("len(Claims) = %d, want 1", len(cred.Claims))
	}
}

func TestParser_ParseContentToCredential_InvalidMarkdown(t *testing.T) {
	cfg := &config.Config{}
	p := NewParser(cfg)

	// Empty content should still parse (no title is not an error in ParseContent)
	content := []byte(``)
	cred, err := p.ParseContentToCredential(content, "/test/empty.md")
	if err != nil {
		t.Fatalf("Empty content should not error: %v", err)
	}
	if cred.Name != "" {
		t.Errorf("Name should be empty for empty content")
	}
}

func TestParser_ParseToCredential(t *testing.T) {
	// Create a temporary markdown file
	tmpDir := t.TempDir()
	mdPath := filepath.Join(tmpDir, "test.md")

	content := []byte(`# Test Credential

A test description.

## Claims

- ` + "`email`" + ` (string): Email address [mandatory]
`)

	if err := os.WriteFile(mdPath, content, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	cfg := &config.Config{
		Language:  "en-US",
		InputFile: mdPath,
	}
	p := NewParser(cfg)

	cred, err := p.ParseToCredential(mdPath)
	if err != nil {
		t.Fatalf("ParseToCredential() error = %v", err)
	}

	if cred.Name != "Test Credential" {
		t.Errorf("Name = %q", cred.Name)
	}
	if len(cred.Claims) != 1 {
		t.Errorf("len(Claims) = %d, want 1", len(cred.Claims))
	}
	if cred.Claims[0].Mandatory != true {
		t.Error("email should be mandatory")
	}
}

func TestParser_ParseToCredential_FileNotFound(t *testing.T) {
	cfg := &config.Config{}
	p := NewParser(cfg)

	_, err := p.ParseToCredential("/nonexistent/file.md")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

func TestParser_Generate(t *testing.T) {
	cfg := &config.Config{
		Language: "en-US",
		BaseURL:  "https://example.com",
	}
	p := NewParser(cfg)

	cred := &formats.ParsedCredential{
		ID:          "test",
		Name:        "Test Credential",
		Description: "A test credential",
		VCT:         "https://example.com/test",
		Claims:      []formats.ClaimDefinition{},
		Localizations: map[string]formats.DisplayLocalization{
			"en-US": {Name: "Test Credential"},
		},
		Metadata:        map[string]interface{}{},
		FormatOverrides: map[string]map[string]interface{}{},
		ClaimMappings:   map[string]map[string]string{},
	}

	// Test with vctm format
	results, err := p.Generate(cred, []string{"vctm"})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	// Should have exactly one result for vctm
	if len(results) == 0 {
		t.Error("Generate should return results")
	}
	// The vctm format should produce output
	for name, output := range results {
		if len(output) == 0 {
			t.Errorf("%s format produced empty output", name)
		}
	}
}

func TestParser_Generate_UnknownFormat(t *testing.T) {
	cfg := &config.Config{}
	p := NewParser(cfg)

	cred := &formats.ParsedCredential{
		ID:              "test",
		Name:            "Test",
		Claims:          []formats.ClaimDefinition{},
		Localizations:   map[string]formats.DisplayLocalization{},
		Metadata:        map[string]interface{}{},
		FormatOverrides: map[string]map[string]interface{}{},
		ClaimMappings:   map[string]map[string]string{},
	}

	// Unknown formats should be skipped, not error
	results, err := p.Generate(cred, []string{"unknown-format"})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	if _, ok := results["unknown-format"]; ok {
		t.Error("Unknown format should not have output")
	}
	// Should return empty map for unknown formats
	if len(results) != 0 {
		t.Errorf("Expected empty results map for unknown format, got %d", len(results))
	}
}

func TestParser_GenerateAll(t *testing.T) {
	cfg := &config.Config{
		Language: "en-US",
		BaseURL:  "https://example.com",
	}
	p := NewParser(cfg)

	cred := &formats.ParsedCredential{
		ID:          "test",
		Name:        "Test Credential",
		Description: "A test credential",
		VCT:         "https://example.com/test",
		Claims:      []formats.ClaimDefinition{},
		Localizations: map[string]formats.DisplayLocalization{
			"en-US": {Name: "Test Credential"},
		},
		Metadata:        map[string]interface{}{},
		FormatOverrides: map[string]map[string]interface{}{},
		ClaimMappings:   map[string]map[string]string{},
	}

	results, err := p.GenerateAll(cred)
	if err != nil {
		t.Fatalf("GenerateAll() error = %v", err)
	}

	// Should have at least one format output
	if len(results) == 0 {
		t.Error("GenerateAll should return at least one format")
	}

	// All outputs should be non-empty
	for name, output := range results {
		if len(output) == 0 {
			t.Errorf("%s format produced empty output", name)
		}
	}
}

func TestOutputFileName(t *testing.T) {
	tests := []struct {
		baseName   string
		formatName string
		want       string
	}{
		{"credential", "vctm", "credential.vctm.json"},
		{"my-cred", "unknown", "my-cred.unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.baseName+"_"+tt.formatName, func(t *testing.T) {
			got := OutputFileName(tt.baseName, tt.formatName)
			// For known formats, check exact match; for unknown, check suffix pattern
			if tt.formatName == "vctm" {
				// vctm format uses "vctm.json" extension
				if got != tt.want {
					t.Errorf("OutputFileName(%q, %q) = %q, want %q", tt.baseName, tt.formatName, got, tt.want)
				}
			} else {
				// Unknown formats fallback to simple suffix
				if got != tt.want {
					t.Errorf("OutputFileName(%q, %q) = %q, want %q", tt.baseName, tt.formatName, got, tt.want)
				}
			}
		})
	}
}

func TestToCredential_FormatsField(t *testing.T) {
	cfg := &config.Config{
		Language:  "en-US",
		InputFile: "/test/path/test.md",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Title:       "Test",
		Description: "Test",
		Sections:    map[string]string{},
		Claims:      map[string]ClaimDef{},
		Metadata: map[string]string{
			"vct":     "https://example.com/test",
			"formats": "sd-jwt,w3c",
		},
		DisplayLocalizations: map[string]DisplayLocalization{},
	}

	cred := p.ToCredential(parsed)

	if cred.Formats != "sd-jwt,w3c" {
		t.Errorf("Formats = %q, want %q", cred.Formats, "sd-jwt,w3c")
	}
}

func TestToCredential_FormatsFieldEmpty(t *testing.T) {
	cfg := &config.Config{
		Language:  "en-US",
		InputFile: "/test/path/test.md",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Title:       "Test",
		Description: "Test",
		Sections:    map[string]string{},
		Claims:      map[string]ClaimDef{},
		Metadata: map[string]string{
			"vct": "https://example.com/test",
		},
		DisplayLocalizations: map[string]DisplayLocalization{},
	}

	cred := p.ToCredential(parsed)

	if cred.Formats != "" {
		t.Errorf("Formats = %q, want empty", cred.Formats)
	}
}
