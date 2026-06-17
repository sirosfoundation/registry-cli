package vctmfmt

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
)

func TestGenerator_Name(t *testing.T) {
	g := &Generator{}
	if g.Name() != "vctm" {
		t.Errorf("Name() = %q, want 'vctm'", g.Name())
	}
}

func TestGenerator_Description(t *testing.T) {
	g := &Generator{}
	desc := g.Description()
	if desc == "" {
		t.Error("Description should not be empty")
	}
	if !contains(desc, "SD-JWT") {
		t.Errorf("Description = %q, should mention SD-JWT", desc)
	}
}

func TestGenerator_FileExtension(t *testing.T) {
	g := &Generator{}
	if g.FileExtension() != "vctm.json" {
		t.Errorf("FileExtension() = %q, want 'vctm.json'", g.FileExtension())
	}
}

func TestGenerator_DeriveIdentifier(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{}

	tests := []struct {
		name string
		cred *formats.ParsedCredential
		want string
	}{
		{
			name: "uses VCT when present",
			cred: &formats.ParsedCredential{
				ID:  "fallback-id",
				VCT: "https://example.com/vct",
			},
			want: "https://example.com/vct",
		},
		{
			name: "falls back to ID when VCT empty",
			cred: &formats.ParsedCredential{
				ID:  "fallback-id",
				VCT: "",
			},
			want: "fallback-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := g.DeriveIdentifier(tt.cred, cfg)
			if got != tt.want {
				t.Errorf("DeriveIdentifier() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGenerator_Generate_Minimal(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{
		Language: "en-US",
	}

	cred := &formats.ParsedCredential{
		ID:   "test-credential",
		Name: "Test Credential",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatalf("Output is not valid JSON: %v", err)
	}

	// Check required fields
	if parsed["vct"] != "test-credential" {
		t.Errorf("vct = %v, want 'test-credential'", parsed["vct"])
	}
	if parsed["name"] != "Test Credential" {
		t.Errorf("name = %v, want 'Test Credential'", parsed["name"])
	}

	// Check display array
	display, ok := parsed["display"].([]interface{})
	if !ok || len(display) == 0 {
		t.Fatal("display should be a non-empty array")
	}
	d0 := display[0].(map[string]interface{})
	if d0["locale"] != "en-US" {
		t.Errorf("display[0].locale = %v, want 'en-US'", d0["locale"])
	}
	if d0["name"] != "Test Credential" {
		t.Errorf("display[0].name = %v, want 'Test Credential'", d0["name"])
	}
}

func TestGenerator_Generate_NameRequired(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		ID:   "test",
		Name: "", // Empty name should fail
	}

	_, err := g.Generate(cred, cfg)
	if err == nil {
		t.Error("Expected error for empty name")
	}
	if !contains(err.Error(), "name is required") {
		t.Errorf("Error = %q, should mention 'name is required'", err.Error())
	}
}

func TestGenerator_Generate_WithDescription(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		ID:          "test",
		Name:        "Test",
		Description: "A test credential description",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	if parsed["description"] != "A test credential description" {
		t.Errorf("description = %v", parsed["description"])
	}
}

func TestGenerator_Generate_WithVCT(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		ID:   "fallback",
		Name: "Test",
		VCT:  "https://example.com/credentials/identity",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	if parsed["vct"] != "https://example.com/credentials/identity" {
		t.Errorf("vct = %v", parsed["vct"])
	}
}

func TestGenerator_Generate_WithMetadata(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		ID:   "test",
		Name: "Test",
		Metadata: map[string]interface{}{
			"extends":              "https://example.com/base",
			"extends#integrity":    "sha256-abc123",
			"schema_uri":           "https://example.com/schema",
			"schema_uri#integrity": "sha256-def456",
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	if parsed["extends"] != "https://example.com/base" {
		t.Errorf("extends = %v", parsed["extends"])
	}
	if parsed["extends#integrity"] != "sha256-abc123" {
		t.Errorf("extends#integrity = %v", parsed["extends#integrity"])
	}
	if parsed["schema_uri"] != "https://example.com/schema" {
		t.Errorf("schema_uri = %v", parsed["schema_uri"])
	}
}

func TestGenerator_Generate_WithClaims(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		ID:   "test",
		Name: "Test",
		Claims: []formats.ClaimDefinition{
			{
				Name:        "given_name",
				Path:        []string{"given_name"},
				DisplayName: "Given Name",
				Description: "The holder's given name",
				Mandatory:   true,
				SD:          "always",
				SvgId:       "givenNameField",
			},
			{
				Name: "email",
				Path: []string{"email"},
			},
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	claims, ok := parsed["claims"].([]interface{})
	if !ok || len(claims) != 2 {
		t.Fatalf("claims should have 2 entries, got %v", parsed["claims"])
	}

	claim0 := claims[0].(map[string]interface{})
	path := claim0["path"].([]interface{})
	if len(path) != 1 || path[0] != "given_name" {
		t.Errorf("claims[0].path = %v", path)
	}
	if claim0["mandatory"] != true {
		t.Error("claims[0].mandatory should be true")
	}
	if claim0["sd"] != "always" {
		t.Errorf("claims[0].sd = %v", claim0["sd"])
	}
	if claim0["svg_id"] != "givenNameField" {
		t.Errorf("claims[0].svg_id = %v", claim0["svg_id"])
	}
	if claim0["description"] != "The holder's given name" {
		t.Errorf("claims[0].description = %v", claim0["description"])
	}

	// Check display
	display, ok := claim0["display"].([]interface{})
	if !ok || len(display) == 0 {
		t.Fatal("claims[0].display should be an array")
	}
	d0 := display[0].(map[string]interface{})
	if d0["label"] != "Given Name" {
		t.Errorf("claims[0].display[0].label = %v", d0["label"])
	}
}

func TestGenerator_Generate_WithColors(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		ID:              "test",
		Name:            "Test",
		BackgroundColor: "#ffffff",
		TextColor:       "#000000",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	display := parsed["display"].([]interface{})[0].(map[string]interface{})
	rendering := display["rendering"].(map[string]interface{})
	simple := rendering["simple"].(map[string]interface{})

	if simple["background_color"] != "#ffffff" {
		t.Errorf("background_color = %v", simple["background_color"])
	}
	if simple["text_color"] != "#000000" {
		t.Errorf("text_color = %v", simple["text_color"])
	}
}

func TestGenerator_Generate_WithLogo_Inline(t *testing.T) {
	tmpDir := t.TempDir()
	logoPath := filepath.Join(tmpDir, "logo.png")
	// Write a minimal PNG-like file
	if err := os.WriteFile(logoPath, []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 0644); err != nil {
		t.Fatalf("Failed to create logo file: %v", err)
	}

	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		ID:           "test",
		Name:         "Test",
		LogoPath:     "logo.png",
		LogoAltText:  "Test Logo",
		SourceDir:    tmpDir,
		InlineImages: true,
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	display := parsed["display"].([]interface{})[0].(map[string]interface{})
	rendering := display["rendering"].(map[string]interface{})
	simple := rendering["simple"].(map[string]interface{})
	logo := simple["logo"].(map[string]interface{})

	uri, ok := logo["uri"].(string)
	if !ok || !hasPrefix(uri, "data:") {
		t.Errorf("logo.uri = %v, should be data URL", uri)
	}
	if logo["alt_text"] != "Test Logo" {
		t.Errorf("logo.alt_text = %v", logo["alt_text"])
	}
}

func TestGenerator_Generate_WithLogo_URL(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{
		Language: "en-US",
		BaseURL:  "https://registry.example.com",
	}

	cred := &formats.ParsedCredential{
		ID:           "test",
		Name:         "Test",
		LogoPath:     "images/logo.png",
		SourceDir:    "/source",
		InlineImages: false,
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	display := parsed["display"].([]interface{})[0].(map[string]interface{})
	rendering := display["rendering"].(map[string]interface{})
	simple := rendering["simple"].(map[string]interface{})
	logo := simple["logo"].(map[string]interface{})

	if logo["uri"] != "https://registry.example.com/images/logo.png" {
		t.Errorf("logo.uri = %v", logo["uri"])
	}
}

func TestGenerator_Generate_WithSVGTemplate_Inline(t *testing.T) {
	tmpDir := t.TempDir()
	svgPath := filepath.Join(tmpDir, "template.svg")
	svgContent := `<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="50"/></svg>`
	if err := os.WriteFile(svgPath, []byte(svgContent), 0644); err != nil {
		t.Fatalf("Failed to create SVG file: %v", err)
	}

	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		ID:              "test",
		Name:            "Test",
		SVGTemplatePath: "template.svg",
		SourceDir:       tmpDir,
		InlineImages:    true,
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	display := parsed["display"].([]interface{})[0].(map[string]interface{})
	rendering := display["rendering"].(map[string]interface{})
	templates := rendering["svg_templates"].([]interface{})

	if len(templates) != 1 {
		t.Fatalf("len(svg_templates) = %d, want 1", len(templates))
	}

	tmpl := templates[0].(map[string]interface{})
	uri := tmpl["uri"].(string)
	if !hasPrefix(uri, "data:image/svg+xml;base64,") {
		t.Errorf("uri = %q, should be data URL", uri)
	}
}

func TestGenerator_Generate_WithSVGTemplate_URI(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		ID:                   "test",
		Name:                 "Test",
		SVGTemplateURI:       "https://example.com/template.svg",
		SVGTemplateIntegrity: "sha256-abc123",
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	display := parsed["display"].([]interface{})[0].(map[string]interface{})
	rendering := display["rendering"].(map[string]interface{})
	templates := rendering["svg_templates"].([]interface{})

	if len(templates) != 1 {
		t.Fatalf("len(svg_templates) = %d, want 1", len(templates))
	}

	tmpl := templates[0].(map[string]interface{})
	if tmpl["uri"] != "https://example.com/template.svg" {
		t.Errorf("uri = %v", tmpl["uri"])
	}
	if tmpl["uri#integrity"] != "sha256-abc123" {
		t.Errorf("uri#integrity = %v", tmpl["uri#integrity"])
	}
}

func TestGenerator_Generate_SVGFromImages(t *testing.T) {
	tmpDir := t.TempDir()
	svgPath := filepath.Join(tmpDir, "card.svg")
	if err := os.WriteFile(svgPath, []byte(`<svg></svg>`), 0644); err != nil {
		t.Fatalf("Failed to create SVG: %v", err)
	}
	pngPath := filepath.Join(tmpDir, "logo.png")
	if err := os.WriteFile(pngPath, []byte{0x89, 0x50}, 0644); err != nil {
		t.Fatalf("Failed to create PNG: %v", err)
	}

	g := &Generator{}
	cfg := &config.Config{Language: "en-US", BaseURL: "https://example.com"}

	cred := &formats.ParsedCredential{
		ID:        "test",
		Name:      "Test",
		SourceDir: tmpDir,
		Images: []formats.ImageRef{
			{Path: "card.svg", AbsolutePath: svgPath, AltText: "Card"},
			{Path: "logo.png", AbsolutePath: pngPath, AltText: "Logo"},
		},
	}

	output, err := g.Generate(cred, cfg)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(output, &parsed)

	display := parsed["display"].([]interface{})[0].(map[string]interface{})
	rendering := display["rendering"].(map[string]interface{})

	// SVG should become svg_templates
	templates := rendering["svg_templates"].([]interface{})
	if len(templates) != 1 {
		t.Errorf("len(svg_templates) = %d, want 1", len(templates))
	}

	// PNG should become logo
	simple := rendering["simple"].(map[string]interface{})
	logo := simple["logo"].(map[string]interface{})
	if !contains(logo["uri"].(string), "logo.png") {
		t.Errorf("logo.uri = %v, should contain logo.png", logo["uri"])
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

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestGenerator_Generate_NestedObjectClaims(t *testing.T) {
	g := &Generator{}
	cfg := &config.Config{Language: "en-US"}

	cred := &formats.ParsedCredential{
		Name:        "Test",
		VCT:         "https://example.com/test",
		Description: "Test",
		Claims: []formats.ClaimDefinition{
			{
				Name:        "address",
				DisplayName: "Address",
				Type:        "object",
				Path:        []string{"address"},
				Children: []formats.ClaimDefinition{
					{Name: "street", DisplayName: "Street", Type: "string", Path: []string{"address", "street"}},
					{Name: "city", DisplayName: "City", Type: "string", Path: []string{"address", "city"}, Mandatory: true},
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

	claims, ok := raw["claims"].([]interface{})
	if !ok {
		t.Fatal("missing claims array")
	}

	// Should have parent + 2 children = 3 claim entries
	if len(claims) != 3 {
		t.Fatalf("expected 3 claims, got %d", len(claims))
	}

	// First claim should be the parent "address"
	first := claims[0].(map[string]interface{})
	path := first["path"].([]interface{})
	if len(path) != 1 || path[0] != "address" {
		t.Errorf("first claim path = %v, want [address]", path)
	}

	// Second should be "address.street"
	second := claims[1].(map[string]interface{})
	path2 := second["path"].([]interface{})
	if len(path2) != 2 || path2[0] != "address" || path2[1] != "street" {
		t.Errorf("second claim path = %v, want [address, street]", path2)
	}
}
