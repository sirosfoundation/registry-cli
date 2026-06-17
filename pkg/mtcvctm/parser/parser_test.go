package parser

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
)

func TestParser_ParseContent(t *testing.T) {
	cfg := &config.Config{
		Language: "en-US",
		BaseURL:  "https://example.com",
	}
	p := NewParser(cfg)

	content := []byte(`# Identity Credential

This is a credential for identity verification.

## Description

A detailed description of the identity credential.

## Claims

- ` + "`given_name`" + ` (string): The given name of the holder [mandatory]
- ` + "`family_name`" + ` (string): The family name of the holder
- ` + "`birth_date`" + ` (date): Date of birth [sd=always]

## Images

![Logo](images/logo.png)
`)

	parsed, err := p.ParseContent(content, "/test/credential.md")
	if err != nil {
		t.Fatalf("ParseContent() error = %v", err)
	}

	if parsed.Title != "Identity Credential" {
		t.Errorf("Title = %q, want %q", parsed.Title, "Identity Credential")
	}

	if parsed.Description != "This is a credential for identity verification." {
		t.Errorf("Description = %q", parsed.Description)
	}

	if len(parsed.Images) != 1 {
		t.Errorf("Expected 1 image, got %d", len(parsed.Images))
	} else {
		if parsed.Images[0].Path != "images/logo.png" {
			t.Errorf("Image path = %q, want images/logo.png", parsed.Images[0].Path)
		}
		if parsed.Images[0].AltText != "Logo" {
			t.Errorf("Image alt = %q, want Logo", parsed.Images[0].AltText)
		}
	}
}

func TestParser_ParseContent_WithFrontMatter(t *testing.T) {
	cfg := &config.Config{
		Language: "en-US",
	}
	p := NewParser(cfg)

	content := []byte(`---
vct: https://example.com/credentials/identity
background_color: "#ffffff"
text_color: "#000000"
extends: https://example.com/base
---

# Identity Credential

This is a test credential.
`)

	parsed, err := p.ParseContent(content, "/test/credential.md")
	if err != nil {
		t.Fatalf("ParseContent() error = %v", err)
	}

	if parsed.Metadata["vct"] != "https://example.com/credentials/identity" {
		t.Errorf("VCT metadata = %q", parsed.Metadata["vct"])
	}

	// YAML properly strips quotes from string values
	if parsed.Metadata["background_color"] != "#ffffff" {
		t.Errorf("background_color = %q, want #ffffff", parsed.Metadata["background_color"])
	}
}

func TestParser_ToVCTM(t *testing.T) {
	cfg := &config.Config{
		Language:  "en-US",
		BaseURL:   "https://registry.example.com",
		InputFile: "/test/identity.md",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Title:       "Identity Credential",
		Description: "A credential for identity verification",
		Sections:    map[string]string{},
		Images:      []ImageRef{},
		Claims: map[string]ClaimDef{
			"given_name": {
				Name:        "given_name",
				Type:        "string",
				Description: "The given name",
				Mandatory:   true,
			},
		},
		Metadata: map[string]string{},
	}

	vctmDoc, err := p.ToVCTM(parsed)
	if err != nil {
		t.Fatalf("ToVCTM() error = %v", err)
	}

	if vctmDoc.VCT != "https://registry.example.com/identity" {
		t.Errorf("VCT = %q", vctmDoc.VCT)
	}

	if vctmDoc.Name != "Identity Credential" {
		t.Errorf("Name = %q", vctmDoc.Name)
	}

	if len(vctmDoc.Display) != 1 {
		t.Errorf("Expected 1 display entry, got %d", len(vctmDoc.Display))
	}

	if len(vctmDoc.Claims) != 1 {
		t.Errorf("Expected 1 claim, got %d", len(vctmDoc.Claims))
	}

	// Find given_name claim in array
	var foundClaim bool
	for _, claim := range vctmDoc.Claims {
		if len(claim.Path) > 0 && claim.Path[0] == "given_name" {
			foundClaim = true
			if !claim.Mandatory {
				t.Error("given_name should be mandatory")
			}
			break
		}
	}
	if !foundClaim {
		t.Error("Missing given_name claim")
	}
}

func TestParser_ToVCTM_WithCredentialLocalizations(t *testing.T) {
	cfg := &config.Config{
		Language:  "en-US",
		BaseURL:   "https://registry.example.com",
		InputFile: "/test/identity.md",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Title:       "Student ID",
		Description: "A digital student ID credential",
		Sections:    map[string]string{},
		Images:      []ImageRef{},
		Claims:      map[string]ClaimDef{},
		Metadata:    map[string]string{},
		DisplayLocalizations: map[string]DisplayLocalization{
			"de-DE": {Name: "Studentenausweis", Description: "Ein digitaler Studentenausweis"},
			"fr-FR": {Name: "Carte étudiant", Description: "Une carte étudiant numérique"},
		},
	}

	vctmDoc, err := p.ToVCTM(parsed)
	if err != nil {
		t.Fatalf("ToVCTM() error = %v", err)
	}

	// Should have 3 display entries: en-US (default), de-DE, fr-FR
	if len(vctmDoc.Display) != 3 {
		t.Errorf("Expected 3 display entries, got %d", len(vctmDoc.Display))
	}

	// Check that we have all expected locales
	locales := make(map[string]bool)
	for _, d := range vctmDoc.Display {
		locales[d.Locale] = true
		switch d.Locale {
		case "en-US":
			if d.Name != "Student ID" {
				t.Errorf("en-US Name = %q, want 'Student ID'", d.Name)
			}
		case "de-DE":
			if d.Name != "Studentenausweis" {
				t.Errorf("de-DE Name = %q, want 'Studentenausweis'", d.Name)
			}
			if d.Description != "Ein digitaler Studentenausweis" {
				t.Errorf("de-DE Description = %q", d.Description)
			}
		case "fr-FR":
			if d.Name != "Carte étudiant" {
				t.Errorf("fr-FR Name = %q, want 'Carte étudiant'", d.Name)
			}
		}
	}

	if !locales["en-US"] {
		t.Error("Missing en-US locale")
	}
	if !locales["de-DE"] {
		t.Error("Missing de-DE locale")
	}
	if !locales["fr-FR"] {
		t.Error("Missing fr-FR locale")
	}
}

func TestParseClaimFromListItem(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantName    string
		wantType    string
		wantMand    bool
		wantSD      string
		wantSvgId   string
		wantDesc    string
		wantDisplay string
		wantMatch   bool
	}{
		{
			name:      "simple claim",
			input:     "`given_name` (string): The given name",
			wantName:  "given_name",
			wantType:  "string",
			wantDesc:  "The given name",
			wantMatch: true,
		},
		{
			name:      "mandatory claim",
			input:     "`email` (string): Email address [mandatory]",
			wantName:  "email",
			wantType:  "string",
			wantMand:  true,
			wantDesc:  "Email address",
			wantMatch: true,
		},
		{
			name:      "claim with sd",
			input:     "`birth_date` (date): Date of birth [sd=always]",
			wantName:  "birth_date",
			wantType:  "date",
			wantSD:    "always",
			wantDesc:  "Date of birth",
			wantMatch: true,
		},
		{
			name:      "no type specified",
			input:     "`name`: The name",
			wantName:  "name",
			wantType:  "string",
			wantDesc:  "The name",
			wantMatch: true,
		},
		{
			name:      "not a claim",
			input:     "This is just regular text",
			wantMatch: false,
		},
		{
			name:        "claim with display name",
			input:       "`given_name` \"Given Name\" (string): The given name of the holder",
			wantName:    "given_name",
			wantType:    "string",
			wantDesc:    "The given name of the holder",
			wantDisplay: "Given Name",
			wantMatch:   true,
		},
		{
			name:        "claim with display name and mandatory",
			input:       "`family_name` \"Family Name\" (string): The family name [mandatory]",
			wantName:    "family_name",
			wantType:    "string",
			wantDesc:    "The family name",
			wantDisplay: "Family Name",
			wantMand:    true,
			wantMatch:   true,
		},
		{
			name:        "claim with combined flags",
			input:       "`student_id` \"Student ID\" (string): Unique student ID [mandatory, svg_id=student_id]",
			wantName:    "student_id",
			wantType:    "string",
			wantDesc:    "Unique student ID",
			wantDisplay: "Student ID",
			wantMand:    true,
			wantSvgId:   "student_id",
			wantMatch:   true,
		},
		{
			name:      "claim with all flags",
			input:     "`secret` (string): A secret value [mandatory, sd=always, svg_id=secret_field]",
			wantName:  "secret",
			wantType:  "string",
			wantDesc:  "A secret value",
			wantMand:  true,
			wantSD:    "always",
			wantSvgId: "secret_field",
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claim := parseClaimFromListItem(tt.input)

			if !tt.wantMatch {
				if claim != nil {
					t.Error("Expected no match")
				}
				return
			}

			if claim == nil {
				t.Fatal("Expected match but got nil")
			}

			if claim.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", claim.Name, tt.wantName)
			}
			if claim.Type != tt.wantType {
				t.Errorf("Type = %q, want %q", claim.Type, tt.wantType)
			}
			if claim.Mandatory != tt.wantMand {
				t.Errorf("Mandatory = %v, want %v", claim.Mandatory, tt.wantMand)
			}
			if claim.SD != tt.wantSD {
				t.Errorf("SD = %q, want %q", claim.SD, tt.wantSD)
			}
			if claim.SvgId != tt.wantSvgId {
				t.Errorf("SvgId = %q, want %q", claim.SvgId, tt.wantSvgId)
			}
			if claim.Description != tt.wantDesc {
				t.Errorf("Description = %q, want %q", claim.Description, tt.wantDesc)
			}
			if claim.DisplayName != tt.wantDisplay {
				t.Errorf("DisplayName = %q, want %q", claim.DisplayName, tt.wantDisplay)
			}
		})
	}
}

func TestExtractFrontMatter(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		want        map[string]string
		wantDisplay map[string]DisplayLocalization
	}{
		{
			name: "with front matter",
			content: `---
vct: https://example.com/test
name: Test
---

# Content`,
			want: map[string]string{
				"vct":  "https://example.com/test",
				"name": "Test",
			},
			wantDisplay: map[string]DisplayLocalization{},
		},
		{
			name:        "no front matter",
			content:     "# Just a heading",
			want:        map[string]string{},
			wantDisplay: map[string]DisplayLocalization{},
		},
		{
			name: "unclosed front matter",
			content: `---
vct: test
# Content`,
			want:        map[string]string{},
			wantDisplay: map[string]DisplayLocalization{},
		},
		{
			name: "with display localizations",
			content: `---
vct: https://example.com/test
display:
  de-DE:
    name: "Studentenausweis"
    description: "Ein digitaler Studentenausweis"
  fr-FR:
    name: "Carte étudiant"
    description: "Une carte étudiant numérique"
---

# Content`,
			want: map[string]string{
				"vct": "https://example.com/test",
			},
			wantDisplay: map[string]DisplayLocalization{
				"de-DE": {Name: "Studentenausweis", Description: "Ein digitaler Studentenausweis"},
				"fr-FR": {Name: "Carte étudiant", Description: "Une carte étudiant numérique"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotDisplay := extractFrontMatter([]byte(tt.content))
			if len(got) != len(tt.want) {
				t.Errorf("extractFrontMatter() returned %d items, want %d", len(got), len(tt.want))
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("extractFrontMatter()[%q] = %q, want %q", k, got[k], v)
				}
			}
			if len(gotDisplay) != len(tt.wantDisplay) {
				t.Errorf("extractFrontMatter() returned %d display items, want %d", len(gotDisplay), len(tt.wantDisplay))
			}
			for k, v := range tt.wantDisplay {
				if gotDisplay[k].Name != v.Name {
					t.Errorf("extractFrontMatter() display[%q].Name = %q, want %q", k, gotDisplay[k].Name, v.Name)
				}
				if gotDisplay[k].Description != v.Description {
					t.Errorf("extractFrontMatter() display[%q].Description = %q, want %q", k, gotDisplay[k].Description, v.Description)
				}
			}
		})
	}
}

func TestParser_Parse_File(t *testing.T) {
	// Create a temporary test file
	tmpDir := t.TempDir()
	mdPath := filepath.Join(tmpDir, "test.md")

	content := `# Test Credential

A test credential for unit testing.

## Claims

- ` + "`test_claim`" + ` (string): A test claim
`
	if err := os.WriteFile(mdPath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	cfg := &config.Config{
		InputFile: mdPath,
		Language:  "en-US",
	}
	p := NewParser(cfg)

	parsed, err := p.Parse(mdPath)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if parsed.Title != "Test Credential" {
		t.Errorf("Title = %q, want %q", parsed.Title, "Test Credential")
	}
}

func TestCalculateIntegrity(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")

	if err := os.WriteFile(testFile, []byte("test content"), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	integrity, err := CalculateIntegrity(testFile)
	if err != nil {
		t.Fatalf("CalculateIntegrity() error = %v", err)
	}

	if integrity == "" {
		t.Error("Expected non-empty integrity hash")
	}

	if len(integrity) < 10 {
		t.Error("Integrity hash seems too short")
	}

	// Should start with sha256-
	if integrity[:7] != "sha256-" {
		t.Errorf("Integrity should start with sha256-, got %q", integrity[:7])
	}
}

func TestCalculateIntegrity_NotFound(t *testing.T) {
	_, err := CalculateIntegrity("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

func TestParser_buildImageURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		path    string
		want    string
	}{
		{
			name:    "simple path",
			baseURL: "https://example.com",
			path:    "images/logo.png",
			want:    "https://example.com/images/logo.png",
		},
		{
			name:    "with trailing slash",
			baseURL: "https://example.com/",
			path:    "images/logo.png",
			want:    "https://example.com/images/logo.png",
		},
		{
			name:    "with leading dot",
			baseURL: "https://example.com",
			path:    "./images/logo.png",
			want:    "https://example.com/images/logo.png",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				BaseURL: tt.baseURL,
			}
			p := NewParser(cfg)
			got := p.buildImageURL(tt.path)
			if got != tt.want {
				t.Errorf("buildImageURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParser_imageToDataURL(t *testing.T) {
	// Create a temp file with known content
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		filename string
		content  []byte
		wantMime string
	}{
		{
			name:     "PNG image",
			filename: "test.png",
			content:  []byte{0x89, 0x50, 0x4E, 0x47}, // PNG magic bytes
			wantMime: "image/png",
		},
		{
			name:     "SVG image",
			filename: "test.svg",
			content:  []byte("<svg></svg>"),
			wantMime: "image/svg+xml",
		},
		{
			name:     "JPEG image",
			filename: "test.jpg",
			content:  []byte{0xFF, 0xD8, 0xFF}, // JPEG magic bytes
			wantMime: "image/jpeg",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(tmpDir, tt.filename)
			if err := os.WriteFile(filePath, tt.content, 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			cfg := &config.Config{
				InlineImages: true,
			}
			p := NewParser(cfg)
			dataURL, err := p.imageToDataURL(filePath)
			if err != nil {
				t.Fatalf("imageToDataURL() error = %v", err)
			}

			// Check that it starts with the correct data URL prefix
			expectedPrefix := "data:" + tt.wantMime + ";base64,"
			if !hasPrefix(dataURL, expectedPrefix) {
				t.Errorf("imageToDataURL() = %q, want prefix %q", dataURL[:min(len(dataURL), 50)], expectedPrefix)
			}
		})
	}
}

func hasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func TestParser_imageToLogo_Inline(t *testing.T) {
	// Create a temp file with known content
	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "logo.png")
	if err := os.WriteFile(imgPath, []byte{0x89, 0x50, 0x4E, 0x47}, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cfg := &config.Config{
		InlineImages: true,
		BaseURL:      "https://example.com",
	}
	p := NewParser(cfg)

	img := ImageRef{
		Path:         "logo.png",
		AbsolutePath: imgPath,
		AltText:      "Test Logo",
	}

	logo := p.imageToLogo(img)

	// With InlineImages=true, URI should be a data URL
	if !hasPrefix(logo.URI, "data:image/png;base64,") {
		t.Errorf("imageToLogo() URI = %q, want data URL", logo.URI[:min(len(logo.URI), 50)])
	}

	// URIIntegrity should be empty for inline images
	if logo.URIIntegrity != "" {
		t.Errorf("imageToLogo() URIIntegrity = %q, want empty for inline images", logo.URIIntegrity)
	}

	// AltText should be preserved
	if logo.AltText != "Test Logo" {
		t.Errorf("imageToLogo() AltText = %q, want %q", logo.AltText, "Test Logo")
	}
}

func TestGetMimeType(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/path/to/image.png", "image/png"},
		{"/path/to/image.PNG", "image/png"},
		{"/path/to/image.svg", "image/svg+xml"},
		{"/path/to/image.SVG", "image/svg+xml"},
		{"/path/to/image.jpg", "image/jpeg"},
		{"/path/to/image.jpeg", "image/jpeg"},
		{"/path/to/image.gif", "image/gif"},
		{"/path/to/image.webp", "image/webp"},
		{"/path/to/image.ico", "image/x-icon"},
		{"/path/to/unknown.xyz", "application/octet-stream"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := getMimeType(tt.path)
			if got != tt.want {
				t.Errorf("getMimeType(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestParseLocalizationFromListItem(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantLocale string
		wantLabel  string
		wantDesc   string
		wantMatch  bool
	}{
		{
			name:       "full localization",
			input:      `en-US: "Given Name" - The given name of the holder`,
			wantLocale: "en-US",
			wantLabel:  "Given Name",
			wantDesc:   "The given name of the holder",
			wantMatch:  true,
		},
		{
			name:       "german localization",
			input:      `de-DE: "Vorname" - Der Vorname des Inhabers`,
			wantLocale: "de-DE",
			wantLabel:  "Vorname",
			wantDesc:   "Der Vorname des Inhabers",
			wantMatch:  true,
		},
		{
			name:       "label only",
			input:      `sv: "Förnamn"`,
			wantLocale: "sv",
			wantLabel:  "Förnamn",
			wantDesc:   "",
			wantMatch:  true,
		},
		{
			name:      "not a localization",
			input:     "This is just regular text",
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			locale, loc, ok := parseLocalizationFromListItem(tt.input)

			if !tt.wantMatch {
				if ok {
					t.Error("Expected no match")
				}
				return
			}

			if !ok {
				t.Fatal("Expected match but got no match")
			}

			if locale != tt.wantLocale {
				t.Errorf("Locale = %q, want %q", locale, tt.wantLocale)
			}
			if loc.Label != tt.wantLabel {
				t.Errorf("Label = %q, want %q", loc.Label, tt.wantLabel)
			}
			if loc.Description != tt.wantDesc {
				t.Errorf("Description = %q, want %q", loc.Description, tt.wantDesc)
			}
		})
	}
}

func TestParser_ClaimsWithLocalization(t *testing.T) {
	cfg := &config.Config{
		Language: "en-US",
		BaseURL:  "https://example.com",
	}
	p := NewParser(cfg)

	content := []byte(`# Test Credential

A test credential.

## Claims

- ` + "`given_name` \"Given Name\" (string): The given name [mandatory]" + `
  - de-DE: "Vorname" - Der Vorname
  - sv: "Förnamn" - Förnamnet
- ` + "`family_name` (string): The family name" + `
`)

	parsed, err := p.ParseContent(content, "/test/credential.md")
	if err != nil {
		t.Fatalf("ParseContent() error = %v", err)
	}

	// Check given_name claim
	claim, ok := parsed.Claims["given_name"]
	if !ok {
		t.Fatal("Missing given_name claim")
	}

	if claim.DisplayName != "Given Name" {
		t.Errorf("DisplayName = %q, want %q", claim.DisplayName, "Given Name")
	}

	if !claim.Mandatory {
		t.Error("given_name should be mandatory")
	}

	if len(claim.Localizations) != 2 {
		t.Errorf("Expected 2 localizations, got %d", len(claim.Localizations))
	}

	if deLoc, ok := claim.Localizations["de-DE"]; ok {
		if deLoc.Label != "Vorname" {
			t.Errorf("German label = %q, want %q", deLoc.Label, "Vorname")
		}
	} else {
		t.Error("Missing de-DE localization")
	}

	// Test VCTM output
	vctmDoc, err := p.ToVCTM(parsed)
	if err != nil {
		t.Fatalf("ToVCTM() error = %v", err)
	}

	// Find given_name claim
	var foundClaim bool
	for _, c := range vctmDoc.Claims {
		if len(c.Path) > 0 && c.Path[0] == "given_name" {
			foundClaim = true
			// Should have 3 display entries (en-US, de-DE, sv)
			if len(c.Display) != 3 {
				t.Errorf("Expected 3 display entries, got %d", len(c.Display))
			}
			break
		}
	}
	if !foundClaim {
		t.Error("Missing given_name claim in VCTM output")
	}
}

func TestParser_imageToLogo_URLBased(t *testing.T) {
	// Test imageToLogo when InlineImages is false (URL-based)
	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "logo.png")
	if err := os.WriteFile(imgPath, []byte{0x89, 0x50, 0x4E, 0x47}, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	cfg := &config.Config{
		InlineImages: false,
		BaseURL:      "https://example.com",
	}
	p := NewParser(cfg)

	img := ImageRef{
		Path:         "images/logo.png",
		AbsolutePath: imgPath,
		AltText:      "Logo",
	}

	logo := p.imageToLogo(img)

	// URI should be a full URL, not a data URL
	if hasPrefix(logo.URI, "data:") {
		t.Errorf("imageToLogo() URI should not be a data URL, got %q", logo.URI[:50])
	}
	if !hasPrefix(logo.URI, "https://example.com") {
		t.Errorf("imageToLogo() URI = %q, want URL starting with https://example.com", logo.URI)
	}

	// Should have integrity hash
	if logo.URIIntegrity == "" {
		t.Error("imageToLogo() should have URIIntegrity for URL-based images")
	}
	if !hasPrefix(logo.URIIntegrity, "sha256-") {
		t.Errorf("URIIntegrity = %q, want sha256- prefix", logo.URIIntegrity)
	}

	if logo.AltText != "Logo" {
		t.Errorf("AltText = %q, want 'Logo'", logo.AltText)
	}
}

func TestParser_imageToLogo_NoBaseURL(t *testing.T) {
	// Test imageToLogo when no BaseURL is configured
	cfg := &config.Config{
		InlineImages: false,
		BaseURL:      "",
	}
	p := NewParser(cfg)

	img := ImageRef{
		Path:    "images/logo.png",
		AltText: "Logo",
	}

	logo := p.imageToLogo(img)

	// Without base URL, should use relative path
	if logo.URI != "images/logo.png" {
		t.Errorf("URI = %q, want 'images/logo.png'", logo.URI)
	}

	// No integrity without base URL
	if logo.URIIntegrity != "" {
		t.Errorf("URIIntegrity should be empty without BaseURL, got %q", logo.URIIntegrity)
	}
}

func TestParser_buildRendering_WithSVG(t *testing.T) {
	tmpDir := t.TempDir()
	svgPath := filepath.Join(tmpDir, "template.svg")
	svgContent := []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)
	if err := os.WriteFile(svgPath, svgContent, 0644); err != nil {
		t.Fatalf("Failed to create SVG file: %v", err)
	}

	cfg := &config.Config{
		BaseURL: "https://example.com/registry",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Images: []ImageRef{
			{Path: "template.svg", AbsolutePath: svgPath, AltText: "Template"},
		},
		Metadata: map[string]string{
			"background_color": "\"#ffffff\"",
			"text_color":       "\"#000000\"",
		},
	}

	rendering := p.buildRendering(parsed)

	if rendering == nil {
		t.Fatal("buildRendering returned nil")
	}

	// Check simple rendering
	if rendering.Simple == nil {
		t.Fatal("Simple rendering is nil")
	}
	if rendering.Simple.BackgroundColor != "#ffffff" {
		t.Errorf("BackgroundColor = %q, want #ffffff", rendering.Simple.BackgroundColor)
	}
	if rendering.Simple.TextColor != "#000000" {
		t.Errorf("TextColor = %q, want #000000", rendering.Simple.TextColor)
	}

	// Check SVG templates
	if len(rendering.SVGTemplates) != 1 {
		t.Errorf("len(SVGTemplates) = %d, want 1", len(rendering.SVGTemplates))
	} else {
		if !hasPrefix(rendering.SVGTemplates[0].URI, "https://example.com") {
			t.Errorf("SVGTemplates[0].URI = %q, want URL", rendering.SVGTemplates[0].URI)
		}
	}
}

func TestParser_buildRendering_NoBaseURL(t *testing.T) {
	// When no BaseURL and there are images, should return nil
	cfg := &config.Config{
		BaseURL: "",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Images: []ImageRef{
			{Path: "logo.png", AltText: "Logo"},
		},
		Metadata: map[string]string{},
	}

	rendering := p.buildRendering(parsed)

	if rendering != nil {
		t.Error("buildRendering should return nil when no BaseURL and has images")
	}
}

func TestParser_buildRendering_NoContent(t *testing.T) {
	cfg := &config.Config{
		BaseURL: "https://example.com",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Images:   []ImageRef{},
		Metadata: map[string]string{},
	}

	rendering := p.buildRendering(parsed)

	if rendering != nil {
		t.Error("buildRendering should return nil when no rendering content")
	}
}

func TestParser_buildRendering_BackgroundImage(t *testing.T) {
	cfg := &config.Config{
		BaseURL: "https://example.com",
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Images: []ImageRef{},
		Metadata: map[string]string{
			"background_image": "\"https://example.com/bg.png\"",
		},
	}

	rendering := p.buildRendering(parsed)

	if rendering == nil {
		t.Fatal("buildRendering returned nil")
	}
	if rendering.Simple == nil {
		t.Fatal("Simple rendering is nil")
	}
	if rendering.Simple.BackgroundImage == nil {
		t.Fatal("BackgroundImage is nil")
	}
	if rendering.Simple.BackgroundImage.URI != "https://example.com/bg.png" {
		t.Errorf("BackgroundImage.URI = %q", rendering.Simple.BackgroundImage.URI)
	}
}

func TestParser_buildRendering_InlineSVG(t *testing.T) {
	tmpDir := t.TempDir()
	svgPath := filepath.Join(tmpDir, "template.svg")
	svgContent := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="50"/></svg>`)
	if err := os.WriteFile(svgPath, svgContent, 0644); err != nil {
		t.Fatalf("Failed to create SVG file: %v", err)
	}

	cfg := &config.Config{
		BaseURL:      "https://example.com",
		InlineImages: true,
	}
	p := NewParser(cfg)

	parsed := &ParsedMarkdown{
		Images: []ImageRef{
			{Path: "template.svg", AbsolutePath: svgPath, AltText: "Template"},
		},
		Metadata: map[string]string{},
	}

	rendering := p.buildRendering(parsed)

	if rendering == nil {
		t.Fatal("buildRendering returned nil")
	}

	if len(rendering.SVGTemplates) != 1 {
		t.Fatalf("len(SVGTemplates) = %d, want 1", len(rendering.SVGTemplates))
	}

	// Should be a data URL when InlineImages is true
	if !hasPrefix(rendering.SVGTemplates[0].URI, "data:image/svg+xml;base64,") {
		t.Errorf("SVGTemplates[0].URI = %q, want data URL", rendering.SVGTemplates[0].URI)
	}

	// No integrity for inline images
	if rendering.SVGTemplates[0].URIIntegrity != "" {
		t.Errorf("URIIntegrity should be empty for inline images, got %q", rendering.SVGTemplates[0].URIIntegrity)
	}
}

func TestParser_ParseContent_NestedObjectClaims(t *testing.T) {
	cfg := &config.Config{
		Language: "en-US",
	}
	p := NewParser(cfg)

	content := []byte("---\nvct: https://example.com/test\n---\n# Test\n\nTest credential.\n\n## Claims\n\n" +
		"- `name` (string): Full name [mandatory]\n" +
		"- `address` \"Address\" (object): Residential address\n" +
		"  - `street` \"Street\" (string): Street name\n" +
		"  - `city` \"City\" (string): City name [mandatory]\n" +
		"  - `zip` \"Zip\" (string): Zip code\n" +
		"- `age` (integer): Age\n")

	parsed, err := p.ParseContent(content, "/test/test.md")
	if err != nil {
		t.Fatalf("ParseContent() error = %v", err)
	}

	// Should have 3 top-level claims
	if len(parsed.Claims) != 3 {
		t.Fatalf("expected 3 top-level claims, got %d", len(parsed.Claims))
	}

	addr, ok := parsed.Claims["address"]
	if !ok {
		t.Fatal("missing 'address' claim")
	}
	if addr.Type != "object" {
		t.Errorf("address type = %q, want object", addr.Type)
	}
	if len(addr.Children) != 3 {
		t.Fatalf("address children = %d, want 3", len(addr.Children))
	}
	if addr.Children[0].Name != "street" {
		t.Errorf("first child = %q, want street", addr.Children[0].Name)
	}
	if addr.Children[1].Name != "city" {
		t.Errorf("second child = %q, want city", addr.Children[1].Name)
	}
	if !addr.Children[1].Mandatory {
		t.Error("city should be mandatory")
	}
}

func TestParser_ParseContent_NestedArrayClaims(t *testing.T) {
	cfg := &config.Config{
		Language: "en-US",
	}
	p := NewParser(cfg)

	content := []byte("---\nvct: https://example.com/test\n---\n# Test\n\nTest credential.\n\n## Claims\n\n" +
		"- `contacts` \"Contacts\" (array): List of contacts\n" +
		"  - `email` \"Email\" (string): Email address\n" +
		"  - `phone` \"Phone\" (string): Phone number\n")

	parsed, err := p.ParseContent(content, "/test/test.md")
	if err != nil {
		t.Fatalf("ParseContent() error = %v", err)
	}

	contacts, ok := parsed.Claims["contacts"]
	if !ok {
		t.Fatal("missing 'contacts' claim")
	}
	if contacts.Type != "array" {
		t.Errorf("contacts type = %q, want array", contacts.Type)
	}
	if len(contacts.Children) != 2 {
		t.Fatalf("contacts children = %d, want 2", len(contacts.Children))
	}
}
