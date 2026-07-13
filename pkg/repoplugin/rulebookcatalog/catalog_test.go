package rulebookcatalog

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/repoplugin"
)

func TestNormalizeSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ds002-pid", "pid"},
		{"ds001-ebwoid", "ebwoid"},
		{"ds004-eucc", "eucc"},
		{"ds005-hello-world", "hello-world"},
		{"company-info", "company-info"},
		{"contact-person", "contact-person"},
		{"gln", "gln"},
		{"iban-ov", "iban-ov"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeSlug(tt.input)
			if got != tt.want {
				t.Errorf("normalizeSlug(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSlugToLabel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"given_name", "Given Name"},
		{"family_name", "Family Name"},
		{"birth-date", "Birth Date"},
		{"nationalities", "Nationalities"},
		{"attestation_legal_category", "Attestation Legal Category"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := slugToLabel(tt.input)
			if got != tt.want {
				t.Errorf("slugToLabel(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCleanDisplayName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"ds002 - Person Identification Data (PID) – SD-JWT VC payload", "Person Identification Data (PID)"},
		{"CompanyInfo SD-JWT VC Schema", "CompanyInfo"},
		{"Employee Attestation", "Employee Attestation"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanDisplayName(tt.input)
			if got != tt.want {
				t.Errorf("cleanDisplayName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestConvertJSONSchemaToVCTM(t *testing.T) {
	// Create a minimal test JSON Schema
	schema := map[string]interface{}{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://example.org/test-schema.json",
		"title":       "Test Credential SD-JWT VC Schema",
		"description": "A test credential schema",
		"type":        "object",
		"required":    []string{"vct", "given_name", "family_name"},
		"properties": map[string]interface{}{
			"vct": map[string]interface{}{
				"type":  "string",
				"const": "urn:test:credential:1",
			},
			"iss": map[string]interface{}{
				"type": "string",
			},
			"given_name": map[string]interface{}{
				"type":        "string",
				"description": "First name of the holder. MUST be selectively disclosable.",
			},
			"family_name": map[string]interface{}{
				"type":        "string",
				"description": "Last name of the holder.",
			},
			"email": map[string]interface{}{
				"type":        "string",
				"description": "Email address. MUST be selectively disclosable (SD claim).",
			},
			"cnf": map[string]interface{}{
				"type": "object",
			},
		},
	}

	tmpDir := t.TempDir()
	schemaPath := filepath.Join(tmpDir, "test-cred-sd-jwt.json")
	data, _ := json.MarshalIndent(schema, "", "  ")
	if err := os.WriteFile(schemaPath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := convertJSONSchemaToVCTM(schemaPath, "test-cred", "https://registry.example.org", "test-org")
	if err != nil {
		t.Fatal(err)
	}

	// Parse result
	var vctm vctmOutput
	if err := json.Unmarshal(result, &vctm); err != nil {
		t.Fatalf("unmarshaling result: %v", err)
	}

	// Verify VCT
	if vctm.VCT != "urn:test:credential:1" {
		t.Errorf("VCT = %q, want %q", vctm.VCT, "urn:test:credential:1")
	}

	// Verify infrastructure claims are excluded
	for _, claim := range vctm.Claims {
		path0, ok := claim.Path[0].(string)
		if !ok {
			continue
		}
		if infrastructureClaims[path0] {
			t.Errorf("infrastructure claim %q should not be in claims list", path0)
		}
	}

	// Verify mandatory detection
	findClaim := func(name string) *vctmClaim {
		for i := range vctm.Claims {
			if len(vctm.Claims[i].Path) > 0 {
				if p, ok := vctm.Claims[i].Path[0].(string); ok && p == name {
					return &vctm.Claims[i]
				}
			}
		}
		return nil
	}

	givenName := findClaim("given_name")
	if givenName == nil {
		t.Fatal("given_name claim not found")
	}
	if !givenName.Mandatory {
		t.Error("given_name should be mandatory")
	}
	if givenName.SD != "always" {
		t.Errorf("given_name SD = %q, want \"always\"", givenName.SD)
	}

	familyName := findClaim("family_name")
	if familyName == nil {
		t.Fatal("family_name claim not found")
	}
	if !familyName.Mandatory {
		t.Error("family_name should be mandatory")
	}

	email := findClaim("email")
	if email == nil {
		t.Fatal("email claim not found")
	}
	if email.Mandatory {
		t.Error("email should not be mandatory")
	}
	if email.SD != "always" {
		t.Errorf("email SD = %q, want \"always\"", email.SD)
	}
}

func TestDiscoverWithMockRepo(t *testing.T) {
	// Create a mock repo structure
	tmpDir := t.TempDir()
	sdJWTDir := filepath.Join(tmpDir, "data-schemas", "sd-jwt")
	mdocDir := filepath.Join(tmpDir, "data-schemas", "mdoc")
	rulebooksDir := filepath.Join(tmpDir, "rulebooks", "rb-pid")

	os.MkdirAll(sdJWTDir, 0o755)
	os.MkdirAll(mdocDir, 0o755)
	os.MkdirAll(rulebooksDir, 0o755)

	// Create a PID schema
	pidSchema := map[string]interface{}{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"title":   "ds002 - Person Identification Data (PID) – SD-JWT VC payload",
		"type":    "object",
		"required": []string{"vct", "given_name", "family_name", "birthdate"},
		"properties": map[string]interface{}{
			"vct":         map[string]interface{}{"type": "string", "const": "urn:eudi:pid:1"},
			"iss":         map[string]interface{}{"type": "string"},
			"given_name":  map[string]interface{}{"type": "string", "description": "First name"},
			"family_name": map[string]interface{}{"type": "string", "description": "Last name"},
			"birthdate":   map[string]interface{}{"type": "string", "description": "Date of birth"},
			"cnf":         map[string]interface{}{"type": "object"},
		},
	}
	data, _ := json.MarshalIndent(pidSchema, "", "  ")
	os.WriteFile(filepath.Join(sdJWTDir, "ds002-pid-sd-jwt.json"), data, 0o644)

	// Create a matching mDOC schema
	mdocSchema := map[string]interface{}{"docType": "eu.europa.ec.eudi.pid.1"}
	mdocData, _ := json.MarshalIndent(mdocSchema, "", "  ")
	os.WriteFile(filepath.Join(mdocDir, "ds002-pid-mdoc.json"), mdocData, 0o644)

	// Create rulebook
	os.WriteFile(filepath.Join(rulebooksDir, "README.md"), []byte("# PID Rulebook\n\nGovernance rules."), 0o644)

	// Run discovery
	plugin := &RulebookCatalog{}
	ctx := repoplugin.Context{
		RepoDir:      tmpDir,
		Organization: "webuild",
		BaseURL:      "https://registry.example.org",
		Options: map[string]string{
			"attestation_los": "iso_18045_high",
			"binding_type":    "key",
		},
		Logger: nil,
	}

	// Need a logger — use discard
	ctx.Logger = discardLogger()

	creds, err := plugin.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	cred := creds[0]
	if cred.Slug != "pid" {
		t.Errorf("slug = %q, want %q", cred.Slug, "pid")
	}
	if cred.Org != "webuild" {
		t.Errorf("org = %q, want %q", cred.Org, "webuild")
	}
	if cred.FormatFiles["mso_mdoc"] == "" {
		t.Error("expected mDOC format file to be detected")
	}
	if cred.RulebookPath == "" {
		t.Error("expected rulebook to be found")
	}
	if cred.SchemaMetaSource == nil {
		t.Fatal("expected schema-meta source from options")
	}
	if cred.SchemaMetaSource.AttestationLoS != "iso_18045_high" {
		t.Errorf("attestation_los = %q, want %q", cred.SchemaMetaSource.AttestationLoS, "iso_18045_high")
	}
	if len(cred.GeneratedVCTM) == 0 {
		t.Error("expected generated VCTM content")
	}

	// Verify VCTM content
	var vctm vctmOutput
	if err := json.Unmarshal(cred.GeneratedVCTM, &vctm); err != nil {
		t.Fatalf("parsing generated VCTM: %v", err)
	}
	if vctm.VCT != "urn:eudi:pid:1" {
		t.Errorf("VCTM VCT = %q, want %q", vctm.VCT, "urn:eudi:pid:1")
	}
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}
