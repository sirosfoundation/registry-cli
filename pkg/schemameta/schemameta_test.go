package schemameta

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.schema-meta.yaml")

	content := `attestation_los: iso_18045_high
binding_type: key
version: 1.0.0
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	src, err := ParseSource(path)
	require.NoError(t, err)
	assert.Equal(t, "iso_18045_high", src.AttestationLoS)
	assert.Equal(t, "key", src.BindingType)
	assert.Equal(t, "1.0.0", src.Version)
}

func TestParseSource_Minimal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.schema-meta.yaml")

	content := `attestation_los: iso_18045_high
binding_type: key
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	src, err := ParseSource(path)
	require.NoError(t, err)
	assert.Equal(t, "iso_18045_high", src.AttestationLoS)
	assert.Equal(t, "key", src.BindingType)
	assert.Empty(t, src.Version)
	assert.Empty(t, src.TrustedAuthorities)
}

func TestParseSource_WithTrustedAuthorities(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.schema-meta.yaml")

	content := `attestation_los: iso_18045_high
binding_type: key
trusted_authorities:
  - framework_type: etsi_tl
    value: https://example.com/tl
    is_lote: true
  - framework_type: aki
    value: dGVzdA==
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	src, err := ParseSource(path)
	require.NoError(t, err)
	require.Len(t, src.TrustedAuthorities, 2)
	assert.Equal(t, "etsi_tl", src.TrustedAuthorities[0].FrameworkType)
	assert.Equal(t, "https://example.com/tl", src.TrustedAuthorities[0].Value)
	require.NotNil(t, src.TrustedAuthorities[0].IsLOTE)
	assert.True(t, *src.TrustedAuthorities[0].IsLOTE)
	assert.Equal(t, "aki", src.TrustedAuthorities[1].FrameworkType)
	assert.Nil(t, src.TrustedAuthorities[1].IsLOTE)
}

func TestGenerateID_Deterministic(t *testing.T) {
	id1 := GenerateID("sirosfoundation", "vctm_pid_arf_1_5")
	id2 := GenerateID("sirosfoundation", "vctm_pid_arf_1_5")
	assert.Equal(t, id1, id2, "same org/slug should produce same UUID")

	id3 := GenerateID("other-org", "vctm_pid_arf_1_5")
	assert.NotEqual(t, id1, id3, "different org should produce different UUID")
}

func TestDetectFormats(t *testing.T) {
	dir := t.TempDir()
	slug := "test_cred"

	// Create format files
	require.NoError(t, os.WriteFile(filepath.Join(dir, slug+".vctm.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, slug+".mdoc.json"), []byte("{}"), 0o644))
	// Unrelated file
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.vctm.json"), []byte("{}"), 0o644))

	formats, files, err := DetectFormats(dir, slug)
	require.NoError(t, err)
	assert.Equal(t, 2, len(formats))
	assert.Contains(t, formats, "dc+sd-jwt")
	assert.Contains(t, formats, "mso_mdoc")
	assert.Equal(t, 2, len(files))
}

func TestDetectFormats_BareJSON(t *testing.T) {
	dir := t.TempDir()
	slug := "vctm_demo_1"

	// Only bare .json file — like demo-credentials
	require.NoError(t, os.WriteFile(filepath.Join(dir, slug+".json"), []byte("{}"), 0o644))

	formats, files, err := DetectFormats(dir, slug)
	require.NoError(t, err)
	assert.Equal(t, 1, len(formats))
	assert.Contains(t, formats, "dc+sd-jwt")
	assert.Contains(t, files, "dc+sd-jwt")
}

func TestDetectFormats_VCTMJsonPreferredOverBareJSON(t *testing.T) {
	dir := t.TempDir()
	slug := "test_cred"

	// Both .vctm.json and .json exist — .vctm.json should win
	require.NoError(t, os.WriteFile(filepath.Join(dir, slug+".vctm.json"), []byte(`{"type":"vctm"}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, slug+".json"), []byte(`{"type":"bare"}`), 0o644))

	formats, files, err := DetectFormats(dir, slug)
	require.NoError(t, err)
	assert.Equal(t, 1, len(formats))
	assert.Contains(t, formats, "dc+sd-jwt")
	// Should use .vctm.json, not .json
	assert.Contains(t, files["dc+sd-jwt"], ".vctm.json")
}

func TestInfer(t *testing.T) {
	src := &SchemaMetaSource{
		AttestationLoS: "iso_18045_high",
		BindingType:    "key",
	}
	formats := []string{"dc+sd-jwt", "mso_mdoc"}
	formatFiles := map[string]string{
		"dc+sd-jwt": "/tmp/test_cred.vctm.json",
		"mso_mdoc":  "/tmp/test_cred.mdoc.json",
	}

	sm := Infer(src, "sirosfoundation", "test_cred", "https://registry.siros.org", formats, formatFiles)

	assert.NotEmpty(t, sm.ID)
	assert.Equal(t, "0.1.0", sm.Version, "should default to 0.1.0")
	assert.Equal(t, "iso_18045_high", sm.AttestationLoS)
	assert.Equal(t, "key", sm.BindingType)
	assert.Equal(t, 2, len(sm.SupportedFormats))
	assert.Equal(t, 2, len(sm.SchemaURIs))
}

func TestInfer_NormalizesLegacyValues(t *testing.T) {
	src := &SchemaMetaSource{
		AttestationLoS: "high",
		BindingType:    "cnf",
	}

	sm := Infer(src, "org", "slug", "https://example.com", nil, nil)
	assert.Equal(t, "iso_18045_high", sm.AttestationLoS)
	assert.Equal(t, "key", sm.BindingType)
}

func TestInfer_WithVersion(t *testing.T) {
	src := &SchemaMetaSource{
		AttestationLoS: "iso_18045_high",
		BindingType:    "key",
		Version:        "2.0.0",
	}

	sm := Infer(src, "org", "slug", "https://example.com", nil, nil)
	assert.Equal(t, "2.0.0", sm.Version)
}

func TestInfer_WithRulebookURI(t *testing.T) {
	src := &SchemaMetaSource{
		AttestationLoS: "iso_18045_high",
		BindingType:    "key",
		RulebookURI:    "https://example.com/rulebook",
	}

	sm := Infer(src, "org", "slug", "https://example.com", nil, nil)
	assert.Equal(t, "https://example.com/rulebook", sm.RulebookURI)
}

func TestNormalizeAttestationLoS(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"iso_18045_high", "iso_18045_high"},
		{"iso_18045_moderate", "iso_18045_moderate"},
		{"iso_18045_enhanced-basic", "iso_18045_enhanced-basic"},
		{"iso_18045_basic", "iso_18045_basic"},
		{"high", "iso_18045_high"},
		{"moderate", "iso_18045_moderate"},
		{"substantial", "iso_18045_moderate"},
		{"enhanced-basic", "iso_18045_enhanced-basic"},
		{"basic", "iso_18045_basic"},
		{"low", "iso_18045_basic"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, NormalizeAttestationLoS(tt.input), "input: %s", tt.input)
	}
}

func TestNormalizeBindingType(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"claim", "claim"},
		{"key", "key"},
		{"biometric", "biometric"},
		{"none", "none"},
		{"cnf", "key"},
		{"holder", "key"},
		{"unknown", "unknown"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, NormalizeBindingType(tt.input), "input: %s", tt.input)
	}
}

func TestValidate_TS11Compliant(t *testing.T) {
	v, err := NewValidator()
	require.NoError(t, err)

	sm := &SchemaMeta{
		ID:               GenerateID("org", "slug"),
		Version:          "1.0.0",
		AttestationLoS:   "iso_18045_high",
		BindingType:      "key",
		RulebookURI:      "https://example.com/rulebook",
		SupportedFormats: []string{"dc+sd-jwt"},
		SchemaURIs: []SchemaURI{
			{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
		},
	}

	assert.NoError(t, v.Validate(sm))
}

func TestValidate_MissingRulebookURI(t *testing.T) {
	v, err := NewValidator()
	require.NoError(t, err)

	sm := &SchemaMeta{
		ID:               GenerateID("org", "slug"),
		Version:          "1.0.0",
		AttestationLoS:   "iso_18045_high",
		BindingType:      "key",
		SupportedFormats: []string{"dc+sd-jwt"},
		SchemaURIs: []SchemaURI{
			{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
		},
	}

	assert.Error(t, v.Validate(sm))
}

func TestValidate_InvalidAttestationLoS(t *testing.T) {
	v, err := NewValidator()
	require.NoError(t, err)

	sm := &SchemaMeta{
		ID:               GenerateID("org", "slug"),
		Version:          "1.0.0",
		AttestationLoS:   "invalid_value",
		BindingType:      "key",
		RulebookURI:      "https://example.com/rulebook",
		SupportedFormats: []string{"dc+sd-jwt"},
		SchemaURIs: []SchemaURI{
			{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
		},
	}

	assert.Error(t, v.Validate(sm))
}

func TestValidate_WithTrustedAuthorities(t *testing.T) {
	v, err := NewValidator()
	require.NoError(t, err)

	isLOTE := true
	sm := &SchemaMeta{
		ID:               GenerateID("org", "slug"),
		Version:          "1.0.0",
		AttestationLoS:   "iso_18045_high",
		BindingType:      "key",
		RulebookURI:      "https://example.com/rulebook",
		SupportedFormats: []string{"dc+sd-jwt"},
		SchemaURIs: []SchemaURI{
			{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
		},
		TrustedAuthorities: []TrustAuthority{
			{FrameworkType: "etsi_tl", Value: "https://example.com/tl", IsLOTE: &isLOTE},
		},
	}

	assert.NoError(t, v.Validate(sm))
}

func TestValidSupportedFormat(t *testing.T) {
	assert.True(t, ValidSupportedFormat("dc+sd-jwt"))
	assert.True(t, ValidSupportedFormat("mso_mdoc"))
	assert.True(t, ValidSupportedFormat("jwt_vc_json"))
	assert.True(t, ValidSupportedFormat("jwt_vc_json-ld"))
	assert.True(t, ValidSupportedFormat("ldp_vc"))
	assert.False(t, ValidSupportedFormat("unknown_format"))
	assert.False(t, ValidSupportedFormat(""))
}

func TestInferLegacy(t *testing.T) {
	formats := []string{"dc+sd-jwt", "mso_mdoc"}
	formatFiles := map[string]string{
		"dc+sd-jwt": "/tmp/out/test_cred.vctm.json",
		"mso_mdoc":  "/tmp/out/test_cred.mdoc.json",
	}

	sm := InferLegacy("myorg", "test_cred", "https://example.org", formats, formatFiles)

	assert.NotEmpty(t, sm.ID)
	assert.Equal(t, "0.1.0", sm.Version)
	assert.Equal(t, formats, sm.SupportedFormats)
	assert.Equal(t, 2, len(sm.SchemaURIs))
	assert.Equal(t, "dc+sd-jwt", sm.SchemaURIs[0].FormatIdentifier)
	assert.Contains(t, sm.SchemaURIs[0].URI, "test_cred.vctm.json")
	assert.Equal(t, "mso_mdoc", sm.SchemaURIs[1].FormatIdentifier)
	assert.Contains(t, sm.SchemaURIs[1].URI, "test_cred.mdoc.json")
}

func TestDetectLegacyCredentials(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(dir, "cred_a.vctm.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "cred_b.vctm"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "known.vctm.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# hi"), 0o644))

	knownSlugs := map[string]bool{"known": true}
	slugs, err := DetectLegacyCredentials(dir, knownSlugs)
	require.NoError(t, err)
	assert.Contains(t, slugs, "cred_a")
	assert.Contains(t, slugs, "cred_b")
	assert.NotContains(t, slugs, "known")
	assert.Equal(t, 2, len(slugs))
}

func TestDetectLegacyCredentials_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	slugs, err := DetectLegacyCredentials(dir, nil)
	require.NoError(t, err)
	assert.Empty(t, slugs)
}

func TestDetectLegacyCredentials_NonexistentDir(t *testing.T) {
	_, err := DetectLegacyCredentials("/nonexistent/path", nil)
	assert.Error(t, err)
}

func TestValidateRaw_AdditionalProperties(t *testing.T) {
	v, err := NewValidator()
	require.NoError(t, err)

	// Valid object with an extra property should fail additionalProperties
	obj := map[string]any{
		"id":               "urn:test:id",
		"version":          "1.0.0",
		"attestationLoS":   "iso_18045_high",
		"bindingType":      "key",
		"rulebookURI":      "https://example.com/rb",
		"supportedFormats": []any{"dc+sd-jwt"},
		"schemaURIs":       []any{map[string]any{"formatIdentifier": "dc+sd-jwt", "uri": "https://example.com/s.json"}},
		"trustedAuthorities": []any{map[string]any{
			"frameworkType": "etsi_tl",
			"value":         "https://example.com/tl",
			"isLOTE":        true,
		}},
		"extraField": "should_fail",
	}
	err = v.ValidateRaw(obj)
	assert.Error(t, err, "additionalProperties should reject unknown fields")
}

func TestValidateRaw_Valid(t *testing.T) {
	v, err := NewValidator()
	require.NoError(t, err)

	obj := map[string]any{
		"id":               "urn:test:id",
		"version":          "1.0.0",
		"attestationLoS":   "iso_18045_high",
		"bindingType":      "key",
		"rulebookURI":      "https://example.com/rb",
		"supportedFormats": []any{"dc+sd-jwt"},
		"schemaURIs":       []any{map[string]any{"formatIdentifier": "dc+sd-jwt", "uri": "https://example.com/s.json"}},
		"trustedAuthorities": []any{map[string]any{
			"frameworkType": "etsi_tl",
			"value":         "https://example.com/tl",
			"isLOTE":        true,
		}},
	}
	err = v.ValidateRaw(obj)
	assert.NoError(t, err)
}

func TestNormalizeAttestationLoS_Invalid(t *testing.T) {
	// Unknown values should pass through unchanged
	result := NormalizeAttestationLoS("totally_invalid")
	assert.Equal(t, "totally_invalid", result)
}

func TestNormalizeBindingType_Invalid(t *testing.T) {
	result := NormalizeBindingType("unknown_type")
	assert.Equal(t, "unknown_type", result)
}

func TestNormalizeLegacyValues(t *testing.T) {
	assert.Equal(t, "iso_18045_high", NormalizeAttestationLoS("high"))
	assert.Equal(t, "iso_18045_moderate", NormalizeAttestationLoS("substantial"))
	assert.Equal(t, "iso_18045_basic", NormalizeAttestationLoS("low"))
	assert.Equal(t, "key", NormalizeBindingType("cnf"))
	assert.Equal(t, "key", NormalizeBindingType("holder"))
}

func TestParseSource_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.schema-meta.yaml")

	content := `attestation_los: [[[invalid
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	_, err := ParseSource(path)
	assert.Error(t, err)
}

func TestInferLegacy_DefaultVersion(t *testing.T) {
	sm := InferLegacy("org", "slug", "https://example.com", []string{"dc+sd-jwt"}, map[string]string{".vctm.json": "/path/to/file"})
	assert.Equal(t, "0.1.0", sm.Version)
}
