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
