package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/registry-cli/pkg/render"
	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

func TestExtractOrg(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"github HTTPS", "https://github.com/sirosfoundation/demo-credentials", "sirosfoundation"},
		{"github HTTPS with .git", "https://github.com/SUNET/vc.git", "SUNET"},
		{"file URL", "file:///home/user/repos/demo-credentials", "repos"},
		{"trailing slash", "https://github.com/org/repo/", "org"},
		{"single segment", "repo", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractOrg(tt.url))
		})
	}
}

func TestExtractRepoName(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected string
	}{
		{"github HTTPS", "https://github.com/sirosfoundation/demo-credentials", "demo-credentials"},
		{"github HTTPS with .git", "https://github.com/SUNET/vc.git", "vc"},
		{"file URL", "file:///home/user/repos/my-creds", "my-creds"},
		{"trailing slash", "https://github.com/org/repo/", "repo"},
		{"single segment", "repo", "repo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractRepoName(tt.url))
		})
	}
}

func TestOrgSlugFromID(t *testing.T) {
	baseURL := "https://registry.siros.org"

	tests := []struct {
		name         string
		schemaURIs   []schemameta.SchemaURI
		expectedOrg  string
		expectedSlug string
	}{
		{
			"vctm.json format",
			[]schemameta.SchemaURI{{FormatIdentifier: "sd-jwt", URI: baseURL + "/myorg/test_cred.vctm.json"}},
			"myorg", "test_cred",
		},
		{
			"mdoc.json format",
			[]schemameta.SchemaURI{{FormatIdentifier: "mdoc", URI: baseURL + "/org2/cred.mdoc.json"}},
			"org2", "cred",
		},
		{
			"bare .vctm",
			[]schemameta.SchemaURI{{FormatIdentifier: "sd-jwt", URI: baseURL + "/org3/legacy.vctm"}},
			"org3", "legacy",
		},
		{
			"bare .json",
			[]schemameta.SchemaURI{{FormatIdentifier: "sd-jwt", URI: baseURL + "/org4/demo.json"}},
			"org4", "demo",
		},
		{
			"no schema URIs",
			nil,
			"", "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := &schemameta.SchemaMeta{SchemaURIs: tt.schemaURIs}
			org, slug := orgSlugFromID(sm, baseURL)
			assert.Equal(t, tt.expectedOrg, org)
			assert.Equal(t, tt.expectedSlug, slug)
		})
	}
}

func TestPrettyFormatJSON(t *testing.T) {
	input := `{"name":"test","value":42}`
	result := prettyFormatJSON([]byte(input))
	assert.Contains(t, result, "  \"name\"")
	assert.Contains(t, result, "  \"value\"")

	// Invalid JSON returns raw input
	invalid := `{not json}`
	assert.Equal(t, invalid, prettyFormatJSON([]byte(invalid)))
}

func TestSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := securityHeaders(inner)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", rec.Header().Get("Referrer-Policy"))
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "default-src 'none'")
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "img-src 'self' https://github.com")
	assert.Contains(t, rec.Header().Get("Permissions-Policy"), "camera=()")
}

func TestWriteOutputs(t *testing.T) {
	dir := t.TempDir()
	schemas := []*schemameta.SchemaMeta{
		{
			ID:               "test-id-1",
			Version:          "1.0.0",
			SupportedFormats: []string{"sd-jwt"},
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
		},
	}

	err := writeOutputs(dir, "https://example.com", schemas)
	require.NoError(t, err)

	// Check individual schema file
	schemaPath := filepath.Join(dir, "api", "v1", "schemas", "test-id-1.json")
	data, err := os.ReadFile(schemaPath)
	require.NoError(t, err)

	var sm schemameta.SchemaMeta
	require.NoError(t, json.Unmarshal(data, &sm))
	assert.Equal(t, "test-id-1", sm.ID)
	assert.Equal(t, "1.0.0", sm.Version)

	// Check aggregate schemas.json
	listPath := filepath.Join(dir, "api", "v1", "schemas.json")
	listData, err := os.ReadFile(listPath)
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(listData, &payload))
	assert.Equal(t, float64(1), payload["total"])
}

func TestWriteLegacyOutput(t *testing.T) {
	dir := t.TempDir()
	schemas := []*schemameta.SchemaMeta{
		{
			ID:               "legacy-1",
			Version:          "0.1.0",
			SupportedFormats: []string{"sd-jwt", "mdoc"},
			AttestationLoS:   "iso_18045_basic",
		},
		{
			ID:               "legacy-2",
			Version:          "0.2.0",
			SupportedFormats: []string{"w3c-vc"},
		},
	}

	err := writeLegacyOutput(dir, schemas)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "api", "v1", "registry.json"))
	require.NoError(t, err)

	var payload map[string]any
	require.NoError(t, json.Unmarshal(data, &payload))
	assert.Equal(t, float64(2), payload["total"])
}

func TestLoadBuiltSchemas(t *testing.T) {
	dir := t.TempDir()
	apiDir := filepath.Join(dir, "api", "v1")
	require.NoError(t, os.MkdirAll(apiDir, 0o755))

	payload := map[string]any{
		"total":  1,
		"limit":  1,
		"offset": 0,
		"data": []map[string]any{
			{
				"id":               "loaded-id",
				"version":          "1.0.0",
				"supportedFormats": []string{"sd-jwt"},
			},
		},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(apiDir, "schemas.json"), data, 0o644))

	schemas, err := loadBuiltSchemas(dir)
	require.NoError(t, err)
	require.Len(t, schemas, 1)
	assert.Equal(t, "loaded-id", schemas[0].ID)
}

func TestLoadBuiltSchemas_MissingFile(t *testing.T) {
	_, err := loadBuiltSchemas(t.TempDir())
	assert.Error(t, err)
}

func TestWriteDCATCatalog(t *testing.T) {
	dir := t.TempDir()
	schemas := []*schemameta.SchemaMeta{
		{
			ID:               "dcat-test-1",
			Version:          "1.0.0",
			SupportedFormats: []string{"sd-jwt"},
		},
	}

	err := writeDCATCatalog(dir, "https://example.com", schemas, "2026-04-26T00:00:00Z")
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "catalog.jsonld"))
	require.NoError(t, err)

	var catalog map[string]any
	require.NoError(t, json.Unmarshal(data, &catalog))
	assert.Equal(t, "dcat:Catalog", catalog["@type"])
	datasets := catalog["dcat:dataset"].([]any)
	assert.Len(t, datasets, 1)
}

func TestWriteOpenAPISpec(t *testing.T) {
	dir := t.TempDir()
	err := writeOpenAPISpec(dir)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, "api", "v1", "openapi.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(data), "openapi")
}

func TestBuildFormatInfo(t *testing.T) {
	dir := t.TempDir()

	// Create format files
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.vctm.json"), []byte("{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.mdoc.json"), []byte("{}"), 0o644))

	formats := buildFormatInfo("org", "test", dir)
	assert.Len(t, formats, 2)

	names := make(map[string]bool)
	for _, f := range formats {
		names[f.Name] = true
	}
	assert.True(t, names["SD-JWT"])
	assert.True(t, names["mDOC"])
}

func TestBuildFormatInfo_LegacyBareVCTM(t *testing.T) {
	dir := t.TempDir()

	// Only bare .vctm file (no .vctm.json)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "legacy.vctm"), []byte("{}"), 0o644))

	formats := buildFormatInfo("org", "legacy", dir)
	require.Len(t, formats, 1)
	assert.Equal(t, "SD-JWT", formats[0].Name)
	assert.Equal(t, "/org/legacy.vctm", formats[0].File)
}

func TestBuildFormatInfo_NoFormats(t *testing.T) {
	dir := t.TempDir()
	formats := buildFormatInfo("org", "missing", dir)
	assert.Empty(t, formats)
}

func TestCopyFormatFiles(t *testing.T) {
	srcDir := t.TempDir()
	outDir := t.TempDir()

	// Create a .vctm.json file in srcDir
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "cred.vctm.json"), []byte(`{"test":true}`), 0o644))

	copyFormatFiles(srcDir, outDir, "testorg", "cred")

	// Check file was copied
	data, err := os.ReadFile(filepath.Join(outDir, "testorg", "cred.vctm.json"))
	require.NoError(t, err)
	assert.Equal(t, `{"test":true}`, string(data))
}

func TestWriteVCTMRegistryJSON(t *testing.T) {
	dir := t.TempDir()
	baseURL := "https://registry.siros.org"

	credentials := []render.CredentialData{
		{
			Org:  "sirosfoundation",
			Slug: "test-cred",
			Schema: &schemameta.SchemaMeta{
				ID:      "test-id-1",
				Version: "1.0.0",
			},
			VCTM: &render.VCTMData{
				VCT:         "https://example.com/types/test-cred",
				Name:        "Test Credential",
				Description: "A test credential for unit tests",
			},
			AvailableFormats: []render.FormatInfo{
				{Name: "SD-JWT", Label: "SD-JWT VC Type Metadata", File: "/sirosfoundation/test-cred.vctm.json"},
				{Name: "mDOC", Label: "mso_mdoc", File: "/sirosfoundation/test-cred.mdoc.json"},
			},
			SourceURL:  "https://github.com/sirosfoundation/demo-credentials",
			SourceRepo: "demo-credentials",
		},
		{
			Org:  "SUNET",
			Slug: "legacy-cred",
			Schema: &schemameta.SchemaMeta{
				ID:      "legacy-id",
				Version: "0.1.0",
				SchemaURIs: []schemameta.SchemaURI{
					{FormatIdentifier: "dc+sd-jwt", URI: baseURL + "/SUNET/legacy-cred.vctm"},
				},
			},
			// No VCTM data — legacy credential without parsed VCTM
		},
	}

	err := writeVCTMRegistryJSON(dir, baseURL, credentials)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".well-known", "vctm-registry.json"))
	require.NoError(t, err)

	var index map[string]any
	require.NoError(t, json.Unmarshal(data, &index))

	// Check top-level fields
	assert.Equal(t, "SIROS Credential Registry", index["name"])
	assert.Equal(t, "2.0", index["version"])
	assert.Equal(t, baseURL, index["url"])
	assert.NotEmpty(t, index["buildTime"])

	// Check credentials array
	creds := index["credentials"].([]any)
	require.Len(t, creds, 2)

	// First credential: has VCTM data and available formats
	c1 := creds[0].(map[string]any)
	assert.Equal(t, "https://example.com/types/test-cred", c1["vct"])
	assert.Equal(t, "Test Credential", c1["name"])
	assert.Equal(t, "A test credential for unit tests", c1["description"])
	assert.Equal(t, "sirosfoundation", c1["organization"])

	formats1 := c1["formats"].(map[string]any)
	vctmFmt := formats1["vctm"].(map[string]any)
	assert.Equal(t, baseURL+"/sirosfoundation/test-cred.vctm.json", vctmFmt["url"])
	mdocFmt := formats1["mdoc"].(map[string]any)
	assert.Equal(t, baseURL+"/sirosfoundation/test-cred.mdoc.json", mdocFmt["url"])

	meta1 := c1["metadata"].(map[string]any)
	assert.Equal(t, baseURL+"/sirosfoundation/test-cred.html", meta1["html"])
	assert.Equal(t, baseURL+"/sirosfoundation/test-cred.vctm.json", meta1["json"])

	source1 := c1["source"].(map[string]any)
	assert.Equal(t, "https://github.com/sirosfoundation/demo-credentials", source1["repository"])

	// Second credential: no VCTM, falls back to schema ID and schema URIs
	c2 := creds[1].(map[string]any)
	assert.Equal(t, "legacy-id", c2["vct"])
	assert.Equal(t, "legacy-cred", c2["name"])

	formats2 := c2["formats"].(map[string]any)
	vctmFmt2 := formats2["vctm"].(map[string]any)
	assert.Equal(t, baseURL+"/SUNET/legacy-cred.vctm", vctmFmt2["url"])
}

func TestWriteVCTMRegistryJSON_EmptyCredentials(t *testing.T) {
	dir := t.TempDir()

	err := writeVCTMRegistryJSON(dir, "https://example.com", nil)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(dir, ".well-known", "vctm-registry.json"))
	require.NoError(t, err)

	var index map[string]any
	require.NoError(t, json.Unmarshal(data, &index))
	// credentials should be null/empty but the file should still be valid JSON
	assert.NotNil(t, index["name"])
	assert.Equal(t, "2.0", index["version"])
}
