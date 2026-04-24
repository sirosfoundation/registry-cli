package render

import (
	"html/template"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRenderer_Defaults(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)
	assert.NotNil(t, r)
}

func TestNewRenderer_WithOverrides(t *testing.T) {
	dir := t.TempDir()
	// Write an override template
	override := `<!DOCTYPE html><html><body>Custom Index: {{len .Credentials}} credentials</body></html>`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "index.html"), []byte(override), 0o644))

	r, err := NewRenderer(dir)
	require.NoError(t, err)
	assert.NotNil(t, r)
}

func TestRenderIndex(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := SiteData{
		BaseURL:   "https://registry.example.org",
		BuildTime: "2026-04-24T12:00:00Z",
		Credentials: []CredentialData{
			{
				Org:  "testorg",
				Slug: "test_cred",
				Schema: &schemameta.SchemaMeta{
					ID:               "test-uuid",
					Version:          "1.0.0",
					AttestationLoS:   "iso_18045_high",
					BindingType:      "key",
					SupportedFormats: []string{"dc+sd-jwt", "mso_mdoc"},
				},
			},
		},
	}

	err = r.RenderIndex(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "testorg")
	assert.Contains(t, string(content), "test_cred")
	assert.Contains(t, string(content), "dc&#43;sd-jwt")
}

func TestRenderCredential(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := CredentialData{
		Org:  "testorg",
		Slug: "test_cred",
		Schema: &schemameta.SchemaMeta{
			ID:               "test-uuid",
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
			SupportedFormats: []string{"dc+sd-jwt"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.org/test.vctm.json"},
			},
		},
	}

	err = r.RenderCredential(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "testorg", "test_cred", "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "test-uuid")
	assert.Contains(t, string(content), "iso_18045_high")
}

func TestRenderRulebook(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := CredentialData{
		Org:          "testorg",
		Slug:         "test_cred",
		HasRulebook:  true,
		RulebookHTML: template.HTML("<h1>Test Rulebook</h1><p>Rules here.</p>"),
		Schema:       &schemameta.SchemaMeta{},
	}

	err = r.RenderRulebook(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "testorg", "test_cred", "rulebook.html"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "Test Rulebook")
	assert.Contains(t, string(content), "Rules here.")
}

func TestRenderRulebook_NoRulebook(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := CredentialData{
		Org:         "testorg",
		Slug:        "test_cred",
		HasRulebook: false,
		Schema:      &schemameta.SchemaMeta{},
	}

	err = r.RenderRulebook(outDir, data)
	require.NoError(t, err)

	// Should not create the file
	_, err = os.Stat(filepath.Join(outDir, "testorg", "test_cred", "rulebook.html"))
	assert.True(t, os.IsNotExist(err))
}

func TestRenderMarkdown(t *testing.T) {
	md := []byte("# Hello\n\nThis is **bold** text.\n\n- Item 1\n- Item 2\n")
	html, err := RenderMarkdown(md)
	require.NoError(t, err)
	assert.Contains(t, string(html), "<h1>Hello</h1>")
	assert.Contains(t, string(html), "<strong>bold</strong>")
	assert.Contains(t, string(html), "<li>Item 1</li>")
}

func TestRenderTS11Docs(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := SiteData{
		BaseURL:   "https://registry.example.org",
		BuildTime: "2026-04-24T12:00:00Z",
	}

	err = r.RenderTS11Docs(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "docs", "ts11.html"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "TS11")
}

func TestRenderAPIDocs(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := SiteData{
		BaseURL:   "https://registry.example.org",
		BuildTime: "2026-04-24T12:00:00Z",
	}

	err = r.RenderAPIDocs(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "docs", "api.html"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "registry.example.org")
}
