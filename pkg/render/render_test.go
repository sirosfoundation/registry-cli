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
	// API endpoint link should not appear when TS11Compliant is false
	assert.NotContains(t, string(content), "GET /schemas/test-uuid")
}

func TestRenderCredential_TS11APIEndpoint(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := CredentialData{
		Org:           "testorg",
		Slug:          "test_cred",
		TS11Compliant: true,
		Schema: &schemameta.SchemaMeta{
			ID:               "test-uuid",
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
			SupportedFormats: []string{"dc+sd-jwt"},
		},
	}

	err = r.RenderCredential(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "testorg", "test_cred", "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "GET /schemas/test-uuid")
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

func TestRenderMarkdown_SanitizesXSS(t *testing.T) {
	md := []byte(`# Title

<script>alert('xss')</script>

<img src=x onerror=alert(1)>

[click](javascript:alert(1))

Normal **bold** text.
`)
	html, err := RenderMarkdown(md)
	require.NoError(t, err)
	result := string(html)

	// Script tags must be stripped
	assert.NotContains(t, result, "<script>")
	assert.NotContains(t, result, "alert('xss')")

	// on* event handlers must be stripped
	assert.NotContains(t, result, "onerror")

	// javascript: URIs must be stripped
	assert.NotContains(t, result, "javascript:")

	// Safe content preserved
	assert.Contains(t, result, "<h1>Title</h1>")
	assert.Contains(t, result, "<strong>bold</strong>")
}

func TestRenderMarkdown_SanitizesSVGXSS(t *testing.T) {
	md := []byte(`<svg><script>alert('svg-xss')</script></svg>

<object data="data:text/html,<script>alert(1)</script>"></object>

<embed src="javascript:alert(1)">
`)
	html, err := RenderMarkdown(md)
	require.NoError(t, err)
	result := string(html)

	assert.NotContains(t, result, "<script>")
	assert.NotContains(t, result, "<svg>")
	assert.NotContains(t, result, "<object")
	assert.NotContains(t, result, "<embed")
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

func TestRenderOrg(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := OrgData{
		Name: "testorg",
		Credentials: []CredentialData{
			{Org: "testorg", Slug: "cred1", Schema: &schemameta.SchemaMeta{ID: "id1"}},
		},
		HasTS11: true,
	}

	err = r.RenderOrg(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "testorg", "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "testorg")
}

func TestRenderExtraDocPages(t *testing.T) {
	// Create override dir with an extra template
	overrideDir := t.TempDir()
	extra := `<!DOCTYPE html><html><body>Extra: {{.BuildTime}}</body></html>`
	require.NoError(t, os.WriteFile(filepath.Join(overrideDir, "custom-page.html"), []byte(extra), 0o644))

	r, err := NewRenderer(overrideDir)
	require.NoError(t, err)

	outDir := t.TempDir()
	data := SiteData{
		BaseURL:   "https://registry.example.org",
		BuildTime: "2026-05-01T00:00:00Z",
	}

	err = r.RenderExtraDocPages(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "docs", "custom-page.html"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "2026-05-01T00:00:00Z")
}

func TestRenderExtraDocPages_NoExtras(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := SiteData{}

	// Should not error even with no extra pages
	err = r.RenderExtraDocPages(outDir, data)
	require.NoError(t, err)
}

func TestCopyStaticAssets(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create source files
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "css"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "css", "style.css"), []byte("body{}"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "favicon.ico"), []byte("icon"), 0o644))

	err := CopyStaticAssets(srcDir, dstDir)
	require.NoError(t, err)

	// Verify files are copied
	css, err := os.ReadFile(filepath.Join(dstDir, "css", "style.css"))
	require.NoError(t, err)
	assert.Equal(t, "body{}", string(css))

	ico, err := os.ReadFile(filepath.Join(dstDir, "favicon.ico"))
	require.NoError(t, err)
	assert.Equal(t, "icon", string(ico))
}

func TestWriteOpenAPISpec(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openapi.yaml")

	err := WriteOpenAPISpec(path)
	require.NoError(t, err)

	content, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Contains(t, string(content), "openapi")
}

func TestCollectAttributes_Empty(t *testing.T) {
	attrs := CollectAttributes(nil)
	assert.Empty(t, attrs)
}

func TestCollectAttributes_NoVCTM(t *testing.T) {
	creds := []CredentialData{
		{Org: "org", Slug: "cred1", Schema: &schemameta.SchemaMeta{ID: "id1"}},
	}
	attrs := CollectAttributes(creds)
	assert.Empty(t, attrs)
}

func TestCollectAttributes_SingleCredential(t *testing.T) {
	creds := []CredentialData{
		{
			Org:  "org1",
			Slug: "cred1",
			VCTM: &VCTMData{
				Name: "Test Credential",
				Claims: []VCTMClaim{
					{Path: []string{"email"}, Display: []VCTMClaimDisplay{{Name: "Email", Locale: "en"}}},
					{Path: []string{"name", "given"}},
				},
			},
			Schema: &schemameta.SchemaMeta{ID: "id1"},
		},
	}
	attrs := CollectAttributes(creds)
	require.Len(t, attrs, 2)

	assert.Equal(t, "email", attrs[0].Path)
	assert.Equal(t, "Email", attrs[0].DisplayName)
	require.Len(t, attrs[0].Credentials, 1)
	assert.Equal(t, "Test Credential", attrs[0].Credentials[0].Name)

	assert.Equal(t, "name.given", attrs[1].Path)
	assert.Empty(t, attrs[1].DisplayName)
}

func TestCollectAttributes_Deduplication(t *testing.T) {
	creds := []CredentialData{
		{
			Org:  "org1",
			Slug: "cred1",
			VCTM: &VCTMData{
				Name: "Cred 1",
				Claims: []VCTMClaim{
					{Path: []string{"email"}, Display: []VCTMClaimDisplay{{Name: "Email"}}},
					{Path: []string{"name"}},
				},
			},
			Schema: &schemameta.SchemaMeta{ID: "id1"},
		},
		{
			Org:  "org2",
			Slug: "cred2",
			VCTM: &VCTMData{
				Name: "Cred 2",
				Claims: []VCTMClaim{
					{Path: []string{"email"}, Display: []VCTMClaimDisplay{{Name: "E-Mail"}}},
					{Path: []string{"phone"}},
				},
			},
			Schema: &schemameta.SchemaMeta{ID: "id2"},
		},
	}
	attrs := CollectAttributes(creds)
	require.Len(t, attrs, 3) // email, name, phone

	// "email" should be deduplicated with two credential references
	assert.Equal(t, "email", attrs[0].Path)
	assert.Equal(t, "Email", attrs[0].DisplayName) // first display name wins
	require.Len(t, attrs[0].Credentials, 2)
	assert.Equal(t, "Cred 1", attrs[0].Credentials[0].Name)
	assert.Equal(t, "Cred 2", attrs[0].Credentials[1].Name)
}

func TestCollectAttributes_UsesSlugWhenNoName(t *testing.T) {
	creds := []CredentialData{
		{
			Org:  "org1",
			Slug: "my_slug",
			VCTM: &VCTMData{
				// Name is empty
				Claims: []VCTMClaim{
					{Path: []string{"field"}},
				},
			},
			Schema: &schemameta.SchemaMeta{ID: "id1"},
		},
	}
	attrs := CollectAttributes(creds)
	require.Len(t, attrs, 1)
	assert.Equal(t, "my_slug", attrs[0].Credentials[0].Name)
}

func TestRenderAttributes(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := SiteData{
		BaseURL:   "https://registry.example.org",
		BuildTime: "2026-04-26T00:00:00Z",
		Attributes: []AttributeData{
			{
				Path:        "email",
				DisplayName: "Email Address",
				Credentials: []AttributeCredRef{
					{Org: "org1", Slug: "cred1", Name: "Cred 1"},
				},
			},
		},
	}

	err = r.RenderAttributes(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "docs", "attributes.html"))
	require.NoError(t, err)
	html := string(content)
	assert.Contains(t, html, "Catalogue of Attributes")
	assert.Contains(t, html, "email")
	assert.Contains(t, html, "Email Address")
	assert.Contains(t, html, "Cred 1")
}

func TestRenderAttributes_Empty(t *testing.T) {
	r, err := NewRenderer("")
	require.NoError(t, err)

	outDir := t.TempDir()
	data := SiteData{
		BaseURL:   "https://registry.example.org",
		BuildTime: "2026-04-26T00:00:00Z",
	}

	err = r.RenderAttributes(outDir, data)
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(outDir, "docs", "attributes.html"))
	require.NoError(t, err)
	assert.Contains(t, string(content), "No attributes found")
}
