// Package render handles HTML template rendering and markdown-to-HTML conversion
// for the registry site.
package render

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/yuin/goldmark"

	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

//go:embed default_templates/*.html default_templates/*.yaml
var defaultTemplates embed.FS

// CredentialData holds the data for rendering a credential detail page.
type CredentialData struct {
	Org           string
	Slug          string
	Schema        *schemameta.SchemaMeta
	TS11Compliant bool
	HasRulebook   bool
	RulebookHTML  template.HTML

	// VCTM content
	VCTM             *VCTMData
	RawVCTMJSON      string
	RawMdocJSON      string
	RawVCJSON        string
	HasMdoc          bool
	HasVC            bool
	AvailableFormats []FormatInfo

	// Source info
	SourceURL  string
	SourceOrg  string
	SourceRepo string
}

// SiteData holds the data for rendering the site index page.
type SiteData struct {
	BaseURL     string
	Credentials []CredentialData
	BuildTime   string
	Orgs        []OrgData
}

// Renderer renders HTML pages from Go templates.
type Renderer struct {
	tmpl *template.Template
}

// NewRenderer creates a renderer, loading default templates and optionally
// overlaying site-specific template overrides.
func NewRenderer(overrideDir string) (*Renderer, error) {
	// Start with default embedded templates
	tmpl, err := template.New("").Funcs(templateFuncs()).ParseFS(defaultTemplates, "default_templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parsing default templates: %w", err)
	}

	// Overlay site-specific overrides if provided
	if overrideDir != "" {
		if _, err := os.Stat(overrideDir); err == nil {
			overrides, err := filepath.Glob(filepath.Join(overrideDir, "*.html"))
			if err != nil {
				return nil, fmt.Errorf("globbing overrides: %w", err)
			}
			if len(overrides) > 0 {
				tmpl, err = tmpl.ParseFiles(overrides...)
				if err != nil {
					return nil, fmt.Errorf("parsing override templates: %w", err)
				}
			}
		}
	}

	return &Renderer{tmpl: tmpl}, nil
}

// RenderIndex renders the site index page.
func (r *Renderer) RenderIndex(outputDir string, data SiteData) error {
	return r.renderToFile(filepath.Join(outputDir, "index.html"), "index.html", data)
}

// RenderCredential renders a credential detail page.
func (r *Renderer) RenderCredential(outputDir string, data CredentialData) error {
	dir := filepath.Join(outputDir, data.Org, data.Slug)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return r.renderToFile(filepath.Join(dir, "index.html"), "credential.html", data)
}

// RenderOrg renders an organization page.
func (r *Renderer) RenderOrg(outputDir string, data OrgData) error {
	dir := filepath.Join(outputDir, data.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return r.renderToFile(filepath.Join(dir, "index.html"), "org.html", data)
}

// RenderRulebook renders a rulebook markdown file to HTML.
func (r *Renderer) RenderRulebook(outputDir string, data CredentialData) error {
	if !data.HasRulebook {
		return nil
	}
	dir := filepath.Join(outputDir, data.Org, data.Slug)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	rbData := struct {
		CredentialData
		Content template.HTML
	}{
		CredentialData: data,
		Content:        data.RulebookHTML,
	}
	return r.renderToFile(filepath.Join(dir, "rulebook.html"), "rulebook.html", rbData)
}

// RenderTS11Docs renders the TS11 documentation page.
func (r *Renderer) RenderTS11Docs(outputDir string, data SiteData) error {
	docsDir := filepath.Join(outputDir, "docs")
	if err := os.MkdirAll(docsDir, 0o755); err != nil {
		return err
	}
	return r.renderToFile(filepath.Join(docsDir, "ts11.html"), "ts11.html", data)
}

// RenderAPIDocs renders the API reference page.
func (r *Renderer) RenderAPIDocs(outputDir string, data SiteData) error {
	docsDir := filepath.Join(outputDir, "docs")
	if err := os.MkdirAll(docsDir, 0o755); err != nil {
		return err
	}
	return r.renderToFile(filepath.Join(docsDir, "api.html"), "api.html", data)
}

// RenderExtraDocPages renders any additional HTML templates loaded from
// the override directory that aren't part of the built-in set.
// They are rendered to docs/{name} in the output directory.
func (r *Renderer) RenderExtraDocPages(outputDir string, data SiteData) error {
	builtIn := map[string]bool{
		"":                true,
		"index.html":      true,
		"credential.html": true,
		"org.html":        true,
		"rulebook.html":   true,
		"ts11.html":       true,
		"api.html":        true,
	}
	docsDir := filepath.Join(outputDir, "docs")
	if err := os.MkdirAll(docsDir, 0o755); err != nil {
		return err
	}
	for _, t := range r.tmpl.Templates() {
		name := t.Name()
		if builtIn[name] || !strings.HasSuffix(name, ".html") {
			continue
		}
		if err := r.renderToFile(filepath.Join(docsDir, name), name, data); err != nil {
			return fmt.Errorf("rendering doc page %s: %w", name, err)
		}
	}
	return nil
}

func (r *Renderer) renderToFile(path, templateName string, data any) error {
	var buf bytes.Buffer
	if err := r.tmpl.ExecuteTemplate(&buf, templateName, data); err != nil {
		return fmt.Errorf("rendering %s: %w", templateName, err)
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

// RenderMarkdown converts markdown content to HTML.
func RenderMarkdown(markdown []byte) (template.HTML, error) {
	var buf bytes.Buffer
	if err := goldmark.Convert(markdown, &buf); err != nil {
		return "", fmt.Errorf("rendering markdown: %w", err)
	}
	return template.HTML(buf.String()), nil
}

// CopyStaticAssets copies static files (CSS, images) from a source directory
// to the output directory, preserving the directory structure.
func CopyStaticAssets(srcDir, dstDir string) error {
	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		dstPath := filepath.Join(dstDir, relPath)
		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dstPath, data, 0o644)
	})
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"join": func(sep string, items []string) string {
			result := ""
			for i, item := range items {
				if i > 0 {
					result += sep
				}
				result += item
			}
			return result
		},
		"formatPath": func(path []string) string {
			return strings.Join(path, ".")
		},
		"safeURL": func(u string) template.URL {
			return template.URL(u)
		},
	}
}

// WriteOpenAPISpec writes the embedded OpenAPI specification to the given path.
func WriteOpenAPISpec(path string) error {
	data, err := defaultTemplates.ReadFile("default_templates/openapi.yaml")
	if err != nil {
		return fmt.Errorf("reading embedded OpenAPI spec: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
