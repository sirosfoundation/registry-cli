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

	"github.com/microcosm-cc/bluemonday"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"

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

// AttributeData holds a single attribute (claim) with references to the
// credentials that define it.
type AttributeData struct {
	Path        string // dot-joined claim path
	DisplayName string // first non-empty display name found
	Credentials []AttributeCredRef
}

// AttributeCredRef links an attribute back to a credential.
type AttributeCredRef struct {
	Org  string
	Slug string
	Name string // credential display name or slug
}

// SiteData holds the data for rendering the site index page.
type SiteData struct {
	BaseURL     string
	Credentials []CredentialData
	BuildTime   string
	Orgs        []OrgData
	TS11Count   int
	Attributes  []AttributeData
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

// RenderAttributes renders the Catalogue of Attributes page.
func (r *Renderer) RenderAttributes(outputDir string, data SiteData) error {
	docsDir := filepath.Join(outputDir, "docs")
	if err := os.MkdirAll(docsDir, 0o755); err != nil {
		return err
	}
	return r.renderToFile(filepath.Join(docsDir, "attributes.html"), "attributes.html", data)
}

// CollectAttributes aggregates claims from all credentials into a deduplicated
// cross-cutting index. Claims with the same dot-path are merged, collecting
// references to all credentials that define them.
func CollectAttributes(credentials []CredentialData) []AttributeData {
	index := make(map[string]*AttributeData)
	var order []string

	for _, cred := range credentials {
		if cred.VCTM == nil || len(cred.VCTM.Claims) == 0 {
			continue
		}
		credName := cred.Slug
		if cred.VCTM.Name != "" {
			credName = cred.VCTM.Name
		}
		ref := AttributeCredRef{
			Org:  cred.Org,
			Slug: cred.Slug,
			Name: credName,
		}
		for _, claim := range cred.VCTM.Claims {
			p := strings.Join(claim.Path, ".")
			if _, exists := index[p]; !exists {
				index[p] = &AttributeData{Path: p}
				order = append(order, p)
			}
			ad := index[p]
			ad.Credentials = append(ad.Credentials, ref)
			// Use the first non-empty display name
			if ad.DisplayName == "" && len(claim.Display) > 0 && claim.Display[0].Name != "" {
				ad.DisplayName = claim.Display[0].Name
			}
		}
	}

	result := make([]AttributeData, 0, len(order))
	for _, p := range order {
		result = append(result, *index[p])
	}
	return result
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
		"attributes.html": true,
	}
	docsDir := filepath.Join(outputDir, "docs")
	if err := os.MkdirAll(docsDir, 0o755); err != nil {
		return err
	}
	for _, t := range r.tmpl.Templates() {
		name := t.Name()
		if builtIn[name] || !strings.HasSuffix(name, ".html") || strings.HasPrefix(name, "_") {
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

// RenderMarkdown converts markdown content to sanitized HTML.
// The output is sanitized with bluemonday to prevent XSS from untrusted
// markdown sources (e.g. external git repositories, rulebooks).
// Uses a strict policy that blocks dangerous elements while allowing
// safe formatting (bold, italic, links, tables, etc).
func RenderMarkdown(markdown []byte) (template.HTML, error) {
	md := goldmark.New(
		goldmark.WithExtensions(extension.Table),
	)
	var buf bytes.Buffer
	if err := md.Convert(markdown, &buf); err != nil {
		return "", fmt.Errorf("rendering markdown: %w", err)
	}
	sanitized := SanitizeHTML(buf.Bytes())
	return template.HTML(sanitized), nil
}

// SanitizeHTML applies strict sanitization to HTML content from untrusted sources.
// Blocks dangerous elements while preserving safe formatting:
// - Allowed: paragraphs, headings, bold, italic, links, tables, lists, code, blockquotes
// - Blocked: scripts, objects, embeds, SVGs, style tags, event handlers, javascript: URIs
// - Blocked: style attributes that could inject CSS
func SanitizeHTML(html []byte) []byte {
	p := newRulebookPolicy()
	return p.SanitizeBytes(html)
}

// newRulebookPolicy creates a strict bluemonday policy for credential rulebooks
// and other untrusted HTML/markdown content from external sources.
// This policy is more restrictive than UGCPolicy to prevent:
// - JavaScript execution via event handlers
// - CSS injection via style attributes
// - SVG/object attacks
// - Potentially dangerous HTML elements
func newRulebookPolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()

	// Allow safe structural elements
	p.AllowElements("p", "div", "br")
	p.AllowElements("h1", "h2", "h3", "h4", "h5", "h6")
	p.AllowElements("blockquote", "hr")

	// Allow text formatting
	p.AllowElements("strong", "em", "code", "pre", "sub", "sup", "mark")
	p.AllowElements("del", "ins")

	// Allow links (but not javascript: protocol)
	p.AllowElements("a")
	p.AllowAttrs("href").OnElements("a")
	p.AllowAttrs("title").OnElements("a")
	p.AllowAttrs("target").OnElements("a")
	p.AllowAttrs("rel").OnElements("a")

	// Allow lists
	p.AllowElements("ol", "ul", "li", "dl", "dt", "dd")

	// Allow tables
	p.AllowElements("table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "col", "colgroup")
	p.AllowAttrs("colspan", "rowspan", "scope").OnElements("th", "td")

	// Allow images (URL only, no inline SVG)
	p.AllowElements("img")
	p.AllowAttrs("src", "alt", "title", "width", "height").OnElements("img")

	// Explicitly block dangerous elements
	p.AllowNoAttrs().OnElements("table", "thead", "tbody", "tfoot", "tr")

	// Block potentially dangerous protocols in URLs (script: specific handling)
	p.AllowURLSchemes("http", "https", "ftp", "ftps", "mailto")

	// Don't allow any style attributes to prevent CSS injection
	// Don't allow event handlers (onclick, onerror, etc)
	// These are implicitly blocked by not calling AllowAttrs for them

	return p
}

// SanitizeSVG sanitizes inline SVG content to remove scripts and event handlers.
// Inline SVGs from credential metadata are processed separately to allow safe SVG
// display while blocking XSS attacks. Returns empty string if SVG contains dangerous
// content that cannot be safely sanitized.
func SanitizeSVG(svgContent []byte) template.HTML {
	// SVGs are complex and potentially dangerous. The safest approach is to:
	// 1. Block inline SVGs entirely in markdown/rulebooks (via policy above)
	// 2. Only allow SVG URIs (external files), not inline content
	// 3. For VCTM logos/backgrounds, only allow safe image URIs
	//
	// If inline SVG support is needed in future, use a dedicated SVG sanitization
	// library (e.g., github.com/RobotsAndPencils/go-svg) rather than general HTML sanitization.

	// For now, return empty to indicate SVG was blocked
	return ""
}

// ValidateCredentialImageURI checks if an image URI is safe for credential display.
// Only allows http/https URIs, blocks data: URIs and javascript: protocols.
func ValidateCredentialImageURI(uri string) bool {
	if uri == "" {
		return false
	}
	return strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://")
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
