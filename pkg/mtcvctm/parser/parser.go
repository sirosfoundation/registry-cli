// Package parser provides markdown parsing and VCTM generation
package parser

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
	"gopkg.in/yaml.v3"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/vctm"
)

// Parser parses markdown files and generates VCTM
type Parser struct {
	config *config.Config
	md     goldmark.Markdown
}

// NewParser creates a new parser with the given configuration
func NewParser(cfg *config.Config) *Parser {
	return &Parser{
		config: cfg,
		md:     goldmark.New(),
	}
}

// ParsedMarkdown represents the parsed structure from a markdown file
type ParsedMarkdown struct {
	// Title is extracted from the first H1 heading
	Title string

	// Description is extracted from the first paragraph after the title
	Description string

	// Sections contains content organized by section headings
	Sections map[string]string

	// Images contains paths to images found in the markdown
	Images []ImageRef

	// Claims contains claim definitions extracted from the markdown
	Claims map[string]ClaimDef

	// Metadata contains front matter or metadata extracted from the markdown
	Metadata map[string]string

	// DisplayLocalizations contains locale-specific display properties for the credential
	DisplayLocalizations map[string]DisplayLocalization
}

// DisplayLocalization contains localized display properties for the credential
type DisplayLocalization struct {
	// Name is the localized credential name
	Name string `yaml:"name"`

	// Description is the localized credential description
	Description string `yaml:"description"`
}

// ImageRef represents a reference to an image
type ImageRef struct {
	// Path is the original path in the markdown
	Path string

	// AltText is the alt text for the image
	AltText string

	// AbsolutePath is the resolved absolute path
	AbsolutePath string
}

// ClaimDef represents a claim definition
type ClaimDef struct {
	// Name is the claim name
	Name string

	// Type is the value type
	Type string

	// Description is the claim description
	Description string

	// Mandatory indicates if the claim is mandatory
	Mandatory bool

	// SD indicates selective disclosure
	SD string

	// SvgId is the ID for SVG template reference
	SvgId string

	// DisplayName is the friendly display label for the claim
	DisplayName string

	// Localizations contains locale-specific display names and descriptions
	Localizations map[string]ClaimLocalization
}

// ClaimLocalization contains localized display information for a claim
type ClaimLocalization struct {
	// Label is the display label in this locale
	Label string

	// Description is the description in this locale
	Description string
}

// Parse parses a markdown file and returns the parsed structure
func (p *Parser) Parse(inputPath string) (*ParsedMarkdown, error) {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return nil, fmt.Errorf("parser: failed to read file: %w", err)
	}

	return p.ParseContent(data, inputPath)
}

// ParseContent parses markdown content and returns the parsed structure
func (p *Parser) ParseContent(content []byte, basePath string) (*ParsedMarkdown, error) {
	reader := text.NewReader(content)
	doc := p.md.Parser().Parse(reader)

	parsed := &ParsedMarkdown{
		Sections: make(map[string]string),
		Images:   make([]ImageRef, 0),
		Claims:   make(map[string]ClaimDef),
		Metadata: make(map[string]string),
	}

	baseDir := filepath.Dir(basePath)

	// Extract front matter if present
	parsed.Metadata, parsed.DisplayLocalizations = extractFrontMatter(content)

	// Walk the AST to extract content
	var currentSection string
	var sectionContent bytes.Buffer

	err := ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}

		switch node := n.(type) {
		case *ast.Heading:
			// Save previous section content
			if currentSection != "" {
				parsed.Sections[currentSection] = strings.TrimSpace(sectionContent.String())
				sectionContent.Reset()
			}

			headingText := extractText(node, content)
			if node.Level == 1 && parsed.Title == "" {
				parsed.Title = headingText
				currentSection = "_title"
			} else {
				currentSection = headingText
			}

		case *ast.Paragraph:
			paragraphText := extractText(node, content)
			if currentSection == "_title" && parsed.Description == "" {
				parsed.Description = paragraphText
			} else {
				sectionContent.WriteString(paragraphText)
				sectionContent.WriteString("\n\n")
			}

		case *ast.Image:
			imgPath := string(node.Destination)
			altText := extractText(node, content)

			absPath := imgPath
			if !filepath.IsAbs(imgPath) && !strings.HasPrefix(imgPath, "http") {
				absPath = filepath.Join(baseDir, imgPath)
			}

			parsed.Images = append(parsed.Images, ImageRef{
				Path:         imgPath,
				AltText:      altText,
				AbsolutePath: absPath,
			})

		case *ast.List:
			// Handle lists specially to capture claim localizations
			parseClaimsList(node, content, parsed)
			return ast.WalkSkipChildren, nil
		}

		return ast.WalkContinue, nil
	})

	// Save last section
	if currentSection != "" && sectionContent.Len() > 0 {
		parsed.Sections[currentSection] = strings.TrimSpace(sectionContent.String())
	}

	if err != nil {
		return nil, fmt.Errorf("parser: failed to walk AST: %w", err)
	}

	return parsed, nil
}

// parseClaimsList parses a list to extract claims with potential localizations
func parseClaimsList(list *ast.List, content []byte, parsed *ParsedMarkdown) {
	for item := list.FirstChild(); item != nil; item = item.NextSibling() {
		listItem, ok := item.(*ast.ListItem)
		if !ok {
			continue
		}

		// Extract the first text content (the claim definition)
		var claimText string
		for child := listItem.FirstChild(); child != nil; child = child.NextSibling() {
			if para, ok := child.(*ast.Paragraph); ok {
				claimText = extractText(para, content)
				break
			} else if txt, ok := child.(*ast.TextBlock); ok {
				claimText = extractText(txt, content)
				break
			}
		}

		claim := parseClaimFromListItem(claimText)
		if claim == nil {
			continue
		}

		// Look for nested list with localizations
		for child := listItem.FirstChild(); child != nil; child = child.NextSibling() {
			if nestedList, ok := child.(*ast.List); ok {
				for nestedItem := nestedList.FirstChild(); nestedItem != nil; nestedItem = nestedItem.NextSibling() {
					if nestedListItem, ok := nestedItem.(*ast.ListItem); ok {
						locText := extractText(nestedListItem, content)
						if locale, loc, ok := parseLocalizationFromListItem(locText); ok {
							claim.Localizations[locale] = loc
						}
					}
				}
			}
		}

		parsed.Claims[claim.Name] = *claim
	}
}

// ToVCTM converts parsed markdown to a VCTM document
func (p *Parser) ToVCTM(parsed *ParsedMarkdown) (*vctm.VCTM, error) {
	v := &vctm.VCTM{
		VCT:         p.config.GetVCT(),
		Name:        parsed.Title,
		Description: parsed.Description,
	}

	// Add display properties
	if parsed.Title != "" || parsed.Description != "" {
		display := vctm.DisplayProperties{
			Locale:      p.config.Language,
			Name:        parsed.Title,
			Description: parsed.Description,
		}

		// Add rendering if there are images or colors
		rendering := p.buildRendering(parsed)
		if rendering != nil {
			display.Rendering = rendering
		}

		v.Display = []vctm.DisplayProperties{display}

		// Add localized display properties from front matter
		for locale, loc := range parsed.DisplayLocalizations {
			// Skip if this is the same as default locale (already added)
			if locale == p.config.Language {
				continue
			}
			localizedDisplay := vctm.DisplayProperties{
				Locale:      locale,
				Name:        loc.Name,
				Description: loc.Description,
			}
			v.Display = append(v.Display, localizedDisplay)
		}
	}

	// Add claims as array with path (draft 12 format)
	if len(parsed.Claims) > 0 {
		v.Claims = make([]vctm.ClaimMetadataEntry, 0, len(parsed.Claims))
		for name, claim := range parsed.Claims {
			entry := vctm.ClaimMetadataEntry{
				Path:      []interface{}{name},
				Mandatory: claim.Mandatory,
				SD:        claim.SD,
				SvgId:     claim.SvgId,
			}

			// Build display array with localizations
			var displays []vctm.ClaimDisplay

			// Add default locale display (from claim definition)
			if claim.Description != "" || claim.DisplayName != "" {
				defaultDisplay := vctm.ClaimDisplay{
					Locale:      p.config.Language,
					Description: claim.Description,
				}
				// Use display name if provided, otherwise fall back to claim name
				if claim.DisplayName != "" {
					defaultDisplay.Label = claim.DisplayName
				} else {
					defaultDisplay.Label = claim.Name
				}
				displays = append(displays, defaultDisplay)
			}

			// Add additional localizations from nested list items
			for locale, loc := range claim.Localizations {
				// Skip if this is the same as default locale (already added)
				if locale == p.config.Language {
					continue
				}
				display := vctm.ClaimDisplay{
					Locale:      locale,
					Label:       loc.Label,
					Description: loc.Description,
				}
				// If label is empty but we have one, use the display name
				if display.Label == "" && claim.DisplayName != "" {
					display.Label = claim.DisplayName
				}
				displays = append(displays, display)
			}

			if len(displays) > 0 {
				entry.Display = displays
			}

			v.Claims = append(v.Claims, entry)
		}
	}

	// Override VCT from metadata if present
	if vctVal, ok := parsed.Metadata["vct"]; ok {
		v.VCT = vctVal
	}

	// Override from extends metadata (now single URI in draft 12)
	if extends, ok := parsed.Metadata["extends"]; ok {
		v.Extends = strings.TrimSpace(extends)
	}
	if extendsIntegrity, ok := parsed.Metadata["extends#integrity"]; ok {
		v.ExtendsIntegrity = strings.TrimSpace(extendsIntegrity)
	}

	return v, nil
}

// imageToLogo converts an ImageRef to a Logo with URL and integrity
func (p *Parser) imageToLogo(img ImageRef) *vctm.Logo {
	logo := &vctm.Logo{
		AltText: img.AltText,
	}

	// If inline images is enabled, convert to data URL
	if p.config.InlineImages {
		if dataURL, err := p.imageToDataURL(img.AbsolutePath); err == nil {
			logo.URI = dataURL
			// No integrity needed for inline data URLs
			return logo
		}
		// Fall through to URL-based approach on error
	}

	if p.config.BaseURL != "" {
		logo.URI = p.buildImageURL(img.Path)
		if integrity, err := p.calculateIntegrity(img.AbsolutePath); err == nil {
			logo.URIIntegrity = integrity
		}
	} else {
		logo.URI = img.Path
	}

	return logo
}

// imageToDataURL reads an image file and converts it to a base64 data URL
func (p *Parser) imageToDataURL(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	mimeType := getMimeType(path)
	encoded := base64.StdEncoding.EncodeToString(data)
	return fmt.Sprintf("data:%s;base64,%s", mimeType, encoded), nil
}

// getMimeType returns the MIME type for an image file based on extension
func getMimeType(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

// buildImageURL builds a full URL for an image
func (p *Parser) buildImageURL(path string) string {
	baseURL := strings.TrimSuffix(p.config.BaseURL, "/")
	path = strings.TrimPrefix(path, "./")
	return baseURL + "/" + path
}

// calculateIntegrity calculates SRI integrity hash for a file
func (p *Parser) calculateIntegrity(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return "sha256-" + base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

// buildRendering builds rendering information from parsed markdown
func (p *Parser) buildRendering(parsed *ParsedMarkdown) *vctm.Rendering {
	// Skip rendering if no base URL configured
	if p.config.BaseURL == "" && len(parsed.Images) > 0 {
		return nil
	}

	rendering := &vctm.Rendering{}
	hasContent := false

	// Build simple rendering
	simple := &vctm.SimpleRendering{}

	// First image as logo
	if len(parsed.Images) > 0 {
		simple.Logo = p.imageToLogo(parsed.Images[0])
		hasContent = true
	}

	// Extract colors from metadata
	if bg, ok := parsed.Metadata["background_color"]; ok {
		simple.BackgroundColor = strings.Trim(bg, "\"")
		hasContent = true
	}
	if tc, ok := parsed.Metadata["text_color"]; ok {
		simple.TextColor = strings.Trim(tc, "\"")
		hasContent = true
	}

	// Check for background image in metadata
	if bgImg, ok := parsed.Metadata["background_image"]; ok {
		simple.BackgroundImage = &vctm.BackgroundImage{
			URI: strings.Trim(bgImg, "\""),
		}
		hasContent = true
	}

	if hasContent {
		rendering.Simple = simple
	}

	// SVG templates
	var svgTemplates []vctm.SVGTemplate
	for _, img := range parsed.Images {
		if strings.HasSuffix(strings.ToLower(img.Path), ".svg") {
			var tmpl vctm.SVGTemplate

			// If inline images is enabled, convert to data URL
			if p.config.InlineImages {
				if dataURL, err := p.imageToDataURL(img.AbsolutePath); err == nil {
					tmpl.URI = dataURL
					// No integrity needed for inline data URLs
					svgTemplates = append(svgTemplates, tmpl)
					continue
				}
				// Fall through to URL-based approach on error
			}

			tmpl.URI = p.buildImageURL(img.Path)
			if integrity, err := p.calculateIntegrity(img.AbsolutePath); err == nil {
				tmpl.URIIntegrity = integrity
			}
			svgTemplates = append(svgTemplates, tmpl)
		}
	}

	if len(svgTemplates) > 0 {
		rendering.SVGTemplates = svgTemplates
	}

	// Return nil if no rendering content
	if rendering.Simple == nil && len(rendering.SVGTemplates) == 0 {
		return nil
	}

	return rendering
}

// extractText extracts text content from an AST node
func extractText(node ast.Node, source []byte) string {
	var buf bytes.Buffer
	for c := node.FirstChild(); c != nil; c = c.NextSibling() {
		if t, ok := c.(*ast.Text); ok {
			buf.Write(t.Segment.Value(source))
			if t.HardLineBreak() || t.SoftLineBreak() {
				buf.WriteString(" ")
			}
		} else if cs, ok := c.(*ast.CodeSpan); ok {
			// Preserve code spans with backticks for claim parsing
			buf.WriteString("`")
			for seg := cs.FirstChild(); seg != nil; seg = seg.NextSibling() {
				if t, ok := seg.(*ast.Text); ok {
					buf.Write(t.Segment.Value(source))
				}
			}
			buf.WriteString("`")
		} else {
			buf.WriteString(extractText(c, source))
		}
	}
	return strings.TrimSpace(buf.String())
}

// frontMatterData represents the YAML front matter structure
type frontMatterData struct {
	Display map[string]DisplayLocalization `yaml:"display"`
}

// extractFrontMatter extracts YAML front matter from markdown
func extractFrontMatter(content []byte) (map[string]string, map[string]DisplayLocalization) {
	metadata := make(map[string]string)
	displayLocs := make(map[string]DisplayLocalization)

	// Check for YAML front matter (--- ... ---)
	if !bytes.HasPrefix(content, []byte("---")) {
		return metadata, displayLocs
	}

	endIndex := bytes.Index(content[3:], []byte("---"))
	if endIndex == -1 {
		return metadata, displayLocs
	}

	frontMatter := content[3 : endIndex+3]

	// First, parse nested structures like display localizations
	var fmData frontMatterData
	if err := yaml.Unmarshal(frontMatter, &fmData); err == nil && fmData.Display != nil {
		displayLocs = fmData.Display
	}

	// Parse as generic map to extract flat string values
	var genericMap map[string]interface{}
	if err := yaml.Unmarshal(frontMatter, &genericMap); err == nil {
		for key, value := range genericMap {
			// Only include string values (skip nested structures like display)
			if strVal, ok := value.(string); ok {
				metadata[key] = strVal
			}
		}
	}

	return metadata, displayLocs
}

// parseClaimFromListItem parses a claim definition from a list item
// Expected formats:
//   - `claim_name` (type): Description [mandatory] [sd=always|never]
//   - `claim_name` "Display Name" (type): Description [mandatory] [sd=always|never]
//
// For localized claims (sub-list items under a claim):
//   - en-US: "Display Name" - Description
//   - de-DE: "Anzeigename" - Beschreibung
var claimPattern = regexp.MustCompile("^`([^`]+)`\\s*(?:\"([^\"]+)\")?\\s*(?:\\(([^)]+)\\))?:?\\s*(.*)$")

// localePattern requires a colon after the locale code and either a quoted label or a dash with description
var localePattern = regexp.MustCompile("^([a-zA-Z]{2,3}(?:-[a-zA-Z]{2,4})?):\\s*(?:\"([^\"]+)\")?\\s*(?:-\\s*)?(.*)$")

func parseClaimFromListItem(text string) *ClaimDef {
	matches := claimPattern.FindStringSubmatch(text)
	if matches == nil {
		return nil
	}

	claim := &ClaimDef{
		Name:          matches[1],
		DisplayName:   matches[2],
		Type:          matches[3],
		Description:   matches[4],
		Localizations: make(map[string]ClaimLocalization),
	}

	if claim.Type == "" {
		claim.Type = "string"
	}

	// Parse and strip all flags from description
	// Flags can appear as [flag1, flag2, ...] or individually as [flag]
	desc := claim.Description

	// Pattern to match bracketed flag groups: [mandatory, svg_id=foo, sd=always]
	bracketPattern := regexp.MustCompile(`\[([^\]]+)\]`)
	bracketMatches := bracketPattern.FindAllStringSubmatch(desc, -1)

	for _, match := range bracketMatches {
		flagContent := match[1]
		flags := strings.Split(flagContent, ",")

		for _, flag := range flags {
			flag = strings.TrimSpace(flag)
			flagLower := strings.ToLower(flag)

			if flagLower == "mandatory" {
				claim.Mandatory = true
			} else if strings.HasPrefix(flagLower, "sd=") {
				claim.SD = strings.TrimPrefix(flagLower, "sd=")
			} else if strings.HasPrefix(flagLower, "svg_id=") {
				claim.SvgId = strings.TrimPrefix(flag, "svg_id=")
			}
		}
	}

	// Remove all bracketed flag groups from description
	desc = bracketPattern.ReplaceAllString(desc, "")

	// Also handle parenthetical flags like (mandatory)
	parenPattern := regexp.MustCompile(`\(mandatory\)`)
	if parenPattern.MatchString(strings.ToLower(desc)) {
		claim.Mandatory = true
		desc = regexp.MustCompile(`(?i)\(mandatory\)`).ReplaceAllString(desc, "")
	}

	claim.Description = strings.TrimSpace(desc)

	return claim
}

// parseLocalizationFromListItem parses localization from a sub-list item
// Expected format: locale: "Label" - Description
// e.g., en-US: "Given Name" - The given name
func parseLocalizationFromListItem(text string) (locale string, loc ClaimLocalization, ok bool) {
	matches := localePattern.FindStringSubmatch(text)
	if matches == nil {
		return "", ClaimLocalization{}, false
	}

	return matches[1], ClaimLocalization{
		Label:       matches[2],
		Description: strings.TrimSpace(matches[3]),
	}, true
}

// CalculateIntegrity is a public helper to calculate SRI integrity for a file
func CalculateIntegrity(path string) (string, error) {
	p := &Parser{}
	return p.calculateIntegrity(path)
}
