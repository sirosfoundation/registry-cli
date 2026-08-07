package rulebookcatalog

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// jsonSchema represents the subset of JSON Schema 2020-12 we need to parse
// from EUDI-style credential validation schemas.
type jsonSchema struct {
	Schema      string                  `json:"$schema"`
	ID          string                  `json:"$id"`
	Title       string                  `json:"title"`
	Description string                  `json:"description"`
	Type        string                  `json:"type"`
	Version     string                  `json:"version"`
	Properties  map[string]*propertyDef `json:"properties"`
	Required    []string                `json:"required"`
	Defs        map[string]*jsonSchema  `json:"$defs"`
}

// propertyDef represents a property definition within a JSON Schema.
type propertyDef struct {
	Type        string                  `json:"type"`
	Const       interface{}             `json:"const"`
	Enum        []interface{}           `json:"enum"`
	Description string                  `json:"description"`
	Format      string                  `json:"format"`
	Examples    []interface{}           `json:"examples"`
	Properties  map[string]*propertyDef `json:"properties"`
	Items       *propertyDef            `json:"items"`
	Required    []string                `json:"required"`
}

// vctmOutput is the VCTM JSON structure per draft-ietf-oauth-sd-jwt-vc §6.
type vctmOutput struct {
	VCT         string        `json:"vct"`
	Name        string        `json:"name,omitempty"`
	Description string        `json:"description,omitempty"`
	Display     []vctmDisplay `json:"display,omitempty"`
	Claims      []vctmClaim   `json:"claims,omitempty"`
}

type vctmDisplay struct {
	Locale      string         `json:"locale"`
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Rendering   *vctmRendering `json:"rendering,omitempty"`
}

type vctmRendering struct {
	Simple       *vctmSimple       `json:"simple,omitempty"`
	SVGTemplates []vctmSVGTemplate `json:"svg_templates,omitempty"`
}

type vctmSimple struct {
	Logo            *vctmImage `json:"logo,omitempty"`
	BackgroundColor string     `json:"background_color,omitempty"`
	TextColor       string     `json:"text_color,omitempty"`
}

type vctmImage struct {
	URI     string `json:"uri"`
	AltText string `json:"alt_text,omitempty"`
}

type vctmSVGTemplate struct {
	URI        string             `json:"uri"`
	Properties *vctmTemplateProps `json:"properties,omitempty"`
}

type vctmTemplateProps struct {
	Orientation string `json:"orientation,omitempty"`
	ColorScheme string `json:"color_scheme,omitempty"`
}

type vctmClaim struct {
	Path        []interface{}  `json:"path"`
	Display     []claimDisplay `json:"display,omitempty"`
	Description string         `json:"description,omitempty"`
	Mandatory   bool           `json:"mandatory,omitempty"`
	SD          string         `json:"sd,omitempty"`
}

type claimDisplay struct {
	Locale string `json:"locale"`
	Label  string `json:"label"`
}

// infrastructureClaims are standard JWT/SD-JWT claims that should not appear
// in the VCTM claims list (they're infrastructure, not credential content).
var infrastructureClaims = map[string]bool{
	"vct":    true,
	"iss":    true,
	"sub":    true,
	"iat":    true,
	"exp":    true,
	"nbf":    true,
	"jti":    true,
	"cnf":    true,
	"status": true,
}

// sdPattern matches descriptions indicating selective disclosure.
var sdPattern = regexp.MustCompile(`(?i)(MUST be selectively disclos|selectively disclosable|SD claim)`)

// convertJSONSchemaToVCTM reads a JSON Schema file and produces VCTM JSON bytes.
// assets maps discovered asset keys to their registry URLs (already resolved).
func convertJSONSchemaToVCTM(schemaPath, slug, baseURL, org string, assets map[string]string) ([]byte, error) {
	data, err := os.ReadFile(schemaPath)
	if err != nil {
		return nil, fmt.Errorf("reading schema file: %w", err)
	}

	var schema jsonSchema
	if err = json.Unmarshal(data, &schema); err != nil {
		return nil, fmt.Errorf("parsing JSON Schema: %w", err)
	}

	// Extract VCT
	vct := extractVCT(&schema)
	if vct == "" {
		return nil, fmt.Errorf("no vct value found in schema %s", schemaPath)
	}

	// Build required set for mandatory detection
	requiredSet := make(map[string]bool)
	for _, r := range schema.Required {
		requiredSet[r] = true
	}

	// Build claims from properties
	var claims []vctmClaim
	for propName, propDef := range schema.Properties {
		if infrastructureClaims[propName] {
			continue
		}

		claim := vctmClaim{
			Path: []interface{}{propName},
			Display: []claimDisplay{
				{Locale: "en-US", Label: slugToLabel(propName)},
			},
		}

		if propDef.Description != "" {
			claim.Description = propDef.Description
		}

		// Mandatory if in required array
		if requiredSet[propName] {
			claim.Mandatory = true
		}

		// Detect selective disclosure from description
		if propDef.Description != "" && sdPattern.MatchString(propDef.Description) {
			claim.SD = "always"
		}

		// Handle nested objects — add child claims
		if propDef.Type == "object" && propDef.Properties != nil {
			for childName, childDef := range propDef.Properties {
				childClaim := vctmClaim{
					Path: []interface{}{propName, childName},
					Display: []claimDisplay{
						{Locale: "en-US", Label: slugToLabel(childName)},
					},
				}
				if childDef.Description != "" {
					childClaim.Description = childDef.Description
				}
				if childDef.Description != "" && sdPattern.MatchString(childDef.Description) {
					childClaim.SD = "always"
				}
				claims = append(claims, childClaim)
			}
		}

		claims = append(claims, claim)
	}

	// Derive name from title
	name := schema.Title
	if name == "" {
		name = slugToLabel(slug)
	}

	output := vctmOutput{
		VCT:         vct,
		Name:        name,
		Description: schema.Description,
		Display: []vctmDisplay{
			{
				Locale:      "en-US",
				Name:        cleanDisplayName(name),
				Description: schema.Description,
				Rendering:   buildRendering(assets),
			},
		},
		Claims: claims,
	}

	result, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshaling VCTM: %w", err)
	}

	return result, nil
}

// extractVCT gets the VCT identifier from the schema's vct property.
func extractVCT(schema *jsonSchema) string {
	prop, ok := schema.Properties["vct"]
	if !ok {
		return ""
	}

	// Try const value first
	if prop.Const != nil {
		if s, ok := prop.Const.(string); ok {
			return s
		}
	}

	// Try examples
	if len(prop.Examples) > 0 {
		if s, ok := prop.Examples[0].(string); ok {
			return s
		}
	}

	// Try enum
	if len(prop.Enum) > 0 {
		if s, ok := prop.Enum[0].(string); ok {
			return s
		}
	}

	return ""
}

// slugToLabel converts snake_case or kebab-case to a display label.
// "given_name" → "Given Name", "birth-date" → "Birth Date"
func slugToLabel(s string) string {
	// Replace separators with spaces
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.ReplaceAll(s, "-", " ")

	// Title case
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// cleanDisplayName strips technical prefixes from schema titles for display.
// "ds002 - Person Identification Data (PID) – SD-JWT VC payload" → "Person Identification Data (PID)"
func cleanDisplayName(title string) string {
	// Strip "dsNNN - " prefix
	if idx := strings.Index(title, " - "); idx != -1 && idx < 10 {
		title = title[idx+3:]
	}

	// Strip trailing format indicators
	for _, suffix := range []string{" – SD-JWT VC payload", " SD-JWT VC payload", " - SD-JWT VC Schema"} {
		title = strings.TrimSuffix(title, suffix)
	}

	// Also handle " SD-JWT VC Schema" pattern
	if idx := strings.Index(title, " SD-JWT VC"); idx != -1 {
		title = title[:idx]
	}

	return strings.TrimSpace(title)
}

// buildRendering constructs VCTM rendering from discovered assets.
// Returns nil if no assets are available.
func buildRendering(assets map[string]string) *vctmRendering {
	if len(assets) == 0 {
		return nil
	}

	rendering := &vctmRendering{}

	// SVG templates
	if uri, ok := assets["svg_template"]; ok {
		tmpl := vctmSVGTemplate{
			URI:        uri,
			Properties: &vctmTemplateProps{Orientation: "landscape", ColorScheme: "light"},
		}
		rendering.SVGTemplates = append(rendering.SVGTemplates, tmpl)
	}
	if uri, ok := assets["svg_template_dark"]; ok {
		tmpl := vctmSVGTemplate{
			URI:        uri,
			Properties: &vctmTemplateProps{Orientation: "landscape", ColorScheme: "dark"},
		}
		rendering.SVGTemplates = append(rendering.SVGTemplates, tmpl)
	}

	// Logo for simple rendering
	if uri, ok := assets["logo"]; ok {
		rendering.Simple = &vctmSimple{
			Logo: &vctmImage{URI: uri},
		}
	}

	if rendering.Simple == nil && len(rendering.SVGTemplates) == 0 {
		return nil
	}
	return rendering
}
