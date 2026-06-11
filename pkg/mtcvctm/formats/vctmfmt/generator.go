// Package vctmfmt provides the VCTM format generator for SD-JWT VC credentials
package vctmfmt

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
)

func init() {
	formats.Register(&Generator{})
}

// Generator implements the VCTM format (SD-JWT VC Type Metadata)
type Generator struct{}

func (g *Generator) Name() string {
	return "vctm"
}

func (g *Generator) Description() string {
	return "SD-JWT VC Type Metadata (draft-ietf-oauth-sd-jwt-vc)"
}

func (g *Generator) FileExtension() string {
	return "vctm.json"
}

func (g *Generator) DeriveIdentifier(parsed *formats.ParsedCredential, cfg *config.Config) string {
	// VCTM uses the VCT field
	if parsed.VCT != "" {
		return parsed.VCT
	}
	// Fallback to ID
	return parsed.ID
}

// Generate produces VCTM JSON for SD-JWT VC credentials
func (g *Generator) Generate(parsed *formats.ParsedCredential, cfg *config.Config) ([]byte, error) {
	output := make(map[string]interface{})

	// Required: vct - use VCT field, fallback to ID
	vct := parsed.VCT
	if vct == "" {
		vct = parsed.ID
	}
	output["vct"] = vct

	// Required: name (must not be empty)
	if parsed.Name == "" {
		return nil, fmt.Errorf("vctm: name is required and must not be empty")
	}
	output["name"] = parsed.Name

	// Optional: description
	if parsed.Description != "" {
		output["description"] = parsed.Description
	}

	// Handle optional fields from metadata
	if v, ok := parsed.Metadata["extends"]; ok {
		output["extends"] = v
	}
	if v, ok := parsed.Metadata["extends#integrity"]; ok {
		output["extends#integrity"] = v
	}
	if v, ok := parsed.Metadata["schema_uri"]; ok {
		output["schema_uri"] = v
	}
	if v, ok := parsed.Metadata["schema_uri#integrity"]; ok {
		output["schema_uri#integrity"] = v
	}

	// Build claims from claim definitions
	if len(parsed.Claims) > 0 {
		claims := make([]map[string]interface{}, 0, len(parsed.Claims))
		for _, claim := range parsed.Claims {
			claimEntry := make(map[string]interface{})
			claimEntry["path"] = claim.Path
			if claim.DisplayName != "" {
				claimEntry["display"] = []map[string]string{
					{"locale": "en-US", "label": claim.DisplayName},
				}
			}
			if claim.Description != "" {
				claimEntry["description"] = claim.Description
			}
			if claim.Mandatory {
				claimEntry["mandatory"] = true
			}
			if claim.SD != "" {
				claimEntry["sd"] = claim.SD
			}
			if claim.SvgId != "" {
				claimEntry["svg_id"] = claim.SvgId
			}
			claims = append(claims, claimEntry)
		}
		output["claims"] = claims
	}

	// Build display with rendering section
	display := make(map[string]interface{})
	rendering := make(map[string]interface{})

	// Collect SVG templates from images and explicit configuration
	svgTemplates := make([]map[string]interface{}, 0)

	// First, add explicit SVG template from metadata
	if parsed.SVGTemplatePath != "" || parsed.SVGTemplateURI != "" {
		template, err := g.buildSVGTemplate(parsed.SVGTemplateURI, parsed.SVGTemplatePath, parsed.SVGTemplateIntegrity, parsed.SourceDir, parsed.InlineImages, cfg)
		if err == nil && template != nil {
			svgTemplates = append(svgTemplates, template)
		}
	}

	// Process images from markdown
	var logoImage *formats.ImageRef
	for i := range parsed.Images {
		img := &parsed.Images[i]
		if strings.HasSuffix(strings.ToLower(img.Path), ".svg") {
			// SVG files become svg_templates
			template, err := g.buildSVGTemplateFromImage(img, parsed.SourceDir, parsed.InlineImages, cfg)
			if err == nil && template != nil {
				svgTemplates = append(svgTemplates, template)
			}
		} else if logoImage == nil {
			// First non-SVG image becomes the logo
			logoImage = img
		}
	}

	// Add svg_templates if any
	if len(svgTemplates) > 0 {
		rendering["svg_templates"] = svgTemplates
	}

	// Handle simple rendering properties
	simple := make(map[string]interface{})

	// Logo handling - prefer explicit logo, then first non-SVG image
	if parsed.LogoPath != "" {
		logo, err := g.imageToLogo(parsed.LogoPath, parsed.LogoAltText, parsed.SourceDir, parsed.InlineImages, cfg)
		if err == nil && logo != nil {
			simple["logo"] = logo
		}
	} else if logoImage != nil {
		logo, err := g.imageToLogo(logoImage.Path, logoImage.AltText, parsed.SourceDir, parsed.InlineImages, cfg)
		if err == nil && logo != nil {
			simple["logo"] = logo
		}
	}

	// Background/text colors
	if parsed.BackgroundColor != "" {
		simple["background_color"] = parsed.BackgroundColor
	}
	if parsed.TextColor != "" {
		simple["text_color"] = parsed.TextColor
	}

	if len(simple) > 0 {
		rendering["simple"] = simple
	}

	if len(rendering) > 0 {
		display["rendering"] = rendering
	}

	// Add locale to display (REQUIRED per spec)
	display["locale"] = cfg.Language

	// Add name to display (REQUIRED per spec)
	display["name"] = parsed.Name

	// Always include display array since locale and name are required
	output["display"] = []map[string]interface{}{display}

	return formats.FormatJSON(output)
}

// buildSVGTemplate creates an SVG template entry from explicit configuration
func (g *Generator) buildSVGTemplate(uri, path, integrity, sourceDir string, inline bool, cfg *config.Config) (map[string]interface{}, error) {
	template := make(map[string]interface{})

	if uri != "" {
		template["uri"] = uri
	} else if path != "" {
		// Build URL or inline
		svgPath := path
		if !filepath.IsAbs(svgPath) {
			svgPath = filepath.Join(sourceDir, svgPath)
		}

		if inline {
			data, err := os.ReadFile(svgPath)
			if err != nil {
				return nil, err
			}
			template["uri"] = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(data)
		} else if cfg.BaseURL != "" {
			template["uri"] = cfg.BaseURL + "/" + path
		}
	}

	if integrity != "" {
		template["uri#integrity"] = integrity
	}

	if len(template) == 0 {
		return nil, nil
	}

	return template, nil
}

// buildSVGTemplateFromImage creates an SVG template entry from an image reference
func (g *Generator) buildSVGTemplateFromImage(img *formats.ImageRef, sourceDir string, inline bool, cfg *config.Config) (map[string]interface{}, error) {
	template := make(map[string]interface{})

	imagePath := img.Path
	if img.AbsolutePath != "" {
		imagePath = img.AbsolutePath
	} else if !filepath.IsAbs(imagePath) {
		imagePath = filepath.Join(sourceDir, imagePath)
	}

	if inline {
		data, err := os.ReadFile(imagePath)
		if err != nil {
			return nil, err
		}
		template["uri"] = "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(data)
	} else if cfg.BaseURL != "" {
		template["uri"] = cfg.BaseURL + "/" + img.Path
	}

	if len(template) == 0 {
		return nil, nil
	}

	return template, nil
}

// imageToLogo converts an image path to a logo object
func (g *Generator) imageToLogo(path, altText, sourceDir string, inline bool, cfg *config.Config) (map[string]interface{}, error) {
	logo := make(map[string]interface{})

	if path != "" {
		imagePath := path
		if !filepath.IsAbs(imagePath) {
			imagePath = filepath.Join(sourceDir, imagePath)
		}

		if inline {
			// Read and inline the image
			data, err := os.ReadFile(imagePath)
			if err != nil {
				return nil, err
			}
			mimeType := http.DetectContentType(data)
			// Handle SVG which DetectContentType doesn't detect well
			if strings.HasSuffix(strings.ToLower(path), ".svg") {
				mimeType = "image/svg+xml"
			}
			logo["uri"] = fmt.Sprintf("data:%s;base64,%s", mimeType, base64.StdEncoding.EncodeToString(data))
		} else if cfg.BaseURL != "" {
			logo["uri"] = cfg.BaseURL + "/" + path
		}
	}

	if altText != "" {
		logo["alt_text"] = altText
	}

	if len(logo) == 0 {
		return nil, nil
	}

	return logo, nil
}
