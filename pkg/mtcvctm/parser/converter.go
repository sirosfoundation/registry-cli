package parser

import (
	"path/filepath"
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
)

// ToCredential converts ParsedMarkdown to the format-agnostic ParsedCredential
func (p *Parser) ToCredential(parsed *ParsedMarkdown) *formats.ParsedCredential {
	cred := &formats.ParsedCredential{
		Name:            parsed.Title,
		Description:     parsed.Description,
		Localizations:   make(map[string]formats.DisplayLocalization),
		Claims:          make([]formats.ClaimDefinition, 0, len(parsed.Claims)),
		Images:          make([]formats.ImageRef, 0, len(parsed.Images)),
		FormatOverrides: make(map[string]map[string]interface{}),
		ClaimMappings:   make(map[string]map[string]string),
		Metadata:        make(map[string]interface{}),
		InlineImages:    p.config.InlineImages,
	}

	// Set source path info
	if p.config.InputFile != "" {
		cred.SourcePath = p.config.InputFile
		cred.SourceDir = filepath.Dir(p.config.InputFile)

		// Derive ID from input file if not specified
		base := filepath.Base(p.config.InputFile)
		ext := filepath.Ext(base)
		cred.ID = strings.TrimSuffix(base, ext)
	}

	// Extract metadata
	for k, v := range parsed.Metadata {
		cred.Metadata[k] = v

		// Handle known fields
		switch k {
		case "id":
			cred.ID = v
		case "vct":
			cred.VCT = v
		case "doctype":
			cred.DocType = v
		case "namespace":
			cred.Namespace = v
		case "formats":
			cred.Formats = v
		case "background_color":
			cred.BackgroundColor = strings.Trim(v, "\"")
		case "text_color":
			cred.TextColor = strings.Trim(v, "\"")
		case "logo":
			cred.LogoPath = strings.Trim(v, "\"")
		case "svg_template":
			cred.SVGTemplatePath = strings.Trim(v, "\"")
		case "svg_template_uri":
			cred.SVGTemplateURI = strings.Trim(v, "\"")
		case "svg_template_integrity":
			cred.SVGTemplateIntegrity = strings.Trim(v, "\"")
		}
	}

	// Handle display localizations
	for locale, loc := range parsed.DisplayLocalizations {
		cred.Localizations[locale] = formats.DisplayLocalization{
			Name:        loc.Name,
			Description: loc.Description,
		}
	}

	// Convert claims
	for name, claim := range parsed.Claims {
		claimDef := formats.ClaimDefinition{
			Name:           name,
			DisplayName:    claim.DisplayName,
			Type:           claim.Type,
			Description:    claim.Description,
			Mandatory:      claim.Mandatory,
			SD:             claim.SD,
			SvgId:          claim.SvgId,
			Localizations:  make(map[string]formats.ClaimLocalization),
			FormatMappings: make(map[string]string),
		}

		// Build path from name
		parts := strings.Split(name, ".")
		claimDef.Path = parts

		// Convert localizations
		for locale, loc := range claim.Localizations {
			claimDef.Localizations[locale] = formats.ClaimLocalization{
				Label:       loc.Label,
				Description: loc.Description,
			}
		}


		// Convert children recursively
		if len(claim.Children) > 0 {
			claimDef.Children = convertChildren(claim.Children, parts)
		}
		cred.Claims = append(cred.Claims, claimDef)
	}

	// Convert images
	for _, img := range parsed.Images {
		cred.Images = append(cred.Images, formats.ImageRef{
			Path:         img.Path,
			AltText:      img.AltText,
			AbsolutePath: img.AbsolutePath,
		})
	}

	// If we have a logo path but no absolute path, try to resolve it
	if cred.LogoPath != "" && cred.LogoAbsPath == "" && p.config.InputFile != "" {
		baseDir := filepath.Dir(p.config.InputFile)
		cred.LogoAbsPath = filepath.Join(baseDir, cred.LogoPath)
	}

	return cred
}

// ParseToCredential parses a markdown file and returns a ParsedCredential
func (p *Parser) ParseToCredential(inputPath string) (*formats.ParsedCredential, error) {
	parsed, err := p.Parse(inputPath)
	if err != nil {
		return nil, err
	}
	return p.ToCredential(parsed), nil
}

// ParseContentToCredential parses markdown content and returns a ParsedCredential
func (p *Parser) ParseContentToCredential(content []byte, basePath string) (*formats.ParsedCredential, error) {
	parsed, err := p.ParseContent(content, basePath)
	if err != nil {
		return nil, err
	}
	return p.ToCredential(parsed), nil
}

// Generate generates output for the specified formats
func (p *Parser) Generate(cred *formats.ParsedCredential, formatNames []string) (map[string][]byte, error) {
	results := make(map[string][]byte)

	for _, name := range formatNames {
		gen, ok := formats.Get(name)
		if !ok {
			continue // Skip unknown formats
		}

		output, err := gen.Generate(cred, p.config)
		if err != nil {
			return nil, err
		}

		results[name] = output
	}

	return results, nil
}

// GenerateAll generates output for all registered formats
func (p *Parser) GenerateAll(cred *formats.ParsedCredential) (map[string][]byte, error) {
	return p.Generate(cred, formats.List())
}

// OutputFileName returns the output filename for a given format
func OutputFileName(baseName, formatName string) string {
	gen, ok := formats.Get(formatName)
	if !ok {
		return baseName + "." + formatName
	}
	return baseName + "." + gen.FileExtension()
}

// convertChildren recursively converts parser ClaimDefs to format ClaimDefinitions,
// building full paths from the parent path.
func convertChildren(children []ClaimDef, parentPath []string) []formats.ClaimDefinition {
	result := make([]formats.ClaimDefinition, 0, len(children))
	for _, child := range children {
		childPath := append(append([]string{}, parentPath...), strings.Split(child.Name, ".")...)
		childDef := formats.ClaimDefinition{
			Name:           child.Name,
			Path:           childPath,
			DisplayName:    child.DisplayName,
			Type:           child.Type,
			Description:    child.Description,
			Mandatory:      child.Mandatory,
			SD:             child.SD,
			SvgId:          child.SvgId,
			Localizations:  make(map[string]formats.ClaimLocalization),
			FormatMappings: make(map[string]string),
		}
		for locale, loc := range child.Localizations {
			childDef.Localizations[locale] = formats.ClaimLocalization{
				Label:       loc.Label,
				Description: loc.Description,
			}
		}
		if len(child.Children) > 0 {
			childDef.Children = convertChildren(child.Children, childPath)
		}
		result = append(result, childDef)
	}
	return result
}
