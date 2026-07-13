// Package rulebookcatalog implements the repo plugin for EUDI-style attestation
// rulebook catalog repositories (e.g., webuild-attestation-rulebooks-catalog).
//
// These repositories organize credential data as:
//
//	data-schemas/sd-jwt/<name>-sd-jwt.json   (JSON Schema 2020-12 validation)
//	data-schemas/mdoc/<name>-mdoc.json       (mDOC validation schema)
//	rulebooks/rb-<slug>/README.md            (governance document)
//
// This plugin converts JSON Schema validation definitions into VCTM format
// and maps the directory structure to the registry pipeline's expectations.
package rulebookcatalog

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/repoplugin"
	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

func init() {
	repoplugin.Register(&RulebookCatalog{})
}

// RulebookCatalog handles EUDI ARF-style rulebook catalog repositories.
type RulebookCatalog struct{}

func (r *RulebookCatalog) Name() string { return "rulebook-catalog" }

func (r *RulebookCatalog) Description() string {
	return "EUDI-style catalog: data-schemas/{sd-jwt,mdoc}/ + rulebooks/rb-<slug>/"
}

func (r *RulebookCatalog) Discover(ctx repoplugin.Context) ([]repoplugin.DiscoveredCredential, error) {
	logger := ctx.Logger

	repoDir := ctx.RepoDir
	if ctx.SubPath != "" {
		repoDir = filepath.Join(repoDir, ctx.SubPath)
	}

	// Discover SD-JWT schemas
	sdJWTDir := filepath.Join(repoDir, "data-schemas", "sd-jwt")
	mdocDir := filepath.Join(repoDir, "data-schemas", "mdoc")
	rulebooksDir := filepath.Join(repoDir, "rulebooks")

	// Walk SD-JWT schemas as primary credential discovery
	entries, err := os.ReadDir(sdJWTDir)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info("no data-schemas/sd-jwt directory found, skipping")
			return nil, nil
		}
		return nil, fmt.Errorf("reading sd-jwt schema dir: %w", err)
	}

	var results []repoplugin.DiscoveredCredential

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), "-sd-jwt.json") {
			continue
		}

		filename := entry.Name()
		rawSlug := strings.TrimSuffix(filename, "-sd-jwt.json")
		slug := normalizeSlug(rawSlug)

		schemaPath := filepath.Join(sdJWTDir, filename)

		// Discover visual assets (SVG templates, logos)
		assets, assetFiles := discoverAssets(repoDir, sdJWTDir, slug, rawSlug, ctx.BaseURL, ctx.Organization)

		// Parse JSON Schema and convert to VCTM (including asset references)
		vctmJSON, err := convertJSONSchemaToVCTM(schemaPath, slug, ctx.BaseURL, ctx.Organization, assets)
		if err != nil {
			logger.Warn("skipping credential: JSON Schema conversion failed",
				"file", filename, "slug", slug, "error", err)
			continue
		}

		cred := repoplugin.DiscoveredCredential{
			Org:           ctx.Organization,
			Slug:          slug,
			GeneratedVCTM: vctmJSON,
			FormatFiles:   make(map[string]string),
			Assets:        assetFiles,
			SourceURL:     ctx.Options["source_url"],
			SourceRepo:    ctx.Options["source_repo"],
		}

		// The original JSON Schema file is NOT a VCTM, but we keep a reference
		// for the sd-jwt format. The pipeline can use GeneratedVCTM for display.
		cred.FormatFiles["dc+sd-jwt"] = schemaPath

		// Look for matching mDOC schema
		mdocCandidates := []string{
			filepath.Join(mdocDir, rawSlug+"-mdoc.json"),
			filepath.Join(mdocDir, slug+"-mdoc.json"),
		}
		for _, mdocPath := range mdocCandidates {
			if _, statErr := os.Stat(mdocPath); statErr == nil {
				cred.FormatFiles["mso_mdoc"] = mdocPath
				break
			}
		}

		// Look for matching rulebook
		rulebookCandidates := []string{
			filepath.Join(rulebooksDir, "rb-"+slug, "README.md"),
			filepath.Join(rulebooksDir, "rb-"+rawSlug, "README.md"),
		}
		for _, rbPath := range rulebookCandidates {
			if _, statErr := os.Stat(rbPath); statErr == nil {
				cred.RulebookPath = rbPath
				break
			}
		}

		// Build SchemaMetaSource from options (source-level defaults)
		cred.SchemaMetaSource = buildSchemaMetaFromOptions(ctx.Options, slug, ctx.BaseURL, ctx.Organization, cred.RulebookPath != "")

		results = append(results, cred)
		logger.Info("discovered credential from catalog",
			"org", ctx.Organization, "slug", slug,
			"has_mdoc", cred.FormatFiles["mso_mdoc"] != "",
			"has_rulebook", cred.RulebookPath != "")
	}

	logger.Info("rulebook-catalog discovery complete",
		"credentials", len(results))
	return results, nil
}

// discoverAssets searches for SVG templates, logos, and other visual assets
// associated with a credential. It returns two maps:
//   - assets: asset key → registry URL (for VCTM embedding)
//   - assetFiles: asset key → absolute file path (for staging)
//
// Convention search paths (in priority order):
//
//	assets/<slug>/card.svg, assets/<slug>/card-dark.svg, assets/<slug>/logo.{svg,png}
//	data-schemas/sd-jwt/<slug>-card.svg, <rawSlug>-card.svg
//	display/<slug>.svg, display/<slug>-card.svg
func discoverAssets(repoDir, sdJWTDir, slug, rawSlug, baseURL, org string) (assets map[string]string, assetFiles map[string]string) {
	assets = make(map[string]string)
	assetFiles = make(map[string]string)

	type candidate struct {
		key  string
		path string
	}

	candidates := []candidate{
		// assets/<slug>/ directory (preferred)
		{"svg_template", filepath.Join(repoDir, "assets", slug, "card.svg")},
		{"svg_template", filepath.Join(repoDir, "assets", slug, slug+"-card.svg")},
		{"svg_template_dark", filepath.Join(repoDir, "assets", slug, "card-dark.svg")},
		{"logo", filepath.Join(repoDir, "assets", slug, "logo.svg")},
		{"logo", filepath.Join(repoDir, "assets", slug, "logo.png")},

		// Co-located with schema in data-schemas/sd-jwt/
		{"svg_template", filepath.Join(sdJWTDir, slug+"-card.svg")},
		{"svg_template", filepath.Join(sdJWTDir, rawSlug+"-card.svg")},
		{"logo", filepath.Join(sdJWTDir, slug+"-logo.svg")},
		{"logo", filepath.Join(sdJWTDir, rawSlug+"-logo.svg")},
		{"logo", filepath.Join(sdJWTDir, slug+"-logo.png")},
		{"logo", filepath.Join(sdJWTDir, rawSlug+"-logo.png")},

		// display/ directory
		{"svg_template", filepath.Join(repoDir, "display", slug+"-card.svg")},
		{"svg_template", filepath.Join(repoDir, "display", slug+".svg")},
		{"logo", filepath.Join(repoDir, "display", slug+"-logo.svg")},
		{"logo", filepath.Join(repoDir, "display", slug+"-logo.png")},
	}

	for _, c := range candidates {
		if _, alreadyFound := assetFiles[c.key]; alreadyFound {
			continue
		}
		if _, err := os.Stat(c.path); err == nil {
			ext := filepath.Ext(c.path)
			assetFilename := slug + "-" + c.key + ext
			assetURL := fmt.Sprintf("%s/%s/%s", baseURL, org, assetFilename)
			assets[c.key] = assetURL
			assetFiles[c.key] = c.path
		}
	}

	return assets, assetFiles
}

// dsPrefix matches legacy "dsNNN-" prefixes in filenames.
var dsPrefix = regexp.MustCompile(`^ds\d+-`)

// normalizeSlug converts raw filenames to canonical credential slugs.
// Examples: "ds002-pid" → "pid", "company-info" → "company-info"
func normalizeSlug(raw string) string {
	// Strip dsNNN- prefix if present
	slug := dsPrefix.ReplaceAllString(raw, "")
	return slug
}

// buildSchemaMetaFromOptions constructs a SchemaMetaSource from source-level defaults.
func buildSchemaMetaFromOptions(options map[string]string, slug, baseURL, org string, hasRulebook bool) *schemameta.SchemaMetaSource {
	los := options["attestation_los"]
	binding := options["binding_type"]

	// If neither is provided, return nil (credential won't be TS11-compliant)
	if los == "" && binding == "" {
		return nil
	}

	src := &schemameta.SchemaMetaSource{
		AttestationLoS: los,
		BindingType:    binding,
	}

	if v, ok := options["version"]; ok {
		src.Version = v
	}

	if hasRulebook {
		src.RulebookURI = fmt.Sprintf("%s/%s/%s/rulebook.html", baseURL, org, slug)
	}

	return src
}
