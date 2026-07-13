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

		// Parse JSON Schema and convert to VCTM
		vctmJSON, err := convertJSONSchemaToVCTM(schemaPath, slug, ctx.BaseURL, ctx.Organization)
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
