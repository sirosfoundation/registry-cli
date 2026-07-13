// Package defaultlayout implements the repo plugin for the standard SIROS
// credential repository layout (co-located schema-meta + format files).
package defaultlayout

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/mdcred"
	"github.com/sirosfoundation/registry-cli/pkg/repoplugin"
	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

func init() {
	repoplugin.Register(&DefaultLayout{})
}

// DefaultLayout handles the standard SIROS credential repository layout:
//
//	<slug>.schema-meta.yaml   (TS11 governance)
//	<slug>.vctm.json          (SD-JWT VC Type Metadata)
//	<slug>.mdoc.json          (mDOC metadata)
//	<slug>.vc.json            (W3C VC schema)
//	rulebook.md               (co-located governance doc)
//
// It also handles markdown files with vct: front matter (converted to VCTM)
// and legacy VCTM-only credentials (no schema-meta).
type DefaultLayout struct{}

func (d *DefaultLayout) Name() string { return "default" }

func (d *DefaultLayout) Description() string {
	return "Standard SIROS layout: co-located schema-meta.yaml + format files per credential"
}

func (d *DefaultLayout) Discover(ctx repoplugin.Context) ([]repoplugin.DiscoveredCredential, error) {
	logger := ctx.Logger

	// Determine walk root
	walkRoot := ctx.RepoDir
	if ctx.SubPath != "" {
		clean := filepath.Clean(ctx.SubPath)
		if filepath.IsAbs(clean) || strings.Contains(clean, "..") {
			return nil, fmt.Errorf("subpath must be a relative path within the repo: %q", ctx.SubPath)
		}
		walkRoot = filepath.Join(ctx.RepoDir, clean)
	}

	// Pass 0: convert markdown credential files to VCTM format files
	converted, err := mdcred.ConvertDirPath(ctx.RepoDir, ctx.SubPath, ctx.BaseURL)
	if err != nil {
		logger.Warn("markdown credential conversion", "error", err)
	}
	for _, c := range converted {
		logger.Info("converted markdown credential", "slug", c.Slug, "formats", len(c.Files))
	}

	var results []repoplugin.DiscoveredCredential
	knownSlugs := make(map[string]bool)

	// Pass 1: find schema-meta files (TS11 credentials)
	if walkErr := filepath.WalkDir(walkRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "dist" || name == "build" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		var slug string
		switch {
		case strings.HasSuffix(name, ".schema-meta.yaml"):
			slug = strings.TrimSuffix(name, ".schema-meta.yaml")
		case strings.HasSuffix(name, ".schema-meta.json"):
			slug = strings.TrimSuffix(name, ".schema-meta.json")
		default:
			return nil
		}

		if knownSlugs[slug] {
			return nil
		}

		credDir := filepath.Dir(path)

		src, parseErr := schemameta.ParseSource(path)
		if parseErr != nil {
			logger.Warn("skipping schema-meta", "file", path, "error", parseErr)
			return nil
		}

		formats, formatFiles, fmtErr := schemameta.DetectFormats(credDir, slug)
		if fmtErr != nil {
			logger.Warn("detecting formats", "slug", slug, "error", fmtErr)
			return nil
		}

		// Check for co-located rulebook.md
		rulebookPath := filepath.Join(credDir, "rulebook.md")
		if src.RulebookURI == "" {
			if _, statErr := os.Stat(rulebookPath); statErr == nil {
				src.RulebookURI = fmt.Sprintf("%s/%s/%s/rulebook.html", ctx.BaseURL, ctx.Organization, slug)
			}
		}

		cred := repoplugin.DiscoveredCredential{
			Org:              ctx.Organization,
			Slug:             slug,
			SchemaMetaSource: src,
			FormatFiles:      formatFiles,
			SourceURL:        ctx.Options["source_url"],
			SourceRepo:       ctx.Options["source_repo"],
		}

		// Set rulebook path if it exists
		if _, statErr := os.Stat(rulebookPath); statErr == nil {
			cred.RulebookPath = rulebookPath
		}

		results = append(results, cred)
		knownSlugs[slug] = true

		logger.Info("processed credential",
			"org", ctx.Organization, "slug", slug, "formats", formats)
		return nil
	}); walkErr != nil {
		return nil, fmt.Errorf("walking repo dir: %w", walkErr)
	}

	// Pass 2: discover legacy VCTM-only credentials (no schema-meta)
	legacyCreds, err := schemameta.DetectLegacyCredentials(walkRoot, knownSlugs)
	if err != nil {
		logger.Warn("detecting legacy credentials", "error", err)
	}
	for _, lc := range legacyCreds {
		_, formatFiles, err := schemameta.DetectFormats(lc.Dir, lc.Slug)
		if err != nil {
			logger.Warn("detecting formats for legacy credential", "slug", lc.Slug, "error", err)
			continue
		}
		if len(formatFiles) == 0 {
			continue
		}

		cred := repoplugin.DiscoveredCredential{
			Org:         ctx.Organization,
			Slug:        lc.Slug,
			FormatFiles: formatFiles,
			SourceURL:   ctx.Options["source_url"],
			SourceRepo:  ctx.Options["source_repo"],
		}

		// Check for co-located rulebook
		rulebookPath := filepath.Join(lc.Dir, "rulebook.md")
		if _, statErr := os.Stat(rulebookPath); statErr == nil {
			cred.RulebookPath = rulebookPath
		}

		results = append(results, cred)
		logger.Info("processed legacy credential",
			"org", ctx.Organization, "slug", lc.Slug)
	}

	return results, nil
}
