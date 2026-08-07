// Package mdcred converts markdown credential definitions to VCTM format files.
package mdcred

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/parser"

	// Import format generators to trigger init() registration
	_ "github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats/jsonschema"
	_ "github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats/mddl"
	_ "github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats/vctmfmt"
	_ "github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats/w3c"
)

// ConvertResult describes a credential converted from markdown.
type ConvertResult struct {
	Slug       string            // base name without .md extension
	SourcePath string            // absolute path to the source .md file
	Files      map[string]string // format name → output file path
}

// ConvertDir scans dir (and subdirectories) for markdown credential files
// (those with vct: or doctype: in YAML front matter — mdoc-only credentials
// have no vct) and converts them to VCTM/MDDL/etc. format files alongside
// the source markdown. It returns the list of converted credentials.
// Already-existing output files are skipped (the repo may have pre-built
// them).
func ConvertDir(dir, baseURL string) ([]ConvertResult, error) {
	return ConvertDirPath(dir, "", baseURL)
}

// ConvertDirPath works like ConvertDir but restricts discovery to the given
// relative subPath within dir. If subPath is empty, the entire dir is scanned.
func ConvertDirPath(dir, subPath, baseURL string) ([]ConvertResult, error) {
	walkRoot := dir
	if subPath != "" {
		// Clean the path and ensure it doesn't escape the repo dir
		clean := filepath.Clean(subPath)
		if filepath.IsAbs(clean) || filepath.VolumeName(clean) != "" || containsDotDot(clean) {
			return nil, fmt.Errorf("subpath must be a relative path within the repo: %q", subPath)
		}
		walkRoot = filepath.Join(dir, clean)
	}

	var results []ConvertResult

	err := filepath.WalkDir(walkRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip hidden directories (e.g. .git)
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".md") {
			return nil
		}

		// Skip non-credential markdown files
		lower := strings.ToLower(d.Name())
		if lower == "readme.md" || lower == "changelog.md" || lower == "rulebook.md" {
			return nil
		}

		slug := strings.TrimSuffix(d.Name(), ".md")
		outputDir := filepath.Dir(path)

		// Quick check: does this markdown declare a credential identifier?
		// vct: for sd-jwt credentials, doctype: for mdoc-only credentials
		// (which have no vct at all).
		if !hasCredentialFrontMatter(path) {
			return nil
		}

		// Skip if any format's output already exists (pre-built). An
		// mdoc-only credential may pre-build just *.mdoc.json with no
		// *.vctm.json, so all registered formats are checked (see
		// hasPrebuiltOutput) rather than assuming VCTM is always the
		// pre-built artifact.
		if hasPrebuiltOutput(outputDir, slug) {
			return nil
		}

		result, convErr := convertFile(path, slug, outputDir, baseURL)
		if convErr != nil {
			return fmt.Errorf("converting %s: %w", path, convErr)
		}
		if result != nil {
			results = append(results, *result)
		}
		return nil
	})
	if err != nil {
		return results, err
	}

	return results, nil
}

// hasCredentialFrontMatter checks if a markdown file starts with YAML front
// matter declaring vct: (sd-jwt credentials) or doctype: (mdoc-only
// credentials, which have no vct).
func hasCredentialFrontMatter(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	content := string(data)
	if !strings.HasPrefix(content, "---") {
		return false
	}
	end := strings.Index(content[3:], "---")
	if end < 0 {
		return false
	}
	frontMatter := content[3 : 3+end]
	for _, line := range strings.Split(frontMatter, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "vct:") || strings.HasPrefix(trimmed, "doctype:") {
			return true
		}
	}
	return false
}

// hasPrebuiltOutput reports whether a pre-built output file already exists
// for slug in outputDir, for any registered format. Conversion is skipped
// entirely when this is true, on the assumption the whole set of outputs was
// pre-built by hand — not just whichever single format happened to have a
// checked-in file. All registered formats (not just VCTM/MDDL) are checked
// so a hand-built w3c or jsonschema output isn't silently overwritten by a
// full reconversion.
func hasPrebuiltOutput(outputDir, slug string) bool {
	for _, formatName := range formats.List() {
		outFile := parser.OutputFileName(slug, formatName)
		info, err := os.Stat(filepath.Join(outputDir, outFile))
		if err == nil {
			if !info.IsDir() {
				return true
			}
			continue
		}
		if !os.IsNotExist(err) {
			// Stat failed for a reason other than "doesn't exist" (e.g.
			// permission denied). We can't reliably confirm there's no
			// pre-built output, so err on the side of skipping conversion
			// rather than risking an overwrite.
			return true
		}
	}
	return false
}

func convertFile(mdPath, slug, outputDir, baseURL string) (*ConvertResult, error) {
	cfg := config.DefaultConfig()
	cfg.InputFile = mdPath
	cfg.BaseURL = baseURL
	cfg.InlineImages = true
	cfg.Formats = "all"

	p := parser.NewParser(cfg)
	cred, err := p.ParseToCredential(mdPath)
	if err != nil {
		return nil, fmt.Errorf("parsing markdown: %w", err)
	}

	// Determine which formats to generate: per-credential override or all
	var formatNames []string
	fmts := strings.TrimSpace(cred.Formats)
	if fmts != "" {
		formatNames, err = formats.ParseFormats(fmts)
		if err != nil {
			return nil, fmt.Errorf("parsing per-credential formats %q: %w", fmts, err)
		}
	} else {
		formatNames = formats.List()
	}

	// Generate the selected format outputs
	outputs, err := p.Generate(cred, formatNames)
	if err != nil {
		return nil, fmt.Errorf("generating formats: %w", err)
	}

	result := &ConvertResult{
		Slug:       slug,
		SourcePath: mdPath,
		Files:      make(map[string]string),
	}

	for formatName, data := range outputs {
		outFile := filepath.Join(outputDir, parser.OutputFileName(slug, formatName))
		if err := os.WriteFile(outFile, data, 0o644); err != nil {
			return nil, fmt.Errorf("writing %s: %w", outFile, err)
		}
		result.Files[formatName] = outFile
	}

	return result, nil
}

// containsDotDot reports whether the cleaned path contains ".." as a segment.
func containsDotDot(p string) bool {
	for _, seg := range strings.Split(p, string(filepath.Separator)) {
		if seg == ".." {
			return true
		}
	}
	return false
}
