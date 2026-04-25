// Package mdcred converts markdown credential definitions to VCTM format files
// using the mtcvctm library.
package mdcred

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirosfoundation/mtcvctm/pkg/config"
	"github.com/sirosfoundation/mtcvctm/pkg/parser"

	// Import format generators to trigger init() registration
	_ "github.com/sirosfoundation/mtcvctm/pkg/formats/mddl"
	_ "github.com/sirosfoundation/mtcvctm/pkg/formats/vctmfmt"
	_ "github.com/sirosfoundation/mtcvctm/pkg/formats/w3c"
)

// ConvertResult describes a credential converted from markdown.
type ConvertResult struct {
	Slug  string            // base name without .md extension
	Files map[string]string // format name → output file path
}

// ConvertDir scans dir (and subdirectories) for markdown credential files
// (those with vct: in YAML front matter) and converts them to VCTM format
// files alongside the source markdown. It returns the list of converted
// credentials. Already-existing output files are skipped (the repo may have
// pre-built them).
func ConvertDir(dir, baseURL string) ([]ConvertResult, error) {
	var results []ConvertResult

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
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

		// Quick check: does this markdown have a vct: front matter?
		if !hasVCTFrontMatter(path) {
			return nil
		}

		// Skip if .vctm.json already exists (pre-built)
		if _, statErr := os.Stat(filepath.Join(outputDir, slug+".vctm.json")); statErr == nil {
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

// hasVCTFrontMatter checks if a markdown file starts with YAML front matter
// containing a vct: field.
func hasVCTFrontMatter(path string) bool {
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
		if strings.HasPrefix(strings.TrimSpace(line), "vct:") {
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

	// Generate all format outputs
	outputs, err := p.GenerateAll(cred)
	if err != nil {
		return nil, fmt.Errorf("generating formats: %w", err)
	}

	result := &ConvertResult{
		Slug:  slug,
		Files: make(map[string]string),
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
