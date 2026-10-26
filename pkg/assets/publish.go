package assets

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Keys are the asset keys layout plugins use in DiscoveredCredential.Assets.
var Keys = []string{"svg_template", "svg_template_dark", "logo"}

// Exts are the file extensions published for an asset.
var Exts = []string{".svg", ".png", ".jpg", ".jpeg", ".webp"}

// IsPublishableExt reports whether ext (with leading dot) is a published
// asset extension.
func IsPublishableExt(ext string) bool {
	for _, e := range Exts {
		if e == ext {
			return true
		}
	}
	return false
}

// Filename returns the published file name of an asset: <slug>-<key><ext>.
func Filename(slug, key, ext string) string {
	return slug + "-" + key + ext
}

// URL returns the absolute URL of a published asset:
// <baseURL>/<org>/<filename>. A trailing slash on baseURL is trimmed.
func URL(baseURL, org, filename string) string {
	return strings.TrimRight(baseURL, "/") + "/" + org + "/" + filename
}

// Check validates asset content for publication. SVG documents are checked
// with ValidateSVG; raster images are accepted by extension.
func Check(filename string, data []byte) error {
	ext := strings.ToLower(filepath.Ext(filename))
	if !IsPublishableExt(ext) {
		return fmt.Errorf("unsupported asset type %q", ext)
	}
	if ext == ".svg" {
		return ValidateSVG(data)
	}
	return nil
}

// Publish copies the staged assets of one credential from srcDir to
// <outputDir>/<org>/, next to the credential's VCTM. Staged files are named
// <slug>-<key><ext> for the known keys and extensions. SVG files are
// validated again before they are written, and a file that would replace a
// credential format file keeps the format file. It returns the published
// file names.
func Publish(srcDir, outputDir, org, slug string, logger *slog.Logger) []string {
	if logger == nil {
		logger = slog.Default()
	}
	var published []string
	for _, key := range Keys {
		for _, ext := range Exts {
			name := Filename(slug, key, ext)
			data, err := os.ReadFile(filepath.Join(srcDir, name))
			if err != nil {
				continue
			}
			if err := Check(name, data); err != nil {
				logger.Warn("not publishing asset", "org", org, "slug", slug, "file", name, "reason", err)
				continue
			}
			dstDir := filepath.Join(outputDir, org)
			if err := os.MkdirAll(dstDir, 0o755); err != nil {
				logger.Warn("creating asset dir", "dir", dstDir, "error", err)
				continue
			}
			if isFormatFile(name, slug) {
				continue
			}
			if err := os.WriteFile(filepath.Join(dstDir, name), data, 0o644); err != nil {
				logger.Warn("writing asset", "file", name, "error", err)
				continue
			}
			published = append(published, name)
		}
	}
	return published
}

// isFormatFile reports whether name is one of the credential's format files.
func isFormatFile(name, slug string) bool {
	switch name {
	case slug + ".vctm", slug + ".json", slug + ".vctm.json", slug + ".mdoc.json", slug + ".vc.json", slug + ".schema.json":
		return true
	}
	return false
}

// DropURIs removes every object whose "uri" is in uris from a VCTM document
// and prunes containers left empty (svg_templates, logo, simple, rendering).
// It returns the document unchanged when uris is empty.
func DropURIs(vctm []byte, uris map[string]bool) ([]byte, error) {
	if len(uris) == 0 || len(vctm) == 0 {
		return vctm, nil
	}
	var doc interface{}
	if err := json.Unmarshal(vctm, &doc); err != nil {
		return nil, fmt.Errorf("parsing VCTM: %w", err)
	}
	doc, _ = prune(doc, uris)
	return json.MarshalIndent(doc, "", "  ")
}

// prune returns the pruned node and whether the node became empty because
// of removals.
func prune(node interface{}, uris map[string]bool) (interface{}, bool) {
	switch v := node.(type) {
	case map[string]interface{}:
		if u, ok := v["uri"].(string); ok && uris[u] {
			return nil, true
		}
		removed := false
		for k, child := range v {
			pruned, emptied := prune(child, uris)
			if emptied {
				delete(v, k)
				removed = true
			} else {
				v[k] = pruned
			}
		}
		return v, removed && len(v) == 0
	case []interface{}:
		if len(v) == 0 {
			return v, false
		}
		out := make([]interface{}, 0, len(v))
		for _, child := range v {
			pruned, emptied := prune(child, uris)
			if !emptied {
				out = append(out, pruned)
			}
		}
		if len(out) == 0 {
			return nil, true
		}
		return out, false
	}
	return node, false
}
