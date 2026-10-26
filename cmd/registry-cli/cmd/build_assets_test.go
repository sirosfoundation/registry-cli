package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/sirosfoundation/registry-cli/pkg/render"
)

const cleanCard = `<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><rect width="10" height="10" fill="#036"/><text id="given_name">{{given_name}}</text></svg>`
const scriptCard = `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`

// buildAssetFixture creates a rulebook-catalog repository with one
// credential ("pid") and the given asset files, builds the registry from it
// and returns the output directory.
func buildAssetFixture(t *testing.T, baseURL string, assetFiles map[string]string) string {
	t.Helper()
	repo := t.TempDir()
	sdJWTDir := filepath.Join(repo, "data-schemas", "sd-jwt")
	require.NoError(t, os.MkdirAll(sdJWTDir, 0o755))
	schema := map[string]interface{}{
		"$schema":  "https://json-schema.org/draft/2020-12/schema",
		"title":    "ds002 - Person Identification Data (PID) – SD-JWT VC payload",
		"type":     "object",
		"required": []string{"vct", "given_name"},
		"properties": map[string]interface{}{
			"vct":        map[string]interface{}{"type": "string", "const": "urn:eudi:pid:1"},
			"given_name": map[string]interface{}{"type": "string", "description": "First name"},
		},
	}
	data, _ := json.Marshal(schema)
	require.NoError(t, os.WriteFile(filepath.Join(sdJWTDir, "ds002-pid-sd-jwt.json"), data, 0o644))
	for rel, content := range assetFiles {
		p := filepath.Join(repo, "assets", "pid", rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}

	sources := map[string]interface{}{
		"sources": []map[string]interface{}{{
			"url":          "file://" + repo,
			"organization": "testorg",
			"layout":       "rulebook-catalog",
			"options":      map[string]string{"attestation_los": "iso_18045_high", "binding_type": "key"},
		}},
	}
	srcYAML, err := yaml.Marshal(sources)
	require.NoError(t, err)
	srcFile := filepath.Join(t.TempDir(), "sources.yaml")
	require.NoError(t, os.WriteFile(srcFile, srcYAML, 0o644))

	out := t.TempDir()
	oldOut, oldBase, oldSrc, oldTpl, oldStatic := flagOutput, flagBaseURL, flagSources, flagTemplates, flagStatic
	t.Cleanup(func() {
		flagOutput, flagBaseURL, flagSources, flagTemplates, flagStatic = oldOut, oldBase, oldSrc, oldTpl, oldStatic
	})
	flagOutput, flagBaseURL, flagSources, flagTemplates, flagStatic = out, baseURL, srcFile, "", ""
	require.NoError(t, runBuild(nil, nil))
	return out
}

func readVCTM(t *testing.T, out string) (raw []byte, vctm render.VCTMData) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(out, "testorg", "pid.vctm.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &vctm))
	return raw, vctm
}

func TestBuild_PublishesPluginAssets(t *testing.T) {
	// Trailing slash on the base URL is trimmed in published URIs.
	out := buildAssetFixture(t, "https://registry.example.org/", map[string]string{
		"card.svg":      cleanCard,
		"card-dark.svg": cleanCard,
		"logo.png":      "\x89PNG\r\n\x1a\n",
	})

	for _, name := range []string{"pid-svg_template.svg", "pid-svg_template_dark.svg", "pid-logo.png"} {
		_, err := os.Stat(filepath.Join(out, "testorg", name))
		assert.NoError(t, err, "asset %s is published", name)
	}
	_, err := os.Stat(filepath.Join(out, "testorg", "pid.vctm.json"))
	assert.NoError(t, err, "format file is still published")

	raw, vctm := readVCTM(t, out)
	require.NotEmpty(t, vctm.Display)
	var uris []string
	for _, d := range vctm.Display {
		require.NotNil(t, d.Rendering)
		for _, tpl := range d.Rendering.SVGTemplates {
			uris = append(uris, tpl.URI)
		}
	}
	assert.ElementsMatch(t, []string{
		"https://registry.example.org/testorg/pid-svg_template.svg",
		"https://registry.example.org/testorg/pid-svg_template_dark.svg",
	}, uris)
	assert.Contains(t, string(raw), "https://registry.example.org/testorg/pid-logo.png")
	assert.NotContains(t, string(raw), `"/testorg/`)

	// The rendered credential page keeps the absolute SVG template URIs
	// (SanitizeVCTM keeps http/https image URIs).
	var sanitized render.VCTMData
	require.NoError(t, json.Unmarshal(raw, &sanitized))
	render.SanitizeVCTM(&sanitized)
	count := 0
	for _, d := range sanitized.Display {
		count += len(d.Rendering.SVGTemplates)
	}
	assert.Equal(t, 2, count)
}

func TestBuild_RejectsUnsafeSVG(t *testing.T) {
	out := buildAssetFixture(t, "https://registry.example.org", map[string]string{
		"card.svg":      cleanCard,
		"card-dark.svg": scriptCard,
	})

	_, err := os.Stat(filepath.Join(out, "testorg", "pid-svg_template.svg"))
	assert.NoError(t, err, "clean card is published")
	_, err = os.Stat(filepath.Join(out, "testorg", "pid-svg_template_dark.svg"))
	assert.True(t, os.IsNotExist(err), "unsafe card is not published")

	raw, vctm := readVCTM(t, out)
	assert.NotContains(t, string(raw), "svg_template_dark", "reference to the rejected card is removed")
	require.NotEmpty(t, vctm.Display)
	require.NotNil(t, vctm.Display[0].Rendering)
	require.Len(t, vctm.Display[0].Rendering.SVGTemplates, 1)
	assert.Equal(t, "https://registry.example.org/testorg/pid-svg_template.svg", vctm.Display[0].Rendering.SVGTemplates[0].URI)
}

func TestBuild_RejectedOnlyCardLeavesNoRendering(t *testing.T) {
	out := buildAssetFixture(t, "https://registry.example.org", map[string]string{"card.svg": scriptCard})
	raw, _ := readVCTM(t, out)
	assert.NotContains(t, string(raw), "svg_template")
	_, err := os.Stat(filepath.Join(out, "testorg", "pid-svg_template.svg"))
	assert.True(t, os.IsNotExist(err))
}
