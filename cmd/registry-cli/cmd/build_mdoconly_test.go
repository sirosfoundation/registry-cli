package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

func TestBuild_MdocOnlyType(t *testing.T) {
	repo := t.TempDir()
	put := func(rel, content string) {
		p := filepath.Join(repo, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	put("data-schemas/mdoc/ds010-mvrc-mdoc.json", `{"title":"Vehicle Registration","description":"mdoc registration certificate","docType":"eu.test.mvrc.1"}`)
	put("data-schemas/mdoc/broken-mdoc.json", `{nope`)
	put("rulebooks/rb-mvrc/README.md", "# mVRC rulebook\n\nBody text.\n")
	put("assets/mvrc/card.svg", cleanCard)
	put("assets/mvrc/logo.png", "\x89PNG\r\n\x1a\n")

	srcYAML, err := yaml.Marshal(map[string]interface{}{"sources": []map[string]interface{}{{
		"url": "file://" + repo, "organization": "testorg", "layout": "rulebook-catalog",
		"options": map[string]string{"attestation_los": "iso_18045_high", "binding_type": "key", "version": "1.2.0"},
	}}})
	require.NoError(t, err)
	srcFile := filepath.Join(t.TempDir(), "sources.yaml")
	require.NoError(t, os.WriteFile(srcFile, srcYAML, 0o644))

	out := t.TempDir()
	oldOut, oldBase, oldSrc, oldTpl, oldStatic := flagOutput, flagBaseURL, flagSources, flagTemplates, flagStatic
	t.Cleanup(func() {
		flagOutput, flagBaseURL, flagSources, flagTemplates, flagStatic = oldOut, oldBase, oldSrc, oldTpl, oldStatic
	})
	flagOutput, flagBaseURL, flagSources, flagTemplates, flagStatic = out, "https://registry.example.org", srcFile, "", ""
	require.NoError(t, runBuild(nil, nil))

	for _, f := range []string{
		"testorg/mvrc.mdoc.json", "testorg/mvrc-svg_template.svg", "testorg/mvrc-logo.png",
		"testorg/mvrc/index.html", "testorg/mvrc/rulebook.html",
	} {
		assert.FileExists(t, filepath.Join(out, f))
	}
	for _, f := range []string{"testorg/mvrc.vctm.json", "testorg/broken.mdoc.json"} {
		assert.NoFileExists(t, filepath.Join(out, f))
	}

	// TS11 entry
	raw, err := os.ReadFile(filepath.Join(out, "api", "v1", "schemas.json"))
	require.NoError(t, err)
	var list struct {
		Data []schemameta.SchemaMeta `json:"data"`
	}
	require.NoError(t, json.Unmarshal(raw, &list))
	require.Len(t, list.Data, 1)
	sm := list.Data[0]
	assert.Equal(t, []string{"mso_mdoc"}, sm.SupportedFormats)
	require.Len(t, sm.SchemaURIs, 1)
	assert.Equal(t, "mso_mdoc", sm.SchemaURIs[0].FormatIdentifier)
	assert.Equal(t, "https://registry.example.org/testorg/mvrc.mdoc.json", sm.SchemaURIs[0].URI)
	assert.Equal(t, "https://registry.example.org/testorg/mvrc/rulebook.html", sm.RulebookURI)
	assert.Equal(t, "1.2.0", sm.Version)

	// Detail page
	page, err := os.ReadFile(filepath.Join(out, "testorg", "mvrc", "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(page), "Vehicle Registration")
	assert.Contains(t, string(page), "mdoc registration certificate")
	assert.Contains(t, string(page), "eu.test.mvrc.1")
	assert.Contains(t, string(page), "mvrc.mdoc.json")

	// Catalogue entry
	reg, err := os.ReadFile(filepath.Join(out, ".well-known", "vctm-registry.json"))
	require.NoError(t, err)
	assert.Contains(t, string(reg), `"name": "Vehicle Registration"`)
	assert.Contains(t, string(reg), "mvrc.mdoc.json")
}

func TestBuild_MixedToMdocOnlyRebuildDropsStaleVCTM(t *testing.T) {
	repo := t.TempDir()
	put := func(rel, content string) {
		p := filepath.Join(repo, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
	}
	put("data-schemas/sd-jwt/car-sd-jwt.json", `{"title":"Car","type":"object","properties":{"vct":{"const":"urn:test:car"},"plate":{"type":"string"}}}`)
	put("data-schemas/mdoc/car-mdoc.json", `{"title":"Car mdoc","docType":"org.test.car"}`)

	srcYAML, err := yaml.Marshal(map[string]interface{}{"sources": []map[string]interface{}{{
		"url": "file://" + repo, "organization": "testorg", "layout": "rulebook-catalog",
	}}})
	require.NoError(t, err)
	srcFile := filepath.Join(t.TempDir(), "sources.yaml")
	require.NoError(t, os.WriteFile(srcFile, srcYAML, 0o644))
	oldOut, oldBase, oldSrc, oldTpl, oldStatic := flagOutput, flagBaseURL, flagSources, flagTemplates, flagStatic
	t.Cleanup(func() {
		flagOutput, flagBaseURL, flagSources, flagTemplates, flagStatic = oldOut, oldBase, oldSrc, oldTpl, oldStatic
	})
	build := func() string {
		out := t.TempDir()
		flagOutput, flagBaseURL, flagSources, flagTemplates, flagStatic = out, "https://registry.example.org", srcFile, "", ""
		require.NoError(t, runBuild(nil, nil))
		return out
	}

	out1 := build()
	assert.FileExists(t, filepath.Join(out1, "testorg", "car.vctm.json"))

	require.NoError(t, os.Remove(filepath.Join(repo, "data-schemas", "sd-jwt", "car-sd-jwt.json")))
	out2 := build()
	assert.NoFileExists(t, filepath.Join(out2, "testorg", "car.vctm.json"))
	assert.FileExists(t, filepath.Join(out2, "testorg", "car.mdoc.json"))
	page, err := os.ReadFile(filepath.Join(out2, "testorg", "car", "index.html"))
	require.NoError(t, err)
	assert.Contains(t, string(page), "Car mdoc")
	assert.NotContains(t, string(page), "urn:test:car")
}
