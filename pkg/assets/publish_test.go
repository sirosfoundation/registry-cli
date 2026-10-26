package assets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURL(t *testing.T) {
	assert.Equal(t, "https://r.example/org/pid-logo.png", URL("https://r.example", "org", "pid-logo.png"))
	assert.Equal(t, "https://r.example/org/pid-logo.png", URL("https://r.example/", "org", "pid-logo.png"))
}

func TestPublish(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	good := []byte(svg(`<rect/>`))
	files := map[string][]byte{
		"pid-svg_template.svg":      good,
		"pid-svg_template_dark.svg": []byte(svg(`<script/>`)),
		"pid-logo.png":              []byte("png"),
		"pid-logo.webp":             []byte("webp"),
		"pid-logo.jpg":              []byte("jpg"),
		"pid-logo.jpeg":             []byte("jpeg"),
		"pid.vctm.json":             []byte("format"),
		"pid-other.svg":             good, // unknown key
	}
	for n, d := range files {
		require.NoError(t, os.WriteFile(filepath.Join(src, n), d, 0o644))
	}
	// A pre-existing format file in the output is untouched.
	require.NoError(t, os.MkdirAll(filepath.Join(out, "org"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(out, "org", "pid.vctm.json"), []byte("keep"), 0o644))

	got := Publish(src, out, "org", "pid", nil)
	assert.ElementsMatch(t, []string{"pid-svg_template.svg", "pid-logo.png", "pid-logo.jpg", "pid-logo.jpeg", "pid-logo.webp"}, got)

	for _, n := range got {
		_, err := os.Stat(filepath.Join(out, "org", n))
		assert.NoError(t, err)
	}
	for _, n := range []string{"pid-svg_template_dark.svg", "pid-other.svg"} {
		_, err := os.Stat(filepath.Join(out, "org", n))
		assert.True(t, os.IsNotExist(err), n)
	}
	kept, _ := os.ReadFile(filepath.Join(out, "org", "pid.vctm.json"))
	assert.Equal(t, "keep", string(kept))
}

func TestPublish_SlugPrefixDoesNotCollide(t *testing.T) {
	src, out := t.TempDir(), t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(src, "iban-attestation-for-individuals-svg_template.svg"), []byte(svg(`<g/>`)), 0o644))
	assert.Empty(t, Publish(src, out, "org", "iban-attestation", nil))
}

func TestDropURIs(t *testing.T) {
	in := `{"vct":"x","display":[{"locale":"en","rendering":{"simple":{"logo":{"uri":"https://a/logo.svg"}},"svg_templates":[{"uri":"https://a/1.svg"},{"uri":"https://a/2.svg"}]}}]}`
	out, err := DropURIs([]byte(in), map[string]bool{"https://a/2.svg": true})
	require.NoError(t, err)
	assert.Contains(t, string(out), "https://a/1.svg")
	assert.NotContains(t, string(out), "https://a/2.svg")

	out, err = DropURIs([]byte(in), map[string]bool{"https://a/1.svg": true, "https://a/2.svg": true, "https://a/logo.svg": true})
	require.NoError(t, err)
	assert.NotContains(t, string(out), "rendering")
	assert.Contains(t, string(out), `"locale"`)

	same, err := DropURIs([]byte(in), nil)
	require.NoError(t, err)
	assert.Equal(t, in, string(same))
}
