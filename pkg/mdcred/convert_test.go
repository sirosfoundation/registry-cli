package mdcred
package mdcred

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasVCTFrontMatter_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "---\nvct: https://example.com/test\nbackground_color: \"#003366\"\n---\n# Test Credential\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.True(t, hasVCTFrontMatter(path))
}

func TestHasVCTFrontMatter_NoFrontMatter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "# Just a regular markdown file\nNo front matter here.\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.False(t, hasVCTFrontMatter(path))
}

func TestHasVCTFrontMatter_FrontMatterWithoutVCT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "---\ntitle: Something\nauthor: Someone\n---\n# Not a credential\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.False(t, hasVCTFrontMatter(path))
}

func TestHasVCTFrontMatter_MissingClosingDelimiter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "---\nvct: https://example.com/test\nNo closing delimiter\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.False(t, hasVCTFrontMatter(path))
}

func TestHasVCTFrontMatter_IndentedVCT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "---\n  vct: https://example.com/test\n---\n# Test\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.True(t, hasVCTFrontMatter(path))
}

func TestHasVCTFrontMatter_NonexistentFile(t *testing.T) {
	assert.False(t, hasVCTFrontMatter("/nonexistent/file.md"))
}

func TestConvertDir_SkipsNonCredentialMarkdown(t *testing.T) {
	dir := t.TempDir()

	// Create files that should be skipped
	for _, name := range []string{"README.md", "readme.md", "CHANGELOG.md", "rulebook.md"} {
		content := "---\nvct: https://example.com/skip\n---\n# Should be skipped\n"
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}

	results, err := ConvertDir(dir, "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestConvertDir_SkipsMarkdownWithoutVCT(t *testing.T) {
	dir := t.TempDir()

	content := "# Just markdown\nNo front matter.\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte(content), 0o644))

	results, err := ConvertDir(dir, "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestConvertDir_SkipsPrebuilt(t *testing.T) {
	dir := t.TempDir()

	// Markdown with vct front matter
	md := "---\nvct: https://example.com/test\n---\n# Test Credential\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte(md), 0o644))

	// Pre-built .vctm.json — should cause skip
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.vctm.json"), []byte("{}"), 0o644))

	results, err := ConvertDir(dir, "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestConvertDir_SkipsHiddenDirs(t *testing.T) {
	dir := t.TempDir()

	// Create .git subdirectory with a markdown file
	gitDir := filepath.Join(dir, ".git")
	require.NoError(t, os.MkdirAll(gitDir, 0o755))
	md := "---\nvct: https://example.com/test\n---\n# Should be skipped\n"
	require.NoError(t, os.WriteFile(filepath.Join(gitDir, "test.md"), []byte(md), 0o644))

	results, err := ConvertDir(dir, "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestConvertDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	results, err := ConvertDir(dir, "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestConvertDir_NonexistentDir(t *testing.T) {
	_, err := ConvertDir("/nonexistent/dir", "https://example.com")
	assert.Error(t, err)
}
