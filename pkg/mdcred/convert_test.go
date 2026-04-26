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

func TestConvertDir_HappyPath(t *testing.T) {
	dir := t.TempDir()

	md := `---
vct: https://example.com/credentials/test
---

# Test Credential

A test credential for unit testing.

## Claims

- ` + "`email`" + ` (string): Email address [mandatory]
- ` + "`name`" + ` (string): Full name
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte(md), 0o644))

	results, err := ConvertDir(dir, "https://example.com")
	require.NoError(t, err)
	require.NotEmpty(t, results, "should have converted at least one credential")

	assert.Equal(t, "test", results[0].Slug)
	assert.NotEmpty(t, results[0].Files, "should have generated at least one format file")

	// Verify at least one output file was written
	for _, path := range results[0].Files {
		_, statErr := os.Stat(path)
		assert.NoError(t, statErr, "output file should exist: %s", path)
	}
}

func TestConvertDir_SubdirectoryDiscovery(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "creds")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	md := `---
vct: https://example.com/credentials/nested
---

# Nested Credential

A nested credential.

## Claims

- ` + "`id`" + ` (string): Identifier
`
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "nested.md"), []byte(md), 0o644))

	results, err := ConvertDir(dir, "https://example.com")
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, "nested", results[0].Slug)
}

func TestConvertFile_Success(t *testing.T) {
	dir := t.TempDir()

	md := `---
vct: https://example.com/credentials/direct
---

# Direct Credential

Testing convertFile directly.

## Claims

- ` + "`given_name`" + ` (string): Given name [mandatory]
`
	mdPath := filepath.Join(dir, "direct.md")
	require.NoError(t, os.WriteFile(mdPath, []byte(md), 0o644))

	result, err := convertFile(mdPath, "direct", dir, "https://example.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "direct", result.Slug)
	assert.NotEmpty(t, result.Files)
}

func TestConvertFile_InvalidMarkdown(t *testing.T) {
	dir := t.TempDir()

	// Markdown with vct front matter but no claims or valid structure
	md := "---\nvct: https://example.com/test\n---\n"
	mdPath := filepath.Join(dir, "bad.md")
	require.NoError(t, os.WriteFile(mdPath, []byte(md), 0o644))

	result, err := convertFile(mdPath, "bad", dir, "https://example.com")
	// mtcvctm may return an error or an empty result depending on the version
	if err != nil {
		assert.Contains(t, err.Error(), "name is required")
	} else {
		// If no error, result should still be valid (possibly with 0 claims)
		assert.NotNil(t, result)
	}
}
