package mdcred

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasCredentialFrontMatter_ValidVCT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "---\nvct: https://example.com/test\nbackground_color: \"#003366\"\n---\n# Test Credential\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.True(t, hasCredentialFrontMatter(path))
}

func TestHasCredentialFrontMatter_ValidDoctype(t *testing.T) {
	// mdoc-only credentials have no vct at all — doctype: alone must trigger conversion.
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "---\ndoctype: org.example.credentials.test\n---\n# Test Credential\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.True(t, hasCredentialFrontMatter(path))
}

func TestHasCredentialFrontMatter_NoFrontMatter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "# Just a regular markdown file\nNo front matter here.\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.False(t, hasCredentialFrontMatter(path))
}

func TestHasCredentialFrontMatter_FrontMatterWithoutVCTOrDoctype(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "---\ntitle: Something\nauthor: Someone\n---\n# Not a credential\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.False(t, hasCredentialFrontMatter(path))
}

func TestHasCredentialFrontMatter_MissingClosingDelimiter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "---\nvct: https://example.com/test\nNo closing delimiter\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.False(t, hasCredentialFrontMatter(path))
}

func TestHasCredentialFrontMatter_IndentedVCT(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.md")
	content := "---\n  vct: https://example.com/test\n---\n# Test\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	assert.True(t, hasCredentialFrontMatter(path))
}

func TestHasCredentialFrontMatter_NonexistentFile(t *testing.T) {
	assert.False(t, hasCredentialFrontMatter("/nonexistent/file.md"))
}

func TestHasPrebuiltOutput_VCTM(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.vctm.json"), []byte("{}"), 0o644))

	assert.True(t, hasPrebuiltOutput(dir, "test"))
}

func TestHasPrebuiltOutput_MDoc(t *testing.T) {
	// An mdoc-only credential may pre-build just *.mdoc.json with no VCTM.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.mdoc.json"), []byte("{}"), 0o644))

	assert.True(t, hasPrebuiltOutput(dir, "test"))
}

func TestHasPrebuiltOutput_None(t *testing.T) {
	dir := t.TempDir()
	assert.False(t, hasPrebuiltOutput(dir, "test"))
}

func TestHasPrebuiltOutput_OtherRegisteredFormats(t *testing.T) {
	// A repo may hand pre-build only a non-VCTM/non-MDOC format (e.g. w3c or
	// jsonschema); hasPrebuiltOutput must check all registered formats, not
	// just the two most common ones, or the other outputs get silently
	// overwritten by a full reconversion.
	for _, ext := range []string{".vc.json", ".schema.json"} {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "test"+ext), []byte("{}"), 0o644))
			assert.True(t, hasPrebuiltOutput(dir, "test"))
		})
	}
}

func TestHasPrebuiltOutput_IgnoresDirectory(t *testing.T) {
	// A directory that happens to share an output file's name (e.g. an
	// accidentally-created dir) must not count as a pre-built artifact.
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "test.vctm.json"), 0o755))

	assert.False(t, hasPrebuiltOutput(dir, "test"))
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

func TestConvertDir_SkipsPrebuiltMDoc(t *testing.T) {
	dir := t.TempDir()

	// mdoc-only credential: doctype, no vct at all.
	md := "---\ndoctype: org.example.credentials.test\n---\n# Test Credential\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte(md), 0o644))

	// Pre-built .mdoc.json with no .vctm.json — should still cause skip.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.mdoc.json"), []byte("{}"), 0o644))

	results, err := ConvertDir(dir, "https://example.com")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestConvertDir_ConvertsDoctypeOnlyCredential(t *testing.T) {
	dir := t.TempDir()

	// mdoc-only credential: doctype and namespace, no vct at all.
	md := `---
doctype: org.example.credentials.test
namespace: org.example.credentials.test
formats: mddl
---

# Test Credential

An mdoc-only credential with no sd-jwt counterpart.

## Claims

- ` + "`family_name`" + ` (string): Family name [mandatory]
`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte(md), 0o644))

	results, err := ConvertDir(dir, "https://example.com")
	require.NoError(t, err)
	require.NotEmpty(t, results, "doctype: alone should trigger conversion even with no vct:")

	assert.Equal(t, "test", results[0].Slug)
	assert.Contains(t, results[0].Files, "mddl")
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

func TestConvertDirPath_RestrictsToSubfolder(t *testing.T) {
	dir := t.TempDir()

	// Create a credential in root (should NOT be found when path is set)
	rootMD := "---\nvct: https://example.com/root\n---\n# Root Credential\n\n## Claims\n\n- `id` (string): ID\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.md"), []byte(rootMD), 0o644))

	// Create a credential in credentials/ (should be found)
	subDir := filepath.Join(dir, "credentials")
	require.NoError(t, os.MkdirAll(subDir, 0o755))
	subMD := "---\nvct: https://example.com/sub\n---\n# Sub Credential\n\n## Claims\n\n- `name` (string): Name\n"
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "sub.md"), []byte(subMD), 0o644))

	// With path restriction, only the subfolder credential should be found
	results, err := ConvertDirPath(dir, "credentials", "https://example.com")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "sub", results[0].Slug)
}

func TestConvertDirPath_EmptyPathScansAll(t *testing.T) {
	dir := t.TempDir()

	md := "---\nvct: https://example.com/test\n---\n# Test\n\n## Claims\n\n- `id` (string): ID\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.md"), []byte(md), 0o644))

	results, err := ConvertDirPath(dir, "", "https://example.com")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "test", results[0].Slug)
}

func TestConvertDirPath_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()

	tests := []string{
		"../etc",
		"foo/../../etc",
		"/absolute/path",
	}
	for _, p := range tests {
		_, err := ConvertDirPath(dir, p, "https://example.com")
		assert.Error(t, err, "expected error for path %q", p)
		assert.Contains(t, err.Error(), "relative path")
	}
}

func TestConvertDirPath_AllowsDotPrefixedDirs(t *testing.T) {
	dir := t.TempDir()

	// Create a ..cache directory (valid, not traversal)
	cacheDir := filepath.Join(dir, "..cache")
	require.NoError(t, os.MkdirAll(cacheDir, 0o755))

	// Should not error (even though no .md files exist)
	results, err := ConvertDirPath(dir, "..cache", "https://example.com")
	require.NoError(t, err)
	assert.Len(t, results, 0)
}
