package discovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadManifest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.yaml")

	content := `sources:
  - github:topic/vctm?org=sirosfoundation
  - git:https://github.com/example/repo.git
defaults:
  branch: vctm
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	m, err := LoadManifest(path)
	require.NoError(t, err)
	assert.Equal(t, 2, len(m.Sources))
	assert.Equal(t, "vctm", m.Defaults.Branch)
	assert.Equal(t, "github:topic/vctm?org=sirosfoundation", m.Sources[0])
	assert.Equal(t, "git:https://github.com/example/repo.git", m.Sources[1])
}

func TestLoadManifest_DefaultBranch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.yaml")

	content := `sources:
  - git:https://github.com/example/repo.git
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	m, err := LoadManifest(path)
	require.NoError(t, err)
	assert.Equal(t, "vctm", m.Defaults.Branch, "should default to 'vctm'")
}

func TestLoadManifest_Empty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.yaml")

	content := `sources: []
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	_, err := LoadManifest(path)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no sources")
}

func TestLoadManifest_NotFound(t *testing.T) {
	_, err := LoadManifest("/nonexistent/sources.yaml")
	assert.Error(t, err)
}

// mockResolver is a test resolver that returns canned results.
type mockResolver struct {
	prefix string
	repos  []ResolvedRepo
}

func (r *mockResolver) Handles(source string) bool {
	return len(source) >= len(r.prefix) && source[:len(r.prefix)] == r.prefix
}

func (r *mockResolver) Resolve(source string) ([]ResolvedRepo, error) {
	return r.repos, nil
}

func TestResolveAll_ExplicitOnly(t *testing.T) {
	m := &SourceManifest{
		Sources:  []string{"git:https://github.com/org/repo1.git", "git:https://github.com/org/repo2.git"},
		Defaults: SourceDefaults{Branch: "vctm"},
	}

	repos, err := ResolveAll(m, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, len(repos))
	for _, r := range repos {
		assert.Equal(t, "explicit", r.Origin)
		assert.Equal(t, "vctm", r.Branch)
	}
}

func TestResolveAll_MetaSource(t *testing.T) {
	m := &SourceManifest{
		Sources:  []string{"test:discover"},
		Defaults: SourceDefaults{Branch: "vctm"},
	}

	resolver := &mockResolver{
		prefix: "test:",
		repos: []ResolvedRepo{
			{URL: "https://github.com/org/repo1.git"},
			{URL: "https://github.com/org/repo2.git"},
		},
	}

	repos, err := ResolveAll(m, []Resolver{resolver})
	require.NoError(t, err)
	assert.Equal(t, 2, len(repos))
	for _, r := range repos {
		assert.Equal(t, "test:discover", r.Origin)
		assert.Equal(t, "vctm", r.Branch)
	}
}

func TestResolveAll_ExplicitTakesPrecedence(t *testing.T) {
	m := &SourceManifest{
		Sources: []string{
			"git:https://github.com/org/repo1.git",
			"test:discover",
		},
		Defaults: SourceDefaults{Branch: "main"},
	}

	resolver := &mockResolver{
		prefix: "test:",
		repos: []ResolvedRepo{
			{URL: "https://github.com/org/repo1.git"}, // duplicate
			{URL: "https://github.com/org/repo2.git"},
		},
	}

	repos, err := ResolveAll(m, []Resolver{resolver})
	require.NoError(t, err)
	assert.Equal(t, 2, len(repos))

	// Find repo1 — should have "explicit" origin
	for _, r := range repos {
		if r.URL == "https://github.com/org/repo1.git" {
			assert.Equal(t, "explicit", r.Origin)
		}
	}
}

func TestResolveAll_UnknownScheme(t *testing.T) {
	m := &SourceManifest{
		Sources:  []string{"unknown:something"},
		Defaults: SourceDefaults{Branch: "vctm"},
	}

	_, err := ResolveAll(m, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no resolver")
}
