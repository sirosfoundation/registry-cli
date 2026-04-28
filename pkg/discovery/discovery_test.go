package discovery

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
	assert.Equal(t, "github:topic/vctm?org=sirosfoundation", m.Sources[0].URL)
	assert.Equal(t, "git:https://github.com/example/repo.git", m.Sources[1].URL)
}

func TestLoadManifest_MixedFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sources.yaml")

	content := `sources:
  - git:https://github.com/org/repo.git
  - url: "file:///path/to/local"
    organization: "MyOrg"
  - url: "git:https://github.com/other/repo.git"
    organization: "CustomLabel"
defaults:
  branch: main
`
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	m, err := LoadManifest(path)
	require.NoError(t, err)
	assert.Equal(t, 3, len(m.Sources))

	// Plain string entry
	assert.Equal(t, "git:https://github.com/org/repo.git", m.Sources[0].URL)
	assert.Empty(t, m.Sources[0].Organization)

	// Struct entry with organization
	assert.Equal(t, "file:///path/to/local", m.Sources[1].URL)
	assert.Equal(t, "MyOrg", m.Sources[1].Organization)

	// Struct entry with git URL and org
	assert.Equal(t, "git:https://github.com/other/repo.git", m.Sources[2].URL)
	assert.Equal(t, "CustomLabel", m.Sources[2].Organization)
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
	assert.Equal(t, "", m.Defaults.Branch, "should default to empty (use repo default)")
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
		Sources:  []SourceEntry{{URL: "git:https://github.com/org/repo1.git"}, {URL: "git:https://github.com/org/repo2.git"}},
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

func TestResolveAll_ExplicitNoBranch(t *testing.T) {
	m := &SourceManifest{
		Sources: []SourceEntry{{URL: "git:https://github.com/org/repo1.git"}},
	}

	repos, err := ResolveAll(m, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(repos))
	assert.Equal(t, "", repos[0].Branch, "explicit entry with no default branch should have empty branch")
}

func TestResolveAll_MetaSource(t *testing.T) {
	m := &SourceManifest{
		Sources:  []SourceEntry{{URL: "test:discover"}},
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
		assert.Equal(t, "vctm", r.Branch, "empty branch from resolver should be filled with default")
	}
}

func TestResolveAll_MetaSourcePreservesResolverBranch(t *testing.T) {
	m := &SourceManifest{
		Sources:  []SourceEntry{{URL: "test:discover"}},
		Defaults: SourceDefaults{Branch: "vctm"},
	}

	resolver := &mockResolver{
		prefix: "test:",
		repos: []ResolvedRepo{
			{URL: "https://github.com/org/repo1.git", Branch: "main"},
			{URL: "https://github.com/org/repo2.git", Branch: "develop"},
		},
	}

	repos, err := ResolveAll(m, []Resolver{resolver})
	require.NoError(t, err)
	assert.Equal(t, 2, len(repos))
	assert.Equal(t, "main", repos[0].Branch, "resolver-provided branch should not be overridden")
	assert.Equal(t, "develop", repos[1].Branch, "resolver-provided branch should not be overridden")
}

func TestResolveAll_ExplicitTakesPrecedence(t *testing.T) {
	m := &SourceManifest{
		Sources: []SourceEntry{
			{URL: "git:https://github.com/org/repo1.git"},
			{URL: "test:discover"},
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
		Sources:  []SourceEntry{{URL: "unknown:something"}},
		Defaults: SourceDefaults{Branch: "vctm"},
	}

	_, err := ResolveAll(m, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no resolver")
}

func TestResolveAll_FileURL(t *testing.T) {
	m := &SourceManifest{
		Sources:  []SourceEntry{{URL: "file:///home/user/credentials"}},
		Defaults: SourceDefaults{Branch: "vctm"},
	}

	repos, err := ResolveAll(m, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(repos))
	assert.Equal(t, "file:///home/user/credentials", repos[0].URL)
	assert.Equal(t, "local", repos[0].Origin)
	assert.Equal(t, "", repos[0].Branch)
	assert.Equal(t, "Local", repos[0].Organization, "file:// sources default to 'Local' org")
}

func TestResolveAll_FileURLAndGit(t *testing.T) {
	m := &SourceManifest{
		Sources: []SourceEntry{
			{URL: "file:///home/user/credentials"},
			{URL: "git:https://github.com/org/repo.git"},
		},
		Defaults: SourceDefaults{Branch: "main"},
	}

	repos, err := ResolveAll(m, nil)
	require.NoError(t, err)
	assert.Equal(t, 2, len(repos))

	var local, remote *ResolvedRepo
	for i := range repos {
		if repos[i].Origin == "local" {
			local = &repos[i]
		} else {
			remote = &repos[i]
		}
	}
	require.NotNil(t, local)
	require.NotNil(t, remote)
	assert.Equal(t, "file:///home/user/credentials", local.URL)
	assert.Equal(t, "https://github.com/org/repo.git", remote.URL)
	assert.Equal(t, "main", remote.Branch)
}

func TestResolveAll_FileURLWithExplicitOrg(t *testing.T) {
	m := &SourceManifest{
		Sources:  []SourceEntry{{URL: "file:///data/creds", Organization: "CustomOrg"}},
		Defaults: SourceDefaults{Branch: "vctm"},
	}

	repos, err := ResolveAll(m, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(repos))
	assert.Equal(t, "CustomOrg", repos[0].Organization, "explicit org label overrides default")
}

func TestResolveAll_GitWithExplicitOrg(t *testing.T) {
	m := &SourceManifest{
		Sources:  []SourceEntry{{URL: "git:https://github.com/org/repo.git", Organization: "OverrideOrg"}},
		Defaults: SourceDefaults{Branch: "main"},
	}

	repos, err := ResolveAll(m, nil)
	require.NoError(t, err)
	require.Equal(t, 1, len(repos))
	assert.Equal(t, "OverrideOrg", repos[0].Organization)
}

func TestResolveAll_GitWithPerEntryBranch(t *testing.T) {
	m := &SourceManifest{
		Sources: []SourceEntry{
			{URL: "git:https://github.com/org/repo1.git", Branch: "vctm"},
			{URL: "git:https://github.com/org/repo2.git"},
		},
		Defaults: SourceDefaults{Branch: "main"},
	}

	repos, err := ResolveAll(m, nil)
	require.NoError(t, err)
	require.Equal(t, 2, len(repos))

	for _, r := range repos {
		if r.URL == "https://github.com/org/repo1.git" {
			assert.Equal(t, "vctm", r.Branch, "per-entry branch overrides default")
		} else {
			assert.Equal(t, "main", r.Branch, "entry without branch uses default")
		}
	}
}

func TestResolveAll_MetaSourceWithExplicitOrg(t *testing.T) {
	m := &SourceManifest{
		Sources:  []SourceEntry{{URL: "test:discover", Organization: "MetaOrg"}},
		Defaults: SourceDefaults{Branch: "vctm"},
	}

	resolver := &mockResolver{
		prefix: "test:",
		repos: []ResolvedRepo{
			{URL: "https://github.com/a/repo1.git"},
			{URL: "https://github.com/b/repo2.git"},
		},
	}

	repos, err := ResolveAll(m, []Resolver{resolver})
	require.NoError(t, err)
	assert.Equal(t, 2, len(repos))
	for _, r := range repos {
		assert.Equal(t, "MetaOrg", r.Organization, "all resolved repos should inherit the source org label")
	}
}

func TestSourceEntryUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantURL    string
		wantOrg    string
		wantBranch string
	}{
		{
			name:    "plain string",
			yaml:    `"git:https://example.com/repo.git"`,
			wantURL: "git:https://example.com/repo.git",
			wantOrg: "",
		},
		{
			name:    "struct with org",
			yaml:    "url: file:///data/creds\norganization: MyOrg",
			wantURL: "file:///data/creds",
			wantOrg: "MyOrg",
		},
		{
			name:    "struct without org",
			yaml:    "url: git:https://example.com/repo.git",
			wantURL: "git:https://example.com/repo.git",
			wantOrg: "",
		},
		{
			name:       "struct with branch",
			yaml:       "url: git:https://example.com/repo.git\nbranch: vctm",
			wantURL:    "git:https://example.com/repo.git",
			wantOrg:    "",
			wantBranch: "vctm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entry SourceEntry
			err := yaml.Unmarshal([]byte(tt.yaml), &entry)
			require.NoError(t, err)
			assert.Equal(t, tt.wantURL, entry.URL)
			assert.Equal(t, tt.wantOrg, entry.Organization)
			assert.Equal(t, tt.wantBranch, entry.Branch)
		})
	}
}

func TestResolveAll_FileURL_RelativePathRejected(t *testing.T) {
	m := &SourceManifest{
		Sources:  []SourceEntry{{URL: "file://relative/path"}},
		Defaults: SourceDefaults{Branch: "vctm"},
	}

	_, err := ResolveAll(m, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "absolute path")
}
