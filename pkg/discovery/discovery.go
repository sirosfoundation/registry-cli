package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/repoplugin"
	"gopkg.in/yaml.v3"
)

// SourceManifest is the top-level structure of a sources.yaml file.
type SourceManifest struct {
	Sources  []SourceEntry  `yaml:"sources"`
	Defaults SourceDefaults `yaml:"defaults"`
}

// SourceDefaults contains default settings applied to all resolved repos.
type SourceDefaults struct {
	Branch string `yaml:"branch"`
}

// SourceEntry represents a source in the manifest. It can be either a plain
// string URI or a struct with explicit organization and branch overrides.
//
// Plain string:
//
//	sources:
//	  - "git:https://github.com/org/repo.git"
//
// Struct with organization and branch:
//
//	sources:
//	  - url: "git:https://github.com/org/repo.git"
//	    organization: "MyOrg"
//	    branch: "vctm"
type SourceEntry struct {
	URL          string            `yaml:"url"`
	Organization string            `yaml:"organization,omitempty"`
	Branch       string            `yaml:"branch,omitempty"`
	Path         string            `yaml:"path,omitempty"`
	Layout       string            `yaml:"layout,omitempty"`
	Options      map[string]string `yaml:"options,omitempty"`

	// Credentials holds per-credential overrides, keyed by the slug the
	// layout derives. It carries facts the published repository does not
	// state in a machine-readable form, such as a disclosure policy that a
	// rulebook fixes in prose.
	Credentials map[string]repoplugin.CredentialOverride `yaml:"credentials,omitempty"`
}

// UnmarshalYAML allows SourceEntry to be parsed from either a plain string
// or a mapping with url and organization fields.
func (s *SourceEntry) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		s.URL = value.Value
		return nil
	}
	type plain SourceEntry
	return value.Decode((*plain)(s))
}

// ResolvedRepo is a concrete git repository to fetch credential data from.
type ResolvedRepo struct {
	URL          string            // git clone URL
	Branch       string            // branch to fetch from
	Origin       string            // how this repo was discovered (e.g. "explicit", "github:topic/vctm")
	Organization string            // explicit organization label (empty = infer from URL)
	Path         string            // optional relative path within the repo to restrict credential discovery
	Layout       string            // repo plugin layout name (empty = "default")
	Options      map[string]string // layout-specific options from sources.yaml

	// Credentials holds per-credential overrides from sources.yaml.
	Credentials map[string]repoplugin.CredentialOverride
}

// Resolver resolves meta-sources into concrete repos.
type Resolver interface {
	// Resolve takes a meta-source URI and returns the repos it resolves to.
	Resolve(source string) ([]ResolvedRepo, error)
	// Handles returns true if this resolver can handle the given source URI scheme.
	Handles(source string) bool
}

// LoadManifest reads and parses a sources.yaml file.
func LoadManifest(path string) (*SourceManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading sources manifest: %w", err)
	}
	var m SourceManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing sources manifest: %w", err)
	}
	if len(m.Sources) == 0 {
		return nil, fmt.Errorf("sources manifest has no sources")
	}
	if err := m.validate(); err != nil {
		return nil, fmt.Errorf("parsing sources manifest: %w", err)
	}
	return &m, nil
}

// validate checks the parts of the manifest that would otherwise fail late,
// or silently. A disclosure value reaches wallets as a claim-level
// instruction, so a typo is rejected here rather than published.
func (m *SourceManifest) validate() error {
	for _, entry := range m.Sources {
		slugs := make([]string, 0, len(entry.Credentials))
		for slug := range entry.Credentials {
			slugs = append(slugs, slug)
		}
		sort.Strings(slugs)

		for _, slug := range slugs {
			if err := entry.Credentials[slug].Disclosure.Validate(slug); err != nil {
				return err
			}
		}
	}

	return nil
}

// ResolveAll resolves all sources in a manifest into concrete repos using
// the provided resolvers. Explicit git: entries are resolved directly.
// Duplicate repos (same URL) are deduplicated, with explicit entries
// taking precedence over meta-source results.
func ResolveAll(manifest *SourceManifest, resolvers []Resolver) ([]ResolvedRepo, error) {
	explicit := make(map[string]ResolvedRepo)
	var discovered []ResolvedRepo

	for _, entry := range manifest.Sources {
		source := entry.URL

		if strings.HasPrefix(source, "git:") {
			url := strings.TrimPrefix(source, "git:")
			branch := entry.Branch
			if branch == "" {
				branch = manifest.Defaults.Branch
			}
			explicit[url] = ResolvedRepo{
				URL:          url,
				Branch:       branch,
				Origin:       "explicit",
				Organization: entry.Organization,
				Path:         entry.Path,
				Layout:       entry.Layout,
				Options:      entry.Options,
				Credentials:  entry.Credentials,
			}
			continue
		}

		if strings.HasPrefix(source, "file://") {
			localPath := strings.TrimPrefix(source, "file://")
			// Validate: resolve symlinks and ensure it's an absolute, clean path
			cleanPath := filepath.Clean(localPath)
			if !filepath.IsAbs(cleanPath) {
				return nil, fmt.Errorf("file:// source must be an absolute path: %q", source)
			}
			org := entry.Organization
			if org == "" {
				org = "Local"
			}
			explicit[source] = ResolvedRepo{
				URL:          source,
				Branch:       "",
				Origin:       "local",
				Organization: org,
				Path:         entry.Path,
				Layout:       entry.Layout,
				Options:      entry.Options,
				Credentials:  entry.Credentials,
			}
			continue
		}

		resolved := false
		for _, r := range resolvers {
			if r.Handles(source) {
				repos, err := r.Resolve(source)
				if err != nil {
					return nil, fmt.Errorf("resolving %q: %w", source, err)
				}
				for i := range repos {
					if repos[i].Branch == "" {
						repos[i].Branch = manifest.Defaults.Branch
					}
					repos[i].Origin = source
					if entry.Organization != "" {
						repos[i].Organization = entry.Organization
					}
					if entry.Path != "" {
						repos[i].Path = entry.Path
					}
					if entry.Layout != "" {
						repos[i].Layout = entry.Layout
					}
					if entry.Options != nil {
						repos[i].Options = entry.Options
					}
				}
				discovered = append(discovered, repos...)
				resolved = true
				break
			}
		}
		if !resolved {
			return nil, fmt.Errorf("no resolver for source %q", source)
		}
	}

	// Merge: explicit entries take precedence
	seen := make(map[string]bool)
	var result []ResolvedRepo

	for _, r := range explicit {
		result = append(result, r)
		seen[r.URL] = true
	}
	for _, r := range discovered {
		if !seen[r.URL] {
			result = append(result, r)
			seen[r.URL] = true
		}
	}

	return result, nil
}
