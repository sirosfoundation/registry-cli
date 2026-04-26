package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
// string URI or a struct with an explicit organization label.
//
// Plain string:
//
//	sources:
//	  - "git:https://github.com/org/repo.git"
//
// Struct with organization:
//
//	sources:
//	  - url: "file:///path/to/local/dir"
//	    organization: "MyOrg"
type SourceEntry struct {
	URL          string `yaml:"url"`
	Organization string `yaml:"organization,omitempty"`
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
	URL          string // git clone URL
	Branch       string // branch to fetch from
	Origin       string // how this repo was discovered (e.g. "explicit", "github:topic/vctm")
	Organization string // explicit organization label (empty = infer from URL)
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
	if m.Defaults.Branch == "" {
		m.Defaults.Branch = "vctm"
	}
	return &m, nil
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
			explicit[url] = ResolvedRepo{
				URL:          url,
				Branch:       manifest.Defaults.Branch,
				Origin:       "explicit",
				Organization: entry.Organization,
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
