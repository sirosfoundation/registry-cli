package discovery

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// SourceManifest is the top-level structure of a sources.yaml file.
type SourceManifest struct {
	Sources  []string       `yaml:"sources"`
	Defaults SourceDefaults `yaml:"defaults"`
}

// SourceDefaults contains default settings applied to all resolved repos.
type SourceDefaults struct {
	Branch string `yaml:"branch"`
}

// ResolvedRepo is a concrete git repository to fetch credential data from.
type ResolvedRepo struct {
	URL    string // git clone URL
	Branch string // branch to fetch from
	Origin string // how this repo was discovered (e.g. "explicit", "github:topic/vctm")
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

	for _, source := range manifest.Sources {
		if strings.HasPrefix(source, "git:") {
			url := strings.TrimPrefix(source, "git:")
			explicit[url] = ResolvedRepo{
				URL:    url,
				Branch: manifest.Defaults.Branch,
				Origin: "explicit",
			}
			continue
		}

		if strings.HasPrefix(source, "file://") {
			explicit[source] = ResolvedRepo{
				URL:    source,
				Branch: "",
				Origin: "local",
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
