// Package repoplugin defines the interface for repository layout plugins.
//
// A repo plugin knows how to discover credentials from a particular repository
// directory layout. Different source repositories organize their credential
// schemas, metadata, and governance documents in different ways. Plugins
// abstract over these layout differences, presenting a uniform
// DiscoveredCredential to the build pipeline.
package repoplugin

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

// DiscoveredCredential is the uniform output from any layout plugin.
// It contains everything the pipeline needs regardless of source structure.
type DiscoveredCredential struct {
	// Org is the organization identifier (used in URLs and grouping).
	Org string

	// Slug is the credential slug (used in URLs and deterministic IDs).
	Slug string

	// SchemaMetaSource contains manually-authored governance metadata.
	// If nil, the credential will not pass TS11 validation (but may still
	// appear on the registry site as a legacy credential).
	SchemaMetaSource *schemameta.SchemaMetaSource

	// FormatFiles maps TS11 format identifiers to absolute file paths.
	// Keys: "dc+sd-jwt", "mso_mdoc", "jwt_vc_json"
	FormatFiles map[string]string

	// GeneratedVCTM holds synthesized VCTM JSON content when the plugin
	// generates it in-memory (e.g., from JSON Schema conversion) rather than
	// reading from an existing file.
	GeneratedVCTM []byte

	// GeneratedMdoc holds synthesized mDOC metadata JSON when generated
	// in-memory by the plugin.
	GeneratedMdoc []byte

	// RulebookPath is the absolute path to the rulebook source (markdown).
	// Empty if no rulebook is available.
	RulebookPath string

	// SourceURL is the repository URL for provenance tracking.
	SourceURL string

	// SourceRepo is the repository name.
	SourceRepo string
}

// Context provides plugins with the information they need for discovery.
type Context struct {
	// RepoDir is the root directory of the cloned or local repository.
	RepoDir string

	// SubPath is an optional relative path restriction within the repo.
	// If set, the plugin should only discover credentials under this path.
	SubPath string

	// Organization is the resolved organization name for this source.
	Organization string

	// BaseURL is the registry base URL for generating schema URIs.
	BaseURL string

	// Options contains source-level key-value options from sources.yaml.
	// Plugins parse their own options from this map.
	Options map[string]string

	// Logger for structured logging.
	Logger *slog.Logger
}

// Plugin discovers credentials from a repository directory.
// Each layout type implements this interface.
type Plugin interface {
	// Name returns the plugin identifier (e.g., "default", "rulebook-catalog").
	// This value is used in the "layout" field of sources.yaml entries.
	Name() string

	// Description returns a human-readable description of the layout this
	// plugin handles.
	Description() string

	// Discover scans the repository directory and returns all credentials
	// found according to the plugin's layout conventions.
	Discover(ctx Context) ([]DiscoveredCredential, error)
}

// Registry holds all registered repo plugins.
type Registry struct {
	mu      sync.RWMutex
	plugins map[string]Plugin
}

// NewRegistry creates a new plugin registry.
func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]Plugin),
	}
}

// Register adds a plugin to the registry.
func (r *Registry) Register(p Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugins[p.Name()] = p
}

// Get retrieves a plugin by name.
func (r *Registry) Get(name string) (Plugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[name]
	return p, ok
}

// List returns the names of all registered plugins.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.plugins))
	for name := range r.plugins {
		names = append(names, name)
	}
	return names
}

// DefaultRegistry is the global plugin registry.
var DefaultRegistry = NewRegistry()

// Register adds a plugin to the default registry.
func Register(p Plugin) {
	DefaultRegistry.Register(p)
}

// Get retrieves a plugin from the default registry.
func Get(name string) (Plugin, bool) {
	return DefaultRegistry.Get(name)
}

// MustGet retrieves a plugin or panics if not found.
func MustGet(name string) Plugin {
	p, ok := Get(name)
	if !ok {
		panic(fmt.Sprintf("repoplugin: plugin %q not registered", name))
	}
	return p
}
