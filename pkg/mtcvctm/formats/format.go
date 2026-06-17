// Package formats provides the interface and registry for credential metadata format generators
package formats

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
)

// ParsedCredential represents format-agnostic parsed credential metadata
type ParsedCredential struct {
	// Core identifiers
	ID   string // Short identifier (derived from filename if not specified)
	Name string // Human-readable name

	// Format-specific identifiers (may be derived or explicit)
	VCT        string   // SD-JWT VC type identifier
	DocType    string   // mso_mdoc document type
	Namespace  string   // mso_mdoc namespace
	W3CTypes   []string // W3C VC type array
	W3CContext []string // W3C VC @context

	// Description
	Description string

	// Display properties
	BackgroundColor string
	TextColor       string
	LogoPath        string
	LogoAltText     string
	LogoAbsPath     string

	// SVG Template for rendering
	SVGTemplatePath      string
	SVGTemplateURI       string
	SVGTemplateIntegrity string

	// Source file info (for resolving relative paths)
	SourcePath string
	SourceDir  string

	// Generation options
	InlineImages bool

	// Localizations
	Localizations map[string]DisplayLocalization

	// Claims
	Claims []ClaimDefinition

	// Images
	Images []ImageRef

	// Format-specific overrides from front matter
	FormatOverrides map[string]map[string]interface{}

	// Claim mappings per format
	ClaimMappings map[string]map[string]string

	// Raw metadata from front matter
	Metadata map[string]interface{}

	// Formats is an optional per-credential format override (e.g. "sd-jwt,w3c").
	// When set, only the listed formats are generated for this credential.
	// When empty, the global config applies.
	Formats string
}

// DisplayLocalization contains localized display properties
type DisplayLocalization struct {
	Name        string
	Description string
}

// ClaimDefinition represents a format-agnostic claim
type ClaimDefinition struct {
	// Name is the claim identifier
	Name string

	// Path for nested claims (e.g., ["address", "street"])
	Path []string

	// DisplayName is the human-readable label
	DisplayName string

	// Type is the data type (string, number, boolean, date, datetime, image, object, array)
	Type string

	// Description of the claim
	Description string

	// Mandatory indicates if the claim is required
	Mandatory bool

	// SD indicates selective disclosure setting
	SD string

	// SvgId for SVG template reference
	SvgId string

	// Localizations per locale
	Localizations map[string]ClaimLocalization

	// FormatMappings maps format name to claim name override
	FormatMappings map[string]string
}

// ClaimLocalization contains localized claim display
type ClaimLocalization struct {
	Label       string
	Description string
}

// ImageRef represents an image reference
type ImageRef struct {
	Path         string
	AltText      string
	AbsolutePath string
}

// Generator is the interface for format-specific generators
type Generator interface {
	// Name returns the format identifier (e.g., "vctm", "mddl", "w3c")
	Name() string

	// Description returns a human-readable description of the format
	Description() string

	// FileExtension returns the output file extension (without dot)
	FileExtension() string

	// Generate produces the format-specific output
	Generate(parsed *ParsedCredential, cfg *config.Config) ([]byte, error)

	// DeriveIdentifier derives the format-specific ID from the parsed credential
	DeriveIdentifier(parsed *ParsedCredential, cfg *config.Config) string
}

// Registry holds all registered format generators
type Registry struct {
	mu         sync.RWMutex
	generators map[string]Generator
}

// NewRegistry creates a new format registry
func NewRegistry() *Registry {
	return &Registry{
		generators: make(map[string]Generator),
	}
}

// Register adds a generator to the registry
func (r *Registry) Register(g Generator) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.generators[g.Name()] = g
}

// Get retrieves a generator by name
func (r *Registry) Get(name string) (Generator, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	g, ok := r.generators[name]
	return g, ok
}

// List returns all registered format names
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.generators))
	for name := range r.generators {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// All returns all registered generators
func (r *Registry) All() []Generator {
	r.mu.RLock()
	defer r.mu.RUnlock()
	generators := make([]Generator, 0, len(r.generators))
	for _, g := range r.generators {
		generators = append(generators, g)
	}
	return generators
}

// ParseFormats parses a comma-separated format string into a list of format names
// "all" returns all registered formats
func (r *Registry) ParseFormats(formatStr string) ([]string, error) {
	formatStr = strings.TrimSpace(formatStr)
	if formatStr == "" || formatStr == "all" {
		return r.List(), nil
	}

	parts := strings.Split(formatStr, ",")
	formats := make([]string, 0, len(parts))

	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		name = ResolveAlias(name)
		if _, ok := r.Get(name); !ok {
			return nil, fmt.Errorf("unknown format: %s (available: %s)", name, strings.Join(r.List(), ", "))
		}
		formats = append(formats, name)
	}

	if len(formats) == 0 {
		return nil, fmt.Errorf("no valid formats specified")
	}

	return formats, nil
}

// DefaultRegistry is the global format registry
var DefaultRegistry = NewRegistry()

// Register adds a generator to the default registry
func Register(g Generator) {
	DefaultRegistry.Register(g)
}

// Get retrieves a generator from the default registry
func Get(name string) (Generator, bool) {
	return DefaultRegistry.Get(name)
}

// List returns all format names from the default registry
func List() []string {
	return DefaultRegistry.List()
}

// ParseFormats parses formats using the default registry
func ParseFormats(formatStr string) ([]string, error) {
	return DefaultRegistry.ParseFormats(formatStr)
}

// FormatJSON is a helper to marshal data as indented JSON
func FormatJSON(data interface{}) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}

// formatAliases maps user-friendly format names to internal registry names
var formatAliases = map[string]string{
	"sd-jwt": "vctm",
	"sdjwt":  "vctm",
	"mdoc":   "mddl",
	"mso_mdoc": "mddl",
}

// ResolveAlias maps a user-facing format name to its internal registry name.
// If no alias is defined the input is returned unchanged.
func ResolveAlias(name string) string {
	if alias, ok := formatAliases[strings.ToLower(name)]; ok {
		return alias
	}
	return name
}
