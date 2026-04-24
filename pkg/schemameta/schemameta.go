// Package schemameta handles parsing, inference, and validation of TS11 SchemaMeta objects.
package schemameta

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// UUIDNamespace is the UUID v5 namespace for registry.siros.org schema IDs.
var UUIDNamespace = uuid.MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8") // DNS namespace

// SchemaMetaSource represents the manually-authored fields from schema-meta.yaml.
type SchemaMetaSource struct {
	AttestationLoS     string `yaml:"attestation_los" json:"attestationLoS"`
	BindingType        string `yaml:"binding_type" json:"bindingType"`
	Version            string `yaml:"version,omitempty" json:"version,omitempty"`
	TrustedAuthorities []any  `yaml:"trusted_authorities,omitempty" json:"trustedAuthorities,omitempty"`
	RulebookURI        string `yaml:"rulebook_uri,omitempty" json:"rulebookURI,omitempty"`
}

// SchemaURI represents a format-specific schema reference.
type SchemaURI struct {
	FormatIdentifier string `json:"formatIdentifier"`
	URI              string `json:"uri"`
}

// SchemaMeta is the full TS11 SchemaMeta object, combining authored and inferred fields.
type SchemaMeta struct {
	ID                 string      `json:"id"`
	Version            string      `json:"version"`
	AttestationLoS     string      `json:"attestationLoS"`
	BindingType        string      `json:"bindingType"`
	SupportedFormats   []string    `json:"supportedFormats"`
	SchemaURIs         []SchemaURI `json:"schemaURIs"`
	RulebookURI        string      `json:"rulebookURI,omitempty"`
	TrustedAuthorities []any       `json:"trustedAuthorities,omitempty"`
}

// FormatMapping maps file extensions to TS11 format identifiers.
var FormatMapping = map[string]string{
	".vctm.json": "dc+sd-jwt",
	".mdoc.json": "mso_mdoc",
	".vc.json":   "jwt_vc_json",
}

// LegacyVCTMExtensions lists file extensions that indicate a legacy VCTM file
// (JSON content) that can be used for credential discovery when no schema-meta exists.
var LegacyVCTMExtensions = []string{".vctm.json", ".vctm"}

// InferLegacy builds a SchemaMeta for a credential discovered via VCTM files
// only (no schema-meta.yaml). These will not pass TS11 validation.
func InferLegacy(org, slug, baseURL string, formats []string, formatFiles map[string]string) *SchemaMeta {
	sm := &SchemaMeta{
		ID:               GenerateID(org, slug),
		Version:          "0.1.0",
		SupportedFormats: formats,
	}

	for _, format := range formats {
		filename := filepath.Base(formatFiles[format])
		sm.SchemaURIs = append(sm.SchemaURIs, SchemaURI{
			FormatIdentifier: format,
			URI:              fmt.Sprintf("%s/%s/%s", baseURL, org, filename),
		})
	}

	return sm
}

// DetectLegacyCredentials scans a directory for VCTM files (.vctm.json or .vctm)
// that do NOT have a corresponding schema-meta file, returning their slugs.
func DetectLegacyCredentials(dir string, knownSlugs map[string]bool) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	seen := make(map[string]bool)
	var slugs []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		for _, ext := range LegacyVCTMExtensions {
			if strings.HasSuffix(name, ext) {
				slug := strings.TrimSuffix(name, ext)
				if slug == "" || knownSlugs[slug] || seen[slug] {
					continue
				}
				seen[slug] = true
				slugs = append(slugs, slug)
			}
		}
	}
	return slugs, nil
}

// ParseSource reads a schema-meta.yaml (or .json) file.
func ParseSource(path string) (*SchemaMetaSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading schema-meta: %w", err)
	}
	var src SchemaMetaSource
	if err := yaml.Unmarshal(data, &src); err != nil {
		return nil, fmt.Errorf("parsing schema-meta: %w", err)
	}
	return &src, nil
}

// GenerateID produces a deterministic UUID v5 from org/slug.
func GenerateID(org, slug string) string {
	name := fmt.Sprintf("https://registry.siros.org/%s/%s", org, slug)
	return uuid.NewSHA1(UUIDNamespace, []byte(name)).String()
}

// DetectFormats scans a directory for known credential format files matching a slug
// and returns the detected format identifiers and file paths.
// It checks FormatMapping extensions first, then falls back to bare .vctm extension.
func DetectFormats(dir, slug string) (formats []string, files map[string]string, err error) {
	files = make(map[string]string)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		for ext, format := range FormatMapping {
			if strings.HasSuffix(name, ext) {
				prefix := strings.TrimSuffix(name, ext)
				if prefix == slug {
					formats = append(formats, format)
					files[format] = filepath.Join(dir, name)
				}
			}
		}
	}

	// Also check for bare .vctm extension (legacy repos like SUNET/vc)
	if _, found := files["dc+sd-jwt"]; !found {
		bareVCTM := filepath.Join(dir, slug+".vctm")
		if _, statErr := os.Stat(bareVCTM); statErr == nil {
			formats = append(formats, "dc+sd-jwt")
			files["dc+sd-jwt"] = bareVCTM
		}
	}

	return formats, files, nil
}

// Infer builds a complete SchemaMeta from authored source fields, detected formats, and context.
func Infer(src *SchemaMetaSource, org, slug, baseURL string, formats []string, formatFiles map[string]string) *SchemaMeta {
	sm := &SchemaMeta{
		ID:                 GenerateID(org, slug),
		AttestationLoS:     src.AttestationLoS,
		BindingType:        src.BindingType,
		SupportedFormats:   formats,
		TrustedAuthorities: src.TrustedAuthorities,
	}

	// Version: from source, or default
	if src.Version != "" {
		sm.Version = src.Version
	} else {
		sm.Version = "0.1.0"
	}

	// SchemaURIs
	for _, format := range formats {
		filename := filepath.Base(formatFiles[format])
		sm.SchemaURIs = append(sm.SchemaURIs, SchemaURI{
			FormatIdentifier: format,
			URI:              fmt.Sprintf("%s/%s/%s", baseURL, org, filename),
		})
	}

	// RulebookURI
	if src.RulebookURI != "" {
		sm.RulebookURI = src.RulebookURI
	}

	return sm
}
