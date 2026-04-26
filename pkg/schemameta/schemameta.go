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

// TrustAuthority represents a trust framework reference per TS11 Section 4.3.3.
type TrustAuthority struct {
	FrameworkType string `yaml:"framework_type" json:"frameworkType"`
	Value         string `yaml:"value" json:"value"`
	IsLOTE        *bool  `yaml:"is_lote,omitempty" json:"isLOTE,omitempty"`
}

// SchemaMetaSource represents the manually-authored fields from schema-meta.yaml.
type SchemaMetaSource struct {
	AttestationLoS     string           `yaml:"attestation_los" json:"attestationLoS"`
	BindingType        string           `yaml:"binding_type" json:"bindingType"`
	Version            string           `yaml:"version,omitempty" json:"version,omitempty"`
	TrustedAuthorities []TrustAuthority `yaml:"trusted_authorities,omitempty" json:"trustedAuthorities,omitempty"`
	RulebookURI        string           `yaml:"rulebook_uri,omitempty" json:"rulebookURI,omitempty"`
}

// SchemaURI represents a format-specific schema reference (TS11 Section 4.3.2).
type SchemaURI struct {
	FormatIdentifier string `json:"formatIdentifier"`
	URI              string `json:"uri"`
}

// SchemaMeta is the full TS11 SchemaMeta object, combining authored and inferred fields.
type SchemaMeta struct {
	ID                 string           `json:"id"`
	Version            string           `json:"version"`
	AttestationLoS     string           `json:"attestationLoS"`
	BindingType        string           `json:"bindingType"`
	SupportedFormats   []string         `json:"supportedFormats"`
	SchemaURIs         []SchemaURI      `json:"schemaURIs"`
	RulebookURI        string           `json:"rulebookURI,omitempty"`
	TrustedAuthorities []TrustAuthority `json:"trustedAuthorities,omitempty"`
}

// FormatMapping maps file extensions to TS11 format identifiers.
var FormatMapping = map[string]string{
	".vctm.json": "dc+sd-jwt",
	".mdoc.json": "mso_mdoc",
	".vc.json":   "jwt_vc_json",
}

// ValidAttestationLoS lists the normative TS11 attestation LoS values.
var ValidAttestationLoS = map[string]bool{
	"iso_18045_high":           true,
	"iso_18045_moderate":       true,
	"iso_18045_enhanced-basic": true,
	"iso_18045_basic":          true,
}

// ValidBindingType lists the normative TS11 binding type values.
var ValidBindingType = map[string]bool{
	"claim":     true,
	"key":       true,
	"biometric": true,
	"none":      true,
}

// ValidSupportedFormat returns true if the format identifier is one of the
// normative TS11 supported formats.
var ValidSupportedFormats = map[string]bool{
	"dc+sd-jwt":      true,
	"mso_mdoc":       true,
	"jwt_vc_json":    true,
	"jwt_vc_json-ld": true,
	"ldp_vc":         true,
}

// ValidSupportedFormat checks whether a format string is in the normative enum.
func ValidSupportedFormat(f string) bool {
	return ValidSupportedFormats[f]
}

// NormalizeAttestationLoS maps legacy/friendly values to normative TS11 enum values.
func NormalizeAttestationLoS(v string) string {
	if ValidAttestationLoS[v] {
		return v
	}
	legacy := map[string]string{
		"high":           "iso_18045_high",
		"moderate":       "iso_18045_moderate",
		"substantial":    "iso_18045_moderate",
		"enhanced-basic": "iso_18045_enhanced-basic",
		"basic":          "iso_18045_basic",
		"low":            "iso_18045_basic",
	}
	if mapped, ok := legacy[strings.ToLower(v)]; ok {
		return mapped
	}
	return v
}

// NormalizeBindingType maps legacy/friendly values to normative TS11 enum values.
func NormalizeBindingType(v string) string {
	if ValidBindingType[v] {
		return v
	}
	legacy := map[string]string{
		"cnf":    "key",
		"holder": "key",
	}
	if mapped, ok := legacy[strings.ToLower(v)]; ok {
		return mapped
	}
	return v
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
// It checks FormatMapping extensions first, then falls back to bare .vctm extension,
// and finally checks for bare {slug}.json as a VCTM (dc+sd-jwt) file.
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

	// Check for bare {slug}.json as a VCTM file (repos like demo-credentials)
	if _, found := files["dc+sd-jwt"]; !found {
		bareJSON := filepath.Join(dir, slug+".json")
		if _, statErr := os.Stat(bareJSON); statErr == nil {
			formats = append(formats, "dc+sd-jwt")
			files["dc+sd-jwt"] = bareJSON
		}
	}

	return formats, files, nil
}

// Infer builds a complete SchemaMeta from authored source fields, detected formats, and context.
func Infer(src *SchemaMetaSource, org, slug, baseURL string, formats []string, formatFiles map[string]string) *SchemaMeta {
	sm := &SchemaMeta{
		ID:                 GenerateID(org, slug),
		AttestationLoS:     NormalizeAttestationLoS(src.AttestationLoS),
		BindingType:        NormalizeBindingType(src.BindingType),
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
