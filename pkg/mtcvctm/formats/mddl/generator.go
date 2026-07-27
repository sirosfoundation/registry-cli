// Package mddl provides the MDDL format generator for mso_mdoc credentials (ISO 18013-5)
package mddl

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/config"
	"github.com/sirosfoundation/registry-cli/pkg/mtcvctm/formats"
)

func init() {
	formats.Register(NewGenerator())
}

// Generator implements the MDDL format generator
type Generator struct{}

// NewGenerator creates a new MDDL generator
func NewGenerator() *Generator {
	return &Generator{}
}

// Name returns the format identifier
func (g *Generator) Name() string {
	return "mddl"
}

// Description returns a human-readable description
func (g *Generator) Description() string {
	return "mso_mdoc credential configuration (ISO 18013-5 / OpenID4VCI)"
}

// FileExtension returns the output file extension
func (g *Generator) FileExtension() string {
	return "mdoc.json"
}

// DeriveIdentifier derives the doctype from the parsed credential
func (g *Generator) DeriveIdentifier(parsed *formats.ParsedCredential, cfg *config.Config) string {
	// Check for explicit doctype
	if parsed.DocType != "" {
		return parsed.DocType
	}

	// Check format-specific override
	if overrides, ok := parsed.FormatOverrides["mddl"]; ok {
		if doctype, ok := overrides["doctype"].(string); ok && doctype != "" {
			return doctype
		}
	}

	// Derive from base URL (reverse domain notation)
	if cfg.BaseURL != "" && parsed.ID != "" {
		// https://registry.siros.org -> org.siros.registry.credentials.{id}
		baseURL := strings.TrimPrefix(cfg.BaseURL, "https://")
		baseURL = strings.TrimPrefix(baseURL, "http://")
		baseURL = strings.TrimSuffix(baseURL, "/")

		parts := strings.Split(baseURL, ".")
		// Reverse the parts
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}

		return strings.Join(parts, ".") + ".credentials." + parsed.ID
	}

	return ""
}

// deriveNamespace derives the namespace from doctype or config
func (g *Generator) deriveNamespace(parsed *formats.ParsedCredential, cfg *config.Config) string {
	// Check for explicit namespace
	if parsed.Namespace != "" {
		return parsed.Namespace
	}

	// Check format-specific override
	if overrides, ok := parsed.FormatOverrides["mddl"]; ok {
		if ns, ok := overrides["namespace"].(string); ok && ns != "" {
			return ns
		}
	}

	// Default to doctype (common pattern in mso_mdoc)
	return g.DeriveIdentifier(parsed, cfg)
}

// MDDL represents mso_mdoc credential configuration metadata
type MDDL struct {
	Format  string                     `json:"format"`
	DocType string                     `json:"doctype"`
	Display []DisplayProperties        `json:"display,omitempty"`
	Claims  map[string]NamespaceClaims `json:"claims,omitempty"`
	Order   *int                       `json:"order,omitempty"`
}

// DisplayProperties for credential display
type DisplayProperties struct {
	Locale          string `json:"locale"`
	Name            string `json:"name"`
	Description     string `json:"description,omitempty"`
	Logo            *Logo  `json:"logo,omitempty"`
	BackgroundColor string `json:"background_color,omitempty"`
	TextColor       string `json:"text_color,omitempty"`
}

// Logo information
type Logo struct {
	URI     string `json:"uri,omitempty"`
	AltText string `json:"alt_text,omitempty"`
}

// NamespaceClaims contains claims within a namespace
type NamespaceClaims map[string]ClaimMetadata

// ClaimMetadata contains metadata for an individual claim
type ClaimMetadata struct {
	Display   []ClaimDisplay           `json:"display,omitempty"`
	Mandatory bool                     `json:"mandatory,omitempty"`
	ValueType string                   `json:"value_type,omitempty"`
	Elements  map[string]ClaimMetadata `json:"elements,omitempty"`
}

// ClaimDisplay for claim-level display
type ClaimDisplay struct {
	Locale string `json:"locale"`
	Name   string `json:"name"`
}

// Generate produces the MDDL output
func (g *Generator) Generate(parsed *formats.ParsedCredential, cfg *config.Config) ([]byte, error) {
	doctype := g.DeriveIdentifier(parsed, cfg)
	namespace := g.deriveNamespace(parsed, cfg)

	if doctype == "" {
		return nil, fmt.Errorf("mddl: doctype is required (set doctype in front matter or provide base_url)")
	}

	mddl := &MDDL{
		Format:  "mso_mdoc",
		DocType: doctype,
	}

	// Add display properties
	if parsed.Name != "" || parsed.Description != "" {
		display := DisplayProperties{
			Locale:          cfg.Language,
			Name:            parsed.Name,
			Description:     parsed.Description,
			BackgroundColor: parsed.BackgroundColor,
			TextColor:       parsed.TextColor,
		}

		// Add logo
		if parsed.LogoPath != "" {
			display.Logo = &Logo{
				URI:     parsed.LogoPath,
				AltText: parsed.LogoAltText,
			}
		}

		mddl.Display = []DisplayProperties{display}

		// Add localizations
		for locale, loc := range parsed.Localizations {
			if locale == cfg.Language {
				continue
			}
			mddl.Display = append(mddl.Display, DisplayProperties{
				Locale:      locale,
				Name:        loc.Name,
				Description: loc.Description,
			})
		}
	}

	// Add claims grouped by namespace
	if len(parsed.Claims) > 0 {
		mddl.Claims = make(map[string]NamespaceClaims)
		mddl.Claims[namespace] = make(NamespaceClaims)

		flattenClaimsMDOC(parsed.Claims, mddl.Claims[namespace], cfg.Language, parsed.ClaimMappings)
	}

	// Check for order override
	if overrides, ok := parsed.FormatOverrides["mddl"]; ok {
		if order, ok := overrides["order"].(int); ok {
			mddl.Order = &order
		}
		if orderFloat, ok := overrides["order"].(float64); ok {
			orderInt := int(orderFloat)
			mddl.Order = &orderInt
		}
	}

	return json.MarshalIndent(mddl, "", "  ")
}

// mapTypeToCDDL maps markdown types to CDDL types
func mapTypeToCDDL(mdType string) string {
	switch strings.ToLower(mdType) {
	case "string":
		return "tstr"
	case "number":
		return "int"
	case "integer":
		return "uint"
	case "boolean", "bool":
		return "bool"
	case "date":
		return "full-date"
	case "datetime":
		return "tdate"
	case "image":
		return "bstr"
	case "object":
		return "map" // CDDL map — element shape described via "elements"
	case "array":
		return "array" // CDDL array — item shape described via "elements"
	default:
		return "tstr"
	}
}

// claimDisplay builds the localized display array for a single claim.
func claimDisplay(claim formats.ClaimDefinition, defaultLocale string) []ClaimDisplay {
	var displays []ClaimDisplay
	displayName := claim.DisplayName
	if displayName == "" {
		displayName = claim.Name
	}
	displays = append(displays, ClaimDisplay{
		Locale: defaultLocale,
		Name:   displayName,
	})
	for locale, loc := range claim.Localizations {
		if locale == defaultLocale {
			continue
		}
		label := loc.Label
		if label == "" {
			label = displayName
		}
		displays = append(displays, ClaimDisplay{
			Locale: locale,
			Name:   label,
		})
	}
	return displays
}

// isContainerClaim reports whether a claim represents a structured CBOR
// element (an mdoc "array" or "map") rather than a scalar leaf value.
func isContainerClaim(claim formats.ClaimDefinition) bool {
	t := strings.ToLower(claim.Type)
	return len(claim.Children) > 0 && (t == "object" || t == "array")
}

// mappedClaimName resolves a claim's element identifier, applying any
// per-format or per-credential mapping override.
func mappedClaimName(claim formats.ClaimDefinition, claimMappings map[string]map[string]string) string {
	claimName := claim.Name
	if mapping, ok := claim.FormatMappings["mddl"]; ok {
		claimName = mapping
	}
	if mappings, ok := claimMappings["mddl"]; ok {
		if mapped, ok := mappings[claim.Name]; ok {
			claimName = mapped
		}
	}
	return claimName
}

// buildElements produces the item/field shape for a container claim's
// children, keyed by their own (relative, non-prefixed) element name —
// ISO 18013-5 CDDL elements like driving_privileges must be encoded as a
// single array-of-records value, so children are described in place rather
// than being flattened into dotted sibling claims.
func buildElements(children []formats.ClaimDefinition, defaultLocale string, claimMappings map[string]map[string]string) map[string]ClaimMetadata {
	elements := make(map[string]ClaimMetadata, len(children))
	for _, child := range children {
		elements[mappedClaimName(child, claimMappings)] = claimMetadataFor(child, defaultLocale, claimMappings)
	}
	return elements
}

// claimMetadataFor builds the ClaimMetadata for a single claim, recursing
// into Elements when the claim is itself a container.
func claimMetadataFor(claim formats.ClaimDefinition, defaultLocale string, claimMappings map[string]map[string]string) ClaimMetadata {
	meta := ClaimMetadata{
		Mandatory: claim.Mandatory,
		ValueType: mapTypeToCDDL(claim.Type),
		Display:   claimDisplay(claim, defaultLocale),
	}
	if isContainerClaim(claim) {
		meta.Elements = buildElements(claim.Children, defaultLocale, claimMappings)
	}
	return meta
}

// flattenClaimsMDOC populates the mDOC namespace claims map from top-level
// claim definitions. Scalar claims become individual entries; container
// claims (object/array with children, e.g. "driving_privileges") become a
// single entry carrying their item shape under "elements" — they must be
// encoded as one CBOR element, not flattened into dotted leaf claims.
func flattenClaimsMDOC(claims []formats.ClaimDefinition, ns NamespaceClaims, defaultLocale string, claimMappings map[string]map[string]string) {
	for _, claim := range claims {
		ns[mappedClaimName(claim, claimMappings)] = claimMetadataFor(claim, defaultLocale, claimMappings)
	}
}
