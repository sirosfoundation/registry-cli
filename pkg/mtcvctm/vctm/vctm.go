// Package vctm provides data structures and utilities for Verifiable Credential Type Metadata
// as specified in Section 6 of draft-ietf-oauth-sd-jwt-vc-12.
package vctm

import (
	"encoding/json"
	"fmt"
)

// VCTM represents a Verifiable Credential Type Metadata document
// as specified in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-12#section-6
type VCTM struct {
	// VCT is the Verifiable Credential Type identifier (REQUIRED)
	VCT string `json:"vct"`

	// Name is a human-readable name for the credential type, intended for developers
	Name string `json:"name,omitempty"`

	// Description is a human-readable description of the credential type, intended for developers
	Description string `json:"description,omitempty"`

	// Extends is a URI of another type that this type extends
	Extends string `json:"extends,omitempty"`

	// ExtendsIntegrity is the integrity hash for the extended type metadata document
	ExtendsIntegrity string `json:"extends#integrity,omitempty"`

	// Display contains display properties in different locales
	Display []DisplayProperties `json:"display,omitempty"`

	// Claims contains the metadata about claims in the credential (array with path)
	Claims []ClaimMetadataEntry `json:"claims,omitempty"`
}

// DisplayProperties contains locale-specific display information
type DisplayProperties struct {
	// Locale is the language tag (e.g., "en-US", "de-DE") - RFC 5646
	Locale string `json:"locale"`

	// Name is a human-readable name for the type, intended for end users (REQUIRED)
	Name string `json:"name,omitempty"`

	// Description is a human-readable description for end users
	Description string `json:"description,omitempty"`

	// Rendering contains rendering information for the type
	Rendering *Rendering `json:"rendering,omitempty"`
}

// Logo contains logo information
type Logo struct {
	// URI is the URI for the logo image (REQUIRED)
	URI string `json:"uri,omitempty"`

	// URIIntegrity contains the integrity hash for the logo URI
	URIIntegrity string `json:"uri#integrity,omitempty"`

	// AltText is alternative text for the logo
	AltText string `json:"alt_text,omitempty"`
}

// BackgroundImage contains background image information
type BackgroundImage struct {
	// URI is the URI pointing to the background image (REQUIRED)
	URI string `json:"uri,omitempty"`

	// URIIntegrity contains the integrity hash for the background image URI
	URIIntegrity string `json:"uri#integrity,omitempty"`
}

// ClaimMetadataEntry contains metadata about a specific claim with JSON path
type ClaimMetadataEntry struct {
	// Path is a non-empty array indicating the claim(s) being addressed (REQUIRED)
	// A string indicates a key, null indicates all array elements, integer indicates array index
	Path []interface{} `json:"path"`

	// Display contains display properties for this claim
	Display []ClaimDisplay `json:"display,omitempty"`

	// Description is a human-readable description of the claim (for developers)
	Description string `json:"description,omitempty"`

	// Mandatory indicates if the claim must be present in the issued credential
	Mandatory bool `json:"mandatory,omitempty"`

	// SD indicates if the claim is selectively disclosable: "always", "allowed", or "never"
	SD string `json:"sd,omitempty"`

	// SvgId is the ID of the claim for reference in SVG templates
	SvgId string `json:"svg_id,omitempty"`
}

// ClaimDisplay contains locale-specific display information for a claim
type ClaimDisplay struct {
	// Locale is the language tag (REQUIRED)
	Locale string `json:"locale"`

	// Label is the display label for the claim (REQUIRED)
	Label string `json:"label,omitempty"`

	// Description is the claim description
	Description string `json:"description,omitempty"`
}

// Rendering contains rendering hints for credential display
type Rendering struct {
	// Simple contains simple rendering hints
	Simple *SimpleRendering `json:"simple,omitempty"`

	// SVGTemplates contains SVG template rendering information
	SVGTemplates []SVGTemplate `json:"svg_templates,omitempty"`
}

// SimpleRendering contains simple rendering properties
type SimpleRendering struct {
	// Logo contains the logo for simple rendering
	Logo *Logo `json:"logo,omitempty"`

	// BackgroundImage contains the background image for the credential
	BackgroundImage *BackgroundImage `json:"background_image,omitempty"`

	// BackgroundColor is an RGB color value for the background
	BackgroundColor string `json:"background_color,omitempty"`

	// TextColor is an RGB color value for the text
	TextColor string `json:"text_color,omitempty"`
}

// SVGTemplate contains SVG template information
type SVGTemplate struct {
	// URI is the URI to the SVG template
	URI string `json:"uri,omitempty"`

	// URIIntegrity contains the integrity hash for the template URI
	URIIntegrity string `json:"uri#integrity,omitempty"`

	// Properties contains template properties
	Properties *SVGTemplateProperties `json:"properties,omitempty"`
}

// SVGTemplateProperties contains properties for SVG templates
type SVGTemplateProperties struct {
	// Orientation specifies the orientation (portrait, landscape)
	Orientation string `json:"orientation,omitempty"`

	// ColorScheme specifies the color scheme (light, dark)
	ColorScheme string `json:"color_scheme,omitempty"`

	// Contrast specifies the contrast level (normal, high)
	Contrast string `json:"contrast,omitempty"`
}

// Validate checks if the VCTM document is valid
func (v *VCTM) Validate() error {
	if v.VCT == "" {
		return fmt.Errorf("vctm: vct field is required")
	}
	return nil
}

// ToJSON serializes the VCTM to JSON
func (v *VCTM) ToJSON() ([]byte, error) {
	if err := v.Validate(); err != nil {
		return nil, err
	}
	return json.MarshalIndent(v, "", "  ")
}

// FromJSON deserializes VCTM from JSON
func FromJSON(data []byte) (*VCTM, error) {
	var vctm VCTM
	if err := json.Unmarshal(data, &vctm); err != nil {
		return nil, fmt.Errorf("vctm: failed to parse JSON: %w", err)
	}
	if err := vctm.Validate(); err != nil {
		return nil, err
	}
	return &vctm, nil
}
