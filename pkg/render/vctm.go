package render

// VCTMData holds parsed SD-JWT VC Type Metadata content.
type VCTMData struct {
	VCT         string        `json:"vct,omitempty"`
	Name        string        `json:"name,omitempty"`
	Description string        `json:"description,omitempty"`
	Extends     string        `json:"extends,omitempty"`
	Display     []VCTMDisplay `json:"display,omitempty"`
	Claims      []VCTMClaim   `json:"claims,omitempty"`
}

// VCTMDisplay holds display properties for a VCTM credential.
type VCTMDisplay struct {
	Locale          string         `json:"locale,omitempty"`
	Name            string         `json:"name,omitempty"`
	Description     string         `json:"description,omitempty"`
	BackgroundColor string         `json:"background_color,omitempty"`
	TextColor       string         `json:"text_color,omitempty"`
	Logo            *VCTMImage     `json:"logo,omitempty"`
	BackgroundImage *VCTMImage     `json:"background_image,omitempty"`
	Rendering       *VCTMRendering `json:"rendering,omitempty"`
}

// VCTMImage holds image data (logo or background).
type VCTMImage struct {
	URI     string `json:"uri,omitempty"`
	AltText string `json:"alt_text,omitempty"`
}

// VCTMRendering holds rendering hints for a display entry.
type VCTMRendering struct {
	SVGTemplates []VCTMSVGTemplate `json:"svg_templates,omitempty"`
}

// VCTMSVGTemplate holds an SVG template reference.
type VCTMSVGTemplate struct {
	URI        string             `json:"uri,omitempty"`
	Properties *VCTMTemplateProps `json:"properties,omitempty"`
}

// VCTMTemplateProps describes SVG template rendering properties.
type VCTMTemplateProps struct {
	Orientation string `json:"orientation,omitempty"`
	ColorScheme string `json:"color_scheme,omitempty"`
	Contrast    string `json:"contrast,omitempty"`
}

// VCTMClaim holds a single claim definition.
type VCTMClaim struct {
	Path    []string           `json:"path"`
	Display []VCTMClaimDisplay `json:"display,omitempty"`
}

// VCTMClaimDisplay holds display info for a claim.
type VCTMClaimDisplay struct {
	Name   string `json:"name,omitempty"`
	Locale string `json:"locale,omitempty"`
}

// FormatInfo describes an available credential format file for download.
type FormatInfo struct {
	Name  string
	Label string
	File  string
}

// OrgData holds the data for rendering an organization page.
type OrgData struct {
	Name        string
	Credentials []CredentialData
}
