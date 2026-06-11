package vctm

import (
	"encoding/json"
	"testing"
)

func TestVCTM_Validate(t *testing.T) {
	tests := []struct {
		name    string
		vctm    VCTM
		wantErr bool
	}{
		{
			name:    "empty vct",
			vctm:    VCTM{},
			wantErr: true,
		},
		{
			name: "valid minimal vctm",
			vctm: VCTM{
				VCT: "https://example.com/credential/test",
			},
			wantErr: false,
		},
		{
			name: "valid vctm with all fields",
			vctm: VCTM{
				VCT:         "https://example.com/credential/identity",
				Name:        "Identity Credential",
				Description: "A credential for identity verification",
				Display: []DisplayProperties{
					{
						Locale: "en-US",
						Name:   "Identity Credential",
					},
				},
				Claims: []ClaimMetadataEntry{
					{
						Path:      []interface{}{"given_name"},
						Mandatory: true,
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.vctm.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("VCTM.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVCTM_ToJSON(t *testing.T) {
	vctm := &VCTM{
		VCT:         "https://example.com/credential/test",
		Name:        "Test Credential",
		Description: "A test credential",
		Display: []DisplayProperties{
			{
				Locale:      "en-US",
				Name:        "Test Credential",
				Description: "A test credential for testing",
				Rendering: &Rendering{
					Simple: &SimpleRendering{
						Logo: &Logo{
							URI:     "https://example.com/logo.png",
							AltText: "Test Logo",
						},
						BackgroundColor: "#ffffff",
						TextColor:       "#000000",
					},
				},
			},
		},
		Claims: []ClaimMetadataEntry{
			{
				Path:      []interface{}{"given_name"},
				Mandatory: true,
				Display: []ClaimDisplay{
					{
						Locale: "en-US",
						Label:  "First Name",
					},
				},
			},
		},
	}

	data, err := vctm.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error = %v", err)
	}

	// Parse back and verify
	var parsed VCTM
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}

	if parsed.VCT != vctm.VCT {
		t.Errorf("VCT mismatch: got %v, want %v", parsed.VCT, vctm.VCT)
	}
	if parsed.Name != vctm.Name {
		t.Errorf("Name mismatch: got %v, want %v", parsed.Name, vctm.Name)
	}
}

func TestVCTM_ToJSON_Invalid(t *testing.T) {
	vctm := &VCTM{}
	_, err := vctm.ToJSON()
	if err == nil {
		t.Error("ToJSON() should fail for invalid VCTM")
	}
}

func TestFromJSON(t *testing.T) {
	jsonData := `{
		"vct": "https://example.com/credential/test",
		"name": "Test Credential",
		"description": "A test credential"
	}`

	vctm, err := FromJSON([]byte(jsonData))
	if err != nil {
		t.Fatalf("FromJSON() error = %v", err)
	}

	if vctm.VCT != "https://example.com/credential/test" {
		t.Errorf("VCT mismatch: got %v", vctm.VCT)
	}
	if vctm.Name != "Test Credential" {
		t.Errorf("Name mismatch: got %v", vctm.Name)
	}
}

func TestFromJSON_Invalid(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			name: "invalid json",
			json: `{invalid}`,
		},
		{
			name: "missing vct",
			json: `{"name": "Test"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := FromJSON([]byte(tt.json))
			if err == nil {
				t.Error("FromJSON() should fail for invalid input")
			}
		})
	}
}

func TestLogo_JSON(t *testing.T) {
	logo := &Logo{
		URI:          "https://example.com/logo.png",
		URIIntegrity: "sha256-abc123",
		AltText:      "My Logo",
	}

	data, err := json.Marshal(logo)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed Logo
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.URI != logo.URI {
		t.Errorf("URI mismatch: got %v, want %v", parsed.URI, logo.URI)
	}
}

func TestRendering_JSON(t *testing.T) {
	rendering := &Rendering{
		Simple: &SimpleRendering{
			Logo: &Logo{
				URI: "https://example.com/logo.png",
			},
			BackgroundColor: "#ffffff",
			TextColor:       "#000000",
		},
		SVGTemplates: []SVGTemplate{
			{
				URI:          "https://example.com/template.svg",
				URIIntegrity: "sha256-def456",
				Properties: &SVGTemplateProperties{
					Orientation: "portrait",
					ColorScheme: "light",
				},
			},
		},
	}

	data, err := json.Marshal(rendering)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var parsed Rendering
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if parsed.Simple.BackgroundColor != rendering.Simple.BackgroundColor {
		t.Errorf("BackgroundColor mismatch")
	}
	if len(parsed.SVGTemplates) != 1 {
		t.Errorf("SVGTemplates count mismatch")
	}
}
