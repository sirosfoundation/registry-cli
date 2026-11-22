package rulebookcatalog

import (
	"encoding/json"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/repoplugin"
)

// ebwoidLikeSchema mirrors the shape of ds001-ebwoid-sd-jwt.json: the
// prohibition on selective disclosure lives in the rulebook, so nothing in the
// schema's prose mentions disclosure at all.
const ebwoidLikeSchema = `{
	"$schema": "https://json-schema.org/draft/2020-12/schema",
	"title": "European Business Wallet - Owner Identification Data",
	"type": "object",
	"properties": {
		"vct": {"type": "string", "examples": ["uri:eu.ebw.oid.1"]},
		"id": {"type": "string", "description": "EUID where available."},
		"name": {"type": "string", "description": "Official name of the EBW owner."},
		"issuing_country": {"type": "string", "description": "ISO 3166-1 alpha-2 code."},
		"administrative_unit": {
			"type": "object",
			"description": "Nested holder, to exercise child claims.",
			"properties": {
				"vat_id": {"type": "string", "description": "VAT identification number."}
			}
		}
	},
	"required": ["vct", "id", "name"]
}`

func sdByPath(t *testing.T, out []byte) map[string]string {
	t.Helper()

	var doc struct {
		Claims []struct {
			Path []any  `json:"path"`
			SD   string `json:"sd"`
		} `json:"claims"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("parsing generated VCTM: %v", err)
	}

	got := make(map[string]string, len(doc.Claims))
	for _, claim := range doc.Claims {
		key := ""
		for i, part := range claim.Path {
			if i > 0 {
				key += "."
			}
			key += part.(string)
		}
		got[key] = claim.SD
	}

	return got
}

// Without an override, EBWOID publishes no sd at all, which SD-JWT VC section
// 9.3 reads as "allowed" - the opposite of what its rulebook requires. This is
// the behaviour the override exists to correct, so it is pinned here.
func TestConvert_WithoutOverride_LeavesEBWOIDDisclosureUnset(t *testing.T) {
	path := writeTempSchema(t, ebwoidLikeSchema)

	out, err := convertJSONSchemaToVCTM(path, "ebwoid", "https://registry.example.org", "example", nil, nil)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	for claim, sd := range sdByPath(t, out) {
		if sd != "" {
			t.Errorf("claim %q = %q, expected no sd without an override", claim, sd)
		}
	}
}

func TestConvert_DefaultOverride_AppliesToEveryClaim(t *testing.T) {
	path := writeTempSchema(t, ebwoidLikeSchema)

	override := &repoplugin.DisclosureOverride{Default: "never"}

	out, err := convertJSONSchemaToVCTM(path, "ebwoid", "https://registry.example.org", "example", nil, override)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	got := sdByPath(t, out)
	if len(got) == 0 {
		t.Fatal("no claims were generated")
	}

	for _, claim := range []string{"id", "name", "issuing_country", "administrative_unit", "administrative_unit.vat_id"} {
		sd, ok := got[claim]
		if !ok {
			t.Errorf("claim %q missing from the generated VCTM", claim)

			continue
		}

		if sd != "never" {
			t.Errorf("claim %q = %q, want never", claim, sd)
		}
	}
}

func TestConvert_ClaimOverride_BeatsDefaultAndDescription(t *testing.T) {
	// The description here asks for "always", so this also proves an explicit
	// override outranks what the prose implies.
	schema := `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"title": "Receipt",
		"type": "object",
		"properties": {
			"vct": {"type": "string", "examples": ["eu.we-build.ereceipt.1"]},
			"receipt_number": {"type": "string", "description": "Identifier. SHALL be selectively disclosable."},
			"total_vat_amount": {"type": "string", "description": "VAT total."}
		},
		"required": ["vct"]
	}`

	path := writeTempSchema(t, schema)

	override := &repoplugin.DisclosureOverride{
		Default: "never",
		Claims:  map[string]string{"receipt_number": "allowed"},
	}

	out, err := convertJSONSchemaToVCTM(path, "e-receipt", "https://registry.example.org", "example", nil, override)
	if err != nil {
		t.Fatalf("conversion failed: %v", err)
	}

	got := sdByPath(t, out)
	if got["receipt_number"] != "allowed" {
		t.Errorf("receipt_number = %q, want allowed (claim entry beats default and description)", got["receipt_number"])
	}

	if got["total_vat_amount"] != "never" {
		t.Errorf("total_vat_amount = %q, want never (default applies)", got["total_vat_amount"])
	}
}
