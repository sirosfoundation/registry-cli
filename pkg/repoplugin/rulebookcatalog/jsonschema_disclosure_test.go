package rulebookcatalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeTempSchema writes a schema to a temporary file and returns its path.
func writeTempSchema(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "example-sd-jwt.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp schema: %v", err)
	}

	return path
}

// The descriptions below are taken verbatim from the WE BUILD attestation
// rulebooks catalogue, which is the corpus this inference actually runs
// against.
func TestDisclosureFor(t *testing.T) {
	tests := []struct {
		name        string
		description string
		want        string
	}{
		{
			// Previously reported "always": the prohibition contains the
			// phrase "selectively disclosable", so a bare substring match
			// published permission to do exactly what the schema forbids.
			name:        "prohibition with SHALL NOT",
			description: "Expiry date as a Unix timestamp (seconds since epoch). Represents the date and time when the attestation expires (ISO 8601 / RFC 7519). SHALL be later than 'iat'. SHALL NOT be selectively disclosable.",
			want:        "never",
		},
		{
			name:        "prohibition without a modal verb",
			description: "Identifier of the legal entity that issued the attestation. For EAA this is the subject entity. For QEAA this is the QTSP. NOT selectively disclosable.",
			want:        "never",
		},
		{
			name:        "prohibition in the plural",
			description: "These attributes are not selectively disclosable.",
			want:        "never",
		},
		{
			// Previously reported "always", which overstates a permission as
			// a requirement.
			name:        "permission with MAY",
			description: "Date until which the approval is valid (business validity, distinct from the technical exp claim). Optional. MAY be selectively disclosable.",
			want:        "allowed",
		},
		{
			// The unrelated "SHALL NOT be later than" must not be read as a
			// disclosure prohibition.
			name:        "permission alongside an unrelated SHALL NOT",
			description: "Date from which the approval is valid (RFC 3339 full-date). SHALL NOT be later than approval_valid_until when present. Mandatory. MAY be selectively disclosable.",
			want:        "allowed",
		},
		{
			name:        "requirement with SHALL",
			description: "Array of authorised person objects. SHALL contain at least one entry. Each entry represents a natural person authorised to act on behalf of the legal entity. SHALL be individually selectively disclosable as a top-level claim.",
			want:        "always",
		},
		{
			name:        "requirement with MUST and an SD claim marker",
			description: "Buyer-internal reference for the underlying commercial relationship (e.g. framework agreement number). Optional. MUST be selectively disclosable (SD claim).",
			want:        "always",
		},
		{
			name:        "requirement phrased as MUST make",
			description: "EN 16931 BG-16. Payment-related information. Contains sensitive payment data; issuer MUST make selectively disclosable. Section 2.3/2.4/3.2.",
			want:        "always",
		},
		{
			name:        "requirement wins over a trailing permission",
			description: "Array of contact person objects. The array itself SHALL be selectively disclosable as a top-level claim; individual objects within the array MAY also be individually disclosed.",
			want:        "always",
		},
		{
			name:        "describes the _sd array rather than a policy",
			description: "Array of disclosure strings for selectively disclosed claims",
			want:        "",
		},
		{
			name:        "says nothing about disclosure",
			description: "ISO 3166-1 alpha-2 code of the provider's country/territory.",
			want:        "",
		},
		{
			name:        "empty description",
			description: "",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := disclosureFor(tt.description); got != tt.want {
				t.Errorf("disclosureFor() = %q, want %q\ndescription: %s", got, tt.want, tt.description)
			}
		})
	}
}

func TestSchemaTypeUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{name: "single type", input: `"string"`, want: []string{"string"}},
		{name: "union type", input: `["string","null"]`, want: []string{"string", "null"}},
		{name: "empty array", input: `[]`, want: []string{}},
		{name: "rejects a number", input: `42`, wantErr: true},
		{name: "rejects an object", input: `{"a":1}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got schemaType
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %s, got %v", tt.input, got)
				}

				return
			}

			if err != nil {
				t.Fatalf("unmarshalling %s: %v", tt.input, err)
			}

			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}

			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// A union type anywhere in a schema used to fail the whole parse, which
// skipped the credential and removed the attestation from the catalogue.
func TestConvertJSONSchemaToVCTM_UnionTypeDoesNotSkipCredential(t *testing.T) {
	schema := `{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"title": "Union type attestation",
		"type": "object",
		"properties": {
			"vct": {"type": "string", "examples": ["uri:example.union.1"]},
			"voting_percentage": {
				"type": ["number", "null"],
				"description": "Share of votes held. SHALL NOT be selectively disclosable."
			}
		},
		"required": ["vct", "voting_percentage"]
	}`

	path := writeTempSchema(t, schema)

	out, err := convertJSONSchemaToVCTM(path, "union", "https://registry.example.org", "example", nil)
	if err != nil {
		t.Fatalf("conversion failed on a valid union type: %v", err)
	}

	var doc struct {
		VCT    string `json:"vct"`
		Claims []struct {
			Path []any  `json:"path"`
			SD   string `json:"sd"`
		} `json:"claims"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("parsing generated VCTM: %v", err)
	}

	if doc.VCT != "uri:example.union.1" {
		t.Errorf("vct = %q, want uri:example.union.1", doc.VCT)
	}

	var found bool
	for _, c := range doc.Claims {
		if len(c.Path) == 1 && c.Path[0] == "voting_percentage" {
			found = true

			if c.SD != "never" {
				t.Errorf("sd = %q, want never", c.SD)
			}
		}
	}

	if !found {
		t.Error("the union-typed claim is missing from the generated VCTM")
	}
}
