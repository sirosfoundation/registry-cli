// Package ts11compliance provides a comprehensive test suite that verifies
// the registry-cli implementation against the normative requirements of
// ETSI TS11 "Specification of interfaces and formats for the catalogue of
// attributes and the catalogue of attestations", Sections 4.3 and 5 (read-only).
//
// Test organization follows the spec structure:
//
//   Section 4.3.1 — SchemaMeta main class data model
//   Section 4.3.2 — Schema sub-class
//   Section 4.3.3 — TrustAuthority sub-class
//   Section 4.3.4 — Format-specific data schemas
//   Section 5.2.1 — Query access (public, read-only)
//   Section 5.3.1 — GET /schemas (filtering, pagination)
//   Section 5.3.1 — GET /schemas/{schemaId}
//   Annex A.2   — JSON Schema validation
//   Annex A.3   — OpenAPI compliance
package ts11compliance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/registry-cli/pkg/apihandler"
	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

// ---------------------------------------------------------------------------
// Fixtures: a realistic catalogue with diverse attestation schemas covering
// every normative enum value and edge case.
// ---------------------------------------------------------------------------

func boolPtr(v bool) *bool { return &v }

// ts11Catalogue returns a catalogue with schemas exercising every normative
// enum and sub-class combination from TS11 Section 4.3.
func ts11Catalogue() []*schemameta.SchemaMeta {
	return []*schemameta.SchemaMeta{
		{
			// Schema 1: QEAA-level PID with high LoS, key binding, dual format, ETSI TL trust
			ID:             "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
			Version:        "1.0.0",
			AttestationLoS: "iso_18045_high",
			BindingType:    "key",
			RulebookURI:    "https://rulebooks.example.eu/pid/v1#sha256-abc123",
			SupportedFormats: []string{"dc+sd-jwt", "mso_mdoc"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://catalogue.example.eu/schemas/pid-sdjwt.json"},
				{FormatIdentifier: "mso_mdoc", URI: "https://catalogue.example.eu/schemas/pid-mdoc.json"},
			},
			TrustedAuthorities: []schemameta.TrustAuthority{
				{FrameworkType: "etsi_tl", Value: "https://ec.europa.eu/tools/lotl/eu-lotl.xml", IsLOTE: boolPtr(false)},
			},
		},
		{
			// Schema 2: EAA with moderate LoS, claim binding, single format, OpenID Federation trust
			ID:             "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
			Version:        "2.1.0",
			AttestationLoS: "iso_18045_moderate",
			BindingType:    "claim",
			RulebookURI:    "https://rulebooks.example.eu/diploma/v2",
			SupportedFormats: []string{"jwt_vc_json"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "jwt_vc_json", URI: "https://catalogue.example.eu/schemas/diploma-vc.json"},
			},
			TrustedAuthorities: []schemameta.TrustAuthority{
				{FrameworkType: "openid_federation", Value: "https://federation.example.eu"},
			},
		},
		{
			// Schema 3: Enhanced-basic LoS, biometric binding, ldp_vc format, AKI trust
			ID:             "cccccccc-cccc-cccc-cccc-cccccccccccc",
			Version:        "1.0.0",
			AttestationLoS: "iso_18045_enhanced-basic",
			BindingType:    "biometric",
			RulebookURI:    "https://rulebooks.example.eu/ehic/v1",
			SupportedFormats: []string{"ldp_vc"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "ldp_vc", URI: "https://catalogue.example.eu/schemas/ehic-ldp.json"},
			},
			TrustedAuthorities: []schemameta.TrustAuthority{
				{FrameworkType: "aki", Value: "dGVzdC1ha2ktdmFsdWU="},
			},
		},
		{
			// Schema 4: Basic LoS, no binding, jwt_vc_json-ld, LoTE trusted list, multi-format
			ID:             "dddddddd-dddd-dddd-dddd-dddddddddddd",
			Version:        "0.9.0",
			AttestationLoS: "iso_18045_basic",
			BindingType:    "none",
			RulebookURI:    "https://rulebooks.example.eu/demo/v1",
			SupportedFormats: []string{"jwt_vc_json-ld", "dc+sd-jwt"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "jwt_vc_json-ld", URI: "https://catalogue.example.eu/schemas/demo-vcld.json"},
				{FormatIdentifier: "dc+sd-jwt", URI: "https://catalogue.example.eu/schemas/demo-sdjwt.json"},
			},
			TrustedAuthorities: []schemameta.TrustAuthority{
				{FrameworkType: "etsi_tl", Value: "https://lote.example.eu/trusted-entities", IsLOTE: boolPtr(true)},
			},
		},
		{
			// Schema 5: High LoS, key binding, all five formats, multiple trust authorities
			ID:             "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee",
			Version:        "3.0.0",
			AttestationLoS: "iso_18045_high",
			BindingType:    "key",
			RulebookURI:    "https://rulebooks.example.eu/multiformat/v3",
			SupportedFormats: []string{"dc+sd-jwt", "mso_mdoc", "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://catalogue.example.eu/schemas/multi-sdjwt.json"},
				{FormatIdentifier: "mso_mdoc", URI: "https://catalogue.example.eu/schemas/multi-mdoc.json"},
				{FormatIdentifier: "jwt_vc_json", URI: "https://catalogue.example.eu/schemas/multi-vc.json"},
				{FormatIdentifier: "jwt_vc_json-ld", URI: "https://catalogue.example.eu/schemas/multi-vcld.json"},
				{FormatIdentifier: "ldp_vc", URI: "https://catalogue.example.eu/schemas/multi-ldp.json"},
			},
			TrustedAuthorities: []schemameta.TrustAuthority{
				{FrameworkType: "etsi_tl", Value: "https://ec.europa.eu/tools/lotl/eu-lotl.xml", IsLOTE: boolPtr(false)},
				{FrameworkType: "aki", Value: "bXVsdGktYWtpLXZhbHVl"},
				{FrameworkType: "openid_federation", Value: "https://federation.example.eu"},
			},
		},
	}
}

func setupTS11(t *testing.T) *http.ServeMux {
	t.Helper()
	h := apihandler.New(ts11Catalogue(), nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

func doGET(t *testing.T, mux *http.ServeMux, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func parsePaginatedList(t *testing.T, w *httptest.ResponseRecorder) apihandler.PaginatedSchemaList {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, "expected 200 OK, body: %s", w.Body.String())
	var result apihandler.PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	return result
}

func parseSchemaMeta(t *testing.T, w *httptest.ResponseRecorder) schemameta.SchemaMeta {
	t.Helper()
	require.Equal(t, http.StatusOK, w.Code, "expected 200 OK, body: %s", w.Body.String())
	var sm schemameta.SchemaMeta
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &sm))
	return sm
}

func schemaIDs(schemas []*schemameta.SchemaMeta) []string {
	ids := make([]string, len(schemas))
	for i, s := range schemas {
		ids[i] = s.ID
	}
	return ids
}

// ===========================================================================
// Section 4.3.1: SchemaMeta main class — data model validation
// ===========================================================================

func TestTS11_4_3_1_SchemaMetaRequiredFields(t *testing.T) {
	// TS11 §4.3.1: SchemaMeta SHALL have version, rulebookURI, attestationLoS,
	// bindingType, supportedFormats [1..*], schemaURIs [1..*].
	// id is server-assigned (readOnly).
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	t.Run("all required fields present", func(t *testing.T) {
		sm := &schemameta.SchemaMeta{
			ID:               schemameta.GenerateID("org", "slug"),
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
			RulebookURI:      "https://example.com/rulebook",
			SupportedFormats: []string{"dc+sd-jwt"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
			},
		}
		assert.NoError(t, v.Validate(sm))
	})

	t.Run("missing version", func(t *testing.T) {
		sm := &schemameta.SchemaMeta{
			ID:               schemameta.GenerateID("org", "slug"),
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
			RulebookURI:      "https://example.com/rulebook",
			SupportedFormats: []string{"dc+sd-jwt"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
			},
		}
		assert.Error(t, v.Validate(sm))
	})

	t.Run("missing attestationLoS", func(t *testing.T) {
		sm := &schemameta.SchemaMeta{
			ID:               schemameta.GenerateID("org", "slug"),
			Version:          "1.0.0",
			BindingType:      "key",
			RulebookURI:      "https://example.com/rulebook",
			SupportedFormats: []string{"dc+sd-jwt"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
			},
		}
		assert.Error(t, v.Validate(sm))
	})

	t.Run("missing bindingType", func(t *testing.T) {
		sm := &schemameta.SchemaMeta{
			ID:               schemameta.GenerateID("org", "slug"),
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			RulebookURI:      "https://example.com/rulebook",
			SupportedFormats: []string{"dc+sd-jwt"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
			},
		}
		assert.Error(t, v.Validate(sm))
	})

	t.Run("missing rulebookURI", func(t *testing.T) {
		sm := &schemameta.SchemaMeta{
			ID:               schemameta.GenerateID("org", "slug"),
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
			SupportedFormats: []string{"dc+sd-jwt"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
			},
		}
		assert.Error(t, v.Validate(sm))
	})

	t.Run("missing supportedFormats", func(t *testing.T) {
		sm := &schemameta.SchemaMeta{
			ID:             schemameta.GenerateID("org", "slug"),
			Version:        "1.0.0",
			AttestationLoS: "iso_18045_high",
			BindingType:    "key",
			RulebookURI:    "https://example.com/rulebook",
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
			},
		}
		assert.Error(t, v.Validate(sm))
	})

	t.Run("empty supportedFormats", func(t *testing.T) {
		sm := &schemameta.SchemaMeta{
			ID:               schemameta.GenerateID("org", "slug"),
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
			RulebookURI:      "https://example.com/rulebook",
			SupportedFormats: []string{},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
			},
		}
		assert.Error(t, v.Validate(sm))
	})

	t.Run("missing schemaURIs", func(t *testing.T) {
		sm := &schemameta.SchemaMeta{
			ID:               schemameta.GenerateID("org", "slug"),
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
			RulebookURI:      "https://example.com/rulebook",
			SupportedFormats: []string{"dc+sd-jwt"},
		}
		assert.Error(t, v.Validate(sm))
	})

	t.Run("empty schemaURIs", func(t *testing.T) {
		sm := &schemameta.SchemaMeta{
			ID:               schemameta.GenerateID("org", "slug"),
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
			RulebookURI:      "https://example.com/rulebook",
			SupportedFormats: []string{"dc+sd-jwt"},
			SchemaURIs:       []schemameta.SchemaURI{},
		}
		assert.Error(t, v.Validate(sm))
	})
}

func TestTS11_4_3_1_AttestationLoSEnumValues(t *testing.T) {
	// TS11 §4.3.1: attestationLoS allowed values are exactly:
	// iso_18045_high, iso_18045_moderate, iso_18045_enhanced-basic, iso_18045_basic
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	validValues := []string{
		"iso_18045_high",
		"iso_18045_moderate",
		"iso_18045_enhanced-basic",
		"iso_18045_basic",
	}
	for _, val := range validValues {
		t.Run("valid_"+val, func(t *testing.T) {
			sm := validSchemaMeta()
			sm.AttestationLoS = val
			assert.NoError(t, v.Validate(sm), "attestationLoS=%q should be valid", val)
		})
	}

	invalidValues := []string{"high", "low", "moderate", "substantial", "basic", "enhanced-basic", ""}
	for _, val := range invalidValues {
		t.Run("invalid_"+val, func(t *testing.T) {
			sm := validSchemaMeta()
			sm.AttestationLoS = val
			assert.Error(t, v.Validate(sm), "attestationLoS=%q should be rejected", val)
		})
	}
}

func TestTS11_4_3_1_BindingTypeEnumValues(t *testing.T) {
	// TS11 §4.3.1: bindingType allowed values are exactly:
	// claim, key, biometric, none
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	validValues := []string{"claim", "key", "biometric", "none"}
	for _, val := range validValues {
		t.Run("valid_"+val, func(t *testing.T) {
			sm := validSchemaMeta()
			sm.BindingType = val
			assert.NoError(t, v.Validate(sm), "bindingType=%q should be valid", val)
		})
	}

	invalidValues := []string{"cnf", "holder", "symmetric", ""}
	for _, val := range invalidValues {
		t.Run("invalid_"+val, func(t *testing.T) {
			sm := validSchemaMeta()
			sm.BindingType = val
			assert.Error(t, v.Validate(sm), "bindingType=%q should be rejected", val)
		})
	}
}

func TestTS11_4_3_1_SupportedFormatsEnumValues(t *testing.T) {
	// TS11 §4.3.1: supportedFormats values from:
	// dc+sd-jwt, mso_mdoc, jwt_vc_json, jwt_vc_json-ld, ldp_vc
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	validFormats := []string{"dc+sd-jwt", "mso_mdoc", "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"}
	for _, fmt := range validFormats {
		t.Run("valid_"+fmt, func(t *testing.T) {
			sm := validSchemaMeta()
			sm.SupportedFormats = []string{fmt}
			sm.SchemaURIs = []schemameta.SchemaURI{
				{FormatIdentifier: fmt, URI: "https://example.com/schema.json"},
			}
			assert.NoError(t, v.Validate(sm), "format=%q should be valid", fmt)
		})
	}

	t.Run("invalid format rejected", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.SupportedFormats = []string{"invalid_format"}
		assert.Error(t, v.Validate(sm), "invalid format should be rejected")
	})

	t.Run("multiple formats allowed", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.SupportedFormats = []string{"dc+sd-jwt", "mso_mdoc", "jwt_vc_json", "jwt_vc_json-ld", "ldp_vc"}
		sm.SchemaURIs = []schemameta.SchemaURI{
			{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/s1.json"},
			{FormatIdentifier: "mso_mdoc", URI: "https://example.com/s2.json"},
			{FormatIdentifier: "jwt_vc_json", URI: "https://example.com/s3.json"},
			{FormatIdentifier: "jwt_vc_json-ld", URI: "https://example.com/s4.json"},
			{FormatIdentifier: "ldp_vc", URI: "https://example.com/s5.json"},
		}
		assert.NoError(t, v.Validate(sm))
	})
}

func TestTS11_4_3_1_RulebookURIIntegrityHash(t *testing.T) {
	// TS11 §4.3.1: rulebookURI MAY be suffixed with #integrity (W3C SRI)
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	sm := validSchemaMeta()
	sm.RulebookURI = "https://rulebooks.example.eu/pid/v1#sha256-abc123def456"
	assert.NoError(t, v.Validate(sm), "rulebookURI with integrity suffix should be valid")
}

func TestTS11_4_3_1_TrustedAuthoritiesOptional(t *testing.T) {
	// TS11 §4.3.1: trustedAuthorities is [0..*] — optional
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	t.Run("absent", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = nil
		assert.NoError(t, v.Validate(sm))
	})

	t.Run("empty array", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = []schemameta.TrustAuthority{}
		assert.NoError(t, v.Validate(sm))
	})
}

func TestTS11_4_3_1_AdditionalPropertiesForbidden(t *testing.T) {
	// TS11 Annex A.2: additionalProperties: false on SchemaMeta
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	sm := validSchemaMeta()
	// Marshal, inject extra field, validate
	data, err := json.Marshal(sm)
	require.NoError(t, err)
	var obj map[string]any
	require.NoError(t, json.Unmarshal(data, &obj))
	obj["extraField"] = "should be rejected"

	// Validate raw object against schema
	assert.Error(t, v.ValidateRaw(obj), "additional properties should be rejected")
}

// ===========================================================================
// Section 4.3.2: Schema sub-class
// ===========================================================================

func TestTS11_4_3_2_SchemaRequiredFields(t *testing.T) {
	// TS11 §4.3.2: Schema SHALL have formatIdentifier [1..1] and uri [1..1]
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	t.Run("valid schema entry", func(t *testing.T) {
		sm := validSchemaMeta()
		assert.NoError(t, v.Validate(sm))
	})

	t.Run("formatIdentifier enum validated", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.SchemaURIs = []schemameta.SchemaURI{
			{FormatIdentifier: "invalid_format", URI: "https://example.com/schema.json"},
		}
		assert.Error(t, v.Validate(sm), "invalid formatIdentifier should be rejected")
	})
}

func TestTS11_4_3_2_SchemaURIIntegrityHash(t *testing.T) {
	// TS11 §4.3.2: uri MAY be suffixed with #integrity (W3C SRI)
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	sm := validSchemaMeta()
	sm.SchemaURIs = []schemameta.SchemaURI{
		{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json#sha256-integrity"},
	}
	assert.NoError(t, v.Validate(sm), "schema URI with integrity suffix should be valid")
}

// ===========================================================================
// Section 4.3.3: TrustAuthority sub-class
// ===========================================================================

func TestTS11_4_3_3_TrustAuthorityRequiredFields(t *testing.T) {
	// TS11 §4.3.3: frameworkType [1..1] and value [1..1] are required
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	t.Run("valid trust authority", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = []schemameta.TrustAuthority{
			{FrameworkType: "etsi_tl", Value: "https://example.com/tl"},
		}
		assert.NoError(t, v.Validate(sm))
	})

	t.Run("missing frameworkType", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = []schemameta.TrustAuthority{
			{Value: "https://example.com/tl"},
		}
		assert.Error(t, v.Validate(sm), "missing frameworkType should be rejected")
	})

	t.Run("missing value", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = []schemameta.TrustAuthority{
			{FrameworkType: "etsi_tl"},
		}
		assert.Error(t, v.Validate(sm), "missing value should be rejected")
	})
}

func TestTS11_4_3_3_FrameworkTypeEnumValues(t *testing.T) {
	// TS11 §4.3.3: frameworkType from: aki, etsi_tl, openid_federation
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	validTypes := []string{"aki", "etsi_tl", "openid_federation"}
	for _, ft := range validTypes {
		t.Run("valid_"+ft, func(t *testing.T) {
			sm := validSchemaMeta()
			sm.TrustedAuthorities = []schemameta.TrustAuthority{
				{FrameworkType: ft, Value: "https://example.com/trust"},
			}
			assert.NoError(t, v.Validate(sm))
		})
	}

	t.Run("invalid frameworkType rejected", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = []schemameta.TrustAuthority{
			{FrameworkType: "x509", Value: "https://example.com/trust"},
		}
		assert.Error(t, v.Validate(sm))
	})
}

func TestTS11_4_3_3_IsLOTEOptional(t *testing.T) {
	// TS11 §4.3.3: isLOTE [0..1] — optional, only applicable to etsi_tl
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	t.Run("isLOTE true for etsi_tl", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = []schemameta.TrustAuthority{
			{FrameworkType: "etsi_tl", Value: "https://lote.example.eu/list", IsLOTE: boolPtr(true)},
		}
		assert.NoError(t, v.Validate(sm))
	})

	t.Run("isLOTE false for etsi_tl", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = []schemameta.TrustAuthority{
			{FrameworkType: "etsi_tl", Value: "https://tl.example.eu/list", IsLOTE: boolPtr(false)},
		}
		assert.NoError(t, v.Validate(sm))
	})

	t.Run("isLOTE absent for aki", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = []schemameta.TrustAuthority{
			{FrameworkType: "aki", Value: "dGVzdA=="},
		}
		assert.NoError(t, v.Validate(sm))
	})
}

func TestTS11_4_3_3_MultipleTrustAuthorities(t *testing.T) {
	// TS11 §4.3.3: trustedAuthorities [0..*] — multiple allowed
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	sm := validSchemaMeta()
	sm.TrustedAuthorities = []schemameta.TrustAuthority{
		{FrameworkType: "etsi_tl", Value: "https://ec.europa.eu/tools/lotl/eu-lotl.xml", IsLOTE: boolPtr(false)},
		{FrameworkType: "aki", Value: "dGVzdC1ha2ktdmFsdWU="},
		{FrameworkType: "openid_federation", Value: "https://federation.example.eu"},
	}
	assert.NoError(t, v.Validate(sm))
}

func TestTS11_4_3_3_TrustAuthorityAdditionalPropertiesForbidden(t *testing.T) {
	// TS11 Annex A.2: additionalProperties: false on TrustAuthority
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	sm := validSchemaMeta()
	data, _ := json.Marshal(sm)
	var obj map[string]any
	_ = json.Unmarshal(data, &obj)

	// Inject extra field into trustedAuthorities
	obj["trustedAuthorities"] = []map[string]any{
		{
			"frameworkType": "etsi_tl",
			"value":         "https://example.com/tl",
			"extraField":    "should be rejected",
		},
	}
	assert.Error(t, v.ValidateRaw(obj), "additional properties in TrustAuthority should be rejected")
}

// ===========================================================================
// Section 4.3.4: Format-specific data schemas
// ===========================================================================

func TestTS11_4_3_4_FormatMappingCovers(t *testing.T) {
	// TS11 §4.3.4: SD-JWT VC → dc+sd-jwt, ISO mDoc → mso_mdoc, W3C VC → jwt_vc_json
	expected := map[string]string{
		".vctm.json": "dc+sd-jwt",
		".mdoc.json": "mso_mdoc",
		".vc.json":   "jwt_vc_json",
	}
	for ext, format := range expected {
		assert.Equal(t, format, schemameta.FormatMapping[ext], "extension %q should map to %q", ext, format)
	}
}

// ===========================================================================
// Section 4.3.1: Legacy value normalization (backward compatibility)
// ===========================================================================

func TestTS11_LegacyNormalization_AttestationLoS(t *testing.T) {
	// Non-normative legacy values SHOULD be mapped to normative equivalents
	cases := []struct {
		legacy, normative string
	}{
		{"high", "iso_18045_high"},
		{"moderate", "iso_18045_moderate"},
		{"substantial", "iso_18045_moderate"},
		{"enhanced-basic", "iso_18045_enhanced-basic"},
		{"basic", "iso_18045_basic"},
		{"low", "iso_18045_basic"},
	}
	for _, tc := range cases {
		t.Run(tc.legacy+"→"+tc.normative, func(t *testing.T) {
			assert.Equal(t, tc.normative, schemameta.NormalizeAttestationLoS(tc.legacy))
		})
	}
}

func TestTS11_LegacyNormalization_BindingType(t *testing.T) {
	cases := []struct {
		legacy, normative string
	}{
		{"cnf", "key"},
		{"holder", "key"},
	}
	for _, tc := range cases {
		t.Run(tc.legacy+"→"+tc.normative, func(t *testing.T) {
			assert.Equal(t, tc.normative, schemameta.NormalizeBindingType(tc.legacy))
		})
	}
}

func TestTS11_InferNormalizesValues(t *testing.T) {
	// Infer() MUST produce normative values even from legacy input
	src := &schemameta.SchemaMetaSource{
		AttestationLoS: "substantial",
		BindingType:    "cnf",
		RulebookURI:    "https://example.com/rb",
	}
	sm := schemameta.Infer(src, "org", "slug", "https://example.com",
		[]string{"dc+sd-jwt"}, map[string]string{"dc+sd-jwt": "/tmp/test.vctm.json"})

	assert.Equal(t, "iso_18045_moderate", sm.AttestationLoS, "legacy 'substantial' must be normalized")
	assert.Equal(t, "key", sm.BindingType, "legacy 'cnf' must be normalized")
}

// ===========================================================================
// Section 5.2.1: Query access — public, read-only
// ===========================================================================

func TestTS11_5_2_1_PublicReadAccess(t *testing.T) {
	// TS11 §5.2.1: GET methods SHALL be open for public access
	mux := setupTS11(t)

	t.Run("GET /schemas returns 200", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GET /schemas/{id} returns 200", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("content-type is application/json when unsigned", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas")
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}

// ===========================================================================
// Section 5.3.1: GET /schemas — full list and filtering
// ===========================================================================

func TestTS11_5_3_1_ListReturnsAllWhenNoParams(t *testing.T) {
	// TS11 §5.3.1: "If no query parameters are included, the method returns
	// the full list of registered attestation schemas."
	mux := setupTS11(t)
	result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas"))
	assert.Equal(t, 5, result.Total, "should return all 5 schemas")
	assert.Equal(t, 5, len(result.Data))
}

func TestTS11_5_3_1_ResponseIsPaginated(t *testing.T) {
	// TS11 §5.3.1: response SHALL provide a paginated list
	mux := setupTS11(t)
	result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas"))

	// Must have pagination envelope fields
	assert.GreaterOrEqual(t, result.Total, 0)
	assert.GreaterOrEqual(t, result.Limit, 0)
	assert.GreaterOrEqual(t, result.Offset, 0)
	assert.NotNil(t, result.Data)
}

func TestTS11_5_3_1_PaginationLimit(t *testing.T) {
	mux := setupTS11(t)

	t.Run("limit=2 returns 2 items", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?limit=2"))
		assert.Equal(t, 5, result.Total, "total should reflect full set")
		assert.Equal(t, 2, len(result.Data), "data should contain limit items")
		assert.Equal(t, 2, result.Limit)
	})

	t.Run("limit=1 returns 1 item", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?limit=1"))
		assert.Equal(t, 1, len(result.Data))
	})
}

func TestTS11_5_3_1_PaginationOffset(t *testing.T) {
	mux := setupTS11(t)

	t.Run("offset=2 skips first 2", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?offset=2"))
		assert.Equal(t, 5, result.Total)
		assert.Equal(t, 3, len(result.Data), "should return remaining items")
		assert.Equal(t, 2, result.Offset)
	})

	t.Run("offset beyond total returns empty", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?offset=100"))
		assert.Equal(t, 5, result.Total)
		assert.Equal(t, 0, len(result.Data))
	})
}

func TestTS11_5_3_1_PaginationLimitAndOffset(t *testing.T) {
	mux := setupTS11(t)

	// Walk through pages
	page1 := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?limit=2&offset=0"))
	page2 := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?limit=2&offset=2"))
	page3 := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?limit=2&offset=4"))

	assert.Equal(t, 2, len(page1.Data))
	assert.Equal(t, 2, len(page2.Data))
	assert.Equal(t, 1, len(page3.Data), "last page should have remaining item")

	// All pages should have consistent total
	assert.Equal(t, 5, page1.Total)
	assert.Equal(t, 5, page2.Total)
	assert.Equal(t, 5, page3.Total)

	// No duplicates across pages
	allIDs := make(map[string]bool)
	for _, p := range [][]*schemameta.SchemaMeta{page1.Data, page2.Data, page3.Data} {
		for _, sm := range p {
			assert.False(t, allIDs[sm.ID], "duplicate ID across pages: %s", sm.ID)
			allIDs[sm.ID] = true
		}
	}
	assert.Equal(t, 5, len(allIDs), "all schemas should appear across pages")
}

func TestTS11_5_3_1_FilterByID(t *testing.T) {
	// TS11 §5.3.1: id parameter filters by unique identifier
	mux := setupTS11(t)

	t.Run("existing ID", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?id=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"))
		assert.Equal(t, 1, result.Total)
		assert.Equal(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", result.Data[0].ID)
	})

	t.Run("non-existent ID", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?id=00000000-0000-0000-0000-000000000000"))
		assert.Equal(t, 0, result.Total)
		assert.Empty(t, result.Data)
	})
}

func TestTS11_5_3_1_FilterBySupportedFormat(t *testing.T) {
	// TS11 §5.3.1: supportedformat parameter
	mux := setupTS11(t)

	t.Run("dc+sd-jwt", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?supportedFormats=dc%2Bsd-jwt"))
		// Schemas 1, 4, 5 have dc+sd-jwt
		assert.Equal(t, 3, result.Total)
		for _, sm := range result.Data {
			assert.Contains(t, sm.SupportedFormats, "dc+sd-jwt")
		}
	})

	t.Run("mso_mdoc", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?supportedFormats=mso_mdoc"))
		// Schemas 1 and 5 have mso_mdoc
		assert.Equal(t, 2, result.Total)
	})

	t.Run("ldp_vc", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?supportedFormats=ldp_vc"))
		// Schemas 3 and 5 have ldp_vc
		assert.Equal(t, 2, result.Total)
	})

	t.Run("jwt_vc_json-ld", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?supportedFormats=jwt_vc_json-ld"))
		// Schemas 4 and 5 have jwt_vc_json-ld
		assert.Equal(t, 2, result.Total)
	})

	t.Run("multiple formats (comma-separated)", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?supportedFormats=dc%2Bsd-jwt,mso_mdoc"))
		// Only schemas with BOTH dc+sd-jwt AND mso_mdoc: 1 and 5
		assert.Equal(t, 2, result.Total)
	})
}

func TestTS11_5_3_1_FilterByAttestationLoS(t *testing.T) {
	// TS11 §5.3.1: attestationlos parameter
	mux := setupTS11(t)

	t.Run("iso_18045_high", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?attestationLoS=iso_18045_high"))
		assert.Equal(t, 2, result.Total) // schemas 1 and 5
		for _, sm := range result.Data {
			assert.Equal(t, "iso_18045_high", sm.AttestationLoS)
		}
	})

	t.Run("iso_18045_moderate", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?attestationLoS=iso_18045_moderate"))
		assert.Equal(t, 1, result.Total) // schema 2
	})

	t.Run("iso_18045_enhanced-basic", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?attestationLoS=iso_18045_enhanced-basic"))
		assert.Equal(t, 1, result.Total) // schema 3
	})

	t.Run("iso_18045_basic", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?attestationLoS=iso_18045_basic"))
		assert.Equal(t, 1, result.Total) // schema 4
	})
}

func TestTS11_5_3_1_FilterByBindingType(t *testing.T) {
	mux := setupTS11(t)

	t.Run("key", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?bindingType=key"))
		assert.Equal(t, 2, result.Total) // schemas 1 and 5
		for _, sm := range result.Data {
			assert.Equal(t, "key", sm.BindingType)
		}
	})

	t.Run("claim", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?bindingType=claim"))
		assert.Equal(t, 1, result.Total) // schema 2
	})

	t.Run("biometric", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?bindingType=biometric"))
		assert.Equal(t, 1, result.Total) // schema 3
	})

	t.Run("none", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?bindingType=none"))
		assert.Equal(t, 1, result.Total) // schema 4
	})
}

func TestTS11_5_3_1_FilterByTrustedAuthoritiesFrameworkType(t *testing.T) {
	mux := setupTS11(t)

	t.Run("etsi_tl", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?trustedAuthoritiesFrameworkType=etsi_tl"))
		assert.Equal(t, 3, result.Total) // schemas 1, 4, 5
		for _, sm := range result.Data {
			found := false
			for _, ta := range sm.TrustedAuthorities {
				if ta.FrameworkType == "etsi_tl" {
					found = true
				}
			}
			assert.True(t, found, "schema %s should have etsi_tl trust authority", sm.ID)
		}
	})

	t.Run("aki", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?trustedAuthoritiesFrameworkType=aki"))
		assert.Equal(t, 2, result.Total) // schemas 3, 5
	})

	t.Run("openid_federation", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?trustedAuthoritiesFrameworkType=openid_federation"))
		assert.Equal(t, 2, result.Total) // schemas 2, 5
	})
}

func TestTS11_5_3_1_FilterByTrustedAuthoritiesValue(t *testing.T) {
	mux := setupTS11(t)

	result := parsePaginatedList(t, doGET(t, mux,
		"/api/v1/schemas?trustedAuthoritiesValue=https://ec.europa.eu/tools/lotl/eu-lotl.xml"))
	assert.Equal(t, 2, result.Total) // schemas 1 and 5
}

func TestTS11_5_3_1_FilterBySchemaUri(t *testing.T) {
	mux := setupTS11(t)

	result := parsePaginatedList(t, doGET(t, mux,
		"/api/v1/schemas?schemaUri=https://catalogue.example.eu/schemas/diploma-vc.json"))
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", result.Data[0].ID)
}

func TestTS11_5_3_1_FilterByRulebookUri(t *testing.T) {
	mux := setupTS11(t)

	result := parsePaginatedList(t, doGET(t, mux,
		"/api/v1/schemas?rulebookUri=https://rulebooks.example.eu/ehic/v1"))
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "cccccccc-cccc-cccc-cccc-cccccccccccc", result.Data[0].ID)
}

func TestTS11_5_3_1_CombinedFilters(t *testing.T) {
	// Multiple query parameters applied simultaneously (AND logic)
	mux := setupTS11(t)

	t.Run("LoS + format", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux,
			"/api/v1/schemas?attestationLoS=iso_18045_high&supportedFormats=mso_mdoc"))
		assert.Equal(t, 2, result.Total) // schemas 1 and 5
	})

	t.Run("binding + framework", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux,
			"/api/v1/schemas?bindingType=key&trustedAuthoritiesFrameworkType=aki"))
		assert.Equal(t, 1, result.Total) // only schema 5
		assert.Equal(t, "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee", result.Data[0].ID)
	})

	t.Run("three filters narrow to one", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux,
			"/api/v1/schemas?attestationLoS=iso_18045_moderate&bindingType=claim&supportedFormats=jwt_vc_json"))
		assert.Equal(t, 1, result.Total)
		assert.Equal(t, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", result.Data[0].ID)
	})

	t.Run("conflicting filters return empty", func(t *testing.T) {
		result := parsePaginatedList(t, doGET(t, mux,
			"/api/v1/schemas?attestationLoS=iso_18045_high&bindingType=biometric"))
		assert.Equal(t, 0, result.Total, "no schema has both high LoS and biometric binding")
	})
}

func TestTS11_5_3_1_FilterWithPagination(t *testing.T) {
	// Filtering + pagination combined
	mux := setupTS11(t)

	// 3 schemas have dc+sd-jwt; paginate through them
	result := parsePaginatedList(t, doGET(t, mux,
		"/api/v1/schemas?supportedFormats=dc%2Bsd-jwt&limit=1&offset=0"))
	assert.Equal(t, 3, result.Total)
	assert.Equal(t, 1, len(result.Data))

	result2 := parsePaginatedList(t, doGET(t, mux,
		"/api/v1/schemas?supportedFormats=dc%2Bsd-jwt&limit=1&offset=2"))
	assert.Equal(t, 3, result2.Total)
	assert.Equal(t, 1, len(result2.Data))
	assert.NotEqual(t, result.Data[0].ID, result2.Data[0].ID, "different pages should return different schemas")
}

func TestTS11_5_3_1_NoMatchReturnsEmptyList(t *testing.T) {
	// TS11 §5.3.1 implies 200 with empty data when no matches
	mux := setupTS11(t)

	w := doGET(t, mux, "/api/v1/schemas?bindingType=nonexistent")
	assert.Equal(t, http.StatusOK, w.Code, "should return 200 even with no matches")

	result := parsePaginatedList(t, w)
	assert.Equal(t, 0, result.Total)
	assert.Empty(t, result.Data)
}

// ===========================================================================
// Section 5.3.1: GET /schemas/{schemaId}
// ===========================================================================

func TestTS11_5_3_1_GetSchemaByID(t *testing.T) {
	// TS11 §5.3.1: GET /schemas/{schemaId} returns full SchemaMeta for matching Id
	mux := setupTS11(t)

	for _, expected := range ts11Catalogue() {
		t.Run(expected.ID, func(t *testing.T) {
			sm := parseSchemaMeta(t, doGET(t, mux, "/api/v1/schemas/"+expected.ID))

			assert.Equal(t, expected.ID, sm.ID)
			assert.Equal(t, expected.Version, sm.Version)
			assert.Equal(t, expected.AttestationLoS, sm.AttestationLoS)
			assert.Equal(t, expected.BindingType, sm.BindingType)
			assert.Equal(t, expected.RulebookURI, sm.RulebookURI)
			assert.Equal(t, expected.SupportedFormats, sm.SupportedFormats)
			assert.Equal(t, len(expected.SchemaURIs), len(sm.SchemaURIs))
			assert.Equal(t, len(expected.TrustedAuthorities), len(sm.TrustedAuthorities))
		})
	}
}

func TestTS11_5_3_1_GetSchemaNotFound(t *testing.T) {
	// TS11 §5.3.1: 404 when schema not found
	mux := setupTS11(t)

	w := doGET(t, mux, "/api/v1/schemas/00000000-0000-0000-0000-000000000000")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTS11_5_3_1_GetSchemaFullContents(t *testing.T) {
	// TS11 §5.3.1: "the full contents of SchemaMeta class for matching instance"
	mux := setupTS11(t)

	// Verify schema 5 (most complex: all formats, multiple trust authorities)
	sm := parseSchemaMeta(t, doGET(t, mux, "/api/v1/schemas/eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"))

	assert.Equal(t, "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee", sm.ID)
	assert.Equal(t, "3.0.0", sm.Version)
	assert.Equal(t, "iso_18045_high", sm.AttestationLoS)
	assert.Equal(t, "key", sm.BindingType)
	assert.Equal(t, "https://rulebooks.example.eu/multiformat/v3", sm.RulebookURI)

	// All five formats
	assert.Equal(t, 5, len(sm.SupportedFormats))
	assert.Contains(t, sm.SupportedFormats, "dc+sd-jwt")
	assert.Contains(t, sm.SupportedFormats, "mso_mdoc")
	assert.Contains(t, sm.SupportedFormats, "jwt_vc_json")
	assert.Contains(t, sm.SupportedFormats, "jwt_vc_json-ld")
	assert.Contains(t, sm.SupportedFormats, "ldp_vc")

	// Five schema URIs
	assert.Equal(t, 5, len(sm.SchemaURIs))

	// Three trust authorities
	assert.Equal(t, 3, len(sm.TrustedAuthorities))
	fwTypes := make(map[string]bool)
	for _, ta := range sm.TrustedAuthorities {
		fwTypes[ta.FrameworkType] = true
	}
	assert.True(t, fwTypes["etsi_tl"])
	assert.True(t, fwTypes["aki"])
	assert.True(t, fwTypes["openid_federation"])
}

// ===========================================================================
// Section 5.3.1: Response structure — JSON serialization
// ===========================================================================

func TestTS11_5_3_1_ListResponseStructure(t *testing.T) {
	// TS11 §5.3.1 + OpenAPI: list response has total, limit, offset, data
	mux := setupTS11(t)

	w := doGET(t, mux, "/api/v1/schemas")
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))

	requiredFields := []string{"total", "limit", "offset", "data"}
	for _, field := range requiredFields {
		assert.Contains(t, raw, field, "response must contain %q field", field)
	}
}

func TestTS11_5_3_1_SchemaResponseStructure(t *testing.T) {
	// TS11 §5.3.1 + Annex A.2: individual schema response has normative fields
	mux := setupTS11(t)

	w := doGET(t, mux, "/api/v1/schemas/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))

	// Required per TS11 §4.3.1
	requiredFields := []string{"id", "version", "attestationLoS", "bindingType",
		"supportedFormats", "schemaURIs", "rulebookURI"}
	for _, field := range requiredFields {
		assert.Contains(t, raw, field, "SchemaMeta response must contain %q", field)
	}

	// Optional fields present when populated
	assert.Contains(t, raw, "trustedAuthorities")
}

func TestTS11_5_3_1_SchemaResponseNoExtraFields(t *testing.T) {
	// TS11 Annex A.2: additionalProperties: false — no extra JSON keys
	mux := setupTS11(t)

	w := doGET(t, mux, "/api/v1/schemas/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))

	allowedFields := map[string]bool{
		"id": true, "version": true, "attestationLoS": true,
		"bindingType": true, "supportedFormats": true, "schemaURIs": true,
		"rulebookURI": true, "trustedAuthorities": true,
	}
	for key := range raw {
		assert.True(t, allowedFields[key], "unexpected field %q in SchemaMeta response", key)
	}
}

func TestTS11_5_3_1_SchemaURIEntryStructure(t *testing.T) {
	// TS11 §4.3.2: Schema entries must have formatIdentifier and uri
	mux := setupTS11(t)

	w := doGET(t, mux, "/api/v1/schemas/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
	var sm schemameta.SchemaMeta
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &sm))

	for i, su := range sm.SchemaURIs {
		assert.NotEmpty(t, su.FormatIdentifier, "schemaURIs[%d].formatIdentifier must not be empty", i)
		assert.NotEmpty(t, su.URI, "schemaURIs[%d].uri must not be empty", i)
		assert.True(t, schemameta.ValidSupportedFormat(su.FormatIdentifier),
			"schemaURIs[%d].formatIdentifier=%q must be a valid format", i, su.FormatIdentifier)
	}
}

func TestTS11_5_3_1_TrustAuthorityEntryStructure(t *testing.T) {
	// TS11 §4.3.3: TrustAuthority entries must have frameworkType and value
	mux := setupTS11(t)

	w := doGET(t, mux, "/api/v1/schemas/eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee")
	var sm schemameta.SchemaMeta
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &sm))

	validFrameworkTypes := map[string]bool{"aki": true, "etsi_tl": true, "openid_federation": true}
	for i, ta := range sm.TrustedAuthorities {
		assert.NotEmpty(t, ta.FrameworkType, "trustedAuthorities[%d].frameworkType must not be empty", i)
		assert.NotEmpty(t, ta.Value, "trustedAuthorities[%d].value must not be empty", i)
		assert.True(t, validFrameworkTypes[ta.FrameworkType],
			"trustedAuthorities[%d].frameworkType=%q must be valid", i, ta.FrameworkType)
	}
}

// ===========================================================================
// Annex A.2: JSON Schema compliance — validate all catalogue entries
// ===========================================================================

func TestTS11_AnnexA2_AllCatalogueEntriesValid(t *testing.T) {
	// Every entry in the catalogue MUST pass the normative JSON Schema
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	for _, sm := range ts11Catalogue() {
		t.Run(sm.ID, func(t *testing.T) {
			assert.NoError(t, v.Validate(sm), "catalogue entry %s should pass TS11 schema validation", sm.ID)
		})
	}
}

func TestTS11_AnnexA2_RejectionCases(t *testing.T) {
	// The validator MUST reject non-compliant objects
	v, err := schemameta.NewValidator()
	require.NoError(t, err)

	t.Run("invalid attestationLoS value", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.AttestationLoS = "high" // not a normative value
		assert.Error(t, v.Validate(sm))
	})

	t.Run("invalid bindingType value", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.BindingType = "cnf" // not a normative value
		assert.Error(t, v.Validate(sm))
	})

	t.Run("invalid supportedFormat value", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.SupportedFormats = []string{"x509"}
		assert.Error(t, v.Validate(sm))
	})

	t.Run("invalid formatIdentifier in schemaURIs", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.SchemaURIs = []schemameta.SchemaURI{
			{FormatIdentifier: "unknown", URI: "https://example.com/schema.json"},
		}
		assert.Error(t, v.Validate(sm))
	})

	t.Run("invalid frameworkType in trustedAuthorities", func(t *testing.T) {
		sm := validSchemaMeta()
		sm.TrustedAuthorities = []schemameta.TrustAuthority{
			{FrameworkType: "x509_cert", Value: "https://example.com/cert"},
		}
		assert.Error(t, v.Validate(sm))
	})
}

// ===========================================================================
// Edge cases and robustness
// ===========================================================================

func TestTS11_EdgeCase_EmptyCatalogue(t *testing.T) {
	// API with zero schemas should still work
	h := apihandler.New(nil, nil, "")
	mux := http.NewServeMux()
	h.Register(mux)

	w := doGET(t, mux, "/api/v1/schemas")
	result := parsePaginatedList(t, w)
	assert.Equal(t, 0, result.Total)
	assert.Empty(t, result.Data)
}

func TestTS11_EdgeCase_DefaultPaginationValues(t *testing.T) {
	// OpenAPI spec: limit default=20, offset default=0
	mux := setupTS11(t)
	result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas"))
	assert.Equal(t, 20, result.Limit, "default limit should be 20")
	assert.Equal(t, 0, result.Offset, "default offset should be 0")
}

func TestTS11_EdgeCase_NegativePagination(t *testing.T) {
	// Negative limit/offset should fall back to defaults
	mux := setupTS11(t)

	result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?limit=-1&offset=-5"))
	assert.Equal(t, 20, result.Limit, "negative limit should fall back to default")
	assert.Equal(t, 0, result.Offset, "negative offset should fall back to default")
}

func TestTS11_EdgeCase_InvalidPagination(t *testing.T) {
	// Non-numeric limit/offset should fall back to defaults
	mux := setupTS11(t)

	result := parsePaginatedList(t, doGET(t, mux, "/api/v1/schemas?limit=abc&offset=xyz"))
	assert.Equal(t, 20, result.Limit)
	assert.Equal(t, 0, result.Offset)
}

// ===========================================================================
// Helpers
// ===========================================================================

func validSchemaMeta() *schemameta.SchemaMeta {
	return &schemameta.SchemaMeta{
		ID:               schemameta.GenerateID("test-org", "test-slug"),
		Version:          "1.0.0",
		AttestationLoS:   "iso_18045_high",
		BindingType:      "key",
		RulebookURI:      "https://example.com/rulebook",
		SupportedFormats: []string{"dc+sd-jwt"},
		SchemaURIs: []schemameta.SchemaURI{
			{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/schema.json"},
		},
	}
}
