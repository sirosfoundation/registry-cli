// Package ts11compliance — additional tests verifying potential gaps identified
// during TS11 read-only compliance gap analysis (May 2026).
//
// These tests cover:
//   - Signed response Content-Type (application/jwt per OpenAPI spec)
//   - x-jku-url header presence when JWS signing is configured
//   - Unsigned response Content-Type (application/json)
//   - Attributes API endpoints (TS11 §4.2 read-only)
//   - Invalid enum parameter rejection (HTTP 400)
//   - OpenAPI spec document structure (Annex A.3)
package ts11compliance

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/registry-cli/pkg/apihandler"
	"github.com/sirosfoundation/registry-cli/pkg/attributes"
	"github.com/sirosfoundation/registry-cli/pkg/jwssign"
)

// ===========================================================================
// Signed response Content-Type and headers (OpenAPI spec / TS11 §5.3.1)
// ===========================================================================

func setupTS11Signed(t *testing.T) *http.ServeMux {
	t.Helper()
	signer, err := jwssign.NewEphemeralSigner("https://registry.example.org", "https://registry.example.org/.well-known/jwks.json")
	require.NoError(t, err)
	t.Cleanup(func() { _ = signer.Close() })

	h := apihandler.New(ts11Catalogue(), signer, "https://registry.example.org/.well-known/jwks.json")
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

func TestTS11_5_3_1_SignedResponse_ContentType(t *testing.T) {
	// TS11 §5.3.1 + OpenAPI spec: when signing is configured, responses SHALL
	// use Content-Type: application/jwt (JWS compact serialization).
	mux := setupTS11Signed(t)

	t.Run("GET /schemas returns application/jwt when signed", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas")
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/jwt", w.Header().Get("Content-Type"),
			"signed responses MUST use Content-Type: application/jwt")
	})

	t.Run("GET /schemas/{id} returns application/jwt when signed", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/jwt", w.Header().Get("Content-Type"))
	})
}

func TestTS11_5_3_1_SignedResponse_JKUHeader(t *testing.T) {
	// OpenAPI spec: responses SHALL include x-jku-url header pointing to JWKS
	// when JWS signing is configured.
	mux := setupTS11Signed(t)

	t.Run("GET /schemas includes x-jku-url", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas")
		jku := w.Header().Get("x-jku-url")
		assert.NotEmpty(t, jku, "signed response MUST include x-jku-url header")
		assert.True(t, strings.HasPrefix(jku, "https://"),
			"x-jku-url MUST be an HTTPS URL, got: %s", jku)
	})

	t.Run("GET /schemas/{id} includes x-jku-url", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
		jku := w.Header().Get("x-jku-url")
		assert.NotEmpty(t, jku)
	})
}

func TestTS11_5_3_1_SignedResponse_IsJWSCompact(t *testing.T) {
	// TS11 + OpenAPI: the body SHALL be a JWS compact serialization (three
	// base64url segments separated by dots).
	mux := setupTS11Signed(t)

	w := doGET(t, mux, "/api/v1/schemas")
	body := w.Body.String()
	parts := strings.Split(body, ".")
	assert.Equal(t, 3, len(parts),
		"JWS compact serialization MUST have exactly 3 dot-separated parts, got %d", len(parts))
}

func TestTS11_5_3_1_UnsignedResponse_ContentType(t *testing.T) {
	// TS11 §5.3.1 + OpenAPI: when signing is NOT configured, responses SHALL
	// use Content-Type: application/json.
	mux := setupTS11(t) // unsigned handler

	t.Run("GET /schemas returns application/json when unsigned", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas")
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})

	t.Run("GET /schemas/{id} returns application/json when unsigned", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}

func TestTS11_5_3_1_UnsignedResponse_NoJKUHeader(t *testing.T) {
	// When signing is not configured, x-jku-url header MUST NOT be present.
	mux := setupTS11(t)

	w := doGET(t, mux, "/api/v1/schemas")
	assert.Empty(t, w.Header().Get("x-jku-url"),
		"unsigned responses MUST NOT include x-jku-url header")
}

// ===========================================================================
// JWKS endpoint (OpenAPI /.well-known/jwks.json)
// ===========================================================================

func TestTS11_JWKS_Endpoint(t *testing.T) {
	// OpenAPI spec: /.well-known/jwks.json SHALL return a valid JWKS when
	// signing is configured.
	mux := setupTS11Signed(t)

	w := doGET(t, mux, "/.well-known/jwks.json")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var jwks map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &jwks))
	assert.Contains(t, jwks, "keys", "JWKS response MUST contain 'keys' field")
}

func TestTS11_JWKS_NotRegistered_WhenUnsigned(t *testing.T) {
	// When signing is not configured, the JWKS endpoint SHOULD NOT be registered.
	mux := setupTS11(t)

	w := doGET(t, mux, "/.well-known/jwks.json")
	// Without signing, the route is not registered so we expect 404 or 405
	assert.NotEqual(t, http.StatusOK, w.Code,
		"JWKS endpoint should not be available when signing is not configured")
}

// ===========================================================================
// Section 5.3.1: Invalid enum query parameters MUST return 400
// ===========================================================================

func TestTS11_5_3_1_InvalidEnumParams_Return400(t *testing.T) {
	// TS11 §5.3.1: If a client provides an invalid value for an enumerated
	// query parameter, the server SHALL respond with 400 Bad Request.
	mux := setupTS11(t)

	t.Run("invalid attestationLoS", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas?attestationLoS=high")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid bindingType", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas?bindingType=cnf")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid supportedFormats", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas?supportedFormats=x509_cert")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("error response is JSON", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/schemas?attestationLoS=invalid_value")
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"),
			"error responses MUST be JSON")

		var errResp map[string]string
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
		assert.Contains(t, errResp, "error", "error response MUST have 'error' field")
		assert.NotEmpty(t, errResp["error"])
	})
}

// ===========================================================================
// Section 4.2: Catalogue of Attributes — read-only API compliance
// ===========================================================================

func ts11Attributes() []attributes.Attribute {
	return []attributes.Attribute{
		{
			Identifier: "urn:eudi:attr:given-name:abc123",
			Name:       []attributes.LangValue{{Value: "Given Name", Lang: "en"}},
			NameSpace:  "https://credentials.example.eu/pid",
			Distributions: []attributes.SchemaDistribution{
				{AccessURL: "https://catalogue.example.eu/api/v1/attributes/schemas/given-name.json", MediaType: "application/schema+json"},
			},
		},
		{
			Identifier: "urn:eudi:attr:family-name:def456",
			Name:       []attributes.LangValue{{Value: "Family Name", Lang: "en"}},
			NameSpace:  "https://credentials.example.eu/pid",
			Distributions: []attributes.SchemaDistribution{
				{AccessURL: "https://catalogue.example.eu/api/v1/attributes/schemas/family-name.json", MediaType: "application/schema+json"},
			},
		},
		{
			Identifier: "urn:eudi:attr:degree-type:ghi789",
			Name:       []attributes.LangValue{{Value: "Degree Type", Lang: "en"}},
			NameSpace:  "https://credentials.example.eu/diploma",
			Distributions: []attributes.SchemaDistribution{
				{AccessURL: "https://catalogue.example.eu/api/v1/attributes/schemas/degree-type.json", MediaType: "application/schema+json"},
			},
		},
	}
}

func setupTS11WithAttributes(t *testing.T) *http.ServeMux {
	t.Helper()
	h := apihandler.New(ts11Catalogue(), nil, "")
	h.SetAttributes(ts11Attributes())
	mux := http.NewServeMux()
	h.Register(mux)
	return mux
}

func TestTS11_4_2_ListAttributes_Exists(t *testing.T) {
	// TS11 §4.2: Catalogue of Attributes SHALL be queryable via GET /attributes
	mux := setupTS11WithAttributes(t)

	w := doGET(t, mux, "/api/v1/attributes")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestTS11_4_2_ListAttributes_PaginationEnvelope(t *testing.T) {
	// The attributes list response SHALL follow the same pagination envelope
	// as the schemas endpoint: total, limit, offset, data.
	mux := setupTS11WithAttributes(t)

	w := doGET(t, mux, "/api/v1/attributes")
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))

	for _, field := range []string{"total", "limit", "offset", "data"} {
		assert.Contains(t, raw, field, "attributes response MUST contain %q", field)
	}
}

func TestTS11_4_2_ListAttributes_ReturnsAll(t *testing.T) {
	mux := setupTS11WithAttributes(t)

	w := doGET(t, mux, "/api/v1/attributes")
	var result apihandler.PaginatedAttributeList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 3, result.Total)
	assert.Equal(t, 3, len(result.Data))
}

func TestTS11_4_2_ListAttributes_Pagination(t *testing.T) {
	mux := setupTS11WithAttributes(t)

	t.Run("limit=1 returns 1 item", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/attributes?limit=1")
		var result apihandler.PaginatedAttributeList
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, 3, result.Total)
		assert.Equal(t, 1, len(result.Data))
	})

	t.Run("offset=2 returns last item", func(t *testing.T) {
		w := doGET(t, mux, "/api/v1/attributes?offset=2")
		var result apihandler.PaginatedAttributeList
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, 3, result.Total)
		assert.Equal(t, 1, len(result.Data))
	})
}

func TestTS11_4_2_ListAttributes_FilterByNameSpace(t *testing.T) {
	// TS11 §4.2: Attributes SHALL be filterable by nameSpace.
	mux := setupTS11WithAttributes(t)

	w := doGET(t, mux, "/api/v1/attributes?nameSpace=https://credentials.example.eu/pid")
	var result apihandler.PaginatedAttributeList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 2, result.Total)
	for _, attr := range result.Data {
		assert.Equal(t, "https://credentials.example.eu/pid", attr.NameSpace)
	}
}

func TestTS11_4_2_ListAttributes_FilterByIdentifier(t *testing.T) {
	mux := setupTS11WithAttributes(t)

	w := doGET(t, mux, "/api/v1/attributes?identifier=urn:eudi:attr:given-name:abc123")
	var result apihandler.PaginatedAttributeList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "urn:eudi:attr:given-name:abc123", result.Data[0].Identifier)
}

func TestTS11_4_2_GetAttribute_ByID(t *testing.T) {
	// TS11 §4.2: GET /attributes/{attrId} returns a single Attribute.
	mux := setupTS11WithAttributes(t)

	w := doGET(t, mux, "/api/v1/attributes/urn:eudi:attr:given-name:abc123")
	assert.Equal(t, http.StatusOK, w.Code)

	var attr attributes.Attribute
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &attr))
	assert.Equal(t, "urn:eudi:attr:given-name:abc123", attr.Identifier)
	assert.NotEmpty(t, attr.Name)
	assert.NotEmpty(t, attr.Distributions)
}

func TestTS11_4_2_GetAttribute_NotFound(t *testing.T) {
	mux := setupTS11WithAttributes(t)

	w := doGET(t, mux, "/api/v1/attributes/nonexistent")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTS11_4_2_GetAttribute_ResponseStructure(t *testing.T) {
	// TS11 §4.2: Attribute response SHALL have identifier, name, distributions
	mux := setupTS11WithAttributes(t)

	w := doGET(t, mux, "/api/v1/attributes/urn:eudi:attr:given-name:abc123")
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))

	// identifier and name are required per TS11 §4.2
	assert.Contains(t, raw, "identifier", "Attribute MUST have 'identifier'")
	assert.Contains(t, raw, "name", "Attribute MUST have 'name'")
	assert.Contains(t, raw, "distributions", "Attribute MUST have 'distributions'")
}

// ===========================================================================
// Section 5.3.1: GET /schemas — 404 response structure
// ===========================================================================

func TestTS11_5_3_1_NotFound_IsJSON(t *testing.T) {
	// Error responses SHALL be JSON with Content-Type: application/json.
	mux := setupTS11(t)

	w := doGET(t, mux, "/api/v1/schemas/00000000-0000-0000-0000-000000000000")
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"),
		"404 responses MUST have Content-Type: application/json")

	var errResp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	assert.Contains(t, errResp, "error")
}

// ===========================================================================
// Signed attributes endpoint
// ===========================================================================

func TestTS11_4_2_SignedAttributes_ContentType(t *testing.T) {
	// When signing is configured, attribute endpoints MUST also return
	// application/jwt, same as schema endpoints.
	signer, err := jwssign.NewEphemeralSigner("https://registry.example.org", "https://registry.example.org/.well-known/jwks.json")
	require.NoError(t, err)
	t.Cleanup(func() { _ = signer.Close() })

	h := apihandler.New(ts11Catalogue(), signer, "https://registry.example.org/.well-known/jwks.json")
	h.SetAttributes(ts11Attributes())
	mux := http.NewServeMux()
	h.Register(mux)

	t.Run("GET /attributes returns application/jwt", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/attributes", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/jwt", w.Header().Get("Content-Type"))
	})

	t.Run("GET /attributes/{id} returns application/jwt", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/attributes/urn:eudi:attr:given-name:abc123", nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/jwt", w.Header().Get("Content-Type"))
	})
}
