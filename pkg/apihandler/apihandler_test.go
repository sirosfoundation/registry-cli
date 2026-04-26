package apihandler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sirosfoundation/registry-cli/pkg/attributes"
	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

func testSchemas() []*schemameta.SchemaMeta {
	return []*schemameta.SchemaMeta{
		{
			ID:               "11111111-1111-1111-1111-111111111111",
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			BindingType:      "key",
			RulebookURI:      "https://example.com/rb1",
			SupportedFormats: []string{"dc+sd-jwt", "mso_mdoc"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/s1.json"},
				{FormatIdentifier: "mso_mdoc", URI: "https://example.com/s1.mdoc.json"},
			},
			TrustedAuthorities: []schemameta.TrustAuthority{
				{FrameworkType: "etsi_tl", Value: "https://example.com/tl"},
			},
		},
		{
			ID:               "22222222-2222-2222-2222-222222222222",
			Version:          "2.0.0",
			AttestationLoS:   "iso_18045_basic",
			BindingType:      "none",
			RulebookURI:      "https://example.com/rb2",
			SupportedFormats: []string{"dc+sd-jwt"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "dc+sd-jwt", URI: "https://example.com/s2.json"},
			},
		},
		{
			ID:               "33333333-3333-3333-3333-333333333333",
			Version:          "1.0.0",
			AttestationLoS:   "iso_18045_high",
			BindingType:      "biometric",
			RulebookURI:      "https://example.com/rb3",
			SupportedFormats: []string{"mso_mdoc"},
			SchemaURIs: []schemameta.SchemaURI{
				{FormatIdentifier: "mso_mdoc", URI: "https://example.com/s3.mdoc.json"},
			},
		},
	}
}

func setupHandler(t *testing.T) (*Handler, *http.ServeMux) {
	t.Helper()
	h := New(testSchemas(), nil, "")
	mux := http.NewServeMux()
	h.Register(mux)
	return h, mux
}

func TestListSchemas_NoFilter(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 3, result.Total)
	assert.Equal(t, 3, len(result.Data))
	assert.Equal(t, 20, result.Limit)
	assert.Equal(t, 0, result.Offset)
}

func TestListSchemas_FilterByID(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas?id=22222222-2222-2222-2222-222222222222", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", result.Data[0].ID)
}

func TestListSchemas_FilterByAttestationLoS(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas?attestationLoS=iso_18045_high", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 2, result.Total)
}

func TestListSchemas_FilterByBindingType(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas?bindingType=none", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", result.Data[0].ID)
}

func TestListSchemas_FilterBySupportedFormats(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas?supportedFormats=mso_mdoc", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 2, result.Total) // schema 1 and 3 have mso_mdoc
}

func TestListSchemas_FilterByTrustedAuthority(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas?trustedAuthoritiesFrameworkType=etsi_tl", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", result.Data[0].ID)
}

func TestListSchemas_FilterByRulebookUri(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas?rulebookUri=https://example.com/rb2", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", result.Data[0].ID)
}

func TestListSchemas_FilterBySchemaUri(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas?schemaUri=https://example.com/s3.mdoc.json", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "33333333-3333-3333-3333-333333333333", result.Data[0].ID)
}

func TestListSchemas_Pagination(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas?limit=1&offset=1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 3, result.Total)
	assert.Equal(t, 1, len(result.Data))
	assert.Equal(t, 1, result.Limit)
	assert.Equal(t, 1, result.Offset)
	assert.Equal(t, "22222222-2222-2222-2222-222222222222", result.Data[0].ID)
}

func TestListSchemas_CombinedFilters(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas?attestationLoS=iso_18045_high&supportedFormats=mso_mdoc", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var result PaginatedSchemaList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 2, result.Total) // schemas 1 and 3
}

func TestGetSchema(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas/11111111-1111-1111-1111-111111111111", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var sm schemameta.SchemaMeta
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &sm))
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", sm.ID)
	assert.Equal(t, "1.0.0", sm.Version)
}

func TestGetSchema_NotFound(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas/99999999-9999-9999-9999-999999999999", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestGetSchema_WithJsonSuffix(t *testing.T) {
	_, mux := setupHandler(t)

	req := httptest.NewRequest("GET", "/api/v1/schemas/11111111-1111-1111-1111-111111111111.json", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func testAttributes() []attributes.Attribute {
	return []attributes.Attribute{
		{
			Identifier: "urn:siros:attr:given-name:abc123",
			Name:       []attributes.LangValue{{Value: "Given Name", Lang: "en"}},
			NameSpace:  "https://credentials.example.com",
			Distributions: []attributes.SchemaDistribution{
				{AccessURL: "https://registry.example.org/api/v1/attributes/schemas/given-name.json", MediaType: "application/schema+json"},
			},
			UsedBy: []attributes.AttestationRef{
				{SchemaID: "uuid-1", Org: "org1", Slug: "identity", Name: "Identity"},
			},
		},
		{
			Identifier: "urn:siros:attr:family-name:def456",
			Name:       []attributes.LangValue{{Value: "Family Name", Lang: "en"}},
			NameSpace:  "https://credentials.example.com",
			Distributions: []attributes.SchemaDistribution{
				{AccessURL: "https://registry.example.org/api/v1/attributes/schemas/family-name.json", MediaType: "application/schema+json"},
			},
			UsedBy: []attributes.AttestationRef{
				{SchemaID: "uuid-1", Org: "org1", Slug: "identity", Name: "Identity"},
				{SchemaID: "uuid-2", Org: "org2", Slug: "diploma", Name: "Diploma"},
			},
		},
	}
}

func setupHandlerWithAttrs(t *testing.T) (*Handler, *http.ServeMux) {
	t.Helper()
	h := New(testSchemas(), nil, "")
	h.SetAttributes(testAttributes())
	mux := http.NewServeMux()
	h.Register(mux)
	return h, mux
}

func TestListAttributes_NoFilter(t *testing.T) {
	_, mux := setupHandlerWithAttrs(t)

	req := httptest.NewRequest("GET", "/api/v1/attributes", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var result PaginatedAttributeList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Data, 2)
}

func TestListAttributes_FilterByNameSpace(t *testing.T) {
	_, mux := setupHandlerWithAttrs(t)

	req := httptest.NewRequest("GET", "/api/v1/attributes?nameSpace=https://credentials.example.com", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var result PaginatedAttributeList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 2, result.Total)
}

func TestListAttributes_FilterByIdentifier(t *testing.T) {
	_, mux := setupHandlerWithAttrs(t)

	req := httptest.NewRequest("GET", "/api/v1/attributes?identifier=urn:siros:attr:given-name:abc123", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var result PaginatedAttributeList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 1, result.Total)
	assert.Equal(t, "urn:siros:attr:given-name:abc123", result.Data[0].Identifier)
}

func TestGetAttribute_Found(t *testing.T) {
	_, mux := setupHandlerWithAttrs(t)

	req := httptest.NewRequest("GET", "/api/v1/attributes/urn:siros:attr:given-name:abc123", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var attr attributes.Attribute
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &attr))
	assert.Equal(t, "urn:siros:attr:given-name:abc123", attr.Identifier)
	assert.Equal(t, "Given Name", attr.Name[0].Value)
}

func TestGetAttribute_NotFound(t *testing.T) {
	_, mux := setupHandlerWithAttrs(t)

	req := httptest.NewRequest("GET", "/api/v1/attributes/nonexistent", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestListAttributes_Pagination(t *testing.T) {
	_, mux := setupHandlerWithAttrs(t)

	req := httptest.NewRequest("GET", "/api/v1/attributes?limit=1&offset=1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var result PaginatedAttributeList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Data, 1)
	assert.Equal(t, "urn:siros:attr:family-name:def456", result.Data[0].Identifier)
}
