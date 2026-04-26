package apihandler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/sirosfoundation/registry-cli/pkg/attributes"
	"github.com/sirosfoundation/registry-cli/pkg/jwssign"
	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

// Handler serves the TS11 API endpoints.
type Handler struct {
	schemas []*schemameta.SchemaMeta
	attrs   []attributes.Attribute
	signer  *jwssign.Signer // nil when signing is not configured
	jku     string
}

// New creates a new API handler. signer may be nil for unsigned responses.
func New(schemas []*schemameta.SchemaMeta, signer *jwssign.Signer, jku string) *Handler {
	return &Handler{schemas: schemas, signer: signer, jku: jku}
}

// SetAttributes sets the attribute catalogue for serving via the API.
func (h *Handler) SetAttributes(attrs []attributes.Attribute) {
	h.attrs = attrs
}

// Register mounts the API routes on the given mux under /api/v1/.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/schemas", h.listSchemas)
	mux.HandleFunc("GET /api/v1/schemas/{schemaId}", h.getSchema)
	mux.HandleFunc("GET /api/v1/attributes", h.listAttributes)
	mux.HandleFunc("GET /api/v1/attributes/{attrId}", h.getAttribute)
	if h.signer != nil {
		mux.HandleFunc("GET /.well-known/jwks.json", h.getJWKS)
	}
}

func (h *Handler) listSchemas(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filtered := h.filterSchemas(q)

	// Pagination
	limit := intParam(q, "limit", 20)
	offset := intParam(q, "offset", 0)
	total := len(filtered)

	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	payload := PaginatedSchemaList{
		Total:  total,
		Limit:  limit,
		Offset: offset,
		Data:   page,
	}

	h.writeResponse(w, r, payload)
}

func (h *Handler) getSchema(w http.ResponseWriter, r *http.Request) {
	schemaID := r.PathValue("schemaId")
	// Strip .json or .jwt suffix if present (static file compat)
	schemaID = strings.TrimSuffix(schemaID, ".json")
	schemaID = strings.TrimSuffix(schemaID, ".jwt")

	for _, sm := range h.schemas {
		if sm.ID == schemaID {
			h.writeResponse(w, r, sm)
			return
		}
	}
	http.Error(w, `{"error":"schema not found"}`, http.StatusNotFound)
}

func (h *Handler) getJWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.signer.JWKS()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jwks)
}

func (h *Handler) listAttributes(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	filtered := h.filterAttributes(q)

	limit := intParam(q, "limit", 20)
	offset := intParam(q, "offset", 0)
	total := len(filtered)

	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := filtered[offset:end]

	payload := PaginatedAttributeList{
		Total:  total,
		Limit:  limit,
		Offset: offset,
		Data:   page,
	}

	h.writeResponse(w, r, payload)
}

func (h *Handler) getAttribute(w http.ResponseWriter, r *http.Request) {
	attrID := r.PathValue("attrId")
	attrID = strings.TrimSuffix(attrID, ".json")
	attrID = strings.TrimSuffix(attrID, ".jwt")

	for i := range h.attrs {
		if h.attrs[i].Identifier == attrID {
			h.writeResponse(w, r, h.attrs[i])
			return
		}
	}
	http.Error(w, `{"error":"attribute not found"}`, http.StatusNotFound)
}

func (h *Handler) filterAttributes(q map[string][]string) []attributes.Attribute {
	result := make([]attributes.Attribute, 0, len(h.attrs))
	for _, attr := range h.attrs {
		if v := paramVal(q, "nameSpace"); v != "" && attr.NameSpace != v {
			continue
		}
		if v := paramVal(q, "identifier"); v != "" && attr.Identifier != v {
			continue
		}
		result = append(result, attr)
	}
	return result
}

// PaginatedAttributeList is the paginated response envelope for attributes.
type PaginatedAttributeList struct {
	Total  int                    `json:"total"`
	Limit  int                    `json:"limit"`
	Offset int                    `json:"offset"`
	Data   []attributes.Attribute `json:"data"`
}

func (h *Handler) writeResponse(w http.ResponseWriter, r *http.Request, data any) {
	if h.signer != nil {
		jsonData, err := json.Marshal(data)
		if err != nil {
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
		compact, err := h.signer.Sign(json.RawMessage(jsonData))
		if err != nil {
			http.Error(w, `{"error":"signing failed"}`, http.StatusInternalServerError)
			return
		}
		if h.jku != "" {
			w.Header().Set("x-jku-url", h.jku)
		}
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = fmt.Fprint(w, compact)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func (h *Handler) filterSchemas(q map[string][]string) []*schemameta.SchemaMeta {
	result := make([]*schemameta.SchemaMeta, 0, len(h.schemas))
	for _, sm := range h.schemas {
		if !matchSchema(sm, q) {
			continue
		}
		result = append(result, sm)
	}
	return result
}

func matchSchema(sm *schemameta.SchemaMeta, q map[string][]string) bool {
	if v := paramVal(q, "id"); v != "" && sm.ID != v {
		return false
	}
	if v := paramVal(q, "attestationLoS"); v != "" && sm.AttestationLoS != v {
		return false
	}
	if v := paramVal(q, "bindingType"); v != "" && sm.BindingType != v {
		return false
	}
	if v := paramVal(q, "rulebookUri"); v != "" && sm.RulebookURI != v {
		return false
	}

	// supportedFormats: comma-separated or repeated; schema must contain ALL requested formats
	if vals := paramVals(q, "supportedFormats"); len(vals) > 0 {
		fmtSet := make(map[string]bool, len(sm.SupportedFormats))
		for _, f := range sm.SupportedFormats {
			fmtSet[f] = true
		}
		for _, wanted := range vals {
			if !fmtSet[wanted] {
				return false
			}
		}
	}

	// trustedAuthoritiesFrameworkType
	if v := paramVal(q, "trustedAuthoritiesFrameworkType"); v != "" {
		found := false
		for _, ta := range sm.TrustedAuthorities {
			if ta.FrameworkType == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// trustedAuthoritiesValue
	if v := paramVal(q, "trustedAuthoritiesValue"); v != "" {
		found := false
		for _, ta := range sm.TrustedAuthorities {
			if ta.Value == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// schemaUri: match any schemaURI entry
	if v := paramVal(q, "schemaUri"); v != "" {
		found := false
		for _, su := range sm.SchemaURIs {
			if su.URI == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// PaginatedSchemaList is the TS11 paginated response envelope.
type PaginatedSchemaList struct {
	Total  int                      `json:"total"`
	Limit  int                      `json:"limit"`
	Offset int                      `json:"offset"`
	Data   []*schemameta.SchemaMeta `json:"data"`
}

func intParam(q map[string][]string, key string, defaultVal int) int {
	v := paramVal(q, key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return defaultVal
	}
	return n
}

func paramVal(q map[string][]string, key string) string {
	vals := q[key]
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func paramVals(q map[string][]string, key string) []string {
	vals := q[key]
	if len(vals) == 0 {
		return nil
	}
	// Support comma-separated values (OAS style: form, explode: false)
	var result []string
	for _, v := range vals {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				result = append(result, part)
			}
		}
	}
	return result
}
