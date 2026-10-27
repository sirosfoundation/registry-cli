// Package mdocinfo reads the descriptive fields of an mdoc data schema (the
// JSON Schema documents found in data-schemas/mdoc/ of rulebook catalogs).
package mdocinfo

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Info holds the descriptive fields of an mdoc data schema.
type Info struct {
	// Title is the schema's top-level "title".
	Title string
	// Description is the schema's top-level "description".
	Description string
	// DocType is the mdoc document type. It is read from a top-level
	// "docType" string, from "properties.docType.const", or from the first
	// "docType" property that declares a "const" anywhere in the document
	// (WE BUILD schemas nest it under "$defs"/"oneOf" branches). Empty when
	// the file declares none.
	DocType string
}

// maxDepth bounds the search for a nested docType.
const maxDepth = 12

// Parse extracts Info from an mdoc data schema. It returns an error when data
// is not a JSON object.
func Parse(data []byte) (Info, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return Info{}, fmt.Errorf("parsing mdoc schema: %w", err)
	}
	if doc == nil {
		return Info{}, fmt.Errorf("parsing mdoc schema: not a JSON object")
	}
	info := Info{}
	if s, ok := doc["title"].(string); ok {
		info.Title = strings.TrimSpace(s)
	}
	if s, ok := doc["description"].(string); ok {
		info.Description = strings.TrimSpace(s)
	}
	if s, ok := doc["docType"].(string); ok {
		info.DocType = strings.TrimSpace(s)
	} else {
		info.DocType = findDocType(doc, 0)
	}
	return info, nil
}

// findDocType returns the const of the first "docType" property found in a
// depth-first walk with sorted keys (deterministic).
func findDocType(node any, depth int) string {
	if depth > maxDepth {
		return ""
	}
	switch v := node.(type) {
	case map[string]any:
		if props, ok := v["properties"].(map[string]any); ok {
			if dt, ok := props["docType"].(map[string]any); ok {
				if c, ok := dt["const"].(string); ok && strings.TrimSpace(c) != "" {
					return strings.TrimSpace(c)
				}
			}
		}
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if r := findDocType(v[k], depth+1); r != "" {
				return r
			}
		}
	case []any:
		for _, e := range v {
			if r := findDocType(e, depth+1); r != "" {
				return r
			}
		}
	}
	return ""
}
