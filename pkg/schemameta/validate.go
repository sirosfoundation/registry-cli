package schemameta

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

//go:embed ts11_schema.json
var ts11SchemaJSON []byte

// Validator validates SchemaMeta objects against the TS11 JSON schema.
type Validator struct {
	schema *jsonschema.Schema
}

// NewValidator creates a validator using the embedded TS11 JSON schema.
func NewValidator() (*Validator, error) {
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("ts11-schema.json", bytes.NewReader(ts11SchemaJSON)); err != nil {
		return nil, fmt.Errorf("adding schema resource: %w", err)
	}
	schema, err := compiler.Compile("ts11-schema.json")
	if err != nil {
		return nil, fmt.Errorf("compiling TS11 schema: %w", err)
	}
	return &Validator{schema: schema}, nil
}

// ValidateRaw checks a raw map against the TS11 JSON schema.
// This is used to test additionalProperties enforcement.
func (v *Validator) ValidateRaw(obj any) error {
	return v.schema.Validate(obj)
}

// Validate checks a SchemaMeta object against the TS11 JSON schema.
func (v *Validator) Validate(sm *SchemaMeta) error {
	// Require non-empty governance fields beyond JSON schema structural validation.
	// Go serializes empty strings as "", which passes JSON Schema "type": "string",
	// but TS11 requires these fields to carry meaningful values.
	if sm.Version == "" {
		return fmt.Errorf("version is required for TS11 compliance")
	}
	if sm.AttestationLoS == "" {
		return fmt.Errorf("attestationLoS is required for TS11 compliance")
	}
	if sm.BindingType == "" {
		return fmt.Errorf("bindingType is required for TS11 compliance")
	}
	if sm.RulebookURI == "" {
		return fmt.Errorf("rulebookURI is required for TS11 compliance")
	}
	for i, ta := range sm.TrustedAuthorities {
		if ta.FrameworkType == "" {
			return fmt.Errorf("trustedAuthorities[%d].frameworkType is required", i)
		}
		if ta.Value == "" {
			return fmt.Errorf("trustedAuthorities[%d].value is required", i)
		}
	}

	// Marshal for JSON Schema validation — include id in the object for schema
	// validation but the normative schema does not require it (readOnly).
	data, err := json.Marshal(sm)
	if err != nil {
		return fmt.Errorf("marshaling schema for validation: %w", err)
	}
	var obj any
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("unmarshaling for validation: %w", err)
	}
	return v.schema.Validate(obj)
}
