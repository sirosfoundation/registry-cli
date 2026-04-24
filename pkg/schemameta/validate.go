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

// Validate checks a SchemaMeta object against the TS11 JSON schema.
func (v *Validator) Validate(sm *SchemaMeta) error {
	// Require non-empty governance fields beyond JSON schema structural validation
	if sm.AttestationLoS == "" {
		return fmt.Errorf("attestationLoS is required for TS11 compliance")
	}
	if sm.BindingType == "" {
		return fmt.Errorf("bindingType is required for TS11 compliance")
	}

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
