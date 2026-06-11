// Package rules provides an extensible rules engine for normalizing VCTM data.
// Rules can transform, fix, or validate VCTM documents to ensure compatibility
// with the latest specification or to handle legacy field names.
package rules

import (
	"fmt"
	"strings"
)

// Rule defines the interface for a normalization rule.
// Rules are applied to VCTM data represented as map[string]interface{} to allow
// flexible transformation regardless of the source (markdown, JSON, etc.).
type Rule interface {
	// Name returns the unique identifier for this rule
	Name() string

	// Description returns a human-readable description of what the rule does
	Description() string

	// Apply transforms the VCTM data in place and returns true if any changes were made.
	// The rule receives the entire VCTM document as a map for maximum flexibility.
	Apply(data map[string]interface{}) (changed bool, err error)
}

// RuleFunc is a convenience type for creating rules from functions
type RuleFunc struct {
	name        string
	description string
	apply       func(map[string]interface{}) (bool, error)
}

func (r *RuleFunc) Name() string        { return r.name }
func (r *RuleFunc) Description() string { return r.description }
func (r *RuleFunc) Apply(data map[string]interface{}) (bool, error) {
	return r.apply(data)
}

// NewRule creates a rule from a function
func NewRule(name, description string, apply func(map[string]interface{}) (bool, error)) Rule {
	return &RuleFunc{name: name, description: description, apply: apply}
}

// Engine manages and applies normalization rules
type Engine struct {
	rules    []Rule
	disabled map[string]bool
	verbose  bool
}

// NewEngine creates a new rules engine with the default built-in rules
func NewEngine() *Engine {
	e := &Engine{
		rules:    make([]Rule, 0),
		disabled: make(map[string]bool),
	}
	// Register all built-in rules
	for _, rule := range builtinRules {
		e.Register(rule)
	}
	return e
}

// NewEmptyEngine creates a rules engine without any rules
func NewEmptyEngine() *Engine {
	return &Engine{
		rules:    make([]Rule, 0),
		disabled: make(map[string]bool),
	}
}

// Register adds a rule to the engine
func (e *Engine) Register(rule Rule) {
	e.rules = append(e.rules, rule)
}

// Disable prevents a rule from being applied
func (e *Engine) Disable(name string) {
	e.disabled[name] = true
}

// Enable allows a previously disabled rule to be applied
func (e *Engine) Enable(name string) {
	delete(e.disabled, name)
}

// SetVerbose enables verbose logging of rule applications
func (e *Engine) SetVerbose(verbose bool) {
	e.verbose = verbose
}

// Apply runs all enabled rules on the data and returns a summary of changes
func (e *Engine) Apply(data map[string]interface{}) (*Result, error) {
	result := &Result{
		Applied: make([]string, 0),
		Skipped: make([]string, 0),
	}

	for _, rule := range e.rules {
		if e.disabled[rule.Name()] {
			result.Skipped = append(result.Skipped, rule.Name())
			continue
		}

		changed, err := rule.Apply(data)
		if err != nil {
			return result, fmt.Errorf("rule %s failed: %w", rule.Name(), err)
		}

		if changed {
			result.Applied = append(result.Applied, rule.Name())
		}
	}

	return result, nil
}

// Rules returns all registered rules
func (e *Engine) Rules() []Rule {
	return e.rules
}

// Result contains the outcome of applying rules
type Result struct {
	Applied []string // Names of rules that made changes
	Skipped []string // Names of disabled rules
}

// String returns a human-readable summary
func (r *Result) String() string {
	if len(r.Applied) == 0 {
		return "No rules applied"
	}
	return fmt.Sprintf("Applied rules: %s", strings.Join(r.Applied, ", "))
}

// HasChanges returns true if any rules made changes
func (r *Result) HasChanges() bool {
	return len(r.Applied) > 0
}
