// Package config provides configuration handling for mtcvctm
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds the configuration for mtcvctm
type Config struct {
	// InputFile is the path to the input markdown file
	InputFile string `yaml:"input" json:"input"`

	// OutputFile is the path to the output VCTM file
	OutputFile string `yaml:"output" json:"output"`

	// OutputDir is the directory for output files (used in multi-format mode)
	OutputDir string `yaml:"output_dir" json:"output_dir"`

	// BaseURL is the base URL for generating image URLs
	BaseURL string `yaml:"base_url" json:"base_url"`

	// VCT is the Verifiable Credential Type identifier
	VCT string `yaml:"vct" json:"vct"`

	// Language is the default language for display properties
	Language string `yaml:"language" json:"language"`

	// GitHubAction indicates if running in GitHub Action mode
	GitHubAction bool `yaml:"github_action" json:"github_action"`

	// VCTMBranch is the branch to commit VCTM files to in GitHub Action mode
	VCTMBranch string `yaml:"vctm_branch" json:"vctm_branch"`

	// InlineImages embeds images as base64 data URLs in the VCTM
	InlineImages bool `yaml:"inline_images" json:"inline_images"`

	// Formats is a comma-separated list of output formats (vctm, mddl, w3c, all)
	Formats string `yaml:"formats" json:"formats"`
}

// DefaultConfig returns a configuration with default values
func DefaultConfig() *Config {
	return &Config{
		Language:   "en-US",
		VCTMBranch: "vctm",
		Formats:    "vctm", // Default to VCTM only for backward compatibility
	}
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: failed to read file %s: %w", path, err)
	}

	config := DefaultConfig()
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("config: failed to parse YAML: %w", err)
	}

	return config, nil
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.InputFile == "" {
		return fmt.Errorf("config: input file is required")
	}

	// Check if input file exists
	if _, err := os.Stat(c.InputFile); os.IsNotExist(err) {
		return fmt.Errorf("config: input file does not exist: %s", c.InputFile)
	}

	return nil
}

// GetOutputFile returns the output file path, deriving from input if not set
func (c *Config) GetOutputFile() string {
	if c.OutputFile != "" {
		return c.OutputFile
	}

	// Derive from input file: replace extension with .vctm
	base := filepath.Base(c.InputFile)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	dir := filepath.Dir(c.InputFile)

	return filepath.Join(dir, name+".vctm")
}

// GetVCT returns the VCT identifier, deriving from base_url if not set
func (c *Config) GetVCT() string {
	if c.VCT != "" {
		return c.VCT
	}

	if c.BaseURL != "" {
		// Derive from base_url and input filename
		base := filepath.Base(c.InputFile)
		ext := filepath.Ext(base)
		name := strings.TrimSuffix(base, ext)
		return strings.TrimSuffix(c.BaseURL, "/") + "/" + name
	}

	return ""
}

// SaveToFile saves the configuration to a YAML file
func (c *Config) SaveToFile(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: failed to marshal YAML: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("config: failed to write file %s: %w", path, err)
	}

	return nil
}

// Merge merges another config into this one, with the other taking precedence for non-empty values
func (c *Config) Merge(other *Config) {
	if other.InputFile != "" {
		c.InputFile = other.InputFile
	}
	if other.OutputFile != "" {
		c.OutputFile = other.OutputFile
	}
	if other.OutputDir != "" {
		c.OutputDir = other.OutputDir
	}
	if other.BaseURL != "" {
		c.BaseURL = other.BaseURL
	}
	if other.VCT != "" {
		c.VCT = other.VCT
	}
	if other.Language != "" {
		c.Language = other.Language
	}
	if other.GitHubAction {
		c.GitHubAction = true
	}
	if other.VCTMBranch != "" {
		c.VCTMBranch = other.VCTMBranch
	}
	if other.InlineImages {
		c.InlineImages = true
	}
	if other.Formats != "" {
		c.Formats = other.Formats
	}
}
