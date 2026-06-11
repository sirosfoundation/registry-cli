package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Language != "en-US" {
		t.Errorf("Default language should be en-US, got %s", cfg.Language)
	}
	if cfg.VCTMBranch != "vctm" {
		t.Errorf("Default vctm_branch should be vctm, got %s", cfg.VCTMBranch)
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	configContent := `input: test.md
output: test.vctm
base_url: https://example.com
vct: https://example.com/credential/test
language: de-DE
vctm_branch: main
`
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if cfg.InputFile != "test.md" {
		t.Errorf("InputFile = %s, want test.md", cfg.InputFile)
	}
	if cfg.OutputFile != "test.vctm" {
		t.Errorf("OutputFile = %s, want test.vctm", cfg.OutputFile)
	}
	if cfg.BaseURL != "https://example.com" {
		t.Errorf("BaseURL = %s, want https://example.com", cfg.BaseURL)
	}
	if cfg.Language != "de-DE" {
		t.Errorf("Language = %s, want de-DE", cfg.Language)
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/config.yaml")
	if err == nil {
		t.Error("LoadFromFile() should fail for non-existent file")
	}
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	if err := os.WriteFile(configPath, []byte("invalid: yaml: content:"), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	_, err := LoadFromFile(configPath)
	if err == nil {
		t.Error("LoadFromFile() should fail for invalid YAML")
	}
}

func TestConfig_Validate(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.md")
	if err := os.WriteFile(testFile, []byte("# Test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name:    "empty input",
			config:  Config{},
			wantErr: true,
		},
		{
			name: "non-existent input",
			config: Config{
				InputFile: "/nonexistent/file.md",
			},
			wantErr: true,
		},
		{
			name: "valid config",
			config: Config{
				InputFile: testFile,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestConfig_GetOutputFile(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{
			name: "explicit output",
			config: Config{
				InputFile:  "/path/to/input.md",
				OutputFile: "/path/to/output.vctm",
			},
			want: "/path/to/output.vctm",
		},
		{
			name: "derived from input",
			config: Config{
				InputFile: "/path/to/credential.md",
			},
			want: "/path/to/credential.vctm",
		},
		{
			name: "derived from input with different extension",
			config: Config{
				InputFile: "/path/to/document.markdown",
			},
			want: "/path/to/document.vctm",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetOutputFile()
			if got != tt.want {
				t.Errorf("Config.GetOutputFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_GetVCT(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{
			name: "explicit vct",
			config: Config{
				VCT: "https://example.com/credentials/test",
			},
			want: "https://example.com/credentials/test",
		},
		{
			name: "derived from base_url",
			config: Config{
				InputFile: "/path/to/identity.md",
				BaseURL:   "https://registry.example.com",
			},
			want: "https://registry.example.com/identity",
		},
		{
			name: "derived from base_url with trailing slash",
			config: Config{
				InputFile: "/path/to/identity.md",
				BaseURL:   "https://registry.example.com/",
			},
			want: "https://registry.example.com/identity",
		},
		{
			name:   "empty when no vct or base_url",
			config: Config{},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetVCT()
			if got != tt.want {
				t.Errorf("Config.GetVCT() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_SaveToFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")

	cfg := &Config{
		InputFile:  "test.md",
		OutputFile: "test.vctm",
		BaseURL:    "https://example.com",
		Language:   "en-US",
	}

	if err := cfg.SaveToFile(configPath); err != nil {
		t.Fatalf("SaveToFile() error = %v", err)
	}

	// Load it back and verify
	loaded, err := LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile() error = %v", err)
	}

	if loaded.InputFile != cfg.InputFile {
		t.Errorf("InputFile mismatch")
	}
	if loaded.BaseURL != cfg.BaseURL {
		t.Errorf("BaseURL mismatch")
	}
}

func TestConfig_Merge(t *testing.T) {
	base := &Config{
		InputFile: "base.md",
		Language:  "en-US",
	}

	overlay := &Config{
		OutputFile:   "output.vctm",
		Language:     "de-DE",
		GitHubAction: true,
	}

	base.Merge(overlay)

	if base.InputFile != "base.md" {
		t.Errorf("InputFile should remain base.md")
	}
	if base.OutputFile != "output.vctm" {
		t.Errorf("OutputFile should be merged")
	}
	if base.Language != "de-DE" {
		t.Errorf("Language should be overridden")
	}
	if !base.GitHubAction {
		t.Errorf("GitHubAction should be true")
	}
}
