package rulebookcatalog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/repoplugin"
)

// An override keyed by a slug no credential has applies nothing and changes
// nothing in the output, so without a warning it is indistinguishable from an
// override that worked. The case that prompted this: the catalogue's
// eInvoice-sd-jwt.json yields the slug "eInvoice", and "einvoice" in
// sources.yaml silently does nothing.
func TestDiscover_WarnsOnUnmatchedOverride(t *testing.T) {
	repo := t.TempDir()
	sdDir := filepath.Join(repo, "data-schemas", "sd-jwt")
	if err := os.MkdirAll(sdDir, 0o755); err != nil {
		t.Fatal(err)
	}

	schema := map[string]interface{}{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"title":   "Test Credential",
		"type":    "object",
		"properties": map[string]interface{}{
			"vct":       map[string]interface{}{"type": "string", "const": "urn:test:1"},
			"some_name": map[string]interface{}{"type": "string"},
		},
	}
	data, _ := json.MarshalIndent(schema, "", "  ")
	if err := os.WriteFile(filepath.Join(sdDir, "eInvoice-sd-jwt.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	var logged bytes.Buffer
	ctx := repoplugin.Context{
		RepoDir:      repo,
		Organization: "testorg",
		BaseURL:      "https://registry.example.org",
		Credentials: map[string]repoplugin.CredentialOverride{
			// Right credential, wrong case.
			"einvoice": {Disclosure: &repoplugin.DisclosureOverride{Default: "never"}},
		},
		Logger: slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}

	plugin := &RulebookCatalog{}
	results, err := plugin.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].Slug != "eInvoice" {
		t.Fatalf("expected one credential with slug eInvoice, got %+v", results)
	}

	out := logged.String()
	if !strings.Contains(out, "einvoice") {
		t.Errorf("warning does not name the unmatched slug:\n%s", out)
	}
	if !strings.Contains(out, "eInvoice") {
		t.Errorf("warning does not name the slugs that do exist:\n%s", out)
	}

	// The override must not have been applied to the credential it nearly
	// matched.
	var vctm vctmOutput
	if err := json.Unmarshal(results[0].GeneratedVCTM, &vctm); err != nil {
		t.Fatal(err)
	}
	for _, claim := range vctm.Claims {
		if claim.SD == "never" {
			t.Errorf("claim %v took the override despite the slug not matching", claim.Path)
		}
	}
}

// The warning must stay quiet when every override matches, and when there are
// none at all.
func TestDiscover_NoWarningWhenOverridesMatch(t *testing.T) {
	repo := t.TempDir()
	sdDir := filepath.Join(repo, "data-schemas", "sd-jwt")
	if err := os.MkdirAll(sdDir, 0o755); err != nil {
		t.Fatal(err)
	}

	schema := map[string]interface{}{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"title":   "Test Credential",
		"type":    "object",
		"properties": map[string]interface{}{
			"vct":       map[string]interface{}{"type": "string", "const": "urn:test:1"},
			"some_name": map[string]interface{}{"type": "string"},
		},
	}
	data, _ := json.MarshalIndent(schema, "", "  ")
	if err := os.WriteFile(filepath.Join(sdDir, "eInvoice-sd-jwt.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	for name, overrides := range map[string]map[string]repoplugin.CredentialOverride{
		"matching": {"eInvoice": {Disclosure: &repoplugin.DisclosureOverride{Default: "never"}}},
		"none":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			var logged bytes.Buffer
			ctx := repoplugin.Context{
				RepoDir:      repo,
				Organization: "testorg",
				BaseURL:      "https://registry.example.org",
				Credentials:  overrides,
				Logger:       slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})),
			}
			if _, err := (&RulebookCatalog{}).Discover(ctx); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(logged.String(), "had no effect") {
				t.Errorf("unexpected warning:\n%s", logged.String())
			}
		})
	}
}
