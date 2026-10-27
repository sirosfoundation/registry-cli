package rulebookcatalog

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/repoplugin"
)

const minimalSDJWT = `{"title":"T","type":"object","properties":{"vct":{"const":"urn:test:1"},"a":{"type":"string"}}}`
const minimalMdoc = `{"title":"Mdoc T","description":"Mdoc D","docType":"org.test.1"}`

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiscover_MdocOnlyAndMixed(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		opts  map[string]string
		// slug -> expected formats (sorted)
		want map[string][]string
	}{
		{"sd-jwt only", map[string]string{"data-schemas/sd-jwt/a-sd-jwt.json": minimalSDJWT},
			nil, map[string][]string{"a": {"dc+sd-jwt"}}},
		{"mdoc only", map[string]string{"data-schemas/mdoc/b-mdoc.json": minimalMdoc},
			nil, map[string][]string{"b": {"mso_mdoc"}}},
		{"both", map[string]string{
			"data-schemas/sd-jwt/c-sd-jwt.json": minimalSDJWT,
			"data-schemas/mdoc/c-mdoc.json":     minimalMdoc},
			nil, map[string][]string{"c": {"dc+sd-jwt", "mso_mdoc"}}},
		{"none", map[string]string{"README.md": "x"}, nil, map[string][]string{}},
		{"unreadable mdoc is skipped, others continue", map[string]string{
			"data-schemas/mdoc/bad-mdoc.json":  `{nope`,
			"data-schemas/mdoc/good-mdoc.json": minimalMdoc},
			nil, map[string][]string{"good": {"mso_mdoc"}}},
		{"slug normalisation keeps case", map[string]string{
			"data-schemas/mdoc/ds009-eInvoice-mdoc.json": minimalMdoc,
			"data-schemas/sd-jwt/ds002-pid-sd-jwt.json":  minimalSDJWT,
			"data-schemas/mdoc/ds002-pid-mdoc.json":      minimalMdoc},
			nil, map[string][]string{"eInvoice": {"mso_mdoc"}, "pid": {"dc+sd-jwt", "mso_mdoc"}}},
		{"sd-jwt slug match suppresses duplicate mdoc-only type", map[string]string{
			"data-schemas/sd-jwt/ds002-pid-sd-jwt.json": minimalSDJWT,
			"data-schemas/mdoc/pid-mdoc.json":           minimalMdoc},
			nil, map[string][]string{"pid": {"dc+sd-jwt", "mso_mdoc"}}},
		{"sd-jwt without prefix attaches prefixed mdoc", map[string]string{
			"data-schemas/sd-jwt/pid-sd-jwt.json":   minimalSDJWT,
			"data-schemas/mdoc/ds002-pid-mdoc.json": minimalMdoc},
			nil, map[string][]string{"pid": {"dc+sd-jwt", "mso_mdoc"}}},
		{"options apply to mdoc-only", map[string]string{
			"data-schemas/mdoc/m-mdoc.json": minimalMdoc,
			"rulebooks/rb-m/README.md":      "# m"},
			map[string]string{"attestation_los": "iso_18045_high", "binding_type": "key", "version": "2.0.0"},
			map[string][]string{"m": {"mso_mdoc"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for rel, c := range tt.files {
				writeFile(t, root, rel, c)
			}
			creds, err := (&RulebookCatalog{}).Discover(repoplugin.Context{
				RepoDir: root, Organization: "org", BaseURL: "https://r.example",
				Options: tt.opts, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string][]string{}
			for _, c := range creds {
				var f []string
				for k := range c.FormatFiles {
					f = append(f, k)
				}
				sort.Strings(f)
				got[c.Slug] = f
				if len(c.GeneratedVCTM) > 0 != (len(f) > 0 && f[0] == "dc+sd-jwt") {
					t.Errorf("%s: GeneratedVCTM presence does not match sd-jwt format", c.Slug)
				}
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for slug, w := range tt.want {
				g := got[slug]
				if len(g) != len(w) {
					t.Fatalf("%s: formats %v, want %v", slug, g, w)
				}
				for i := range w {
					if g[i] != w[i] {
						t.Fatalf("%s: formats %v, want %v", slug, g, w)
					}
				}
			}
			if tt.opts != nil {
				c := creds[0]
				if c.SchemaMetaSource == nil || c.SchemaMetaSource.AttestationLoS != "iso_18045_high" ||
					c.SchemaMetaSource.BindingType != "key" || c.SchemaMetaSource.Version != "2.0.0" {
					t.Errorf("options not applied: %+v", c.SchemaMetaSource)
				}
				if c.SchemaMetaSource.RulebookURI != "https://r.example/org/m/rulebook.html" || c.RulebookPath == "" {
					t.Errorf("rulebook not attached: %+v %q", c.SchemaMetaSource, c.RulebookPath)
				}
			} else if len(creds) > 0 && creds[0].SchemaMetaSource != nil {
				t.Errorf("SchemaMetaSource set without options")
			}
		})
	}
}

func TestDiscover_MdocOnlyAssets(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "data-schemas/mdoc/m-mdoc.json", minimalMdoc)
	writeFile(t, root, "assets/m/card.svg", "<svg/>")
	writeFile(t, root, "assets/m/logo.png", "x")
	creds, err := (&RulebookCatalog{}).Discover(repoplugin.Context{
		RepoDir: root, Organization: "org", BaseURL: "https://r.example",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil || len(creds) != 1 {
		t.Fatalf("creds=%d err=%v", len(creds), err)
	}
	if creds[0].Assets["svg_template"] == "" || creds[0].Assets["logo"] == "" {
		t.Errorf("assets not discovered: %v", creds[0].Assets)
	}
}
