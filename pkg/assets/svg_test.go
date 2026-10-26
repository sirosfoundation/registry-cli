package assets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wrap = `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="10" height="10">%s</svg>`

func svg(body string) string { return strings.Replace(wrap, "%s", body, 1) }

func TestValidateSVG_Rejections(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"not xml", `this is not xml`},
		{"unclosed tag", `<svg xmlns="http://www.w3.org/2000/svg"><g></svg>`},
		{"empty", ``},
		{"wrong root", `<html><body/></html>`},
		{"script", svg(`<script>alert(1)</script>`)},
		{"script with prefix", `<s:svg xmlns:s="http://www.w3.org/2000/svg"><s:script>x</s:script></s:svg>`},
		{"foreignObject", svg(`<foreignObject><div/></foreignObject>`)},
		{"iframe", svg(`<iframe src="#a"/>`)},
		{"object", svg(`<object data="#a"/>`)},
		{"embed", svg(`<embed src="#a"/>`)},
		{"onload", `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`},
		{"onclick upper", svg(`<rect ONCLICK="x()"/>`)},
		{"javascript href", svg(`<a href="javascript:alert(1)"><rect/></a>`)},
		{"javascript obfuscated", svg(`<a xlink:href=" java&#9;script:alert(1)"><rect/></a>`)},
		{"data uri image", svg(`<image href="data:image/png;base64,AAAA"/>`)},
		{"data uri in fill", svg(`<rect fill="data:text/html,x"/>`)},
		{"external href", svg(`<image href="https://example.org/x.png"/>`)},
		{"external xlink href", svg(`<image xlink:href="http://example.org/x.png"/>`)},
		{"relative href", svg(`<image href="other.svg"/>`)},
		{"external src", svg(`<image src="https://example.org/x.png"/>`)},
		{"use external", svg(`<use href="other.svg#icon"/>`)},
		{"use external xlink", svg(`<use xlink:href="https://example.org/a.svg#i"/>`)},
		{"style import", svg(`<style>@import url(https://example.org/a.css);</style>`)},
		{"style external url", svg(`<style>rect{fill:url(https://example.org/a)}</style>`)},
		{"style attr external url", svg(`<rect style="fill:url('http://example.org/a')"/>`)},
		{"fill external url", svg(`<rect fill="url(http://example.org/a)"/>`)},
		{"animate href", svg(`<a><animate attributeName="href" values="https://example.org/"/></a>`)},
		{"entity declaration", `<!DOCTYPE svg [<!ENTITY a "aaaa">]><svg xmlns="http://www.w3.org/2000/svg">&a;</svg>`},
		{"too large", svg(`<!--` + strings.Repeat("a", MaxSVGSize) + `-->`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSVG([]byte(tc.doc)); err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
		})
	}
}

func TestValidateSVG_Accepts(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"plain", svg(`<rect width="5" height="5" fill="#fff"/>`)},
		{"xml prolog", `<?xml version="1.0" encoding="UTF-8"?>` + svg(`<g/>`)},
		{"same document use", svg(`<defs><g id="a"/></defs><use href="#a"/><use xlink:href="#a"/>`)},
		{"internal url ref", svg(`<defs><linearGradient id="g"/></defs><rect fill="url(#g)" style="stroke:url('#g')"/>`)},
		{"internal style", svg(`<style>.a{fill:url(#g)}</style><rect class="a"/>`)},
		{"text content with words", svg(`<text>onload javascript: data: script</text>`)},
		{"attribute starting with o", svg(`<rect opacity="0.5" overflow="hidden" orient="auto"/>`)},
		{"comment", svg(`<!-- script -->`)},
		{"claim placeholder", svg(`<text id="given_name">{{given_name}}</text>`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateSVG([]byte(tc.doc)); err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}

// TestValidateSVG_AcceptsFixtureCards validates every card in an optional
// real-world fixture tree named by REGISTRY_CLI_SVG_FIXTURE.
func TestValidateSVG_AcceptsFixtureCards(t *testing.T) {
	root := os.Getenv("REGISTRY_CLI_SVG_FIXTURE")
	if root == "" {
		t.Skip("REGISTRY_CLI_SVG_FIXTURE not set")
	}
	n := 0
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".svg") {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		n++
		if verr := ValidateSVG(data); verr != nil {
			t.Errorf("%s: %v", p, verr)
		}
		return nil
	})
	t.Logf("validated %d fixture SVGs", n)
}
