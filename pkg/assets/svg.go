// Package assets validates and publishes visual assets (SVG card templates,
// logos) discovered by repository layout plugins.
package assets

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// MaxSVGSize is the largest SVG document accepted for publication.
const MaxSVGSize = 2 << 20

// forbiddenElements lists SVG elements that execute code or embed foreign
// documents. Names are compared in lower case without namespace prefix.
var forbiddenElements = map[string]bool{
	"script":        true,
	"foreignobject": true,
	"iframe":        true,
	"object":        true,
	"embed":         true,
}

// referenceAttributes carry URL references; only same-document "#id"
// fragments are accepted.
var referenceAttributes = map[string]bool{
	"href": true,
	"src":  true,
}

// ValidateSVG checks that data is a well-formed SVG document that is safe
// to serve from the registry origin. It returns a descriptive error for the
// first violation found. The document is walked with the encoding/xml
// tokenizer, so the checks follow the parsed structure of the document.
func ValidateSVG(data []byte) error {
	if len(data) == 0 {
		return errors.New("empty document")
	}
	if len(data) > MaxSVGSize {
		return fmt.Errorf("document larger than %d bytes", MaxSVGSize)
	}

	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	seenRoot := false
	styleDepth := 0

	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("not well-formed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.Directive:
			if strings.Contains(strings.ToUpper(string(t)), "ENTITY") {
				return errors.New("entity declarations are not allowed")
			}
		case xml.StartElement:
			name := strings.ToLower(t.Name.Local)
			if !seenRoot {
				seenRoot = true
				if name != "svg" {
					return fmt.Errorf("root element is <%s>, expected <svg>", t.Name.Local)
				}
			}
			if forbiddenElements[name] {
				return fmt.Errorf("forbidden element <%s>", t.Name.Local)
			}
			if name == "style" {
				styleDepth++
			}
			if err := checkAttributes(name, t.Attr); err != nil {
				return err
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "style") && styleDepth > 0 {
				styleDepth--
			}
		case xml.CharData:
			if styleDepth > 0 {
				if err := checkCSS(string(t)); err != nil {
					return fmt.Errorf("style element: %w", err)
				}
			}
		}
	}
	if !seenRoot {
		return errors.New("no root element")
	}
	return nil
}

func checkAttributes(element string, attrs []xml.Attr) error {
	animTarget := ""
	for _, a := range attrs {
		if strings.EqualFold(a.Name.Local, "attributeName") {
			animTarget = strings.ToLower(a.Value)
		}
	}
	for _, a := range attrs {
		local := strings.ToLower(a.Name.Local)
		value := normalizeValue(a.Value)

		if strings.HasPrefix(local, "on") {
			return fmt.Errorf("event handler attribute %q", a.Name.Local)
		}
		if referenceAttributes[local] && !strings.HasPrefix(value, "#") && value != "" {
			return fmt.Errorf("external reference in %q attribute: %q", a.Name.Local, truncate(a.Value))
		}
		for _, scheme := range []string{"javascript:", "vbscript:"} {
			if strings.HasPrefix(value, scheme) {
				return fmt.Errorf("%s URI in %q attribute", scheme, a.Name.Local)
			}
		}
		if strings.HasPrefix(value, "data:") {
			return fmt.Errorf("data: URI in %q attribute", a.Name.Local)
		}
		if local == "style" {
			if err := checkCSS(a.Value); err != nil {
				return fmt.Errorf("style attribute: %w", err)
			}
		} else if strings.Contains(value, "url(") {
			if err := checkCSS(a.Value); err != nil {
				return fmt.Errorf("%q attribute: %w", a.Name.Local, err)
			}
		}
		// Animation elements may rewrite href at runtime.
		if (element == "set" || element == "animate") && local != "attributename" &&
			(animTarget == "href" || animTarget == "xlink:href" || animTarget == "src") &&
			(local == "to" || local == "values" || local == "from") {
			v := strings.TrimSpace(value)
			if v != "" && !strings.HasPrefix(v, "#") {
				return fmt.Errorf("<%s> rewrites %s to an external value", element, animTarget)
			}
		}
	}
	return nil
}

// checkCSS rejects @import and url() references that leave the document.
func checkCSS(css string) error {
	l := strings.ToLower(css)
	if strings.Contains(l, "@import") {
		return errors.New("@import is not allowed")
	}
	if strings.Contains(l, "javascript:") || strings.Contains(l, "vbscript:") || strings.Contains(l, "expression(") {
		return errors.New("script reference in CSS")
	}
	rest := l
	for {
		i := strings.Index(rest, "url(")
		if i < 0 {
			return nil
		}
		rest = rest[i+4:]
		end := strings.Index(rest, ")")
		if end < 0 {
			return errors.New("unterminated url()")
		}
		target := strings.Trim(strings.TrimSpace(rest[:end]), `"'`)
		if !strings.HasPrefix(target, "#") {
			return fmt.Errorf("external url() reference %q", truncate(target))
		}
		rest = rest[end:]
	}
}

// normalizeValue lower-cases a value and drops whitespace and control
// characters, which browsers ignore inside URL schemes.
func normalizeValue(v string) string {
	var b strings.Builder
	for _, r := range v {
		if r <= ' ' || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

func truncate(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}
