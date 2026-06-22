# registry-cli

[![CI](https://github.com/sirosfoundation/registry-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/sirosfoundation/registry-cli/actions/workflows/ci.yml)
[![Security](https://github.com/sirosfoundation/registry-cli/actions/workflows/security.yml/badge.svg)](https://github.com/sirosfoundation/registry-cli/actions/workflows/security.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/sirosfoundation/registry-cli)](https://goreportcard.com/report/github.com/sirosfoundation/registry-cli)
[![License](https://img.shields.io/badge/License-BSD_2--Clause-blue.svg)](LICENSE)

A CLI tool for building TS11-compliant Catalogue of Attestations sites from
credential schemas discovered across GitHub repositories.

## Overview

`registry-cli` discovers credential type metadata (VCTMs) from configured
source repositories, validates them against the TS11 schema-meta model, and
produces a static site with:

- Per-credential detail pages with TS11 metadata
- Rendered rulebooks (from co-located `rulebook.md`)
- A JSON API (`/api/v1/schemas.json`) with per-schema endpoints
- An OpenAPI specification
- Optional JWS signing of all API responses

## Installation

```sh
go install github.com/sirosfoundation/registry-cli/cmd/registry-cli@latest
```

## Usage

### Build a site

```sh
registry-cli build \
  --sources sources.yaml \
  --output dist \
  --base-url https://registry.siros.org \
  --templates templates-go \
  --static static
```

### Sign API responses (requires PKCS#11 or dev key)

```sh
registry-cli sign \
  --input dist/api/v1 \
  --key-mode dev
```

## Sources manifest

The `sources.yaml` file declares where to find credential repositories:

```yaml
defaults:
  branch: vctm

sources:
  # Auto-discover by GitHub topic
  - "github:topic/vctm?org=sirosfoundation"

  # Explicit repository
  - "git:https://github.com/org/repo.git"

  # Local directory with explicit organization label
  - url: "file:///path/to/local/credentials"
    organization: "MyOrg"

  # Remote repo with custom org label
  - url: "git:https://github.com/other/repo.git"
    organization: "CustomLabel"
```

Source entries can be plain strings or structs with `url` and optional
`organization` fields. Local (`file://`) sources default to organization
"Local" if no label is provided.

## Schema-meta: TS11 Governance Metadata

Each credential must have a co-located `.schema-meta.yaml` file (or `.schema-meta.json`) providing TS11 **Catalogue of Attestations** compliance metadata. Only **two fields are required**; all others are inferred automatically.

### Required Fields

| Field | Values | Description |
|-------|--------|-------------|
| `attestation_los` | `iso_18045_high`, `iso_18045_moderate`, `iso_18045_enhanced-basic`, `iso_18045_basic` | Attestation Level of Surety per ISO 18045. Friendly aliases (`high`, `moderate`, `enhanced-basic`, `basic`, `substantial`, `low`) are normalized automatically. |
| `binding_type` | `key`, `biometric`, `claim`, `none` | How the credential is bound to the holder. Friendly aliases (`cnf` → `key`, `holder` → `key`) are normalized. |

### Optional Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | string | `"0.1.0"` | Schema version (semver). Can also be derived from git tags. |
| `rulebook_uri` | string | *(auto-generated)* | URL to attestation rulebook. If omitted, registry-cli auto-detects from co-located `rulebook.md`. |
| `trusted_authorities` | array | *(empty)* | Trust framework references per TS11 §4.3.3. See [Trusted Authorities](#trusted-authorities) below. |

### Auto-Generated Fields (do NOT set these)

The following fields are inferred automatically at build time:

| Field | Source |
|-------|--------|
| `id` | UUID v5 deterministically derived from `org/slug` |
| `supportedFormats` | Detected from co-located files: `.vctm.json` → `dc+sd-jwt`, `.mdoc.json` → `mso_mdoc`, `.vc.json` → `jwt_vc_json` |
| `schemaURIs` | Generated from `supportedFormats` and registry base URL |

### Minimal Example

```yaml
attestation_los: iso_18045_high
binding_type: key
```

### Full Example

```yaml
attestation_los: iso_18045_high
binding_type: key
version: "1.0.0"
rulebook_uri: https://example.com/credentials/my-credential/rulebook
trusted_authorities:
  - framework_type: etsi_tl
    value: "https://tl.etsi.org/export/trustlist.xml"
    is_lote: false
  - framework_type: eidas
    value: "https://eidas.ec.europa.eu"
    is_lote: false
    trust_mark_id: "https://eidas.ec.europa.eu/markers/high"
    trust_mark_issuers:
      - "https://issuer.example.com"
```

### Trusted Authorities

Trusted authority entries define governance frameworks and trust marks:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `framework_type` | string | Yes | Identifier for the trust framework (e.g., `etsi_tl`, `eidas`, `custom-scheme`) |
| `value` | string | Yes | Trust list URL or authority endpoint |
| `is_lote` | boolean | No | Whether this is a List of Trusted Entities (LOTE) |
| `trust_mark_id` | string | No | URI identifying the trust mark |
| `trust_mark_issuers` | array of strings | No | URLs of entities authorized to issue this trust mark |

### File Placement

Place the `.schema-meta.yaml` file in the same directory and with the same base name as your credential files:

```
credentials/
├── my-credential.md              (markdown source)
├── my-credential.schema-meta.yaml (TS11 metadata)
├── my-credential.vctm.json       (auto-generated or pre-built)
├── my-credential.mdoc.json       (auto-generated or pre-built)
└── my-credential.vc.json         (auto-generated or pre-built)
```

### Publishing Without Schema-Meta

Credentials discovered without a `.schema-meta.yaml` file appear in the **human-readable site** but are **excluded** from TS11 API responses (`/api/v1/schemas.json`). This allows incremental migration to TS11 compliance.

## Packages

| Package | Purpose |
|---|---|
| `pkg/discovery` | Source resolution, GitHub topic search, repo cloning |
| `pkg/schemameta` | TS11 schema-meta parsing, inference, validation |
| `pkg/render` | HTML template rendering, markdown conversion |
| `pkg/jwssign` | JWS signing (dev, SoftHSM, YubiHSM) via PKCS#11 |
| `pkg/apihandler` | TS11 REST API with filtering, pagination, JWS-signed responses |
| `pkg/ts11compliance` | TS11 specification compliance test suite |
| `pkg/mdcred` | Markdown-based credential conversion |

## Output Formats

`registry-cli convert` transforms Markdown credential definitions into the following formats:

| Format | Aliases | Output file | Description |
|--------|---------|-------------|-------------|
| `vctm` | `sd-jwt`, `sdjwt` | `.vctm.json` | SD-JWT VC Type Metadata |
| `mddl` | `mdoc`, `mso_mdoc` | `.mdoc.json` | mDOC MDDL (ISO 18013-5) |
| `w3c` | `jwt_vc_json` | `.vc.json` | W3C VCDM 2.0 credential schema |
| `jsonschema` | `json-schema`, `schema` | `.schema.json` | Standalone JSON Schema (draft-07) |

By default all formats are generated. Use `--format` or `formats:` front matter to select specific formats.

## Serve (development)

```sh
registry-cli serve --sources sources.yaml --output dist --port 8080
```

## Docker

```sh
# Build and run with docker compose
docker compose up --build

# Or build the image directly
docker build -t registry-cli:latest .
docker run -p 8080:8080 -v ./sources:/data/sources:ro registry-cli:latest
```

## Security

### Markdown and Content Sanitization

`registry-cli` processes potentially untrusted content from external credential repositories (rulebooks, VCTM metadata). All user-generated content is sanitized to prevent XSS attacks:

#### Rulebook Markdown Sanitization

Attestation rulebooks are converted from Markdown to HTML and sanitized using a strict content security policy:

**Allowed elements:** paragraphs, headings, bold, italic, links, tables, lists, code blocks, blockquotes

**Blocked elements:** script tags, objects, embeds, SVGs, style tags, iframe, form

**Blocked attributes:** event handlers (onclick, onerror, etc.), style attributes, javascript: URIs, data: URIs

Example attack prevention:
```markdown
<!-- Blocked: scripts are stripped -->
<script>alert('xss')</script>

<!-- Blocked: event handlers are removed -->
<img src=x onerror="alert(1)">

<!-- Blocked: style attributes prevent CSS injection -->
<p style="position:fixed;...">Overlay</p>

<!-- Blocked: javascript: URIs are filtered -->
[Click me](javascript:alert(1))

<!-- Allowed: safe links are preserved -->
[Documentation](https://example.com/docs)
```

#### SVG and Image URI Validation

Credential metadata (VCTM) may reference images for logos and backgrounds:

- **Allowed:** `https://` and `http://` URIs pointing to external image files
- **Blocked:** `data:` URIs (inline data), `blob:` URIs, `javascript:` protocols, `file://` URIs

Invalid image URIs are silently removed from rendered credential pages. The implementation is in `pkg/render/vctm.go::SanitizeVCTM()`.

#### Testing

Comprehensive security tests verify sanitization effectiveness:

```bash
go test ./pkg/render -run "Sanitize" -v
```

Tests cover:
- XSS via script tags and event handlers
- CSS injection via style attributes
- SVG and object attacks
- Data URI attacks
- JavaScript protocol handlers
- Safe content preservation (links, tables, lists)

### Recommendations for Repository Maintainers

When publishing credentials with rulebooks:

1. **Avoid HTML in Markdown:** Write rulebooks using standard Markdown syntax
2. **Don't embed SVGs:** Reference SVGs via URLs only, never inline
3. **Use safe links:** Only use `https://` links to trusted documentation
4. **No styling:** Don't use HTML style attributes or CSS; format using Markdown
5. **No JavaScript:** Avoid any JavaScript references or data URIs

Example safe rulebook structure:
```markdown
# PID Attestation Rulebook

## Overview
This rulebook governs Personal ID credentials.

- [Framework documentation](https://example.com/pid-framework)
- [Technical specifications](https://example.com/pid-spec)

## Requirements
- Attestation LoS: high
- Binding type: key

## See also
- [PID Rulebook v1.5](https://example.com/pid-rulebook-1.5)
```

## Testing

```sh
make test              # Unit tests
make test-softhsm      # Include SoftHSM PKCS#11 integration tests
make coverage           # Coverage report
make lint               # Run linter
```

## License

See [LICENSE](LICENSE).
