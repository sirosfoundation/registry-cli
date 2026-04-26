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

## Schema-meta

Each credential can have a co-located `.schema-meta.yaml` file providing
TS11 metadata:

```yaml
attestation_los: substantial
binding_type: cnf
version: "1.0"
```

These are discovered automatically from the vctm branch of each repository.

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

## Testing

```sh
make test              # Unit tests
make test-softhsm      # Include SoftHSM PKCS#11 integration tests
make coverage           # Coverage report
make lint               # Run linter
```

## License

See [LICENSE](LICENSE).
