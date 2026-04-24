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
```

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
| `pkg/jwssign` | JWS signing (dev, SoftHSM, YubiHSM) |
| `pkg/registry` | Registry data structures |

## License

See [LICENSE](LICENSE).
