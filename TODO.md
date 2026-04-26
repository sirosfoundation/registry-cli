# Registry-CLI — Findings & Action Plan

Analysis date: 2026-04-26  
Last updated: 2026-04-26

## Architecture Overview

registry-cli is a Go CLI tool implementing ETSI TS11 "Catalogue of Attestations"
as a static-first, Git-as-write-API system. The tool discovers credential schemas
from git repositories (via `sources.yaml`), builds TS11-compliant SchemaMeta objects,
validates them against the normative JSON Schema, and generates:

- A static HTML site
- A TS11-compliant REST API (pre-built JSON + live serve mode)
- JWS-signed API responses via PKCS#11 (SoftHSM/YubiHSM)
- OpenAPI 3.1.0 specification
- DCAT-AP catalog for machine discovery

## What Has Been Accomplished

| Area                        | Status |
|-----------------------------|--------|
| TS11 Data Model (§4.3)      | ✅ Complete |
| JSON Schema validation      | ✅ Complete |
| Read-only API (§5.3.1)      | ✅ Complete |
| OpenAPI spec (Annex A.3)    | ✅ Complete |
| JWS signing via PKCS#11     | ✅ Complete |
| Legacy value normalization  | ✅ Complete |
| Source discovery pipeline    | ✅ Complete |
| HTML site rendering         | ✅ Complete |
| DCAT-AP catalog             | ✅ Complete |
| TS11 compliance test suite  | ✅ 45 tests |
| CI/CD (test/lint/CodeQL/vuln) | ✅ Complete |
| Docker container + GHCR publish | ✅ Complete |
| SoftHSM PKCS#11 integration tests | ✅ 9 tests |
| Mixed sources.yaml format (org labels) | ✅ Complete |
| Security hardening          | ✅ Complete |
| Test coverage >70%          | ✅ 78.6% |

## Explicit Out-of-Scope Decisions

| Item                              | Rationale |
|-----------------------------------|-----------|
| Write API (POST/PUT/DELETE §5.3.2–5.3.4) | Git-as-write-API design; authorization via PR review |
| Authentication & authorization    | Read-only API is public per TS11 §5.2.1 |
| Catalogue of Attributes (§4.2)   | Deferred to Phase 5 per design doc |
| GitLab/Bitbucket meta-sources    | Only GitHub implemented; future work |
| Runtime database                  | Static-first architecture |
| Rate limiting / API keys          | CDN-level concern (GitHub Pages) |

## Security Findings — All Resolved

### HIGH — XSS via unsanitized markdown rendering
- **Location:** `pkg/render/render.go` `RenderMarkdown()`
- **Fix:** Added `bluemonday.UGCPolicy()` HTML sanitization after goldmark rendering.
- **Test:** `TestRenderMarkdown_SanitizesXSS` verifies script, onerror, javascript: stripped.
- **Status:** ✅ Fixed

### MEDIUM — Missing HTTP server timeouts
- **Location:** `cmd/registry-cli/cmd/serve.go`
- **Fix:** Added `ReadTimeout: 30s`, `WriteTimeout: 30s`, `IdleTimeout: 120s`.
- **Status:** ✅ Fixed

### MEDIUM — No security headers on HTTP responses
- **Location:** `cmd/registry-cli/cmd/serve.go`
- **Fix:** Added `securityHeaders()` middleware: X-Content-Type-Options, X-Frame-Options, Referrer-Policy.
- **Status:** ✅ Fixed

### MEDIUM — PKCS#11 PIN in process arguments
- **Location:** `pkg/jwssign/jwssign.go` `ParsePKCS11URI()`
- **Fix:** Falls back to `PKCS11_PIN` environment variable when `pin=` not in URI.
- **Test:** `TestParsePKCS11URI_PINFromEnv`, `TestParsePKCS11URI_ExplicitPINOverridesEnv`.
- **Status:** ✅ Fixed

### LOW — Git argument injection via crafted branch names
- **Location:** `cmd/registry-cli/cmd/build.go` `cloneRepo()`
- **Fix:** Added `--` separator before URL and destination arguments.
- **Status:** ✅ Fixed

### LOW — Swallowed errors in file copy operations
- **Location:** `cmd/registry-cli/cmd/build.go` `copyFormatFiles()`
- **Fix:** Replaced `_ =` with `logger.Warn()` logging.
- **Status:** ✅ Fixed

### LOW — Path traversal via file:// sources
- **Location:** `pkg/discovery/discovery.go`
- **Fix:** Validates file:// paths are absolute after `filepath.Clean()`.
- **Test:** `TestResolveAll_FileURL_RelativePathRejected`.
- **Status:** ✅ Fixed

## Feature Implementation — All Complete

### Docker container for publishing ✅
- Multi-stage Dockerfile (golang:1.26-alpine → alpine:3.23)
- CGO_ENABLED=1 for crypto11/PKCS#11 support
- docker-compose.yml for local development
- `.github/workflows/docker-publish.yml` for GHCR (multi-arch amd64+arm64)
- Makefile targets: `docker`, `docker-run`

### Local file organization + org labels ✅
- `file://` sources default to "Local" organization
- `sources.yaml` supports mixed format: plain strings + structs with `url`/`organization`
- Custom `UnmarshalYAML` for `SourceEntry` handles both formats
- `ResolvedRepo.Organization` field propagated through build pipeline
- 7 new discovery tests covering all org label scenarios

### PKCS#11 SoftHSM integration tests ✅
- `pkg/jwssign/testutil/softhsm_helper.go` — reusable test helper
- `pkg/jwssign/jwssign_softhsm_test.go` — 12 tests with `//go:build softhsm`
- Tests: NewSigner, NewSignerFromConfig, Sign, JWKS, PublicJWK, SignFile, SignDirectory, SignAggregate, KeyNotFound
- CI updated with `test-softhsm` job (installs softhsm2 + opensc)
- Also fixed hex key ID decoding bug discovered during testing

## Test Coverage Summary

Total coverage: **78.6%** (target: >70%)

| Package         | Coverage | Tests |
|-----------------|----------|-------|
| discovery       | 94.4%    | 25    |
| schemameta      | 85.0%    | 24    |
| render          | 78.8%    | 15    |
| apihandler      | 76.8%    | 13    |
| jwssign         | 73.3%    | 14    |
| mdcred          | 57.6%    | 12    |
| ts11compliance  | —        | 45    |
| **Total**       | **78.6%**| **148** |

## Remaining Future Work

These are not blockers but opportunities for future improvement:

- **Write API**: If needed, implement POST/PUT/DELETE per TS11 §5.3.2–5.3.4
- **Catalogue of Attributes**: TS11 §4.2, deferred to Phase 5
- **mdcred coverage**: Currently 57.6% — `convertFile()` requires mtcvctm test fixtures
- **cmd/ tests**: Command-level integration tests (currently no test files)
- **GitLab/Bitbucket resolvers**: Additional meta-source types
- **CSP header**: Content-Security-Policy not yet added (low priority for static/API site)
- **E2E build pipeline test**: Full sources.yaml → site → API verification
