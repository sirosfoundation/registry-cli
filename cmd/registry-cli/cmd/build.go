package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/registry-cli/pkg/discovery"
	"github.com/sirosfoundation/registry-cli/pkg/mdcred"
	"github.com/sirosfoundation/registry-cli/pkg/render"
	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Build the registry site and API payloads",
	Long: `Discover credential repositories from sources.yaml, fetch credential data,
infer SchemaMeta envelopes, and generate the static site with unsigned API payloads.`,
	RunE: runBuild,
}

var (
	flagOutput    string
	flagBaseURL   string
	flagSources   string
	flagTemplates string
	flagStatic    string
)

func init() {
	buildCmd.Flags().StringVar(&flagOutput, "output", "dist", "Output directory")
	buildCmd.Flags().StringVar(&flagBaseURL, "base-url", "https://registry.siros.org", "Base URL for the registry site")
	buildCmd.Flags().StringVar(&flagSources, "sources", "sources.yaml", "Path to sources.yaml manifest")
	buildCmd.Flags().StringVar(&flagTemplates, "templates", "", "Path to site-specific template overrides")
	buildCmd.Flags().StringVar(&flagStatic, "static", "", "Path to static assets directory")
	rootCmd.AddCommand(buildCmd)
}

func runBuild(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// 1. Load sources manifest
	manifest, err := discovery.LoadManifest(flagSources)
	if err != nil {
		return fmt.Errorf("loading sources: %w", err)
	}
	logger.Info("loaded sources manifest", "sources", len(manifest.Sources), "default_branch", manifest.Defaults.Branch)

	// 2. Resolve sources into concrete repos
	resolvers := buildResolvers()
	repos, err := discovery.ResolveAll(manifest, resolvers)
	if err != nil {
		return fmt.Errorf("resolving sources: %w", err)
	}
	logger.Info("resolved repos", "count", len(repos))
	for _, r := range repos {
		logger.Info("  repo", "url", r.URL, "branch", r.Branch, "origin", r.Origin)
	}

	// 3. Clone/fetch repos and discover credentials
	workDir, err := os.MkdirTemp("", "registry-cli-*")
	if err != nil {
		return fmt.Errorf("creating work directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(workDir) }()

	var schemas []*schemameta.SchemaMeta
	for _, repo := range repos {
		repoSchemas, processErr := processRepo(repo, workDir, flagBaseURL, logger)
		if processErr != nil {
			logger.Warn("skipping repo", "url", repo.URL, "error", processErr)
			continue
		}
		schemas = append(schemas, repoSchemas...)
	}
	logger.Info("discovered schemas", "count", len(schemas))

	// 4. Validate schemas against TS11 JSON schema and track compliance
	ts11Compliant := make(map[string]bool)
	var ts11Schemas []*schemameta.SchemaMeta
	validator, err := schemameta.NewValidator()
	if err != nil {
		logger.Warn("could not load TS11 schema validator", "error", err)
	} else {
		for _, sm := range schemas {
			if valErr := validator.Validate(sm); valErr != nil {
				logger.Info("credential is not TS11-compliant", "id", sm.ID, "reason", valErr)
			} else {
				ts11Compliant[sm.ID] = true
				ts11Schemas = append(ts11Schemas, sm)
			}
		}
	}
	logger.Info("TS11 compliance", "total", len(schemas), "compliant", len(ts11Schemas))

	// 5. Write API outputs (only TS11-compliant schemas)
	if writeErr := writeOutputs(flagOutput, flagBaseURL, ts11Schemas); writeErr != nil {
		return fmt.Errorf("writing outputs: %w", writeErr)
	}

	// 5b. Write legacy API output (all schemas, including non-TS11)
	if writeErr := writeLegacyOutput(flagOutput, schemas); writeErr != nil {
		return fmt.Errorf("writing legacy output: %w", writeErr)
	}

	// 6. Render HTML site (all credentials, with TS11 compliance flag)
	credentials, err := buildCredentialData(repos, workDir, flagOutput, schemas, flagBaseURL, ts11Compliant)
	if err != nil {
		return fmt.Errorf("building credential data: %w", err)
	}

	renderer, err := render.NewRenderer(flagTemplates)
	if err != nil {
		return fmt.Errorf("creating renderer: %w", err)
	}

	// Group credentials by org
	orgMap := make(map[string][]render.CredentialData)
	for _, cred := range credentials {
		orgMap[cred.Org] = append(orgMap[cred.Org], cred)
	}
	var orgs []render.OrgData
	for orgName, orgCreds := range orgMap {
		hasTS11 := false
		for _, c := range orgCreds {
			if c.TS11Compliant {
				hasTS11 = true
				break
			}
		}
		// Construct GitHub avatar URL from org name
		avatarURL := "https://github.com/" + orgName + ".png?size=80"
		orgs = append(orgs, render.OrgData{Name: orgName, Credentials: orgCreds, HasTS11: hasTS11, AvatarURL: avatarURL})
	}

	ts11Count := 0
	for _, c := range credentials {
		if c.TS11Compliant {
			ts11Count++
		}
	}

	siteData := render.SiteData{
		BaseURL:     flagBaseURL,
		Credentials: credentials,
		BuildTime:   time.Now().UTC().Format(time.RFC3339),
		Orgs:        orgs,
		TS11Count:   ts11Count,
	}

	if err := renderer.RenderIndex(flagOutput, siteData); err != nil {
		return fmt.Errorf("rendering index: %w", err)
	}
	for _, cred := range credentials {
		if err := renderer.RenderCredential(flagOutput, cred); err != nil {
			return fmt.Errorf("rendering credential %s/%s: %w", cred.Org, cred.Slug, err)
		}
		if err := renderer.RenderRulebook(flagOutput, cred); err != nil {
			return fmt.Errorf("rendering rulebook %s/%s: %w", cred.Org, cred.Slug, err)
		}
	}
	for _, orgData := range orgs {
		if err := renderer.RenderOrg(flagOutput, orgData); err != nil {
			return fmt.Errorf("rendering org %s: %w", orgData.Name, err)
		}
	}
	if err := renderer.RenderTS11Docs(flagOutput, siteData); err != nil {
		return fmt.Errorf("rendering TS11 docs: %w", err)
	}
	if err := renderer.RenderAPIDocs(flagOutput, siteData); err != nil {
		return fmt.Errorf("rendering API docs: %w", err)
	}
	if err := renderer.RenderExtraDocPages(flagOutput, siteData); err != nil {
		return fmt.Errorf("rendering extra doc pages: %w", err)
	}

	// 7. Copy OpenAPI spec
	if err := writeOpenAPISpec(flagOutput); err != nil {
		return fmt.Errorf("writing OpenAPI spec: %w", err)
	}

	// 7b. Write DCAT-AP catalog for machine discovery
	if err := writeDCATCatalog(flagOutput, flagBaseURL, schemas, siteData.BuildTime); err != nil {
		return fmt.Errorf("writing DCAT catalog: %w", err)
	}

	// 8. Copy static assets
	if flagStatic != "" {
		staticDst := filepath.Join(flagOutput, "static")
		if err := render.CopyStaticAssets(flagStatic, staticDst); err != nil {
			return fmt.Errorf("copying static assets: %w", err)
		}
	}

	logger.Info("build complete", "output", flagOutput, "schemas", len(schemas),
		"credentials", len(credentials))
	return nil
}

func buildResolvers() []discovery.Resolver {
	var resolvers []discovery.Resolver

	// GitHub resolver (uses GITHUB_TOKEN from environment)
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		resolvers = append(resolvers, discovery.NewGitHubResolverWithToken(token))
	} else {
		resolvers = append(resolvers, discovery.NewGitHubResolverUnauthenticated())
	}

	return resolvers
}

func processRepo(repo discovery.ResolvedRepo, workDir, baseURL string, logger *slog.Logger) ([]*schemameta.SchemaMeta, error) {
	// Extract org name from URL
	org := extractOrg(repo.URL)
	if org == "" {
		return nil, fmt.Errorf("cannot determine org from URL %q", repo.URL)
	}

	var repoDir string
	if repo.Origin == "local" {
		// Local directory: use file:// URL path directly, no git clone
		localPath := strings.TrimPrefix(repo.URL, "file://")
		absPath, err := filepath.Abs(localPath)
		if err != nil {
			return nil, fmt.Errorf("resolving local path %q: %w", localPath, err)
		}
		repoDir = absPath
		logger.Info("using local directory", "path", repoDir)
	} else {
		// Clone repo
		repoDir = filepath.Join(workDir, org, extractRepoName(repo.URL))
		if err := cloneRepo(repo.URL, repo.Branch, repoDir); err != nil {
			return nil, fmt.Errorf("cloning %s: %w", repo.URL, err)
		}
	}

	// Pass 0: convert markdown credential files to VCTM format files
	converted, err := mdcred.ConvertDir(repoDir, baseURL)
	if err != nil {
		logger.Warn("markdown credential conversion", "error", err)
	}
	for _, c := range converted {
		logger.Info("converted markdown credential", "slug", c.Slug, "formats", len(c.Files))
	}

	// Find schema-meta files
	entries, err := os.ReadDir(repoDir)
	if err != nil {
		return nil, fmt.Errorf("reading repo dir: %w", err)
	}

	var schemas []*schemameta.SchemaMeta
	knownSlugs := make(map[string]bool)

	// First pass: find schema-meta files (TS11 credentials)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		var slug string
		switch {
		case strings.HasSuffix(name, ".schema-meta.yaml"):
			slug = strings.TrimSuffix(name, ".schema-meta.yaml")
		case strings.HasSuffix(name, ".schema-meta.json"):
			slug = strings.TrimSuffix(name, ".schema-meta.json")
		default:
			continue
		}

		src, parseErr := schemameta.ParseSource(filepath.Join(repoDir, name))
		if parseErr != nil {
			logger.Warn("skipping schema-meta", "file", name, "error", parseErr)
			continue
		}

		formats, formatFiles, fmtErr := schemameta.DetectFormats(repoDir, slug)
		if fmtErr != nil {
			logger.Warn("detecting formats", "slug", slug, "error", fmtErr)
			continue
		}

		// Check for co-located rulebook.md
		rulebookPath := filepath.Join(repoDir, "rulebook.md")
		if src.RulebookURI == "" {
			if _, statErr := os.Stat(rulebookPath); statErr == nil {
				src.RulebookURI = fmt.Sprintf("%s/%s/%s/rulebook.html", baseURL, org, slug)
			}
		}

		sm := schemameta.Infer(src, org, slug, baseURL, formats, formatFiles)
		schemas = append(schemas, sm)
		knownSlugs[slug] = true

		logger.Info("processed credential",
			"org", org, "slug", slug, "id", sm.ID,
			"formats", sm.SupportedFormats)
	}

	// Second pass: discover legacy VCTM-only credentials (no schema-meta)
	legacySlugs, err := schemameta.DetectLegacyCredentials(repoDir, knownSlugs)
	if err != nil {
		logger.Warn("detecting legacy credentials", "error", err)
	}
	for _, slug := range legacySlugs {
		formats, formatFiles, err := schemameta.DetectFormats(repoDir, slug)
		if err != nil {
			logger.Warn("detecting formats for legacy credential", "slug", slug, "error", err)
			continue
		}
		if len(formats) == 0 {
			continue
		}

		sm := schemameta.InferLegacy(org, slug, baseURL, formats, formatFiles)
		schemas = append(schemas, sm)

		logger.Info("processed legacy credential",
			"org", org, "slug", slug, "id", sm.ID,
			"formats", sm.SupportedFormats)
	}

	return schemas, nil
}

func writeOutputs(outputDir, baseURL string, schemas []*schemameta.SchemaMeta) error {
	// Create directory structure
	apiDir := filepath.Join(outputDir, "api", "v1")
	schemasDir := filepath.Join(apiDir, "schemas")
	if err := os.MkdirAll(schemasDir, 0o755); err != nil {
		return err
	}

	// Write individual schema JSON files
	for _, sm := range schemas {
		data, err := json.MarshalIndent(sm, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling schema %s: %w", sm.ID, err)
		}
		path := filepath.Join(schemasDir, sm.ID+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}

	// Write aggregate schemas list (unsigned — signing happens in `registry-cli sign`)
	listPayload := map[string]any{
		"total":  len(schemas),
		"limit":  len(schemas),
		"offset": 0,
		"data":   schemas,
	}
	data, err := json.MarshalIndent(listPayload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling schema list: %w", err)
	}
	if err := os.WriteFile(filepath.Join(apiDir, "schemas.json"), data, 0o644); err != nil {
		return err
	}

	return nil
}

// writeLegacyOutput writes a legacy vctm-registry.json that includes ALL credentials
// (both TS11-compliant and non-TS11), preserving backward compatibility.
func writeLegacyOutput(outputDir string, schemas []*schemameta.SchemaMeta) error {
	type legacyCredential struct {
		ID               string   `json:"id"`
		Version          string   `json:"version"`
		SupportedFormats []string `json:"supportedFormats"`
		AttestationLoS   string   `json:"attestationLoS,omitempty"`
		BindingType      string   `json:"bindingType,omitempty"`
	}

	var creds []legacyCredential
	for _, sm := range schemas {
		creds = append(creds, legacyCredential{
			ID:               sm.ID,
			Version:          sm.Version,
			SupportedFormats: sm.SupportedFormats,
			AttestationLoS:   sm.AttestationLoS,
			BindingType:      sm.BindingType,
		})
	}

	payload := map[string]any{
		"total":       len(creds),
		"credentials": creds,
	}

	apiDir := filepath.Join(outputDir, "api", "v1")
	if err := os.MkdirAll(apiDir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling legacy registry: %w", err)
	}
	return os.WriteFile(filepath.Join(apiDir, "registry.json"), data, 0o644)
}

func extractOrg(cloneURL string) string {
	// Strip URL schemes: file:///path → /path, https://... → ...
	cloneURL = strings.TrimPrefix(cloneURL, "file://")
	cloneURL = strings.TrimSuffix(cloneURL, ".git")
	cloneURL = strings.TrimRight(cloneURL, "/")
	parts := strings.Split(cloneURL, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func extractRepoName(cloneURL string) string {
	cloneURL = strings.TrimPrefix(cloneURL, "file://")
	cloneURL = strings.TrimSuffix(cloneURL, ".git")
	cloneURL = strings.TrimRight(cloneURL, "/")
	parts := strings.Split(cloneURL, "/")
	if len(parts) >= 1 {
		return parts[len(parts)-1]
	}
	return ""
}

func cloneRepo(url, branch, dest string) error {
	return execGit("clone", "--depth", "1", "--branch", branch, url, dest)
}

// buildCredentialData constructs render.CredentialData for each schema,
// including VCTM content, format files, and rulebook rendering.
func buildCredentialData(repos []discovery.ResolvedRepo, workDir, outputDir string, schemas []*schemameta.SchemaMeta, baseURL string, ts11Compliant map[string]bool) ([]render.CredentialData, error) {
	var credentials []render.CredentialData

	for _, sm := range schemas {
		org, slug := orgSlugFromID(sm, baseURL)

		cred := render.CredentialData{
			Org:           org,
			Slug:          slug,
			Schema:        sm,
			TS11Compliant: ts11Compliant[sm.ID],
		}

		// Find the repo containing this credential
		for _, repo := range repos {
			repoOrg := extractOrg(repo.URL)
			if repoOrg != org {
				continue
			}
			var repoDir string
			if repo.Origin == "local" {
				localPath := strings.TrimPrefix(repo.URL, "file://")
				absPath, _ := filepath.Abs(localPath)
				repoDir = absPath
			} else {
				repoDir = filepath.Join(workDir, repoOrg, extractRepoName(repo.URL))
			}

			// Verify this repo has either a schema-meta file or a VCTM file for this slug
			found := false
			for _, ext := range []string{".schema-meta.yaml", ".schema-meta.json", ".vctm.json", ".vctm"} {
				if _, err := os.Stat(filepath.Join(repoDir, slug+ext)); err == nil {
					found = true
					break
				}
			}
			if !found {
				continue
			}

			// Source info
			cred.SourceURL = repo.URL
			cred.SourceOrg = repoOrg
			cred.SourceRepo = extractRepoName(repo.URL)

			// Read rulebook
			rulebookPath := filepath.Join(repoDir, "rulebook.md")
			if data, err := os.ReadFile(rulebookPath); err == nil {
				html, renderErr := render.RenderMarkdown(data)
				if renderErr == nil {
					cred.HasRulebook = true
					cred.RulebookHTML = html
				}
			}

			// Read and parse VCTM JSON (try .vctm.json first, then bare .vctm)
			vctmPath := filepath.Join(repoDir, slug+".vctm.json")
			if data, err := os.ReadFile(vctmPath); err == nil {
				cred.RawVCTMJSON = prettyFormatJSON(data)
				var vctm render.VCTMData
				if jsonErr := json.Unmarshal(data, &vctm); jsonErr == nil {
					cred.VCTM = &vctm
				}
			} else {
				// Try bare .vctm extension (legacy repos like SUNET/vc)
				bareVCTMPath := filepath.Join(repoDir, slug+".vctm")
				if data, err := os.ReadFile(bareVCTMPath); err == nil {
					cred.RawVCTMJSON = prettyFormatJSON(data)
					var vctm render.VCTMData
					if jsonErr := json.Unmarshal(data, &vctm); jsonErr == nil {
						cred.VCTM = &vctm
					}
				}
			}

			// Read mDOC JSON
			mdocPath := filepath.Join(repoDir, slug+".mdoc.json")
			if data, err := os.ReadFile(mdocPath); err == nil {
				cred.RawMdocJSON = prettyFormatJSON(data)
				cred.HasMdoc = true
			}

			// Read W3C VC JSON
			vcPath := filepath.Join(repoDir, slug+".vc.json")
			if data, err := os.ReadFile(vcPath); err == nil {
				cred.RawVCJSON = prettyFormatJSON(data)
				cred.HasVC = true
			}

			// Build available formats and copy format files to output
			cred.AvailableFormats = buildFormatInfo(org, slug, repoDir)
			copyFormatFiles(repoDir, outputDir, org, slug)

			break
		}

		if cred.SourceURL == "" {
			slog.Default().Warn("credential not matched to any repo", "org", org, "slug", slug, "id", sm.ID)
		}
		credentials = append(credentials, cred)
	}

	return credentials, nil
}

// orgSlugFromID extracts org and slug by reversing the UUID generation.
// Since we can't reverse a hash, we look at the schemaURIs for the org path.
func orgSlugFromID(sm *schemameta.SchemaMeta, baseURL string) (org, slug string) {
	if len(sm.SchemaURIs) > 0 {
		uri := sm.SchemaURIs[0].URI
		rest := strings.TrimPrefix(uri, baseURL+"/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) >= 1 {
			org = parts[0]
		}
		if len(parts) >= 2 {
			// filename like test_cred.vctm.json → extract slug
			filename := parts[1]
			for ext := range schemameta.FormatMapping {
				if strings.HasSuffix(filename, ext) {
					slug = strings.TrimSuffix(filename, ext)
					return
				}
			}
			// Also handle bare .vctm extension
			if strings.HasSuffix(filename, ".vctm") {
				slug = strings.TrimSuffix(filename, ".vctm")
				return
			}
		}
	}
	return
}

func writeOpenAPISpec(outputDir string) error {
	apiDir := filepath.Join(outputDir, "api", "v1")
	if err := os.MkdirAll(apiDir, 0o755); err != nil {
		return err
	}
	return render.WriteOpenAPISpec(filepath.Join(apiDir, "openapi.yaml"))
}

func writeDCATCatalog(outputDir, baseURL string, schemas []*schemameta.SchemaMeta, buildTime string) error {
	type distribution struct {
		Type      string `json:"@type"`
		AccessURL string `json:"dcat:accessURL"`
		MediaType string `json:"dcat:mediaType"`
		Title     string `json:"dcterms:title"`
	}
	type dataset struct {
		Type         string         `json:"@type"`
		Identifier   string         `json:"dcterms:identifier"`
		Title        string         `json:"dcterms:title"`
		Description  string         `json:"dcterms:description,omitempty"`
		Distribution []distribution `json:"dcat:distribution,omitempty"`
	}
	type catalog struct {
		Context     any       `json:"@context"`
		Type        string    `json:"@type"`
		Title       string    `json:"dcterms:title"`
		Description string    `json:"dcterms:description"`
		Publisher   any       `json:"dcterms:publisher"`
		Modified    string    `json:"dcterms:modified"`
		Homepage    string    `json:"foaf:homepage"`
		Datasets    []dataset `json:"dcat:dataset"`
	}

	var datasets []dataset
	for _, sm := range schemas {
		ds := dataset{
			Type:        "dcat:Dataset",
			Identifier:  sm.ID,
			Title:       sm.ID,
			Description: "Attestation schema (formats: " + strings.Join(sm.SupportedFormats, ", ") + ")",
			Distribution: []distribution{
				{
					Type:      "dcat:Distribution",
					AccessURL: baseURL + "/api/v1/schemas/" + sm.ID + ".json",
					MediaType: "application/json",
					Title:     "Schema metadata (JSON)",
				},
			},
		}
		datasets = append(datasets, ds)
	}

	cat := catalog{
		Context: []any{
			"https://www.w3.org/ns/dcat",
			map[string]string{
				"dcterms": "http://purl.org/dc/terms/",
				"dcat":    "http://www.w3.org/ns/dcat#",
				"foaf":    "http://xmlns.com/foaf/0.1/",
			},
		},
		Type:        "dcat:Catalog",
		Title:       "SIROS Credential Type Registry",
		Description: "Catalogue of Attestations implementing ETSI TS11",
		Publisher: map[string]string{
			"@type":     "foaf:Organization",
			"foaf:name": "SIROS Foundation",
		},
		Modified: buildTime,
		Homepage: baseURL,
		Datasets: datasets,
	}

	data, err := json.MarshalIndent(cat, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling DCAT catalog: %w", err)
	}

	return os.WriteFile(filepath.Join(outputDir, "catalog.jsonld"), data, 0o644)
}

func prettyFormatJSON(data []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return string(data)
	}
	return buf.String()
}

func buildFormatInfo(org, slug, repoDir string) []render.FormatInfo {
	type fmtDef struct {
		ext, name, label string
	}
	defs := []fmtDef{
		{".vctm.json", "SD-JWT", "SD-JWT VC Type Metadata"},
		{".mdoc.json", "mDOC", "mso_mdoc Credential Configuration"},
		{".vc.json", "W3C VC", "W3C VCDM 2.0 JSON Schema"},
	}
	var formats []render.FormatInfo
	for _, d := range defs {
		if _, err := os.Stat(filepath.Join(repoDir, slug+d.ext)); err == nil {
			formats = append(formats, render.FormatInfo{
				Name:  d.name,
				Label: d.label,
				File:  "/" + org + "/" + slug + d.ext,
			})
		}
	}
	// Also check for bare .vctm (legacy) if no .vctm.json was found
	if len(formats) == 0 || formats[0].Name != "SD-JWT" {
		if _, err := os.Stat(filepath.Join(repoDir, slug+".vctm")); err == nil {
			// Prepend SD-JWT entry for bare .vctm
			formats = append([]render.FormatInfo{{
				Name:  "SD-JWT",
				Label: "SD-JWT VC Type Metadata",
				File:  "/" + org + "/" + slug + ".vctm",
			}}, formats...)
		}
	}
	return formats
}

func copyFormatFiles(repoDir, outputDir, org, slug string) {
	// Copy files from FormatMapping
	for ext := range schemameta.FormatMapping {
		srcPath := filepath.Join(repoDir, slug+ext)
		data, err := os.ReadFile(srcPath)
		if err != nil {
			continue
		}
		dstDir := filepath.Join(outputDir, org)
		_ = os.MkdirAll(dstDir, 0o755)
		_ = os.WriteFile(filepath.Join(dstDir, slug+ext), data, 0o644)
	}
	// Also copy bare .vctm files
	bareVCTM := filepath.Join(repoDir, slug+".vctm")
	if data, err := os.ReadFile(bareVCTM); err == nil {
		dstDir := filepath.Join(outputDir, org)
		_ = os.MkdirAll(dstDir, 0o755)
		_ = os.WriteFile(filepath.Join(dstDir, slug+".vctm"), data, 0o644)
	}
}
