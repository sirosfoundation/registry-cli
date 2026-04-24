package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/registry-cli/pkg/discovery"
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

	// 4. Validate schemas against TS11 JSON schema
	validator, err := schemameta.NewValidator()
	if err != nil {
		logger.Warn("could not load TS11 schema validator", "error", err)
	} else {
		for _, sm := range schemas {
			if valErr := validator.Validate(sm); valErr != nil {
				logger.Warn("schema validation warning", "id", sm.ID, "error", valErr)
			}
		}
	}

	// 5. Write API outputs (unsigned JSON)
	if writeErr := writeOutputs(flagOutput, flagBaseURL, schemas); writeErr != nil {
		return fmt.Errorf("writing outputs: %w", writeErr)
	}

	// 6. Render HTML site
	credentials, err := buildCredentialData(repos, workDir, schemas, flagBaseURL)
	if err != nil {
		return fmt.Errorf("building credential data: %w", err)
	}

	renderer, err := render.NewRenderer(flagTemplates)
	if err != nil {
		return fmt.Errorf("creating renderer: %w", err)
	}

	siteData := render.SiteData{
		BaseURL:     flagBaseURL,
		Credentials: credentials,
		BuildTime:   time.Now().UTC().Format(time.RFC3339),
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
	if err := renderer.RenderTS11Docs(flagOutput, siteData); err != nil {
		return fmt.Errorf("rendering TS11 docs: %w", err)
	}
	if err := renderer.RenderAPIDocs(flagOutput, siteData); err != nil {
		return fmt.Errorf("rendering API docs: %w", err)
	}

	// 7. Copy OpenAPI spec
	if err := writeOpenAPISpec(flagOutput); err != nil {
		return fmt.Errorf("writing OpenAPI spec: %w", err)
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

	// Clone repo
	repoDir := filepath.Join(workDir, org, extractRepoName(repo.URL))
	if err := cloneRepo(repo.URL, repo.Branch, repoDir); err != nil {
		return nil, fmt.Errorf("cloning %s: %w", repo.URL, err)
	}

	// Find schema-meta files
	entries, err := os.ReadDir(repoDir)
	if err != nil {
		return nil, fmt.Errorf("reading repo dir: %w", err)
	}

	var schemas []*schemameta.SchemaMeta
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

		src, err := schemameta.ParseSource(filepath.Join(repoDir, name))
		if err != nil {
			logger.Warn("skipping schema-meta", "file", name, "error", err)
			continue
		}

		formats, formatFiles, err := schemameta.DetectFormats(repoDir, slug)
		if err != nil {
			logger.Warn("detecting formats", "slug", slug, "error", err)
			continue
		}

		// Check for co-located rulebook.md
		rulebookPath := filepath.Join(repoDir, "rulebook.md")
		if src.RulebookURI == "" {
			if _, err := os.Stat(rulebookPath); err == nil {
				src.RulebookURI = fmt.Sprintf("%s/%s/%s/rulebook.html", baseURL, org, slug)
			}
		}

		sm := schemameta.Infer(src, org, slug, baseURL, formats, formatFiles)
		schemas = append(schemas, sm)

		logger.Info("processed credential",
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

func extractOrg(cloneURL string) string {
	// https://github.com/sirosfoundation/demo-credentials.git → sirosfoundation
	cloneURL = strings.TrimSuffix(cloneURL, ".git")
	parts := strings.Split(cloneURL, "/")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func extractRepoName(cloneURL string) string {
	cloneURL = strings.TrimSuffix(cloneURL, ".git")
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
// including rulebook rendering if a rulebook.md is present.
func buildCredentialData(repos []discovery.ResolvedRepo, workDir string, schemas []*schemameta.SchemaMeta, baseURL string) ([]render.CredentialData, error) {
	// Build a map of org → schema for lookup
	var credentials []render.CredentialData

	for _, sm := range schemas {
		// Extract org and slug from the schema's SchemaURIs
		org, slug := orgSlugFromID(sm, baseURL)

		cred := render.CredentialData{
			Org:    org,
			Slug:   slug,
			Schema: sm,
		}

		// Look for rulebook.md in the cloned repo
		for _, repo := range repos {
			repoOrg := extractOrg(repo.URL)
			repoDir := filepath.Join(workDir, repoOrg, extractRepoName(repo.URL))
			rulebookPath := filepath.Join(repoDir, "rulebook.md")
			if repoOrg == org {
				if data, err := os.ReadFile(rulebookPath); err == nil {
					html, err := render.RenderMarkdown(data)
					if err == nil {
						cred.HasRulebook = true
						cred.RulebookHTML = html
					}
					break
				}
			}
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
