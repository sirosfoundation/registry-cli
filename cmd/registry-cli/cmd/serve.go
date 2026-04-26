package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/registry-cli/pkg/apihandler"
	"github.com/sirosfoundation/registry-cli/pkg/attributes"
	"github.com/sirosfoundation/registry-cli/pkg/jwssign"
	"github.com/sirosfoundation/registry-cli/pkg/schemameta"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Build and serve the registry site with a local HTTP server",
	Long: `Build the registry site and start a local HTTP server to serve it.
The server implements the TS11 Catalogue of Attestations API with query filtering
and pagination. When signing flags are provided, API responses are JWS-signed.
Press Ctrl+C to stop the server.`,
	RunE: runServe,
}

var (
	flagServeAddr     string
	flagServePort     int
	flagServePKCS11   string
	flagServeKeyLabel string
	flagServeIssuer   string
	flagServeJKU      string
)

func init() {
	serveCmd.Flags().StringVar(&flagServeAddr, "addr", "127.0.0.1", "Address to bind to")
	serveCmd.Flags().IntVar(&flagServePort, "port", 8080, "Port to listen on")

	// Signing flags (optional — without these, API serves unsigned JSON)
	serveCmd.Flags().StringVar(&flagServePKCS11, "pkcs11-uri", "", "PKCS#11 URI for JWS signing (e.g. pkcs11:module=/path/lib.so;token=label;pin=1234)")
	serveCmd.Flags().StringVar(&flagServeKeyLabel, "key-label", "", "PKCS#11 key label for signing")
	serveCmd.Flags().StringVar(&flagServeIssuer, "issuer", "", "JWT issuer claim")
	serveCmd.Flags().StringVar(&flagServeJKU, "jku", "", "JWS Key URL header value")

	// Inherit build flags
	serveCmd.Flags().StringVar(&flagOutput, "output", "dist", "Output directory")
	serveCmd.Flags().StringVar(&flagBaseURL, "base-url", "", "Base URL for the registry site (defaults to http://addr:port)")
	serveCmd.Flags().StringVar(&flagSources, "sources", "sources.yaml", "Path to sources.yaml manifest")
	serveCmd.Flags().StringVar(&flagTemplates, "templates", "", "Path to site-specific template overrides")
	serveCmd.Flags().StringVar(&flagStatic, "static", "", "Path to static assets directory")
	rootCmd.AddCommand(serveCmd)
}

func runServe(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// Default base URL to the local server address
	if flagBaseURL == "" {
		flagBaseURL = fmt.Sprintf("http://%s:%d", flagServeAddr, flagServePort)
	}

	// Run the build
	logger.Info("building site...", "base-url", flagBaseURL)
	if err := runBuild(cmd, args); err != nil {
		return fmt.Errorf("build failed: %w", err)
	}

	// Load TS11-compliant schemas from the built API output
	schemas, err := loadBuiltSchemas(flagOutput)
	if err != nil {
		return fmt.Errorf("loading built schemas: %w", err)
	}
	logger.Info("loaded schemas for API", "count", len(schemas))

	// Set up optional JWS signer
	var signer *jwssign.Signer
	if flagServePKCS11 != "" && flagServeKeyLabel != "" {
		signer, err = jwssign.NewSignerFromConfig(flagServePKCS11, flagServeKeyLabel, flagServeIssuer, flagServeJKU)
		if err != nil {
			return fmt.Errorf("initializing signer: %w", err)
		}
		defer signer.Close()
		logger.Info("JWS signing enabled", "issuer", flagServeIssuer)
	} else {
		logger.Info("JWS signing not configured, serving unsigned JSON")
	}

	// Set up HTTP mux with API handler + static file fallback
	listenAddr := fmt.Sprintf("%s:%d", flagServeAddr, flagServePort)
	mux := http.NewServeMux()

	api := apihandler.New(schemas, signer, flagServeJKU)

	// Load built attributes catalogue
	builtAttrs, err := loadBuiltAttributes(flagOutput)
	if err != nil {
		logger.Warn("could not load attributes catalogue", "error", err)
	} else {
		api.SetAttributes(builtAttrs)
		logger.Info("loaded attributes for API", "count", len(builtAttrs))
	}

	api.Register(mux)

	// Static file server as fallback for HTML, format files, etc.
	fs := http.FileServer(http.Dir(flagOutput))
	mux.Handle("/", fs)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           securityHeaders(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	logger.Info("serving registry", "url", fmt.Sprintf("http://%s", listenAddr), "dir", flagOutput)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	return nil
}

// loadBuiltSchemas reads the schemas.json file produced by the build step.
func loadBuiltSchemas(outputDir string) ([]*schemameta.SchemaMeta, error) {
	path := filepath.Join(outputDir, "api", "v1", "schemas.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var payload struct {
		Data []*schemameta.SchemaMeta `json:"data"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return payload.Data, nil
}

func loadBuiltAttributes(outputDir string) ([]attributes.Attribute, error) {
	path := filepath.Join(outputDir, "api", "v1", "attributes.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var payload struct {
		Data []attributes.Attribute `json:"data"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return payload.Data, nil
}

// securityHeaders wraps an http.Handler and adds security response headers.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; img-src 'self' https://github.com; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
