package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Build and serve the registry site with a local HTTP server",
	Long: `Build the registry site and start a local HTTP server to serve it.
This is useful for local development and preview. The site is rebuilt once
at startup. Press Ctrl+C to stop the server.`,
	RunE: runServe,
}

var (
	flagServeAddr string
	flagServePort int
)

func init() {
	serveCmd.Flags().StringVar(&flagServeAddr, "addr", "127.0.0.1", "Address to bind to")
	serveCmd.Flags().IntVar(&flagServePort, "port", 8080, "Port to listen on")

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

	// Serve the output directory
	listenAddr := fmt.Sprintf("%s:%d", flagServeAddr, flagServePort)
	mux := http.NewServeMux()
	fs := http.FileServer(http.Dir(flagOutput))
	mux.Handle("/", fs)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
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
