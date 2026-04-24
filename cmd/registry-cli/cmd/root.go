package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version   = "dev"
	Commit    = "none"
	BuildTime = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "registry-cli",
	Short: "TS11-compliant credential registry builder and signer",
	Long: `registry-cli builds and signs TS11-compliant Catalogue of Attestations
from credential data discovered via sources.yaml.

It produces a static site with JWS-signed API responses suitable for
deployment to GitHub Pages, Cloudflare Pages, or any static hosting.`,
}

func Execute() error {
	return rootCmd.Execute()
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("registry-cli %s (commit: %s, built: %s)\n", Version, Commit, BuildTime)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
