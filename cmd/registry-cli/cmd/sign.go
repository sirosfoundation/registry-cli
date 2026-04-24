package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/sirosfoundation/registry-cli/pkg/jwssign"
	"github.com/spf13/cobra"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign JSON API payloads as JWS via PKCS#11",
	Long: `Sign unsigned JSON files produced by 'registry-cli build' as JWS compact
serialization using PKCS#11. Supports SoftHSM2 and YubiHSM2 backends.`,
	RunE: runSign,
}

var (
	flagInput      string
	flagPattern    string
	flagPKCS11URI  string
	flagKeyLabel   string
	flagIssuer     string
	flagJKU        string
	flagJWKSOutput string
	flagAggregate  string
)

func init() {
	signCmd.Flags().StringVar(&flagInput, "input", "", "Input directory containing JSON files to sign")
	signCmd.Flags().StringVar(&flagPattern, "pattern", "*.json", "Glob pattern for files to sign")
	signCmd.Flags().StringVar(&flagPKCS11URI, "pkcs11-uri", "", "PKCS#11 URI for the signing key")
	signCmd.Flags().StringVar(&flagKeyLabel, "key-label", "registry-signing", "Label of the signing key in the HSM")
	signCmd.Flags().StringVar(&flagIssuer, "issuer", "", "JWT issuer (iss claim)")
	signCmd.Flags().StringVar(&flagJKU, "jku", "", "JWS Key URL (jku header)")
	signCmd.Flags().StringVar(&flagJWKSOutput, "jwks-output", "", "Path to write JWKS public key file")
	signCmd.Flags().StringVar(&flagAggregate, "aggregate", "", "Path to write aggregate JWS (for schemas list)")

	_ = signCmd.MarkFlagRequired("input")
	_ = signCmd.MarkFlagRequired("pkcs11-uri")
	_ = signCmd.MarkFlagRequired("issuer")

	rootCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// 1. Initialize PKCS#11 signer
	signer, err := jwssign.NewSignerFromConfig(flagPKCS11URI, flagKeyLabel, flagIssuer, flagJKU)
	if err != nil {
		return fmt.Errorf("initializing signer: %w", err)
	}
	defer signer.Close()

	logger.Info("initialized PKCS#11 signer", "key-label", flagKeyLabel, "issuer", flagIssuer)

	// 2. Sign individual files
	schemasDir := filepath.Join(flagInput, "schemas")
	if _, err := os.Stat(schemasDir); err == nil {
		signed, err := signer.SignDirectory(schemasDir, flagPattern)
		if err != nil {
			return fmt.Errorf("signing schemas: %w", err)
		}
		logger.Info("signed individual schemas", "count", len(signed))
	}

	// 3. Sign aggregate (schemas list)
	aggregatePath := flagAggregate
	if aggregatePath == "" {
		aggregatePath = filepath.Join(flagInput, "schemas.jwt")
	}
	if err := signer.SignAggregate(schemasDir, flagPattern, aggregatePath); err != nil {
		return fmt.Errorf("signing aggregate: %w", err)
	}
	logger.Info("signed aggregate schema list", "output", aggregatePath)

	// 4. Write JWKS
	jwksPath := flagJWKSOutput
	if jwksPath == "" {
		jwksPath = filepath.Join(flagInput, ".well-known", "jwks.json")
	}
	if err := writeJWKS(signer, jwksPath); err != nil {
		return fmt.Errorf("writing JWKS: %w", err)
	}
	logger.Info("wrote JWKS", "output", jwksPath)

	return nil
}

func writeJWKS(signer *jwssign.Signer, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	jwks := signer.JWKS()
	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JWKS: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
