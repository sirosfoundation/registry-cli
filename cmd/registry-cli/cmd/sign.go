package cmd

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/sirosfoundation/registry-cli/pkg/jwssign"
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign JSON API payloads as JWS",
	Long: `Sign unsigned JSON files produced by 'registry-cli build' as JWS compact
serialization. Uses PKCS#11 when --pkcs11-uri is provided, otherwise generates
an ephemeral in-memory key (suitable for development and CI).`,
	RunE: runSign,
}

var (
	flagInput        string
	flagPattern      string
	flagPKCS11URI    string
	flagKeyLabel     string
	flagIssuer       string
	flagJKU          string
	flagJWKSOutput   string
	flagAggregate    string
	flagPreviousJWKS string
	flagKeyRetention time.Duration
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
	signCmd.Flags().StringVar(&flagPreviousJWKS, "previous-jwks", "", "Path to previous JWKS file for key rotation (keys are retained for --key-retention)")
	signCmd.Flags().DurationVar(&flagKeyRetention, "key-retention", 30*24*time.Hour, "Duration to retain previous signing keys in JWKS after rotation")

	_ = signCmd.MarkFlagRequired("input")

	rootCmd.AddCommand(signCmd)
}

func runSign(cmd *cobra.Command, args []string) error {
	logger := slog.Default()

	// 1. Initialize signer: PKCS#11 if configured, otherwise ephemeral
	var signer *jwssign.Signer
	var err error

	if flagPKCS11URI != "" {
		signer, err = jwssign.NewSignerFromConfig(flagPKCS11URI, flagKeyLabel, flagIssuer, flagJKU)
		if err != nil {
			return fmt.Errorf("initializing PKCS#11 signer: %w", err)
		}
		logger.Info("initialized PKCS#11 signer", "key-label", flagKeyLabel, "issuer", flagIssuer)
	} else {
		if flagIssuer == "" {
			flagIssuer = "registry-cli"
		}
		signer, err = jwssign.NewEphemeralSigner(flagIssuer, flagJKU)
		if err != nil {
			return fmt.Errorf("initializing ephemeral signer: %w", err)
		}
		logger.Info("initialized ephemeral signer (no PKCS#11 configured)", "issuer", flagIssuer)
	}
	defer signer.Close()

	// 2. Sign individual files
	schemasDir := filepath.Join(flagInput, "schemas")
	if _, err := os.Stat(schemasDir); err == nil {
		signed, err := signer.SignDirectory(schemasDir, flagPattern)
		if err != nil {
			return fmt.Errorf("signing schemas: %w", err)
		}
		logger.Info("signed individual schemas", "count", len(signed))
	}

	// 2b. Sign attribute files
	attrsDir := filepath.Join(flagInput, "attributes")
	if _, err := os.Stat(attrsDir); err == nil {
		signed, err := signer.SignDirectory(attrsDir, flagPattern)
		if err != nil {
			return fmt.Errorf("signing attributes: %w", err)
		}
		logger.Info("signed individual attributes", "count", len(signed))

		// Sign attribute schemas too
		attrSchemasDir := filepath.Join(attrsDir, "schemas")
		if _, err := os.Stat(attrSchemasDir); err == nil {
			signedSchemas, err := signer.SignDirectory(attrSchemasDir, flagPattern)
			if err != nil {
				return fmt.Errorf("signing attribute schemas: %w", err)
			}
			logger.Info("signed attribute schemas", "count", len(signedSchemas))
		}
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

	// 4. Write JWKS (with key rotation support)
	jwksPath := flagJWKSOutput
	if jwksPath == "" {
		jwksPath = filepath.Join(flagInput, ".well-known", "jwks.json")
	}

	currentJWKS := signer.JWKS()

	// If --previous-jwks is set, merge old keys for rotation overlap
	var outputJWKS jwssign.TimestampedJWKS
	if flagPreviousJWKS != "" {
		previousJWKS, loadErr := jwssign.LoadTimestampedJWKS(flagPreviousJWKS)
		if loadErr != nil {
			logger.Warn("could not load previous JWKS, starting fresh", "error", loadErr)
			outputJWKS = jwssign.MergeJWKS(currentJWKS, jwssign.TimestampedJWKS{KeyAdded: make(map[string]int64)}, flagKeyRetention)
		} else {
			before := len(previousJWKS.Keys)
			outputJWKS = jwssign.MergeJWKS(currentJWKS, previousJWKS, flagKeyRetention)
			retained := len(outputJWKS.Keys) - len(currentJWKS.Keys)
			if retained > 0 {
				logger.Info("key rotation: retained previous keys", "previous", before, "retained", retained, "retention", flagKeyRetention)
			}
		}
	} else {
		// No previous JWKS — just wrap current key with timestamp
		outputJWKS = jwssign.MergeJWKS(currentJWKS, jwssign.TimestampedJWKS{KeyAdded: make(map[string]int64)}, flagKeyRetention)
	}

	if err := writeJWKS(outputJWKS, jwksPath); err != nil {
		return fmt.Errorf("writing JWKS: %w", err)
	}
	logger.Info("wrote JWKS", "output", jwksPath, "keys", len(outputJWKS.Keys))

	return nil
}

func writeJWKS(jwks jwssign.TimestampedJWKS, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling JWKS: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}
