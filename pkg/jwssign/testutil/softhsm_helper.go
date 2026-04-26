package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// SoftHSMTestHelper provides utilities for testing with SoftHSM.
type SoftHSMTestHelper struct {
	TokenDir    string
	TokenName   string
	SlotID      int
	UserPIN     string
	SOUserPIN   string
	LibPath     string
	initialized bool
}

// NewSoftHSMTestHelper creates a new SoftHSM test helper.
func NewSoftHSMTestHelper() *SoftHSMTestHelper {
	uuid := make([]byte, 8)
	_, _ = rand.Read(uuid)
	dirName := fmt.Sprintf("registry-cli-softhsm-test-%d-%x", time.Now().UnixNano(), uuid)

	return &SoftHSMTestHelper{
		TokenDir:  filepath.Join(os.TempDir(), dirName),
		TokenName: "registry-cli-test-token",
		SlotID:    0,
		UserPIN:   "1234",
		SOUserPIN: "5678",
	}
}

// IsSoftHSMAvailable checks if SoftHSM is available on the system.
func (h *SoftHSMTestHelper) IsSoftHSMAvailable() bool {
	commonPaths := []string{
		"/usr/lib/softhsm/libsofthsm2.so",
		"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
		"/usr/local/lib/softhsm/libsofthsm2.so",
		"/usr/lib64/softhsm/libsofthsm2.so",
	}

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			h.LibPath = path
			return true
		}
	}

	_, err := exec.LookPath("softhsm2-util")
	return err == nil
}

// Setup creates a new SoftHSM token for testing.
func (h *SoftHSMTestHelper) Setup() error {
	if err := os.MkdirAll(h.TokenDir, 0o700); err != nil {
		return fmt.Errorf("creating token directory: %w", err)
	}

	confPath := filepath.Join(h.TokenDir, "softhsm2.conf")
	confContent := fmt.Sprintf("directories.tokendir = %s\nobjectstore.backend = file\nlog.level = INFO\nslots.removable = true\n", h.TokenDir)

	if err := os.WriteFile(confPath, []byte(confContent), 0o600); err != nil {
		return fmt.Errorf("creating SoftHSM config: %w", err)
	}

	if err := os.Setenv("SOFTHSM2_CONF", confPath); err != nil {
		return fmt.Errorf("setting SOFTHSM2_CONF: %w", err)
	}

	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", h.TokenName,
		"--so-pin", h.SOUserPIN,
		"--pin", h.UserPIN)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("initializing token: %w, output: %s", err, output)
	}

	outputStr := string(output)
	for _, line := range strings.Split(outputStr, "\n") {
		if strings.Contains(line, "Slot ") {
			var slotID int
			if _, scanErr := fmt.Sscanf(line, "Slot %d", &slotID); scanErr == nil {
				h.SlotID = slotID
				break
			}
		}
	}

	if strings.Contains(outputStr, "The token has been initialized") {
		h.initialized = true
		return nil
	}

	return fmt.Errorf("unexpected token init output: %s", outputStr)
}

// GenerateAndImportTestCert generates a key pair and certificate in the token.
func (h *SoftHSMTestHelper) GenerateAndImportTestCert(keyLabel, certLabel, keyID string) error {
	if !h.initialized {
		return fmt.Errorf("SoftHSM token not initialized")
	}

	if _, err := exec.LookPath("pkcs11-tool"); err != nil {
		return fmt.Errorf("pkcs11-tool not found: %w", err)
	}

	if keyID == "" {
		keyID = "01"
	}

	// Generate RSA key pair in the token
	cmd := exec.Command("pkcs11-tool", "--module", h.LibPath,
		"--token-label", h.TokenName,
		"--login", "--pin", h.UserPIN,
		"--keypairgen", "--key-type", "rsa:2048",
		"--id", keyID,
		"--label", keyLabel)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("generating keypair: %w, output: %s", err, output)
	}

	// Create self-signed certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating temp key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generating serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "Registry CLI Test Certificate"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("creating certificate: %w", err)
	}

	certFile := filepath.Join(h.TokenDir, "cert.pem")
	f, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("creating cert file: %w", err)
	}
	if encErr := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); encErr != nil {
		f.Close()
		return fmt.Errorf("writing cert: %w", encErr)
	}
	f.Close()

	// Import certificate into token
	cmd = exec.Command("pkcs11-tool", "--module", h.LibPath,
		"--token-label", h.TokenName,
		"--login", "--pin", h.UserPIN,
		"--write-object", certFile, "--type", "cert",
		"--id", keyID,
		"--label", certLabel)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("importing certificate: %w, output: %s", err, output)
	}

	return nil
}

// Cleanup removes the temporary directory.
func (h *SoftHSMTestHelper) Cleanup() error {
	if h.TokenDir != "" {
		return os.RemoveAll(h.TokenDir)
	}
	return nil
}

// GetPKCS11URI returns the PKCS#11 URI for the test token.
func (h *SoftHSMTestHelper) GetPKCS11URI() string {
	return fmt.Sprintf("pkcs11:module=%s;token=%s;pin=%s", h.LibPath, h.TokenName, h.UserPIN)
}

// SkipIfSoftHSMUnavailable skips the test if SoftHSM is not available.
func SkipIfSoftHSMUnavailable(t *testing.T) *SoftHSMTestHelper {
	helper := NewSoftHSMTestHelper()
	if !helper.IsSoftHSMAvailable() {
		t.Skip("Skipping: SoftHSM not available")
		return nil
	}
	return helper
}
