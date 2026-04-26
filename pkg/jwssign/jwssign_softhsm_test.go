//go:build softhsm

package jwssign

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sirosfoundation/registry-cli/pkg/jwssign/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testKeyLabel  = "test-signing-key"
	testCertLabel = "test-signing-cert"
	testKeyID     = "01"
)

func setupSoftHSM(t *testing.T) (*testutil.SoftHSMTestHelper, string) {
	t.Helper()
	helper := testutil.SkipIfSoftHSMUnavailable(t)
	require.NoError(t, helper.Setup())
	t.Cleanup(func() { _ = helper.Cleanup() })

	require.NoError(t, helper.GenerateAndImportTestCert(testKeyLabel, testCertLabel, testKeyID))
	return helper, helper.GetPKCS11URI()
}

func newTestSigner(t *testing.T, helper *testutil.SoftHSMTestHelper) *Signer {
	t.Helper()
	signer, err := NewSigner(Config{
		PKCS11Module: helper.LibPath,
		TokenLabel:   helper.TokenName,
		PIN:          helper.UserPIN,
		KeyLabel:     testKeyLabel,
		KeyID:        testKeyID,
		Issuer:       "https://test.example.org",
		JKU:          "https://test.example.org/.well-known/jwks.json",
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = signer.Close() })
	return signer
}

func TestNewSigner_SoftHSM(t *testing.T) {
	helper, _ := setupSoftHSM(t)
	signer := newTestSigner(t, helper)
	assert.NotNil(t, signer)
}

func TestNewSignerFromConfig_SoftHSM(t *testing.T) {
	helper, pkcs11URI := setupSoftHSM(t)
	_ = helper

	signer, err := NewSignerFromConfig(
		pkcs11URI, testKeyLabel,
		"https://test.example.org",
		"https://test.example.org/.well-known/jwks.json",
	)
	require.NoError(t, err)
	defer signer.Close()
	assert.NotNil(t, signer)
}

func TestSign_SoftHSM(t *testing.T) {
	helper, _ := setupSoftHSM(t)
	signer := newTestSigner(t, helper)

	payload := json.RawMessage(`{"hello":"world"}`)
	compact, err := signer.Sign(payload)
	require.NoError(t, err)
	assert.NotEmpty(t, compact)

	// JWS compact serialization has 3 parts separated by dots
	parts := splitJWS(compact)
	assert.Equal(t, 3, len(parts), "JWS compact should have 3 parts")
}

func TestJWKS_SoftHSM(t *testing.T) {
	helper, _ := setupSoftHSM(t)
	signer := newTestSigner(t, helper)

	jwks := signer.JWKS()
	assert.Equal(t, 1, len(jwks.Keys))
	assert.Equal(t, "sig", jwks.Keys[0].Use)
	assert.Equal(t, testKeyID, jwks.Keys[0].KeyID)
	assert.NotNil(t, jwks.Keys[0].Key)
}

func TestPublicJWK_SoftHSM(t *testing.T) {
	helper, _ := setupSoftHSM(t)
	signer := newTestSigner(t, helper)

	jwk := signer.PublicJWK()
	assert.Equal(t, testKeyID, jwk.KeyID)
	assert.Equal(t, "sig", jwk.Use)
	assert.NotEmpty(t, jwk.Algorithm)
	assert.NotNil(t, jwk.Key)
}

func TestSignFile_SoftHSM(t *testing.T) {
	helper, _ := setupSoftHSM(t)
	signer := newTestSigner(t, helper)

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "test.json")
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{"test":true}`), 0o644))

	jwtPath, err := signer.SignFile(jsonPath)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "test.jwt"), jwtPath)

	content, err := os.ReadFile(jwtPath)
	require.NoError(t, err)
	assert.NotEmpty(t, content)
	assert.Equal(t, 3, len(splitJWS(string(content))))
}

func TestSignDirectory_SoftHSM(t *testing.T) {
	helper, _ := setupSoftHSM(t)
	signer := newTestSigner(t, helper)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"a":1}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"b":2}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "c.txt"), []byte("not json"), 0o644))

	signed, err := signer.SignDirectory(dir, "*.json")
	require.NoError(t, err)
	assert.Equal(t, 2, len(signed))
	for _, path := range signed {
		assert.True(t, filepath.Ext(path) == ".jwt")
		_, err := os.Stat(path)
		assert.NoError(t, err)
	}
}

func TestSignAggregate_SoftHSM(t *testing.T) {
	helper, _ := setupSoftHSM(t)
	signer := newTestSigner(t, helper)

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.json"), []byte(`{"x":1}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "y.json"), []byte(`{"y":2}`), 0o644))

	outputPath := filepath.Join(dir, "out", "aggregate.jwt")
	err := signer.SignAggregate(dir, "*.json", outputPath)
	require.NoError(t, err)

	content, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	assert.Equal(t, 3, len(splitJWS(string(content))))
}

func TestNewSigner_KeyNotFound(t *testing.T) {
	helper, _ := setupSoftHSM(t)

	_, err := NewSigner(Config{
		PKCS11Module: helper.LibPath,
		TokenLabel:   helper.TokenName,
		PIN:          helper.UserPIN,
		KeyLabel:     "nonexistent-key",
		KeyID:        "ff",
	})
	assert.Error(t, err)
}

func splitJWS(compact string) []string {
	parts := make([]string, 0)
	for _, p := range split(compact, '.') {
		parts = append(parts, p)
	}
	return parts
}

func split(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
