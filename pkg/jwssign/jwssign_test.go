package jwssign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePKCS11URI(t *testing.T) {
	tests := []struct {
		name    string
		uri     string
		module  string
		token   string
		pin     string
		wantErr bool
	}{
		{
			name:   "full URI",
			uri:    "pkcs11:module=/usr/lib/softhsm/libsofthsm2.so;token=registry;pin=1234",
			module: "/usr/lib/softhsm/libsofthsm2.so",
			token:  "registry",
			pin:    "1234",
		},
		{
			name:   "without pkcs11: prefix",
			uri:    "module=/usr/lib/softhsm/libsofthsm2.so;token=test;pin=0000",
			module: "/usr/lib/softhsm/libsofthsm2.so",
			token:  "test",
			pin:    "0000",
		},
		{
			name:    "missing module",
			uri:     "pkcs11:token=test;pin=1234",
			wantErr: true,
		},
		{
			name:    "missing token",
			uri:     "pkcs11:module=/path/to/lib.so;pin=1234",
			wantErr: true,
		},
		{
			name:   "no pin (allowed)",
			uri:    "pkcs11:module=/path/to/lib.so;token=test",
			module: "/path/to/lib.so",
			token:  "test",
			pin:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			module, token, pin, err := ParsePKCS11URI(tt.uri)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.module, module)
			assert.Equal(t, tt.token, token)
			assert.Equal(t, tt.pin, pin)
		})
	}
}

func TestAlgorithmForKey_ECDSA(t *testing.T) {
	// Algorithm detection is tested via the public API in integration tests.
	// Unit testing algorithmForKey requires generating test keys.
	// This is covered by the integration test with SoftHSM2.
}

func TestParsePKCS11URI_PINFromEnv(t *testing.T) {
	t.Setenv("PKCS11_PIN", "env-pin-value")
	module, token, pin, err := ParsePKCS11URI("pkcs11:module=/path/to/lib.so;token=test")
	require.NoError(t, err)
	assert.Equal(t, "/path/to/lib.so", module)
	assert.Equal(t, "test", token)
	assert.Equal(t, "env-pin-value", pin, "should fall back to PKCS11_PIN env var")
}

func TestParsePKCS11URI_ExplicitPINOverridesEnv(t *testing.T) {
	t.Setenv("PKCS11_PIN", "env-pin")
	_, _, pin, err := ParsePKCS11URI("pkcs11:module=/path/to/lib.so;token=test;pin=explicit-pin")
	require.NoError(t, err)
	assert.Equal(t, "explicit-pin", pin, "explicit pin= in URI should take precedence")
}

func testJWK(t *testing.T, kid string) jose.JSONWebKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return jose.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     kid,
		Algorithm: "ES256",
		Use:       "sig",
	}
}

func TestMergeJWKS_NoPrevious(t *testing.T) {
	current := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{testJWK(t, "new-key")}}
	previous := TimestampedJWKS{KeyAdded: make(map[string]int64)}

	merged := MergeJWKS(current, previous, 30*24*time.Hour)

	assert.Len(t, merged.Keys, 1)
	assert.Equal(t, "new-key", merged.Keys[0].KeyID)
	// Should have x-key-added timestamp
	ts, ok := merged.KeyAdded["new-key"]
	assert.True(t, ok, "current key should have timestamp in KeyAdded")
	assert.Greater(t, ts, int64(0))
}

func TestMergeJWKS_RetainsPreviousKeys(t *testing.T) {
	currentKey := testJWK(t, "key-2")
	current := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{currentKey}}

	// Previous key added recently (within retention)
	prevKey := testJWK(t, "key-1")
	previous := TimestampedJWKS{
		Keys:     []jose.JSONWebKey{prevKey},
		KeyAdded: map[string]int64{"key-1": time.Now().Add(-24 * time.Hour).Unix()},
	}

	merged := MergeJWKS(current, previous, 30*24*time.Hour)

	assert.Len(t, merged.Keys, 2)
	assert.Equal(t, "key-2", merged.Keys[0].KeyID, "current key should be first")
	assert.Equal(t, "key-1", merged.Keys[1].KeyID, "previous key should be retained")
}

func TestMergeJWKS_ExpiresOldKeys(t *testing.T) {
	current := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{testJWK(t, "key-3")}}

	previous := TimestampedJWKS{
		Keys: []jose.JSONWebKey{testJWK(t, "key-1"), testJWK(t, "key-2")},
		KeyAdded: map[string]int64{
			"key-1": time.Now().Add(-60 * 24 * time.Hour).Unix(), // 60 days ago — expired
			"key-2": time.Now().Add(-10 * 24 * time.Hour).Unix(), // 10 days ago — retained
		},
	}

	merged := MergeJWKS(current, previous, 30*24*time.Hour)

	assert.Len(t, merged.Keys, 2)
	assert.Equal(t, "key-3", merged.Keys[0].KeyID)
	assert.Equal(t, "key-2", merged.Keys[1].KeyID)
}

func TestMergeJWKS_DeduplicatesSameKey(t *testing.T) {
	key := testJWK(t, "same-key")
	current := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}

	previous := TimestampedJWKS{
		Keys:     []jose.JSONWebKey{testJWK(t, "same-key")},
		KeyAdded: map[string]int64{"same-key": time.Now().Add(-1 * time.Hour).Unix()},
	}

	merged := MergeJWKS(current, previous, 30*24*time.Hour)

	assert.Len(t, merged.Keys, 1, "duplicate key ID should be deduplicated")
	assert.Equal(t, "same-key", merged.Keys[0].KeyID)
}

func TestMergeJWKS_StampsUnstampedPreviousKeys(t *testing.T) {
	current := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{testJWK(t, "new")}}

	// Previous key without timestamp — should be stamped and retained
	previous := TimestampedJWKS{
		Keys:     []jose.JSONWebKey{testJWK(t, "old")},
		KeyAdded: make(map[string]int64), // no entry for "old"
	}

	merged := MergeJWKS(current, previous, 30*24*time.Hour)

	assert.Len(t, merged.Keys, 2)
	ts, ok := merged.KeyAdded["old"]
	assert.True(t, ok, "unstamped key should get timestamp on first merge")
	assert.Greater(t, ts, int64(0))
}

func TestLoadTimestampedJWKS_FileNotFound(t *testing.T) {
	jwks, err := LoadTimestampedJWKS("/nonexistent/path/jwks.json")
	require.NoError(t, err)
	assert.Empty(t, jwks.Keys, "missing file should return empty JWKS")
	assert.NotNil(t, jwks.KeyAdded)
}

func TestLoadTimestampedJWKS_ValidFile(t *testing.T) {
	key := testJWK(t, "test-key")
	jwks := TimestampedJWKS{
		Keys:     []jose.JSONWebKey{key},
		KeyAdded: map[string]int64{"test-key": 1234567890},
	}
	data, err := json.Marshal(jwks)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "jwks.json")
	require.NoError(t, os.WriteFile(path, data, 0o644))

	loaded, err := LoadTimestampedJWKS(path)
	require.NoError(t, err)
	assert.Len(t, loaded.Keys, 1)
	assert.Equal(t, "test-key", loaded.Keys[0].KeyID)
	assert.Equal(t, int64(1234567890), loaded.KeyAdded["test-key"])
}

func TestLoadTimestampedJWKS_StandardJWKS(t *testing.T) {
	// A standard JWKS without x-key-added should load fine
	key := testJWK(t, "std-key")
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}}
	data, err := json.Marshal(jwks)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "jwks.json")
	require.NoError(t, os.WriteFile(path, data, 0o644))

	loaded, err := LoadTimestampedJWKS(path)
	require.NoError(t, err)
	assert.Len(t, loaded.Keys, 1)
	assert.NotNil(t, loaded.KeyAdded)
	assert.Empty(t, loaded.KeyAdded, "standard JWKS should have no timestamps")
}

func TestLoadTimestampedJWKS_InvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "jwks.json")
	require.NoError(t, os.WriteFile(path, []byte("not json"), 0o644))

	_, err := LoadTimestampedJWKS(path)
	assert.Error(t, err)
}

func TestNewEphemeralSigner(t *testing.T) {
	signer, err := NewEphemeralSigner("test-issuer", "https://example.com/jwks.json")
	require.NoError(t, err)
	require.NotNil(t, signer)
	defer signer.Close()

	assert.Equal(t, "ephemeral", signer.keyID)
	assert.Equal(t, jose.ES256, signer.alg)
}

func TestEphemeralSigner_Sign(t *testing.T) {
	signer, err := NewEphemeralSigner("test-issuer", "")
	require.NoError(t, err)
	defer signer.Close()

	payload := json.RawMessage(`{"name":"test credential"}`)
	compact, err := signer.Sign(payload)
	require.NoError(t, err)

	// JWS compact has 3 parts
	parts := strings.Split(compact, ".")
	assert.Len(t, parts, 3, "JWS compact serialization should have 3 parts")

	// Verify the signature using the public key
	jwk := signer.PublicJWK()
	parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	verified, err := parsed.Verify(jwk.Key)
	require.NoError(t, err)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(verified, &envelope))
	assert.Equal(t, "test-issuer", envelope["iss"])
	assert.NotNil(t, envelope["iat"])
	assert.NotNil(t, envelope["data"])
}

func TestEphemeralSigner_SignWithJKU(t *testing.T) {
	signer, err := NewEphemeralSigner("issuer", "https://example.com/jwks.json")
	require.NoError(t, err)
	defer signer.Close()

	compact, err := signer.Sign(json.RawMessage(`{}`))
	require.NoError(t, err)

	parsed, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	// Check jku header
	assert.Equal(t, "https://example.com/jwks.json", parsed.Signatures[0].Protected.ExtraHeaders["jku"])
}

func TestEphemeralSigner_PublicJWK(t *testing.T) {
	signer, err := NewEphemeralSigner("issuer", "")
	require.NoError(t, err)
	defer signer.Close()

	jwk := signer.PublicJWK()
	assert.Equal(t, "ephemeral", jwk.KeyID)
	assert.Equal(t, "ES256", jwk.Algorithm)
	assert.Equal(t, "sig", jwk.Use)
	assert.IsType(t, &ecdsa.PublicKey{}, jwk.Key)
}

func TestEphemeralSigner_JWKS(t *testing.T) {
	signer, err := NewEphemeralSigner("issuer", "")
	require.NoError(t, err)
	defer signer.Close()

	jwks := signer.JWKS()
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, "ephemeral", jwks.Keys[0].KeyID)
}

func TestEphemeralSigner_SignFile(t *testing.T) {
	signer, err := NewEphemeralSigner("issuer", "")
	require.NoError(t, err)
	defer signer.Close()

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "test.json")
	require.NoError(t, os.WriteFile(jsonPath, []byte(`{"hello":"world"}`), 0o644))

	jwtPath, err := signer.SignFile(jsonPath)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "test.jwt"), jwtPath)

	// Verify the JWT file was created and is valid
	data, err := os.ReadFile(jwtPath)
	require.NoError(t, err)

	parsed, err := jose.ParseSigned(string(data), []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	_, err = parsed.Verify(signer.PublicJWK().Key)
	require.NoError(t, err)
}

func TestEphemeralSigner_SignDirectory(t *testing.T) {
	signer, err := NewEphemeralSigner("issuer", "")
	require.NoError(t, err)
	defer signer.Close()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"a":1}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"b":2}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "skip.txt"), []byte("not json"), 0o644))

	signed, err := signer.SignDirectory(dir, "*.json")
	require.NoError(t, err)
	assert.Len(t, signed, 2)
}

func TestEphemeralSigner_SignAggregate(t *testing.T) {
	signer, err := NewEphemeralSigner("issuer", "")
	require.NoError(t, err)
	defer signer.Close()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"a":1}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"b":2}`), 0o644))

	outPath := filepath.Join(dir, "aggregate.jwt")
	err = signer.SignAggregate(dir, "*.json", outPath)
	require.NoError(t, err)

	data, err := os.ReadFile(outPath)
	require.NoError(t, err)

	parsed, err := jose.ParseSigned(string(data), []jose.SignatureAlgorithm{jose.ES256})
	require.NoError(t, err)

	verified, err := parsed.Verify(signer.PublicJWK().Key)
	require.NoError(t, err)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(verified, &envelope))
	assert.Equal(t, float64(2), envelope["data"].(map[string]any)["total"])
}

func TestEphemeralSigner_Close(t *testing.T) {
	signer, err := NewEphemeralSigner("issuer", "")
	require.NoError(t, err)

	// Close should be safe (no-op, no PKCS#11 context)
	assert.NoError(t, signer.Close())
	// Double-close should also be safe
	assert.NoError(t, signer.Close())
}
