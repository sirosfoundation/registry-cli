// Package jwssign implements JWS compact serialization signing.
// It supports PKCS#11 backends (SoftHSM2, YubiHSM2) for production use,
// and ephemeral in-memory keys for development and CI.
package jwssign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/go-jose/go-jose/v4"
)

// Signer signs JSON payloads as JWS compact serialization.
type Signer struct {
	ctx    *crypto11.Context // nil for ephemeral signers
	key    crypto.Signer
	alg    jose.SignatureAlgorithm
	issuer string
	jku    string
	keyID  string
}

// Config holds the configuration for creating a Signer.
type Config struct {
	// PKCS11Module is the path to the PKCS#11 shared library.
	PKCS11Module string
	// TokenLabel is the PKCS#11 token label.
	TokenLabel string
	// PIN is the PKCS#11 token PIN.
	PIN string
	// KeyLabel is the label of the signing key in the HSM.
	KeyLabel string
	// KeyID is the hex ID of the key (default "01").
	KeyID string
	// Issuer is the JWT "iss" claim.
	Issuer string
	// JKU is the JWS Key URL header value.
	JKU string
}

// ParsePKCS11URI parses a PKCS#11 URI into module, token, and pin components.
// Format: pkcs11:module=/path/to/lib.so;token=label;pin=1234
func ParsePKCS11URI(uri string) (module, token, pin string, err error) {
	uri = strings.TrimPrefix(uri, "pkcs11:")
	for _, part := range strings.Split(uri, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch k {
		case "module":
			module = v
		case "token":
			token = v
		case "pin":
			pin = v
		}
	}
	if module == "" {
		return "", "", "", fmt.Errorf("pkcs11 URI missing module")
	}
	if token == "" {
		return "", "", "", fmt.Errorf("pkcs11 URI missing token")
	}
	// Fall back to PKCS11_PIN environment variable if pin not in URI.
	// This avoids embedding the PIN in configuration files.
	if pin == "" {
		pin = os.Getenv("PKCS11_PIN")
	}
	return module, token, pin, nil
}

// NewSigner creates a new JWS signer backed by a PKCS#11 key.
func NewSigner(cfg Config) (*Signer, error) {
	if cfg.PKCS11Module == "" {
		return nil, fmt.Errorf("PKCS11Module is required")
	}
	module := cfg.PKCS11Module
	token := cfg.TokenLabel
	pin := cfg.PIN

	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:       module,
		TokenLabel: token,
		Pin:        pin,
	})
	if err != nil {
		return nil, fmt.Errorf("configuring PKCS#11: %w", err)
	}

	keyID := cfg.KeyID
	if keyID == "" {
		keyID = "01"
	}
	idBytes, err := hex.DecodeString(keyID)
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("decoding key ID %q as hex: %w", keyID, err)
	}

	kp, err := ctx.FindKeyPair(idBytes, []byte(cfg.KeyLabel))
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("finding key pair %q: %w", cfg.KeyLabel, err)
	}
	if kp == nil {
		ctx.Close()
		return nil, fmt.Errorf("key pair %q not found", cfg.KeyLabel)
	}

	signer := kp

	alg, err := algorithmForKey(signer.Public())
	if err != nil {
		ctx.Close()
		return nil, err
	}

	return &Signer{
		ctx:    ctx,
		key:    signer,
		alg:    alg,
		issuer: cfg.Issuer,
		jku:    cfg.JKU,
		keyID:  keyID,
	}, nil
}

// NewSignerFromConfig creates a signer from a parsed PKCS11 URI string.
func NewSignerFromConfig(pkcs11URI, keyLabel, issuer, jku string) (*Signer, error) {
	module, token, pin, err := ParsePKCS11URI(pkcs11URI)
	if err != nil {
		return nil, err
	}
	return NewSigner(Config{
		PKCS11Module: module,
		TokenLabel:   token,
		PIN:          pin,
		KeyLabel:     keyLabel,
		Issuer:       issuer,
		JKU:          jku,
	})
}

// NewEphemeralSigner creates a signer backed by an in-memory ECDSA P-256 key.
// This is suitable for development, CI, and deployments without HSM access.
// The key exists only for the lifetime of the process.
func NewEphemeralSigner(issuer, jku string) (*Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral key: %w", err)
	}

	return &Signer{
		ctx:    nil,
		key:    key,
		alg:    jose.ES256,
		issuer: issuer,
		jku:    jku,
		keyID:  "ephemeral",
	}, nil
}

// Close releases the PKCS#11 context.
func (s *Signer) Close() error {
	if s.ctx != nil {
		return s.ctx.Close()
	}
	return nil
}

// Sign signs a JSON payload and returns a JWS compact serialization string.
// The payload is wrapped in a JWT envelope with iss and iat claims.
func (s *Signer) Sign(payload json.RawMessage) (string, error) {
	envelope := map[string]any{
		"iss":  s.issuer,
		"iat":  time.Now().Unix(),
		"data": payload,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshaling JWT envelope: %w", err)
	}

	opts := &jose.SignerOptions{}
	if s.jku != "" {
		opts.WithHeader("jku", s.jku)
	}

	// Use OpaqueSigner for PKCS#11 keys (go-jose's type switch doesn't handle
	// crypto.Signer directly), or the native key for ephemeral signers.
	var signingKey any
	if s.ctx != nil {
		signingKey = &pkcs11CryptoSigner{s.key}
	} else {
		signingKey = s.key
	}

	joseSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: s.alg, Key: signingKey},
		opts,
	)
	if err != nil {
		return "", fmt.Errorf("creating JWS signer: %w", err)
	}

	obj, err := joseSigner.Sign(data)
	if err != nil {
		return "", fmt.Errorf("signing payload: %w", err)
	}

	return obj.CompactSerialize()
}

// PublicJWK returns the public key as a JSON Web Key.
func (s *Signer) PublicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       s.key.Public(),
		KeyID:     s.keyID,
		Algorithm: string(s.alg),
		Use:       "sig",
	}
}

// JWKS returns a JSON Web Key Set containing the public key.
func (s *Signer) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{s.PublicJWK()},
	}
}

// TimestampedJWKS extends a standard JWKS with per-key timestamps for
// key rotation tracking. The "x-key-added" field is ignored by standard
// JWKS consumers but preserved by this tool.
type TimestampedJWKS struct {
	Keys     []jose.JSONWebKey `json:"keys"`
	KeyAdded map[string]int64  `json:"x-key-added,omitempty"`
}

// ToJoseJWKS converts to a standard jose.JSONWebKeySet (drops timestamps).
func (t *TimestampedJWKS) ToJoseJWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{Keys: t.Keys}
}

// MergeJWKS merges the current signing key with keys from a previous JWKS,
// retaining old keys for a configurable duration to support key rotation.
// Keys whose timestamp in KeyAdded is older than the retention period are
// removed. The current key is always added with a fresh timestamp.
// If a previous key has the same KeyID as the current key, it is replaced.
func MergeJWKS(current jose.JSONWebKeySet, previous TimestampedJWKS, retention time.Duration) TimestampedJWKS {
	now := time.Now()
	cutoff := now.Add(-retention)
	cutoffUnix := cutoff.Unix()

	result := TimestampedJWKS{
		KeyAdded: make(map[string]int64),
	}

	// Always include current key(s) first
	currentIDs := make(map[string]bool)
	for _, k := range current.Keys {
		result.Keys = append(result.Keys, k)
		result.KeyAdded[k.KeyID] = now.Unix()
		currentIDs[k.KeyID] = true
	}

	// Retain previous keys that are not expired and not duplicates of current
	for _, k := range previous.Keys {
		if currentIDs[k.KeyID] {
			continue // replaced by current key
		}
		addedUnix, hasTimestamp := previous.KeyAdded[k.KeyID]
		if hasTimestamp && addedUnix < cutoffUnix {
			continue // expired
		}
		// Preserve the timestamp, or stamp it now if missing
		if !hasTimestamp {
			addedUnix = now.Unix()
		}
		result.Keys = append(result.Keys, k)
		result.KeyAdded[k.KeyID] = addedUnix
	}

	return result
}

// LoadTimestampedJWKS reads a TimestampedJWKS from a JSON file. Returns an
// empty JWKS if the file does not exist.
func LoadTimestampedJWKS(path string) (TimestampedJWKS, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return TimestampedJWKS{KeyAdded: make(map[string]int64)}, nil
		}
		return TimestampedJWKS{}, fmt.Errorf("reading JWKS %s: %w", path, err)
	}
	var jwks TimestampedJWKS
	if err := json.Unmarshal(data, &jwks); err != nil {
		return TimestampedJWKS{}, fmt.Errorf("parsing JWKS %s: %w", path, err)
	}
	if jwks.KeyAdded == nil {
		jwks.KeyAdded = make(map[string]int64)
	}
	return jwks, nil
}

// SignFile reads a JSON file, signs it, and writes the JWS to a .jwt file.
func (s *Signer) SignFile(jsonPath string) (string, error) {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", jsonPath, err)
	}
	jwtPath := strings.TrimSuffix(jsonPath, filepath.Ext(jsonPath)) + ".jwt"
	compact, err := s.Sign(json.RawMessage(data))
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(jwtPath, []byte(compact), 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", jwtPath, err)
	}
	return jwtPath, nil
}

// SignDirectory signs all files matching a glob pattern in a directory.
func (s *Signer) SignDirectory(dir, pattern string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, fmt.Errorf("globbing %s/%s: %w", dir, pattern, err)
	}

	var signed []string
	for _, path := range matches {
		jwtPath, err := s.SignFile(path)
		if err != nil {
			return signed, fmt.Errorf("signing %s: %w", path, err)
		}
		signed = append(signed, jwtPath)
	}
	return signed, nil
}

// SignAggregate reads all JSON files matching a pattern, combines them into a
// list payload, signs it, and writes to the output path.
func (s *Signer) SignAggregate(dir, pattern, outputPath string) error {
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return fmt.Errorf("globbing: %w", err)
	}

	var items []json.RawMessage
	for _, path := range matches {
		fileData, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading %s: %w", path, readErr)
		}
		items = append(items, json.RawMessage(fileData))
	}

	listPayload := map[string]any{
		"total":  len(items),
		"limit":  len(items),
		"offset": 0,
		"data":   items,
	}
	payloadBytes, err := json.Marshal(listPayload)
	if err != nil {
		return fmt.Errorf("marshaling aggregate: %w", err)
	}

	compact, err := s.Sign(json.RawMessage(payloadBytes))
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(outputPath, []byte(compact), 0o644)
}

// pkcs11CryptoSigner wraps crypto11.Signer so go-jose accepts it.
// go-jose's type switch only checks for *ecdsa.PrivateKey, *rsa.PrivateKey, etc.
// but not crypto.Signer directly. This wrapper implements jose.OpaqueSigner.
type pkcs11CryptoSigner struct {
	signer crypto.Signer
}

func (s *pkcs11CryptoSigner) Public() *jose.JSONWebKey {
	return &jose.JSONWebKey{Key: s.signer.Public()}
}

func (s *pkcs11CryptoSigner) SignPayload(payload []byte, alg jose.SignatureAlgorithm) ([]byte, error) {
	var hash crypto.Hash
	switch alg {
	case jose.ES256:
		hash = crypto.SHA256
	case jose.ES384:
		hash = crypto.SHA384
	case jose.ES512:
		hash = crypto.SHA512
	case jose.RS256:
		hash = crypto.SHA256
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h := hash.New()
	h.Write(payload)
	digest := h.Sum(nil)

	return s.signer.Sign(nil, digest, hash)
}

func (s *pkcs11CryptoSigner) Algs() []jose.SignatureAlgorithm {
	pub := s.signer.Public()
	alg, err := algorithmForKey(pub)
	if err != nil {
		return nil
	}
	return []jose.SignatureAlgorithm{alg}
}

func algorithmForKey(pub crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %v", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return jose.RS256, nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", pub)
	}
}
