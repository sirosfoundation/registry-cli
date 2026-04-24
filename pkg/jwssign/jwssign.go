// Package jwssign implements JWS compact serialization signing via PKCS#11.
// It supports SoftHSM2 and YubiHSM2 backends for the 3-tier signing model
// (dev/softhsm/yubihsm).
package jwssign

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
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
	ctx      *crypto11.Context
	key      crypto11.Signer
	alg      jose.SignatureAlgorithm
	issuer   string
	jku      string
	keyID    string
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
	return module, token, pin, nil
}

// NewSigner creates a new JWS signer backed by a PKCS#11 key.
func NewSigner(cfg Config) (*Signer, error) {
	module, token, pin, err := ParsePKCS11URI(
		fmt.Sprintf("pkcs11:module=%s;token=%s;pin=%s", cfg.PKCS11Module, cfg.TokenLabel, cfg.PIN),
	)
	if cfg.PKCS11Module == "" {
		// Try parsing from a full URI
		module, token, pin, err = ParsePKCS11URI(cfg.PKCS11Module)
		if err != nil {
			return nil, err
		}
	} else {
		module = cfg.PKCS11Module
		token = cfg.TokenLabel
		pin = cfg.PIN
	}

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
	idBytes := []byte(keyID)

	kp, err := ctx.FindKeyPair(idBytes, []byte(cfg.KeyLabel))
	if err != nil {
		ctx.Close()
		return nil, fmt.Errorf("finding key pair %q: %w", cfg.KeyLabel, err)
	}
	if kp == nil {
		ctx.Close()
		return nil, fmt.Errorf("key pair %q not found", cfg.KeyLabel)
	}

	signer, ok := kp.(crypto11.Signer)
	if !ok {
		ctx.Close()
		return nil, fmt.Errorf("key pair does not implement crypto11.Signer")
	}

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
		"data": json.RawMessage(payload),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return "", fmt.Errorf("marshaling JWT envelope: %w", err)
	}

	opts := &jose.SignerOptions{}
	if s.jku != "" {
		opts.WithHeader("jku", s.jku)
	}

	joseSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: s.alg, Key: &pkcs11CryptoSigner{s.key}},
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
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		items = append(items, json.RawMessage(data))
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
	signer crypto11.Signer
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
