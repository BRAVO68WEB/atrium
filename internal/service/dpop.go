package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/cache"

	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/golang-jwt/jwt/v5"
)

type DPoPService struct {
	replay cache.Cache
}

type DPoPProof struct {
	jwt.RegisteredClaims
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	ATH   string `json:"ath,omitempty"`
	Nonce string `json:"nonce,omitempty"`
	// JKT is the thumbprint of the key that verified this proof. It is not a claim.
	JKT string `json:"-"`
}

type DPoPJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
}

func NewDPoPService() *DPoPService {
	defer telemetry.Step("service.NewDPoPService")()
	return NewDPoPServiceWithCache(cache.NewMemory())
}

func NewDPoPServiceWithCache(store cache.Cache) *DPoPService {
	defer telemetry.Step("service.NewDPoPServiceWithCache")()
	if store == nil {
		store = cache.NewMemory()
	}
	return &DPoPService{replay: store}
}

// ValidateDPoPProof validates a DPoP proof JWT
func (s *DPoPService) ValidateDPoPProof(ctx context.Context, dpopHeader string, method string, uri string, accessToken string) (*DPoPProof, error) {
	defer telemetry.Step("service.DPoPService.ValidateDPoPProof")()
	if dpopHeader == "" {
		return nil, fmt.Errorf("DPoP header is required")
	}

	// Parse without verification first to get the header
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(dpopHeader, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse DPoP proof: %w", err)
	}

	// Get the JWK from header
	jwkRaw, ok := token.Header["jwk"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("missing jwk in DPoP header")
	}

	// Parse the public key
	pubKey, err := s.parseJWK(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWK: %w", err)
	}

	// Verify the signature
	token, err = jwt.Parse(dpopHeader, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("DPoP signature verification failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid DPoP claims")
	}

	// Extract claims
	htm, _ := claims["htm"].(string)
	htu, _ := claims["htu"].(string)
	jti, _ := claims["jti"].(string)
	ath, _ := claims["ath"].(string)

	// Validate required claims
	if jti == "" {
		return nil, fmt.Errorf("missing jti claim")
	}
	if htm == "" {
		return nil, fmt.Errorf("missing htm claim")
	}
	if htu == "" {
		return nil, fmt.Errorf("missing htu claim")
	}

	// Validate method
	if htm != method {
		return nil, fmt.Errorf("htm mismatch: expected %s, got %s", method, htm)
	}

	// Validate URI (ignore query and fragment)
	expectedHTU := s.normalizeURI(uri)
	actualHTU := s.normalizeURI(htu)
	if expectedHTU != actualHTU {
		return nil, fmt.Errorf("htu mismatch: expected %s, got %s", expectedHTU, actualHTU)
	}

	// A proof presented with an access token must be bound to that token.
	if accessToken != "" {
		if ath == "" {
			return nil, fmt.Errorf("missing ath claim")
		}
		if err := s.validateATH(ath, accessToken); err != nil {
			return nil, err
		}
	}

	// Check for replay
	if err := s.checkReplay(ctx, jti); err != nil {
		return nil, err
	}

	thumbprint, err := s.GetPublicKeyThumbprint(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get thumbprint: %w", err)
	}

	return &DPoPProof{
		HTM: htm,
		HTU: htu,
		ATH: ath,
		JKT: thumbprint,
	}, nil
}

// CreateDPoPProof creates a DPoP proof JWT
func (s *DPoPService) CreateDPoPProof(key *ecdsa.PrivateKey, method string, uri string, accessToken string) (string, error) {
	defer telemetry.Step("service.DPoPService.CreateDPoPProof")()
	jti, err := generateJTI()
	if err != nil {
		return "", fmt.Errorf("failed to generate jti: %w", err)
	}

	claims := &DPoPProof{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt: jwt.NewNumericDate(time.Now()),
			ID:       jti,
		},
		HTM: method,
		HTU: uri,
	}

	// Add access token hash if provided
	if accessToken != "" {
		claims.ATH = s.computeATH(accessToken)
	}

	// Get public key coordinates for JWK header via ECDH API
	pubKey := &key.PublicKey
	ecdhKey, _ := pubKey.ECDH()
	pubBytes := ecdhKey.Bytes()
	x := base64.RawURLEncoding.EncodeToString(pubBytes[1:33])
	y := base64.RawURLEncoding.EncodeToString(pubBytes[33:65])

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   x,
		"y":   y,
	}

	return token.SignedString(key)
}

// GenerateKeyPair generates a new ECDSA P-256 key pair
func (s *DPoPService) GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	defer telemetry.Step("service.DPoPService.GenerateKeyPair")()
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// GetPublicKeyThumbprint returns the JWK thumbprint of a public key
func (s *DPoPService) GetPublicKeyThumbprint(pubKey *ecdsa.PublicKey) (string, error) {
	defer
	// Get coordinates via ECDH API
	telemetry.Step("service.DPoPService.GetPublicKeyThumbprint")()

	ecdhKey, err := pubKey.ECDH()
	if err != nil {
		return "", fmt.Errorf("failed to convert to ECDH key: %w", err)
	}
	pubBytes := ecdhKey.Bytes()
	x := base64.RawURLEncoding.EncodeToString(pubBytes[1:33])
	y := base64.RawURLEncoding.EncodeToString(pubBytes[33:65])

	// Create canonical JWK
	jwk := map[string]interface{}{
		"crv": "P-256",
		"kty": "EC",
		"x":   x,
		"y":   y,
	}

	// Marshal to JSON (sorted keys)
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(jwkBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// ExportPublicKeyAsJWK exports a public key as a JWK map
func (s *DPoPService) ExportPublicKeyAsJWK(pubKey *ecdsa.PublicKey) map[string]interface{} {
	defer telemetry.Step("service.DPoPService.ExportPublicKeyAsJWK")()
	ecdhKey, _ := pubKey.ECDH()
	pubBytes := ecdhKey.Bytes()
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(pubBytes[1:33]),
		"y":   base64.RawURLEncoding.EncodeToString(pubBytes[33:65]),
	}
}

func (s *DPoPService) parseJWK(jwkRaw map[string]interface{}) (*ecdsa.PublicKey, error) {
	defer telemetry.Step("service.DPoPService.parseJWK")()
	kty, _ := jwkRaw["kty"].(string)
	if kty != "EC" {
		return nil, fmt.Errorf("unsupported key type: %s", kty)
	}

	crv, _ := jwkRaw["crv"].(string)
	xStr, _ := jwkRaw["x"].(string)
	yStr, _ := jwkRaw["y"].(string)

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}

	var curve elliptic.Curve
	switch crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	return ecPublicKey(curve, xBytes, yBytes)
}

func (s *DPoPService) validateATH(ath string, accessToken string) error {
	defer
	// Compute SHA-256 hash of access token
	telemetry.Step("service.DPoPService.validateATH")()

	hash := sha256.Sum256([]byte(accessToken))
	expectedATH := base64.RawURLEncoding.EncodeToString(hash[:])

	if ath != expectedATH {
		return fmt.Errorf("ath mismatch")
	}
	return nil
}

func (s *DPoPService) computeATH(accessToken string) string {
	defer telemetry.Step("service.DPoPService.computeATH")()
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (s *DPoPService) checkReplay(ctx context.Context, jti string) error {
	defer telemetry.Step("service.DPoPService.checkReplay")()
	if s == nil || s.replay == nil {
		return fmt.Errorf("DPoP replay cache is not configured")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ok, err := s.replay.Add(ctx, "dpop:jti:"+jti, []byte("1"), 10*time.Minute)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("DPoP proof replay detected")
	}
	return nil
}

func (s *DPoPService) normalizeURI(uri string) string {
	defer
	// Remove query and fragment
	telemetry.Step("service.DPoPService.normalizeURI")()

	if idx := strings.Index(uri, "?"); idx != -1 {
		uri = uri[:idx]
	}
	if idx := strings.Index(uri, "#"); idx != -1 {
		uri = uri[:idx]
	}
	return uri
}

func generateJTI() (string, error) {
	defer telemetry.Step("service.generateJTI")()
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
