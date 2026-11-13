package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
)

var (
	ErrClientNotFound   = errors.New("client not found")
	ErrClientKeyExists  = errors.New("application already has a signing key")
	ErrClientKeyMissing = errors.New("application has no signing key")
)

type ClientKeyResult struct {
	Kid        string
	Alg        string
	JWKSURI    string
	PrivatePEM string
	PublicJWKS string
}

type ClientKeyService struct {
	repo   *repository.ClientRepository
	issuer string
	retain time.Duration
}

func NewClientKeyService(repo *repository.ClientRepository, issuer string, retain time.Duration) *ClientKeyService {
	defer telemetry.Step("service.NewClientKeyService")()
	if retain <= 0 {
		retain = 48 * time.Hour
	}
	return &ClientKeyService{repo: repo, issuer: strings.TrimRight(strings.TrimSpace(issuer), "/"), retain: retain}
}

// URI is the tenant JWKS. Application public keys are entries in that keys array.
func (s *ClientKeyService) URI(string) string {
	return s.issuer + "/oidc/jwks"
}

type PublishedSigningKey struct {
	ClientID  string
	Kid       string
	Alg       string
	Kty       string
	Status    string
	CreatedAt string
	RetireAt  string
}

func (s *ClientKeyService) Published() ([]PublishedSigningKey, error) {
	defer telemetry.Step("service.ClientKeyService.Published")()
	if s == nil || s.repo == nil {
		return nil, nil
	}
	rows, err := s.repo.PublishedClientSigningKeys(time.Now())
	if err != nil {
		return nil, err
	}
	out := make([]PublishedSigningKey, 0, len(rows))
	for _, row := range rows {
		item := PublishedSigningKey{
			ClientID: row.ClientID, Kid: row.Kid, Alg: row.Alg, Kty: "RSA", Status: "retiring",
		}
		if row.Status == "active" {
			item.Status = "active"
		}
		var doc struct {
			Kty string `json:"kty"`
		}
		if json.Unmarshal([]byte(row.PublicJWK), &doc) == nil && doc.Kty != "" {
			item.Kty = doc.Kty
		}
		if !row.CreatedAt.IsZero() {
			item.CreatedAt = row.CreatedAt.UTC().Format(time.RFC3339)
		}
		if !row.RetireAt.IsZero() {
			item.RetireAt = row.RetireAt.UTC().Format(time.RFC3339)
		}
		out = append(out, item)
	}
	return out, nil
}

func (s *ClientKeyService) Active(clientID string) (kid, alg string, ok bool, err error) {
	defer telemetry.Step("service.ClientKeyService.Active")()
	if s == nil || s.repo == nil {
		return "", "", false, nil
	}
	return s.repo.ActiveClientSigningKey(clientID)
}

func (s *ClientKeyService) Create(clientID string) (ClientKeyResult, error) {
	defer telemetry.Step("service.ClientKeyService.Create")()
	if _, err := s.mustClient(clientID); err != nil {
		return ClientKeyResult{}, err
	}
	if _, _, ok, err := s.repo.ActiveClientSigningKey(clientID); err != nil {
		return ClientKeyResult{}, err
	} else if ok {
		return ClientKeyResult{}, ErrClientKeyExists
	}
	return s.generate(clientID)
}

func (s *ClientKeyService) Rotate(clientID string) (ClientKeyResult, error) {
	defer telemetry.Step("service.ClientKeyService.Rotate")()
	if _, err := s.mustClient(clientID); err != nil {
		return ClientKeyResult{}, err
	}
	kid, _, ok, err := s.repo.ActiveClientSigningKey(clientID)
	if err != nil {
		return ClientKeyResult{}, err
	}
	if !ok {
		return ClientKeyResult{}, ErrClientKeyMissing
	}
	if err := s.repo.RetireClientSigningKey(kid, time.Now().Add(s.retain)); err != nil {
		return ClientKeyResult{}, err
	}
	result, err := s.generate(clientID)
	if err != nil {
		return ClientKeyResult{}, err
	}
	return result, nil
}

func (s *ClientKeyService) PublicJWKS(clientID string) ([]byte, error) {
	defer telemetry.Step("service.ClientKeyService.PublicJWKS")()
	if _, err := s.mustClient(clientID); err != nil {
		return nil, err
	}
	body, _, err := s.published(clientID)
	return body, err
}

func (s *ClientKeyService) Delete(clientID string) error {
	defer telemetry.Step("service.ClientKeyService.Delete")()
	if s == nil || s.repo == nil {
		return nil
	}
	return s.repo.DeleteClientSigningKeys(clientID)
}

func (s *ClientKeyService) mustClient(clientID string) (bool, error) {
	_, err := s.repo.GetByID(clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrClientNotFound
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (s *ClientKeyService) generate(clientID string) (ClientKeyResult, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return ClientKeyResult{}, err
	}
	kid, err := newKid()
	if err != nil {
		return ClientKeyResult{}, err
	}
	jwk := rsaPublicJWK(kid, key)
	raw, err := json.Marshal(jwk)
	if err != nil {
		return ClientKeyResult{}, err
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err := s.repo.InsertClientSigningKey(repository.ClientSigningKey{
		ClientID: clientID, Kid: kid, Alg: "RS256", PrivatePEM: pemText, PublicJWK: string(raw), CreatedAt: time.Now().UTC(),
	}); err != nil {
		if conflict(err) {
			return ClientKeyResult{}, ErrClientKeyExists
		}
		return ClientKeyResult{}, err
	}
	body, uri, err := s.published(clientID)
	if err != nil {
		return ClientKeyResult{}, err
	}
	if err := s.repo.PublishClientJWKS(clientID, string(body), uri); err != nil {
		return ClientKeyResult{}, err
	}
	return ClientKeyResult{Kid: kid, Alg: "RS256", JWKSURI: uri, PrivatePEM: pemText, PublicJWKS: string(body)}, nil
}

func (s *ClientKeyService) published(clientID string) ([]byte, string, error) {
	rows, err := s.repo.ListClientSigningKeys(clientID)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	keys := make([]JWK, 0)
	for _, row := range rows {
		if row.Status != "active" && (row.RetireAt.IsZero() || !row.RetireAt.After(now)) {
			continue
		}
		var jwk JWK
		if err := json.Unmarshal([]byte(row.PublicJWK), &jwk); err != nil {
			return nil, "", fmt.Errorf("client signing key %s: %w", row.Kid, err)
		}
		keys = append(keys, jwk)
	}
	body, err := json.Marshal(JWKS{Keys: keys})
	if err != nil {
		return nil, "", err
	}
	return body, s.URI(clientID), nil
}

func rsaPublicJWK(kid string, key *rsa.PrivateKey) JWK {
	return JWK{
		Kty: "RSA", Kid: kid, Use: "sig", Alg: "RS256",
		N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(exponentBytes(key.E)),
	}
}

func exponentBytes(e int) []byte {
	if e == 0 {
		return []byte{0}
	}
	var out []byte
	for v := e; v > 0; v >>= 8 {
		out = append([]byte{byte(v)}, out...)
	}
	return out
}

func newKid() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func conflict(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") || strings.Contains(msg, "duplicate")
}
