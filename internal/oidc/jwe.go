package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
)

const (
	encAlgRSAOAEP256 = "RSA-OAEP-256"
	encA256GCM       = "A256GCM"
)

func (h *Handler) sealIDToken(clientID, signed string) (string, error) {
	defer telemetry.Step("oidc.Handler.sealIDToken")()
	client, err := h.loadClient(clientID)
	if err != nil || client == nil {
		return signed, nil
	}
	return h.encryptNested(client, signed, client.IDTokenEncryptedResponseAlg, client.IDTokenEncryptedResponseEnc)
}

func (h *Handler) sealUserInfo(clientID string, claims map[string]any) (string, bool, error) {
	defer telemetry.Step("oidc.Handler.sealUserInfo")()
	client, err := h.loadClient(clientID)
	if err != nil || client == nil || strings.TrimSpace(client.UserinfoEncryptedResponseAlg) == "" {
		return "", false, nil
	}
	if err := checkEncPair(client.UserinfoEncryptedResponseAlg, client.UserinfoEncryptedResponseEnc); err != nil {
		return "", false, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	key, kid := h.keySet.GetRSAKey()
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		return "", false, err
	}
	encrypted, err := h.encryptNested(client, signed, client.UserinfoEncryptedResponseAlg, client.UserinfoEncryptedResponseEnc)
	return encrypted, true, err
}

func (h *Handler) loadClient(id string) (*models.Client, error) {
	defer telemetry.Step("oidc.Handler.loadClient")()
	if h == nil || h.clients == nil || id == "" {
		return nil, nil
	}
	return h.clients.GetByID(id)
}

func (h *Handler) encryptNested(client *models.Client, signed, alg, enc string) (string, error) {
	defer telemetry.Step("oidc.Handler.encryptNested")()
	if strings.TrimSpace(alg) == "" && strings.TrimSpace(enc) == "" {
		return signed, nil
	}
	if err := checkEncPair(alg, enc); err != nil {
		return "", err
	}
	key, err := h.encryptionKey(client)
	if err != nil {
		return "", fmt.Errorf("invalid_client: %w", err)
	}
	recipient := jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: key.Key, KeyID: key.KeyID}
	options := &jose.EncrypterOptions{}
	options = options.WithContentType("JWT")
	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, options)
	if err != nil {
		return "", err
	}
	object, err := encrypter.Encrypt([]byte(signed))
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}

func checkEncPair(alg, enc string) error {
	defer telemetry.Step("oidc.checkEncPair")()
	if alg != encAlgRSAOAEP256 || enc != encA256GCM {
		return fmt.Errorf("unsupported encryption alg %q enc %q", alg, enc)
	}
	return nil
}

func (h *Handler) encryptionKey(client *models.Client) (*jose.JSONWebKey, error) {
	defer telemetry.Step("oidc.Handler.encryptionKey")()
	raw := strings.TrimSpace(client.JWKS)
	if raw == "" && strings.TrimSpace(client.JWKSUri) != "" {
		if h.fetchSector == nil {
			return nil, fmt.Errorf("jwks_uri cannot be fetched")
		}
		body, err := h.fetchSector(context.Background(), client.JWKSUri)
		if err != nil {
			return nil, err
		}
		raw = string(body)
	}
	if raw == "" {
		return nil, fmt.Errorf("client has no encryption key")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal([]byte(raw), &set); err != nil {
		return nil, fmt.Errorf("client jwks: %w", err)
	}
	for _, key := range set.Keys {
		if _, ok := key.Key.(*rsa.PublicKey); !ok {
			continue
		}
		if key.Use == "enc" || key.Algorithm == encAlgRSAOAEP256 {
			copied := key
			return &copied, nil
		}
	}
	return nil, fmt.Errorf("client jwks has no RSA encryption key")
}
