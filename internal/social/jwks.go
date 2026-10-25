package social

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/golang-jwt/jwt/v5"
)

func verifyIDToken(ctx context.Context, c *Client, jwksURL, raw, issuer, audience, nonce string) (map[string]any, error) {
	defer telemetry.Step("social.verifyIDToken")()
	if jwksURL == "" {
		return nil, fmt.Errorf("jwks uri is empty")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "atrium")
	body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]any{}
	for _, rawKey := range set.Keys {
		kid, key, err := parseJWK(rawKey)
		if err != nil || key == nil {
			continue
		}
		keys[kid] = key
	}
	parsed, err := jwt.Parse(raw, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		if kid != "" {
			if key := keys[kid]; key != nil {
				return key, nil
			}
		}
		if len(keys) == 1 {
			for _, key := range keys {
				return key, nil
			}
		}
		return nil, fmt.Errorf("no matching jwk")
	}, jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}))
	if err != nil {
		return nil, fmt.Errorf("id token: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return nil, fmt.Errorf("id token is invalid")
	}
	if nonce != "" && stringClaim(claims, "nonce") != nonce {
		return nil, fmt.Errorf("id token nonce mismatch")
	}
	out := map[string]any{}
	for k, v := range claims {
		out[k] = v
	}
	return out, nil
}

func parseJWK(raw json.RawMessage) (string, any, error) {
	defer telemetry.Step("social.parseJWK")()
	var meta struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Crv string `json:"crv"`
		N   string `json:"n"`
		E   string `json:"e"`
		X   string `json:"x"`
		Y   string `json:"y"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return "", nil, err
	}
	switch meta.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(meta.N)
		if err != nil {
			return "", nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(meta.E)
		if err != nil {
			return "", nil, err
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e == 0 {
			return "", nil, fmt.Errorf("bad rsa exponent")
		}
		return meta.Kid, &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	case "EC":
		if meta.Crv != "P-256" {
			return "", nil, fmt.Errorf("unsupported curve")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(meta.X)
		if err != nil {
			return "", nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(meta.Y)
		if err != nil {
			return "", nil, err
		}
		pub, err := ecPublicKey(elliptic.P256(), xBytes, yBytes)
		if err != nil {
			return "", nil, err
		}
		return meta.Kid, pub, nil
	default:
		return "", nil, fmt.Errorf("unsupported key type")
	}
}

func ecPublicKey(curve elliptic.Curve, x, y []byte) (*ecdsa.PublicKey, error) {
	defer telemetry.Step("social.ecPublicKey")()
	size := (curve.Params().BitSize + 7) / 8
	if len(x) == 0 || len(y) == 0 || len(x) > size || len(y) > size {
		return nil, fmt.Errorf("invalid EC coordinates")
	}
	raw := make([]byte, 1+2*size)
	raw[0] = 4
	copy(raw[1+size-len(x):1+size], x)
	copy(raw[1+2*size-len(y):], y)
	return ecdsa.ParseUncompressedPublicKey(curve, raw)
}
