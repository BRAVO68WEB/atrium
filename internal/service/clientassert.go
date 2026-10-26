package service

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/cache"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/golang-jwt/jwt/v5"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// VerifyClientAssertion checks a client_secret_jwt or private_key_jwt assertion.
// aud may be the issuer, the token endpoint, or the endpoint that received it.
func VerifyClientAssertion(ctx context.Context, replay cache.Cache, keys *JARService, client *models.Client, raw, assertionType, issuer, requestURL string) error {
	defer telemetry.Step("service.VerifyClientAssertion")()
	if client == nil {
		return fmt.Errorf("invalid client assertion")
	}
	if assertionType != "" && assertionType != clientAssertionType {
		return fmt.Errorf("invalid client assertion")
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		return fmt.Errorf("invalid client assertion")
	}
	alg, _ := unverified.Header["alg"].(string)
	if alg == "" || alg == "none" {
		return fmt.Errorf("invalid client assertion")
	}
	token, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Method == nil || t.Method.Alg() != alg {
			return nil, fmt.Errorf("unexpected signing method")
		}
		switch alg {
		case "HS256", "HS384", "HS512":
			if client.Secret == "" {
				return nil, fmt.Errorf("client has no secret")
			}
			return []byte(client.Secret), nil
		case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
			if keys == nil {
				return nil, fmt.Errorf("no signing keys")
			}
			return keys.ClientPublicKey(client, t.Header)
		default:
			return nil, fmt.Errorf("unsupported assertion alg")
		}
	}, jwt.WithValidMethods([]string{alg}))
	if err != nil || token == nil || !token.Valid {
		return fmt.Errorf("invalid client assertion")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid client assertion")
	}
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss != client.ID || sub != client.ID {
		return fmt.Errorf("invalid client assertion")
	}
	if !audienceMatches(claims["aud"], issuer, requestURL) {
		return fmt.Errorf("invalid client assertion")
	}
	exp, ok := numericTime(claims["exp"])
	if !ok || !exp.After(time.Now()) {
		return fmt.Errorf("invalid client assertion")
	}
	if iat, ok := numericTime(claims["iat"]); ok && iat.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("invalid client assertion")
	}
	if nbf, ok := numericTime(claims["nbf"]); ok && nbf.After(time.Now().Add(time.Minute)) {
		return fmt.Errorf("invalid client assertion")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return fmt.Errorf("invalid client assertion")
	}
	if replay == nil {
		return nil
	}
	ttl := time.Until(exp)
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if ttl > 24*time.Hour {
		ttl = 24 * time.Hour
	}
	fresh, err := replay.Add(ctx, "client-assertion:"+jti, []byte("1"), ttl)
	if err != nil {
		return fmt.Errorf("invalid client assertion")
	}
	if !fresh {
		return fmt.Errorf("invalid client assertion")
	}
	return nil
}

func audienceMatches(raw any, issuer, requestURL string) bool {
	allowed := map[string]bool{}
	issuer = strings.TrimRight(issuer, "/")
	if issuer != "" {
		allowed[issuer] = true
		allowed[issuer+"/oauth/token"] = true
	}
	if requestURL != "" {
		allowed[requestURL] = true
	}
	switch v := raw.(type) {
	case string:
		return allowed[v]
	case []any:
		for _, item := range v {
			s, _ := item.(string)
			if allowed[s] {
				return true
			}
		}
	}
	return false
}

func numericTime(raw any) (time.Time, bool) {
	switch v := raw.(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	case int:
		return time.Unix(int64(v), 0), true
	default:
		return time.Time{}, false
	}
}

// RequestURL is scheme, host, and path, without a query string.
func RequestURL(scheme, host, path string) string {
	u := url.URL{Scheme: scheme, Host: host, Path: path}
	return u.String()
}
