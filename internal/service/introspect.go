package service

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
)

// ErrInvalidClient is returned when the introspection caller cannot authenticate.
var ErrInvalidClient = errors.New("invalid_client")

// Introspection is an RFC 7662 response. Inactive tokens carry only Active.
type Introspection struct {
	Active    bool            `json:"active"`
	Scope     string          `json:"scope,omitempty"`
	ClientID  string          `json:"client_id,omitempty"`
	Username  string          `json:"username,omitempty"`
	TokenType string          `json:"token_type,omitempty"`
	Exp       int64           `json:"exp,omitempty"`
	Iat       int64           `json:"iat,omitempty"`
	Nbf       int64           `json:"nbf,omitempty"`
	Sub       string          `json:"sub,omitempty"`
	Iss       string          `json:"iss,omitempty"`
	Aud       string          `json:"aud,omitempty"`
	JTI       string          `json:"jti,omitempty"`
	OrgID     string          `json:"org_id,omitempty"`
	OrgRole   string          `json:"org_role,omitempty"`
	Act       json.RawMessage `json:"act,omitempty"`
}

// Introspector looks up access and refresh tokens for a confidential caller.
type Introspector struct {
	tokens             *repository.TokenRepository
	users              *repository.UserRepository
	issuer             string
	managementClientID string
}

func NewIntrospector(tokens *repository.TokenRepository, users *repository.UserRepository, cfg *config.Config) *Introspector {
	defer telemetry.Step("service.NewIntrospector")()
	issuer := ""
	management := ""
	if cfg != nil {
		issuer = cfg.Security.Issuer
		management = cfg.Management.ClientID
	}
	return &Introspector{tokens: tokens, users: users, issuer: issuer, managementClientID: management}
}

// Introspect returns an inactive result when the token is unknown, expired,
// revoked, or the caller is not allowed to see it.
func (s *Introspector) Introspect(caller *models.Client, raw, hint string) (*Introspection, error) {
	defer telemetry.Step("service.Introspector.Introspect")()
	if caller == nil || caller.TokenEndpointAuthMethod == "none" || caller.TokenEndpointAuthMethod == "" {
		return nil, ErrInvalidClient
	}
	inactive := &Introspection{Active: false}
	if strings.TrimSpace(raw) == "" || s == nil || s.tokens == nil {
		return inactive, nil
	}
	access, refresh := s.lookup(raw, hint)
	if access == nil && refresh == nil {
		return inactive, nil
	}
	clientID, resource, userID, scopes, tokenType, exp, iat, jti, orgID, act, revoked := flatten(access, refresh)
	if !s.allowed(caller, clientID, resource) || revoked || (!exp.IsZero() && time.Now().After(exp)) {
		return inactive, nil
	}
	out := &Introspection{
		Active:    true,
		Scope:     strings.Join(scopes, " "),
		ClientID:  clientID,
		TokenType: tokenType,
		Exp:       exp.Unix(),
		Iss:       s.issuer,
		Aud:       clientID,
		JTI:       jti,
		OrgID:     orgID,
	}
	if resource != "" {
		out.Aud = resource
	}
	if !iat.IsZero() {
		out.Iat = iat.Unix()
		out.Nbf = iat.Unix()
	}
	if userID != "" {
		out.Sub = userID
		if s.users != nil {
			if user, err := s.users.GetByID(userID); err == nil && user != nil {
				out.Username = user.Username
			}
		}
	}
	if act = strings.TrimSpace(act); act != "" {
		if json.Valid([]byte(act)) && strings.HasPrefix(act, "{") {
			out.Act = json.RawMessage(act)
		} else if raw, err := json.Marshal(map[string]string{"sub": act}); err == nil {
			out.Act = raw
		}
	}
	return out, nil
}

func (s *Introspector) lookup(raw, hint string) (*models.AccessToken, *models.RefreshToken) {
	defer telemetry.Step("service.Introspector.lookup")()
	hint = strings.ToLower(strings.TrimSpace(hint))
	if hint == "refresh_token" {
		if rt, err := s.tokens.GetRefreshToken(raw); err == nil {
			return nil, rt
		}
	}
	if at, err := s.tokens.GetAccessToken(raw); err == nil {
		return at, nil
	}
	if hint != "refresh_token" {
		if rt, err := s.tokens.GetRefreshToken(raw); err == nil {
			return nil, rt
		}
	}
	return nil, nil
}

func (s *Introspector) allowed(caller *models.Client, tokenClient, resource string) bool {
	defer telemetry.Step("service.Introspector.allowed")()
	if s.managementClientID != "" && caller.ID == s.managementClientID {
		return true
	}
	if caller.ID == tokenClient {
		return true
	}
	return resource != "" && caller.ID == resource
}

func flatten(access *models.AccessToken, refresh *models.RefreshToken) (clientID, resource, userID string, scopes []string, tokenType string, exp, iat time.Time, jti, orgID, act string, revoked bool) {
	defer telemetry.Step("service.flatten")()
	if access != nil {
		tokenType = access.TokenType
		if tokenType == "" {
			tokenType = "Bearer"
		}
		return access.ClientID, access.Resource, access.UserID, access.Scopes, tokenType, access.ExpiresAt, access.IssuedAt, access.JTI, access.OrgID, access.Act, access.Revoked
	}
	return refresh.ClientID, refresh.Resource, refresh.UserID, refresh.Scopes, "refresh_token", refresh.ExpiresAt, refresh.IssuedAt, refresh.JTI, refresh.OrgID, refresh.Act, refresh.Revoked
}
