package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/internal/telemetry"
)

type ctxKey int

const (
	ctxToken ctxKey = iota
)

type Middleware struct {
	tokens  *repository.TokenRepository
	clients *repository.ClientRepository
	users   *repository.UserRepository
	dpop    *service.DPoPService
}

func NewMiddleware(tokens *repository.TokenRepository, clients *repository.ClientRepository, users *repository.UserRepository, dpop *service.DPoPService) *Middleware {
	defer telemetry.Step("auth.NewMiddleware")()
	return &Middleware{tokens: tokens, clients: clients, users: users, dpop: dpop}
}

func TokenFrom(ctx context.Context) *models.AccessToken {
	defer telemetry.Step("auth.TokenFrom")()
	tok, _ := ctx.Value(ctxToken).(*models.AccessToken)
	return tok
}

func (m *Middleware) RequireManagement(next http.Handler) http.Handler {
	defer telemetry.Step("auth.Middleware.RequireManagement")()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, status, code, desc := m.load(r, false)
		if tok == nil {
			writeAuthError(w, status, code, desc)
			return
		}
		if tok.UserID != "" || !service.HasScope(tok.Scopes, service.ManagementScope) {
			writeAuthError(w, http.StatusForbidden, "insufficient_scope", "A management client-credentials token is required")
			return
		}
		client, err := m.clients.GetByID(tok.ClientID)
		if err != nil || !service.HasGrant(client.GrantTypes, "client_credentials") || !service.HasScope(client.Scopes, service.ManagementScope) {
			writeAuthError(w, http.StatusForbidden, "insufficient_scope", "Client is not allowed to call management APIs")
			return
		}
		if tok.TokenType == "DPoP" {
			if err := m.checkDPoP(r, tok); err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxToken, tok)))
	})
}

func (m *Middleware) RequireUser(next http.Handler) http.Handler {
	defer telemetry.Step("auth.Middleware.RequireUser")()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, status, code, desc := m.load(r, true)
		if tok == nil {
			writeAuthError(w, status, code, desc)
			return
		}
		if tok.UserID == "" {
			writeAuthError(w, http.StatusForbidden, "insufficient_scope", "A user access token is required")
			return
		}
		user, err := m.users.GetByID(tok.UserID)
		if err != nil || user.Disabled {
			writeAuthError(w, http.StatusUnauthorized, "invalid_token", "User is not allowed")
			return
		}
		if tok.TokenType == "DPoP" {
			if err := m.checkDPoP(r, tok); err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid_token", err.Error())
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxToken, tok)))
	})
}

func (m *Middleware) load(r *http.Request, userCall bool) (*models.AccessToken, int, string, string) {
	defer telemetry.Step("auth.Middleware.load")()
	raw := bearer(r)
	if raw == "" {
		return nil, http.StatusUnauthorized, "invalid_token", "Authorization header required"
	}
	tok, err := m.tokens.GetAccessToken(raw)
	if err != nil || tok.Revoked || time.Now().After(tok.ExpiresAt) {
		return nil, http.StatusUnauthorized, "invalid_token", "Token expired or revoked"
	}
	_ = userCall
	return tok, 0, "", ""
}

func (m *Middleware) checkDPoP(r *http.Request, tok *models.AccessToken) error {
	defer telemetry.Step("auth.Middleware.checkDPoP")()
	header := r.Header.Get("DPoP")
	if header == "" {
		return fmt.Errorf("DPoP header required")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	fullURI := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
	proof, err := m.dpop.ValidateDPoPProof(r.Context(), header, r.Method, fullURI, tok.Token)
	if err != nil {
		return err
	}
	if tok.DPoPJKT != "" && (proof == nil || proof.JKT != tok.DPoPJKT) {
		return fmt.Errorf("DPoP key does not match the token")
	}
	return nil
}

func bearer(r *http.Request) string {
	defer telemetry.Step("auth.bearer")()
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if len(h) > 5 && strings.EqualFold(h[:5], "dpop ") {
		return strings.TrimSpace(h[5:])
	}
	return ""
}

func writeAuthError(w http.ResponseWriter, status int, code, description string) {
	defer telemetry.Step("auth.writeAuthError")()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="%s", error_description="%s"`, code, description))
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, `{"error":"%s","error_description":"%s"}`+"\n", code, description)
}
