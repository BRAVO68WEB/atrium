package oauth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/oidc"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

func (h *Handler) handleAuthorizationCodeToken(w http.ResponseWriter, r *http.Request) {
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	codeVerifier := r.Form.Get("code_verifier")

	clientID, clientSecret := presentedClient(r)

	if code == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	authCode, err := h.authCodeRepo.Get(code)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid authorization code")
		return
	}

	client, ok := h.requireClient(w, authCode.ClientID, "", http.StatusBadRequest)
	if !ok {
		return
	}

	// Validate mTLS only when client auth method requires it
	if client.TokenEndpointAuthMethod == "tls_client_auth" || client.TokenEndpointAuthMethod == "self_signed_tls_client_auth" {
		cert := h.mtlsSvc.ExtractClientCertificate(r)
		if cert == nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "Client certificate required")
			return
		}
		if err := h.mtlsSvc.ValidateClientCertificate(cert, nil); err != nil {
			writeTokenError(w, http.StatusBadRequest, "invalid_client", "Invalid client certificate: "+err.Error())
			return
		}
	}

	dpopJKT, ok := h.enforceClientDPoP(w, r, client)
	if !ok {
		return
	}

	if authCode.Used {
		if authCode.FamilyID != "" {
			_ = h.tokenRepo.RevokeFamily(authCode.FamilyID)
		} else {
			_ = h.tokenRepo.RevokeAllForClient(authCode.ClientID, authCode.UserID)
		}
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code already used")
		return
	}

	if time.Now().After(authCode.ExpiresAt) {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code expired")
		return
	}

	// RFC 6749: redirect_uri is REQUIRED if included in authorization request
	if redirectURI != authCode.RedirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	actorToken := r.Form.Get("actor_token")
	if authCode.RequestedActor != "" {
		if actorToken == "" {
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", "actor_token is required")
			return
		}
		subject, err := h.actorSubject(actorToken)
		if err != nil || subject != authCode.RequestedActor {
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", "actor_token does not match the consented actor")
			return
		}
	} else if actorToken != "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request", "actor_token is not allowed")
		return
	}

	switch authenticateClient(client, clientID, clientSecret, true) {
	case "":
	case "mismatch":
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "client_id mismatch")
		return
	default:
		writeTokenError(w, http.StatusBadRequest, "invalid_client", "Invalid client secret")
		return
	}

	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", "code_verifier is required")
			return
		}
		if !crypto.ValidateCodeChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid code_verifier")
			return
		}
	}

	if err := h.authCodeRepo.MarkUsed(code); err != nil {
		if errors.Is(err, repository.ErrCodeUsed) {
			if authCode.FamilyID != "" {
				_ = h.tokenRepo.RevokeFamily(authCode.FamilyID)
			} else {
				_ = h.tokenRepo.RevokeAllForClient(authCode.ClientID, authCode.UserID)
			}
			writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code already used")
			return
		}
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to mark authorization code as used")
		return
	}

	tokenType := boundTokenType(client)
	orgSlug := h.orgSlug(authCode.OrgID)

	accessToken, err := h.issueAccessTokenFor(authCode.ClientID, authCode.UserID, strings.Join(authCode.Scopes, " "), tokenType, authCode.OrgID, orgSlug, authCode.Resource, authCode.RequestedActor)
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate access token")
		return
	}

	refreshToken, err := crypto.GenerateToken()
	if err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to generate refresh token")
		return
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  authCode.ClientID,
		UserID:    authCode.UserID,
		Scopes:    authCode.Scopes,
		TokenType: tokenType,
		DPoPJKT:   dpopJKT,
		Resource:  authCode.Resource,
		OrgID:     authCode.OrgID,
		Act:       authCode.RequestedActor,
		ExpiresAt: time.Now().Add(h.cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    authCode.ClientID,
		UserID:      authCode.UserID,
		Scopes:      authCode.Scopes,
		FamilyID:    authCode.FamilyID,
		Resource:    authCode.Resource,
		Act:         authCode.RequestedActor,
		OrgID:       authCode.OrgID,
		ExpiresAt:   time.Now().Add(h.cfg.Security.RefreshTokenLifetime),
	}

	if err := h.tokenRepo.SaveAccessToken(accessTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save access token")
		return
	}

	if err := h.tokenRepo.SaveRefreshToken(refreshTok); err != nil {
		writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to save refresh token")
		return
	}

	var idToken string
	if containsScope(authCode.Scopes, "openid") && h.oidcHandler != nil {
		// Use nonce stored with the authorization code, not from the token request
		idToken, err = h.oidcHandler.CreateIDToken(authCode.ClientID, authCode.UserID, authCode.Nonce, authCode.Scopes, oidc.IDTokenExtra{SID: authCode.SessionID, AuthTime: authCode.AuthTime, OrgID: authCode.OrgID, OrgSlug: orgSlug})
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to create ID token")
			return
		}
	}

	writeOIDCTokenResponse(w, accessToken, refreshToken, idToken, int(h.cfg.Security.AccessTokenLifetime.Seconds()), tokenType, strings.Join(authCode.Scopes, " "))
}
