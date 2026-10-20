package flows

import (
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
	pkgerrors "github.com/bravo68web/oauth-impl/pkg/errors"
)

type FlowContext struct {
	Clients *repository.ClientRepository
	Tokens  *repository.TokenRepository
	Codes   *repository.AuthCodeRepository
	Cfg     *config.Config
}

type TokenResult struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int
	Scope        string
}

func NewFlowContext(db *database.DB, cfg *config.Config) *FlowContext {
	return &FlowContext{
		Clients: repository.NewClientRepository(db),
		Tokens:  repository.NewTokenRepository(db),
		Codes:   repository.NewAuthCodeRepository(db),
		Cfg:     cfg,
	}
}

func (fc *FlowContext) ValidateClient(clientID, clientSecret string) (*models.Client, *pkgerrors.OAuthError) {
	if clientID == "" {
		return nil, pkgerrors.InvalidClient("client_id is required")
	}

	client, err := fc.Clients.GetByID(clientID)
	if err != nil {
		return nil, pkgerrors.InvalidClient("Client not found")
	}

	if client.TokenEndpointAuthMethod != "none" && !crypto.SecretEqual(clientSecret, client.Secret) {
		return nil, pkgerrors.InvalidClient("Invalid client credentials")
	}

	return client, nil
}

func (fc *FlowContext) ValidateGrantType(client *models.Client, grantType string) *pkgerrors.OAuthError {
	for _, gt := range client.GrantTypes {
		if gt == grantType {
			return nil
		}
	}
	return pkgerrors.UnauthorizedClient(
		fmt.Sprintf("Client not authorized for %s grant", grantType),
	)
}

func (fc *FlowContext) GenerateTokens(clientID, userID string, scopes []string) (*TokenResult, *pkgerrors.OAuthError) {
	accessToken, err := crypto.GenerateToken()
	if err != nil {
		return nil, pkgerrors.ServerError("Failed to generate access token")
	}

	refreshToken, err := crypto.GenerateToken()
	if err != nil {
		return nil, pkgerrors.ServerError("Failed to generate refresh token")
	}

	accessTok := &models.AccessToken{
		Token:     accessToken,
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(fc.Cfg.Security.AccessTokenLifetime),
	}

	refreshTok := &models.RefreshToken{
		Token:       refreshToken,
		AccessToken: accessToken,
		ClientID:    clientID,
		UserID:      userID,
		Scopes:      scopes,
		ExpiresAt:   time.Now().Add(fc.Cfg.Security.RefreshTokenLifetime),
	}

	if err := fc.Tokens.SaveAccessToken(accessTok); err != nil {
		return nil, pkgerrors.ServerError("Failed to save access token")
	}

	if err := fc.Tokens.SaveRefreshToken(refreshTok); err != nil {
		return nil, pkgerrors.ServerError("Failed to save refresh token")
	}

	return &TokenResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(fc.Cfg.Security.AccessTokenLifetime.Seconds()),
		Scope:        strings.Join(scopes, " "),
	}, nil
}

func (fc *FlowContext) ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier string) (*models.AuthorizationCode, *pkgerrors.OAuthError) {
	if code == "" {
		return nil, pkgerrors.InvalidRequest("code is required")
	}

	authCode, err := fc.Codes.Get(code)
	if err != nil {
		return nil, pkgerrors.InvalidGrant("Invalid authorization code")
	}

	if authCode.Used {
		return nil, pkgerrors.InvalidGrant("Authorization code already used")
	}

	if time.Now().After(authCode.ExpiresAt) {
		return nil, pkgerrors.InvalidGrant("Authorization code expired")
	}

	if redirectURI != "" && redirectURI != authCode.RedirectURI {
		return nil, pkgerrors.InvalidGrant("redirect_uri mismatch")
	}

	if authCode.ClientID != clientID {
		return nil, pkgerrors.InvalidGrant("client_id mismatch")
	}

	if authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, pkgerrors.InvalidGrant("code_verifier is required")
		}
		if !crypto.ValidateCodeChallenge(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, pkgerrors.InvalidGrant("Invalid code_verifier")
		}
	}

	return authCode, nil
}

func (fc *FlowContext) ValidateScopes(requestedScopes []string, allowedScopes []string) []string {
	if len(requestedScopes) == 0 {
		return allowedScopes
	}

	valid := make([]string, 0)
	for _, rs := range requestedScopes {
		for _, as := range allowedScopes {
			if rs == as {
				valid = append(valid, rs)
				break
			}
		}
	}

	return valid
}
