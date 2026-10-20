package service

import (
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/pkg/crypto"
)

// TokenExchangeService implements RFC 8693 for a local access token.
// An ID-JAG is issued by XAA from the token endpoint, not by ExchangeToken.
type TokenExchangeService struct {
	tokenRepo  *repository.TokenRepository
	userRepo   *repository.UserRepository
	clientRepo *repository.ClientRepository
	cfg        *config.SecurityConfig
}

type TokenExchangeRequest struct {
	GrantType          string `json:"grant_type"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	ActorToken         string `json:"actor_token"`
	ActorTokenType     string `json:"actor_token_type"`
	Resource           string `json:"resource"`
	Audience           string `json:"audience"`
	Scope              string `json:"scope"`
	RequestedTokenType string `json:"requested_token_type"`
}

type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
	RefreshToken    string `json:"refresh_token,omitempty"`
}

// Token type constants
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeSAML1        = "urn:ietf:params:oauth:token-type:saml1"
	TokenTypeSAML2        = "urn:ietf:params:oauth:token-type:saml2"
)

func NewTokenExchangeService(
	tokenRepo *repository.TokenRepository,
	userRepo *repository.UserRepository,
	clientRepo *repository.ClientRepository,
	cfg *config.SecurityConfig,
) *TokenExchangeService {
	return &TokenExchangeService{
		tokenRepo:  tokenRepo,
		userRepo:   userRepo,
		clientRepo: clientRepo,
		cfg:        cfg,
	}
}

// ExchangeToken performs a token exchange per RFC 8693
func (s *TokenExchangeService) ExchangeToken(
	clientID string,
	req *TokenExchangeRequest,
) (*TokenExchangeResponse, error) {
	// Validate grant type
	if req.GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		return nil, fmt.Errorf("unsupported grant type: %s", req.GrantType)
	}

	// Validate subject token
	if req.SubjectToken == "" {
		return nil, fmt.Errorf("subject_token is required")
	}

	// Validate subject token type
	if req.SubjectTokenType == "" {
		req.SubjectTokenType = TokenTypeAccessToken
	}

	// Validate the subject token
	subjectInfo, err := s.validateToken(req.SubjectToken, req.SubjectTokenType)
	if err != nil {
		return nil, fmt.Errorf("invalid subject_token: %w", err)
	}

	// Validate actor token if provided
	var actorID string
	if req.ActorToken != "" {
		if req.ActorTokenType == "" {
			req.ActorTokenType = TokenTypeAccessToken
		}
		actorInfo, err := s.validateToken(req.ActorToken, req.ActorTokenType)
		if err != nil {
			return nil, fmt.Errorf("invalid actor_token: %w", err)
		}
		actorID = actorInfo.UserID
	}

	// Determine requested token type
	requestedType := TokenTypeAccessToken
	if req.RequestedTokenType != "" {
		requestedType = req.RequestedTokenType
	}

	// Parse scopes
	scopes := crypto.NormalizeScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = subjectInfo.Scopes
	}

	// Generate new token
	newAccessToken, err := crypto.GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// Create new access token
	accessTok := &models.AccessToken{
		Token:     newAccessToken,
		ClientID:  clientID,
		UserID:    subjectInfo.UserID,
		Scopes:    scopes,
		TokenType: "Bearer",
		ExpiresAt: time.Now().Add(s.cfg.AccessTokenLifetime),
	}

	if err := s.tokenRepo.SaveAccessToken(accessTok); err != nil {
		return nil, fmt.Errorf("failed to save access token: %w", err)
	}

	response := &TokenExchangeResponse{
		AccessToken:     newAccessToken,
		IssuedTokenType: requestedType,
		TokenType:       "Bearer",
		ExpiresIn:       int(s.cfg.AccessTokenLifetime.Seconds()),
		Scope:           strings.Join(scopes, " "),
	}

	// Optionally issue refresh token
	if containsScope(scopes, "offline_access") {
		newRefreshToken, err := crypto.GenerateToken()
		if err == nil {
			refreshTok := &models.RefreshToken{
				Token:       newRefreshToken,
				AccessToken: newAccessToken,
				ClientID:    clientID,
				UserID:      subjectInfo.UserID,
				Scopes:      scopes,
				ExpiresAt:   time.Now().Add(s.cfg.RefreshTokenLifetime),
			}
			if err := s.tokenRepo.SaveRefreshToken(refreshTok); err == nil {
				response.RefreshToken = newRefreshToken
			}
		}
	}

	_ = actorID // Used for audit logging in production

	return response, nil
}

func (s *TokenExchangeService) validateToken(token, tokenType string) (*models.AccessToken, error) {
	switch tokenType {
	case TokenTypeAccessToken:
		at, err := s.tokenRepo.GetAccessToken(token)
		if err != nil {
			return nil, fmt.Errorf("token not found")
		}
		if at.Revoked {
			return nil, fmt.Errorf("token is revoked")
		}
		if time.Now().After(at.ExpiresAt) {
			return nil, fmt.Errorf("token is expired")
		}
		return at, nil
	default:
		return nil, fmt.Errorf("unsupported token type: %s", tokenType)
	}
}
