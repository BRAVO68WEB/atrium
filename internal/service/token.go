package service

import (
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
)

// TokenService lists and revokes access tokens for the management API.
// Issuance and introspection stay on the OAuth handler.
type TokenService struct {
	tokenRepo *repository.TokenRepository
}

func NewTokenService(tokenRepo *repository.TokenRepository) *TokenService {
	defer telemetry.Step("service.NewTokenService")()
	return &TokenService{tokenRepo: tokenRepo}
}

func (s *TokenService) RevokeToken(token string) error {
	defer telemetry.Step("service.TokenService.RevokeToken")()
	return s.tokenRepo.RevokeAccessToken(token)
}

func (s *TokenService) ListTokens(clientID, userID string) ([]*models.AccessToken, error) {
	defer telemetry.Step("service.TokenService.ListTokens")()
	return s.tokenRepo.ListAccessTokens(clientID, userID)
}
