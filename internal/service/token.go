package service

import (
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
)

// TokenService lists and revokes access tokens for the management API.
// Issuance and introspection stay on the OAuth handler.
type TokenService struct {
	tokenRepo *repository.TokenRepository
}

func NewTokenService(tokenRepo *repository.TokenRepository) *TokenService {
	return &TokenService{tokenRepo: tokenRepo}
}

func (s *TokenService) RevokeToken(token string) error {
	return s.tokenRepo.RevokeAccessToken(token)
}

func (s *TokenService) ListTokens(clientID, userID string) ([]*models.AccessToken, error) {
	return s.tokenRepo.ListAccessTokens(clientID, userID)
}
