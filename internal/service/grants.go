package service

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bravo68web/oauth-impl/internal/repository"
)

// GrantedApp is one client the user has allowed to act for them.
type GrantedApp struct {
	ClientID  string
	Name      string
	Initial   string
	Scopes    []string
	GrantedAt time.Time
}

// GrantService lists those grants and removes one, including its tokens.
type GrantService struct {
	consents *repository.ConsentRepository
	tokens   *repository.TokenRepository
	clients  *repository.ClientRepository
}

func NewGrantService(consents *repository.ConsentRepository, tokens *repository.TokenRepository, clients *repository.ClientRepository) *GrantService {
	return &GrantService{consents: consents, tokens: tokens, clients: clients}
}

func (s *GrantService) List(userID string) ([]GrantedApp, error) {
	if s == nil || s.consents == nil {
		return nil, nil
	}
	rows, err := s.consents.ListByUser(userID)
	if err != nil {
		return nil, err
	}
	out := make([]GrantedApp, 0, len(rows))
	for _, row := range rows {
		name := row.ClientID
		if s.clients != nil {
			if client, err := s.clients.GetByID(row.ClientID); err == nil && client != nil && client.Name != "" {
				name = client.Name
			}
		}
		out = append(out, GrantedApp{
			ClientID:  row.ClientID,
			Name:      name,
			Initial:   firstLetter(name),
			Scopes:    row.Scopes,
			GrantedAt: row.GrantedAt,
		})
	}
	return out, nil
}

// Revoke removes the consent and revokes that client's access and refresh tokens for the user.
func (s *GrantService) Revoke(userID, clientID string) error {
	if s == nil || s.consents == nil || s.tokens == nil {
		return nil
	}
	if err := s.consents.Delete(userID, clientID); err != nil {
		return err
	}
	return s.tokens.RevokeAllForClient(clientID, userID)
}

func firstLetter(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "?"
	}
	r, _ := utf8.DecodeRuneInString(name)
	return strings.ToUpper(string(r))
}
