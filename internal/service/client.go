package service

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
)

type ClientService struct {
	clientRepo *repository.ClientRepository
}

func NewClientService(clientRepo *repository.ClientRepository) *ClientService {
	defer telemetry.Step("service.NewClientService")()
	return &ClientService{clientRepo: clientRepo}
}

type CreateClientInput struct {
	ID                                         string
	Name                                       string
	RedirectURIs                               []string
	GrantTypes                                 []string
	Scopes                                     []string
	TokenEndpointAuthMethod                    string
	DPoPBoundAccessTokens                      bool
	RequirePushedAuthorizationRequests         bool
	BackchannelTokenDeliveryMode               string
	BackchannelClientNotificationEndpoint      string
	BackchannelAuthenticationRequestSigningAlg string
	BackchannelLogoutURI                       string
	BackchannelLogoutSessionRequired           *bool
	PostLogoutRedirectURIs                     []string
	DCREnabled                                 bool
	CIMDEnabled                                bool
	SkipConsent                                bool
	SubjectType                                string
	SectorIdentifierURI                        string
	JWKS                                       string
	IDTokenEncryptedResponseAlg                string
	IDTokenEncryptedResponseEnc                string
	UserinfoEncryptedResponseAlg               string
	UserinfoEncryptedResponseEnc               string
}

func (s *ClientService) CreateClient(input CreateClientInput) (*models.Client, error) {
	defer telemetry.Step("service.ClientService.CreateClient")()
	if input.Name == "" {
		return nil, fmt.Errorf("name is required")
	}

	if input.TokenEndpointAuthMethod == "" {
		input.TokenEndpointAuthMethod = "client_secret_basic"
	}
	sessionRequired := true
	if input.BackchannelLogoutSessionRequired != nil {
		sessionRequired = *input.BackchannelLogoutSessionRequired
	}
	if input.RedirectURIs == nil {
		input.RedirectURIs = []string{}
	}
	if input.PostLogoutRedirectURIs == nil {
		input.PostLogoutRedirectURIs = []string{}
	}

	clientID := uuid.New().String()
	if input.ID != "" {
		if !validClientID(input.ID) {
			return nil, fmt.Errorf("client id is invalid")
		}
		existing, err := s.clientRepo.GetByID(input.ID)
		if err == nil && existing != nil {
			return nil, fmt.Errorf("client id is already in use")
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("failed to create client: %w", err)
		}
		clientID = input.ID
	}

	client := &models.Client{
		ID:                                    clientID,
		Secret:                                generateSecret(),
		Name:                                  input.Name,
		RedirectURIs:                          input.RedirectURIs,
		GrantTypes:                            input.GrantTypes,
		Scopes:                                input.Scopes,
		TokenEndpointAuthMethod:               input.TokenEndpointAuthMethod,
		DPoPBoundAccessTokens:                 input.DPoPBoundAccessTokens,
		RequirePushedAuthorizationRequests:    input.RequirePushedAuthorizationRequests,
		BackchannelTokenDeliveryMode:          input.BackchannelTokenDeliveryMode,
		BackchannelClientNotificationEndpoint: input.BackchannelClientNotificationEndpoint,
		BackchannelAuthenticationRequestSigningAlg: input.BackchannelAuthenticationRequestSigningAlg,
		BackchannelLogoutURI:                       input.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:           sessionRequired,
		PostLogoutRedirectURIs:                     input.PostLogoutRedirectURIs,
		RegistrationSource:                         "management",
		DCREnabled:                                 input.DCREnabled,
		CIMDEnabled:                                input.CIMDEnabled,
		SkipConsent:                                input.SkipConsent,
		SubjectType:                                input.SubjectType,
		SectorIdentifierURI:                        input.SectorIdentifierURI,
		JWKS:                                       input.JWKS,
		IDTokenEncryptedResponseAlg:                input.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:                input.IDTokenEncryptedResponseEnc,
		UserinfoEncryptedResponseAlg:               input.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc:               input.UserinfoEncryptedResponseEnc,
		CreatedAt:                                  time.Now(),
		UpdatedAt:                                  time.Now(),
	}
	if err := ValidateSubjectType(client); err != nil {
		return nil, err
	}

	if err := s.clientRepo.Create(client); err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return client, nil
}

func (s *ClientService) GetClient(id string) (*models.Client, error) {
	defer telemetry.Step("service.ClientService.GetClient")()
	return s.clientRepo.GetByID(id)
}

func (s *ClientService) ListClients() ([]*models.Client, error) {
	defer telemetry.Step("service.ClientService.ListClients")()
	return s.clientRepo.List()
}

func (s *ClientService) UpdateClient(client *models.Client) error {
	defer telemetry.Step("service.ClientService.UpdateClient")()
	if err := ValidateSubjectType(client); err != nil {
		return err
	}
	client.UpdatedAt = time.Now()
	return s.clientRepo.Update(client)
}

func (s *ClientService) DeleteClient(id string) error {
	defer telemetry.Step("service.ClientService.DeleteClient")()
	return s.clientRepo.Delete(id)
}

func (s *ClientService) ValidateClient(clientID, clientSecret string) (*models.Client, error) {
	defer telemetry.Step("service.ClientService.ValidateClient")()
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}

	client, err := s.clientRepo.GetByID(clientID)
	if err != nil {
		return nil, fmt.Errorf("client not found")
	}

	if client.TokenEndpointAuthMethod != "none" && !crypto.SecretEqual(clientSecret, client.Secret) {
		return nil, fmt.Errorf("invalid client credentials")
	}

	return client, nil
}

func (s *ClientService) ResetSecret(id string) (string, error) {
	defer telemetry.Step("service.ClientService.ResetSecret")()
	if _, err := s.clientRepo.GetByID(id); err != nil {
		return "", err
	}
	secret := generateSecret()
	if err := s.clientRepo.ResetSecret(id, secret); err != nil {
		return "", err
	}
	return secret, nil
}

func (s *ClientService) ValidateGrantType(client *models.Client, grantType string) error {
	defer telemetry.Step("service.ClientService.ValidateGrantType")()
	for _, gt := range client.GrantTypes {
		if gt == grantType {
			return nil
		}
	}
	return fmt.Errorf("client not authorized for %s grant", grantType)
}

func validClientID(id string) bool {
	defer telemetry.Step("service.validClientID")()
	if len(id) < 1 || len(id) > 128 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case i > 0 && (r == '-' || r == '_' || r == '.'):
		default:
			return false
		}
	}
	return true
}

func generateSecret() string {
	defer telemetry.Step("service.generateSecret")()
	secret, err := crypto.GenerateToken()
	if err != nil {
		return uuid.New().String()
	}
	return secret
}
