package service

import (
	"database/sql"
	"log"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

func SeedManagementClient(repo *repository.ClientRepository, cfg *config.Config) error {
	defer telemetry.Step("service.SeedManagementClient")()
	if cfg == nil {
		return nil
	}
	id := strings.TrimSpace(cfg.Management.ClientID)
	secret := cfg.Management.ClientSecret
	if id == "" || secret == "" {
		return nil
	}
	existing, err := repo.GetByID(id)
	if err == nil {
		if existing.Secret != secret {
			log.Printf("management client %s already exists; leaving the stored secret unchanged", id)
		}
		return nil
	}
	if err != sql.ErrNoRows {
		return err
	}
	now := time.Now()
	client := &models.Client{
		ID:                               id,
		Secret:                           secret,
		Name:                             "Management",
		RedirectURIs:                     []string{},
		GrantTypes:                       []string{"client_credentials"},
		Scopes:                           []string{ManagementScope},
		TokenEndpointAuthMethod:          "client_secret_basic",
		BackchannelLogoutSessionRequired: true,
		PostLogoutRedirectURIs:           []string{},
		CreatedAt:                        now,
		UpdatedAt:                        now,
	}
	if err := repo.Create(client); err != nil {
		return err
	}
	log.Printf("seeded management client %s", id)
	return nil
}
