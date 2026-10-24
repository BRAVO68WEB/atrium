package repository

import (
	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type PARRepository struct {
	db database.SQL
}

func NewPARRepository(db database.SQL) *PARRepository {
	defer telemetry.Step("repository.NewPARRepository")()
	return &PARRepository{db: db}
}

func (r *PARRepository) Save(par *models.PushedAuthRequest) error {
	defer telemetry.Step("repository.PARRepository.Save")()
	query := `INSERT INTO pushed_auth_requests (request_uri, client_id, request_params, expires_at)
		VALUES (?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		par.RequestURI, par.ClientID, par.RequestParams, par.ExpiresAt,
	)
	return err
}

func (r *PARRepository) GetByRequestURI(requestURI string) (*models.PushedAuthRequest, error) {
	defer telemetry.Step("repository.PARRepository.GetByRequestURI")()
	query := `SELECT request_uri, client_id, request_params, expires_at
		FROM pushed_auth_requests WHERE request_uri = ?`

	par := &models.PushedAuthRequest{}
	err := r.db.QueryRow(query, requestURI).Scan(
		&par.RequestURI, &par.ClientID, &par.RequestParams, &par.ExpiresAt,
	)
	return par, err
}
