package repository

import (
	"github.com/bravo68web/atrium/internal/database"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
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
	query := `SELECT request_uri, client_id, request_params, expires_at, used
		FROM pushed_auth_requests WHERE request_uri = ?`

	par := &models.PushedAuthRequest{}
	var used int
	err := r.db.QueryRow(query, requestURI).Scan(
		&par.RequestURI, &par.ClientID, &par.RequestParams, &par.ExpiresAt, &used,
	)
	par.Used = used != 0
	return par, err
}

func (r *PARRepository) MarkUsed(requestURI string) error {
	defer telemetry.Step("repository.PARRepository.MarkUsed")()
	_, err := r.db.Exec(`UPDATE pushed_auth_requests SET used = 1 WHERE request_uri = ?`, requestURI)
	return err
}

func (r *PARRepository) Delete(requestURI string) error {
	defer telemetry.Step("repository.PARRepository.Delete")()
	_, err := r.db.Exec(`DELETE FROM pushed_auth_requests WHERE request_uri = ?`, requestURI)
	return err
}
