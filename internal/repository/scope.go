package repository

import (
	"database/sql"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type ScopeRepository struct {
	db database.SQL
}

func NewScopeRepository(db database.SQL) *ScopeRepository {
	defer telemetry.Step("repository.NewScopeRepository")()
	return &ScopeRepository{db: db}
}

func (r *ScopeRepository) Create(scope *models.Scope) error {
	defer telemetry.Step("repository.ScopeRepository.Create")()
	query := `INSERT INTO scopes (name, description, resource_server, is_default, created_at)
		VALUES (?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		scope.Name, scope.Description, scope.ResourceServer,
		boolInt(scope.IsDefault), time.Now(),
	)
	return err
}

func (r *ScopeRepository) Get(name string) (*models.Scope, error) {
	defer telemetry.Step("repository.ScopeRepository.Get")()
	query := `SELECT name, description, resource_server, is_default, created_at
		FROM scopes WHERE name = ?`

	scope := &models.Scope{}
	var resourceServer sql.NullString
	var isDefault bit

	err := r.db.QueryRow(query, name).Scan(
		&scope.Name, &scope.Description, &resourceServer,
		&isDefault, &scope.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if resourceServer.Valid {
		scope.ResourceServer = resourceServer.String
	}
	scope.IsDefault = isDefault.Bool()

	return scope, nil
}

func (r *ScopeRepository) List() ([]*models.Scope, error) {
	defer telemetry.Step("repository.ScopeRepository.List")()
	query := `SELECT name, description, resource_server, is_default, created_at
		FROM scopes ORDER BY name`

	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	scopes := make([]*models.Scope, 0)
	for rows.Next() {
		scope := &models.Scope{}
		var resourceServer sql.NullString
		var isDefault bit

		err := rows.Scan(
			&scope.Name, &scope.Description, &resourceServer,
			&isDefault, &scope.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if resourceServer.Valid {
			scope.ResourceServer = resourceServer.String
		}
		scope.IsDefault = isDefault.Bool()

		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func (r *ScopeRepository) ListByResource(resourceURI string) ([]*models.Scope, error) {
	defer telemetry.Step("repository.ScopeRepository.ListByResource")()
	query := `SELECT name, description, resource_server, is_default, created_at
		FROM scopes WHERE resource_server = ? ORDER BY name`

	rows, err := r.db.Query(query, resourceURI)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	scopes := make([]*models.Scope, 0)
	for rows.Next() {
		scope := &models.Scope{}
		var resourceServer sql.NullString
		var isDefault bit

		err := rows.Scan(
			&scope.Name, &scope.Description, &resourceServer,
			&isDefault, &scope.CreatedAt,
		)
		if err != nil {
			return nil, err
		}

		if resourceServer.Valid {
			scope.ResourceServer = resourceServer.String
		}
		scope.IsDefault = isDefault.Bool()

		scopes = append(scopes, scope)
	}
	return scopes, nil
}

func (r *ScopeRepository) Delete(name string) error {
	defer telemetry.Step("repository.ScopeRepository.Delete")()
	_, err := r.db.Exec("DELETE FROM scopes WHERE name = ?", name)
	return err
}
