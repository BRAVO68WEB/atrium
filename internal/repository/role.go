package repository

import (
	"database/sql"
	"time"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
)

type RoleRepository struct {
	db database.SQL
}

func NewRoleRepository(db database.SQL) *RoleRepository {
	defer telemetry.Step("repository.NewRoleRepository")()
	return &RoleRepository{db: db}
}

func (r *RoleRepository) Create(role *models.Role) error {
	defer telemetry.Step("repository.RoleRepository.Create")()
	_, err := r.db.Exec(`INSERT INTO roles (id, name, description, created_at) VALUES (?, ?, ?, ?)`,
		role.ID, role.Name, role.Description, role.CreatedAt)
	return err
}

func (r *RoleRepository) Get(id string) (*models.Role, error) {
	defer telemetry.Step("repository.RoleRepository.Get")()
	role := &models.Role{}
	err := r.db.QueryRow(`SELECT id, name, description, created_at FROM roles WHERE id = ?`, id).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt)
	if err != nil {
		return nil, err
	}
	return role, nil
}

func (r *RoleRepository) GetByName(name string) (*models.Role, error) {
	defer telemetry.Step("repository.RoleRepository.GetByName")()
	role := &models.Role{}
	err := r.db.QueryRow(`SELECT id, name, description, created_at FROM roles WHERE name = ?`, name).Scan(
		&role.ID, &role.Name, &role.Description, &role.CreatedAt)
	if err != nil {
		return nil, err
	}
	return role, nil
}

func (r *RoleRepository) List() ([]*models.Role, error) {
	defer telemetry.Step("repository.RoleRepository.List")()
	rows, err := r.db.Query(`SELECT id, name, description, created_at FROM roles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []*models.Role{}
	for rows.Next() {
		role := &models.Role{}
		if err := rows.Scan(&role.ID, &role.Name, &role.Description, &role.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

func (r *RoleRepository) Update(role *models.Role) error {
	defer telemetry.Step("repository.RoleRepository.Update")()
	res, err := r.db.Exec(`UPDATE roles SET name = ?, description = ? WHERE id = ?`, role.Name, role.Description, role.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *RoleRepository) Delete(id string) error {
	defer telemetry.Step("repository.RoleRepository.Delete")()
	if _, err := r.db.Exec(`DELETE FROM role_scopes WHERE role_id = ?`, id); err != nil {
		return err
	}
	if _, err := r.db.Exec(`DELETE FROM user_roles WHERE role_id = ?`, id); err != nil {
		return err
	}
	res, err := r.db.Exec(`DELETE FROM roles WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *RoleRepository) Scopes(roleID string) ([]models.RoleScope, error) {
	defer telemetry.Step("repository.RoleRepository.Scopes")()
	rows, err := r.db.Query(`SELECT resource_uri, scope FROM role_scopes WHERE role_id = ? ORDER BY resource_uri, scope`, roleID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []models.RoleScope{}
	for rows.Next() {
		var item models.RoleScope
		if err := rows.Scan(&item.Resource, &item.Scope); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *RoleRepository) ReplaceScopes(roleID string, scopes []models.RoleScope) error {
	defer telemetry.Step("repository.RoleRepository.ReplaceScopes")()
	if _, err := r.db.Exec(`DELETE FROM role_scopes WHERE role_id = ?`, roleID); err != nil {
		return err
	}
	for _, item := range scopes {
		if _, err := r.db.Exec(`INSERT INTO role_scopes (role_id, resource_uri, scope) VALUES (?, ?, ?)`,
			roleID, item.Resource, item.Scope); err != nil {
			return err
		}
	}
	return nil
}

func (r *RoleRepository) AssignRole(userID, roleID, orgID string) error {
	defer telemetry.Step("repository.RoleRepository.AssignRole")()
	_, err := r.db.Exec(`INSERT INTO user_roles (user_id, role_id, org_id, created_at) VALUES (?, ?, ?, ?)`,
		userID, roleID, orgID, time.Now().UTC())
	return err
}

func (r *RoleRepository) RemoveRole(userID, roleID, orgID string) error {
	defer telemetry.Step("repository.RoleRepository.RemoveRole")()
	res, err := r.db.Exec(`DELETE FROM user_roles WHERE user_id = ? AND role_id = ? AND org_id = ?`, userID, roleID, orgID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *RoleRepository) AssignScope(userID, resource, scope, orgID string) error {
	defer telemetry.Step("repository.RoleRepository.AssignScope")()
	_, err := r.db.Exec(`INSERT INTO user_scopes (user_id, resource_uri, scope, org_id, created_at) VALUES (?, ?, ?, ?, ?)`,
		userID, resource, scope, orgID, time.Now().UTC())
	return err
}

func (r *RoleRepository) RemoveScope(userID, resource, scope, orgID string) error {
	defer telemetry.Step("repository.RoleRepository.RemoveScope")()
	res, err := r.db.Exec(`DELETE FROM user_scopes WHERE user_id = ? AND resource_uri = ? AND scope = ? AND org_id = ?`,
		userID, resource, scope, orgID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *RoleRepository) UserRoles(userID string) ([]models.UserRole, error) {
	defer telemetry.Step("repository.RoleRepository.UserRoles")()
	rows, err := r.db.Query(`SELECT ur.user_id, ur.role_id, roles.name, ur.org_id
		FROM user_roles ur JOIN roles ON roles.id = ur.role_id
		WHERE ur.user_id = ? ORDER BY roles.name, ur.org_id`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []models.UserRole{}
	for rows.Next() {
		var item models.UserRole
		if err := rows.Scan(&item.UserID, &item.RoleID, &item.Name, &item.OrgID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *RoleRepository) UserScopes(userID string) ([]models.UserScope, error) {
	defer telemetry.Step("repository.RoleRepository.UserScopes")()
	rows, err := r.db.Query(`SELECT user_id, resource_uri, scope, org_id FROM user_scopes
		WHERE user_id = ? ORDER BY resource_uri, scope, org_id`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []models.UserScope{}
	for rows.Next() {
		var item models.UserScope
		if err := rows.Scan(&item.UserID, &item.Resource, &item.Scope, &item.OrgID); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (r *RoleRepository) HeldScopes(userID, orgID string) ([]string, error) {
	defer telemetry.Step("repository.RoleRepository.HeldScopes")()
	rows, err := r.db.Query(`SELECT rs.scope FROM role_scopes rs
		JOIN user_roles ur ON ur.role_id = rs.role_id
		WHERE ur.user_id = ? AND (ur.org_id = '' OR ur.org_id = ?)
		UNION
		SELECT scope FROM user_scopes
		WHERE user_id = ? AND (org_id = '' OR org_id = ?)`, userID, orgID, userID, orgID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []string{}
	for rows.Next() {
		var scope string
		if err := rows.Scan(&scope); err != nil {
			return nil, err
		}
		out = append(out, scope)
	}
	return out, rows.Err()
}

func (r *RoleRepository) HasRole(userID, roleID, orgID string) (bool, error) {
	defer telemetry.Step("repository.RoleRepository.HasRole")()
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM user_roles WHERE user_id = ? AND role_id = ? AND org_id = ?`,
		userID, roleID, orgID).Scan(&n)
	return n > 0, err
}

func (r *RoleRepository) HasScope(userID, resource, scope, orgID string) (bool, error) {
	defer telemetry.Step("repository.RoleRepository.HasScope")()
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM user_scopes WHERE user_id = ? AND resource_uri = ? AND scope = ? AND org_id = ?`,
		userID, resource, scope, orgID).Scan(&n)
	return n > 0, err
}
