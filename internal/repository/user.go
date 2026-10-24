package repository

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

const userColumns = `id, username, password_hash, COALESCE(email, ''), COALESCE(phone_number, ''), created_at,
	last_login_at, COALESCE(email_verified, 0), COALESCE(disabled, 0), COALESCE(given_name, ''), COALESCE(family_name, ''), COALESCE(attributes, '{}')`

func decodeAttributes(raw string) map[string]string {
	defer telemetry.Step("repository.decodeAttributes")()
	out := map[string]string{}
	if raw == "" || raw == "{}" {
		return out
	}
	_ = json.Unmarshal([]byte(raw), &out)
	if out == nil {
		return map[string]string{}
	}
	return out
}

func (r *UserRepository) SetAttributes(id string, attrs map[string]string) error {
	defer telemetry.Step("repository.UserRepository.SetAttributes")()
	if attrs == nil {
		attrs = map[string]string{}
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(`UPDATE users SET attributes = ? WHERE id = ?`, string(raw), id)
	return err
}

func scanUser(scan func(dest ...any) error) (*models.User, error) {
	defer telemetry.Step("repository.scanUser")()
	user := &models.User{}
	var lastLogin sql.NullTime
	var emailVerified, disabled int
	var attrs string
	if err := scan(
		&user.ID, &user.Username, &user.PasswordHash,
		&user.Email, &user.PhoneNumber, &user.CreatedAt,
		&lastLogin, &emailVerified, &disabled, &user.GivenName, &user.FamilyName, &attrs,
	); err != nil {
		return nil, err
	}
	user.Attributes = decodeAttributes(attrs)
	if lastLogin.Valid {
		t := lastLogin.Time
		user.LastLoginAt = &t
	}
	user.EmailVerified = emailVerified != 0
	user.Disabled = disabled != 0
	return user, nil
}

type UserRepository struct {
	db database.SQL
}

func NewUserRepository(db database.SQL) *UserRepository {
	defer telemetry.Step("repository.NewUserRepository")()
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(user *models.User) error {
	defer telemetry.Step("repository.UserRepository.Create")()
	rawAttrs, _ := json.Marshal(user.Attributes)
	if user.Attributes == nil {
		rawAttrs = []byte("{}")
	}
	query := `INSERT INTO users (id, username, password_hash, email, phone_number, created_at,
		email_verified, disabled, given_name, family_name, attributes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		user.ID, user.Username, user.PasswordHash,
		user.Email, user.PhoneNumber, user.CreatedAt,
		boolInt(user.EmailVerified), boolInt(user.Disabled), user.GivenName, user.FamilyName, string(rawAttrs),
	)
	return err
}

func (r *UserRepository) GetByID(id string) (*models.User, error) {
	defer telemetry.Step("repository.UserRepository.GetByID")()
	return scanUser(r.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE id = ?`, id).Scan)
}

func (r *UserRepository) GetByUsername(username string) (*models.User, error) {
	defer telemetry.Step("repository.UserRepository.GetByUsername")()
	return scanUser(r.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE username = ?`, username).Scan)
}

func (r *UserRepository) GetByEmail(email string) (*models.User, error) {
	defer telemetry.Step("repository.UserRepository.GetByEmail")()
	return scanUser(r.db.QueryRow(`SELECT `+userColumns+` FROM users WHERE lower(email) = lower(?)`, email).Scan)
}

func (r *UserRepository) List() ([]*models.User, error) {
	defer telemetry.Step("repository.UserRepository.List")()
	rows, err := r.db.Query(`SELECT ` + userColumns + ` FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	users := make([]*models.User, 0)
	for rows.Next() {
		user, err := scanUser(rows.Scan)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (r *UserRepository) UpdateProfile(user *models.User) error {
	defer telemetry.Step("repository.UserRepository.UpdateProfile")()
	res, err := r.db.Exec(`UPDATE users SET email = ?, phone_number = ?, given_name = ?, family_name = ?,
		email_verified = ?, disabled = ? WHERE id = ?`,
		user.Email, user.PhoneNumber, user.GivenName, user.FamilyName,
		boolInt(user.EmailVerified), boolInt(user.Disabled), user.ID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (r *UserRepository) TouchLastLogin(id string, at time.Time) error {
	defer telemetry.Step("repository.UserRepository.TouchLastLogin")()
	_, err := r.db.Exec(`UPDATE users SET last_login_at = ? WHERE id = ?`, at, id)
	return err
}

func (r *UserRepository) UpdatePasswordHash(id, hash string) error {
	defer telemetry.Step("repository.UserRepository.UpdatePasswordHash")()
	res, err := r.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (r *UserRepository) UpdateMFA(id string, mfaEnabled bool, mfaSecret string) error {
	defer telemetry.Step("repository.UserRepository.UpdateMFA")()
	query := `UPDATE users SET mfa_enabled = ?, mfa_secret = ?, mfa_pending_secret = NULL WHERE id = ?`
	_, err := r.db.Exec(query, boolInt(mfaEnabled), mfaSecret, id)
	return err
}

func (r *UserRepository) GetMFA(id string) (bool, string, error) {
	defer telemetry.Step("repository.UserRepository.GetMFA")()
	query := `SELECT mfa_enabled, COALESCE(mfa_secret, '') FROM users WHERE id = ?`
	var mfaEnabled bit
	var mfaSecret string
	err := r.db.QueryRow(query, id).Scan(&mfaEnabled, &mfaSecret)
	return mfaEnabled.Bool(), mfaSecret, err
}

func (r *UserRepository) SavePendingSecret(id string, secret string) error {
	defer telemetry.Step("repository.UserRepository.SavePendingSecret")()
	query := `UPDATE users SET mfa_pending_secret = ? WHERE id = ?`
	_, err := r.db.Exec(query, secret, id)
	return err
}

func (r *UserRepository) GetPendingSecret(id string) (string, error) {
	defer telemetry.Step("repository.UserRepository.GetPendingSecret")()
	query := `SELECT COALESCE(mfa_pending_secret, '') FROM users WHERE id = ?`
	var secret string
	err := r.db.QueryRow(query, id).Scan(&secret)
	if err != nil {
		return "", err
	}
	if secret == "" {
		return "", fmt.Errorf("no pending MFA secret found")
	}
	return secret, nil
}

func (r *UserRepository) ClearPendingSecret(id string) error {
	defer telemetry.Step("repository.UserRepository.ClearPendingSecret")()
	query := `UPDATE users SET mfa_pending_secret = NULL WHERE id = ?`
	_, err := r.db.Exec(query, id)
	return err
}
