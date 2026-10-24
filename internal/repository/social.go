package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type SocialLogin struct {
	State     string
	Provider  string
	Verifier  string
	Nonce     string
	Params    map[string]string
	ExpiresAt time.Time
	Used      bool
}

type SocialRepository struct {
	db database.SQL
}

func NewSocialRepository(db database.SQL) *SocialRepository {
	defer telemetry.Step("repository.NewSocialRepository")()
	return &SocialRepository{db: db}
}

func (r *SocialRepository) SaveLogin(row SocialLogin) error {
	defer telemetry.Step("repository.SocialRepository.SaveLogin")()
	raw, err := json.Marshal(row.Params)
	if err != nil {
		return err
	}
	_, err = r.db.Exec(`INSERT INTO social_logins (state, provider, verifier, nonce, params_json, expires_at, used)
		VALUES (?, ?, ?, ?, ?, ?, 0)`,
		row.State, row.Provider, row.Verifier, row.Nonce, string(raw), row.ExpiresAt.UTC().Format(time.RFC3339))
	return err
}

// Consume marks a login row used and returns it. A missing, used, or other-provider state returns sql.ErrNoRows.
func (r *SocialRepository) Consume(state, provider string) (SocialLogin, error) {
	defer telemetry.Step("repository.SocialRepository.Consume")()
	res, err := r.db.Exec(`UPDATE social_logins SET used = 1 WHERE state = ? AND provider = ? AND used = 0`, state, provider)
	if err != nil {
		return SocialLogin{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return SocialLogin{}, err
	}
	if n == 0 {
		return SocialLogin{}, sql.ErrNoRows
	}
	var raw string
	var exp dbTime
	var used bit
	row := SocialLogin{Params: map[string]string{}}
	err = r.db.QueryRow(`SELECT state, provider, verifier, nonce, params_json, expires_at, used FROM social_logins WHERE state = ?`, state).
		Scan(&row.State, &row.Provider, &row.Verifier, &row.Nonce, &raw, &exp, &used)
	if err != nil {
		return SocialLogin{}, err
	}
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &row.Params); err != nil {
			return SocialLogin{}, err
		}
	}
	row.ExpiresAt = exp.Time
	row.Used = used.Bool()
	return row, nil
}

func (r *SocialRepository) FindIdentity(provider, subject string) (string, error) {
	defer telemetry.Step("repository.SocialRepository.FindIdentity")()
	var userID string
	err := r.db.QueryRow(`SELECT user_id FROM social_identities WHERE provider = ? AND subject = ?`, provider, subject).Scan(&userID)
	return userID, err
}

func (r *SocialRepository) InsertIdentity(provider, subject, userID, email string, created time.Time) error {
	defer telemetry.Step("repository.SocialRepository.InsertIdentity")()
	_, err := r.db.Exec(`INSERT INTO social_identities (provider, subject, user_id, email, created_at) VALUES (?, ?, ?, ?, ?)`,
		provider, subject, userID, email, created.UTC().Format(time.RFC3339))
	return err
}

func IsNotFound(err error) bool {
	defer telemetry.Step("repository.IsNotFound")()
	return errors.Is(err, sql.ErrNoRows)
}
