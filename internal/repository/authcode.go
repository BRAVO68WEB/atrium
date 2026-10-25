package repository

import (
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
)

// ErrCodeUsed is returned when an authorization code was already consumed.
var ErrCodeUsed = errors.New("authorization code already used")

type AuthCodeRepository struct {
	db database.SQL
}

func NewAuthCodeRepository(db database.SQL) *AuthCodeRepository {
	defer telemetry.Step("repository.NewAuthCodeRepository")()
	return &AuthCodeRepository{db: db}
}

func (r *AuthCodeRepository) Save(code *models.AuthorizationCode) error {
	defer telemetry.Step("repository.AuthCodeRepository.Save")()
	scopes, _ := json.Marshal(code.Scopes)
	query := `INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, resource, nonce,
		code_challenge, code_challenge_method, family_id, session_id, auth_time, expires_at, used, org_id, requested_actor)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var authTime any
	if !code.AuthTime.IsZero() {
		authTime = code.AuthTime
	}
	_, err := r.db.Exec(query,
		code.Code, code.ClientID, code.UserID, code.RedirectURI,
		string(scopes), code.Resource, code.Nonce,
		code.CodeChallenge, code.CodeChallengeMethod,
		code.FamilyID, code.SessionID, authTime,
		code.ExpiresAt, boolInt(code.Used), code.OrgID, code.RequestedActor,
	)
	return err
}

func (r *AuthCodeRepository) Get(code string) (*models.AuthorizationCode, error) {
	defer telemetry.Step("repository.AuthCodeRepository.Get")()
	query := `SELECT code, client_id, user_id, redirect_uri, scopes, resource, nonce,
		code_challenge, code_challenge_method, COALESCE(family_id, ''), COALESCE(session_id, ''), auth_time, expires_at, used, COALESCE(org_id, ''), COALESCE(requested_actor, '')
		FROM authorization_codes WHERE code = ?`

	ac := &models.AuthorizationCode{}
	var scopes string
	var resource, nonce sql.NullString
	var authTime sql.NullTime
	var used bit

	err := r.db.QueryRow(query, code).Scan(
		&ac.Code, &ac.ClientID, &ac.UserID, &ac.RedirectURI,
		&scopes, &resource, &nonce,
		&ac.CodeChallenge, &ac.CodeChallengeMethod,
		&ac.FamilyID, &ac.SessionID, &authTime,
		&ac.ExpiresAt, &used, &ac.OrgID, &ac.RequestedActor,
	)
	if err != nil {
		return nil, err
	}

	if resource.Valid {
		ac.Resource = resource.String
	}
	if nonce.Valid {
		ac.Nonce = nonce.String
	}
	if authTime.Valid {
		ac.AuthTime = authTime.Time
	}
	ac.Used = used.Bool()

	if err := json.Unmarshal([]byte(scopes), &ac.Scopes); err != nil {
		return nil, err
	}
	return ac, nil
}

func (r *AuthCodeRepository) MarkUsed(code string) error {
	defer telemetry.Step("repository.AuthCodeRepository.MarkUsed")()
	res, err := r.db.Exec("UPDATE authorization_codes SET used = 1 WHERE code = ? AND used = 0", code)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrCodeUsed
	}
	return nil
}
