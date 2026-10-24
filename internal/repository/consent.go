package repository

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/google/uuid"
)

type ConsentRepository struct {
	db database.SQL
}

func NewConsentRepository(db database.SQL) *ConsentRepository {
	defer telemetry.Step("repository.NewConsentRepository")()
	return &ConsentRepository{db: db}
}

func (r *ConsentRepository) Save(userID, clientID string, scopes []string) error {
	defer telemetry.Step("repository.ConsentRepository.Save")()
	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return err
	}

	id := uuid.New().String()
	query := `INSERT INTO consents (id, user_id, client_id, scopes, granted_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = excluded.scopes, granted_at = excluded.granted_at`

	_, err = r.db.Exec(query, id, userID, clientID, string(scopesJSON), time.Now())
	return err
}

func (r *ConsentRepository) Get(userID, clientID string) (*models.Consent, error) {
	defer telemetry.Step("repository.ConsentRepository.Get")()
	query := `SELECT id, user_id, client_id, scopes, granted_at, expires_at
		FROM consents WHERE user_id = ? AND client_id = ?`

	consent := &models.Consent{}
	var scopesStr string
	var expiresAt sql.NullTime

	err := r.db.QueryRow(query, userID, clientID).Scan(
		&consent.ID, &consent.UserID, &consent.ClientID,
		&scopesStr, &consent.GrantedAt, &expiresAt,
	)
	if err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		consent.ExpiresAt = &expiresAt.Time
	}

	if err := json.Unmarshal([]byte(scopesStr), &consent.Scopes); err != nil {
		consent.Scopes = []string{}
	}

	return consent, nil
}

func (r *ConsentRepository) Delete(userID, clientID string) error {
	defer telemetry.Step("repository.ConsentRepository.Delete")()
	_, err := r.db.Exec("DELETE FROM consents WHERE user_id = ? AND client_id = ?", userID, clientID)
	return err
}

func (r *ConsentRepository) ListByUser(userID string) ([]*models.Consent, error) {
	defer telemetry.Step("repository.ConsentRepository.ListByUser")()
	query := `SELECT id, user_id, client_id, scopes, granted_at, expires_at
		FROM consents WHERE user_id = ? ORDER BY granted_at DESC`

	rows, err := r.db.Query(query, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	consents := make([]*models.Consent, 0)
	for rows.Next() {
		consent := &models.Consent{}
		var scopesStr string
		var expiresAt sql.NullTime

		err := rows.Scan(
			&consent.ID, &consent.UserID, &consent.ClientID,
			&scopesStr, &consent.GrantedAt, &expiresAt,
		)
		if err != nil {
			return nil, err
		}

		if expiresAt.Valid {
			consent.ExpiresAt = &expiresAt.Time
		}

		if err := json.Unmarshal([]byte(scopesStr), &consent.Scopes); err != nil {
			consent.Scopes = []string{}
		}

		consents = append(consents, consent)
	}
	return consents, nil
}
