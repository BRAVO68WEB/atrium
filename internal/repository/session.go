package repository

import (
	"time"

	"github.com/bravo68web/atrium/internal/database"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
)

type SessionRepository struct {
	db database.SQL
}

func NewSessionRepository(db database.SQL) *SessionRepository {
	defer telemetry.Step("repository.NewSessionRepository")()
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(s *models.BrowserSession) error {
	defer telemetry.Step("repository.SessionRepository.Create")()
	_, err := r.db.Exec(`INSERT INTO sessions (id, user_id, username, auth_time, mfa_verified, user_agent, ip, created_at, expires_at, revoked, migration_password)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.UserID, s.Username, s.AuthTime, boolInt(s.MFAVerified), s.UserAgent, s.IP, s.CreatedAt, s.ExpiresAt, boolInt(s.Revoked), boolInt(s.PasswordPending),
	)
	return err
}

func scanSession(scan func(dest ...any) error) (*models.BrowserSession, error) {
	defer telemetry.Step("repository.scanSession")()
	s := &models.BrowserSession{}
	var mfa, revoked, passwordPending int
	if err := scan(
		&s.ID, &s.UserID, &s.Username, &s.AuthTime, &mfa, &s.UserAgent, &s.IP, &s.CreatedAt, &s.ExpiresAt, &revoked, &passwordPending,
	); err != nil {
		return nil, err
	}
	s.MFAVerified = mfa != 0
	s.Revoked = revoked != 0
	s.PasswordPending = passwordPending != 0
	return s, nil
}

const sessionColumns = `id, user_id, COALESCE(username, ''), auth_time, mfa_verified, COALESCE(user_agent, ''), COALESCE(ip, ''), created_at, expires_at, revoked, COALESCE(migration_password, 0)`

func (r *SessionRepository) Get(id string) (*models.BrowserSession, error) {
	defer telemetry.Step("repository.SessionRepository.Get")()
	return scanSession(r.db.QueryRow(`SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id).Scan)
}

func (r *SessionRepository) MarkMFA(id string) error {
	defer telemetry.Step("repository.SessionRepository.MarkMFA")()
	_, err := r.db.Exec(`UPDATE sessions SET mfa_verified = 1 WHERE id = ?`, id)
	return err
}

func (r *SessionRepository) Revoke(id string) error {
	defer telemetry.Step("repository.SessionRepository.Revoke")()
	_, err := r.db.Exec(`UPDATE sessions SET revoked = 1 WHERE id = ?`, id)
	return err
}

func (r *SessionRepository) ListByUser(userID string) ([]*models.BrowserSession, error) {
	defer telemetry.Step("repository.SessionRepository.ListByUser")()
	rows, err := r.db.Query(`SELECT `+sessionColumns+` FROM sessions WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make([]*models.BrowserSession, 0)
	for rows.Next() {
		s, err := scanSession(rows.Scan)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *SessionRepository) RevokeAllExcept(userID, exceptSID string) ([]string, error) {
	defer telemetry.Step("repository.SessionRepository.RevokeAllExcept")()
	rows, err := r.db.Query(`SELECT id FROM sessions WHERE user_id = ? AND revoked = 0 AND id != ?`, userID, exceptSID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		if _, err := r.db.Exec(`UPDATE sessions SET revoked = 1 WHERE id = ?`, id); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

func (r *SessionRepository) RecordClient(sid, clientID string) error {
	defer telemetry.Step("repository.SessionRepository.RecordClient")()
	if sid == "" || clientID == "" {
		return nil
	}
	_, err := r.db.Exec(`INSERT INTO session_clients (sid, client_id) VALUES (?, ?) ON CONFLICT (sid, client_id) DO NOTHING`, sid, clientID)
	return err
}

func (r *SessionRepository) ListClients(sid string) ([]string, error) {
	defer telemetry.Step("repository.SessionRepository.ListClients")()
	rows, err := r.db.Query(`SELECT client_id FROM session_clients WHERE sid = ?`, sid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (r *SessionRepository) Active(s *models.BrowserSession, now time.Time) bool {
	defer telemetry.Step("repository.SessionRepository.Active")()
	return s != nil && !s.Revoked && now.Before(s.ExpiresAt)
}
