package repository

import (
	"encoding/json"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type CIBARepository struct {
	db database.SQL
}

func NewCIBARepository(db database.SQL) *CIBARepository {
	defer telemetry.Step("repository.NewCIBARepository")()
	return &CIBARepository{db: db}
}

func (r *CIBARepository) Save(req *models.CIBARequest) error {
	defer telemetry.Step("repository.CIBARepository.Save")()
	scopesJSON, err := json.Marshal(req.Scopes)
	if err != nil {
		return err
	}

	query := `INSERT INTO ciba_requests (auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token, scopes)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	var userID any
	if req.UserID != "" {
		userID = req.UserID
	}
	_, err = r.db.Exec(query,
		req.AuthReqID, req.ClientID, userID, req.BindingMessage,
		req.UserCode, req.Status, req.DeliveryMode, req.ExpiresAt,
		req.Interval, req.ClientNotificationToken, string(scopesJSON),
	)
	return err
}

func (r *CIBARepository) GetByID(authReqID string) (*models.CIBARequest, error) {
	defer telemetry.Step("repository.CIBARepository.GetByID")()
	query := `SELECT auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token, scopes
		FROM ciba_requests WHERE auth_req_id = ?`

	req := &models.CIBARequest{}
	var scopesStr string
	err := r.db.QueryRow(query, authReqID).Scan(
		&req.AuthReqID, &req.ClientID, &req.UserID, &req.BindingMessage,
		&req.UserCode, &req.Status, &req.DeliveryMode, &req.ExpiresAt,
		&req.Interval, &req.ClientNotificationToken, &scopesStr,
	)
	if err != nil {
		return nil, err
	}

	if scopesStr != "" {
		if err := json.Unmarshal([]byte(scopesStr), &req.Scopes); err != nil {
			req.Scopes = []string{}
		}
	}

	return req, nil
}

func (r *CIBARepository) UpdateStatus(authReqID, status string) error {
	defer telemetry.Step("repository.CIBARepository.UpdateStatus")()
	_, err := r.db.Exec("UPDATE ciba_requests SET status = ? WHERE auth_req_id = ?", status, authReqID)
	return err
}

func (r *CIBARepository) GetPending() ([]*models.CIBARequest, error) {
	defer telemetry.Step("repository.CIBARepository.GetPending")()
	query := `SELECT auth_req_id, client_id, user_id, binding_message, user_code,
		status, delivery_mode, expires_at, interval, client_notification_token, scopes
		FROM ciba_requests WHERE status = 'pending' AND expires_at > ?
		ORDER BY expires_at DESC`

	rows, err := r.db.Query(query, time.Now())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	requests := make([]*models.CIBARequest, 0)
	for rows.Next() {
		req := &models.CIBARequest{}
		var scopesStr string
		err := rows.Scan(
			&req.AuthReqID, &req.ClientID, &req.UserID, &req.BindingMessage,
			&req.UserCode, &req.Status, &req.DeliveryMode, &req.ExpiresAt,
			&req.Interval, &req.ClientNotificationToken, &scopesStr,
		)
		if err != nil {
			return nil, err
		}

		if scopesStr != "" {
			if err := json.Unmarshal([]byte(scopesStr), &req.Scopes); err != nil {
				req.Scopes = []string{}
			}
		}

		requests = append(requests, req)
	}
	return requests, nil
}
