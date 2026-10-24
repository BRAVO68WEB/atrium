package repository

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"

	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type DeviceCodeRepository struct {
	db database.SQL
}

func NewDeviceCodeRepository(db database.SQL) *DeviceCodeRepository {
	defer telemetry.Step("repository.NewDeviceCodeRepository")()
	return &DeviceCodeRepository{db: db}
}

func (r *DeviceCodeRepository) Save(dc *models.DeviceCode) error {
	defer telemetry.Step("repository.DeviceCodeRepository.Save")()
	scopes, _ := json.Marshal(dc.Scopes)
	query := `INSERT INTO device_codes (device_code, user_code, client_id, scopes, status, expires_at, interval, user_id, session_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		dc.DeviceCode, dc.UserCode, dc.ClientID,
		string(scopes), dc.Status, dc.ExpiresAt, dc.Interval,
		dc.UserID, dc.SessionID,
	)
	return err
}

func scanDevice(scan func(dest ...any) error) (*models.DeviceCode, error) {
	defer telemetry.Step("repository.scanDevice")()
	dc := &models.DeviceCode{}
	var scopes string
	var userID, sessionID sql.NullString
	var authTime sql.NullTime
	if err := scan(
		&dc.DeviceCode, &dc.UserCode, &dc.ClientID,
		&scopes, &dc.Status, &dc.ExpiresAt, &dc.Interval,
		&userID, &sessionID, &authTime,
	); err != nil {
		return nil, err
	}
	dc.UserID = userID.String
	dc.SessionID = sessionID.String
	if authTime.Valid {
		dc.AuthTime = authTime.Time
	}
	if err := json.Unmarshal([]byte(scopes), &dc.Scopes); err != nil {
		return nil, err
	}
	return dc, nil
}

const deviceColumns = `device_code, user_code, client_id, scopes, status, expires_at, interval, user_id, session_id, auth_time`

func (r *DeviceCodeRepository) GetByDeviceCode(deviceCode string) (*models.DeviceCode, error) {
	defer telemetry.Step("repository.DeviceCodeRepository.GetByDeviceCode")()
	return scanDevice(r.db.QueryRow(`SELECT `+deviceColumns+` FROM device_codes WHERE device_code = ?`, deviceCode).Scan)
}

func (r *DeviceCodeRepository) GetByUserCode(userCode string) (*models.DeviceCode, error) {
	defer telemetry.Step("repository.DeviceCodeRepository.GetByUserCode")()
	return scanDevice(r.db.QueryRow(`SELECT `+deviceColumns+` FROM device_codes WHERE user_code = ?`, userCode).Scan)
}

func (r *DeviceCodeRepository) UpdateStatus(deviceCode, status string) error {
	defer telemetry.Step("repository.DeviceCodeRepository.UpdateStatus")()
	_, err := r.db.Exec("UPDATE device_codes SET status = ? WHERE device_code = ?", status, deviceCode)
	return err
}

func (r *DeviceCodeRepository) Approve(deviceCode, userID, sessionID string, authTime time.Time) error {
	defer telemetry.Step("repository.DeviceCodeRepository.Approve")()
	var at any
	if !authTime.IsZero() {
		at = authTime
	}
	_, err := r.db.Exec(`UPDATE device_codes SET status = 'approved', user_id = ?, session_id = ?, auth_time = ? WHERE device_code = ?`,
		userID, sessionID, at, deviceCode)
	return err
}
