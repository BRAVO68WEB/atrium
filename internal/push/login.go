package push

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
)

// ErrDeviceRevoked means the user has no active authenticator left.
var ErrDeviceRevoked = errors.New("device revoked")

// ErrWeakInteraction means the request asked for a ceremony below the floor.
var ErrWeakInteraction = errors.New("interaction type is below the floor")

// LoginNotice is a pending sign-in the device owner can approve.
type LoginNotice struct {
	AuthReqID       string
	BindingMessage  string
	InteractionType string
}

// PrepareLogin binds a CIBA request to the user's latest active device.
// No registered device returns empty strings and a nil error, so CIBA
// without an authenticator stays on its existing path.
func (s *Service) PrepareLogin(userID, authReqID, interaction, binding string) (string, string, error) {
	var deviceID string
	err := s.db.QueryRow(`SELECT id FROM push_devices WHERE user_id = ? AND status = 'active' ORDER BY COALESCE(last_used_at, created_at) DESC LIMIT 1`, userID).Scan(&deviceID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", "", err
		}
		var revoked int
		if scanErr := s.db.QueryRow(`SELECT COUNT(*) FROM push_devices WHERE user_id = ? AND status = 'revoked'`, userID).Scan(&revoked); scanErr != nil {
			return "", "", scanErr
		}
		if revoked > 0 {
			return "", "", ErrDeviceRevoked
		}
		return "", "", nil
	}
	if interaction == "" {
		interaction = s.cfg.Push.MinimumInteractionType
	}
	if ceremonyRank(interaction) < ceremonyRank(s.cfg.Push.MinimumInteractionType) {
		return "", "", ErrWeakInteraction
	}
	if interaction == "number_choose" && binding == "" {
		n, err := rand.Int(rand.Reader, big.NewInt(90))
		if err != nil {
			return "", "", err
		}
		binding = fmt.Sprintf("%02d", n.Int64()+10)
	}
	if interaction == "input_manual" && binding == "" {
		buf := make([]byte, 4)
		if _, err := rand.Read(buf); err != nil {
			return "", "", err
		}
		binding = fmt.Sprintf("%x", buf)
	}
	if _, err := s.db.Exec(`INSERT INTO push_auth_requests (auth_req_id, device_id, user_id, interaction_type, binding_message, status) VALUES (?, ?, ?, ?, ?, 'pending')`,
		authReqID, deviceID, userID, interaction, binding); err != nil {
		return "", "", err
	}
	_, _ = s.db.Exec(`UPDATE push_devices SET last_used_at = ? WHERE id = ?`, s.now().UTC().Format("2006-01-02T15:04:05Z"), deviceID)
	return interaction, binding, nil
}

// DeviceRevoked reports a pending sign-in whose authenticator was revoked.
func (s *Service) DeviceRevoked(authReqID string) bool {
	var status string
	err := s.db.QueryRow(`SELECT status FROM push_auth_requests WHERE auth_req_id = ?`, authReqID).Scan(&status)
	return err == nil && status == "revoked"
}

// PendingLogins lists sign-in requests waiting on this user's device.
func (s *Service) PendingLogins(userID string) ([]LoginNotice, error) {
	rows, err := s.db.Query(`SELECT auth_req_id, COALESCE(binding_message, ''), interaction_type FROM push_auth_requests WHERE user_id = ? AND status = 'pending' ORDER BY auth_req_id`, userID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []LoginNotice
	for rows.Next() {
		var item LoginNotice
		if err := rows.Scan(&item.AuthReqID, &item.BindingMessage, &item.InteractionType); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	if out == nil {
		out = []LoginNotice{}
	}
	return out, rows.Err()
}

// FinishLogin marks the pending sign-in approved or denied for this user.
func (s *Service) FinishLogin(userID, authReqID, status string) error {
	res, err := s.db.Exec(`UPDATE push_auth_requests SET status = ? WHERE auth_req_id = ? AND user_id = ? AND status = 'pending'`, status, authReqID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return problem(400, "invalid_request", "sign-in request is not pending")
	}
	return nil
}

func (s *Service) cascadeRevoke(deviceID string) {
	_, _ = s.db.Exec(`UPDATE push_auth_requests SET status = 'revoked' WHERE device_id = ? AND status = 'pending'`, deviceID)
}

func ceremonyRank(value string) int {
	switch value {
	case "boolean":
		return 1
	case "number_choose", "input_manual":
		return 2
	default:
		return 0
	}
}
