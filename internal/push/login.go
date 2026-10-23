package push

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
)

// ErrDeviceRevoked means the user has no active authenticator left.
var ErrDeviceRevoked = errors.New("device revoked")

// ErrWeakInteraction means the request asked for a ceremony below the floor.
var ErrWeakInteraction = errors.New("interaction type is below the floor")

// ErrCeremonyUnsupported means the active device did not register this ceremony.
var ErrCeremonyUnsupported = errors.New("device does not support the interaction type")

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
	var deviceID, typesText string
	err := s.db.QueryRow(`SELECT id, COALESCE(interaction_types, '[]') FROM push_devices WHERE user_id = ? AND status = 'active' ORDER BY COALESCE(last_used_at, created_at) DESC LIMIT 1`, userID).Scan(&deviceID, &typesText)
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
	var types []string
	_ = json.Unmarshal([]byte(typesText), &types)
	if !contains(types, interaction) {
		return "", "", ErrCeremonyUnsupported
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

// NumberChoices returns three two-digit values. One of them is answer.
func NumberChoices(answer string) []string {
	seen := map[string]bool{answer: true}
	out := []string{answer}
	for len(out) < 3 {
		n, err := rand.Int(rand.Reader, big.NewInt(90))
		if err != nil {
			break
		}
		candidate := fmt.Sprintf("%02d", n.Int64()+10)
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
	}
	for i := len(out) - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			break
		}
		j := int(jBig.Int64())
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// FinishLogin marks the pending sign-in approved or denied for this user.
// proof must match the stored check for number_choose and input_manual.
func (s *Service) FinishLogin(userID, authReqID, status, proof string) error {
	if status == "approved" {
		var interaction, binding string
		err := s.db.QueryRow(`SELECT interaction_type, COALESCE(binding_message, '') FROM push_auth_requests WHERE auth_req_id = ? AND user_id = ? AND status = 'pending'`, authReqID, userID).Scan(&interaction, &binding)
		if err != nil {
			return problem(400, "invalid_request", "sign-in request is not pending")
		}
		if (interaction == "number_choose" || interaction == "input_manual") && proof != binding {
			return problem(400, "invalid_request", "confirmation does not match")
		}
	}
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

// ListPending returns this device's waiting sign-ins. The caller has already authenticated.
func (s *Service) ListPending(deviceID string) ([]LoginNotice, error) {
	rows, err := s.db.Query(`SELECT auth_req_id, COALESCE(binding_message, ''), interaction_type FROM push_auth_requests WHERE device_id = ? AND status = 'pending' ORDER BY auth_req_id`, deviceID)
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

// PollPending authenticates the device and lists its pending sign-ins.
func (s *Service) PollPending(r *http.Request, deviceID, credential string) ([]LoginNotice, string, error) {
	row, err := s.authenticate(r, deviceID, credential)
	if err != nil {
		return nil, "", err
	}
	list, err := s.ListPending(row.id)
	if err != nil {
		return nil, "", err
	}
	return list, s.issueNonce(row.id), nil
}

// PollDecide authenticates the device and records its decision.
func (s *Service) PollDecide(r *http.Request, deviceID, credential, authReqID, action, proof string) (string, string, error) {
	row, err := s.authenticate(r, deviceID, credential)
	if err != nil {
		return "", "", err
	}
	status := "denied"
	if action != "deny" {
		status = "approved"
	}
	if err := s.FinishLogin(row.userID, authReqID, status, proof); err != nil {
		return "", s.issueNonce(row.id), err
	}
	return row.userID, s.issueNonce(row.id), nil
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
