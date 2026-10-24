package push

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/service"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
	"github.com/go-jose/go-jose/v4"
)

// notify posts an opaque wake. A failure is ignored so the caller still succeeds.
func (s *Service) notify(deviceID, reason, ref string) {
	defer telemetry.Step("push.Service.notify")()
	if s == nil || s.cfg == nil || (!s.cfg.Push.PingEnabled && !s.cfg.Push.PushEnabled) {
		return
	}
	var address string
	if err := s.db.QueryRow(`SELECT COALESCE(push_address, '') FROM push_devices WHERE id = ?`, deviceID).Scan(&address); err != nil {
		return
	}
	s.deliver(strings.TrimSpace(address), reason, ref)
}

func (s *Service) deliver(address, reason, ref string) {
	defer telemetry.Step("push.Service.deliver")()
	opaque := map[string]string{"wake_reason": reason, "ref_id": ref}
	if s.cfg.Push.PushEnabled {
		relay := strings.TrimSpace(s.cfg.Push.RelayEndpoint)
		if relay != "" {
			routed := map[string]string{
				"wake_reason":  reason,
				"ref_id":       ref,
				"push_address": address,
			}
			if postWake(s.cfg, relay, routed) {
				return
			}
		} else if address != "" && postWake(s.cfg, address, opaque) {
			return
		}
	}
	if s.cfg.Push.PingEnabled && address != "" {
		postWake(s.cfg, address, opaque)
	}
}

func postWake(cfg *config.Config, target string, body map[string]string) bool {
	defer telemetry.Step("push.postWake")()
	payload, err := json.Marshal(body)
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	_, status, err := service.FetchSafe(ctx, cfg, http.MethodPost, target, bytes.NewReader(payload), header)
	return err == nil && status >= 200 && status < 300
}

// SealPending encrypts the pending JSON to the device's current P-256 key.
func (s *Service) SealPending(deviceID string, payload []byte) (string, error) {
	defer telemetry.Step("push.Service.SealPending")()
	var text string
	if err := s.db.QueryRow(`SELECT jwk FROM push_devices WHERE id = ?`, deviceID).Scan(&text); err != nil {
		return "", err
	}
	pub, err := publicFromJWKText(text)
	if err != nil {
		return "", err
	}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES_A256KW, Key: pub}, nil)
	if err != nil {
		return "", err
	}
	object, err := encrypter.Encrypt(payload)
	if err != nil {
		return "", err
	}
	return object.CompactSerialize()
}

func (s *Service) noteDelivery(deviceID, authReqID, mode string) {
	defer telemetry.Step("push.Service.noteDelivery")()
	if mode != "push" && mode != "poll" {
		return
	}
	_, _ = s.db.Exec(`UPDATE push_auth_requests SET delivery_mode = ? WHERE auth_req_id = ? AND device_id = ?`, mode, authReqID, deviceID)
	if mode == "poll" && s.cfg != nil && s.cfg.Push.PushEnabled {
		log.Printf("push delivery fell back to poll for device %s request %s", deviceID, authReqID)
	}
}

func deliveryModes(cfg *config.Config) []string {
	defer telemetry.Step("push.deliveryModes")()
	var modes []string
	if cfg != nil && cfg.Push.PushEnabled {
		modes = append(modes, "push")
	}
	if cfg != nil && cfg.Push.PingEnabled {
		modes = append(modes, "ping")
	}
	return append(modes, "poll")
}
