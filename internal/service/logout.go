package service

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/oidc"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
)

type LogoutService struct {
	sessions *SessionService
	clients  *repository.ClientRepository
	oidc     *oidc.Handler
	hooks    *WebhookDispatcher
	http     *http.Client
	fetch    *config.Config
}

func (s *LogoutService) SetFetchConfig(cfg *config.Config) {
	defer telemetry.Step("service.LogoutService.SetFetchConfig")()
	if s != nil {
		s.fetch = cfg
	}
}

func (s *LogoutService) SetWebhooks(d *WebhookDispatcher) {
	defer telemetry.Step("service.LogoutService.SetWebhooks")()
	if s != nil {
		s.hooks = d
	}
}

func NewLogoutService(sessions *SessionService, clients *repository.ClientRepository, oidcHandler *oidc.Handler) *LogoutService {
	defer telemetry.Step("service.NewLogoutService")()
	return &LogoutService{
		sessions: sessions,
		clients:  clients,
		oidc:     oidcHandler,
		http: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (s *LogoutService) End(sid string) {
	defer telemetry.Step("service.LogoutService.End")()
	if s == nil || sid == "" {
		return
	}
	sub := ""
	username := ""
	if sess, err := s.sessions.GetAny(sid); err == nil && sess != nil {
		sub = sess.UserID
		username = sess.Username
	}
	_ = s.sessions.Revoke(sid)
	s.Notify(sid, sub)
	if s.hooks != nil {
		s.hooks.Emit(EventLogout, map[string]any{
			"user_id": sub, "username": username, "session_id": sid,
		})
	}
}

func (s *LogoutService) Notify(sid, sub string) {
	defer telemetry.Step("service.LogoutService.Notify")()
	if s == nil || s.oidc == nil || sid == "" {
		return
	}
	clientIDs, err := s.sessions.Clients(sid)
	if err != nil {
		log.Printf("back-channel logout: list clients for %s: %v", sid, err)
		return
	}
	for _, clientID := range clientIDs {
		client, err := s.clients.GetByID(clientID)
		if err != nil || client.BackchannelLogoutURI == "" {
			continue
		}
		subject := sub
		if computed, err := s.oidc.Subject(context.Background(), client, sub); err == nil && computed != "" {
			subject = computed
		}
		tok, err := s.oidc.CreateLogoutToken(client.ID, subject, sid)
		if err != nil {
			log.Printf("back-channel logout: sign token for %s: %v", client.ID, err)
			continue
		}
		body := url.Values{}
		body.Set("logout_token", tok)
		req, err := http.NewRequest(http.MethodPost, client.BackchannelLogoutURI, strings.NewReader(body.Encode()))
		if err != nil {
			log.Printf("back-channel logout: build request for %s: %v", client.ID, err)
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if s.fetch != nil {
			_, status, err := FetchSafe(req.Context(), s.fetch, http.MethodPost, client.BackchannelLogoutURI, strings.NewReader(body.Encode()), req.Header)
			if err != nil {
				log.Printf("back-channel logout: post to %s: %v", client.BackchannelLogoutURI, err)
				continue
			}
			if status < 200 || status >= 300 {
				log.Printf("back-channel logout: %s returned %d", client.BackchannelLogoutURI, status)
			}
			continue
		}
		resp, err := s.http.Do(req)
		if err != nil {
			log.Printf("back-channel logout: post to %s: %v", client.BackchannelLogoutURI, err)
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			log.Printf("back-channel logout: %s returned %d", client.BackchannelLogoutURI, resp.StatusCode)
		}
	}
}
