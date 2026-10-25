package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/atrium/internal/background"
	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/notify"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
)

const (
	EventLogin          = "login"
	EventLoginFailed    = "login_failed"
	EventLogout         = "logout"
	EventSSOSession     = "sso_session_triggered"
	EventBruteforce     = "bruteforce_detected"
	EventForgotPassword = "forgot_password"
	EventChangePassword = "change_password"
	EventPasswordReset  = "password_reset"
	EventUserRegistered = "user_registered"
	EventEmailVerified  = "email_verified"
	EventUserDisabled   = "user_disabled"
	EventWebhookTest    = "webhook.test"
)

var webhookEvents = map[string]struct{}{
	EventLogin:          {},
	EventLoginFailed:    {},
	EventLogout:         {},
	EventSSOSession:     {},
	EventBruteforce:     {},
	EventForgotPassword: {},
	EventChangePassword: {},
	EventPasswordReset:  {},
	EventUserRegistered: {},
	EventEmailVerified:  {},
	EventUserDisabled:   {},
	EventWebhookTest:    {},
	"*":                 {},
}

func KnownWebhookEvents() []string {
	defer telemetry.Step("service.KnownWebhookEvents")()
	return []string{
		EventLogin,
		EventLoginFailed,
		EventLogout,
		EventSSOSession,
		EventBruteforce,
		EventForgotPassword,
		EventChangePassword,
		EventPasswordReset,
		EventUserRegistered,
		EventEmailVerified,
		EventUserDisabled,
	}
}

type WebhookDispatcher struct {
	repo   *repository.WebhookRepository
	http   *http.Client
	fetch  *config.Config
	outbox Outbox
}

func (d *WebhookDispatcher) SetOutbox(box Outbox) {
	defer telemetry.Step("service.WebhookDispatcher.SetOutbox")()
	if d != nil {
		d.outbox = box
	}
}

func (d *WebhookDispatcher) SetFetchConfig(cfg *config.Config) {
	defer telemetry.Step("service.WebhookDispatcher.SetFetchConfig")()
	if d != nil {
		d.fetch = cfg
	}
}

func NewWebhookDispatcher(repo *repository.WebhookRepository) *WebhookDispatcher {
	defer telemetry.Step("service.NewWebhookDispatcher")()
	return &WebhookDispatcher{
		repo: repo,
		http: &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

type WebhookInput struct {
	URL         string
	Secret      string
	Events      []string
	Enabled     *bool
	Description string
}

func (d *WebhookDispatcher) Create(in WebhookInput) (*models.Webhook, error) {
	defer telemetry.Step("service.WebhookDispatcher.Create")()
	if err := d.checkURL(in.URL); err != nil {
		return nil, err
	}
	events, err := normalizeEvents(in.Events)
	if err != nil {
		return nil, err
	}
	secret := strings.TrimSpace(in.Secret)
	if secret == "" {
		secret, err = randomSecret()
		if err != nil {
			return nil, err
		}
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	now := time.Now()
	hook := &models.Webhook{
		ID:          uuid.NewString(),
		URL:         in.URL,
		Secret:      secret,
		Events:      events,
		Enabled:     enabled,
		Description: in.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := d.repo.Create(hook); err != nil {
		return nil, err
	}
	return hook, nil
}

func (d *WebhookDispatcher) Update(id string, in WebhookInput) (*models.Webhook, error) {
	defer telemetry.Step("service.WebhookDispatcher.Update")()
	hook, err := d.repo.Get(id)
	if err != nil {
		return nil, err
	}
	if in.URL != "" {
		if err := d.checkURL(in.URL); err != nil {
			return nil, err
		}
		hook.URL = in.URL
	}
	if in.Events != nil {
		events, err := normalizeEvents(in.Events)
		if err != nil {
			return nil, err
		}
		hook.Events = events
	}
	if strings.TrimSpace(in.Secret) != "" {
		hook.Secret = strings.TrimSpace(in.Secret)
	}
	if in.Enabled != nil {
		hook.Enabled = *in.Enabled
	}
	if in.Description != "" {
		hook.Description = in.Description
	}
	if err := d.repo.Update(hook); err != nil {
		return nil, err
	}
	return hook, nil
}

func (d *WebhookDispatcher) List() ([]*models.Webhook, error) {
	defer telemetry.Step("service.WebhookDispatcher.List")()
	return d.repo.List()
}

func (d *WebhookDispatcher) Get(id string) (*models.Webhook, error) {
	defer telemetry.Step("service.WebhookDispatcher.Get")()
	return d.repo.Get(id)
}

func (d *WebhookDispatcher) Delete(id string) error {
	defer telemetry.Step("service.WebhookDispatcher.Delete")()
	return d.repo.Delete(id)
}

func (d *WebhookDispatcher) Test(id string) error {
	defer telemetry.Step("service.WebhookDispatcher.Test")()
	hook, err := d.repo.Get(id)
	if err != nil {
		return err
	}
	body := payload(EventWebhookTest, map[string]any{"webhook_id": hook.ID})
	return d.post(hook, EventWebhookTest, body)
}

func (d *WebhookDispatcher) Emit(event string, data map[string]any) {
	defer telemetry.Step("service.WebhookDispatcher.Emit")()
	if d == nil || d.repo == nil {
		return
	}
	copied := make(map[string]any, len(data))
	for key, value := range data {
		copied[key] = value
	}
	background.Go(func() {
		defer telemetry.Step("service.WebhookDispatcher.deliver")()
		if d.outbox != nil {
			d.enqueue(event, copied)
			return
		}
		d.deliver(event, copied)
	})
}

func (d *WebhookDispatcher) enqueue(event string, data map[string]any) {
	hooks, err := d.repo.List()
	if err != nil {
		log.Printf("webhooks: list: %v", err)
		return
	}
	body := string(payload(event, data))
	for _, hook := range hooks {
		if hook == nil || !hook.Wants(event) {
			continue
		}
		err := d.outbox.Publish(context.Background(), notify.Job{
			Kind:   notify.KindWebhook,
			HookID: hook.ID,
			Event:  event,
			Body:   body,
		}, 0)
		if err != nil {
			log.Printf("webhook %s %s: %v", hook.ID, event, err)
		}
	}
}

func (d *WebhookDispatcher) deliver(event string, data map[string]any) {
	hooks, err := d.repo.List()
	if err != nil {
		log.Printf("webhooks: list: %v", err)
		return
	}
	body := payload(event, data)
	for _, hook := range hooks {
		if !hook.Wants(event) {
			continue
		}
		if err := d.post(hook, event, body); err != nil {
			log.Printf("webhook %s %s: %v", hook.ID, event, err)
		}
	}
}

func payload(event string, data map[string]any) []byte {
	defer telemetry.Step("service.payload")()
	if data == nil {
		data = map[string]any{}
	}
	raw, err := json.Marshal(map[string]any{
		"id":         uuid.NewString(),
		"event":      event,
		"created_at": time.Now().UTC().Format(time.RFC3339),
		"data":       data,
	})
	if err != nil {
		return []byte(`{"event":"error"}`)
	}
	return raw
}

func (d *WebhookDispatcher) post(hook *models.Webhook, event string, body []byte) error {
	defer telemetry.Step("service.WebhookDispatcher.post")()
	req, err := http.NewRequest(http.MethodPost, hook.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(hook.Secret))
	_, _ = mac.Write([]byte(ts))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "atrium-webhooks")
	req.Header.Set("X-Webhook-Event", event)
	req.Header.Set("X-Webhook-Timestamp", ts)
	req.Header.Set("X-Webhook-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	if d.fetch != nil {
		_, status, err := FetchSafe(req.Context(), d.fetch, http.MethodPost, hook.URL, bytes.NewReader(body), req.Header)
		if err != nil {
			return err
		}
		if status < 200 || status >= 300 {
			return fmt.Errorf("receiver returned %d", status)
		}
		return nil
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("receiver returned %d", resp.StatusCode)
	}
	return nil
}

func (d *WebhookDispatcher) checkURL(raw string) error {
	defer telemetry.Step("service.WebhookDispatcher.checkURL")()
	if d != nil && d.fetch != nil {
		return ValidateFetchTarget(d.fetch, raw)
	}
	return validateWebhookURL(raw)
}

func validateWebhookURL(raw string) error {
	defer telemetry.Step("service.validateWebhookURL")()
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("webhook url must be an absolute http or https URL")
	}
	return nil
}

func normalizeEvents(events []string) ([]string, error) {
	defer telemetry.Step("service.normalizeEvents")()
	if len(events) == 0 {
		return nil, fmt.Errorf("at least one event is required")
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(events))
	for _, event := range events {
		event = strings.TrimSpace(event)
		if _, ok := webhookEvents[event]; !ok {
			return nil, fmt.Errorf("unknown webhook event %q", event)
		}
		if _, ok := seen[event]; ok {
			continue
		}
		seen[event] = struct{}{}
		out = append(out, event)
	}
	return out, nil
}

func randomSecret() (string, error) {
	defer telemetry.Step("service.randomSecret")()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
