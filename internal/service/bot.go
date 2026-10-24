package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

const (
	recaptchaSiteverify = "https://www.google.com/recaptcha/api/siteverify"
	turnstileSiteverify = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
)

// BotPoster replaces the siteverify call in tests.
var BotPoster func(ctx context.Context, provider, secret, token, remoteIP string) error

// VerifyBot checks a bot_token. An empty provider skips the check.
// A configured provider with a missing or rejected token fails closed.
func VerifyBot(ctx context.Context, bot config.BotProtectionConfig, token, remoteIP string) error {
	defer telemetry.Step("service.VerifyBot")()
	if bot.Provider == "" {
		return nil
	}
	if bot.SiteKey == "" || bot.SecretKey == "" || token == "" {
		return fmt.Errorf("bot verification failed")
	}
	if BotPoster != nil {
		return BotPoster(ctx, bot.Provider, bot.SecretKey, token, remoteIP)
	}
	endpoint := recaptchaSiteverify
	if bot.Provider == "turnstile" {
		endpoint = turnstileSiteverify
	}
	form := url.Values{}
	form.Set("secret", bot.SecretKey)
	form.Set("response", token)
	if host, _, ok := strings.Cut(remoteIP, ":"); ok && host != "" {
		form.Set("remoteip", host)
	}
	header := http.Header{}
	header.Set("Content-Type", "application/x-www-form-urlencoded")
	body, status, err := FetchSafe(ctx, nil, http.MethodPost, endpoint, strings.NewReader(form.Encode()), header)
	if err != nil {
		return fmt.Errorf("bot verification failed")
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("bot verification failed")
	}
	var parsed struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil || !parsed.Success {
		return fmt.Errorf("bot verification failed")
	}
	return nil
}
