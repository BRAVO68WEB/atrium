package service

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/social"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/crypto"
)

var (
	ErrSocialProviderNotFound     = errors.New("social provider not found")
	ErrSocialState                = errors.New("invalid social login state")
	ErrSocialRegistrationDisabled = errors.New("social registration is disabled")
	ErrSocialEmailInUse           = errors.New("email already registered")
	ErrSocialAccountDisabled      = errors.New("account disabled")
)

// SocialButton is one link on the login page.
type SocialButton struct {
	ID   string
	Name string
}

// SocialResult is a completed upstream login.
type SocialResult struct {
	User   *models.User
	Params map[string]string
}

type SocialService struct {
	cfg      *config.Config
	users    *UserService
	userRepo *repository.UserRepository
	repo     *repository.SocialRepository
	account  *AccountService
	upstream *social.Client
}

func NewSocialService(cfg *config.Config, users *UserService, userRepo *repository.UserRepository, repo *repository.SocialRepository, account *AccountService, upstream *social.Client) *SocialService {
	defer telemetry.Step("service.NewSocialService")()
	if upstream == nil {
		upstream = social.NewClient(nil)
	}
	return &SocialService{cfg: cfg, users: users, userRepo: userRepo, repo: repo, account: account, upstream: upstream}
}

func (s *SocialService) Buttons() []SocialButton {
	defer telemetry.Step("service.SocialService.Buttons")()
	if s == nil || s.cfg == nil {
		return nil
	}
	var out []SocialButton
	for _, p := range s.cfg.Social.Providers {
		if !p.Enabled || p.ClientID == "" || p.ClientSecret == "" {
			continue
		}
		resolved, err := social.Resolve(p)
		if err != nil {
			continue
		}
		out = append(out, SocialButton{ID: p.ID, Name: resolved.Name})
	}
	return out
}

func (s *SocialService) provider(id string) (config.SocialProvider, bool) {
	defer telemetry.Step("service.SocialService.provider")()
	if s == nil || s.cfg == nil {
		return config.SocialProvider{}, false
	}
	for _, p := range s.cfg.Social.Providers {
		if p.ID == id && p.Enabled && p.ClientID != "" && p.ClientSecret != "" {
			return p, true
		}
	}
	return config.SocialProvider{}, false
}

// Begin stores a single-use state and returns the upstream authorization URL.
func (s *SocialService) Begin(ctx context.Context, id string, params map[string]string) (string, error) {
	defer telemetry.Step("service.SocialService.Begin")()
	raw, ok := s.provider(id)
	if !ok {
		return "", ErrSocialProviderNotFound
	}
	resolved, err := social.Resolve(raw)
	if err != nil {
		return "", err
	}
	resolved, err = s.upstream.Prepare(ctx, resolved)
	if err != nil {
		return "", err
	}
	state, err := randomHex(32)
	if err != nil {
		return "", err
	}
	nonce, err := randomHex(16)
	if err != nil {
		return "", err
	}
	verifier := ""
	challenge := ""
	if resolved.UsePKCE {
		verifier, err = crypto.GenerateCodeVerifier()
		if err != nil {
			return "", err
		}
		challenge = crypto.GenerateCodeChallenge(verifier)
	}
	copied := map[string]string{}
	for k, v := range params {
		copied[k] = v
	}
	if err := s.repo.SaveLogin(repository.SocialLogin{
		State:     state,
		Provider:  id,
		Verifier:  verifier,
		Nonce:     nonce,
		Params:    copied,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}); err != nil {
		return "", err
	}
	return social.AuthorizeURL(resolved, s.redirectURI(id), state, nonce, challenge)
}

// Complete exchanges the code and finds or creates the local user.
func (s *SocialService) Complete(ctx context.Context, id, code, state string) (SocialResult, error) {
	defer telemetry.Step("service.SocialService.Complete")()
	if code == "" || state == "" {
		return SocialResult{}, ErrSocialState
	}
	raw, ok := s.provider(id)
	if !ok {
		return SocialResult{}, ErrSocialProviderNotFound
	}
	row, err := s.repo.Consume(state, id)
	if err != nil {
		return SocialResult{}, ErrSocialState
	}
	if time.Now().After(row.ExpiresAt) {
		return SocialResult{}, ErrSocialState
	}
	resolved, err := social.Resolve(raw)
	if err != nil {
		return SocialResult{}, err
	}
	resolved, err = s.upstream.Prepare(ctx, resolved)
	if err != nil {
		return SocialResult{}, err
	}
	redirectURI := s.redirectURI(id)
	tok, err := s.upstream.Exchange(ctx, resolved, redirectURI, code, row.Verifier)
	if err != nil {
		return SocialResult{}, err
	}
	profile, err := s.upstream.Profile(ctx, resolved, redirectURI, tok, row.Nonce)
	if err != nil {
		return SocialResult{}, err
	}
	user, err := s.findOrCreate(id, profile)
	if err != nil {
		return SocialResult{Params: row.Params}, err
	}
	return SocialResult{User: user, Params: row.Params}, nil
}

func (s *SocialService) findOrCreate(provider string, profile social.Profile) (*models.User, error) {
	defer telemetry.Step("service.SocialService.findOrCreate")()
	userID, err := s.repo.FindIdentity(provider, profile.Subject)
	if err == nil {
		user, err := s.users.GetUser(userID)
		if err != nil {
			return nil, err
		}
		if user.Disabled {
			return nil, ErrSocialAccountDisabled
		}
		return user, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if profile.Email != "" {
		existing, err := s.userRepo.GetByEmail(profile.Email)
		if err == nil && existing != nil {
			return nil, ErrSocialEmailInUse
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
	if s.cfg.Security.DisableRegistration || s.cfg.Security.DisableSocialRegistration {
		return nil, ErrSocialRegistrationDisabled
	}
	username, err := s.uniqueUsername(profile.Username, profile.Email, provider, profile.Subject)
	if err != nil {
		return nil, err
	}
	secret, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	user, err := s.users.InsertUser(NewUser{
		Username:      username,
		Password:      secret,
		Email:         profile.Email,
		GivenName:     profile.GivenName,
		FamilyName:    profile.FamilyName,
		EmailVerified: profile.EmailVerified,
	})
	if err != nil {
		return nil, err
	}
	if err := s.repo.InsertIdentity(provider, profile.Subject, user.ID, profile.Email, time.Now()); err != nil {
		return nil, err
	}
	if s.account != nil {
		s.account.EmitRegistered(user, "social", provider)
	}
	return user, nil
}

func (s *SocialService) uniqueUsername(hint, email, provider, subject string) (string, error) {
	defer telemetry.Step("service.SocialService.uniqueUsername")()
	base := sanitizeUsername(hint)
	if base == "" && email != "" {
		local := email
		if i := strings.IndexByte(email, '@'); i >= 0 {
			local = email[:i]
		}
		base = sanitizeUsername(local)
	}
	if base == "" {
		base = sanitizeUsername(provider + "-" + subject)
	}
	if base == "" {
		base = "user"
	}
	candidate := base
	for n := 2; n < 1000; n++ {
		_, err := s.userRepo.GetByUsername(candidate)
		if errors.Is(err, sql.ErrNoRows) {
			return candidate, nil
		}
		if err != nil {
			return "", err
		}
		candidate = fmt.Sprintf("%s-%d", base, n)
	}
	return "", fmt.Errorf("could not choose a username")
}

func (s *SocialService) redirectURI(id string) string {
	defer telemetry.Step("service.SocialService.redirectURI")()
	issuer := ""
	port := 8080
	if s.cfg != nil {
		issuer = strings.TrimRight(s.cfg.Security.Issuer, "/")
		if s.cfg.Server.Port > 0 {
			port = s.cfg.Server.Port
		}
	}
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", port)
	}
	return issuer + "/login/social/" + id + "/callback"
}

func sanitizeUsername(value string) string {
	defer telemetry.Step("service.sanitizeUsername")()
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if len(out) > 64 {
		out = out[:64]
	}
	return strings.Trim(out, "-")
}

func randomHex(n int) (string, error) {
	defer telemetry.Step("service.randomHex")()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
