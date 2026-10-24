package service

import (
	"database/sql"
	"fmt"
	"hash/fnv"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"context"

	"github.com/bravo68web/oauth-impl/internal/background"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/mailer"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/notify"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

var (
	ErrRateLimited          = fmt.Errorf("too many requests")
	ErrBadToken             = fmt.Errorf("invalid or expired token")
	ErrRegistrationDisabled = fmt.Errorf("registration is disabled")
)

type AccountService struct {
	users                *UserService
	userRepo             *repository.UserRepository
	emails               *repository.EmailTokenRepository
	logins               *repository.LoginEventRepository
	sessions             *SessionService
	tokens               *repository.TokenRepository
	mail                 mailer.Mailer
	templates            *mailer.Templates
	logout               *LogoutService
	hooks                *WebhookDispatcher
	trusted              []string
	issuer               string
	resetTTL             time.Duration
	registrationDisabled bool
	lim                  *rateLimiter
	mu                   sync.Mutex
	lastMail             map[string]time.Time
	outbox               Outbox
}

func NewAccountService(
	users *UserService,
	userRepo *repository.UserRepository,
	emails *repository.EmailTokenRepository,
	logins *repository.LoginEventRepository,
	sessions *SessionService,
	tokens *repository.TokenRepository,
	mail mailer.Mailer,
	logout *LogoutService,
	cfg *config.Config,
) *AccountService {
	defer telemetry.Step("service.NewAccountService")()
	if mail == nil {
		mail = mailer.Nop{}
	}
	ttl := cfg.Security.ResetTokenLifetime
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	issuer := cfg.Security.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", cfg.Server.Port)
	}
	return &AccountService{
		users:                users,
		userRepo:             userRepo,
		emails:               emails,
		logins:               logins,
		sessions:             sessions,
		tokens:               tokens,
		mail:                 mail,
		logout:               logout,
		trusted:              append([]string{}, cfg.Security.TrustedProxies...),
		issuer:               issuer,
		resetTTL:             ttl,
		registrationDisabled: cfg.Security.DisableRegistration,
		lim:                  newRateLimiter(),
		lastMail:             map[string]time.Time{},
	}
}

func (a *AccountService) SetOutbox(box Outbox) {
	defer telemetry.Step("service.AccountService.SetOutbox")()
	if a != nil {
		a.outbox = box
	}
}

func (a *AccountService) SetTemplates(t *mailer.Templates) {
	defer telemetry.Step("service.AccountService.SetTemplates")()
	if a != nil {
		a.templates = t
	}
}

func (a *AccountService) SetWebhooks(d *WebhookDispatcher) {
	defer telemetry.Step("service.AccountService.SetWebhooks")()
	if a != nil {
		a.hooks = d
	}
}

func (a *AccountService) EmitRegistered(user *models.User, source, provider string) {
	defer telemetry.Step("service.AccountService.EmitRegistered")()
	if a == nil || user == nil {
		return
	}
	data := map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
	}
	if source != "" {
		data["source"] = source
		data["provider"] = provider
	}
	a.emit(EventUserRegistered, data)
}

func (a *AccountService) emit(event string, data map[string]any) {
	defer telemetry.Step("service.AccountService.emit")()
	if a == nil || a.hooks == nil {
		return
	}
	a.hooks.Emit(event, data)
}

func (a *AccountService) RegistrationDisabled() bool {
	defer telemetry.Step("service.AccountService.RegistrationDisabled")()
	return a != nil && a.registrationDisabled
}

func (a *AccountService) Register(username, password, email, phone string) (*models.User, error) {
	defer telemetry.Step("service.AccountService.Register")()
	if a.RegistrationDisabled() {
		return nil, ErrRegistrationDisabled
	}
	user, err := a.users.InsertUser(NewUser{
		Username: username,
		Password: password,
		Email:    email,
		Phone:    phone,
	})
	if err != nil {
		return nil, err
	}
	if email != "" {
		_ = a.sendVerify(user)
	}
	a.emit(EventUserRegistered, map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
	})
	return user, nil
}

func (a *AccountService) Forgot(identifier, ip string) error {
	defer telemetry.Step("service.AccountService.Forgot")()
	if !a.lim.allow("forgot-ip:"+ip, 20, time.Hour) {
		return ErrRateLimited
	}
	user := a.findUser(identifier)
	data := map[string]any{"identifier": identifier, "ip": ip, "matched": false}
	if user != nil {
		data["matched"] = true
		data["user_id"] = user.ID
		data["username"] = user.Username
		data["email"] = user.Email
	}
	if !a.mail.Enabled() {
		a.emit(EventForgotPassword, data)
		return mailer.ErrDisabled
	}
	if user == nil || user.Email == "" {
		a.emit(EventForgotPassword, data)
		return nil
	}
	if !a.lim.allow("forgot:"+user.Email, 5, time.Hour) {
		return ErrRateLimited
	}
	token, err := a.emails.Create(user.ID, "reset", a.resetTTL)
	if err != nil {
		return err
	}
	a.emit(EventForgotPassword, data)
	return a.sendMail(user, "reset", mailer.Data{
		Link: a.issuer + "/reset?token=" + token,
		TTL:  a.resetTTL.String(),
	})
}

func (a *AccountService) Reset(token, password, ip string) error {
	defer telemetry.Step("service.AccountService.Reset")()
	if !a.lim.allow("reset-ip:"+ip, 10, time.Hour) {
		return ErrRateLimited
	}
	userID, err := a.emails.Consume(token, "reset")
	if err != nil {
		return ErrBadToken
	}
	if err := a.users.SetPassword(userID, password); err != nil {
		return err
	}
	if user, err := a.userRepo.GetByID(userID); err == nil {
		a.sendPasswordChanged(user)
		a.emit(EventPasswordReset, map[string]any{
			"user_id": user.ID, "username": user.Username, "email": user.Email, "ip": ip, "source": "reset",
		})
	}
	return nil
}

func (a *AccountService) Verify(token string) error {
	defer telemetry.Step("service.AccountService.Verify")()
	userID, err := a.emails.Consume(token, "verify")
	if err != nil {
		return ErrBadToken
	}
	user, err := a.userRepo.GetByID(userID)
	if err != nil {
		return err
	}
	user.EmailVerified = true
	if err := a.userRepo.UpdateProfile(user); err != nil {
		return err
	}
	a.emit(EventEmailVerified, map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
	})
	return nil
}

func (a *AccountService) SendVerification(user *models.User) error {
	defer telemetry.Step("service.AccountService.SendVerification")()
	if !a.mail.Enabled() {
		return mailer.ErrDisabled
	}
	if user == nil || user.Email == "" {
		return fmt.Errorf("user has no email")
	}
	return a.sendVerify(user)
}

func (a *AccountService) ChangePassword(userID, current, next, keepAccess, keepSID string) error {
	defer telemetry.Step("service.AccountService.ChangePassword")()
	if err := a.users.ChangePassword(userID, current, next); err != nil {
		return err
	}
	a.afterCredentialChange(userID, keepAccess, keepSID)
	if user, err := a.userRepo.GetByID(userID); err == nil {
		a.emit(EventChangePassword, map[string]any{
			"user_id": user.ID, "username": user.Username, "email": user.Email, "source": "self_service",
		})
	}
	return nil
}

func (a *AccountService) AdminSetPassword(userID, password string) error {
	defer telemetry.Step("service.AccountService.AdminSetPassword")()
	if err := a.users.SetPassword(userID, password); err != nil {
		return err
	}
	if user, err := a.userRepo.GetByID(userID); err == nil {
		a.sendPasswordChanged(user)
		a.emit(EventChangePassword, map[string]any{
			"user_id": user.ID, "username": user.Username, "email": user.Email, "source": "management",
		})
	}
	return nil
}

func (a *AccountService) SetDisabled(user *models.User, disabled bool) error {
	defer telemetry.Step("service.AccountService.SetDisabled")()
	user.Disabled = disabled
	if err := a.userRepo.UpdateProfile(user); err != nil {
		return err
	}
	if !disabled {
		return nil
	}
	_ = a.tokens.RevokeAllForUser(user.ID)
	sids, err := a.sessions.RevokeAllExcept(user.ID, "")
	if err != nil {
		return err
	}
	for _, sid := range sids {
		a.logout.Notify(sid, user.ID)
	}
	a.emit(EventUserDisabled, map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
	})
	return nil
}

func (a *AccountService) RevokeSession(userID, sid string) error {
	defer telemetry.Step("service.AccountService.RevokeSession")()
	sess, err := a.sessions.GetAny(sid)
	if err != nil || sess.UserID != userID {
		return sql.ErrNoRows
	}
	a.logout.End(sid)
	return nil
}

func (a *AccountService) Record(user *models.User, r *http.Request, success, mfa bool) {
	defer telemetry.Step("service.AccountService.Record")()
	if a == nil || user == nil {
		return
	}
	copied := cloneUser(user)
	ev := &models.LoginEvent{
		UserID:    copied.ID,
		Success:   success,
		MFA:       mfa,
		IP:        a.RequestIP(r),
		CreatedAt: time.Now(),
	}
	if r != nil {
		ev.UserAgent = r.UserAgent()
	}
	enqueueRecord(copied.ID, func() {
		defer telemetry.Step("service.AccountService.record")()
		a.record(&copied, ev)
	})
}

func (a *AccountService) record(user *models.User, ev *models.LoginEvent) {
	if a == nil || user == nil || ev == nil {
		return
	}
	seen := false
	if ev.IP != "" {
		seen, _ = a.logins.HasIP(user.ID, ev.IP)
	}
	if err := a.logins.Insert(ev); err != nil {
		log.Printf("login event: %v", err)
	}
	event := EventLoginFailed
	if ev.Success {
		event = EventLogin
	}
	data := map[string]any{
		"user_id": user.ID, "username": user.Username, "email": user.Email,
		"ip": ev.IP, "user_agent": ev.UserAgent, "mfa": ev.MFA, "success": ev.Success,
	}
	if ev.Success && ev.IP != "" && !seen {
		data["new_ip"] = true
	}
	a.emit(event, data)
	if ev.Success {
		a.users.TouchLastLogin(user.ID)
		a.maybeLoginMail(user, ev)
		return
	}
	a.maybeFailMail(user, ev)
}

func (a *AccountService) Activity(userID string, limit int) ([]*models.LoginEvent, error) {
	defer telemetry.Step("service.AccountService.Activity")()
	return a.logins.ListByUser(userID, limit)
}

func (a *AccountService) LoginAnalytics(userID string, window time.Duration) (*models.LoginAnalytics, error) {
	defer telemetry.Step("service.AccountService.LoginAnalytics")()
	if window <= 0 {
		window = 30 * 24 * time.Hour
	}
	if window > 366*24*time.Hour {
		window = 366 * 24 * time.Hour
	}
	out, err := a.logins.Analytics(userID, time.Now().Add(-window))
	if err != nil {
		return nil, err
	}
	out.Window = window.String()
	return out, nil
}

func (a *AccountService) RequestIP(r *http.Request) string {
	defer telemetry.Step("service.AccountService.RequestIP")()
	if a == nil {
		return ClientIP(r, nil)
	}
	return ClientIP(r, a.trusted)
}

func (a *AccountService) afterCredentialChange(userID, keepAccess, keepSID string) {
	defer telemetry.Step("service.AccountService.afterCredentialChange")()
	_ = a.tokens.RevokeOtherFamilies(userID, keepAccess)
	sids, err := a.sessions.RevokeAllExcept(userID, keepSID)
	if err != nil {
		log.Printf("revoke sessions for %s: %v", userID, err)
		return
	}
	for _, sid := range sids {
		a.logout.Notify(sid, userID)
	}
	if user, err := a.userRepo.GetByID(userID); err == nil {
		a.sendPasswordChanged(user)
	}
}

func (a *AccountService) findUser(identifier string) *models.User {
	defer telemetry.Step("service.AccountService.findUser")()
	if a == nil || a.users == nil || identifier == "" {
		return nil
	}
	user, err := a.users.FindByLogin(identifier)
	if err != nil {
		return nil
	}
	return user
}

func (a *AccountService) sendVerify(user *models.User) error {
	defer telemetry.Step("service.AccountService.sendVerify")()
	if !a.mail.Enabled() || user.Email == "" {
		return nil
	}
	token, err := a.emails.Create(user.ID, "verify", a.resetTTL)
	if err != nil {
		log.Printf("verify token: %v", err)
		return err
	}
	if err := a.sendMail(user, "verify", mailer.Data{Link: a.issuer + "/verify-email?token=" + token}); err != nil {
		log.Printf("verify mail: %v", err)
		return err
	}
	return nil
}

func (a *AccountService) sendPasswordChanged(user *models.User) {
	defer telemetry.Step("service.AccountService.sendPasswordChanged")()
	if !a.mail.Enabled() || user == nil || user.Email == "" {
		return
	}
	if err := a.sendMail(user, "password_changed", mailer.Data{}); err != nil {
		log.Printf("password-changed mail: %v", err)
	}
}

func (a *AccountService) maybeLoginMail(user *models.User, ev *models.LoginEvent) {
	defer telemetry.Step("service.AccountService.maybeLoginMail")()
	if !a.mail.Enabled() || user.Email == "" {
		return
	}
	if !a.markMail("login:"+user.ID, 10*time.Minute) {
		return
	}
	ip, err := a.storedIP(user.ID)
	if err != nil {
		log.Printf("login mail ip: %v", err)
	}
	if err := a.sendMail(user, "new_sign_in", mailer.Data{
		Time: ev.CreatedAt.Format(time.RFC3339), IP: ip,
	}); err != nil {
		log.Printf("login mail: %v", err)
	}
}

func (a *AccountService) maybeFailMail(user *models.User, ev *models.LoginEvent) {
	defer telemetry.Step("service.AccountService.maybeFailMail")()
	n, err := a.logins.CountFailuresSince(user.ID, time.Now().Add(-15*time.Minute))
	if err != nil || n < 5 {
		return
	}
	if a.markMail("bruteforce:"+user.ID, 15*time.Minute) {
		a.emit(EventBruteforce, map[string]any{
			"user_id": user.ID, "username": user.Username, "email": user.Email,
			"ip": ev.IP, "user_agent": ev.UserAgent, "failures": n, "window": "15m",
		})
	}
	if !a.mail.Enabled() || user.Email == "" {
		return
	}
	if !a.markMail("fail:"+user.ID, time.Hour) {
		return
	}
	ip, ipErr := a.storedIP(user.ID)
	if ipErr != nil {
		log.Printf("failed-login mail ip: %v", ipErr)
	}
	if err := a.sendMail(user, "login_failed", mailer.Data{Count: fmt.Sprintf("%d", n), IP: ip}); err != nil {
		log.Printf("failed-login mail: %v", err)
	}
}

func (a *AccountService) storedIP(userID string) (string, error) {
	defer telemetry.Step("service.AccountService.storedIP")()
	if a == nil || a.logins == nil || userID == "" {
		return "", nil
	}
	return a.logins.LatestIP(userID)
}

func (a *AccountService) sendMail(user *models.User, name string, data mailer.Data) error {
	defer telemetry.Step("service.AccountService.sendMail")()
	if a == nil || a.mail == nil || user == nil || user.ID == "" || a.userRepo == nil {
		return nil
	}
	stored, err := a.userRepo.GetByID(user.ID)
	if err != nil {
		return err
	}
	if stored == nil || strings.TrimSpace(stored.Email) == "" {
		return nil
	}
	data.Issuer = mailer.OneLine(a.issuer)
	data.Username = mailer.OneLine(stored.Username)
	data.Email = mailer.OneLine(stored.Email)
	data.Link = mailer.OneLine(data.Link)
	data.TTL = mailer.OneLine(data.TTL)
	data.Time = mailer.OneLine(data.Time)
	data.IP = mailer.OneLine(data.IP)
	data.Agent = ""
	data.Count = mailer.OneLine(data.Count)

	subject, body, err := mailer.Render(a.templates, name, data)
	if err != nil {
		return err
	}
	if a.outbox != nil {
		return a.outbox.Publish(context.Background(), notify.Job{
			Kind:    notify.KindMail,
			To:      stored.Email,
			Subject: subject,
			Text:    body,
		}, 0)
	}
	to := stored.Email
	userID := stored.ID
	mail := a.mail
	background.Go(func() {
		defer telemetry.Step("service.AccountService.sendMailAsync")()
		if err := mail.Send(to, subject, body); err != nil {
			log.Printf("mail %s for %s: %v", name, userID, err)
		}
	})
	return nil
}

func (a *AccountService) markMail(key string, window time.Duration) bool {
	defer telemetry.Step("service.AccountService.markMail")()
	a.mu.Lock()
	defer a.mu.Unlock()
	if last, ok := a.lastMail[key]; ok && time.Since(last) < window {
		return false
	}
	a.lastMail[key] = time.Now()
	return true
}

func cloneUser(user *models.User) models.User {
	copied := *user
	if user.Attributes != nil {
		copied.Attributes = make(map[string]string, len(user.Attributes))
		for key, value := range user.Attributes {
			copied.Attributes[key] = value
		}
	}
	if user.LastLoginAt != nil {
		at := *user.LastLoginAt
		copied.LastLoginAt = &at
	}
	return copied
}

// recordLaneCount stripes login recording so one user stays in order
// without a map entry per user.
const recordLaneCount = 64

type recordLane struct {
	mu   sync.Mutex
	jobs []func()
	live bool
}

var recordLanes [recordLaneCount]recordLane

func enqueueRecord(userID string, job func()) {
	if userID == "" {
		userID = "_"
	}
	sum := fnv.New32a()
	_, _ = sum.Write([]byte(userID))
	lane := &recordLanes[sum.Sum32()%recordLaneCount]
	lane.mu.Lock()
	lane.jobs = append(lane.jobs, job)
	if lane.live {
		lane.mu.Unlock()
		return
	}
	lane.live = true
	lane.mu.Unlock()
	background.Go(func() {
		for {
			lane.mu.Lock()
			if len(lane.jobs) == 0 {
				lane.live = false
				lane.mu.Unlock()
				return
			}
			next := lane.jobs[0]
			lane.jobs = lane.jobs[1:]
			lane.mu.Unlock()
			func() {
				defer func() {
					if rec := recover(); rec != nil {
						log.Printf("login record: %v", rec)
					}
				}()
				next()
			}()
		}
	})
}

type rateLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	defer telemetry.Step("service.newRateLimiter")()
	return &rateLimiter{hits: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(key string, max int, window time.Duration) bool {
	defer telemetry.Step("service.rateLimiter.allow")()
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	cut := now.Add(-window)
	prev := l.hits[key]
	kept := prev[:0]
	for _, t := range prev {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}
