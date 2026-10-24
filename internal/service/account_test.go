package service

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bravo68web/oauth-impl/internal/background"
	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/bravo68web/oauth-impl/internal/testpg"
	"github.com/bravo68web/oauth-impl/pkg/passhash"
)

type fakeMail struct {
	mu   sync.Mutex
	msgs []string
}

func (f *fakeMail) Enabled() bool { return true }

func (f *fakeMail) Send(to, subject, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.msgs = append(f.msgs, to+"|"+subject+"|"+text)
	return nil
}

func TestRegisterDisabledCreatesNoUser(t *testing.T) {
	db := testpg.Open(t)
	conn := db
	cfg := config.DefaultConfig()
	cfg.Security.DisableRegistration = true
	users := NewUserService(repository.NewUserRepository(conn), nil, &cfg.Security, passhash.Bcrypt(bcrypt.MinCost))
	account := NewAccountService(users, repository.NewUserRepository(conn), repository.NewEmailTokenRepository(conn), repository.NewLoginEventRepository(conn), nil, repository.NewTokenRepository(conn), nil, nil, cfg)
	if _, err := account.Register("ada", "correct horse", "ada@example.com", ""); !errors.Is(err, ErrRegistrationDisabled) {
		t.Fatalf("err = %v", err)
	}
	list, err := users.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 0 {
		t.Fatalf("users = %+v", list)
	}
}

func TestResetAndLoginMail(t *testing.T) {
	db := testpg.Open(t)
	conn := db
	cfg := config.DefaultConfig()
	users := NewUserService(repository.NewUserRepository(conn), nil, &cfg.Security, passhash.Bcrypt(bcrypt.MinCost))
	sessions := NewSessionService(repository.NewSessionRepository(conn), time.Hour)
	mail := &fakeMail{}
	account := NewAccountService(users, repository.NewUserRepository(conn), repository.NewEmailTokenRepository(conn), repository.NewLoginEventRepository(conn), sessions, repository.NewTokenRepository(conn), mail, nil, cfg)

	user, err := account.Register("ada", "correct horse", "ada@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	background.Wait()
	if user.EmailVerified {
		t.Fatal("self-service registration verified the email")
	}
	if len(mail.msgs) != 1 || !strings.Contains(mail.msgs[0], "/verify-email?token=") {
		t.Fatalf("verify mail %#v", mail.msgs)
	}

	token := tokenFrom(mail.msgs[0])
	if err := account.Verify(token); err != nil {
		t.Fatal(err)
	}
	if err := account.Verify(token); err == nil {
		t.Fatal("verify token was reused")
	}

	if err := account.Forgot("missing@example.com", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	background.Wait()
	if len(mail.msgs) != 1 {
		t.Fatal("unknown user sent mail")
	}
	if err := account.Forgot("ada", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	background.Wait()
	reset := tokenFrom(mail.msgs[1])
	if err := account.Reset(reset, "new password", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if _, err := users.Authenticate("ada", "new password"); err != nil {
		t.Fatal(err)
	}
	if err := account.Reset(reset, "other", "127.0.0.1"); err == nil {
		t.Fatal("reset token was reused")
	}

	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.Header.Set("User-Agent", "visit https://evil.example\r\nBcc: eve@example.com")
	account.Record(user, req, true, false)
	background.Wait()
	signIn := ""
	for _, msg := range mail.msgs {
		if strings.Contains(msg, "New sign-in") {
			signIn = msg
		}
	}
	if signIn == "" || !strings.Contains(signIn, "127.0.0.1") || strings.Contains(signIn, "evil.example") || strings.Contains(signIn, "Bcc:") {
		t.Fatalf("sign-in mail %q", signIn)
	}
	events, err := account.Activity(user.ID, 10)
	if err != nil || len(events) != 1 || !events[0].Success {
		t.Fatalf("events %#v %v", events, err)
	}
}

func TestFailedRecordsStayOrdered(t *testing.T) {
	db := testpg.Open(t)
	cfg := config.DefaultConfig()
	users := NewUserService(repository.NewUserRepository(db), nil, &cfg.Security, passhash.Bcrypt(bcrypt.MinCost))
	account := NewAccountService(users, repository.NewUserRepository(db), repository.NewEmailTokenRepository(db), repository.NewLoginEventRepository(db), nil, repository.NewTokenRepository(db), nil, nil, cfg)
	var mu sync.Mutex
	var events []string
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		events = append(events, r.Header.Get("X-Webhook-Event"))
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer receiver.Close()
	hooks := NewWebhookDispatcher(repository.NewWebhookRepository(db))
	account.SetWebhooks(hooks)
	if _, err := hooks.Create(WebhookInput{URL: receiver.URL, Secret: "topsecret", Events: []string{EventLoginFailed, EventBruteforce}}); err != nil {
		t.Fatal(err)
	}
	user, err := users.CreateUser("ada", "correct horse", "ada@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	req.RemoteAddr = "198.51.100.8:9"
	for range 5 {
		account.Record(user, req, false, false)
	}
	background.Wait()
	mu.Lock()
	defer mu.Unlock()
	failed := 0
	brute := 0
	for _, event := range events {
		switch event {
		case EventLoginFailed:
			failed++
		case EventBruteforce:
			brute++
		}
	}
	if failed != 5 || brute != 1 {
		t.Fatalf("events %v", events)
	}
}

func tokenFrom(msg string) string {
	i := strings.Index(msg, "token=")
	if i < 0 {
		return ""
	}
	rest := msg[i+len("token="):]
	if n := strings.IndexAny(rest, "\r\n &"); n >= 0 {
		return rest[:n]
	}
	return rest
}
