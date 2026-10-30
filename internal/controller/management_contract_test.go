package controller

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/service"
	"github.com/bravo68web/atrium/pkg/passhash"
	"github.com/go-chi/chi/v5"
)

func TestUsernameLookupAndResetEmail(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "mgmt.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	userRepo := repository.NewUserRepository(db)
	users := service.NewUserService(userRepo, service.NewTOTPService(userRepo, &cfg.Security.MFA), &cfg.Security, passhash.Bcrypt(0))
	mail := &captureMail{}
	account := service.NewAccountService(users, userRepo, repository.NewEmailTokenRepository(db), repository.NewLoginEventRepository(db), nil, nil, mail, nil, cfg)
	mgmt := NewManagementController(nil, users, nil, nil, nil, nil, nil, account, nil, nil)
	ada, err := users.CreateUser("ada", "Correct-horse-1", "ada@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.InsertUser(service.NewUser{Username: "sam", Email: "sam@example.com", MigrationPending: true}); err != nil {
		t.Fatal(err)
	}

	mux := chi.NewRouter()
	mux.Get("/api/users", mgmt.HandleListUsers)
	mux.Post("/api/users/{userID}/password/reset-email", mgmt.HandleResetEmail)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	resp, err := http.Get(ts.URL + "/api/users?username=ada")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var listed []models.User
	if err := json.NewDecoder(resp.Body).Decode(&listed); err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].ID != ada.ID || !listed[0].HasPassword {
		t.Fatalf("lookup %+v", listed)
	}

	miss, err := http.Get(ts.URL + "/api/users?username=ada@example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = miss.Body.Close() }()
	raw, _ := io.ReadAll(miss.Body)
	if strings.TrimSpace(string(raw)) != "[]" && !strings.Contains(string(raw), "[]") {
		t.Fatalf("email is not a username match: %s", raw)
	}

	reset, err := http.Post(ts.URL+"/api/users/"+ada.ID+"/password/reset-email", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reset.Body.Close() }()
	if reset.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(reset.Body)
		t.Fatalf("reset %d %s", reset.StatusCode, body)
	}
	mail.waitCount(t, 1)
	body := mail.last()
	if mail.count() != 1 || !strings.Contains(body, "/reset?token=") {
		t.Fatalf("mail %d %q", mail.count(), body)
	}

	sam, err := users.GetUserByUsername("sam")
	if err != nil {
		t.Fatal(err)
	}
	denied, err := http.Post(ts.URL+"/api/users/"+sam.ID+"/password/reset-email", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = denied.Body.Close() }()
	if denied.StatusCode != http.StatusConflict {
		t.Fatalf("empty hash reset %d", denied.StatusCode)
	}
}
