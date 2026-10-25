package service

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/testpg"
	"github.com/bravo68web/atrium/pkg/passhash"
)

func TestLoginAnalyticsGroupsIPs(t *testing.T) {
	db := testpg.Open(t)
	cfg := config.DefaultConfig()
	repo := repository.NewLoginEventRepository(db)
	users := NewUserService(repository.NewUserRepository(db), nil, &cfg.Security, passhash.Bcrypt(bcrypt.MinCost))
	account := NewAccountService(users, repository.NewUserRepository(db), repository.NewEmailTokenRepository(db), repo, NewSessionService(repository.NewSessionRepository(db), time.Hour), repository.NewTokenRepository(db), nil, nil, cfg)
	user, err := users.CreateUser("ada", "correct horse", "ada@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	events := []*models.LoginEvent{
		{UserID: user.ID, Success: false, IP: "203.0.113.8", UserAgent: "old", CreatedAt: now.Add(-2 * time.Hour)},
		{UserID: user.ID, Success: true, IP: "203.0.113.8", UserAgent: "browser", CreatedAt: now.Add(-time.Hour)},
		{UserID: user.ID, Success: true, IP: "203.0.113.20", UserAgent: "phone", CreatedAt: now.Add(-10 * time.Minute)},
	}
	for _, ev := range events {
		if err := repo.Insert(ev); err != nil {
			t.Fatal(err)
		}
	}
	report, err := account.LoginAnalytics(user.ID, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if report.Attempts != 3 || report.Successes != 2 || report.Failures != 1 || report.UniqueIPs != 2 || report.NewIPs != 2 {
		t.Fatalf("%+v", report)
	}
	if len(report.ByIP) != 2 || report.ByIP[0].IP != "203.0.113.20" || !report.ByIP[0].New {
		t.Fatalf("by ip %+v", report.ByIP)
	}
	if report.ByIP[1].LastUserAgent != "browser" || report.ByIP[1].Failures != 1 {
		t.Fatalf("known ip %+v", report.ByIP[1])
	}
	if len(report.ByDay) == 0 {
		t.Fatal("expected a daily bucket")
	}
}
