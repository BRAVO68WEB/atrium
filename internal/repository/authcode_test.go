package repository

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
)

func TestMarkUsedRejectsASecondConsume(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "codes.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, username, password_hash) VALUES ('u1', 'ada', 'x')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO clients (id, name) VALUES ('c1', 'app')`); err != nil {
		t.Fatal(err)
	}
	repo := NewAuthCodeRepository(db)
	code := &models.AuthorizationCode{
		Code:        "code-1",
		ClientID:    "c1",
		UserID:      "u1",
		RedirectURI: "https://app.example/cb",
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	if err := repo.Save(code); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkUsed(code.Code); err != nil {
		t.Fatal(err)
	}
	if err := repo.MarkUsed(code.Code); !errors.Is(err, ErrCodeUsed) {
		t.Fatalf("second consume: %v", err)
	}
}
