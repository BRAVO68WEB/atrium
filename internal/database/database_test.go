package database_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/testpg"
)

func TestMigrateRejectsDuplicateEmails(t *testing.T) {
	db := testpg.Open(t)
	if _, err := db.Exec(`DROP INDEX IF EXISTS idx_users_email_lower`); err != nil {
		t.Fatal(err)
	}
	users := repository.NewUserRepository(db)
	for i, email := range []string{"Ada@x.com", "ada@x.com"} {
		user := &models.User{
			ID:           fmt.Sprintf("user-%d", i),
			Username:     fmt.Sprintf("user-%d", i),
			PasswordHash: "hash",
			Email:        email,
			CreatedAt:    time.Now(),
		}
		if err := users.Create(user); err != nil {
			t.Fatal(err)
		}
	}
	err := db.Migrate()
	if err == nil || !strings.Contains(err.Error(), "duplicate emails") {
		t.Fatalf("migrate err = %v", err)
	}
}
