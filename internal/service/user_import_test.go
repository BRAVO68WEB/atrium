package service

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/pkg/passhash"
)

func TestImportAcceptsTheHasherFromAlgo(t *testing.T) {
	svc := newImportService(t, customImportHasher{})
	doc := ImportDocument{Mode: "create", Users: []ImportUser{{
		Username:     "ada",
		PasswordHash: "$custom$secret",
	}}}
	result, err := svc.ImportUsers(doc, false, nil)
	if err != nil || result.Created != 1 || len(result.Errors) != 0 {
		t.Fatalf("import %+v %v", result, err)
	}
	user, err := svc.Authenticate("ada", "secret")
	if err != nil || user.Username != "ada" {
		t.Fatalf("login %v %v", user, err)
	}
	rejected := ImportDocument{Users: []ImportUser{{Username: "bob", PasswordHash: "sha1$nope"}}}
	result, err = svc.ImportUsers(rejected, false, nil)
	if err != nil || result.Created != 0 || len(result.Errors) != 1 {
		t.Fatalf("rejected %+v %v", result, err)
	}
}

func TestImportCreateUpsertAndDryRun(t *testing.T) {
	svc := newImportService(t, passhash.Bcrypt(passhash.DefaultBcryptCost))
	first, err := svc.ImportUsers(ImportDocument{Users: []ImportUser{{
		Username: "ada",
		Email:    "ada@example.com",
		Password: "correct horse",
	}}}, false, nil)
	if err != nil || first.Created != 1 {
		t.Fatalf("create %+v %v", first, err)
	}
	again, err := svc.ImportUsers(ImportDocument{Mode: "create", Users: []ImportUser{{
		Username: "ada",
		Password: "correct horse",
	}}}, false, nil)
	if err != nil || again.Created != 0 || len(again.Errors) != 1 {
		t.Fatalf("duplicate %+v %v", again, err)
	}
	dry, err := svc.ImportUsers(ImportDocument{Mode: "upsert", Users: []ImportUser{{
		Username: "ada",
		Email:    "next@example.com",
	}}}, true, nil)
	if err != nil || dry.Updated != 1 {
		t.Fatalf("dry %+v %v", dry, err)
	}
	stored, _ := svc.GetUserByUsername("ada")
	if stored.Email != "ada@example.com" {
		t.Fatalf("dry run wrote %s", stored.Email)
	}
	updated, err := svc.ImportUsers(ImportDocument{Mode: "upsert", Users: []ImportUser{{
		Username: "ada",
		Email:    "next@example.com",
	}}}, false, nil)
	if err != nil || updated.Updated != 1 {
		t.Fatalf("upsert %+v %v", updated, err)
	}
	stored, _ = svc.GetUserByUsername("ada")
	if stored.Email != "next@example.com" || !strings.HasPrefix(stored.PasswordHash, "$2") {
		t.Fatalf("upsert stored %+v", stored)
	}
	exported, err := svc.ExportUsers(false, nil)
	if err != nil || exported.Users[0].PasswordHash != "" {
		t.Fatalf("export %+v %v", exported, err)
	}
	withSecrets, err := svc.ExportUsers(true, nil)
	if err != nil || !strings.HasPrefix(withSecrets.Users[0].PasswordHash, "$2") {
		t.Fatalf("secrets %+v %v", withSecrets.Users, err)
	}
}

func newImportService(t *testing.T, hasher passhash.Hasher) *UserService {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "users.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	return NewUserService(repository.NewUserRepository(db), nil, &cfg.Security, hasher)
}

type customImportHasher struct{}

func (customImportHasher) ID() string { return "custom" }

func (customImportHasher) Hash(password string) (string, error) {
	return "$custom$" + password, nil
}

func (customImportHasher) Verify(encoded, password string) error {
	if encoded == "$custom$"+password {
		return nil
	}
	return errMismatch
}

func (customImportHasher) Recognizes(encoded string) bool {
	return strings.HasPrefix(encoded, "$custom$")
}

var errMismatch = errImportMismatch{}

type errImportMismatch struct{}

func (errImportMismatch) Error() string { return "mismatch" }
