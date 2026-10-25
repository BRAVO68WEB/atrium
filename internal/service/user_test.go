package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/testpg"
	"github.com/bravo68web/atrium/pkg/passhash"
)

type scriptHasher struct {
	hashFn   func(string) (string, error)
	verifyFn func(string, string) error
	needs    func(string) bool
}

func (s scriptHasher) ID() string { return "script" }

func (s scriptHasher) Hash(password string) (string, error) {
	return s.hashFn(password)
}

func (s scriptHasher) Verify(encoded, password string) error {
	return s.verifyFn(encoded, password)
}

func (s scriptHasher) NeedsRehash(encoded string) bool {
	return s.needs != nil && s.needs(encoded)
}

func newTestUserService(t *testing.T, hasher passhash.Hasher) (*UserService, *repository.UserRepository) {
	t.Helper()
	db := testpg.Open(t)
	repo := repository.NewUserRepository(db)
	cfg := config.DefaultConfig()
	return NewUserService(repo, NewTOTPService(repo, &cfg.Security.MFA), &cfg.Security, hasher), repo
}

func TestCreateUserStoresHasherOutput(t *testing.T) {
	h := scriptHasher{
		hashFn:   func(password string) (string, error) { return "hashed:" + password, nil },
		verifyFn: func(encoded, password string) error { return errors.New("not used") },
	}
	svc, repo := newTestUserService(t, h)

	user, err := svc.CreateUser("ada", "secret-pass", "ada@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if user.PasswordHash != "hashed:secret-pass" {
		t.Fatalf("hash = %q", user.PasswordHash)
	}
	stored, err := repo.GetByUsername("ada")
	if err != nil {
		t.Fatal(err)
	}
	if stored.PasswordHash != "hashed:secret-pass" {
		t.Fatalf("stored hash = %q", stored.PasswordHash)
	}

	if _, err := svc.CreateUser("", "secret", "", ""); err == nil {
		t.Fatal("expected empty username error")
	}
	if _, err := svc.CreateUser("ada", "other", "", ""); err == nil {
		t.Fatal("expected duplicate username error")
	}
}

func TestAuthenticateRehashesLegacyEncoding(t *testing.T) {
	h := scriptHasher{
		hashFn: func(password string) (string, error) { return "new:" + password, nil },
		verifyFn: func(encoded, password string) error {
			if encoded == "new:"+password || encoded == "old:"+password {
				return nil
			}
			return errors.New("mismatch")
		},
		needs: func(encoded string) bool { return strings.HasPrefix(encoded, "old:") },
	}
	svc, repo := newTestUserService(t, h)

	user, err := svc.CreateUser("ada", "secret-pass", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.UpdatePasswordHash(user.ID, "old:secret-pass"); err != nil {
		t.Fatal(err)
	}

	got, err := svc.Authenticate("ada", "secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if got.PasswordHash != "new:secret-pass" {
		t.Fatalf("memory hash = %q", got.PasswordHash)
	}
	stored, err := repo.GetByUsername("ada")
	if err != nil {
		t.Fatal(err)
	}
	if stored.PasswordHash != "new:secret-pass" {
		t.Fatalf("stored hash = %q", stored.PasswordHash)
	}

	if _, err := svc.Authenticate("ada", "nope"); err == nil {
		t.Fatal("expected authentication failure")
	}
	stored, err = repo.GetByUsername("ada")
	if err != nil {
		t.Fatal(err)
	}
	if stored.PasswordHash != "new:secret-pass" {
		t.Fatalf("failed login changed hash to %q", stored.PasswordHash)
	}
}

func TestAuthenticateByEmailIdentifier(t *testing.T) {
	h := scriptHasher{
		hashFn: func(password string) (string, error) { return "h:" + password, nil },
		verifyFn: func(encoded, password string) error {
			if encoded != "h:"+password {
				return errors.New("mismatch")
			}
			return nil
		},
	}
	svc, _ := newTestUserService(t, h)
	svc.cfg.LoginIdentifier = "email"
	if _, err := svc.CreateUser("ada", "secret-pass", "", ""); err == nil {
		t.Fatal("expected email to be required")
	}
	if _, err := svc.CreateUser("ada", "secret-pass", "Ada@Example.com", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate("ada", "secret-pass"); err == nil {
		t.Fatal("username must not authenticate when the identifier is email")
	}
	got, err := svc.Authenticate("ada@example.com", "secret-pass")
	if err != nil {
		t.Fatal(err)
	}
	if got.Username != "ada" {
		t.Fatalf("user = %+v", got)
	}
	if _, err := svc.CreateUser("other", "secret-pass", "ada@example.com", ""); err == nil {
		t.Fatal("expected duplicate email to be rejected")
	}
}

func TestCreateUserRejectsDuplicateMailbox(t *testing.T) {
	h := scriptHasher{
		hashFn:   func(password string) (string, error) { return "h:" + password, nil },
		verifyFn: func(string, string) error { return nil },
	}
	svc, repo := newTestUserService(t, h)
	if _, err := svc.CreateUser("ada", "secret-pass", "Ada@Example.com", ""); err != nil {
		t.Fatal(err)
	}
	_, err := svc.CreateUser("other", "secret-pass", "ada@example.com", "")
	if !errors.Is(err, ErrEmailTaken) {
		t.Fatalf("error = %v", err)
	}
	stored, err := repo.GetByUsername("ada")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Email != "ada@example.com" {
		t.Fatalf("email = %q", stored.Email)
	}
}

func TestCreateUserHasherError(t *testing.T) {
	h := scriptHasher{
		hashFn:   func(string) (string, error) { return "", errors.New("boom") },
		verifyFn: func(string, string) error { return nil },
	}
	svc, _ := newTestUserService(t, h)
	_, err := svc.CreateUser("ada", "secret-pass", "", "")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %v", err)
	}
}
