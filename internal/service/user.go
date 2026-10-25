package service

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/passhash"
)

var (
	ErrEmailRequired = errors.New("email is required")
	ErrEmailTaken    = errors.New("email already exists")
)

type UserService struct {
	userRepo *repository.UserRepository
	totpSvc  *TOTPService
	cfg      *config.SecurityConfig
	hasher   passhash.Hasher
}

func NewUserService(userRepo *repository.UserRepository, totpSvc *TOTPService, cfg *config.SecurityConfig, hasher passhash.Hasher) *UserService {
	defer telemetry.Step("service.NewUserService")()
	if hasher == nil {
		panic("passhash.Hasher is required")
	}
	return &UserService{
		userRepo: userRepo,
		totpSvc:  totpSvc,
		cfg:      cfg,
		hasher:   hasher,
	}
}

type NewUser struct {
	Username      string
	Password      string
	Email         string
	Phone         string
	GivenName     string
	FamilyName    string
	EmailVerified bool
	Disabled      bool
	Attributes    map[string]string
}

func (s *UserService) CreateUser(username, password, email, phone string) (*models.User, error) {
	defer telemetry.Step("service.UserService.CreateUser")()
	return s.InsertUser(NewUser{
		Username: username,
		Password: password,
		Email:    email,
		Phone:    phone,
	})
}

func (s *UserService) InsertUser(in NewUser) (*models.User, error) {
	defer telemetry.Step("service.UserService.InsertUser")()
	in.Email = normalizeEmail(in.Email)
	if in.Username == "" || in.Password == "" {
		return nil, fmt.Errorf("username and password are required")
	}
	if s.cfg != nil {
		if err := CheckPassword(s.cfg.Password, in.Username, in.Password); err != nil {
			return nil, err
		}
	}

	existing, _ := s.userRepo.GetByUsername(in.Username)
	if existing != nil {
		return nil, fmt.Errorf("username already exists")
	}
	if err := s.reserveEmail("", in.Email); err != nil {
		return nil, err
	}

	hashedPassword, err := s.hasher.Hash(in.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &models.User{
		ID:            uuid.New().String(),
		Username:      in.Username,
		PasswordHash:  hashedPassword,
		Email:         in.Email,
		PhoneNumber:   in.Phone,
		GivenName:     in.GivenName,
		FamilyName:    in.FamilyName,
		EmailVerified: in.EmailVerified && in.Email != "",
		Disabled:      in.Disabled,
		Attributes:    in.Attributes,
		CreatedAt:     time.Now(),
	}

	if err := s.userRepo.Create(user); err != nil {
		if emailConflict(err) {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

func (s *UserService) GetUser(id string) (*models.User, error) {
	defer telemetry.Step("service.UserService.GetUser")()
	return s.userRepo.GetByID(id)
}

func (s *UserService) GetUserByUsername(username string) (*models.User, error) {
	defer telemetry.Step("service.UserService.GetUserByUsername")()
	return s.userRepo.GetByUsername(username)
}

func (s *UserService) ListUsers() ([]*models.User, error) {
	defer telemetry.Step("service.UserService.ListUsers")(

	// FindByLogin looks up the account named by security.login_identifier.
	)
	return s.userRepo.List()
}

func (s *UserService) FindByLogin(identifier string) (*models.User, error) {
	defer telemetry.Step("service.UserService.FindByLogin")()
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, fmt.Errorf("invalid credentials")
	}
	if s.loginIdentifier() == "email" {
		return s.userRepo.GetByEmail(strings.ToLower(identifier))
	}
	return s.userRepo.GetByUsername(identifier)
}

func (s *UserService) loginIdentifier() string {
	defer telemetry.Step("service.UserService.loginIdentifier")()
	if s == nil || s.cfg == nil || s.cfg.LoginIdentifier == "" {
		return "username"
	}
	return s.cfg.LoginIdentifier
}

func normalizeEmail(email string) string {
	defer telemetry.Step("service.normalizeEmail")()
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *UserService) reserveEmail(userID, email string) error {
	defer telemetry.Step("service.UserService.reserveEmail")()
	email = normalizeEmail(email)
	if email == "" {
		if s.loginIdentifier() == "email" {
			return ErrEmailRequired
		}
		return nil
	}
	existing, err := s.userRepo.GetByEmail(email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if existing == nil || existing.ID == userID {
		return nil
	}
	return ErrEmailTaken
}

func emailConflict(err error) bool {
	defer telemetry.Step("service.emailConflict")()
	return err != nil && strings.Contains(err.Error(), "idx_users_email_lower")
}

func (s *UserService) Authenticate(username, password string) (*models.User, error) {
	defer telemetry.Step("service.UserService.Authenticate")()
	if username == "" || password == "" {
		return nil, fmt.Errorf("invalid credentials")
	}

	user, err := s.FindByLogin(username)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	if user.Disabled {
		return nil, fmt.Errorf("invalid credentials")
	}

	if err := s.hasher.Verify(user.PasswordHash, password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}
	s.maybeRehash(user, password)

	return user, nil
}

func (s *UserService) maybeRehash(user *models.User, password string) {
	defer telemetry.Step("service.UserService.maybeRehash")()
	re, ok := s.hasher.(passhash.Rehasher)
	if !ok || !re.NeedsRehash(user.PasswordHash) {
		return
	}
	encoded, err := s.hasher.Hash(password)
	if err != nil {
		log.Printf("password rehash failed for user %s: %v", user.ID, err)
		return
	}
	if err := s.userRepo.UpdatePasswordHash(user.ID, encoded); err != nil {
		log.Printf("password rehash store failed for user %s: %v", user.ID, err)
		return
	}
	user.PasswordHash = encoded
}

func (s *UserService) AuthenticateWithMFA(username, password, totpCode string) (*models.User, bool, error) {
	defer telemetry.Step("service.UserService.AuthenticateWithMFA")()
	user, err := s.Authenticate(username, password)
	if err != nil {
		return nil, false, err
	}

	if s.cfg.MFA.Required {
		mfaEnabled, err := s.totpSvc.IsMFAEnabled(user.ID)
		if err != nil {
			return nil, false, fmt.Errorf("failed to check MFA status: %w", err)
		}

		if mfaEnabled {
			if totpCode == "" {
				return user, false, nil
			}

			valid, err := s.totpSvc.VerifyLogin(user.ID, totpCode)
			if err != nil || !valid {
				return nil, false, fmt.Errorf("invalid TOTP code")
			}
		}
	}

	return user, true, nil
}

func (s *UserService) SetAttributes(id string, attrs map[string]string) error {
	defer telemetry.Step("service.UserService.SetAttributes")()
	return s.userRepo.SetAttributes(id, attrs)
}

func (s *UserService) UpdateProfile(user *models.User) error {
	defer telemetry.Step("service.UserService.UpdateProfile")()
	if user == nil {
		return fmt.Errorf("user is required")
	}
	user.Email = normalizeEmail(user.Email)
	if err := s.reserveEmail(user.ID, user.Email); err != nil {
		return err
	}
	if err := s.userRepo.UpdateProfile(user); err != nil {
		if emailConflict(err) {
			return ErrEmailTaken
		}
		return err
	}
	return nil
}

func (s *UserService) SetPassword(id, password string) error {
	defer telemetry.Step("service.UserService.SetPassword")()
	if password == "" {
		return fmt.Errorf("password is required")
	}
	username := ""
	if user, err := s.userRepo.GetByID(id); err == nil && user != nil {
		username = user.Username
	}
	if s.cfg != nil {
		if err := CheckPassword(s.cfg.Password, username, password); err != nil {
			return err
		}
	}
	hashed, err := s.hasher.Hash(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	return s.userRepo.UpdatePasswordHash(id, hashed)
}

func (s *UserService) ChangePassword(id, current, next string) error {
	defer telemetry.Step("service.UserService.ChangePassword")()
	if next == "" {
		return fmt.Errorf("password is required")
	}
	user, err := s.userRepo.GetByID(id)
	if err != nil {
		return fmt.Errorf("user not found")
	}
	if err := s.hasher.Verify(user.PasswordHash, current); err != nil {
		return fmt.Errorf("invalid credentials")
	}
	return s.SetPassword(id, next)
}

func (s *UserService) TouchLastLogin(id string) {
	defer telemetry.Step("service.UserService.TouchLastLogin")()
	_ = s.userRepo.TouchLastLogin(id, time.Now())
}
