package service

import (
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/bravo68web/atrium/pkg/passhash"
	"github.com/google/uuid"
)

const maxImportUsers = 200

// ImportDocument is the user migration file and the import API body.
type ImportDocument struct {
	Mode  string       `json:"mode"`
	Users []ImportUser `json:"users"`
}

// ImportUser is one account in an import or export document.
type ImportUser struct {
	Username         string            `json:"username"`
	Email            string            `json:"email,omitempty"`
	EmailVerified    bool              `json:"email_verified,omitempty"`
	Password         string            `json:"password,omitempty"`
	PasswordHash     string            `json:"password_hash,omitempty"`
	GivenName        string            `json:"given_name,omitempty"`
	FamilyName       string            `json:"family_name,omitempty"`
	PhoneNumber      string            `json:"phone_number,omitempty"`
	Disabled         bool              `json:"disabled,omitempty"`
	MigrationPending bool              `json:"migration_pending,omitempty"`
	TOTPSecret       string            `json:"totp_secret,omitempty"`
	Attributes       map[string]string `json:"attributes,omitempty"`
	UserMetadata     map[string]string `json:"user_metadata,omitempty"`
	Orgs             []string          `json:"orgs,omitempty"`
}

// ImportError is one row the import did not write.
type ImportError struct {
	Index    int    `json:"index"`
	Username string `json:"username,omitempty"`
	Error    string `json:"error"`
}

// ImportResult is the import response.
type ImportResult struct {
	Created int           `json:"created"`
	Updated int           `json:"updated"`
	Errors  []ImportError `json:"errors"`
}

type orgDirectory interface {
	Enabled() bool
	Get(idOrSlug string) (*models.Organization, error)
	AddMember(orgID, userID, role string) error
	ListForUser(userID string) ([]*models.Organization, error)
}

// ImportUsers writes the document. dry checks every row and writes nothing.
// One bad row does not roll back rows already written.
func (s *UserService) ImportUsers(doc ImportDocument, dry bool, orgs orgDirectory) (ImportResult, error) {
	defer telemetry.Step("service.UserService.ImportUsers")()
	mode := strings.ToLower(strings.TrimSpace(doc.Mode))
	if mode == "" {
		mode = "create"
	}
	if mode != "create" && mode != "upsert" {
		return ImportResult{}, fmt.Errorf("mode must be create or upsert")
	}
	if len(doc.Users) > maxImportUsers {
		return ImportResult{}, fmt.Errorf("at most %d users per import", maxImportUsers)
	}
	result := ImportResult{Errors: []ImportError{}}
	for i, row := range doc.Users {
		kind, err := s.importRow(mode, row, dry, orgs)
		if err != nil {
			result.Errors = append(result.Errors, ImportError{Index: i, Username: strings.TrimSpace(row.Username), Error: err.Error()})
			continue
		}
		switch kind {
		case "created":
			result.Created++
		case "updated":
			result.Updated++
		}
	}
	return result, nil
}

func (s *UserService) importRow(mode string, row ImportUser, dry bool, orgs orgDirectory) (string, error) {
	defer telemetry.Step("service.UserService.importRow")()
	row.Username = strings.TrimSpace(row.Username)
	row.Email = normalizeEmail(row.Email)
	row.PasswordHash = strings.TrimSpace(row.PasswordHash)
	row.TOTPSecret = strings.TrimSpace(row.TOTPSecret)
	if row.Username == "" {
		return "", fmt.Errorf("username is required")
	}
	if row.Password != "" && row.PasswordHash != "" {
		return "", fmt.Errorf("set password or password_hash, not both")
	}
	hash, err := s.importHash(row)
	if err != nil {
		return "", err
	}
	if row.TOTPSecret != "" && !validTOTPSecret(row.TOTPSecret) {
		return "", fmt.Errorf("totp_secret is not base32")
	}
	if err := CheckMetadata(row.Attributes); err != nil {
		return "", err
	}
	if err := CheckMetadata(row.UserMetadata); err != nil {
		return "", err
	}
	if err := s.checkOrgs(orgs, row.Orgs); err != nil {
		return "", err
	}
	existing, err := s.userRepo.GetByUsername(row.Username)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if existing != nil {
		if mode == "create" {
			return "", fmt.Errorf("username already exists")
		}
		if dry {
			return "updated", nil
		}
		if err := s.applyImport(existing, row, hash, orgs); err != nil {
			return "", err
		}
		return "updated", nil
	}
	if hash == "" && !row.MigrationPending {
		return "", fmt.Errorf("password or password_hash is required")
	}
	if hash != "" && row.MigrationPending {
		return "", fmt.Errorf("migration_pending cannot include a password")
	}
	if dry {
		return "created", nil
	}
	user := &models.User{
		ID:               uuid.New().String(),
		Username:         row.Username,
		PasswordHash:     hash,
		Email:            row.Email,
		PhoneNumber:      row.PhoneNumber,
		GivenName:        row.GivenName,
		FamilyName:       row.FamilyName,
		EmailVerified:    row.EmailVerified && row.Email != "",
		Disabled:         row.Disabled,
		HasPassword:      hash != "",
		MigrationPending: row.MigrationPending,
		Attributes:       row.Attributes,
		UserMetadata:     row.UserMetadata,
		CreatedAt:        time.Now().UTC(),
	}
	if err := s.reserveEmail("", user.Email); err != nil {
		return "", err
	}
	if err := s.userRepo.Create(user); err != nil {
		if emailConflict(err) {
			return "", ErrEmailTaken
		}
		return "", err
	}
	if row.TOTPSecret != "" {
		if err := s.userRepo.UpdateMFA(user.ID, true, row.TOTPSecret); err != nil {
			return "", err
		}
	}
	if err := s.addOrgs(orgs, user.ID, row.Orgs); err != nil {
		return "", err
	}
	return "created", nil
}

func (s *UserService) importHash(row ImportUser) (string, error) {
	defer telemetry.Step("service.UserService.importHash")()
	if row.PasswordHash != "" {
		if !passhash.Accepts(s.hasher, row.PasswordHash) {
			return "", fmt.Errorf("password hash is not accepted by the server hasher")
		}
		return row.PasswordHash, nil
	}
	if row.Password == "" {
		return "", nil
	}
	if s.cfg != nil {
		if err := CheckPassword(s.cfg.Password, row.Username, row.Password); err != nil {
			return "", err
		}
	}
	hashed, err := s.hasher.Hash(row.Password)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return hashed, nil
}

func (s *UserService) applyImport(user *models.User, row ImportUser, hash string, orgs orgDirectory) error {
	defer telemetry.Step("service.UserService.applyImport")()
	user.Email = row.Email
	user.PhoneNumber = row.PhoneNumber
	user.GivenName = row.GivenName
	user.FamilyName = row.FamilyName
	user.EmailVerified = row.EmailVerified && row.Email != ""
	user.Disabled = row.Disabled
	if err := s.UpdateProfile(user); err != nil {
		return err
	}
	if row.Attributes != nil {
		if err := s.SetAttributes(user.ID, row.Attributes); err != nil {
			return err
		}
	}
	if row.UserMetadata != nil {
		if err := s.SetUserMetadata(user.ID, row.UserMetadata); err != nil {
			return err
		}
	}
	if row.MigrationPending {
		if hash != "" {
			return fmt.Errorf("migration_pending cannot include a password")
		}
		if err := s.userRepo.SetPasswordState(user.ID, "", true); err != nil {
			return err
		}
	} else if hash != "" {
		if err := s.userRepo.UpdatePasswordHash(user.ID, hash); err != nil {
			return err
		}
	}
	if row.TOTPSecret != "" {
		if err := s.userRepo.UpdateMFA(user.ID, true, row.TOTPSecret); err != nil {
			return err
		}
	}
	return s.addOrgs(orgs, user.ID, row.Orgs)
}

func (s *UserService) checkOrgs(orgs orgDirectory, slugs []string) error {
	defer telemetry.Step("service.UserService.checkOrgs")()
	if len(slugs) == 0 {
		return nil
	}
	if orgs == nil || !orgs.Enabled() {
		return fmt.Errorf("organizations are disabled")
	}
	for _, slug := range slugs {
		slug = strings.TrimSpace(slug)
		if slug == "" {
			return fmt.Errorf("organization slug is empty")
		}
		if _, err := orgs.Get(slug); err != nil {
			return fmt.Errorf("unknown organization")
		}
	}
	return nil
}

func (s *UserService) addOrgs(orgs orgDirectory, userID string, slugs []string) error {
	defer telemetry.Step("service.UserService.addOrgs")()
	for _, slug := range slugs {
		slug = strings.TrimSpace(slug)
		err := orgs.AddMember(slug, userID, "member")
		if err != nil && !duplicateMember(err) {
			return err
		}
	}
	return nil
}

func duplicateMember(err error) bool {
	defer telemetry.Step("service.duplicateMember")()
	if err == nil {
		return false
	}
	text := err.Error()
	return strings.Contains(text, "UNIQUE") || strings.Contains(text, "duplicate")
}

func validTOTPSecret(secret string) bool {
	defer telemetry.Step("service.validTOTPSecret")()
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if len(secret) < 16 {
		return false
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err == nil {
		return true
	}
	_, err := base32.StdEncoding.DecodeString(secret)
	return err == nil
}

// ExportUsers returns an upsert document. Secrets are omitted unless includeSecrets is set.
func (s *UserService) ExportUsers(includeSecrets bool, orgs orgDirectory) (ImportDocument, error) {
	defer telemetry.Step("service.UserService.ExportUsers")()
	users, err := s.userRepo.List()
	if err != nil {
		return ImportDocument{}, err
	}
	doc := ImportDocument{Mode: "upsert", Users: []ImportUser{}}
	for _, user := range users {
		row := ImportUser{
			Username:         user.Username,
			Email:            user.Email,
			EmailVerified:    user.EmailVerified,
			GivenName:        user.GivenName,
			FamilyName:       user.FamilyName,
			PhoneNumber:      user.PhoneNumber,
			Disabled:         user.Disabled,
			MigrationPending: user.MigrationPending,
			Attributes:       user.Attributes,
			UserMetadata:     user.UserMetadata,
		}
		if includeSecrets {
			row.PasswordHash = user.PasswordHash
			if _, secret, err := s.userRepo.GetMFA(user.ID); err == nil {
				row.TOTPSecret = secret
			}
		}
		if orgs != nil && orgs.Enabled() {
			list, err := orgs.ListForUser(user.ID)
			if err != nil {
				return ImportDocument{}, err
			}
			for _, org := range list {
				row.Orgs = append(row.Orgs, org.Slug)
			}
		}
		doc.Users = append(doc.Users, row)
	}
	return doc, nil
}
