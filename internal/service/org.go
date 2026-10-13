package service

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/bravo68web/oauth-impl/internal/config"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/repository"
	"github.com/google/uuid"
)

var (
	ErrOrgDisabled = errors.New("organizations are disabled")
	ErrOrgInvalid  = errors.New("unknown organization")
	ErrOrgDenied   = errors.New("user is not a member of the organization")
)

// OrgChoice is the organization stamped on a token.
type OrgChoice struct {
	ID   string
	Slug string
	Name string
}

type OrgService struct {
	repo *repository.OrgRepository
	cfg  *config.Config
}

func NewOrgService(repo *repository.OrgRepository, cfg *config.Config) *OrgService {
	return &OrgService{repo: repo, cfg: cfg}
}

func (s *OrgService) Enabled() bool {
	return s != nil && s.cfg != nil && s.cfg.Org.Enabled
}

func (s *OrgService) Autolookup() bool {
	return s.Enabled() && s.cfg.Org.EnabledDomainBasedAutolookup
}

// Resolve picks the organization for a token. A nil choice means the token
// has no organization. Domain autolookup fills an omitted organization only
// when that flag is on and the user is already a member of the matching org.
func (s *OrgService) Resolve(client *models.Client, user *models.User, requested string) (*OrgChoice, error) {
	requested = strings.TrimSpace(requested)
	if !s.Enabled() {
		if requested != "" {
			return nil, ErrOrgDisabled
		}
		return nil, nil
	}
	var (
		target *models.Organization
		err    error
	)
	if client != nil && client.OrgID != "" {
		target, err = s.repo.Get(client.OrgID)
		if err != nil {
			return nil, ErrOrgInvalid
		}
		if requested != "" && requested != target.ID && requested != target.Slug {
			return nil, ErrOrgInvalid
		}
	} else if requested != "" {
		target, err = s.repo.Get(requested)
		if err != nil {
			target, err = s.repo.GetBySlug(requested)
		}
		if err != nil {
			return nil, ErrOrgInvalid
		}
	} else if s.Autolookup() && user != nil {
		if domain := EmailDomain(user.Email); domain != "" {
			found, lookErr := s.repo.GetByDomain(domain)
			if lookErr == nil {
				member, memErr := s.repo.IsMember(found.ID, user.ID)
				if memErr != nil {
					return nil, memErr
				}
				if member {
					target = found
				}
			}
		}
	}
	if target == nil {
		return nil, nil
	}
	if user == nil {
		if client != nil && client.OrgID == target.ID {
			return choice(target), nil
		}
		return nil, ErrOrgDenied
	}
	member, err := s.repo.IsMember(target.ID, user.ID)
	if err != nil {
		return nil, err
	}
	if !member {
		return nil, ErrOrgDenied
	}
	return choice(target), nil
}

func choice(org *models.Organization) *OrgChoice {
	return &OrgChoice{ID: org.ID, Slug: org.Slug, Name: org.Name}
}

func (s *OrgService) Create(name, slug string, domains []string, logoURL string) (*models.Organization, error) {
	if !s.Enabled() {
		return nil, ErrOrgDisabled
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	if !validSlug(slug) {
		return nil, fmt.Errorf("slug must be lowercase letters, numbers, and hyphens")
	}
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("name is required")
	}
	logoURL, err := normalizeLogoURL(logoURL)
	if err != nil {
		return nil, err
	}
	org := &models.Organization{ID: uuid.NewString(), Slug: slug, Name: strings.TrimSpace(name), LogoURL: logoURL, CreatedAt: time.Now().UTC()}
	if err := s.repo.Create(org); err != nil {
		return nil, err
	}
	for _, domain := range domains {
		if err := s.AddDomain(org.ID, domain); err != nil {
			return nil, err
		}
	}
	return s.repo.Get(org.ID)
}

func normalizeLogoURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", fmt.Errorf("logo_url must be an absolute http or https url")
	}
	return raw, nil
}

func (s *OrgService) AddDomain(orgID, domain string) error {
	if !s.Enabled() {
		return ErrOrgDisabled
	}
	domain, err := NormalizeDomain(domain)
	if err != nil {
		return err
	}
	if _, err := s.repo.Get(orgID); err != nil {
		if org, slugErr := s.repo.GetBySlug(orgID); slugErr == nil {
			orgID = org.ID
		} else {
			return ErrOrgInvalid
		}
	}
	return s.repo.AddDomain(orgID, domain)
}

func (s *OrgService) AddMember(orgID, userID, role string) error {
	if !s.Enabled() {
		return ErrOrgDisabled
	}
	switch role {
	case "", "member":
		role = "member"
	case "admin":
	default:
		return fmt.Errorf("role must be member or admin")
	}
	if _, err := s.repo.Get(orgID); err != nil {
		org, slugErr := s.repo.GetBySlug(orgID)
		if slugErr != nil {
			return ErrOrgInvalid
		}
		orgID = org.ID
	}
	return s.repo.AddMember(orgID, userID, role, time.Now().UTC())
}

// NeedsChoice reports that the browser must ask which organization to use.
// A bound client, or a request that already names an organization, does not ask.
func (s *OrgService) NeedsChoice(client *models.Client, userID, requested string) (bool, error) {
	if !s.Enabled() || strings.TrimSpace(requested) != "" || (client != nil && client.OrgID != "") {
		return false, nil
	}
	orgs, err := s.ListForUser(userID)
	if err != nil {
		return false, err
	}
	return len(orgs) > 1, nil
}

func (s *OrgService) ListForUser(userID string) ([]*models.Organization, error) {
	if !s.Enabled() {
		return nil, nil
	}
	return s.repo.ListForUser(userID)
}

func (s *OrgService) List() ([]*models.Organization, error) {
	if !s.Enabled() {
		return nil, ErrOrgDisabled
	}
	return s.repo.List()
}

func (s *OrgService) Get(idOrSlug string) (*models.Organization, error) {
	org, err := s.repo.Get(idOrSlug)
	if err == nil {
		return org, nil
	}
	return s.repo.GetBySlug(idOrSlug)
}

// EmailDomain returns the host part of an email address.
func EmailDomain(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return email[at+1:]
}

// NormalizeDomain checks a bare hostname used for organization lookup.
func NormalizeDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "@")
	if domain == "" || strings.Contains(domain, " ") || strings.Contains(domain, "/") || strings.Contains(domain, ":") || strings.Contains(domain, "*") {
		return "", fmt.Errorf("domain must be a bare hostname")
	}
	for _, r := range domain {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' {
			continue
		}
		return "", fmt.Errorf("domain must be a bare hostname")
	}
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", fmt.Errorf("domain must be a bare hostname")
	}
	return domain, nil
}

func validSlug(slug string) bool {
	if slug == "" || len(slug) > 64 {
		return false
	}
	for i, r := range slug {
		if unicode.IsDigit(r) || (r >= 'a' && r <= 'z') {
			continue
		}
		if r == '-' && i > 0 {
			continue
		}
		return false
	}
	return true
}
