package service

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
)

var (
	ErrRoleExists      = errors.New("role already exists")
	ErrUnknownRole     = errors.New("role not found")
	ErrUnknownScope    = errors.New("scope is not on that resource")
	ErrManagementGrant = errors.New("management cannot be granted by a role")
	ErrUnknownOrg      = errors.New("unknown organization")
	ErrGrantMissing    = errors.New("grant not found")
)

// AccessService stores roles and the scopes those roles put on a user token.
type AccessService struct {
	roles     *repository.RoleRepository
	resources *repository.ResourceRepository
	users     *repository.UserRepository
	orgs      *repository.OrgRepository
}

func NewAccessService(roles *repository.RoleRepository, resources *repository.ResourceRepository, users *repository.UserRepository, orgs *repository.OrgRepository) *AccessService {
	defer telemetry.Step("service.NewAccessService")()
	return &AccessService{roles: roles, resources: resources, users: users, orgs: orgs}
}

func (s *AccessService) CreateRole(name, description string) (*models.Role, error) {
	defer telemetry.Step("service.AccessService.CreateRole")()
	name = strings.TrimSpace(name)
	if !validRoleName(name) {
		return nil, fmt.Errorf("role name must be 1-64 letters, digits, or .:_-")
	}
	if existing, err := s.roles.GetByName(name); err == nil && existing != nil {
		return nil, ErrRoleExists
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	role := &models.Role{
		ID:          uuid.New().String(),
		Name:        name,
		Description: strings.TrimSpace(description),
		Scopes:      []models.RoleScope{},
		CreatedAt:   time.Now().UTC(),
	}
	if err := s.roles.Create(role); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") || strings.Contains(err.Error(), "duplicate") {
			return nil, ErrRoleExists
		}
		return nil, err
	}
	return role, nil
}

func (s *AccessService) ListRoles() ([]*models.Role, error) {
	defer telemetry.Step("service.AccessService.ListRoles")()
	roles, err := s.roles.List()
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		scopes, err := s.roles.Scopes(role.ID)
		if err != nil {
			return nil, err
		}
		if scopes == nil {
			scopes = []models.RoleScope{}
		}
		role.Scopes = scopes
	}
	return roles, nil
}

func (s *AccessService) GetRole(id string) (*models.Role, error) {
	defer telemetry.Step("service.AccessService.GetRole")()
	role, err := s.roles.Get(id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnknownRole
		}
		return nil, err
	}
	scopes, err := s.roles.Scopes(role.ID)
	if err != nil {
		return nil, err
	}
	if scopes == nil {
		scopes = []models.RoleScope{}
	}
	role.Scopes = scopes
	return role, nil
}

func (s *AccessService) UpdateRole(id, name, description string, rename, redescribe bool) (*models.Role, error) {
	defer telemetry.Step("service.AccessService.UpdateRole")()
	role, err := s.GetRole(id)
	if err != nil {
		return nil, err
	}
	if rename {
		name = strings.TrimSpace(name)
		if !validRoleName(name) {
			return nil, fmt.Errorf("role name must be 1-64 letters, digits, or .:_-")
		}
		if name != role.Name {
			if existing, err := s.roles.GetByName(name); err == nil && existing != nil && existing.ID != role.ID {
				return nil, ErrRoleExists
			} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
		}
		role.Name = name
	}
	if redescribe {
		role.Description = strings.TrimSpace(description)
	}
	if err := s.roles.Update(role); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUnknownRole
		}
		return nil, err
	}
	return role, nil
}

func (s *AccessService) DeleteRole(id string) error {
	defer telemetry.Step("service.AccessService.DeleteRole")()
	if err := s.roles.Delete(id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUnknownRole
		}
		return err
	}
	return nil
}

func (s *AccessService) SetRoleScopes(roleID string, scopes []models.RoleScope) (*models.Role, error) {
	defer telemetry.Step("service.AccessService.SetRoleScopes")()
	if _, err := s.GetRole(roleID); err != nil {
		return nil, err
	}
	clean, err := s.cleanGrants(scopes)
	if err != nil {
		return nil, err
	}
	if err := s.roles.ReplaceScopes(roleID, clean); err != nil {
		return nil, err
	}
	return s.GetRole(roleID)
}

func (s *AccessService) AssignRole(userID, roleID, org string) (models.UserRole, error) {
	defer telemetry.Step("service.AccessService.AssignRole")()
	if err := s.requireUser(userID); err != nil {
		return models.UserRole{}, err
	}
	role, err := s.GetRole(roleID)
	if err != nil {
		return models.UserRole{}, err
	}
	orgID, err := s.resolveOrg(org)
	if err != nil {
		return models.UserRole{}, err
	}
	found, err := s.roles.HasRole(userID, roleID, orgID)
	if err != nil {
		return models.UserRole{}, err
	}
	if !found {
		if err := s.roles.AssignRole(userID, roleID, orgID); err != nil {
			return models.UserRole{}, err
		}
	}
	return models.UserRole{UserID: userID, RoleID: role.ID, Name: role.Name, OrgID: orgID}, nil
}

func (s *AccessService) RemoveRole(userID, roleID, org string) error {
	defer telemetry.Step("service.AccessService.RemoveRole")()
	orgID, err := s.resolveOrg(org)
	if err != nil {
		return err
	}
	if err := s.roles.RemoveRole(userID, roleID, orgID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrGrantMissing
		}
		return err
	}
	return nil
}

func (s *AccessService) AssignScope(userID, resource, scope, org string) (models.UserScope, error) {
	defer telemetry.Step("service.AccessService.AssignScope")()
	if err := s.requireUser(userID); err != nil {
		return models.UserScope{}, err
	}
	resource = strings.TrimSpace(resource)
	scope = strings.TrimSpace(scope)
	if err := s.validGrant(resource, scope); err != nil {
		return models.UserScope{}, err
	}
	orgID, err := s.resolveOrg(org)
	if err != nil {
		return models.UserScope{}, err
	}
	found, err := s.roles.HasScope(userID, resource, scope, orgID)
	if err != nil {
		return models.UserScope{}, err
	}
	if !found {
		if err := s.roles.AssignScope(userID, resource, scope, orgID); err != nil {
			return models.UserScope{}, err
		}
	}
	return models.UserScope{UserID: userID, Resource: resource, Scope: scope, OrgID: orgID}, nil
}

func (s *AccessService) RemoveScope(userID, resource, scope, org string) error {
	defer telemetry.Step("service.AccessService.RemoveScope")()
	orgID, err := s.resolveOrg(org)
	if err != nil {
		return err
	}
	if err := s.roles.RemoveScope(userID, strings.TrimSpace(resource), strings.TrimSpace(scope), orgID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrGrantMissing
		}
		return err
	}
	return nil
}

func (s *AccessService) UserAccess(userID string) (models.UserAccess, error) {
	defer telemetry.Step("service.AccessService.UserAccess")()
	if err := s.requireUser(userID); err != nil {
		return models.UserAccess{}, err
	}
	roles, err := s.roles.UserRoles(userID)
	if err != nil {
		return models.UserAccess{}, err
	}
	scopes, err := s.roles.UserScopes(userID)
	if err != nil {
		return models.UserAccess{}, err
	}
	if roles == nil {
		roles = []models.UserRole{}
	}
	if scopes == nil {
		scopes = []models.UserScope{}
	}
	return models.UserAccess{Roles: roles, Scopes: scopes}, nil
}

// Narrow keeps identity scopes and drops any other scope the user does not hold.
// A client-credentials call has an empty user id and is returned unchanged.
func (s *AccessService) Narrow(userID, orgID string, scopes []string) ([]string, error) {
	defer telemetry.Step("service.AccessService.Narrow")()
	if s == nil || userID == "" {
		return scopes, nil
	}
	heldList, err := s.roles.HeldScopes(userID, orgID)
	if err != nil {
		return nil, err
	}
	held := map[string]struct{}{}
	for _, scope := range heldList {
		if scope == ManagementScope || identityScope(scope) {
			continue
		}
		held[scope] = struct{}{}
	}
	out := make([]string, 0, len(scopes))
	seen := map[string]struct{}{}
	for _, scope := range scopes {
		if _, ok := seen[scope]; ok {
			continue
		}
		if scope == ManagementScope {
			continue
		}
		if identityScope(scope) {
			out = append(out, scope)
			seen[scope] = struct{}{}
			continue
		}
		if _, ok := held[scope]; ok {
			out = append(out, scope)
			seen[scope] = struct{}{}
		}
	}
	return out, nil
}

func (s *AccessService) cleanGrants(scopes []models.RoleScope) ([]models.RoleScope, error) {
	defer telemetry.Step("service.AccessService.cleanGrants")()
	out := make([]models.RoleScope, 0, len(scopes))
	seen := map[string]struct{}{}
	for _, item := range scopes {
		item.Resource = strings.TrimSpace(item.Resource)
		item.Scope = strings.TrimSpace(item.Scope)
		key := item.Resource + "\x00" + item.Scope
		if _, ok := seen[key]; ok {
			continue
		}
		if err := s.validGrant(item.Resource, item.Scope); err != nil {
			return nil, err
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out, nil
}

func (s *AccessService) validGrant(resource, scope string) error {
	defer telemetry.Step("service.AccessService.validGrant")()
	if scope == ManagementScope {
		return ErrManagementGrant
	}
	if resource == "" || scope == "" {
		return ErrUnknownScope
	}
	if s.resources == nil {
		return ErrUnknownScope
	}
	row, err := s.resources.Get(resource)
	if err != nil {
		return ErrUnknownScope
	}
	for _, name := range row.Scopes {
		if name == scope {
			return nil
		}
	}
	return ErrUnknownScope
}

func (s *AccessService) requireUser(userID string) error {
	defer telemetry.Step("service.AccessService.requireUser")()
	if s.users == nil || strings.TrimSpace(userID) == "" {
		return fmt.Errorf("user not found")
	}
	user, err := s.users.GetByID(userID)
	if err != nil || user == nil {
		return fmt.Errorf("user not found")
	}
	return nil
}

func (s *AccessService) resolveOrg(org string) (string, error) {
	defer telemetry.Step("service.AccessService.resolveOrg")()
	org = strings.TrimSpace(org)
	if org == "" {
		return "", nil
	}
	if s.orgs == nil {
		return "", ErrUnknownOrg
	}
	if row, err := s.orgs.Get(org); err == nil && row != nil {
		return row.ID, nil
	}
	if row, err := s.orgs.GetBySlug(org); err == nil && row != nil {
		return row.ID, nil
	}
	return "", ErrUnknownOrg
}

func identityScope(scope string) bool {
	defer telemetry.Step("service.identityScope")()
	switch scope {
	case "openid", "profile", "email", "address", "phone", "offline_access":
		return true
	default:
		return false
	}
}

func validRoleName(name string) bool {
	defer telemetry.Step("service.validRoleName")()
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == ':' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}
