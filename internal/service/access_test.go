package service

import (
	"errors"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/testpg"
)

func TestRoleScopesFollowTheOrganization(t *testing.T) {
	db := testpg.Open(t)
	resources := repository.NewResourceRepository(db)
	if err := resources.Create(&models.Resource{
		URI: "https://api.envsync.cloud", Name: "EnvSync",
		Scopes: []string{"projects:read", "billing:read", "audit:read", "management"},
	}); err != nil {
		t.Fatal(err)
	}
	users := repository.NewUserRepository(db)
	if err := users.Create(&models.User{ID: "user-1", Username: "ada", PasswordHash: "x", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	orgs := repository.NewOrgRepository(db)
	if err := orgs.Create(&models.Organization{ID: "org-1", Slug: "acme-corp", Name: "Acme", CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	access := NewAccessService(repository.NewRoleRepository(db), resources, users, orgs)

	viewer, err := access.CreateRole("viewer", "Read projects")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.SetRoleScopes(viewer.ID, []models.RoleScope{{Resource: "https://api.envsync.cloud", Scope: "missing"}}); !errors.Is(err, ErrUnknownScope) {
		t.Fatalf("missing scope err %v", err)
	}
	if _, err := access.SetRoleScopes(viewer.ID, []models.RoleScope{{Resource: "https://api.envsync.cloud", Scope: "management"}}); !errors.Is(err, ErrManagementGrant) {
		t.Fatalf("management err %v", err)
	}
	if _, err := access.SetRoleScopes(viewer.ID, []models.RoleScope{{Resource: "https://api.envsync.cloud", Scope: "projects:read"}}); err != nil {
		t.Fatal(err)
	}
	accountant, err := access.CreateRole("accountant", "Read billing")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := access.SetRoleScopes(accountant.ID, []models.RoleScope{{Resource: "https://api.envsync.cloud", Scope: "billing:read"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := access.AssignRole("user-1", viewer.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := access.AssignRole("user-1", accountant.ID, "acme-corp"); err != nil {
		t.Fatal(err)
	}
	if _, err := access.AssignScope("user-1", "https://api.envsync.cloud", "audit:read", ""); err != nil {
		t.Fatal(err)
	}
	listed, err := access.UserAccess("user-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range listed.Roles {
		if role.Name == "accountant" && (role.OrgName != "Acme" || role.OrgSlug != "acme-corp" || role.OrgID != "org-1") {
			t.Fatalf("accountant org %+v", role)
		}
		if role.Name == "viewer" && (role.OrgID != "" || role.OrgName != "") {
			t.Fatalf("viewer should be global %+v", role)
		}
	}

	global, err := access.Narrow("user-1", "", []string{"openid", "projects:read", "billing:read", "audit:read", "management"})
	if err != nil {
		t.Fatal(err)
	}
	if joinScopes(global) != "openid projects:read audit:read" {
		t.Fatalf("global %v", global)
	}
	org, err := access.Narrow("user-1", "org-1", []string{"openid", "projects:read", "billing:read", "audit:read"})
	if err != nil {
		t.Fatal(err)
	}
	if joinScopes(org) != "openid projects:read billing:read audit:read" {
		t.Fatalf("org %v", org)
	}
	machine, err := access.Narrow("", "", []string{"management", "audit:read"})
	if err != nil {
		t.Fatal(err)
	}
	if joinScopes(machine) != "management audit:read" {
		t.Fatalf("machine %v", machine)
	}
}

func joinScopes(scopes []string) string {
	out := ""
	for i, scope := range scopes {
		if i > 0 {
			out += " "
		}
		out += scope
	}
	return out
}
