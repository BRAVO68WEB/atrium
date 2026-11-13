package service

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/repository"
)

func TestOrgResolveHonorsFlags(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "org.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	repo := repository.NewOrgRepository(db)
	cfg := &config.Config{}
	svc := NewOrgService(repo, cfg)
	user := &models.User{ID: "user-1", Email: "ada@acme.example"}
	client := &models.Client{ID: "app"}

	if choice, err := svc.Resolve(client, user, ""); err != nil || choice != nil {
		t.Fatalf("disabled choice=%v err=%v", choice, err)
	}
	if _, err := svc.Resolve(client, user, "acme"); err != ErrOrgDisabled {
		t.Fatalf("disabled request err=%v", err)
	}

	cfg.Org.Enabled = true
	org, err := svc.Create("Acme", "acme", []string{"acme.example"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(org.ID, user.ID, "member"); err != nil {
		t.Fatal(err)
	}
	if choice, err := svc.Resolve(client, user, ""); err != nil || choice != nil {
		t.Fatalf("no autolookup choice=%v err=%v", choice, err)
	}
	cfg.Org.EnabledDomainBasedAutolookup = true
	choice, err := svc.Resolve(client, user, "")
	if err != nil || choice == nil || choice.Slug != "acme" {
		t.Fatalf("autolookup choice=%v err=%v", choice, err)
	}
	stranger := &models.User{ID: "user-2", Email: "bea@acme.example"}
	if choice, err := svc.Resolve(client, stranger, ""); err != nil || choice != nil {
		t.Fatalf("non-member autolookup choice=%v err=%v", choice, err)
	}
	if _, err := svc.Resolve(client, stranger, "acme"); err != ErrOrgDenied {
		t.Fatalf("explicit non-member err=%v", err)
	}
	bound := &models.Client{ID: "bound", OrgID: org.ID}
	if _, err := svc.Resolve(bound, stranger, ""); err != ErrOrgDenied {
		t.Fatalf("bound non-member err=%v", err)
	}
	got, err := svc.Resolve(bound, user, "")
	if err != nil || got.ID != org.ID {
		t.Fatalf("bound member choice=%v err=%v", got, err)
	}
	if _, err := svc.Resolve(bound, user, "other"); err != ErrOrgInvalid {
		t.Fatalf("wrong org err=%v", err)
	}
	single, err := svc.NeedsChoice(client, user.ID, "")
	if err != nil || single {
		t.Fatalf("single membership needs=%v err=%v", single, err)
	}
	second, err := svc.Create("Beta", "beta", nil, "https://cdn.example/beta.png")
	if err != nil {
		t.Fatal(err)
	}
	if second.LogoURL != "https://cdn.example/beta.png" || second.Initial() != "B" {
		t.Fatalf("logo org = %+v", second)
	}
	if _, err := svc.Create("Nope", "nope", nil, "javascript:alert(1)"); err == nil {
		t.Fatal("expected a bad logo url to fail")
	}
	if err := svc.AddMember(second.ID, user.ID, "member"); err != nil {
		t.Fatal(err)
	}
	needs, err := svc.NeedsChoice(client, user.ID, "")
	if err != nil || !needs {
		t.Fatalf("needs choice=%v err=%v", needs, err)
	}
	needs, err = svc.NeedsChoice(client, user.ID, "acme")
	if err != nil || needs {
		t.Fatalf("named org should not ask, needs=%v err=%v", needs, err)
	}
	needs, err = svc.NeedsChoice(bound, user.ID, "")
	if err != nil || needs {
		t.Fatalf("bound client should not ask, needs=%v err=%v", needs, err)
	}
	if domain, err := NormalizeDomain(" ACME.Example "); err != nil || domain != "acme.example" {
		t.Fatalf("domain=%s err=%v", domain, err)
	}
	_ = time.Now()
}

func TestOrgUpdate(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "org.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Org.Enabled = true
	svc := NewOrgService(repository.NewOrgRepository(db), cfg)
	org, err := svc.Create("Acme", "acme", []string{"acme.example"}, "https://cdn.example/a.png")
	if err != nil {
		t.Fatal(err)
	}
	other, err := svc.Create("Beta", "beta", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	name := "Acme Labs"
	updated, err := svc.Update(org.ID, &name, nil, nil)
	if err != nil || updated.Name != "Acme Labs" || updated.Slug != "acme" || updated.LogoURL != "https://cdn.example/a.png" {
		t.Fatalf("name update %+v err=%v", updated, err)
	}
	if len(updated.Domains) != 1 || updated.Domains[0] != "acme.example" {
		t.Fatalf("domains %+v", updated.Domains)
	}
	slug := "acme-labs"
	logo := ""
	updated, err = svc.Update(org.Slug, nil, &slug, &logo)
	if err != nil || updated.Slug != "acme-labs" || updated.LogoURL != "" || updated.Name != "Acme Labs" {
		t.Fatalf("slug update %+v err=%v", updated, err)
	}
	taken := other.Slug
	if _, err := svc.Update(updated.ID, nil, &taken, nil); err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("duplicate slug err=%v", err)
	}
	bad := "not a url"
	if _, err := svc.Update(updated.ID, nil, nil, &bad); err == nil {
		t.Fatal("expected a bad logo url to fail")
	}
	blank := "  "
	if _, err := svc.Update(updated.ID, &blank, nil, nil); err == nil {
		t.Fatal("expected an empty name to fail")
	}
	if _, err := db.Exec(`INSERT INTO users (id, username, password_hash, email, given_name, family_name) VALUES (?, ?, ?, ?, ?, ?)`,
		"user-1", "ada", "x", "ada@acme.example", "Ada", "Lovelace"); err != nil {
		t.Fatal(err)
	}
	if err := svc.AddMember(org.ID, "user-1", "admin"); err != nil {
		t.Fatal(err)
	}
	members, err := svc.Members(updated.ID)
	if err != nil || len(members) != 1 || members[0].Username != "ada" || members[0].Email != "ada@acme.example" || members[0].Role != "admin" || members[0].GivenName != "Ada" {
		t.Fatalf("members %+v err=%v", members, err)
	}
}
