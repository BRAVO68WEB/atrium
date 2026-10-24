package repository

import (
	"database/sql"
	"time"

	"github.com/bravo68web/oauth-impl/internal/database"
	"github.com/bravo68web/oauth-impl/internal/models"
	"github.com/bravo68web/oauth-impl/internal/telemetry"
)

type OrgRepository struct {
	db database.SQL
}

func NewOrgRepository(db database.SQL) *OrgRepository {
	defer telemetry.Step("repository.NewOrgRepository")()
	return &OrgRepository{db: db}
}

func (r *OrgRepository) Create(org *models.Organization) error {
	defer telemetry.Step("repository.OrgRepository.Create")()
	_, err := r.db.Exec(`INSERT INTO organizations (id, slug, name, logo_url, created_at) VALUES (?, ?, ?, ?, ?)`,
		org.ID, org.Slug, org.Name, org.LogoURL, org.CreatedAt)
	return err
}

func scanOrg(scan func(dest ...any) error) (*models.Organization, error) {
	defer telemetry.Step("repository.scanOrg")()
	org := &models.Organization{}
	var created dbTime
	if err := scan(&org.ID, &org.Slug, &org.Name, &org.LogoURL, &created); err != nil {
		return nil, err
	}
	org.CreatedAt = created.Time
	return org, nil
}

func (r *OrgRepository) Get(id string) (*models.Organization, error) {
	defer telemetry.Step("repository.OrgRepository.Get")()
	org, err := scanOrg(r.db.QueryRow(`SELECT id, slug, name, logo_url, created_at FROM organizations WHERE id = ?`, id).Scan)
	if err != nil {
		return nil, err
	}
	return r.withDomains(org)
}

func (r *OrgRepository) GetBySlug(slug string) (*models.Organization, error) {
	defer telemetry.Step("repository.OrgRepository.GetBySlug")()
	org, err := scanOrg(r.db.QueryRow(`SELECT id, slug, name, logo_url, created_at FROM organizations WHERE slug = ?`, slug).Scan)
	if err != nil {
		return nil, err
	}
	return r.withDomains(org)
}

func (r *OrgRepository) GetByDomain(domain string) (*models.Organization, error) {
	defer telemetry.Step("repository.OrgRepository.GetByDomain")()
	org, err := scanOrg(r.db.QueryRow(`SELECT o.id, o.slug, o.name, o.logo_url, o.created_at
		FROM organizations o JOIN organization_domains d ON d.org_id = o.id
		WHERE d.domain = ?`, domain).Scan)
	if err != nil {
		return nil, err
	}
	return r.withDomains(org)
}

func (r *OrgRepository) ListForUser(userID string) ([]*models.Organization, error) {
	defer telemetry.Step("repository.OrgRepository.ListForUser")()
	return r.list(`SELECT o.id, o.slug, o.name, o.logo_url, o.created_at
		FROM organizations o
		JOIN org_memberships m ON m.org_id = o.id
		WHERE m.user_id = ?
		ORDER BY o.name`, userID)
}

func (r *OrgRepository) List() ([]*models.Organization, error) {
	defer telemetry.Step("repository.OrgRepository.List")()
	return r.list(`SELECT id, slug, name, logo_url, created_at FROM organizations ORDER BY slug`)
}

// list reads every organization before loading domains. SQLite allows one
// open statement, so a domain query cannot run while these rows are open.
func (r *OrgRepository) list(query string, args ...any) ([]*models.Organization, error) {
	defer telemetry.Step("repository.OrgRepository.list")()
	rows, err := r.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	out := []*models.Organization{}
	for rows.Next() {
		org, err := scanOrg(rows.Scan)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		out = append(out, org)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	for i, org := range out {
		full, err := r.withDomains(org)
		if err != nil {
			return nil, err
		}
		out[i] = full
	}
	return out, nil
}

func (r *OrgRepository) AddDomain(orgID, domain string) error {
	defer telemetry.Step("repository.OrgRepository.AddDomain")()
	_, err := r.db.Exec(`INSERT INTO organization_domains (domain, org_id) VALUES (?, ?)`, domain, orgID)
	return err
}

func (r *OrgRepository) RemoveDomain(orgID, domain string) error {
	defer telemetry.Step("repository.OrgRepository.RemoveDomain")()
	res, err := r.db.Exec(`DELETE FROM organization_domains WHERE org_id = ? AND domain = ?`, orgID, domain)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *OrgRepository) AddMember(orgID, userID, role string, at time.Time) error {
	defer telemetry.Step("repository.OrgRepository.AddMember")()
	_, err := r.db.Exec(`INSERT INTO org_memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)`,
		orgID, userID, role, at)
	return err
}

func (r *OrgRepository) RemoveMember(orgID, userID string) error {
	defer telemetry.Step("repository.OrgRepository.RemoveMember")()
	res, err := r.db.Exec(`DELETE FROM org_memberships WHERE org_id = ? AND user_id = ?`, orgID, userID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (r *OrgRepository) IsMember(orgID, userID string) (bool, error) {
	defer telemetry.Step("repository.OrgRepository.IsMember")()
	var n int
	err := r.db.QueryRow(`SELECT COUNT(*) FROM org_memberships WHERE org_id = ? AND user_id = ?`, orgID, userID).Scan(&n)
	return n > 0, err
}

func (r *OrgRepository) SetClientOrg(clientID, orgID string) error {
	defer telemetry.Step("repository.OrgRepository.SetClientOrg")()
	_, err := r.db.Exec(`UPDATE clients SET org_id = ? WHERE id = ?`, orgID, clientID)
	return err
}

func (r *OrgRepository) withDomains(org *models.Organization) (*models.Organization, error) {
	defer telemetry.Step("repository.OrgRepository.withDomains")()
	rows, err := r.db.Query(`SELECT domain FROM organization_domains WHERE org_id = ? ORDER BY domain`, org.ID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		org.Domains = append(org.Domains, domain)
	}
	return org, rows.Err()
}
