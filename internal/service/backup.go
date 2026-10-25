package service

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bravo68web/atrium/internal/database"
	"github.com/bravo68web/atrium/internal/models"
	"github.com/bravo68web/atrium/internal/oidc"
	"github.com/bravo68web/atrium/internal/repository"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/google/uuid"
)

const BackupVersion = 1

// ErrRestoreConflict is returned when a restore would mix two directories.
var ErrRestoreConflict = errors.New("server already has users or clients other than the management client")

// BackupDocument is the management backup file. It omits sessions, tokens,
// and other in-flight rows. Password hashes, client secrets, webhook
// secrets, TOTP secrets, and signing private keys are included.
type BackupDocument struct {
	Version          int                `json:"version"`
	Users            []BackupUser       `json:"users"`
	Clients          []models.Client    `json:"clients"`
	Organizations    []BackupOrg        `json:"organizations"`
	Consents         []models.Consent   `json:"consents"`
	Scopes           []models.Scope     `json:"scopes"`
	Resources        []models.Resource  `json:"resources"`
	Webhooks         []models.Webhook   `json:"webhooks"`
	SocialIdentities []BackupSocial     `json:"social_identities"`
	PushDevices      []BackupPushDevice `json:"push_devices"`
	PairwiseSubjects []BackupPairwise   `json:"pairwise_subjects"`
	SigningKeys      []BackupSigningKey `json:"signing_keys"`
}

// BackupUser keeps the account id so a restore does not mint a new one.
type BackupUser struct {
	ID            string            `json:"id"`
	Username      string            `json:"username"`
	Email         string            `json:"email,omitempty"`
	EmailVerified bool              `json:"email_verified,omitempty"`
	PasswordHash  string            `json:"password_hash"`
	GivenName     string            `json:"given_name,omitempty"`
	FamilyName    string            `json:"family_name,omitempty"`
	PhoneNumber   string            `json:"phone_number,omitempty"`
	Disabled      bool              `json:"disabled,omitempty"`
	TOTPSecret    string            `json:"totp_secret,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
	Orgs          []string          `json:"orgs,omitempty"`
	CreatedAt     time.Time         `json:"created_at,omitempty"`
}

type BackupOrg struct {
	ID        string         `json:"id"`
	Slug      string         `json:"slug"`
	Name      string         `json:"name"`
	LogoURL   string         `json:"logo_url,omitempty"`
	Domains   []string       `json:"domains,omitempty"`
	Members   []BackupMember `json:"members,omitempty"`
	CreatedAt time.Time      `json:"created_at,omitempty"`
}

type BackupMember struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

type BackupSocial struct {
	Provider  string `json:"provider"`
	Subject   string `json:"subject"`
	UserID    string `json:"user_id"`
	Email     string `json:"email,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

type BackupPushDevice struct {
	ID               string `json:"id"`
	UserID           string `json:"user_id"`
	ClientID         string `json:"client_id,omitempty"`
	JWK              string `json:"jwk"`
	JKT              string `json:"jkt"`
	CredentialHash   string `json:"credential_hash"`
	Platform         string `json:"platform,omitempty"`
	PushAddress      string `json:"push_address,omitempty"`
	InteractionTypes string `json:"interaction_types"`
	Attestation      string `json:"attestation,omitempty"`
	Status           string `json:"status"`
	CreatedAt        string `json:"created_at,omitempty"`
	LastUsedAt       string `json:"last_used_at,omitempty"`
	PreviousJWK      string `json:"previous_jwk,omitempty"`
	PreviousJKT      string `json:"previous_jkt,omitempty"`
	GraceUntil       string `json:"grace_until,omitempty"`
	IsPrimary        bool   `json:"is_primary,omitempty"`
}

type BackupPairwise struct {
	SectorID  string `json:"sector_id"`
	PPID      string `json:"ppid"`
	UserID    string `json:"user_id"`
	CreatedAt string `json:"created_at,omitempty"`
}

type BackupSigningKey struct {
	Kid        string `json:"kid"`
	Alg        string `json:"alg"`
	Status     string `json:"status"`
	PrivatePEM string `json:"private_pem"`
	CreatedAt  string `json:"created_at,omitempty"`
	RetireAt   string `json:"retire_at,omitempty"`
}

// RestoreResult counts the rows a restore wrote or would write.
type RestoreResult struct {
	DryRun           bool     `json:"dry_run"`
	Users            int      `json:"users"`
	Clients          int      `json:"clients"`
	Organizations    int      `json:"organizations"`
	Consents         int      `json:"consents"`
	Scopes           int      `json:"scopes"`
	Resources        int      `json:"resources"`
	Webhooks         int      `json:"webhooks"`
	SocialIdentities int      `json:"social_identities"`
	PushDevices      int      `json:"push_devices"`
	PairwiseSubjects int      `json:"pairwise_subjects"`
	SigningKeys      int      `json:"signing_keys"`
	Warnings         []string `json:"warnings,omitempty"`
}

// Backup reads and writes the durable directory. keys is reloaded after a
// restore that includes signing keys so JWKS matches the file.
type Backup struct {
	db           *database.DB
	users        *repository.UserRepository
	clients      *repository.ClientRepository
	orgs         *repository.OrgRepository
	scopes       *repository.ScopeRepository
	resources    *repository.ResourceRepository
	hooks        *repository.WebhookRepository
	managementID string
	keys         *oidc.KeySet
}

func NewBackup(db *database.DB, users *repository.UserRepository, clients *repository.ClientRepository, orgs *repository.OrgRepository, scopes *repository.ScopeRepository, resources *repository.ResourceRepository, hooks *repository.WebhookRepository, managementID string, keys *oidc.KeySet) *Backup {
	defer telemetry.Step("service.NewBackup")()
	return &Backup{
		db: db, users: users, clients: clients, orgs: orgs, scopes: scopes,
		resources: resources, hooks: hooks, managementID: strings.TrimSpace(managementID), keys: keys,
	}
}

func (b *Backup) Export() (BackupDocument, error) {
	defer telemetry.Step("service.Backup.Export")()
	doc := emptyBackup()
	if b == nil || b.db == nil {
		return doc, fmt.Errorf("backup is not configured")
	}
	var err error
	if doc.Users, err = b.exportUsers(); err != nil {
		return BackupDocument{}, err
	}
	clients, err := b.clients.List()
	if err != nil {
		return BackupDocument{}, err
	}
	doc.Clients = make([]models.Client, 0, len(clients))
	for _, client := range clients {
		if client != nil {
			doc.Clients = append(doc.Clients, *client)
		}
	}
	if doc.Organizations, err = b.exportOrgs(); err != nil {
		return BackupDocument{}, err
	}
	if doc.Consents, err = b.exportConsents(); err != nil {
		return BackupDocument{}, err
	}
	scopes, err := b.scopes.List()
	if err != nil {
		return BackupDocument{}, err
	}
	doc.Scopes = make([]models.Scope, 0, len(scopes))
	for _, row := range scopes {
		if row != nil {
			doc.Scopes = append(doc.Scopes, *row)
		}
	}
	resources, err := b.resources.List()
	if err != nil {
		return BackupDocument{}, err
	}
	doc.Resources = make([]models.Resource, 0, len(resources))
	for _, row := range resources {
		if row != nil {
			doc.Resources = append(doc.Resources, *row)
		}
	}
	hooks, err := b.hooks.List()
	if err != nil {
		return BackupDocument{}, err
	}
	doc.Webhooks = make([]models.Webhook, 0, len(hooks))
	for _, row := range hooks {
		if row != nil {
			doc.Webhooks = append(doc.Webhooks, *row)
		}
	}
	if doc.SocialIdentities, err = b.exportSocial(); err != nil {
		return BackupDocument{}, err
	}
	if doc.PushDevices, err = b.exportPush(); err != nil {
		return BackupDocument{}, err
	}
	if doc.PairwiseSubjects, err = b.exportPairwise(); err != nil {
		return BackupDocument{}, err
	}
	if doc.SigningKeys, err = b.exportKeys(); err != nil {
		return BackupDocument{}, err
	}
	return doc, nil
}

// Restore writes doc. dry writes nothing. force is required when the server
// already has a user or a client other than the management client.
func (b *Backup) Restore(doc BackupDocument, dry, force bool) (RestoreResult, error) {
	defer telemetry.Step("service.Backup.Restore")()
	if err := validateBackup(doc); err != nil {
		return RestoreResult{}, err
	}
	if b == nil || b.db == nil {
		return RestoreResult{}, fmt.Errorf("backup is not configured")
	}
	occupied, err := b.occupied()
	if err != nil {
		return RestoreResult{}, err
	}
	if occupied && !force {
		return RestoreResult{}, ErrRestoreConflict
	}
	result := countBackup(doc)
	result.DryRun = dry
	if len(doc.PairwiseSubjects) > 0 {
		result.Warnings = []string{"pairwise subjects were restored; they match this server only when oidc.pairwise_salt is unchanged"}
	}
	if dry {
		return result, nil
	}
	err = b.db.WithTx(func(q database.SQL) error {
		for _, org := range doc.Organizations {
			if err := upsertOrg(q, org); err != nil {
				return err
			}
		}
		for _, user := range doc.Users {
			if err := upsertUser(q, user); err != nil {
				return err
			}
		}
		for _, org := range doc.Organizations {
			if err := replaceOrgMembers(q, org); err != nil {
				return err
			}
		}
		for _, client := range doc.Clients {
			if err := upsertClient(q, client); err != nil {
				return err
			}
		}
		for _, row := range doc.Consents {
			if err := upsertConsent(q, row); err != nil {
				return err
			}
		}
		for _, row := range doc.Scopes {
			if err := upsertScope(q, row); err != nil {
				return err
			}
		}
		for _, row := range doc.Resources {
			if err := upsertResource(q, row); err != nil {
				return err
			}
		}
		for _, row := range doc.Webhooks {
			if err := upsertWebhook(q, row); err != nil {
				return err
			}
		}
		for _, row := range doc.SocialIdentities {
			if err := upsertSocial(q, row); err != nil {
				return err
			}
		}
		for _, row := range doc.PushDevices {
			if err := upsertPush(q, row); err != nil {
				return err
			}
		}
		for _, row := range doc.PairwiseSubjects {
			if err := upsertPairwise(q, row); err != nil {
				return err
			}
		}
		if len(doc.SigningKeys) > 0 {
			if err := replaceKeys(q, doc.SigningKeys); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return RestoreResult{}, err
	}
	if len(doc.SigningKeys) > 0 && b.keys != nil {
		if err := b.keys.Reload(); err != nil {
			return RestoreResult{}, err
		}
	}
	return result, nil
}

func (b *Backup) occupied() (bool, error) {
	var users int
	if err := b.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users); err != nil {
		return false, err
	}
	var clients int
	var err error
	if b.managementID == "" {
		err = b.db.QueryRow(`SELECT COUNT(*) FROM clients`).Scan(&clients)
	} else {
		err = b.db.QueryRow(`SELECT COUNT(*) FROM clients WHERE id <> ?`, b.managementID).Scan(&clients)
	}
	if err != nil {
		return false, err
	}
	return users > 0 || clients > 0, nil
}

func (b *Backup) exportUsers() ([]BackupUser, error) {
	rows, err := b.users.List()
	if err != nil {
		return nil, err
	}
	out := make([]BackupUser, 0, len(rows))
	for _, user := range rows {
		enabled, secret, err := b.users.GetMFA(user.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		item := BackupUser{
			ID: user.ID, Username: user.Username, Email: user.Email,
			EmailVerified: user.EmailVerified, PasswordHash: user.PasswordHash,
			GivenName: user.GivenName, FamilyName: user.FamilyName,
			PhoneNumber: user.PhoneNumber, Disabled: user.Disabled,
			Attributes: user.Attributes, CreatedAt: user.CreatedAt,
		}
		if enabled {
			item.TOTPSecret = secret
		}
		if b.orgs != nil {
			orgs, err := b.orgs.ListForUser(user.ID)
			if err != nil {
				return nil, err
			}
			for _, org := range orgs {
				item.Orgs = append(item.Orgs, org.Slug)
			}
		}
		out = append(out, item)
	}
	return out, nil
}

func (b *Backup) exportOrgs() ([]BackupOrg, error) {
	if b.orgs == nil {
		return []BackupOrg{}, nil
	}
	rows, err := b.orgs.List()
	if err != nil {
		return nil, err
	}
	members, err := b.memberships()
	if err != nil {
		return nil, err
	}
	out := make([]BackupOrg, 0, len(rows))
	for _, org := range rows {
		item := BackupOrg{
			ID: org.ID, Slug: org.Slug, Name: org.Name, LogoURL: org.LogoURL,
			Domains: org.Domains, Members: members[org.ID], CreatedAt: org.CreatedAt,
		}
		out = append(out, item)
	}
	return out, nil
}

func (b *Backup) memberships() (map[string][]BackupMember, error) {
	rows, err := b.db.Query(`SELECT org_id, user_id, role FROM org_memberships ORDER BY org_id, user_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]BackupMember{}
	for rows.Next() {
		var orgID, userID, role string
		if err := rows.Scan(&orgID, &userID, &role); err != nil {
			return nil, err
		}
		out[orgID] = append(out[orgID], BackupMember{UserID: userID, Role: role})
	}
	return out, rows.Err()
}

func (b *Backup) exportConsents() ([]models.Consent, error) {
	rows, err := b.db.Query(`SELECT id, user_id, client_id, scopes, granted_at, expires_at FROM consents ORDER BY user_id, client_id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []models.Consent{}
	for rows.Next() {
		var item models.Consent
		var scopes string
		var expires sql.NullTime
		if err := rows.Scan(&item.ID, &item.UserID, &item.ClientID, &scopes, &item.GrantedAt, &expires); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(scopes), &item.Scopes)
		if item.Scopes == nil {
			item.Scopes = []string{}
		}
		if expires.Valid {
			item.ExpiresAt = &expires.Time
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (b *Backup) exportSocial() ([]BackupSocial, error) {
	rows, err := b.db.Query(`SELECT provider, subject, user_id, COALESCE(email, ''), created_at FROM social_identities ORDER BY provider, subject`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []BackupSocial{}
	for rows.Next() {
		var item BackupSocial
		if err := rows.Scan(&item.Provider, &item.Subject, &item.UserID, &item.Email, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (b *Backup) exportPush() ([]BackupPushDevice, error) {
	rows, err := b.db.Query(`SELECT id, user_id, COALESCE(client_id, ''), jwk, jkt, credential_hash,
		COALESCE(platform, ''), COALESCE(push_address, ''), interaction_types, COALESCE(attestation, ''),
		status, created_at, COALESCE(last_used_at, ''), COALESCE(previous_jwk, ''), COALESCE(previous_jkt, ''),
		COALESCE(grace_until, ''), COALESCE(is_primary, 0)
		FROM push_devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []BackupPushDevice{}
	for rows.Next() {
		var item BackupPushDevice
		var primary int
		if err := rows.Scan(&item.ID, &item.UserID, &item.ClientID, &item.JWK, &item.JKT, &item.CredentialHash,
			&item.Platform, &item.PushAddress, &item.InteractionTypes, &item.Attestation,
			&item.Status, &item.CreatedAt, &item.LastUsedAt, &item.PreviousJWK, &item.PreviousJKT,
			&item.GraceUntil, &primary); err != nil {
			return nil, err
		}
		item.IsPrimary = primary != 0
		out = append(out, item)
	}
	return out, rows.Err()
}

func (b *Backup) exportPairwise() ([]BackupPairwise, error) {
	rows, err := b.db.Query(`SELECT sector_id, ppid, user_id, created_at FROM pairwise_subjects ORDER BY sector_id, ppid`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []BackupPairwise{}
	for rows.Next() {
		var item BackupPairwise
		if err := rows.Scan(&item.SectorID, &item.PPID, &item.UserID, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (b *Backup) exportKeys() ([]BackupSigningKey, error) {
	rows, err := b.db.Query(`SELECT kid, alg, status, private_pem, created_at, COALESCE(retire_at, '') FROM signing_keys ORDER BY kid`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []BackupSigningKey{}
	for rows.Next() {
		var item BackupSigningKey
		if err := rows.Scan(&item.Kid, &item.Alg, &item.Status, &item.PrivatePEM, &item.CreatedAt, &item.RetireAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func emptyBackup() BackupDocument {
	return BackupDocument{
		Version: BackupVersion, Users: []BackupUser{}, Clients: []models.Client{},
		Organizations: []BackupOrg{}, Consents: []models.Consent{}, Scopes: []models.Scope{},
		Resources: []models.Resource{}, Webhooks: []models.Webhook{}, SocialIdentities: []BackupSocial{},
		PushDevices: []BackupPushDevice{}, PairwiseSubjects: []BackupPairwise{}, SigningKeys: []BackupSigningKey{},
	}
}

func countBackup(doc BackupDocument) RestoreResult {
	return RestoreResult{
		Users: len(doc.Users), Clients: len(doc.Clients), Organizations: len(doc.Organizations),
		Consents: len(doc.Consents), Scopes: len(doc.Scopes), Resources: len(doc.Resources),
		Webhooks: len(doc.Webhooks), SocialIdentities: len(doc.SocialIdentities),
		PushDevices: len(doc.PushDevices), PairwiseSubjects: len(doc.PairwiseSubjects),
		SigningKeys: len(doc.SigningKeys),
	}
}

func validateBackup(doc BackupDocument) error {
	if doc.Version != BackupVersion {
		return fmt.Errorf("version must be 1")
	}
	users := map[string]bool{}
	for i, row := range doc.Users {
		if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.Username) == "" {
			return fmt.Errorf("users[%d] needs an id and a username", i)
		}
		if strings.TrimSpace(row.PasswordHash) == "" {
			return fmt.Errorf("users[%d] needs a password_hash", i)
		}
		if users[row.ID] {
			return fmt.Errorf("users[%d] repeats id %s", i, row.ID)
		}
		users[row.ID] = true
	}
	clients := map[string]bool{}
	for i, row := range doc.Clients {
		if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.Name) == "" {
			return fmt.Errorf("clients[%d] needs an id and a name", i)
		}
		if clients[row.ID] {
			return fmt.Errorf("clients[%d] repeats id %s", i, row.ID)
		}
		clients[row.ID] = true
	}
	orgs := map[string]bool{}
	for i, row := range doc.Organizations {
		if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.Slug) == "" || strings.TrimSpace(row.Name) == "" {
			return fmt.Errorf("organizations[%d] needs an id, a slug, and a name", i)
		}
		if orgs[row.ID] {
			return fmt.Errorf("organizations[%d] repeats id %s", i, row.ID)
		}
		orgs[row.ID] = true
		for _, member := range row.Members {
			if !users[member.UserID] {
				return fmt.Errorf("organizations[%d] member %s is not in users", i, member.UserID)
			}
			if strings.TrimSpace(member.Role) == "" {
				return fmt.Errorf("organizations[%d] member %s needs a role", i, member.UserID)
			}
		}
	}
	for i, row := range doc.Consents {
		if !users[row.UserID] || !clients[row.ClientID] || len(row.Scopes) == 0 {
			return fmt.Errorf("consents[%d] needs a known user, a known client, and scopes", i)
		}
	}
	for i, row := range doc.Scopes {
		if strings.TrimSpace(row.Name) == "" {
			return fmt.Errorf("scopes[%d] needs a name", i)
		}
	}
	for i, row := range doc.Resources {
		if strings.TrimSpace(row.URI) == "" || strings.TrimSpace(row.Name) == "" {
			return fmt.Errorf("resources[%d] needs a uri and a name", i)
		}
	}
	for i, row := range doc.Webhooks {
		if strings.TrimSpace(row.ID) == "" || strings.TrimSpace(row.URL) == "" || strings.TrimSpace(row.Secret) == "" {
			return fmt.Errorf("webhooks[%d] needs an id, a url, and a secret", i)
		}
	}
	for i, row := range doc.SocialIdentities {
		if strings.TrimSpace(row.Provider) == "" || strings.TrimSpace(row.Subject) == "" || !users[row.UserID] {
			return fmt.Errorf("social_identities[%d] needs a provider, a subject, and a known user", i)
		}
	}
	for i, row := range doc.PushDevices {
		if strings.TrimSpace(row.ID) == "" || !users[row.UserID] || strings.TrimSpace(row.JWK) == "" || strings.TrimSpace(row.CredentialHash) == "" {
			return fmt.Errorf("push_devices[%d] needs an id, a known user, a jwk, and a credential_hash", i)
		}
	}
	for i, row := range doc.PairwiseSubjects {
		if strings.TrimSpace(row.SectorID) == "" || strings.TrimSpace(row.PPID) == "" || !users[row.UserID] {
			return fmt.Errorf("pairwise_subjects[%d] needs a sector_id, a ppid, and a known user", i)
		}
	}
	for i, row := range doc.SigningKeys {
		if err := validSigningKey(row); err != nil {
			return fmt.Errorf("signing_keys[%d]: %w", i, err)
		}
	}
	return nil
}

func validSigningKey(row BackupSigningKey) error {
	switch row.Alg {
	case "RS256", "ES256", "Ed25519":
	default:
		return fmt.Errorf("alg must be RS256, ES256, or Ed25519")
	}
	if strings.TrimSpace(row.Kid) == "" || strings.TrimSpace(row.Status) == "" {
		return fmt.Errorf("needs a kid and a status")
	}
	block, _ := pem.Decode([]byte(row.PrivatePEM))
	if block == nil {
		return fmt.Errorf("private_pem is not a PEM block")
	}
	switch row.Alg {
	case "RS256":
		_, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		return err
	case "ES256":
		_, err := x509.ParseECPrivateKey(block.Bytes)
		return err
	default:
		_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		return err
	}
}

func upsertUser(q database.SQL, user BackupUser) error {
	attrs := user.Attributes
	if attrs == nil {
		attrs = map[string]string{}
	}
	raw, err := json.Marshal(attrs)
	if err != nil {
		return err
	}
	created := user.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err = q.Exec(`INSERT INTO users (id, username, password_hash, email, phone_number, created_at,
		email_verified, disabled, given_name, family_name, attributes, mfa_enabled, mfa_secret)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash,
		email = excluded.email, phone_number = excluded.phone_number, email_verified = excluded.email_verified,
		disabled = excluded.disabled, given_name = excluded.given_name, family_name = excluded.family_name,
		attributes = excluded.attributes, mfa_enabled = excluded.mfa_enabled, mfa_secret = excluded.mfa_secret`,
		user.ID, user.Username, user.PasswordHash, user.Email, user.PhoneNumber, created,
		bit(user.EmailVerified), bit(user.Disabled), user.GivenName, user.FamilyName, string(raw),
		bit(user.TOTPSecret != ""), user.TOTPSecret)
	return err
}

func upsertOrg(q database.SQL, org BackupOrg) error {
	created := org.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	if _, err := q.Exec(`INSERT INTO organizations (id, slug, name, logo_url, created_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET slug = excluded.slug, name = excluded.name, logo_url = excluded.logo_url`,
		org.ID, org.Slug, org.Name, org.LogoURL, created); err != nil {
		return err
	}
	if _, err := q.Exec(`DELETE FROM organization_domains WHERE org_id = ?`, org.ID); err != nil {
		return err
	}
	for _, domain := range org.Domains {
		if _, err := q.Exec(`INSERT INTO organization_domains (domain, org_id) VALUES (?, ?)`, domain, org.ID); err != nil {
			return err
		}
	}
	return nil
}

func replaceOrgMembers(q database.SQL, org BackupOrg) error {
	if _, err := q.Exec(`DELETE FROM org_memberships WHERE org_id = ?`, org.ID); err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, member := range org.Members {
		if _, err := q.Exec(`INSERT INTO org_memberships (org_id, user_id, role, created_at) VALUES (?, ?, ?, ?)`,
			org.ID, member.UserID, member.Role, now); err != nil {
			return err
		}
	}
	return nil
}

func upsertClient(q database.SQL, client models.Client) error {
	source := client.RegistrationSource
	if source == "" {
		source = "management"
	}
	subject := client.SubjectType
	if subject == "" {
		subject = "public"
	}
	created := client.CreatedAt
	updated := client.UpdatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	if updated.IsZero() {
		updated = created
	}
	_, err := q.Exec(`INSERT INTO clients (id, secret, name, redirect_uris, grant_types, scopes,
		token_endpoint_auth_method, dpop_bound_access_tokens,
		require_pushed_authorization_requests, backchannel_token_delivery_mode,
		backchannel_client_notification_endpoint, backchannel_authentication_request_signing_alg,
		backchannel_logout_uri, backchannel_logout_session_required, post_logout_redirect_uris,
		jwks, jwks_uri, request_object_signing_alg,
		registration_source, dcr_enabled, cimd_enabled,
		subject_type, sector_identifier_uri,
		id_token_encrypted_response_alg, id_token_encrypted_response_enc,
		userinfo_encrypted_response_alg, userinfo_encrypted_response_enc,
		created_at, updated_at, org_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET secret = excluded.secret, name = excluded.name,
		redirect_uris = excluded.redirect_uris, grant_types = excluded.grant_types, scopes = excluded.scopes,
		token_endpoint_auth_method = excluded.token_endpoint_auth_method,
		dpop_bound_access_tokens = excluded.dpop_bound_access_tokens,
		require_pushed_authorization_requests = excluded.require_pushed_authorization_requests,
		backchannel_token_delivery_mode = excluded.backchannel_token_delivery_mode,
		backchannel_client_notification_endpoint = excluded.backchannel_client_notification_endpoint,
		backchannel_authentication_request_signing_alg = excluded.backchannel_authentication_request_signing_alg,
		backchannel_logout_uri = excluded.backchannel_logout_uri,
		backchannel_logout_session_required = excluded.backchannel_logout_session_required,
		post_logout_redirect_uris = excluded.post_logout_redirect_uris,
		jwks = excluded.jwks, jwks_uri = excluded.jwks_uri,
		request_object_signing_alg = excluded.request_object_signing_alg,
		registration_source = excluded.registration_source, dcr_enabled = excluded.dcr_enabled,
		cimd_enabled = excluded.cimd_enabled, subject_type = excluded.subject_type,
		sector_identifier_uri = excluded.sector_identifier_uri,
		id_token_encrypted_response_alg = excluded.id_token_encrypted_response_alg,
		id_token_encrypted_response_enc = excluded.id_token_encrypted_response_enc,
		userinfo_encrypted_response_alg = excluded.userinfo_encrypted_response_alg,
		userinfo_encrypted_response_enc = excluded.userinfo_encrypted_response_enc,
		org_id = excluded.org_id`,
		client.ID, client.Secret, client.Name, jsonList(client.RedirectURIs), jsonList(client.GrantTypes), jsonList(client.Scopes),
		client.TokenEndpointAuthMethod, bit(client.DPoPBoundAccessTokens),
		bit(client.RequirePushedAuthorizationRequests), client.BackchannelTokenDeliveryMode,
		client.BackchannelClientNotificationEndpoint, client.BackchannelAuthenticationRequestSigningAlg,
		client.BackchannelLogoutURI, bit(client.BackchannelLogoutSessionRequired), jsonList(client.PostLogoutRedirectURIs),
		client.JWKS, client.JWKSUri, client.RequestObjectSigningAlg,
		source, bit(client.DCREnabled), bit(client.CIMDEnabled),
		subject, client.SectorIdentifierURI,
		client.IDTokenEncryptedResponseAlg, client.IDTokenEncryptedResponseEnc,
		client.UserinfoEncryptedResponseAlg, client.UserinfoEncryptedResponseEnc,
		created, updated, client.OrgID)
	return err
}

func upsertConsent(q database.SQL, row models.Consent) error {
	id := row.ID
	if id == "" {
		id = uuid.NewString()
	}
	granted := row.GrantedAt
	if granted.IsZero() {
		granted = time.Now().UTC()
	}
	var expires any
	if row.ExpiresAt != nil {
		expires = *row.ExpiresAt
	}
	_, err := q.Exec(`INSERT INTO consents (id, user_id, client_id, scopes, granted_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes = excluded.scopes,
		granted_at = excluded.granted_at, expires_at = excluded.expires_at`,
		id, row.UserID, row.ClientID, jsonList(row.Scopes), granted, expires)
	return err
}

func upsertScope(q database.SQL, row models.Scope) error {
	created := row.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err := q.Exec(`INSERT INTO scopes (name, description, resource_server, is_default, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET description = excluded.description,
		resource_server = excluded.resource_server, is_default = excluded.is_default`,
		row.Name, row.Description, row.ResourceServer, bit(row.IsDefault), created)
	return err
}

func upsertResource(q database.SQL, row models.Resource) error {
	created := row.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	_, err := q.Exec(`INSERT INTO resources (uri, name, description, scopes, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (uri) DO UPDATE SET name = excluded.name, description = excluded.description, scopes = excluded.scopes`,
		row.URI, row.Name, row.Description, jsonList(row.Scopes), created)
	return err
}

func upsertWebhook(q database.SQL, row models.Webhook) error {
	events, err := json.Marshal(row.Events)
	if err != nil {
		return err
	}
	created := row.CreatedAt
	updated := row.UpdatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	if updated.IsZero() {
		updated = created
	}
	_, err = q.Exec(`INSERT INTO webhooks (id, url, secret, events, enabled, description, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET url = excluded.url, secret = excluded.secret, events = excluded.events,
		enabled = excluded.enabled, description = excluded.description, updated_at = excluded.updated_at`,
		row.ID, row.URL, row.Secret, string(events), bit(row.Enabled), row.Description, created, updated)
	return err
}

func upsertSocial(q database.SQL, row BackupSocial) error {
	created := row.CreatedAt
	if created == "" {
		created = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := q.Exec(`INSERT INTO social_identities (provider, subject, user_id, email, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (provider, subject) DO UPDATE SET user_id = excluded.user_id, email = excluded.email`,
		row.Provider, row.Subject, row.UserID, row.Email, created)
	return err
}

func upsertPush(q database.SQL, row BackupPushDevice) error {
	created := row.CreatedAt
	if created == "" {
		created = time.Now().UTC().Format(time.RFC3339)
	}
	types := row.InteractionTypes
	if types == "" {
		types = "[]"
	}
	_, err := q.Exec(`INSERT INTO push_devices (id, user_id, client_id, jwk, jkt, credential_hash, platform,
		push_address, interaction_types, attestation, status, created_at, last_used_at,
		previous_jwk, previous_jkt, grace_until, is_primary)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET user_id = excluded.user_id, client_id = excluded.client_id,
		jwk = excluded.jwk, jkt = excluded.jkt, credential_hash = excluded.credential_hash,
		platform = excluded.platform, push_address = excluded.push_address,
		interaction_types = excluded.interaction_types, attestation = excluded.attestation,
		status = excluded.status, last_used_at = excluded.last_used_at,
		previous_jwk = excluded.previous_jwk, previous_jkt = excluded.previous_jkt,
		grace_until = excluded.grace_until, is_primary = excluded.is_primary`,
		row.ID, row.UserID, row.ClientID, row.JWK, row.JKT, row.CredentialHash, row.Platform,
		row.PushAddress, types, row.Attestation, row.Status, created, row.LastUsedAt,
		row.PreviousJWK, row.PreviousJKT, row.GraceUntil, bit(row.IsPrimary))
	return err
}

func upsertPairwise(q database.SQL, row BackupPairwise) error {
	created := row.CreatedAt
	if created == "" {
		created = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := q.Exec(`INSERT INTO pairwise_subjects (sector_id, ppid, user_id, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (sector_id, ppid) DO UPDATE SET user_id = excluded.user_id`,
		row.SectorID, row.PPID, row.UserID, created)
	return err
}

func replaceKeys(q database.SQL, keys []BackupSigningKey) error {
	if _, err := q.Exec(`DELETE FROM signing_keys`); err != nil {
		return err
	}
	for _, key := range keys {
		var retire any
		if strings.TrimSpace(key.RetireAt) != "" {
			retire = key.RetireAt
		}
		created := key.CreatedAt
		if created == "" {
			created = time.Now().UTC().Format(time.RFC3339)
		}
		if _, err := q.Exec(`INSERT INTO signing_keys (kid, alg, status, private_pem, created_at, retire_at)
			VALUES (?, ?, ?, ?, ?, ?)`,
			key.Kid, key.Alg, key.Status, key.PrivatePEM, created, retire); err != nil {
			return err
		}
	}
	return nil
}

func jsonList(v any) string {
	raw, err := json.Marshal(v)
	if err != nil || string(raw) == "null" {
		return "[]"
	}
	return string(raw)
}

func bit(v bool) int {
	if v {
		return 1
	}
	return 0
}
