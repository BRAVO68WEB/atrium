package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/bravo68web/atrium/internal/config"
	"github.com/bravo68web/atrium/internal/telemetry"
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// Row is one query result. Scan runs the query.
type Row interface {
	Scan(dest ...any) error
}

// SQL is the query handle repositories use. Postgres placeholders are rewritten.
type SQL interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) Row
	Dialect() string
}

func (db *DB) Dialect() string {
	if db == nil || db.driver == "" {
		return "sqlite"
	}
	return db.driver
}

type DB struct {
	conn   *sql.DB
	driver string
}

// New opens a SQLite file. Tests and the default server use this.
func New(dbPath string) (*DB, error) {
	return openSQLite(dbPath)
}

// Open selects sqlite or postgres from config.
func Open(cfg *config.Config) (*DB, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is nil")
	}
	switch cfg.Database.Driver {
	case "", "sqlite":
		if cfg.Database.Path == "" {
			return nil, fmt.Errorf("database.path is required for sqlite")
		}
		return openSQLite(cfg.Database.Path)
	case "postgres":
		if cfg.Database.DSN == "" {
			return nil, fmt.Errorf("database.dsn is required for postgres")
		}
		return openPostgres(cfg.Database.DSN)
	default:
		return nil, fmt.Errorf("database.driver must be sqlite or postgres")
	}
}

func openSQLite(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	conn.SetMaxOpenConns(1)
	conn.SetMaxIdleConns(1)

	db := &DB{conn: conn, driver: "sqlite"}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}
	return db, nil
}

func openPostgres(dsn string) (*DB, error) {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	conn.SetMaxOpenConns(10)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.PingContext(ctx); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("postgres: %w", err)
	}
	return &DB{conn: conn, driver: "postgres"}, nil
}

func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	done := telemetry.QuerySpan(db.driver, query, len(args))
	result, err := db.conn.ExecContext(telemetry.Context(), db.prepare(query), args...)
	done(err)
	return result, err
}

func (db *DB) Query(query string, args ...any) (*sql.Rows, error) {
	done := telemetry.QuerySpan(db.driver, query, len(args))
	rows, err := db.conn.QueryContext(telemetry.Context(), db.prepare(query), args...)
	done(err)
	return rows, err
}

func (db *DB) QueryRow(query string, args ...any) Row {
	done := telemetry.QuerySpan(db.driver, query, len(args))
	row := &tracedRow{
		row:  db.conn.QueryRowContext(telemetry.Context(), db.prepare(query), args...),
		done: done,
	}
	runtime.SetFinalizer(row, func(row *tracedRow) { row.finish(nil) })
	return row
}

// tracedRow ends the query span when Scan runs. QueryRow itself does not
// talk to the database. Scan does.
type tracedRow struct {
	row  *sql.Row
	done func(error)
	once sync.Once
}

func (r *tracedRow) Scan(dest ...any) error {
	err := r.row.Scan(dest...)
	r.finish(err)
	return err
}

func (r *tracedRow) finish(err error) {
	r.once.Do(func() {
		runtime.SetFinalizer(r, nil)
		if r.done != nil {
			r.done(err)
		}
	})
}

func (db *DB) Close() error {
	return db.conn.Close()
}

func (db *DB) Conn() *sql.DB {
	return db.conn
}

func (db *DB) Migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			secret TEXT,
			name TEXT NOT NULL,
			redirect_uris TEXT,
			grant_types TEXT,
			scopes TEXT,
			token_endpoint_auth_method TEXT DEFAULT 'client_secret_basic',
			dpop_bound_access_tokens INTEGER DEFAULT 0,
			require_pushed_authorization_requests INTEGER DEFAULT 0,
			backchannel_token_delivery_mode TEXT,
			backchannel_client_notification_endpoint TEXT,
			backchannel_authentication_request_signing_alg TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			email TEXT,
			phone_number TEXT,
			mfa_enabled INTEGER DEFAULT 0,
			mfa_secret TEXT,
			mfa_pending_secret TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS authorization_codes (
			code TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL,
			scopes TEXT,
			resource TEXT,
			nonce TEXT,
			code_challenge TEXT,
			code_challenge_method TEXT,
			expires_at DATETIME NOT NULL,
			used INTEGER DEFAULT 0,
			FOREIGN KEY (client_id) REFERENCES clients(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS access_tokens (
			token TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id TEXT,
			scopes TEXT,
			token_type TEXT DEFAULT 'Bearer',
			dpop_jkt TEXT,
			cert_thumbprint TEXT,
			expires_at DATETIME NOT NULL,
			revoked INTEGER DEFAULT 0,
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
			token TEXT PRIMARY KEY,
			access_token TEXT,
			client_id TEXT NOT NULL,
			user_id TEXT,
			scopes TEXT,
			expires_at DATETIME,
			revoked INTEGER DEFAULT 0,
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE TABLE IF NOT EXISTS device_codes (
			device_code TEXT PRIMARY KEY,
			user_code TEXT NOT NULL,
			client_id TEXT NOT NULL,
			scopes TEXT,
			status TEXT DEFAULT 'pending',
			expires_at DATETIME NOT NULL,
			interval INTEGER DEFAULT 5,
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE TABLE IF NOT EXISTS pushed_auth_requests (
			request_uri TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			request_params TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used INTEGER NOT NULL DEFAULT 0,
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE TABLE IF NOT EXISTS ciba_requests (
			auth_req_id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			user_id TEXT,
			binding_message TEXT,
			user_code TEXT,
			status TEXT DEFAULT 'pending',
			delivery_mode TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			interval INTEGER DEFAULT 5,
			client_notification_token TEXT,
			FOREIGN KEY (client_id) REFERENCES clients(id),
			FOREIGN KEY (user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS oidc_nonces (
			nonce TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS dpop_proofs (
			jti TEXT PRIMARY KEY,
			htm TEXT NOT NULL,
			htu TEXT NOT NULL,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON access_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client ON refresh_tokens(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_authorization_codes_client ON authorization_codes(client_id)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_status ON device_codes(status)`,
		`CREATE INDEX IF NOT EXISTS idx_ciba_requests_status ON ciba_requests(status)`,

		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			username TEXT,
			auth_time DATETIME NOT NULL,
			mfa_verified INTEGER NOT NULL DEFAULT 0,
			user_agent TEXT,
			ip TEXT,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`,
		`CREATE TABLE IF NOT EXISTS session_clients (
			sid TEXT NOT NULL,
			client_id TEXT NOT NULL,
			PRIMARY KEY (sid, client_id)
		)`,
		`CREATE TABLE IF NOT EXISTS email_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			purpose TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			expires_at DATETIME NOT NULL,
			used_at DATETIME,
			created_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_email_tokens_hash ON email_tokens(token_hash)`,
		`CREATE TABLE IF NOT EXISTS login_events (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			success INTEGER NOT NULL,
			mfa INTEGER NOT NULL DEFAULT 0,
			ip TEXT,
			user_agent TEXT,
			created_at DATETIME NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_login_events_user ON login_events(user_id, created_at)`,
		`CREATE INDEX IF NOT EXISTS idx_login_events_ip ON login_events(ip, created_at)`,
		`CREATE TABLE IF NOT EXISTS schema_flags (
			name TEXT PRIMARY KEY
		)`,
		`CREATE TABLE IF NOT EXISTS social_logins (
			state TEXT PRIMARY KEY,
			provider TEXT NOT NULL,
			verifier TEXT NOT NULL,
			nonce TEXT NOT NULL,
			params_json TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			used INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS social_identities (
			provider TEXT NOT NULL,
			subject TEXT NOT NULL,
			user_id TEXT NOT NULL,
			email TEXT,
			created_at TEXT NOT NULL,
			PRIMARY KEY (provider, subject)
		)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			actor_type TEXT NOT NULL,
			actor_id TEXT NOT NULL,
			action TEXT NOT NULL,
			target_type TEXT,
			target_id TEXT,
			ip TEXT,
			user_agent TEXT,
			metadata TEXT NOT NULL,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS signing_keys (
			kid TEXT PRIMARY KEY,
			alg TEXT NOT NULL,
			status TEXT NOT NULL,
			private_pem TEXT NOT NULL,
			created_at TEXT NOT NULL,
			retire_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS webhooks (
			id TEXT PRIMARY KEY,
			url TEXT NOT NULL,
			secret TEXT NOT NULL,
			events TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			description TEXT,
			created_at DATETIME NOT NULL,
			updated_at DATETIME NOT NULL
		)`,

		// Consent persistence
		`CREATE TABLE IF NOT EXISTS consents (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			client_id TEXT NOT NULL,
			scopes TEXT NOT NULL,
			granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME,
			FOREIGN KEY (user_id) REFERENCES users(id),
			FOREIGN KEY (client_id) REFERENCES clients(id)
		)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_consents_user_client ON consents(user_id, client_id)`,

		// Custom scope definitions
		`CREATE TABLE IF NOT EXISTS scopes (
			name TEXT PRIMARY KEY,
			description TEXT,
			resource_server TEXT,
			is_default INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,

		// Resource servers (RFC 8707)
		`CREATE TABLE IF NOT EXISTS organizations (
			id TEXT PRIMARY KEY,
			slug TEXT NOT NULL UNIQUE,
			name TEXT NOT NULL,
			logo_url TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS organization_domains (
			domain TEXT PRIMARY KEY,
			org_id TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS org_memberships (
			org_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (org_id, user_id)
		)`,
		`CREATE TABLE IF NOT EXISTS pairwise_subjects (
			sector_id TEXT NOT NULL,
			ppid TEXT NOT NULL,
			user_id TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (sector_id, ppid)
		)`,
		`CREATE TABLE IF NOT EXISTS resources (
			uri TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			scopes TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS roles (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			description TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS role_scopes (
			role_id TEXT NOT NULL,
			resource_uri TEXT NOT NULL,
			scope TEXT NOT NULL,
			PRIMARY KEY (role_id, resource_uri, scope)
		)`,
		`CREATE TABLE IF NOT EXISTS user_roles (
			user_id TEXT NOT NULL,
			role_id TEXT NOT NULL,
			org_id TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, role_id, org_id)
		)`,
		`CREATE TABLE IF NOT EXISTS user_scopes (
			user_id TEXT NOT NULL,
			resource_uri TEXT NOT NULL,
			scope TEXT NOT NULL,
			org_id TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_id, resource_uri, scope, org_id)
		)`,
		`CREATE TABLE IF NOT EXISTS push_registration_tokens (
			jti TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			client_id TEXT,
			expires_at TEXT NOT NULL,
			used INTEGER NOT NULL DEFAULT 0
		)`,
		`CREATE TABLE IF NOT EXISTS push_devices (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			client_id TEXT,
			jwk TEXT NOT NULL,
			jkt TEXT NOT NULL,
			credential_hash TEXT NOT NULL,
			platform TEXT,
			push_address TEXT,
			interaction_types TEXT NOT NULL,
			attestation TEXT,
			status TEXT NOT NULL,
			created_at TEXT NOT NULL,
			last_used_at TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS push_auth_requests (
			auth_req_id TEXT PRIMARY KEY,
			device_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			interaction_type TEXT NOT NULL,
			binding_message TEXT,
			status TEXT NOT NULL
		)`,
	}

	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("failed to execute migration: %w", err)
		}
	}

	// Safe ALTER TABLE migrations (ignore "duplicate column" errors)
	alters := []string{
		`ALTER TABLE access_tokens ADD COLUMN resource TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN resource TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN nonce TEXT`,
		`ALTER TABLE refresh_tokens ADD COLUMN resource TEXT`,
		`ALTER TABLE users ADD COLUMN last_login_at DATETIME`,
		`ALTER TABLE clients ADD COLUMN jwks TEXT`,
		`ALTER TABLE clients ADD COLUMN jwks_uri TEXT`,
		`ALTER TABLE clients ADD COLUMN request_object_signing_alg TEXT`,
		`ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN given_name TEXT`,
		`ALTER TABLE users ADD COLUMN family_name TEXT`,
		`ALTER TABLE clients ADD COLUMN backchannel_logout_uri TEXT`,
		`ALTER TABLE clients ADD COLUMN backchannel_logout_session_required INTEGER NOT NULL DEFAULT 1`,
		`ALTER TABLE clients ADD COLUMN post_logout_redirect_uris TEXT`,
		`ALTER TABLE device_codes ADD COLUMN user_id TEXT`,
		`ALTER TABLE device_codes ADD COLUMN session_id TEXT`,
		`ALTER TABLE device_codes ADD COLUMN auth_time DATETIME`,
		`ALTER TABLE refresh_tokens ADD COLUMN id TEXT`,
		`ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN family_id TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN session_id TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN auth_time DATETIME`,
		`ALTER TABLE users ADD COLUMN attributes TEXT NOT NULL DEFAULT '{}'`,
		`ALTER TABLE users ADD COLUMN user_metadata TEXT NOT NULL DEFAULT '{}'`,
		`ALTER TABLE clients ADD COLUMN registration_source TEXT NOT NULL DEFAULT 'management'`,
		`ALTER TABLE clients ADD COLUMN dcr_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE clients ADD COLUMN cimd_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE ciba_requests ADD COLUMN scopes TEXT`,
		`ALTER TABLE access_tokens ADD COLUMN iat DATETIME`,
		`ALTER TABLE access_tokens ADD COLUMN jti TEXT`,
		`ALTER TABLE access_tokens ADD COLUMN org_id TEXT`,
		`ALTER TABLE access_tokens ADD COLUMN act TEXT`,
		`ALTER TABLE refresh_tokens ADD COLUMN iat DATETIME`,
		`ALTER TABLE refresh_tokens ADD COLUMN jti TEXT`,
		`ALTER TABLE refresh_tokens ADD COLUMN org_id TEXT`,
		`ALTER TABLE refresh_tokens ADD COLUMN act TEXT`,
		`ALTER TABLE clients ADD COLUMN subject_type TEXT NOT NULL DEFAULT 'public'`,
		`ALTER TABLE clients ADD COLUMN sector_identifier_uri TEXT`,
		`ALTER TABLE clients ADD COLUMN id_token_encrypted_response_alg TEXT`,
		`ALTER TABLE clients ADD COLUMN id_token_encrypted_response_enc TEXT`,
		`ALTER TABLE clients ADD COLUMN userinfo_encrypted_response_alg TEXT`,
		`ALTER TABLE clients ADD COLUMN userinfo_encrypted_response_enc TEXT`,
		`ALTER TABLE clients ADD COLUMN org_id TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN org_id TEXT`,
		`ALTER TABLE authorization_codes ADD COLUMN requested_actor TEXT`,
		`ALTER TABLE organizations ADD COLUMN logo_url TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE push_devices ADD COLUMN previous_jwk TEXT`,
		`ALTER TABLE push_devices ADD COLUMN previous_jkt TEXT`,
		`ALTER TABLE push_devices ADD COLUMN grace_until TEXT`,
		`ALTER TABLE push_devices ADD COLUMN is_primary INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE push_auth_requests ADD COLUMN delivery_mode TEXT`,
		`ALTER TABLE pushed_auth_requests ADD COLUMN used INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE users ADD COLUMN migration_pending INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE sessions ADD COLUMN migration_password INTEGER NOT NULL DEFAULT 0`,
	}
	for _, alter := range alters {
		if _, err := db.Exec(alter); err != nil && db.driver == "postgres" && !isDuplicateColumn(err) {
			return fmt.Errorf("failed to execute migration: %w", err)
		}
	}

	if _, err := db.Exec(`INSERT INTO schema_flags (name) VALUES ('email_verified_backfill')`); err == nil {
		_, _ = db.Exec(`UPDATE users SET email_verified = 1 WHERE email IS NOT NULL AND email != ''`)
	}
	if err := db.backfillRefreshIDs(); err != nil {
		return err
	}
	return db.ensureUniqueEmails()
}

func (db *DB) ensureUniqueEmails() error {
	rows, err := db.Query(`SELECT lower(email) FROM users WHERE email IS NOT NULL AND email <> '' GROUP BY lower(email) HAVING COUNT(*) > 1`)
	if err != nil {
		return fmt.Errorf("email uniqueness: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var dups []string
	for rows.Next() {
		var email string
		if err := rows.Scan(&email); err != nil {
			return fmt.Errorf("email uniqueness: %w", err)
		}
		dups = append(dups, email)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("email uniqueness: %w", err)
	}
	if len(dups) > 0 {
		return fmt.Errorf("duplicate emails exist: %s", strings.Join(dups, ", "))
	}
	if _, err := db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (lower(email)) WHERE email IS NOT NULL AND email <> ''`); err != nil {
		return fmt.Errorf("email uniqueness: %w", err)
	}
	return nil
}

func isDuplicateColumn(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42701"
}

func (db *DB) backfillRefreshIDs() error {
	rows, err := db.Query(`SELECT token FROM refresh_tokens WHERE id IS NULL OR id = '' OR family_id IS NULL OR family_id = ''`)
	if err != nil {
		return fmt.Errorf("refresh token ids: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return err
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, token := range tokens {
		if _, err := db.Exec(`UPDATE refresh_tokens SET
			id = CASE WHEN id IS NULL OR id = '' THEN ? ELSE id END,
			family_id = CASE WHEN family_id IS NULL OR family_id = '' THEN ? ELSE family_id END
			WHERE token = ?`, newID(), newID(), token); err != nil {
			return fmt.Errorf("refresh token ids: %w", err)
		}
	}
	return nil
}
