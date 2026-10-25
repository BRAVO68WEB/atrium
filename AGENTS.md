# AGENTS.md - Atrium

## Quick Reference

```bash
just run              # Start server (loads config.yaml if present)
just dev              # Hot reload with air
just test             # Run all tests
just build            # Build all binaries to bin/
just test-flow        # Quick integration test
just e2e              # Playwright + Mocha flows (cd e2e && npm install first)

# CLI commands
./bin/atrium-cli init                    # Generate config.yaml and algo.go
./bin/atrium-cli init --mfa              # Generate config with MFA enabled
./bin/atrium-cli init --hash argon2id    # argon2id hasher, bcrypt still verifies
./bin/atrium-cli server status           # Check server status
./bin/atrium-cli client list             # List clients
./bin/atrium-cli mfa enable --user-id X  # Enable MFA for user
```

## Architecture

Three binaries in `cmd/`:
- **atrium** - Main HTTP server (chi router, SQLite, port 8080)
- **atrium-cli** - Management CLI (client/user/token management + config init)
- **atrium-mobile** - Mobile polling CLI (CIBA request approval)

### Layered Architecture (Route → Controller → Service → Repository)

Key package boundaries:
- `internal/route/` - Route definitions (maps URLs to controllers)
- `internal/controller/` - HTTP request/response handling (thin layer)
- `internal/service/` - Business logic (no HTTP, no SQL)
- `internal/repository/` - Database access (SQL only, no business logic)
- `internal/templates/` - Go HTML templates (login, register, consent, MFA, device, reset, logout)
- `internal/mailer/` - SMTP and the disabled mailer
- `internal/auth/` - Bearer checks for `/api` and `/api/me`
- `internal/handlers/oauth/` - Legacy OAuth handlers (being migrated)
- `internal/handlers/oidc/` - OIDC handler (discovery, JWKS, UserInfo)
- `internal/database/` - SQLite or Postgres connection + migrations
- `internal/cache/` - Memory or Redis TTL cache (CIMD documents, DPoP replay)
- `internal/queue/` - Memory or Redis queue for CIBA and device approval
- `internal/config/` - YAML config with MFA settings
- `internal/hashalgo/` - Operator password hasher (`algo.go` exports `Hash`)
- `internal/models/` - Data models
- `pkg/crypto/` - PKCE, token generation
- `pkg/passhash/` - bcrypt, argon2id, and fallback hashers
- `openapi/` - OpenAPI 3.1 spec

### New Features

**MFA (TOTP):**
- Config: `security.mfa.enabled`, `security.mfa.required`
- Web enrollment: `/mfa/enroll` (QR code + secret text)
- CLI enrollment: `atrium-cli mfa enable --user-id X`
- QR rendering: `skip2/go-qrcode` (PNG + ASCII art)
- TOTP: `pquerna/otp` library

**Web Pages:**
- `/login` - Login form
- `/register` - Registration form. `security.disable_registration` returns 403 for this page, `POST /register`, and `POST /api/account/register`. Management `POST /api/users` still creates users.
- `/login/social/{id}` - Social login. Providers live in `social.providers`. `security.disable_social_registration` blocks creating an account from that callback.
- `/consent` - OIDC consent screen
- `/organization` - Organization selector. Shown when a signed-in user belongs to more than one organization and the client is not bound to one organization and the request did not name one.
- `/mfa/enroll` - TOTP enrollment with QR code
- `/forgot`, `/reset`, `/verify-email`, `/device`, `/oauth/logout` - account pages
- Branding: `branding` in config, assets at `/branding/assets/`, optional HTML overlay in `branding.templates` (read at startup)

**API Documentation:**
- `/docs` - Scalar OpenAPI UI
- `/openapi` - OpenAPI spec (JSON)
- `/docs/openapi.yaml` - OpenAPI spec (YAML)

## Testing

```bash
go test ./pkg/crypto/... -v        # Crypto tests
go test ./internal/queue/... -v    # Queue tests
go test ./internal/database/... -v # Database tests
go test ./tests/integration/... -v # Integration tests
go test ./... -v                   # All tests
```

The `E2E` GitHub check runs `cd e2e && npm test` on every pull request. Docker must be available because that suite starts Postgres with testcontainers.

## Key Quirks

- **SQLite single-connection**: `database.driver: sqlite` sets `MaxOpenConns=1`. `postgres` uses `database.dsn` and a pool of 10. `?` placeholders are rewritten to `$1` for Postgres. `migrations/*.sql` are records; `database.Migrate` is the live migrator.
- **Tests**: unit tests, `tests/integration`, and `e2e` use Postgres from `internal/testpg` (testcontainers). `e2e/pgserve` keeps that container up for Mocha. Docker must be running.
- **Redis**: `queue.type` and `cache.provider` stay `memory` unless `redis.addr` is set and the matching value is `redis`. Redis holds the CIBA/device approval queue, CIMD documents, and DPoP `jti` replay entries. It does not hold users or tokens.
- **Password hashing**: `internal/hashalgo/algo.go` exports one function, `Hash() passhash.Hasher`. Default is bcrypt (`passhash.DefaultBcryptCost`). Login, register, `POST /api/users`, and the password grant all use `UserService`. `HASH_ALGO` and `security.hash_algo` must be `internal/hashalgo/algo.go`. Edit the file, then `just run` or `just build`. Startup refuses to serve when the file differs from the binary.
- **Config load**: empty `-config` loads `./config.yaml` when it exists, otherwise built-in defaults. A `-config` path that is missing is fatal.
- **CIBA queue polling**: `MemoryQueue.Poll()` uses a channel. `queue.type: redis` stores the same requests with a TTL of `expires_at` and approves them in one Redis script.
- **OIDC key generation**: RSA + EC keys generated on startup. `subject_type: pairwise` replaces `sub` with a sector PPID. `oidc.pairwise_salt` is required when any pairwise client exists. Changing the salt changes every pairwise `sub`. ID tokens and UserInfo are nested JWEs (`RSA-OAEP-256` + `A256GCM`) only when the client sets the matching `*_encrypted_response_alg` and `*_encrypted_response_enc` and publishes an encryption key. Access tokens stay unencrypted.
- **Config defaults**: Server binds `0.0.0.0:8080`, SQLite at `./atrium.db`
- **MFA**: TOTP with QR code rendering (PNG for web, ASCII for CLI)
- **Management API**: `/api` and `/ciba` require a client-credentials access token with scope `management`. `atrium-cli init` writes `management.client_id` and `management.client_secret`. Startup inserts that client when it is missing. The CLI and `atrium-mobile` send the bearer token (`--client-id`, `--client-secret`, or `management.*` in `--config`).
- **CIAM**: `/api/me` uses the user access token. Public reset and registration live under `/api/account`. SMTP is `smtp` in config and stays off until `enabled` is true.
- **Sessions**: Browser sessions are SQLite rows. Cookie lifetime is `security.session_lifetime` (default 8h). `/device` approval uses that session. `/oauth/logout` sends OIDC back-channel logout tokens.
- **Refresh tokens**: Rotation keeps `family_id`. Reuse revokes that family. List APIs return a public id and omit the secret.
- **Login analytics**: `login_events` stores IP and user agent. `GET /api/me/login-analytics` and `GET /api/analytics/logins` summarize attempts, failure rate, new addresses, per-IP totals, and per-day totals. `security.trusted_proxies` is the only case where `X-Forwarded-For` is read. A first-seen address sets `new_ip` on the login webhook.
- **Webhooks**: `webhooks` table. Management CRUD at `/api/webhooks`. Each row lists events (`login`, `logout`, `sso_session_triggered`, `bruteforce_detected`, `forgot_password`, `change_password`, and others). Delivery is HMAC-SHA256 in `X-Webhook-Signature` and does not fail the user action.
- **Templates**: Go `html/template` in `internal/templates/`. `branding.templates` replaces a page by file name at startup. `docs.html` is not part of the auth chrome. Editing the embedded HTML does not change a built `bin/atrium` until the next build; the overlay directory does, after a restart.
- **OpenAPI**: Spec in `openapi/spec.yaml`, Scalar UI at `/docs`
- **Traces**: `telemetry.enabled` is false unless set. When it is true, `telemetry.otlp_endpoint` is required and the server exports OTLP/HTTP spans. One request log carries `trace_id`. The HTTP span is the root. Handlers, helpers, and SQL queries on that goroutine are child spans. Query spans keep the statement and the argument count, not the values. `log.format` is `text` or `json`. Span attributes on the request are `client_id`, `grant_type`, `org_id`, and `oauth.error`. Tokens, codes, and secrets are not span attributes.
- **Email templates**: `email.templates_dir` is empty unless set. Files are `reset.txt`, `verify.txt`, `password_changed.txt`, `new_sign_in.txt`, and `login_failed.txt`. The first line is `Subject:`. A missing file keeps the built-in text. A broken file stops startup.
- **Login identifier**: `security.login_identifier` is `username` (default) or `email`. The password-grant field stays `username`. Email mode rejects a duplicate mailbox.
- **Organizations**: `org.enabled` is false unless set. `org.enabled_domain_based_autolookup` requires `org.enabled`. When autolookup is on and a non-interactive request omits `organization`, a member whose email domain matches an organization domain receives that `org_id`. The browser authorize flow shows `/organization` when the user belongs to more than one organization and neither the client nor the request has already chosen one. `prompt=none` returns `interaction_required` in that case. An explicit organization still requires membership.

## OAuth Flows Implemented

| Flow | Endpoint | Status |
|------|----------|--------|
| Authorization Code + PKCE | `/oauth/authorize` + `/oauth/token` | Working |
| Client Credentials | `/oauth/token` | Working |
| Device Code | `/oauth/device` + `/oauth/token` | Working |
| CIBA (Poll mode) | `/oauth/bc-authorize` + `/oauth/token` | Working |
| PAR | `/oauth/par` | Working |
| Token Introspection | `/oauth/introspect` | Working. Confidential clients only. A client sees its own tokens, tokens whose `resource` is that client, or any token when it is the global management client. |
| Token Revocation | `/oauth/revoke` | Working |
| Dynamic Registration | `/oauth/register` | Working |
| OIDC Discovery | `/.well-known/openid-configuration` | Working |
| JWKS | `/oidc/jwks` | Working |
| UserInfo | `/oidc/userinfo` | Working |
| RP-Initiated Logout | `/oauth/logout` | Working |
| Back-Channel Logout | client `backchannel_logout_uri` | Working |

## CLI Tools

```bash
# Initialize config and internal/hashalgo/algo.go
./bin/atrium-cli init
./bin/atrium-cli init --mfa
./bin/atrium-cli init --hash argon2id
./bin/atrium-cli init --output myconfig.yaml
./bin/atrium-cli init --force
HASH_ALGO=./myhash.go ./bin/atrium-cli init

# Management
./bin/atrium-cli client list
./bin/atrium-cli client create --name "App" --redirect-uri "https://example.com/cb"
./bin/atrium-cli user create --username "user" --password "pass"
./bin/atrium-cli ciba pending

# MFA
./bin/atrium-cli mfa enable --user-id <id>
./bin/atrium-cli mfa enable --user-id <id> --show-secret
./bin/atrium-cli mfa verify --user-id <id> --code 123456

# Mobile
./bin/atrium-mobile list
./bin/atrium-mobile approve <auth-req-id> --user-id <user-id>
./bin/atrium-mobile deny <auth-req-id> --reason "Denied"
```

## Development

- Hot reload: `just dev` (requires `air` - install via `just install-tools`)
- Linting: `just lint` (requires `golangci-lint`)
- Formatting: `just fmt` (requires `goimports`)
- Full check: `just check` (fmt → vet → lint → test)

## Dependencies

Key external packages:
- `github.com/go-chi/chi/v5` - HTTP router
- `github.com/pquerna/otp` - TOTP generation/validation
- `github.com/skip2/go-qrcode` - QR code rendering
- `github.com/golang-jwt/jwt/v5` - JWT handling
- `github.com/spf13/cobra` - CLI framework
- `modernc.org/sqlite` - SQLite driver
- `github.com/jackc/pgx/v5` - Postgres driver
- `github.com/redis/go-redis/v9` - Redis client
- `golang.org/x/crypto` - bcrypt and argon2id password hashing
- `go.opentelemetry.io/otel` - optional OTLP/HTTP traces
