# Deploy

This page is how you run oauth-impl. Keys and defaults are in
[Configuration](CONFIG.md). The data layout is in
[Infrastructure](INFRA.md).

## Start the process

From the repository root:

```bash
just run
```

`just run` executes `go run cmd/oauth-server/main.go`. With no
`config.yaml` in the working directory, the server listens on
`http://localhost:8080`. When `config.yaml` is present, that file sets
the host, port, and TLS.

```bash
just dev                 # reload on save, requires air
just build               # bin/oauth-server, bin/oauth-cli, bin/oauth-mobile
./bin/oauth-server
go run cmd/oauth-server/main.go --port 9090
go run cmd/oauth-server/main.go --config /etc/oauth/config.yaml
go run cmd/oauth-server/main.go --db /var/lib/oauth/oauth.db
```

`--port` overrides `server.port`. `--db` overrides `database.path`. A
missing file passed to `--config` exits. An empty `--config` still loads
`./config.yaml` when that file exists.

Run the server from the project root. Startup reads
`internal/hashalgo/algo.go` and refuses to serve when that file differs
from the binary.

`GET /health` returns `{"status":"ok"}`.

`oauth-server --version` prints the build version. `--help` lists
`--config`, `--port`, `--db`, and `--version`. `GET /version` needs no
token. A local build returns `{"version":"dev"}`. A release build adds
`commit` and `date`.

## TLS

Set `server.tls.enabled` and point `cert_file` and `key_file` at the
certificate and key. Client certificates use `client_ca`, `client_auth`
(`require_and_verify`, `require`, `request`, or `none`), and `crl_file`.
A missing client CA is fatal when TLS client auth is configured. A
missing CRL is a warning.

`scripts/cert.sh` writes a local CA and server certificate under
`certs/` and replaces `config.yaml` with a TLS example on port 8443.
Use it on a fresh checkout. When you already have a config, set the TLS
paths yourself. `scripts/cert.sh --force` regenerates the certificates.
`certs/` is gitignored.

## Reverse proxy

Set `security.issuer` and `oidc.issuer` to the public `https` URL. The
browser and discovery documents use that issuer.

The client IP recorded for login analytics is the TCP peer. List the
proxy in `security.trusted_proxies` as CIDR blocks, for example
`10.0.0.0/8`, when the server sits behind a proxy. Only then are
`X-Forwarded-For` and `X-Real-IP` read. A forwarded address that is
itself inside that list is skipped.

## Postgres

SQLite is the default. For Postgres:

```yaml
database:
  driver: postgres
  dsn: postgres://oauth:oauth@localhost:5432/oauth?sslmode=disable
  migrations: true
```

`database.path` is unused when the driver is `postgres`. Integer flags
are stored as `0` and `1`.

## Redis

Leave `redis.addr` empty to keep the approval queue, CIMD documents, and
DPoP replay in the process. Set the address and switch the consumers you
want to share:

```yaml
redis:
  addr: localhost:6379
  prefix: oauth
queue:
  type: redis
cache:
  provider: redis
```

`addr` is `host:port` or a `redis://` URL. The process opens one
connection when the queue, the cache, or notify asks for Redis. Users,
sessions, tokens, consents, and audit stay in SQL. More than one
server process shares queue and cache state only when those settings
are `redis`. The key names, and the warning you get when the queue is
shared and the cache is not, are in [Infrastructure](INFRA.md).

## Notify

Webhook and mail delivery run after the response. `notify.type` is
`memory`, `redis`, or `rabbitmq`. `memory` is the default. A restart
drops jobs still in that process. `redis` uses `redis.addr` and stores
due jobs under `prefix:notify:`. `rabbitmq` uses `notify.rabbitmq.url`.

A failed attempt waits 1 second, then 5 seconds, 30 seconds, 2
minutes, and 10 minutes. A 4xx response other than 429 is not retried.
`POST /api/webhooks/{id}/test` still waits for that one call. Login
recording stays in the process so the next attempt sees the new row.

## SMTP

Password reset, email confirmation, and login mail send when
`smtp.enabled` is true. The server stores the token or the login,
returns the response, and then talks to SMTP. With SMTP off,
forgot-password returns `503` and `mailer_disabled`. An operator can
still set a password with `oauth-cli user password` or
`POST /api/users/{id}/password`. Login still succeeds when a send
fails.

Message text is in [Configuration](CONFIG.md).

Mailpit catches that mail when you want to read it without a real
mailbox. `deploy/compose.yaml` starts `axllent/mailpit` and points the
stack SMTP settings at it. Open http://localhost:8025 for the inbox.
The API is `GET http://localhost:8025/api/v1/messages`. A server you
start on the host uses this block instead, because `mailpit` is only a
name inside Compose:

```yaml
smtp:
  enabled: true
  host: 127.0.0.1
  port: 1025
  from: oauth@localhost
  starttls: false
  implicit_tls: false
```

## Webhook tester

`deploy/compose.yaml` also starts `tarampampam/webhook-tester` on
http://localhost:8089. With auto-created sessions, any URL whose first
path segment is a UUID is a capture bucket. Open the bucket in the UI
at `/s/<uuid>`.

The server refuses plain `http` except to a loopback address, and it
refuses private addresses. Register the hook from a server that is
running on the host:

```yaml
security:
  allow_insecure_fetch: true
  fetch_allow_ips:
    - 127.0.0.1
```

Use `http://127.0.0.1:8089/11111111-2222-3333-4444-555555555555` as the
webhook URL, then open
http://localhost:8089/s/11111111-2222-3333-4444-555555555555.
`POST /api/webhooks/{id}/test` waits for this receiver and returns the
result. The browser suite still uses its own receivers and does not
call Mailpit or webhook-tester.

## Compose examples

`deploy/compose.yaml` builds the tree you have checked out, with
Postgres and Mailpit.

`deploy/examples/image/compose.yaml` runs the published `0.1.1` image
with the same two services. That image contains the stock bcrypt
hasher. Mounting a different `algo.go` does not change it.

`deploy/examples/full/compose.yaml` builds an image whose hasher is
`internal/hashalgo/examples/pbkdf2-sha256`. New passwords are
PBKDF2-HMAC-SHA256 at 600000 iterations, and a stored bcrypt hash still
verifies. The stack also runs Postgres, Redis for the cache and the
CIBA queue, RabbitMQ for webhook and mail retries, an OpenTelemetry
collector, Mailpit, and the five files in `deploy/examples/full/email`.

```bash
docker compose -f deploy/examples/image/compose.yaml up
docker compose -f deploy/examples/full/compose.yaml up --build
```

The full server is at http://localhost:8080. Mailpit is at
http://localhost:8025. RabbitMQ management is at
http://localhost:15672 with user `oauth` and password `oauth`. The
collector prints spans to its own log.

## Logs and traces

Each request writes one log record. The fields are `method`, `route`,
`status`, `duration_ms`, `client_id`, `grant_type`, `org_id`,
`oauth.error`, `trace_id`, and `span_id`. `route` is the path pattern,
so `/api/users/{userID}` stays one series. `trace_id` and `span_id` are
empty while tracing is off. `log.format` is `text` or `json`.

Traces stay off unless `telemetry.enabled` is true. The server then
exports OTLP over HTTP to `telemetry.otlp_endpoint`. Enabling traces
with an empty endpoint is a startup error. The trace for one request
starts at the HTTP span. Each handler and helper on that goroutine is a
child span, and each query is a child of the function that ran it. The
query span keeps the SQL text with placeholders. Argument values and
quoted literals are not attributes. A client fetch is an `http.client`
span with the host and the status code, not the query string. Spans
omit tokens, codes, secrets, and `Authorization`. Copy `trace_id` from
the log into your tracing UI to see the path, the functions, and the
time spent in each.

## Release

Pushing a `v*` tag is the only publish step. A tag such as `v1.2.3`
creates a GitHub Release and a container image. Pushes to `main` do not
publish either one.

```bash
git tag v1.2.3
git push origin v1.2.3
```

The release archive for each OS and architecture contains
`oauth-server`, `oauth-cli`, and `oauth-mobile`, plus
`internal/hashalgo/algo.go`. Linux and macOS archives are `.tar.gz`.
Windows archives are `.zip`. The names look like
`oauth-impl_1.2.3_linux_amd64.tar.gz` and
`oauth-impl_1.2.3_windows_386.zip`.

| OS | amd64 | 386 | arm64 |
| --- | --- | --- | --- |
| linux | yes | yes | yes |
| windows | yes | yes | yes |
| darwin | yes | no | yes |

macOS has no 32-bit build. Extract an archive and run `./oauth-server`
from that directory so startup can read the hasher file.

The server image is `ghcr.io/bravo68web/oauth-impl`. One tag covers
`linux/amd64`, `linux/arm64`, and `linux/arm/v7`. A stable tag also
publishes `1.2.3`, `1.2`, `1`, and `latest`. A prerelease tag such as
`v1.2.3-rc.1` publishes `1.2.3-rc.1` and leaves `latest` where it is.

```bash
docker run --rm -p 8080:8080 ghcr.io/bravo68web/oauth-impl:1.2.3
```

That container listens on port 8080 and stores SQLite in its working
directory. With no config file, it uses the same built-in defaults as
`just run`. Those defaults are for a local trial: HTTP only, issuer
`http://localhost:8080`, PKCE not required, and plain PKCE allowed.
Mount a config when you want Postgres, TLS, or stricter token rules:

```bash
docker run --rm -p 8080:8080 \
  -v "$PWD/config.yaml:/config/config.yaml:ro" \
  ghcr.io/bravo68web/oauth-impl:1.2.3 \
  -config /config/config.yaml
```

`deploy/compose.yaml` already passes that `-config` argument. The first
push creates a private GHCR package. Open the package, link it to this
repository, and set the visibility to public before other people can
pull it.

## Related

[Configuration](CONFIG.md) lists every key.
[CLI](CLI.md) is how you manage the running server.
