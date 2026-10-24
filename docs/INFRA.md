# Infrastructure

oauth-impl is three binaries and one SQL database. Optional Redis holds
only expiring data. Operator settings are in [Configuration](CONFIG.md).
How to start the process is in [Deploy](DEPLOY.md).

## Binaries

| Binary | Role |
| --- | --- |
| `oauth-server` | HTTP issuer, browser pages, management API |
| `oauth-cli` | Management client for that API |
| `oauth-mobile` | Poll and approve CIBA requests |

Build them with `just build`. Output goes to `bin/`.

## Request path

```
HTTP request
  -> internal/route          URL to controller
  -> internal/controller     request and response
  -> internal/service        rules, no SQL
  -> internal/repository     SQL only
  -> SQLite or Postgres
```

OAuth and OIDC protocol handlers live in `internal/handlers/oauth` and
`internal/oidc`. Browser HTML is in `internal/templates`. The OpenAPI
document is `openapi/spec.yaml`.

## SQL

`database.driver` is `sqlite` or `postgres`. SQLite is the default, at
`database.path` (`./oauth.db`). The SQLite pool uses one connection.

`database.Migrate` applies the schema when `database.migrations` is true.
Files in `migrations/` record those steps. They are not a second
migrator.

Booleans are stored as integers `0` and `1`. Timestamps are written in a
form both drivers scan.

Users, sessions, tokens, consents, audit, organizations, and webhook
subscriptions stay in SQL.

## Redis

`queue.type` and `cache.provider` stay `memory` when `redis.addr` is
empty. One Redis connection serves both when either setting is
`redis`. Redis holds only values that expire:

| Key | How long it lives | What it is |
| --- | --- | --- |
| `q:<id>` and `q:exp` | until the request expires | CIBA and device approval queue |
| `cimd:<client id>` | 5 minutes | fetched client metadata document |
| `sector:<url>` | 5 minutes | sector identifier document |
| `dpop:jti:<jti>` | 10 minutes | DPoP proof replay |
| `xaa:subject:<hash>` | until the token expires | subject-token replay |
| `xaa:used:<issuer and jti>` | until the assertion expires | ID-JAG replay |

The prefix in front of those keys is `redis.prefix`, which defaults to
`oauth`. Users, sessions, clients, tokens, and signing keys stay in
SQL. A cache error on a metadata document is a miss, and the server
fetches the document again. A cache error on a replay key rejects the
proof.

If `queue.type` is `redis` and `cache.provider` is `memory`, startup
logs a warning. The approval queue is shared across processes. DPoP,
XAA, CIMD, and sector state are not.

## Signing keys

The process generates RSA and EC signing keys on startup and publishes
them at `/oidc/jwks`. `oidc.key_rotation_interval` of `0s` leaves
rotation off. `POST /api/keys/rotate`, or `oauth-cli keys rotate`,
publishes a new pair and keeps the previous public keys until
`oidc.key_retain` elapses (48 hours by default). Private keys stay in
SQL.

## Related

[API](API.md) is the route map.
[Testing](TESTING.md) is how the Postgres and browser suites run.
