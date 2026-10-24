# API

The field-level contract is the OpenAPI document. This page is the route
map. Command equivalents are in [CLI](CLI.md). Sample curls are in
[examples.sh](examples.sh).

| Document | Where |
| --- | --- |
| Spec source | `openapi/spec.yaml` |
| Scalar UI | `GET /docs` |
| Spec JSON | `GET /openapi` |
| Spec YAML | `GET /docs/openapi.yaml` |

`just docs` prints those URLs for a server on port 8080.

## Who can call what

`/api` management routes and `/ciba` need `Authorization: Bearer` with a
client-credentials token whose scope contains `management`. `oauth-cli
init` writes that client into `management.client_id` and
`management.client_secret`. The server inserts the client on startup
when the id is missing.

A user access token calls `/api/me`. It cannot call the management
routes. Dynamic registration drops the `management` scope. A
client-credentials request can only receive scopes already stored on
the client.

`GET /api/backup` and `POST /api/restore` move the durable directory.
The document version is `1`. It includes users (with ids and password
hashes), clients (with secrets), organizations, consents, scopes,
resources, webhooks, social identities, push devices, pairwise
subjects, and signing keys. It does not include sessions, access
tokens, refresh tokens, or authorization codes. `?dry_run=true` writes
nothing. `?force=true` is required when the server already has a user
or a client other than the management client. A restore that includes
signing keys replaces the key set and the live JWKS. Pairwise subjects
match only when `oidc.pairwise_salt` is the same value that produced
them. The salt is not in the file.

`POST /api/users/import` and `GET /api/users/export` move accounts.
The body is `{ "mode": "create", "users": [ ... ] }`. `mode` may be
`upsert`. A row sets `password` or `password_hash`, not both. A hash
is stored when the server hasher accepts it: bcrypt, argon2id, or
`Recognizes` on the hasher from `internal/hashalgo/algo.go`.
`?dry_run=true` writes nothing. Export omits secrets unless
`include_secrets=true`. Sessions and tokens are not in the file.

Public account routes are `POST /api/account/register`,
`POST /api/account/password/forgot`, `POST /api/account/password/reset`,
and `POST /api/account/email/verify`.

`GET /health` needs no token. `GET /version` needs no token. A local
build returns `{"version":"dev"}`. A release build adds `commit` and
`date`.

Push-device registration is separate from `/oauth/device`. It is off
unless `push.enabled` is true. See [Push devices](PUSH.md).
AAuth discovery is separate from these routes. It is off unless
`aauth.enabled` is true. See [AAuth](AAUTH.md).

## OAuth and OIDC

| Method | Path | Role |
| --- | --- | --- |
| GET, POST | `/oauth/authorize` | Authorization endpoint |
| GET | `/oauth/oob` | Combined-code helper |
| POST | `/oauth/token` | Token endpoint |
| POST | `/oauth/revoke` | Revoke a token (RFC 7009) |
| POST | `/oauth/introspect` | Introspect a token (RFC 7662) |
| POST | `/oauth/register` | Dynamic client registration |
| POST | `/oauth/device` | Device authorization |
| POST | `/oauth/par` | Pushed authorization request |
| POST | `/oauth/bc-authorize` | CIBA backchannel authentication |
| GET, POST | `/oauth/logout` | RP-initiated logout |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/.well-known/oauth-authorization-server` | Authorization server metadata |
| GET | `/oidc/jwks` | Signing keys |
| GET | `/oidc/userinfo` | UserInfo |

`POST /oauth/token` accepts these `grant_type` values when the client
allows them:

| Grant | `grant_type` |
| --- | --- |
| Authorization code | `authorization_code` |
| Client credentials | `client_credentials` |
| Refresh | `refresh_token` |
| Device code | `urn:ietf:params:oauth:grant-type:device_code` |
| CIBA | `urn:openid:params:grant-type:ciba` |
| Token exchange | `urn:ietf:params:oauth:grant-type:token-exchange` |
| Password | `password` |
| JWT bearer | `urn:ietf:params:oauth:grant-type:jwt-bearer` |

The default discovery list includes every grant above except `password`
and the JWT bearer grant. The JWT bearer grant is advertised only when
`xaa.enabled` is true. See [Cross-app access](XAA.md).

`oauth-cli client master` creates a client that includes `password`.
The password grant sends the identifier in `username`. CIBA on this
server is poll mode. A token exchange has to present an access token
this client already holds. The new scope stays inside that token's
scope.

With `xaa.enabled` on, token exchange accepts
`requested_token_type` `urn:ietf:params:oauth:token-type:id-jag`.
`subject_token` is an ID token from this server and `audience` is the
resource authorization server. The JWT bearer grant then accepts that
assertion. Neither response includes a refresh token.

A client can register `urn:ietf:wg:oauth:2.0:oob` or
`urn:ietf:wg:oauth:2.0:oob:auto` instead of an HTTP callback. The request
must use `response_type=code` and PKCE `S256`. After sign-in the server
returns an HTML page that shows the code. The token request sends that
same `redirect_uri` with the pasted code and `code_verifier`. `oauth-cli
flow paste` prints the URL and reads the code.

When `security.oob_helper` is true, `GET /oauth/oob` is the helper page
from draft-richer-oauth-oob-authcode. Register that URL as a normal
redirect URI. The authorization response is still a redirect, with `code`
and `state` on the query string. The page shows one combined value. The
draft names an HKDF info parameter and does not assign its bytes. This
server uses the ASCII string `draft-richer-oauth-oob-authcode`. With the
flag off, the path returns 404.

An authorization request may include `requested_actor`, the client id
of an agent registered on this server. That request requires PKCE
`S256`. The consent screen names the agent and is shown on every such
request. The token request then includes `actor_token`, an access token
this server already issued to that agent. The access token is a JWT
(`typ` `at+jwt`) even when the server default is opaque. `sub` is the
user, `aud` is the resource or the issuer, `client_id` and `azp` are the
calling client, and `act` is `{"sub":"<agent client id>"}`. A code
without `requested_actor` rejects `actor_token`.

JWT access tokens from every grant use that same profile. `aud` is the
`resource` parameter when the request sends one, and the issuer
otherwise.

`POST /oauth/introspect` is for confidential clients. A client sees its
own tokens, tokens whose resource is that client, or every token when
it is the management client. Anyone else gets `{"active":false}`.

Authorize `response_type`:

| Response type | Returns |
| --- | --- |
| `code` | Authorization code |
| `token` | Access token |
| `id_token` | ID token |
| `code id_token` | Code and ID token |
| `code token` | Code and access token |
| `code id_token token` | All three |
| `id_token token` | ID token and access token |
| `none` | No token, `state` only |

ID tokens and UserInfo are signed. They are encrypted as a nested JWE
only when the client sets the encryption algorithms and publishes an
RSA key. Access tokens stay unencrypted. A client with `subject_type:
pairwise` receives a sector subject. See [Configuration](CONFIG.md).

## Browser

| Method | Path | Role |
| --- | --- | --- |
| GET, POST | `/login` | Password form |
| POST | `/login/mfa` | TOTP step |
| GET | `/login/social/{id}` | Start social login |
| GET | `/login/social/{id}/callback` | Finish social login |
| GET, POST | `/register` | Self-service signup |
| GET, POST | `/consent` | Consent |
| GET, POST | `/organization` | Choose an organization |
| GET, POST | `/forgot`, `/reset` | Password reset pages |
| GET | `/verify-email` | Email confirmation page |
| GET, POST | `/device` | Device-code approval |
| GET | `/mfa/enroll` | TOTP enrollment |
| POST | `/mfa/enroll/verify` | Confirm enrollment |
| GET | `/branding/assets/{name}` | One branding file |

`/organization` appears when organizations are on, the request did not
name one, and the user has more than one membership. See
[Configuration](CONFIG.md).

## Account API

User token:

```
GET    /api/me
PATCH  /api/me
POST   /api/me/password
POST   /api/me/email/send
GET    /api/me/sessions
DELETE /api/me/sessions/{sid}
GET    /api/me/refresh-tokens
DELETE /api/me/refresh-tokens/{id}
GET    /api/me/activity
GET    /api/me/login-analytics?window=720h
GET    /api/me/consents
DELETE /api/me/consents/{clientID}
```

`DELETE /api/me/consents/{clientID}` removes that application's consent
and revokes its access and refresh tokens. The same removal is
`DELETE /api/consents?user_id=&client_id=` for a management client, and
the browser page `GET /profile` for the signed-in user.

`/profile` also changes the password, sends a verification email, turns
off an authenticator after a valid code, and signs out other browsers.
The current browser has no sign-out button on that list.

`window` is a Go duration. The default is 30 days (`720h`).

## Management API

Clients, users, and tokens:

```
GET    /api/clients
POST   /api/clients
GET    /api/clients/{id}
PUT    /api/clients/{id}
DELETE /api/clients/{id}

GET    /api/users
POST   /api/users
GET    /api/users/{id}
PATCH  /api/users/{id}
POST   /api/users/{id}/password
POST   /api/users/{id}/mfa/enable
POST   /api/users/{id}/mfa/verify
GET    /api/users/{id}/mfa/status
POST   /api/users/{id}/mfa/disable
GET    /api/users/{id}/sessions
DELETE /api/users/{id}/sessions/{sid}
GET    /api/users/{id}/activity
GET    /api/users/{id}/login-analytics

GET    /api/tokens
POST   /api/tokens/{token}/revoke
GET    /api/refresh-tokens
POST   /api/refresh-tokens/{id}/revoke
```

Refresh-token lists use the public id and omit the secret.

Scopes, resources, and consents:

```
GET    /api/scopes
POST   /api/scopes
GET    /api/scopes/{name}
DELETE /api/scopes/{name}

GET    /api/resources
POST   /api/resources
GET    /api/resources/{uri}
PUT    /api/resources/{uri}
DELETE /api/resources/{uri}
GET    /api/resources/{uri}/scopes

GET    /api/consents
DELETE /api/consents
```

Organizations, webhooks, audit, analytics, CIBA, and keys:

```
GET    /api/orgs
POST   /api/orgs
GET    /api/orgs/{orgID}
POST   /api/orgs/{orgID}/domains
POST   /api/orgs/{orgID}/members
```

`POST /api/orgs` takes `name`, `slug`, optional `domains`, and optional
`logo_url`. `logo_url` is an absolute http or https URL. The organization
picker shows that image. An empty `logo_url` shows the first letter of
the name on a colored ground. The color is chosen from the name, so it
stays the same each visit.

```

GET    /api/webhooks
POST   /api/webhooks
GET    /api/webhooks/{id}
PATCH  /api/webhooks/{id}
DELETE /api/webhooks/{id}
POST   /api/webhooks/{id}/test

GET    /api/audit
GET    /api/analytics/logins
POST   /api/keys/rotate

GET    /api/ciba/pending
POST   /api/ciba/{id}/approve
POST   /api/ciba/{id}/deny
```

`oauth-mobile` calls `GET /ciba/pending`, `POST /ciba/approve`, and
`POST /ciba/deny`. Its `status` command calls `GET /health`.

Webhook deliveries are `POST` JSON. `X-Webhook-Signature` is `sha256=`
plus the hex HMAC-SHA256 of the timestamp, a dot, and the raw body, using
the webhook secret.
`X-Webhook-Timestamp` is the unix time. `X-Webhook-Event` is the event
name. `*` subscribes to every event. Events include `login`,
`login_failed`, `logout`, `sso_session_triggered`,
`bruteforce_detected`, `forgot_password`, `change_password`,
`password_reset`, `user_registered`, `email_verified`, and
`user_disabled`. The server returns the response, then delivers the
event. A failed delivery is retried for about 10 minutes. A delivery
error is logged and does not change that response.
`POST /api/webhooks/{id}/test` still waits for the receiver and sends
`webhook.test`.

`POST /api/keys/rotate` returns the new key ids. Private keys stay in
SQL. See [Infrastructure](INFRA.md).

## Errors

Protocol errors use the OAuth shape:

```json
{
  "error": "invalid_request",
  "error_description": "what went wrong"
}
```

The OpenAPI document lists status codes per route.

## Related

[CLI](CLI.md) calls these routes.
[Configuration](CONFIG.md) is the issuer and client policy behind them.
