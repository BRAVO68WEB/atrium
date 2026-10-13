# OAuth Implementation Server

oauth-impl is a self-hosted OAuth 2.0 and OpenID Connect issuer. One Go
process serves the protocol, the browser sign-in pages, and the management
API.

## Goals

Run it with a SQLite file and no extra services. `just run` is enough for
local use. Administration is a client-credentials token with the
`management` scope, through `/api` and `oauth-cli`. Postgres, Redis, SMTP,
and traces turn on when you set them.

## Features

- Authorization code with PKCE, client credentials, device code, refresh
  tokens, token exchange, and on-behalf-of delegation to a registered agent
- A paste-the-code page for the out-of-band redirect URNs, and an optional
  combined-code helper at `/oauth/oob`
- CIBA in poll mode, and pushed authorization requests
- OpenID Connect discovery, JWKS, UserInfo, and ID tokens
- Pairwise subjects, and nested encryption for ID tokens and UserInfo when
  a client opts in
- DPoP and mutual TLS client authentication
- TOTP enrollment, browser login, registration, consent, organization
  choice, and logout
- Account APIs for the signed-in user, and management APIs for the
  management client
- Dynamic client registration and client ID metadata documents
- Social login, webhooks, audit, and login analytics

Access tokens are opaque unless you set `security.access_token_format` to
`jwt`.

## Quick start

```bash
git clone https://github.com/bravo68web/oauth-impl.git
cd oauth-impl
just run
```

With no `config.yaml`, the server listens on `http://localhost:8080`. When
that file is present, `just run` uses its port and TLS settings.

```bash
just build
./bin/oauth-cli init
```

`init` writes `config.yaml` and `internal/hashalgo/algo.go`. It leaves an
existing file in place unless you pass `--force`.

## Documentation

| Guide | What it covers |
| --- | --- |
| [Configuration](docs/CONFIG.md) | Config file, keys, mail templates, hashing |
| [Deploy](docs/DEPLOY.md) | Process, TLS, Postgres, Redis, SMTP, traces |
| [Branding](docs/BRANDING.md) | Login pages, assets, and HTML overlays |
| [CLI](docs/CLI.md) | `oauth-cli` and `oauth-mobile` |
| [Infrastructure](docs/INFRA.md) | Process layout, SQL, Redis, signing keys |
| [Testing](docs/TESTING.md) | Go tests, Postgres, and the browser suite |
| [API](docs/API.md) | Route map and the OpenAPI spec |
| [Push devices](docs/PUSH.md) | Authenticator registration |
| [AAuth](docs/AAUTH.md) | Agent authorization discovery |
| [Contributing](CONTRIBUTING.md) | Checks, hasher contract, and pull requests |

After the server is running, the Scalar UI is at
[http://localhost:8080/docs](http://localhost:8080/docs).

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Jyotirmoy Bandyopadhayaya.
