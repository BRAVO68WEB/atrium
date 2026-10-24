# CLI

`oauth-cli` calls the management API. `oauth-mobile` approves CIBA
requests. Both take a client-credentials client. Sample curls are in
[examples.sh](examples.sh). Routes are in [API](API.md).

## Build

```bash
just build
# or
just build-cli
just build-mobile
```

Binaries land in `bin/`.

## Version

`oauth-server --version`, `oauth-cli --version`, and
`oauth-mobile --version` print the build version. `--help` lists the
flags. `GET /version` returns the same version as JSON. A local build
reports `dev`. A release build adds the commit and the build time.

## Credentials

Both tools share these flags:

| Flag | Default | Meaning |
| --- | --- | --- |
| `--server` | `http://127.0.0.1:8080` | Issuer URL |
| `--client-id` | empty | Management client id |
| `--client-secret` | empty | Management client secret |
| `--config` | `config.yaml` | File that holds `management.client_id` and `management.client_secret` |

When the flags are empty, the tool reads credentials in this order:
`OAUTH_CLI_CLIENT_ID` and `OAUTH_CLI_CLIENT_SECRET`, then `--config`.
A remote file can be only `server`, `client_id`, and `client_secret`.
A server `config.yaml` still works through `management.client_id` and
`management.client_secret`. The CLI does not open a database.
It then asks `POST /oauth/token` for a token with scope `management`.
`OAUTH_CLI_SERVER` sets the issuer when you do not pass `--server`.

```bash
oauth-cli --server https://auth.example.com \
  --client-id "$OAUTH_CLI_CLIENT_ID" \
  --client-secret "$OAUTH_CLI_CLIENT_SECRET" \
  user list
```

`oauth-mobile` also has `--interval` (default 5 seconds) for `poll`.

## init

`init` does not talk to a running server. It writes the config and the
hasher. See [Configuration](CONFIG.md).

```bash
./bin/oauth-cli init
./bin/oauth-cli init --mfa --output config.yaml
./bin/oauth-cli init --hash argon2id
./bin/oauth-cli init --force
```

## oauth-cli commands

```bash
./bin/oauth-cli server status
./bin/oauth-cli server discovery
```

### Clients

```bash
./bin/oauth-cli client list
./bin/oauth-cli client create --name "App" --redirect-uri "https://app.example/cb"
./bin/oauth-cli client get <id>
./bin/oauth-cli client update <id> --dpop
./bin/oauth-cli client delete <id>
./bin/oauth-cli client master
```

`create` accepts repeated `--redirect-uri`, `--grant-type` (default
`authorization_code`), and `--scope` (default `openid`), plus
`--dcr-enabled` and `--cimd-enabled`. `master` creates one client with
the grants used by conformance tools, including `password`.

### Users

```bash
./bin/oauth-cli user list
./bin/oauth-cli user create --username ada --password "correct horse" --email ada@example.com
./bin/oauth-cli user get <id>
./bin/oauth-cli user password <id> --password "a new secret"
./bin/oauth-cli user disable <id>
./bin/oauth-cli user enable <id>
./bin/oauth-cli user import users.json
./bin/oauth-cli user import users.json --mode upsert --dry-run
./bin/oauth-cli user export --output users.json
./bin/oauth-cli user export --include-secrets --output users.json
```

`import` reads the same JSON document as `POST /api/users/import`.
It exits non-zero when any row has an error. `export` omits password
hashes and TOTP secrets unless you pass `--include-secrets`. The file
mode is `0600`. `init` does not call a remote server.

### Backup

```bash
./bin/oauth-cli backup --output auth-backup.json
./bin/oauth-cli restore auth-backup.json --dry-run
./bin/oauth-cli restore auth-backup.json
./bin/oauth-cli restore auth-backup.json --force
```

`backup` and `restore` call `GET /api/backup` and `POST /api/restore`.
The file holds users, clients, organizations, consents, webhooks,
social identities, push devices, pairwise subjects, and signing keys.
It includes password hashes, client secrets, webhook secrets, TOTP
secrets, and private keys. It does not include sessions or tokens.
The written file mode is `0600`. A restore onto a server that already
has a user, or a client other than the management client, is refused
unless you pass `--force`. `--dry-run` prints the counts and writes
nothing. Keep `config.yaml` and `internal/hashalgo/algo.go` next to
the file. `oidc.pairwise_salt` is not inside the JSON. Pairwise
subjects only match when that salt is unchanged.

### Tokens

```bash
./bin/oauth-cli token list --client-id <id> --user-id <id>
./bin/oauth-cli token revoke <access-token>
./bin/oauth-cli token introspect <token>
./bin/oauth-cli token refresh list
./bin/oauth-cli token refresh revoke <id>
```

`refresh list` prints public ids. It does not print the refresh token
secret.

### MFA

Enrollment in the CLI is TOTP.

```bash
./bin/oauth-cli mfa enable --user-id <id>
./bin/oauth-cli mfa enable --user-id <id> --show-secret
./bin/oauth-cli mfa verify --user-id <id> --code 123456
./bin/oauth-cli mfa status --user-id <id>
```

### CIBA, flows, and keys

```bash
./bin/oauth-cli ciba pending
./bin/oauth-cli ciba approve <auth-req-id> --user-id <id>
./bin/oauth-cli ciba deny <auth-req-id> --reason "Denied"

./bin/oauth-cli flow client-credentials --client-id <id> --client-secret <secret>
./bin/oauth-cli flow device --client-id <id> --client-secret <secret>
./bin/oauth-cli flow paste --client-id <id>

./bin/oauth-cli keys generate --output ./keys
./bin/oauth-cli keys rotate
```

`flow paste` prints an authorize URL and waits for a code copied from the
browser. The client must allow `authorization_code` and register
`urn:ietf:wg:oauth:2.0:oob`. Pass `--client-secret` for a confidential
client. Leave it off when `token_endpoint_auth_method` is `none`.

Set `security.oob_helper` to serve `/oauth/oob`. Register that URL as the
client's redirect URI and pass it to `--redirect-uri`. The page shows one
combined value. The command unwraps it with the `state` it stored. Pasting
the page address works as well. The flag is off unless you set it.

`keys generate` writes DPoP and client signing keys for OAuch.
`--dpop-only` and `--client-only` limit the files. `keys rotate` calls
`POST /api/keys/rotate`.

### Scopes, resources, and consents

```bash
./bin/oauth-cli scope list
./bin/oauth-cli scope create --name calendar --description "Calendar read"
./bin/oauth-cli scope delete calendar

./bin/oauth-cli resource list
./bin/oauth-cli resource create --uri https://api.example --name API
./bin/oauth-cli resource delete https://api.example

./bin/oauth-cli consent list --user-id <id>
./bin/oauth-cli consent revoke --user-id <id> --client-id <id>
```

### Webhooks, analytics, and audit

```bash
./bin/oauth-cli webhook list
./bin/oauth-cli webhook create --url https://app.example/hook --event login --event logout
./bin/oauth-cli webhook create --url https://app.example/hook --event '*'
./bin/oauth-cli webhook test <id>
./bin/oauth-cli webhook delete <id>

./bin/oauth-cli analytics logins
./bin/oauth-cli analytics logins --user-id <id> --window 24h

./bin/oauth-cli audit list --window 720h --action client.create --actor-id <id>
```

`--event` repeats. `*` subscribes to every event. Omit `--secret` and
the server generates one.

### Organizations

Organizations do nothing until `org.enabled` is true. See
[Configuration](CONFIG.md).

```bash
./bin/oauth-cli org create --name "North" --slug north --domain north.example --logo-url https://cdn.example/north.png
./bin/oauth-cli org domain --org north --domain west.example
./bin/oauth-cli org member --org north --user-id <id> --role member
```

`--role` is `member` or `admin`. Omit `--logo-url` and the picker shows
the first letter of the name.

## oauth-mobile

```bash
./bin/oauth-mobile list
./bin/oauth-mobile poll
./bin/oauth-mobile approve <auth-req-id> --user-id <id>
./bin/oauth-mobile deny <auth-req-id>
./bin/oauth-mobile status
```

`poll` prints pending CIBA requests until you interrupt it. `status`
calls `GET /health` and does not need the management client.

## Related

[Configuration](CONFIG.md) is the file `init` writes.
[API](API.md) is what these commands call.
