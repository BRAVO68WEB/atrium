# CLI

`atrium-cli` calls the management API. `atrium-mobile` approves CIBA
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

`atrium --version`, `atrium-cli --version`, and
`atrium-mobile --version` print the build version. `--help` lists the
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
atrium-cli --server https://auth.example.com \
  --client-id "$OAUTH_CLI_CLIENT_ID" \
  --client-secret "$OAUTH_CLI_CLIENT_SECRET" \
  user list
```

`atrium-mobile` also has `--interval` (default 5 seconds) for `poll`.

## init

`init` does not talk to a running server. It writes the config and the
hasher. See [Configuration](CONFIG.md).

```bash
./bin/atrium-cli init
./bin/atrium-cli init --mfa --output config.yaml
./bin/atrium-cli init --hash argon2id
./bin/atrium-cli init --force
```

## atrium-cli commands

```bash
./bin/atrium-cli server status
./bin/atrium-cli server discovery
```

### Clients

```bash
./bin/atrium-cli client list
./bin/atrium-cli client create --name "App" --redirect-uri "https://app.example/cb"
./bin/atrium-cli client get <id>
./bin/atrium-cli client update <id> --dpop
./bin/atrium-cli client delete <id>
./bin/atrium-cli client master
```

`create` accepts repeated `--redirect-uri`, `--grant-type` (default
`authorization_code`), and `--scope` (default `openid`), plus
`--dcr-enabled` and `--cimd-enabled`. `master` creates one client with
the grants used by conformance tools, including `password`.

### Users

```bash
./bin/atrium-cli user list
./bin/atrium-cli user create --username ada --password "correct horse" --email ada@example.com
./bin/atrium-cli user get <id>
./bin/atrium-cli user password <id> --password "a new secret"
./bin/atrium-cli user disable <id>
./bin/atrium-cli user enable <id>
./bin/atrium-cli user import users.json
./bin/atrium-cli user import users.json --mode upsert --dry-run
./bin/atrium-cli user export --output users.json
./bin/atrium-cli user export --include-secrets --output users.json
```

`import` reads the same JSON document as `POST /api/users/import`.
It exits non-zero when any row has an error. `export` omits password
hashes and TOTP secrets unless you pass `--include-secrets`. The file
mode is `0600`. `init` does not call a remote server.

`user export` and `user import` carry `attributes` and
`user_metadata`. The other user commands do not edit those maps. Use
`PATCH /api/users/{id}` for both, and `PATCH /api/me` for
`user_metadata`. See [API](API.md).

### Backup

```bash
./bin/atrium-cli backup --output auth-backup.json
./bin/atrium-cli restore auth-backup.json --dry-run
./bin/atrium-cli restore auth-backup.json
./bin/atrium-cli restore auth-backup.json --force
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
./bin/atrium-cli token list --client-id <id> --user-id <id>
./bin/atrium-cli token revoke <id>
./bin/atrium-cli token introspect <token>
./bin/atrium-cli token refresh list
./bin/atrium-cli token refresh revoke <id>
```

`token list` and `refresh list` print public ids. They do not print
the bearer. `token revoke` takes the access-token id from that list.

### MFA

Enrollment in the CLI is TOTP.

```bash
./bin/atrium-cli mfa enable --user-id <id>
./bin/atrium-cli mfa enable --user-id <id> --show-secret
./bin/atrium-cli mfa verify --user-id <id> --code 123456
./bin/atrium-cli mfa status --user-id <id>
```

### CIBA, flows, and keys

```bash
./bin/atrium-cli ciba pending
./bin/atrium-cli ciba approve <auth-req-id> --user-id <id>
./bin/atrium-cli ciba deny <auth-req-id> --reason "Denied"

./bin/atrium-cli flow client-credentials --client-id <id> --client-secret <secret>
./bin/atrium-cli flow device --client-id <id> --client-secret <secret>
./bin/atrium-cli flow paste --client-id <id>

./bin/atrium-cli keys generate --output ./keys
./bin/atrium-cli keys rotate
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
./bin/atrium-cli scope list
./bin/atrium-cli scope create --name calendar --description "Calendar read"
./bin/atrium-cli scope delete calendar

./bin/atrium-cli resource list
./bin/atrium-cli resource create --uri https://api.example --name API
./bin/atrium-cli resource delete https://api.example

./bin/atrium-cli role create --name viewer --description "Read projects"
./bin/atrium-cli role list
./bin/atrium-cli role scopes <id> --grant "https://api.example|projects:read"
./bin/atrium-cli user role <user-id> --role <role-id>
./bin/atrium-cli user role <user-id> --role <role-id> --org-id <org-id>
./bin/atrium-cli user role <user-id> --role <role-id> --remove
./bin/atrium-cli user scope <user-id> --resource https://api.example --scope projects:read
./bin/atrium-cli user scope <user-id> --resource https://api.example --scope projects:read --remove

./bin/atrium-cli consent list --user-id <id>
./bin/atrium-cli consent revoke --user-id <id> --client-id <id>
```

`role scopes` replaces that role's scopes with the `--grant` values.
Each grant is `resource|scope`. Repeat `--grant` for more than one.
`--org-id` limits `user role` and `user scope` to tokens for that
organization. Leave it out and the grant is on every token.

### Webhooks, analytics, and audit

```bash
./bin/atrium-cli webhook list
./bin/atrium-cli webhook create --url https://app.example/hook --event login --event logout
./bin/atrium-cli webhook create --url https://app.example/hook --event '*'
./bin/atrium-cli webhook test <id>
./bin/atrium-cli webhook delete <id>

./bin/atrium-cli analytics logins
./bin/atrium-cli analytics logins --user-id <id> --window 24h

./bin/atrium-cli audit list --window 720h --action client.create --actor-id <id>
```

`--event` repeats. `*` subscribes to every event. Omit `--secret` and
the server generates one.

### Organizations

Organizations do nothing until `org.enabled` is true. See
[Configuration](CONFIG.md).

```bash
./bin/atrium-cli org create --name "North" --slug north --domain north.example --logo-url https://cdn.example/north.png
./bin/atrium-cli org domain --org north --domain west.example
./bin/atrium-cli org member --org north --user-id <id> --role member
```

`--role` is `member` or `admin`. Omit `--logo-url` and the picker shows
the first letter of the name.

## atrium-mobile

```bash
./bin/atrium-mobile list
./bin/atrium-mobile poll
./bin/atrium-mobile approve <auth-req-id> --user-id <id>
./bin/atrium-mobile deny <auth-req-id>
./bin/atrium-mobile status
```

`poll` prints pending CIBA requests until you interrupt it. `status`
calls `GET /health` and does not need the management client.

## Related

[Configuration](CONFIG.md) is the file `init` writes.
[API](API.md) is what these commands call.
