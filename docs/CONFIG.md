# Configuration

The server reads one YAML file. This page is the key reference. How to
run the process is in [Deploy](DEPLOY.md). Page copy is in
[Branding](BRANDING.md).

## Load order

`atrium-cli init` writes `config.yaml` from the built-in defaults, fills
`management.client_id` and `management.client_secret`, and generates
`oidc.pairwise_salt`. It also writes `internal/hashalgo/algo.go` when
that file is missing. An existing config or an edited hasher stays in
place unless you pass `--force`.

```bash
./bin/atrium-cli init
./bin/atrium-cli init --mfa --output config.yaml
./bin/atrium-cli init --hash argon2id
HASH_ALGO=./myhash.go ./bin/atrium-cli init
```

`--hash` is `bcrypt` or `argon2id`. `HASH_ALGO` copies another Go file
onto `internal/hashalgo/algo.go` during init, and only when the
destination is still the stock file or `--force` is set.

`internal/hashalgo/examples/` holds drop-in copies: `bcrypt-cost12`,
`argon2id`, `argon2id-small`, `argon2id-only`, `pepper`, `scrypt`,
`migrate`, `pbkdf2-sha256`, and `pbkdf2-sha512`. Copy one over the live
file and rebuild. A single unsalted SHA-256 is not one of them.

```bash
cp internal/hashalgo/examples/argon2id/algo.go internal/hashalgo/algo.go
just build
```

At startup:

- No `--config` flag and no `./config.yaml`: built-in defaults, HTTP on
  port 8080.
- No `--config` flag and `./config.yaml` exists: that file.
- `--config` set: that path. A missing file exits.

The file is merged onto the defaults, then normalized. Empty branding
copy is filled in. `security.login_identifier` becomes `username` when
empty.

## Defaults

Values below are the built-in defaults. `init --mfa` also sets
`security.mfa.enabled` and `security.mfa.required` to true.

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    client_ca: ""
    client_auth: none
    crl_file: ""

database:
  driver: sqlite
  path: ./atrium.db
  dsn: ""
  migrations: true

redis:
  addr: ""
  username: ""
  password: ""
  db: 0
  prefix: atrium

cache:
  provider: memory

queue:
  type: memory
  poll_interval: 5s
  max_pending: 100

notify:
  type: memory
  rabbitmq:
    url: ""
    exchange: oauth.notify
    queue: oauth.notify

security:
  issuer: http://localhost:8080
  login_identifier: username
  access_token_format: opaque
  access_token_lifetime: 1h
  refresh_token_lifetime: 24h
  authorization_code_lifetime: 10m
  device_code_lifetime: 30m
  ciba_request_lifetime: 2m
  request_uri_lifetime: 1m
  session_lifetime: 8h
  reset_token_lifetime: 30m
  require_pkce: false
  allow_plain_pkce: true
  oob_helper: false
  hash_algo: internal/hashalgo/algo.go
  data_key: replace-me
  trusted_proxies: []
  disable_registration: false
  disable_social_registration: false
  allow_insecure_fetch: false
  fetch_allow_ips: []
  password:
    min_length: 8
    max_length: 128
    require_uppercase: false
    require_lowercase: false
    require_number: false
    require_symbol: false
    block_username: true
  bot_protection:
    provider: ""
    site_key: ""
    secret_key: ""
  mfa:
    enabled: false
    required: false
    issuer: Atrium
    digits: 6
    period: 30
  mtls:
    enabled: false
    cert_binding: false
    bind_refresh_token: false
    require_for_token: false
  dpop:
    enabled: false
    proof_lifetime: 300
    nonce_required: false
    nonce_lifetime: 300

management:
  client_id: ""
  client_secret: ""

smtp:
  enabled: false
  host: ""
  port: 587
  username: ""
  password: ""
  from: ""
  starttls: true
  implicit_tls: false

email:
  templates_dir: ""

branding:
  product_name: Atrium
  login_title: Sign In
  username_label: Username
  password_label: Password
  submit_label: Sign In
  assets_dir: ""
  logo_file: ""
  favicon_file: ""
  background_file: ""
  primary_color: "#0066ff"
  background_color: ""
  text_color: ""
  footer_text: ""
  support_url: ""
  privacy_url: ""
  terms_url: ""
  show_register: true
  show_forgot_password: true
  templates: ""

registration:
  dcr_enabled: true
  cimd_enabled: false

social:
  providers: []

org:
  enabled: false
  enabled_domain_based_autolookup: false

push:
  enabled: false
  registration_token_ttl: 300
  minimum_interaction_type: boolean
  max_devices_per_user: 5
  client_attestation_required: false
  grace_period_seconds: 300
  ping_enabled: false
  push_enabled: false
  relay_endpoint: ""

aauth:
  enabled: false
  ap_issuer: ""
  ps_issuer: ""
  as_issuer: ""
  resource_issuer: ""
  resource_mode: as

xaa:
  enabled: false
  trusts: []
  idps: []

debug:
  ui: false

telemetry:
  enabled: false
  service_name: atrium
  otlp_endpoint: ""
  insecure: false
  sample_ratio: 1

oidc:
  issuer: http://localhost:8080
  signing_key: ""
  pairwise_salt: ""
  key_rotation_interval: 0s
  key_retain: 48h
  claim_mappings: []
  supported_scopes:
    - openid
    - profile
    - email
    - address
    - phone
    - offline_access
  supported_grant_types:
    - authorization_code
    - client_credentials
    - refresh_token
    - urn:ietf:params:oauth:grant-type:device_code
    - urn:openid:params:grant-type:ciba
    - urn:ietf:params:oauth:grant-type:token-exchange
```

`init` fills `management` and `oidc.pairwise_salt`. The lists under
`oidc` are the discovery defaults.

## Sign-in and passwords

`security.login_identifier` is `username` (the default) or `email`. The
password grant still sends the value in the `username` field. In email
mode, sign-in, forgot-password, and that grant look up the mailbox. A
mailbox is stored in lowercase, and a second account cannot reuse it,
including when the identifier is `username`.

`security.identifier_first` is false unless set. When it is true, the
sign-in page asks for the identifier first. The next submit looks the
account up. An account with no password and `migration_pending` is sent
the email code and never sees a password field. Any other account is
shown the password field, with social buttons under it when providers
are configured. The password grant is unchanged.

`security.disable_passwords` is false unless set. When it is true, browser
sign-in and the password grant do not accept a password. `security.passwordless_mode`
is `otp` (the default) or `link`. `otp` emails a 6-digit code (`login_otp`,
10 minutes) and signs the browser in when the code matches. `link` emails
a one-time URL (`login_link`, 10 minutes) and signs the browser in when it
is opened. An unknown identifier gets the same screen and no mail. Forgot
and reset are refused. Migration password setup is not used while passwords
are disabled. `smtp.enabled`, `smtp.host`, and `smtp.from` are required,
and startup fails without them.

`security.password` is checked when a password is set. `block_username`
rejects a password that contains the username.

A migrated account has an empty password and `migration_pending`. The
next browser sign-in emails a 6-digit code (`migrate_otp`, 10 minutes),
then requires a new password before any OAuth code is issued. The
password grant returns `migration_required` and does not send mail.
`POST /api/users/{id}/migration-notice` sends `migrate_notice` with no
code. An empty password with `migration_pending` false, such as a SAML
account, does not receive the code, and forgot-password does not attach
one. Restore and import accept that empty hash only together with the
flag.

`security.access_token_format` is `opaque` or `jwt`. Opaque is the
default. Access tokens are never encrypted. ID tokens and UserInfo are
nested JWEs only when the client sets the encryption algorithms and
publishes an RSA encryption key. The algorithms are RSA-OAEP-256 and
A256GCM.

`security.oob_helper` defaults to false. When it is true, `GET /oauth/oob`
shows one combined authorization code after a normal redirect to that
URL. The flag does not change the `urn:ietf:wg:oauth:2.0:oob` page. That
page is available when the client registers the URN.

`security.hash_algo` must name `internal/hashalgo/algo.go`. That file
exports one function, `Hash()`. Edit the body and rebuild. `init --hash
argon2id` writes an argon2id hasher that still verifies old bcrypt
hashes and rehashes on the next successful login. The stock argon2id
settings use 64 MiB of memory. Lower `Memory` in the file when login
stalls. Startup exits when the on-disk file differs from the binary.
A custom hasher implements `Recognizes(encoded string) bool` when its
stored form is not one of the built-in prefixes. User import stores
`password_hash` only when that method, or a built-in prefix, accepts
the string. `MD5`, `SHA256`, `SHA512`, `SHA3512`, `SHA2_128`, and
`PBKDF2` are PBKDF2-HMAC constructions. `SHA2_128` uses a 16-byte
SHA-256 key because SHA-2 has no 128-bit hash. New passwords should
stay on bcrypt or argon2id.

`security.data_key` is required. It is 32 bytes of standard base64.
`atrium-cli init` writes one. Startup refuses to serve when it is
missing or the wrong length. Client secrets are encrypted with this
key. Opaque access tokens and refresh tokens are stored as SHA-256.
A JWT access token is not stored; the row keeps its `jti`. The key
stays in the config file, not in the database. Changing it does not
decrypt old secrets. Set each client secret again if you replace it.

## Mail templates

`email.templates_dir` replaces the built-in messages. Each file is
`reset.txt`, `verify.txt`, `password_changed.txt`, `new_sign_in.txt`,
or `login_failed.txt`. The first line is `Subject: ...`. A missing file
keeps the built-in text. A file that does not parse stops startup. An
empty `templates_dir` keeps every built-in message.

Templates can use `Issuer`, `Username`, `Email`, `Link`, `Code`, `TTL`,
`IP`, `Time`, and `Count`. The server leaves `Agent` empty. A new
sign-in message includes the stored IP and does not include the
browser user agent.

## Organizations

`org.enabled` gates organizations. Both flags default to false, so a
default server never selects an organization.

`org.enabled_domain_based_autolookup` requires `org.enabled`. It selects
an organization from the user's email domain only when they are already
a member. It does not create a membership. Naming an organization the
user is not in returns `access_denied`.

`push.enabled` defaults to false. It registers authenticator devices
for a later wake signal. It does not change `/oauth/device`.
`grace_period_seconds` is how long the previous device key still
verifies after rotation. The default is 300. `ping_enabled` and
`push_enabled` send an HTTP wake. Both default to false.
`relay_endpoint` is the HTTPS URL that receives a push wake. See
[Push devices](PUSH.md).

`debug.ui` defaults to false. Set it to true to serve `/preview`, a
catalog of the auth screens with sample data. Leave it off on a
server that other people can reach. Submitting a form on a preview
still uses the real endpoint.
## AAuth

`aauth.enabled` defaults to false. A default server does not publish
AAuth metadata and does not mount AAuth routes. The OAuth and OpenID
Connect endpoints stay as they are.

When you set it to true, the process publishes four discovery documents
and one Ed25519 key. An empty issuer uses `security.issuer`.
`resource_mode` is `as` or `ps`. Token issuance is not served yet. See
[AAuth](AAUTH.md).

The browser authorize flow uses `/organization` when the user belongs to
more than one organization, the request did not name one, and the client
is not bound to one. One membership is not chosen automatically unless
the client is bound, the request names the organization, or autolookup
matches. `prompt=none` with a needed choice returns
`interaction_required`.

## Pairwise subjects

A client `subject_type` is `public` (the default) or `pairwise`.
Pairwise `sub` is derived from `oidc.pairwise_salt`, the sector, and the
local user id. The same sector yields one subject. A different redirect
host yields another. Startup fails when a pairwise client exists and
the salt is empty. `init` generates a salt. Changing the salt changes
every pairwise subject.

`oidc.claim_mappings` can add claims from the user record. A mapping
cannot set `sub`, `iss`, `aud`, `exp`, `iat`, `org_id`, `org_slug`,
or `org_role`.

`source` `attr.<key>` reads one `attributes` value. `user.<key>` reads
one `user_metadata` value. `const:<text>` writes that text.
`username`, `email`, `email_verified`, `phone`, `given_name`, and
`family_name` read those profile fields. A source of `sub` copies the
subject the client receives. For a pairwise client that value is the
sector identifier, not the local account id. The claim is added when
the token includes every scope named on the mapping. An empty scope
list adds the claim on every token.

## Social login

`social.providers` lists upstream OAuth apps. Each `id` is lowercase.
`type` is `google`, `github`, `facebook`, `oidc`, or `oauth2`. An
enabled provider needs `client_id` and `client_secret`. Presets fill the
endpoints. `oidc` needs `issuer`. `oauth2` needs the authorization,
token, and userinfo URLs.

Register this redirect on the upstream app:

`{security.issuer}/login/social/{id}/callback`

The login page links to each enabled provider. The first sign-in creates
a local user with a random password. The next sign-in from the same
provider account uses that user. An email that already belongs to a
password user is not attached. `security.disable_social_registration`
and `security.disable_registration` both refuse that first sign-in. A
provider account that is already linked can still sign in.

```yaml
social:
  providers:
    - id: google
      type: google
      name: Google
      enabled: true
      client_id: ""
      client_secret: ""
```

## Cross-app access

`xaa.enabled` defaults to false. A default server does not issue an
ID-JAG and does not accept
`urn:ietf:params:oauth:grant-type:jwt-bearer`. Leave the grant out of
`oidc.supported_grant_types`. While the flag is on, discovery adds
the grant. While it is off, discovery leaves the grant out. See
[Cross-app access](XAA.md).

`xaa.trusts` is the allow list when this server is the identity
provider. Each row has `client_id` (the app here), `audience` (the
resource authorization server's issuer), `resource_client_id` (that
app's client id there), and `scopes`. A request is refused when no
row matches the client, the audience, and the scopes.

`xaa.idps` is the allow list when this server is the resource
authorization server. Each row has `issuer`, `jwks_uri`, and `scopes`.
The user's email in the assertion must already belong to a verified
account here. A row with an `http` `jwks_uri` is fetched only when
`security.allow_insecure_fetch` allows that host.

`POST /api/clients` accepts `id` when the trust row has to name a
client you choose. Omit `id` and the server generates one.

```yaml
xaa:
  enabled: true
  trusts:
    - client_id: field-notes
      audience: https://notes.example
      resource_client_id: notes-api
      scopes:
        - notes.read
  idps:
    - issuer: https://idp.example
      jwks_uri: https://idp.example/oidc/jwks
      scopes:
        - notes.read
```

## Other switches

`registration.dcr_enabled` allows `POST /oauth/register`. Dynamic
registration cannot mint the `management` scope. `registration.cimd_enabled`
allows an `https` client id that points at a metadata document.

`security.bot_protection.provider` empty skips the check. `turnstile`
uses Cloudflare Turnstile. Any other value is checked with Google
reCAPTCHA siteverify. A configured provider needs `site_key`,
`secret_key`, and a token from the browser.

`security.allow_insecure_fetch` and `security.fetch_allow_ips` widen
outbound fetches the server makes for sector documents, CIMD,
webhooks, and identity-provider signing keys. Leave them at the
defaults on a public issuer.

`security.dpop.proof_lifetime` and `nonce_lifetime` are seconds, not Go
durations. `security.mfa.period` is the TOTP step in seconds.

`log.format` is `text` or `json`. Leave it empty for a text line on
stderr. `json` prints one JSON object per record.

`telemetry.enabled` defaults to false. Turning it on requires
`telemetry.otlp_endpoint`. An empty endpoint with tracing enabled is a
startup error. See [Deploy](DEPLOY.md).

## Operator console

`dashboard.enabled` defaults to false. Set it to true to serve `/dashboard`.
Sign in with the management client id and secret. The session cookie lasts
`dashboard.session_lifetime`, which defaults to 8h.

The console can edit this file. A saved change is on disk immediately and
takes effect after the process starts again. In Docker, the console can
stop the process when `ATRIUM_IN_DOCKER=1`. `restart: unless-stopped` brings
the container back. The config file must be mounted read-write, and uid
65534 must be able to write it. Leave a secret field blank to keep the
value already in the file.

## Related

[Branding](BRANDING.md) is the HTML and asset overlay.
[CLI](CLI.md) is `init` and the management commands.
