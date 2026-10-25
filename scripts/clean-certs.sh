#!/bin/bash
set -e

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
CONFIG_FILE="$(cd "$(dirname "$0")/.." && pwd)/config.yaml"

echo "=== Cleaning certificates and resetting config ==="

if [ -d "$CERT_DIR" ]; then
    rm -rf "$CERT_DIR"
    echo "✓ Removed certs/ directory"
fi

if [[ "$OSTYPE" == "darwin"* ]]; then
    sudo security delete-certificate -c "OAuth Test CA" /Library/Keychains/System.keychain 2>/dev/null || true
    echo "✓ Removed CA from macOS keychain"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo rm -f /usr/local/share/ca-certificates/oauth-test-ca.crt
    sudo update-ca-certificates 2>/dev/null || true
    echo "✓ Removed CA from Linux trust store"
fi

cat > "$CONFIG_FILE" << EOF
# Atrium Configuration
server:
  host: "0.0.0.0"
  port: 8080
  tls:
    enabled: false
    cert_file: ""
    key_file: ""
    client_ca: ""
    client_auth: "none"
    crl_file: ""

database:
  driver: sqlite
  path: "./oauth.db"
  dsn: ""
  migrations: true

redis:
  addr: ""
  username: ""
  password: ""
  db: 0
  prefix: oauth

cache:
  provider: memory

security:
  access_token_lifetime: 3600s
  refresh_token_lifetime: 86400s
  authorization_code_lifetime: 600s
  device_code_lifetime: 1800s
  ciba_request_lifetime: 120s
  request_uri_lifetime: 60s
  require_pkce: false
  allow_plain_pkce: true
  issuer: "http://localhost:8080"
  hash_algo: "internal/hashalgo/algo.go"
  session_lifetime: 8h
  reset_token_lifetime: 30m
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
    issuer: "Atrium"
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

social:
  providers: []

branding:
  product_name: "Atrium"
  login_title: "Sign In"
  username_label: "Username"
  password_label: "Password"
  submit_label: "Sign In"
  assets_dir: ""
  logo_file: ""
  favicon_file: ""
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

queue:
  type: "memory"
  poll_interval: 5s
  max_pending: 100

oidc:
  issuer: "http://localhost:8080"
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
  supported_claims:
    - sub
    - name
    - given_name
    - family_name
    - email
    - email_verified
    - preferred_username
  supported_grant_types:
    - authorization_code
    - client_credentials
    - refresh_token
    - password
    - urn:ietf:params:oauth:grant-type:device_code
    - urn:openid:params:grant-type:ciba
    - urn:ietf:params:oauth:grant-type:token-exchange
  supported_auth_methods:
    - client_secret_basic
    - client_secret_post
    - client_secret_jwt
    - private_key_jwt
    - none
EOF

echo "✓ Reset config.yaml to HTTP mode"
echo ""
echo "Done! Server will run on http://localhost:8080"
