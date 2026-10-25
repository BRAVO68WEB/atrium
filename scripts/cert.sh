#!/bin/bash
set -e

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
CONFIG_FILE="$(cd "$(dirname "$0")/.." && pwd)/config.yaml"
FORCE=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --force) FORCE=true; shift ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
done

echo "=== Atrium - Certificate Generator ==="

if [ -f "$CERT_DIR/server.crt" ] && [ "$FORCE" = false ]; then
    echo "Certificates already exist. Use --force to regenerate."
    exit 0
fi

mkdir -p "$CERT_DIR"

echo "1. Generating CA certificate..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -days 3650 -nodes \
    -subj "/CN=OAuth Test CA/O=Atrium/C=US" 2>/dev/null

echo "2. Generating server certificate..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -nodes \
    -subj "/CN=localhost/O=Atrium/C=US" 2>/dev/null

cat > "$CERT_DIR/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

openssl x509 -req \
    -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/server.crt" \
    -days 365 \
    -extfile "$CERT_DIR/server.ext" 2>/dev/null

echo "3. Generating client certificate..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -nodes \
    -subj "/CN=Test Client/O=OAuth Client/C=US" 2>/dev/null

openssl x509 -req \
    -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/client.crt" \
    -days 365 2>/dev/null

echo "4. Generating revoked client certificate (for CRL testing)..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/revoked-client.key" \
    -out "$CERT_DIR/revoked-client.csr" \
    -nodes \
    -subj "/CN=Revoked Client/O=OAuth Client/C=US" 2>/dev/null

openssl x509 -req \
    -in "$CERT_DIR/revoked-client.csr" \
    -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial \
    -out "$CERT_DIR/revoked-client.crt" \
    -days 365 2>/dev/null

echo "5. Generating CRL (Certificate Revocation List)..."
cat > "$CERT_DIR/crl.cnf" << EOF
[ca]
default_ca = CA_default

[CA_default]
database = $CERT_DIR/index.txt
crlnumber = $CERT_DIR/crlnumber
default_md = sha256
default_crl_days = 30

[req]
distinguished_name = req_dn

[req_dn]
EOF

touch "$CERT_DIR/index.txt"
echo 01 > "$CERT_DIR/crlnumber"

REVOKED_SERIAL=$(openssl x509 -in "$CERT_DIR/revoked-client.crt" -noout -serial | cut -d= -f2)
echo "R	$(date +%y%m%d%H%M%SZ)		$REVOKED_SERIAL" >> "$CERT_DIR/index.txt"

openssl ca -gencrl \
    -keyfile "$CERT_DIR/ca.key" \
    -cert "$CERT_DIR/ca.crt" \
    -out "$CERT_DIR/ca.crl" \
    -config "$CERT_DIR/crl.cnf" 2>/dev/null

echo "6. Generating PKCS#12 bundle..."
openssl pkcs12 -export \
    -in "$CERT_DIR/client.crt" \
    -inkey "$CERT_DIR/client.key" \
    -certfile "$CERT_DIR/ca.crt" \
    -out "$CERT_DIR/client.p12" \
    -password pass:changeit 2>/dev/null

echo "7. Trusting CA certificate at OS level..."
if [[ "$OSTYPE" == "darwin"* ]]; then
    sudo security add-trusted-cert -d -r trustRoot \
        -k /Library/Keychains/System.keychain \
        "$CERT_DIR/ca.crt" 2>/dev/null || true
    echo "   ✓ CA certificate trusted on macOS"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    sudo cp "$CERT_DIR/ca.crt" /usr/local/share/ca-certificates/oauth-test-ca.crt 2>/dev/null || true
    sudo update-ca-certificates 2>/dev/null || true
    echo "   ✓ CA certificate trusted on Linux"
fi

echo "8. Updating config.yaml..."
cat > "$CONFIG_FILE" << EOF
# Atrium Configuration
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    enabled: true
    cert_file: "certs/server.crt"
    key_file: "certs/server.key"
    client_ca: "certs/ca.crt"
    client_auth: "request"
    crl_file: "certs/ca.crl"

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
  issuer: "https://localhost:8443"
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
    enabled: true
    cert_binding: true
    bind_refresh_token: true
    require_for_token: false
  dpop:
    enabled: true
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
  issuer: "https://localhost:8443"
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
    - tls_client_auth
    - self_signed_tls_client_auth
EOF

echo ""
echo "=== Certificate Generation Complete ==="
echo ""
echo "Files generated:"
echo "  CA Certificate:        $CERT_DIR/ca.crt"
echo "  CA Key:                $CERT_DIR/ca.key"
echo "  CRL:                   $CERT_DIR/ca.crl"
echo "  Server Certificate:    $CERT_DIR/server.crt"
echo "  Server Key:            $CERT_DIR/server.key"
echo "  Client Certificate:    $CERT_DIR/client.crt"
echo "  Client Key:            $CERT_DIR/client.key"
echo "  Revoked Certificate:   $CERT_DIR/revoked-client.crt"
echo "  Revoked Key:           $CERT_DIR/revoked-client.key"
echo "  Client PKCS#12:        $CERT_DIR/client.p12"
echo ""
echo "Config updated: $CONFIG_FILE"
echo "Server will run on: https://localhost:8443"
echo ""
echo "Test commands:"
echo "  curl https://localhost:8443/health"
echo "  curl --cert certs/client.crt --key certs/client.key https://localhost:8443/health"
echo "  curl --cert certs/revoked-client.crt --key certs/revoked-client.key https://localhost:8443/health"
