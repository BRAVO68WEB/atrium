#!/bin/bash
set -e

CERT_DIR="${1:-./certs}"
DAYS="${2:-365}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           TLS Certificate Generator & Trust Setup           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Output directory: $CERT_DIR"
echo "Validity: $DAYS days"
echo ""

mkdir -p "$CERT_DIR"

# ──────────────────────────────────────────────
# 1. Generate CA
# ──────────────────────────────────────────────
echo "1. Generating CA..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days "$DAYS" -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=US/ST=State/L=City/O=OAuth Test/CN=OAuth Test CA" 2>/dev/null

# ──────────────────────────────────────────────
# 2. Generate Server Certificate
# ──────────────────────────────────────────────
echo "2. Generating server certificate..."
openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=State/L=City/O=OAuth Test/CN=localhost" 2>/dev/null

cat > "$CERT_DIR/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = *.local
IP.1 = 127.0.0.1
IP.2 = ::1
IP.3 = 0.0.0.0
EOF

openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" \
    -days "$DAYS" -extfile "$CERT_DIR/server.ext" 2>/dev/null

# ──────────────────────────────────────────────
# 3. Generate Client Certificate (for mTLS)
# ──────────────────────────────────────────────
echo "3. Generating client certificate..."
openssl genrsa -out "$CERT_DIR/client.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -subj "/C=US/ST=State/L=City/O=OAuth Test/CN=atrium-client" 2>/dev/null

cat > "$CERT_DIR/client.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/client.crt" \
    -days "$DAYS" -extfile "$CERT_DIR/client.ext" 2>/dev/null

# ──────────────────────────────────────────────
# 4. Generate Revoked Certificate (for CRL testing)
# ──────────────────────────────────────────────
echo "4. Generating revoked client certificate..."
openssl genrsa -out "$CERT_DIR/revoked.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/revoked.key" \
    -out "$CERT_DIR/revoked.csr" \
    -subj "/C=US/ST=State/L=City/O=OAuth Test/CN=revoked-client" 2>/dev/null

openssl x509 -req -in "$CERT_DIR/revoked.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/revoked.crt" \
    -days "$DAYS" -extfile "$CERT_DIR/client.ext" 2>/dev/null

# ──────────────────────────────────────────────
# 5. Generate CRL
# ──────────────────────────────────────────────
echo "5. Generating CRL..."
REVOKED_SERIAL=$(openssl x509 -in "$CERT_DIR/revoked.crt" -noout -serial | cut -d= -f2)

cat > "$CERT_DIR/crl.cnf" << EOF
[ca]
default_ca = CA_default

[CA_default]
database = $CERT_DIR/index.txt
crlnumber = $CERT_DIR/crlnumber

[crl_ext]
authorityKeyIdentifier=keyid:always
EOF

touch "$CERT_DIR/index.txt"
echo "01" > "$CERT_DIR/crlnumber"

openssl ca -config "$CERT_DIR/crl.cnf" \
    -cert "$CERT_DIR/ca.crt" \
    -keyfile "$CERT_DIR/ca.key" \
    -revoke "$CERT_DIR/revoked.crt" \
    -crl_reason keyCompromise 2>/dev/null || true

openssl ca -config "$CERT_DIR/crl.cnf" \
    -cert "$CERT_DIR/ca.crt" \
    -keyfile "$CERT_DIR/ca.key" \
    -gencrl -out "$CERT_DIR/crl.pem" 2>/dev/null

# Create bundles
cat "$CERT_DIR/server.crt" "$CERT_DIR/ca.crt" > "$CERT_DIR/server-bundle.crt"
cat "$CERT_DIR/client.crt" "$CERT_DIR/ca.crt" > "$CERT_DIR/client-bundle.crt"

# Set permissions
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt "$CERT_DIR"/*.pem

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   Certificates Generated                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  CA:      $CERT_DIR/ca.crt"
echo "  Server:  $CERT_DIR/server.crt + server.key"
echo "  Client:  $CERT_DIR/client.crt + client.key"
echo "  Revoked: $CERT_DIR/revoked.crt + revoked.key"
echo "  CRL:     $CERT_DIR/crl.pem"
echo ""

# ──────────────────────────────────────────────
# Trust the CA certificate
# ──────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   Trusting CA Certificate                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

OS=$(uname -s)

case "$OS" in
    Darwin)
        echo "Detected: macOS"
        echo ""
        echo "Adding CA to System Keychain..."
        sudo security add-trusted-cert -d -r trustRoot \
            -k /Library/Keychains/System.keychain \
            "$CERT_DIR/ca.crt" 2>/dev/null && {
            echo "  ✓ CA added to System Keychain (trusted by Chrome, Safari, curl, Go, etc.)"
        } || {
            echo "  ⚠ Failed to add to System Keychain (may already exist or need sudo)"
            echo ""
            echo "  Manual steps for macOS:"
            echo "  1. Double-click $CERT_DIR/ca.crt"
            echo "  2. Keychain Access opens → add to 'System' keychain"
            echo "  3. Double-click the cert → Trust → 'Always Trust'"
            echo "  4. Enter password to confirm"
        }
        echo ""
        echo "Also adding to login Keychain (for user-level trust)..."
        security add-trusted-cert -d -r trustRoot \
            -k ~/Library/Keychains/login.keychain-db \
            "$CERT_DIR/ca.crt" 2>/dev/null && {
            echo "  ✓ CA added to login Keychain"
        } || true
        ;;

    Linux)
        echo "Detected: Linux"
        echo ""

        # Detect distro
        if [ -f /etc/debian_version ]; then
            # Debian/Ubuntu
            echo "Adding CA to system trust store (Debian/Ubuntu)..."
            sudo cp "$CERT_DIR/ca.crt" /usr/local/share/ca-certificates/oauth-test-ca.crt
            sudo update-ca-certificates 2>/dev/null
            echo "  ✓ CA added to system trust store"
            echo "  ✓ Trusted by: curl, wget, Go, Node.js, Chrome, Firefox"
        elif [ -f /etc/redhat-release ]; then
            # RHEL/CentOS/Fedora
            echo "Adding CA to system trust store (RHEL/Fedora)..."
            sudo cp "$CERT_DIR/ca.crt" /etc/pki/ca-trust/source/anchors/oauth-test-ca.crt
            sudo update-ca-trust 2>/dev/null
            echo "  ✓ CA added to system trust store"
        else
            echo "  ⚠ Unknown Linux distro"
            echo "  Manual: Copy ca.crt to your system trust store"
        fi
        ;;

    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        echo "Detected: Windows"
        echo ""
        echo "Adding CA to Windows Trusted Root store..."
        certutil -addstore -f "Root" "$CERT_DIR/ca.crt" 2>/dev/null && {
            echo "  ✓ CA added to Windows Trusted Root Certification Authorities"
            echo "  ✓ Trusted by: Chrome, Edge, IE, curl, Go, Node.js"
        } || {
            echo "  ⚠ Failed (run as Administrator)"
            echo ""
            echo "  Manual steps for Windows:"
            echo "  1. Double-click $CERT_DIR/ca.crt"
            echo "  2. Click 'Install Certificate'"
            echo "  3. Select 'Local Machine' → Next"
            echo "  4. Select 'Place all certificates in the following store'"
            echo "  5. Browse → 'Trusted Root Certification Authorities'"
            echo "  6. Finish"
        }
        ;;

    *)
        echo "Unknown OS: $OS"
        echo "Manual trust setup required."
        ;;
esac

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   Tool-Specific Trust                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

CA_CERT="$(cd "$CERT_DIR" && pwd)/ca.crt"

echo "  curl:"
echo "    curl --cacert $CA_CERT https://localhost:8443/health"
echo "    # Or disable verification: curl -k https://localhost:8443/health"
echo ""
echo "  Go (环境变量):"
echo "    export SSL_CERT_FILE=$CA_CERT"
echo "    export REQUESTS_CA_BUNDLE=$CA_CERT"
echo ""
echo "  Node.js:"
echo "    export NODE_EXTRA_CA_CERTS=$CA_CERT"
echo ""
echo "  Python requests:"
echo "    export REQUESTS_CA_BUNDLE=$CA_CERT"
echo "    # Or: requests.get(url, verify='$CA_CERT')"
echo ""
echo "  Git:"
echo "    git config --global http.sslCAInfo $CA_CERT"
echo ""
echo "  wget:"
echo "    wget --ca-certificate=$CA_CERT https://localhost:8443/health"
echo ""
echo "  Docker (in container):"
echo "    COPY certs/ca.crt /usr/local/share/ca-certificates/"
echo "    RUN update-ca-certificates"
echo ""

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   Browser Trust                             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Chrome/Safari/Edge:"
echo "    → Uses OS trust store (already added above on macOS/Windows)"
echo "    → On Linux: import in chrome://settings/certificates"
echo ""
echo "  Firefox:"
echo "    → Has its own trust store"
echo "    → Settings → Privacy & Security → Certificates → View Certificates"
echo "    → Authorities → Import → select $CA_CERT"
echo "    → Check 'Trust to identify websites'"
echo ""

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   Quick Test Commands                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  # Health check (with trusted CA):"
echo "  curl --cacert $CA_CERT https://localhost:8443/health"
echo ""
echo "  # With client cert (mTLS):"
echo "  curl --cacert $CA_CERT \\"
echo "    --cert $CERT_DIR/client.crt --key $CERT_DIR/client.key \\"
echo "    https://localhost:8443/health"
echo ""
echo "  # Token request:"
echo "  curl --cacert $CA_CERT \\"
echo "    -u master-client:master-secret \\"
echo "    -X POST https://localhost:8443/oauth/token \\"
echo "    -d 'grant_type=client_credentials&scope=openid'"
echo ""
echo "Done!"
