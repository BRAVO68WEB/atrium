#!/bin/bash
set -e

CERT_DIR="${1:-./certs}"
DAYS="${2:-365}"

echo "=== Generating TLS Certificates ==="
echo "Output directory: $CERT_DIR"
echo "Validity: $DAYS days"
echo ""

mkdir -p "$CERT_DIR"

# Generate CA key and certificate
echo "1. Generating CA..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096
openssl req -new -x509 -days "$DAYS" -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" \
    -subj "/C=US/ST=State/L=City/O=OAuth Test/CN=OAuth Test CA"

# Generate server key and certificate
echo "2. Generating server certificate..."
openssl genrsa -out "$CERT_DIR/server.key" 2048
openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" \
    -subj "/C=US/ST=State/L=City/O=OAuth Test/CN=localhost"

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

openssl x509 -req -in "$CERT_DIR/server.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" \
    -days "$DAYS" -extfile "$CERT_DIR/server.ext"

# Generate client key and certificate
echo "3. Generating client certificate..."
openssl genrsa -out "$CERT_DIR/client.key" 2048
openssl req -new -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" \
    -subj "/C=US/ST=State/L=City/O=OAuth Test/CN=atrium-client"

cat > "$CERT_DIR/client.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req -in "$CERT_DIR/client.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/client.crt" \
    -days "$DAYS" -extfile "$CERT_DIR/client.ext"

# Generate revoked client key and certificate
echo "4. Generating revoked client certificate..."
openssl genrsa -out "$CERT_DIR/revoked.key" 2048
openssl req -new -key "$CERT_DIR/revoked.key" \
    -out "$CERT_DIR/revoked.csr" \
    -subj "/C=US/ST=State/L=City/O=OAuth Test/CN=revoked-client"

openssl x509 -req -in "$CERT_DIR/revoked.csr" \
    -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/revoked.crt" \
    -days "$DAYS" -extfile "$CERT_DIR/client.ext"

# Generate CRL with revoked certificate
echo "5. Generating CRL..."
# Get serial number of revoked certificate
REVOKED_SERIAL=$(openssl x509 -in "$CERT_DIR/revoked.crt" -noout -serial | cut -d= -f2)

# Create CRL config
cat > "$CERT_DIR/crl.cnf" << EOF
[ca]
default_ca = CA_default

[CA_default]
database = $CERT_DIR/index.txt
crlnumber = $CERT_DIR/crlnumber

[crl_ext]
authorityKeyIdentifier=keyid:always
EOF

# Initialize CRL database
touch "$CERT_DIR/index.txt"
echo "01" > "$CERT_DIR/crlnumber"

# Revoke the certificate
openssl ca -config "$CERT_DIR/crl.cnf" \
    -cert "$CERT_DIR/ca.crt" \
    -keyfile "$CERT_DIR/ca.key" \
    -revoke "$CERT_DIR/revoked.crt" \
    -crl_reason keyCompromise 2>/dev/null || true

# Generate CRL
openssl ca -config "$CERT_DIR/crl.cnf" \
    -cert "$CERT_DIR/ca.crt" \
    -keyfile "$CERT_DIR/ca.key" \
    -gencrl -out "$CERT_DIR/crl.pem" 2>/dev/null

# Create combined PEM for server
cat "$CERT_DIR/server.crt" "$CERT_DIR/ca.crt" > "$CERT_DIR/server-bundle.crt"

# Set permissions
chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt "$CERT_DIR"/*.pem

echo ""
echo "=== Certificates Generated ==="
echo ""
echo "CA Certificate:     $CERT_DIR/ca.crt"
echo "Server Certificate: $CERT_DIR/server.crt"
echo "Server Key:         $CERT_DIR/server.key"
echo "Client Certificate: $CERT_DIR/client.crt"
echo "Client Key:         $CERT_DIR/client.key"
echo "Revoked Certificate: $CERT_DIR/revoked.crt"
echo "Revoked Key:        $CERT_DIR/revoked.key"
echo "CRL:                $CERT_DIR/crl.pem"
echo ""
echo "=== Test Commands ==="
echo ""
echo "# Health check (no cert):"
echo "curl -k https://localhost:8443/health"
echo ""
echo "# Health check (with client cert):"
echo "curl -k --cert $CERT_DIR/client.crt --key $CERT_DIR/client.key https://localhost:8443/health"
echo ""
echo "# Health check (with revoked cert - should fail):"
echo "curl -k --cert $CERT_DIR/revoked.crt --key $CERT_DIR/revoked.key https://localhost:8443/health"
echo ""
echo "# Token endpoint (with client cert):"
echo "curl -k --cert $CERT_DIR/client.crt --key $CERT_DIR/client.key \\"
echo "  -X POST https://localhost:8443/oauth/token \\"
echo "  -d 'grant_type=client_credentials&client_id=test&client_secret=secret'"
