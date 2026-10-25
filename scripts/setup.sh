#!/bin/bash
set -e

SERVER_URL="${1:-http://127.0.0.1:8080}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Atrium Setup Script                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if server is running
echo "1. Checking server status..."
if ! curl -s "$SERVER_URL/health" > /dev/null 2>&1; then
    echo "   Server not reachable at $SERVER_URL"
    echo "   Starting server..."
    go run ./cmd/atrium/ &
    SERVER_PID=$!
    sleep 3
    echo "   Server started (PID: $SERVER_PID)"
else
    echo "   Server is running"
fi

MGMT_ID="${MGMT_CLIENT_ID:-}"
MGMT_SECRET="${MGMT_CLIENT_SECRET:-}"
if [ -z "$MGMT_ID" ] && [ -f config.yaml ]; then
    MGMT_ID=$(awk '/^management:/{f=1} f && /client_id:/{gsub(/"/,"",$2); print $2; exit}' config.yaml)
    MGMT_SECRET=$(awk '/^management:/{f=1} f && /client_secret:/{gsub(/"/,"",$2); print $2; exit}' config.yaml)
fi
if [ -z "$MGMT_ID" ] || [ -z "$MGMT_SECRET" ]; then
    echo "Set management.client_id and management.client_secret (atrium-cli init writes them), then restart the server."
    exit 1
fi
MGMT_TOKEN=$(curl -s -X POST "$SERVER_URL/oauth/token" -u "$MGMT_ID:$MGMT_SECRET" -d "grant_type=client_credentials&scope=management" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
if [ -z "$MGMT_TOKEN" ]; then
    echo "Failed to obtain a management access token."
    exit 1
fi

# Create master client
echo ""
echo "2. Creating master client..."
RESPONSE=$(curl -s -X POST "$SERVER_URL/api/clients" \
    -H "Authorization: Bearer $MGMT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "Master Client",
        "redirect_uris": [
            "https://localhost/callback",
            "http://localhost:3000/callback",
            "http://localhost:8080/callback"
        ],
        "grant_types": [
            "authorization_code",
            "client_credentials",
            "refresh_token",
            "password",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:openid:params:grant-type:ciba",
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ],
        "scopes": [
            "openid", "profile", "email", "address", "phone", "offline_access",
            "read", "write", "admin"
        ],
        "token_endpoint_auth_method": "client_secret_basic",
        "dpop_bound_access_tokens": false,
        "require_pushed_authorization_requests": false,
        "backchannel_token_delivery_mode": "poll"
    }')

CLIENT_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
CLIENT_SECRET=$(echo "$RESPONSE" | grep -o '"secret":"[^"]*"' | cut -d'"' -f4)

echo "   Master client created!"
echo ""

# Create test user
echo "3. Creating test user..."
curl -s -X POST "$SERVER_URL/api/users" \
    -H "Authorization: Bearer $MGMT_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "username": "admin",
        "password": "admin123",
        "email": "admin@example.com"
    }' > /dev/null 2>&1 || true

echo "   Test user created (admin/admin123)"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete                            ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Server URL:     $SERVER_URL"
echo "║  Client ID:      $CLIENT_ID"
echo "║  Client Secret:  $CLIENT_SECRET"
echo "║  Test User:      admin / admin123"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Quick Test:                                                 ║"
echo "║  curl -u $CLIENT_ID:$CLIENT_SECRET \\"
echo "║    -X POST $SERVER_URL/oauth/token \\"
echo "║    -d 'grant_type=client_credentials&scope=openid'"
echo "╚══════════════════════════════════════════════════════════════╝"
