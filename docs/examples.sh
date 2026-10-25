#!/bin/bash
# Atrium - Usage Examples
# Make sure the server is running: just run

SERVER="http://localhost:8080"

echo "=== Atrium - Usage Examples ==="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}1. Dynamic Client Registration${NC}"
echo "----------------------------"
CLIENT=$(curl -s -X POST "$SERVER/oauth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "Example App",
    "redirect_uris": ["https://example.com/callback"],
    "grant_types": ["authorization_code", "client_credentials", "refresh_token"],
    "scope": "openid profile email"
  }')

CLIENT_ID=$(echo $CLIENT | grep -o '"client_id":"[^"]*"' | cut -d'"' -f4)
CLIENT_SECRET=$(echo $CLIENT | grep -o '"client_secret":"[^"]*"' | cut -d'"' -f4)

echo "Client ID: $CLIENT_ID"
echo "Client Secret: $CLIENT_SECRET"
echo ""

echo -e "${BLUE}2. Create User${NC}"
echo "------------"
echo "Set MGMT_TOKEN to a client-credentials access token with the management scope."
if [ -z "$MGMT_TOKEN" ]; then
  echo "MGMT_TOKEN is empty; skipping user creation."
  USER_ID=""
else
USER=$(curl -s -X POST "$SERVER/api/users" \
  -H "Authorization: Bearer $MGMT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "password123",
    "email": "test@example.com"
  }')

USER_ID=$(echo $USER | grep -o '"id":"[^"]*"' | cut -d'"' -f4)
echo "User ID: $USER_ID"
fi
echo ""

echo -e "${BLUE}3. Client Credentials Flow${NC}"
echo "-------------------------"
TOKEN=$(curl -s -X POST "$SERVER/oauth/token" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=client_credentials&scope=openid")

echo "Token Response:"
echo $TOKEN | python3 -m json.tool 2>/dev/null || echo $TOKEN
echo ""

echo -e "${BLUE}4. Authorization Code Flow with PKCE${NC}"
echo "-----------------------------------"

# Generate PKCE
CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | shasum -a 256 | cut -d' ' -f1 | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')

echo "Code Verifier: $CODE_VERIFIER"
echo "Code Challenge: $CODE_CHALLENGE"

# Get authorization code
AUTH_RESPONSE=$(curl -s -D - "$SERVER/oauth/authorize?client_id=$CLIENT_ID&response_type=code&redirect_uri=https://example.com/callback&scope=openid%20profile&state=test123&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256" 2>/dev/null)
AUTH_CODE=$(echo "$AUTH_RESPONSE" | grep -o 'code=[^&]*' | head -1 | cut -d'=' -f2)
echo "Authorization Code: $AUTH_CODE"

# Exchange for tokens
TOKEN=$(curl -s -X POST "$SERVER/oauth/token" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=authorization_code&code=$AUTH_CODE&redirect_uri=https://example.com/callback&code_verifier=$CODE_VERIFIER")

echo "Token Response:"
echo $TOKEN | python3 -m json.tool 2>/dev/null || echo $TOKEN

ACCESS_TOKEN=$(echo $TOKEN | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
echo ""

echo -e "${BLUE}5. UserInfo Endpoint${NC}"
echo "------------------"
USERINFO=$(curl -s "$SERVER/oidc/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN")
echo "UserInfo Response:"
echo $USERINFO | python3 -m json.tool 2>/dev/null || echo $USERINFO
echo ""

echo -e "${BLUE}6. Token Introspection${NC}"
echo "--------------------"
INTROSPECT=$(curl -s -X POST "$SERVER/oauth/introspect" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "token=$ACCESS_TOKEN")
echo "Introspect Response:"
echo $INTROSPECT | python3 -m json.tool 2>/dev/null || echo $INTROSPECT
echo ""

echo -e "${BLUE}7. OIDC Discovery${NC}"
echo "----------------"
DISCOVERY=$(curl -s "$SERVER/.well-known/openid-configuration")
echo "Discovery Response:"
echo $DISCOVERY | python3 -m json.tool 2>/dev/null | head -20
echo "..."
echo ""

echo -e "${BLUE}8. JWKS Endpoint${NC}"
echo "---------------"
JWKS=$(curl -s "$SERVER/oidc/jwks")
echo "JWKS Response:"
echo $JWKS | python3 -m json.tool 2>/dev/null | head -30
echo "..."
echo ""

echo -e "${BLUE}9. Device Authorization Flow${NC}"
echo "---------------------------"
DEVICE=$(curl -s -X POST "$SERVER/oauth/device" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "scope=openid")
echo "Device Response:"
echo $DEVICE | python3 -m json.tool 2>/dev/null || echo $DEVICE

DEVICE_CODE=$(echo $DEVICE | grep -o '"device_code":"[^"]*"' | cut -d'"' -f4)
USER_CODE=$(echo $DEVICE | grep -o '"user_code":"[^"]*"' | cut -d'"' -f4)
echo "Device Code: $DEVICE_CODE"
echo "User Code: $USER_CODE"
echo ""

echo -e "${BLUE}10. CIBA Flow${NC}"
echo "------------"
CIBA=$(curl -s -X POST "$SERVER/oauth/bc-authorize" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID&scope=openid%20profile&login_hint=testuser&binding_message=Approve%20login")
echo "CIBA Response:"
echo $CIBA | python3 -m json.tool 2>/dev/null || echo $CIBA

AUTH_REQ_ID=$(echo $CIBA | grep -o '"auth_req_id":"[^"]*"' | cut -d'"' -f4)
echo "Auth Req ID: $AUTH_REQ_ID"
echo ""

echo -e "${GREEN}=== All examples completed! ===${NC}"
