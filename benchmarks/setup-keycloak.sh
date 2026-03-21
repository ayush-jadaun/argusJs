#!/bin/bash
# Setup Keycloak realm, client, and test configuration for benchmarking
# Run after Keycloak is up: bash benchmarks/setup-keycloak.sh

KC_URL="http://localhost:8080"
ADMIN_USER="admin"
ADMIN_PASS="admin"
REALM="benchmark"

echo "=== Setting up Keycloak for benchmarking ==="

# 1. Get admin token
echo "Getting admin token..."
ADMIN_TOKEN=$(curl -sf -X POST "${KC_URL}/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" \
  -d "username=${ADMIN_USER}" \
  -d "password=${ADMIN_PASS}" \
  -d "grant_type=password" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)

if [ -z "$ADMIN_TOKEN" ]; then
  echo "Failed to get admin token. Is Keycloak running on ${KC_URL}?"
  exit 1
fi
echo "Got admin token"

# 2. Create benchmark realm
echo "Creating realm '${REALM}'..."
curl -sf -X POST "${KC_URL}/admin/realms" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"realm\": \"${REALM}\",
    \"enabled\": true,
    \"registrationAllowed\": true,
    \"loginWithEmailAllowed\": true,
    \"duplicateEmailsAllowed\": false
  }" || echo "(realm may already exist)"

# 3. Create public client for benchmarking
echo "Creating client 'bench-client'..."
curl -sf -X POST "${KC_URL}/admin/realms/${REALM}/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{
    \"clientId\": \"bench-client\",
    \"enabled\": true,
    \"publicClient\": true,
    \"directAccessGrantsEnabled\": true,
    \"standardFlowEnabled\": false,
    \"serviceAccountsEnabled\": false
  }" || echo "(client may already exist)"

echo ""
echo "=== Keycloak setup complete ==="
echo "Realm: ${REALM}"
echo "Client: bench-client"
echo "Register: POST ${KC_URL}/realms/${REALM}/protocol/openid-connect/registrations"
echo "Login:    POST ${KC_URL}/realms/${REALM}/protocol/openid-connect/token"
