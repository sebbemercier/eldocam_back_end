#!/bin/bash
set -e

# Script to configure Vault JWT Auth for Nomad Workload Identity
# Must be run with Vault root token or admin permissions

VAULT_ADDR="http://master-nomad.tmg:8200"
VAULT_TOKEN="${1:-}"  # Pass Vault root token as first argument

if [ -z "$VAULT_TOKEN" ]; then
  echo "Error: Vault token required"
  echo "Usage: $0 <vault-root-token>"
  exit 1
fi

export VAULT_ADDR
export VAULT_TOKEN

echo "==> Configuring Vault JWT Auth for Nomad"

# Step 1: Enable JWT auth backend
echo "Enabling JWT auth backend..."
curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{"type": "jwt"}' \
  $VAULT_ADDR/v1/sys/auth/jwt || echo "JWT auth may already be enabled"

# Step 2: Get Nomad server public key for JWT verification
echo -e "\n==> Getting Nomad JWKS keys..."
JWKS_URL="http://192.168.1.11:4646/.well-known/jwks.json"
echo "JWKS URL: $JWKS_URL"

# Step 3: Configure JWT auth with Nomad JWKS
echo "Configuring JWT auth with Nomad JWKS..."
curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
  -d "{
    \"jwks_url\": \"$JWKS_URL\",
    \"jwt_supported_algs\": [\"RS256\", \"EdDSA\"],
    \"default_role\": \"nomad-workloads\"
  }" \
  $VAULT_ADDR/v1/auth/jwt/config

# Step 4: Create a role for Nomad workloads
echo -e "\n==> Creating Nomad workload role..."
curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
  -d '{
    "role_type": "jwt",
    "bound_audiences": ["vault.io"],
    "user_claim": "/nomad_job_id",
    "user_claim_json_pointer": true,
    "claim_mappings": {
      "nomad_namespace": "nomad_namespace",
      "nomad_job_id": "nomad_job_id",
      "nomad_task": "nomad_task"
    },
    "token_type": "service",
    "token_policies": ["eldocam-backend"],
    "token_period": "30m",
    "token_explicit_max_ttl": 0
  }' \
  $VAULT_ADDR/v1/auth/jwt/role/nomad-workloads

# Step 5: Verify configuration
echo -e "\n==> Verifying configuration..."
echo "JWT Auth config:"
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/auth/jwt/config | jq .

echo -e "\nJWT Role config:"
curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
  $VAULT_ADDR/v1/auth/jwt/role/nomad-workloads | jq .

echo -e "\n✓ Vault JWT Auth configured successfully!"
echo -e "\nNext steps:"
echo "1. Update Nomad server configuration to use JWT auth"
echo "2. Restart Nomad servers"
echo "3. Redeploy the backend job"
