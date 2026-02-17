#!/bin/bash
# Script pour gérer les secrets Vault depuis CircleCI
# Usage: ./manage-vault-secrets.sh update|list

set -e

VAULT_ADDR="${VAULT_ADDR:-http://master-nomad.tmg:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-}"

if [ -z "$VAULT_TOKEN" ]; then
  echo "❌ ERROR: VAULT_TOKEN environment variable is required"
  exit 1
fi

export VAULT_ADDR
export VAULT_TOKEN

case "$1" in
  update)
    echo "📝 Updating Vault secrets from environment variables..."
    
    # Update Mailjet secrets
    if [ -n "$MAILJET_API_KEY" ] && [ -n "$MAILJET_SECRET_KEY" ]; then
      curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
        -d "{\"data\": {\"api_key\": \"$MAILJET_API_KEY\", \"secret_key\": \"$MAILJET_SECRET_KEY\"}}" \
        "$VAULT_ADDR/v1/secret/data/eldocam/mailjet"
      echo "✅ Mailjet secrets updated"
    fi
    
    # Update Email config
    if [ -n "$SENDER_EMAIL" ] && [ -n "$SENDER_NAME" ] && [ -n "$ADMIN_TO" ]; then
      curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
        -d "{\"data\": {\"sender_email\": \"$SENDER_EMAIL\", \"sender_name\": \"$SENDER_NAME\", \"admin_to\": \"$ADMIN_TO\"}}" \
        "$VAULT_ADDR/v1/secret/data/eldocam/email"
      echo "✅ Email config updated"
    fi
    
    # Update Turnstile secret
    if [ -n "$TURNSTILE_SECRET" ]; then
      curl -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" \
        -d "{\"data\": {\"secret\": \"$TURNSTILE_SECRET\"}}" \
        "$VAULT_ADDR/v1/secret/data/eldocam/turnstile"
      echo "✅ Turnstile secret updated"
    fi
    
    echo ""
    echo "🎉 All secrets updated successfully!"
    echo "⚠️  Note: Nomad jobs using these secrets need to be restarted to pick up changes"
    ;;
    
  list)
    echo "📋 Current Vault secrets:"
    echo ""
    echo "=== Mailjet ==="
    curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/secret/data/eldocam/mailjet" | jq -r '.data.data | to_entries[] | "\(.key): \(.value[:10])***"'
    
    echo ""
    echo "=== Email Config ==="
    curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/secret/data/eldocam/email" | jq -r '.data.data | to_entries[] | "\(.key): \(.value)"'
    
    echo ""
    echo "=== Turnstile ==="
    curl -s -H "X-Vault-Token: $VAULT_TOKEN" "$VAULT_ADDR/v1/secret/data/eldocam/turnstile" | jq -r '.data.data.secret[:20] + "***"'
    ;;
    
  *)
    echo "Usage: $0 {update|list}"
    echo ""
    echo "update - Update Vault secrets from environment variables"
    echo "         Required env vars:"
    echo "         - MAILJET_API_KEY, MAILJET_SECRET_KEY"
    echo "         - SENDER_EMAIL, SENDER_NAME, ADMIN_TO"
    echo "         - TURNSTILE_SECRET"
    echo ""
    echo "list   - List current secrets in Vault (masked)"
    exit 1
    ;;
esac
