# Vault Integration - TODO

## État actuel
Les secrets sont stockés **en dur dans le job Nomad** (`nomad/eldocam-backend.nomad.hcl`).

⚠️ **Temporaire** - pour rétablir Vault:

## Problème rencontré
Nomad 1.11+ utilise **Workload Identity** par défaut pour Vault:
- Tente JWT auth sur `/v1/auth/jwt-nomad/login`
- Impossible de désactiver depuis le job
- Nécessite configuration serveur avec accès sudo

## Solutions possibles

### Option 1: Configurer JWT Auth Backend (recommandé)
```bash
# Sur un serveur avec Vault configured
vault auth enable -path=jwt-nomad jwt
vault write auth/jwt-nomad/config \
  jwks_url="http://192.168.1.11:4646/.well-known/jwks.json" \
  bound_issuer="http://192.168.1.11:4646" \
  default_role="nomad-workloads"

vault write auth/jwt-nomad/role/nomad-workloads \
  role_type="jwt" \
  bound_audiences="vault.io" \
  user_claim="/nomad_job_id" \
  user_claim_json_pointer=true \
  claim_mappings="/nomad_namespace"="nomad_namespace" \
  token_policies="eldocam-backend" \
  token_ttl=15m
```

### Option 2: Désactiver Workload Identity sur serveurs
SSH sur chaque serveur Nomad (192.168.1.11-13):
```bash
sudo tee -a /etc/nomad.d/nomad.hcl <<EOF
vault {
  enabled = true
  address = "http://master-nomad.tmg:8200"
  token = "$VAULT_TOKEN"  # Use environment variable
  jwt_auth_backend_path = ""  # Disable workload identity
}
EOF
sudo systemctl restart nomad
```

### Option 3: Utiliser Nomad Variables (Nomad 1.4+)
Plus moderne que Vault pour secrets d'application:
```bash
nomad var put nomad/jobs/eldocam-backend \
  MAILJET_API_KEY=xxx \
  MAILJET_SECRET_KEY=xxx \
  ...
```

## Restaurer Vault dans le job
Une fois JWT configuré ou workload identity désactivé:

```hcl
vault {
  policies      = ["eldocam-backend"]
  change_mode   = "restart"
  change_signal = "SIGTERM"
}

template {
  data = <<EOH
{{ with secret "secret/data/eldocam/mailjet" }}
MAILJET_API_KEY="{{ .Data.data.api_key }}"
{{ end }}
...
EOH
  destination = "secrets/app.env"
  env         = true
}
```

Secrets toujours dans Vault à:
- `secret/eldocam/mailjet` (api_key, secret_key)
- `secret/eldocam/email` (sender_email, sender_name, admin_to)  
- `secret/eldocam/turnstile` (secret)

Policy `eldocam-backend` existe et donne accès lecture.
