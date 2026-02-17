# Eldocam Backend

API backend en Go pour gérer les formulaires de contact Eldocam avec validation Cloudflare Turnstile et envoi email via Mailjet.

## 🏗️ Architecture

- **Runtime**: Go 1.25.1+
- **Orchestration**: HashiCorp Nomad 1.11.2 (cluster 3 servers + 2 clients)
- **Secrets**: HashiCorp Vault (KV v2 + Workload Identity JWT)
- **Reverse Proxy**: Traefik v3.1 avec TLS automatique (Cloudflare DNS challenge)
- **CI/CD**: CircleCI Cloud
- **Container Registry**: GitHub Container Registry (ghcr.io)
- **Email**: Mailjet SMTP
- **Anti-spam**: Cloudflare Turnstile + rate limiting

## 🌐 URLs Production

- **API Backend**: https://api.eldocam.com
- **Frontend**: https://eldocam.com
- **Nomad UI**: https://nomad.eldocam.com
- **Health Check**: https://api.eldocam.com/health

## ✨ Fonctionnalités

- **Validation formulaire**: Schema validation avec validator/v10
- **Vérification Turnstile**: Validation côté serveur du challenge Cloudflare
- **Envoi emails**: Email admin + auto-réponse utilisateur via Mailjet
- **Rate limiting**: Protection anti-abuse par IP
- **High Availability**: 2 réplicas avec health checks automatiques
- **Zero-downtime deployment**: Rolling updates avec Nomad

## 🚀 Déploiement

### CI/CD Automatique (Recommandé)
Push sur `main` → CircleCI build + deploy automatiquement:
1. Build Docker image
2. Push sur ghcr.io/sebbemercier/eldocam-backend
3. Deploy sur Nomad avec rolling update
4. Secrets injectés automatiquement depuis Vault

**Configuration**: Voir [CIRCLECI_SETUP.md](CIRCLECI_SETUP.md)

### Déploiement Manuel
```bash
# 1. Build et push Docker image
docker build -t ghcr.io/sebbemercier/eldocam-backend:latest .
docker push ghcr.io/sebbemercier/eldocam-backend:latest

# 2. Deploy sur Nomad
export NOMAD_ADDR=https://nomad.eldocam.com
export NOMAD_TOKEN=your_nomad_acl_token
export NOMAD_SKIP_VERIFY=1
nomad job run nomad/eldocam-backend.nomad.hcl

# 3. Monitorer le déploiement
nomad job status eldocam-backend
```

## 🔐 Gestion des Secrets

Tous les secrets sont dans **HashiCorp Vault** (jamais dans Git):

### Secrets Vault (KV v2)
- `secret/eldocam/mailjet` → `api_key`, `secret_key`
- `secret/eldocam/email` → `sender_email`, `sender_name`, `admin_to`
- `secret/eldocam/turnstile` → `secret`

### Injection automatique
Le job Nomad utilise **Workload Identity** (JWT authentication) pour récupérer les secrets de Vault automatiquement au runtime.

### Mise à jour des secrets
```bash
# Utiliser le script fourni
cd scripts
export VAULT_TOKEN=your_vault_token
export MAILJET_API_KEY=new_key
export MAILJET_SECRET_KEY=new_secret
# ... autres variables
./manage-vault-secrets.sh update

# Redémarrer le job pour appliquer
nomad job restart eldocam-backend
```

## 🛠️ Développement Local

```bash
# Installer les dépendances Go
go mod download

# Variables d'environnement (copier depuis Vault)
export MAILJET_API_KEY=xxx
export MAILJET_SECRET_KEY=xxx
export SENDER_EMAIL=noreply@example.com
export SENDER_NAME="Eldocam"
export ADMIN_TO=admin@example.com
export TURNSTILE_SECRET=xxx

# Lancer l'API
go run main.go
```

API disponible sur http://localhost:8000

## 📦 Structure Projet

```
.
├── .circleci/
│   └── config.yml                  # Pipeline CircleCI
├── nomad/
│   └── eldocam-backend.nomad.hcl  # Job definition Nomad avec Vault
├── scripts/
│   └── manage-vault-secrets.sh    # Gestion secrets Vault
├── Dockerfile                      # Multi-stage build optimisé
├── main.go                         # Code Go principal
├── go.mod, go.sum                 # Dependencies
├── CIRCLECI_SETUP.md              # Doc CI/CD complète
├── VAULT_TODO.md                  # Options avancées Vault
└── vault-jwt-setup.sh             # Setup Vault JWT auth
```

## 🔍 Monitoring & Troubleshooting

### Status check
```bash
# Job Nomad
export NOMAD_ADDR=https://nomad.eldocam.com
export NOMAD_TOKEN=your_token
nomad job status eldocam-backend

# Health endpoint
curl https://api.eldocam.com/health

# Logs d'allocation
nomad alloc logs -f <allocation-id>
```

### Problèmes courants

**Backend ne démarre pas**
1. Vérifier Vault accessible: `curl http://master-nomad.tmg:8200/v2/sys/health`
2. Vérifier JWT auth config: `curl http://master-nomad.tmg:8200/v1/auth/jwt-nomad/config`
3. Vérifier logs Nomad

**Secrets non injectés**
1. Vérifier secrets dans Vault
2. Vérifier policy `eldocam-backend` donne accès read
3. Redémarrer job: `nomad job restart eldocam-backend`

**CircleCI deploy fail**
- Vérifier contexts CircleCI (github-creds, nomad-creds)
- Vérifier token Nomad valide
- Voir [CIRCLECI_SETUP.md](CIRCLECI_SETUP.md)

## 📚 Documentation

- [CIRCLECI_SETUP.md](CIRCLECI_SETUP.md) - Setup complet CI/CD + contexts
- [VAULT_TODO.md](VAULT_TODO.md) - Options configuration Vault avancées
- [vault-jwt-setup.sh](vault-jwt-setup.sh) - Script configuration Vault JWT
- [scripts/manage-vault-secrets.sh](scripts/manage-vault-secrets.sh) - CLI pour gérer secrets

## 🔒 Sécurité

✅ Aucun secret dans Git (Vault uniquement)  
✅ Workload Identity JWT pour auth Vault (plus sécurisé que tokens statiques)  
✅ TLS sur toutes les communications externes  
✅ Rate limiting anti-abuse  
✅ Validation Turnstile côté serveur  
✅ Contexts CircleCI encrypted pour credentials  

## 📄 License

Propriétaire - Eldocam
