# HashiCorp Vault: Secrets Management

`#vault` `#security` `#pki` `#kubernetes` `#secrets`

Centraliser, sécuriser et contrôler l'accès aux secrets. Fini les mots de passe statiques.

---

## Pourquoi HashiCorp Vault ?

### Le Problème : Secret Sprawl

**Scénario classique (cauchemar de sécurité) :**

```
Infrastructure typique SANS Vault :

├─ .env files                    (mots de passe en clair)
├─ Ansible vault.yml             (chiffré mais clé partagée)
├─ Kubernetes Secrets            (base64 ≠ chiffrement)
├─ CI/CD Variables               (GitLab/GitHub Secrets)
├─ AWS Secrets Manager           (verrouillage AWS)
├─ Azure Key Vault               (verrouillage Azure)
├─ Post-it sur l'écran           (classique)
└─ Email "Voici les credentials" (audit nightmare)
```

**Problèmes critiques :**

| Problème | Impact SecNumCloud |
|----------|-------------------|
| **Secret Sprawl** | Secrets éparpillés dans 10+ endroits différents |
| **Rotation manuelle** | Mots de passe jamais changés (années) |
| **Pas d'audit** | Impossible de savoir qui a accédé à quoi |
| **Secrets statiques** | Une fuite = compromission permanente |
| **Révocation impossible** | Pas de moyen de révoquer un secret divulgué |
| **Pas de chiffrement** | `.env` files commitées dans Git (🔥) |

**Exemple de fuite classique :**

```bash
# Fichier .env committé par erreur
git log --all --full-history -- "*env*"

# Résultat : 47 commits avec DB_PASSWORD="SuperSecret123"
# → Le mot de passe est dans l'historique Git POUR TOUJOURS
# → Même après suppression, il reste accessible dans les commits
```

### La Solution : HashiCorp Vault

```mermaid
flowchart TD
    A[Application] -->|1. Authenticate| B[Vault]
    B -->|2. Policy Check| C{Authorized?}
    C -->|Yes| D[Secrets Engine]
    C -->|No| E[Access Denied]

    D -->|3a. Static Secret| F[KV Store]
    D -->|3b. Dynamic Secret| G[Database Engine]
    D -->|3c. Certificate| H[PKI Engine]

    F -->|4. Return Secret| A
    G -->|4. Create User + Return Creds| I[PostgreSQL]
    I -->|5. Temp User| A
    H -->|4. Generate Cert| A

    A -->|TTL Expired| J[Vault Revokes]
    J -->|Delete User| I

    style B fill:#f9d71c
    style G fill:#2ecc71
    style H fill:#3498db
```

**Vault = "Fort Knox" pour vos secrets**

!!! success "Bénéfices Critiques"
    1. **Encryption as a Service** : Chiffrement centralisé (AES-256-GCM)
    2. **Dynamic Secrets** : Credentials créés à la demande, détruits après usage
    3. **Leasing & Revocation** : Chaque secret a un TTL (Time To Live)
    4. **Audit Log** : Chaque accès est tracé (conformité SecNumCloud)
    5. **Secret Versioning** : Rollback possible en cas d'erreur
    6. **Multi-Cloud** : AWS, Azure, GCP avec la même API

---

## Section 1 : Concepts Fondamentaux

### 1. Encryption as a Service

**Sans Vault :**
```bash
# Application chiffre elle-même
echo "my-secret" | openssl enc -aes-256-cbc -out secret.enc

# Problème : Où stocker la clé de chiffrement ?
# → Si la clé est dans le code, ça ne sert à rien
```

**Avec Vault (Transit Engine) :**
```bash
# Vault gère le chiffrement
vault write transit/encrypt/my-app plaintext=$(base64 <<< "my-secret")

# Output : vault:v1:8SDd3WHDOjf7mq69CyCqYjBXAiQQAVZRkFM96XVW...
# → La clé de chiffrement ne quitte JAMAIS Vault
# → L'application n'a jamais accès à la clé maître
```

### 2. Dynamic Secrets (Game Changer)

**Problème des secrets statiques :**
```
Database Password : "Prod2019!"
Créé en          : 2019-03-15
Dernière rotation : JAMAIS
Personnes ayant eu accès : 47 (dont 12 qui ont quitté l'entreprise)
Risque de compromission : CRITIQUE
```

**Solution avec Dynamic Secrets :**

```mermaid
sequenceDiagram
    participant App
    participant Vault
    participant DB as PostgreSQL

    App->>Vault: GET /database/creds/readonly
    Vault->>DB: CREATE USER vault_user_abc123
    Vault->>DB: GRANT SELECT ON ALL TABLES
    DB-->>Vault: User created
    Vault-->>App: {user: vault_user_abc123, pass: xyz789, ttl: 1h}

    Note over App: Use credentials for 1 hour

    Note over Vault: TTL expires after 1h
    Vault->>DB: DROP USER vault_user_abc123
    DB-->>Vault: User deleted

    Note over App,DB: Credentials no longer valid
```

**Exemple concret :**

```bash
# Demander un accès temporaire à PostgreSQL
$ vault read database/creds/readonly

Key                Value
---                -----
lease_id           database/creds/readonly/2f6a614c...
lease_duration     1h
lease_renewable    true
password           A1a-xyZ9kP3mN2vB
username           v-token-readonly-abc123def456-1634567890

# Après 1 heure : Le user PostgreSQL est AUTOMATIQUEMENT supprimé
# → Impossible de réutiliser ces credentials
# → Fuite d'un mot de passe = impact limité à 1h maximum
```

**Bénéfices :**
- ✅ Pas de rotation manuelle (automatique)
- ✅ Audit précis (qui a demandé quoi, quand)
- ✅ Révocation immédiate en cas d'incident
- ✅ Pas de "shared passwords" (chaque app a ses credentials)

### 3. Leasing & Revocation

**Chaque secret a un cycle de vie :**

```
┌─────────────────────────────────────────────────────────┐
│                    Secret Lifecycle                      │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  Creation          Usage             Renewal      Death  │
│     │               │                   │           │    │
│     ▼               ▼                   ▼           ▼    │
│  [Generate] ─> [TTL: 1h] ─> [Renew +30m] ─> [Revoke]   │
│     │               │                   │           │    │
│     │               │                   │           │    │
│  Vault creates   App uses         App requests   Vault  │
│  credentials     secret for       extension      deletes│
│  on-demand       limited time     (if allowed)   secret │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

**Commandes de gestion du lease :**

```bash
# Voir tous les leases actifs
vault list sys/leases/lookup/database/creds/readonly

# Renouveler un lease (si renewable)
vault lease renew database/creds/readonly/2f6a614c

# Révoquer un lease spécifique (urgence)
vault lease revoke database/creds/readonly/2f6a614c

# Révoquer TOUS les leases d'un path (incident de sécurité)
vault lease revoke -prefix database/creds/readonly
```

---

## Section 2 : Architecture & Initialisation

### Seal/Unseal : Le Mécanisme de Sécurité

**Problème :** Comment protéger Vault lui-même ?

**Solution : Shamir's Secret Sharing**

```
Master Key (déchiffre toutes les données)
    │
    ├─ Split en 5 clés (Unseal Keys)
    │
    ├─ Unseal Key 1 : aH3kP...
    ├─ Unseal Key 2 : 9mVzQ...
    ├─ Unseal Key 3 : 2nBxR...
    ├─ Unseal Key 4 : 7wKpS...
    └─ Unseal Key 5 : 5tDfT...

Threshold : 3 clés minimum requises pour déverrouiller
```

**États de Vault :**

| État | Description | Actions possibles |
|------|-------------|-------------------|
| **Sealed** | Verrouillé (au démarrage) | Aucune opération |
| **Unsealed** | Déverrouillé (opérationnel) | Toutes opérations |
| **Standby** | Réplica en attente (HA) | Read-only |

**Workflow d'initialisation :**

```bash
# 1. Initialiser Vault (PREMIÈRE FOIS UNIQUEMENT)
vault operator init -key-shares=5 -key-threshold=3

# Output (SAUVEGARDER IMMÉDIATEMENT DANS UN ENDROIT SÛR)
Unseal Key 1: aH3kP9mVzQ2nBxR7wKpS5tDfT...
Unseal Key 2: 9mVzQ2nBxR7wKpS5tDfTaH3kP...
Unseal Key 3: 2nBxR7wKpS5tDfTaH3kP9mVzQ...
Unseal Key 4: 7wKpS5tDfTaH3kP9mVzQ2nBxR...
Unseal Key 5: 5tDfTaH3kP9mVzQ2nBxR7wKpS...

Initial Root Token: hvs.CAESIKqP3mN2vB9kXyZ1...

# 2. Unsealer Vault (après chaque redémarrage)
vault operator unseal  # Entrer Unseal Key 1
vault operator unseal  # Entrer Unseal Key 2
vault operator unseal  # Entrer Unseal Key 3
# → Vault is now unsealed

# 3. Se connecter avec le root token
vault login hvs.CAESIKqP3mN2vB9kXyZ1...
```

!!! danger "CRITIQUE : Sauvegarde des Unseal Keys"
    **PERTE DES UNSEAL KEYS = PERTE DÉFINITIVE DE TOUTES LES DONNÉES**

    Options de sauvegarde sécurisées :
    - ✅ **PGP Encryption** : Chiffrer chaque clé avec la clé publique d'un admin
    - ✅ **Cloud KMS** : AWS KMS, Azure Key Vault (Auto-Unseal)
    - ✅ **Hardware Security Module (HSM)** : Pour SecNumCloud Niveau 3
    - ✅ **Offline Storage** : Coffre-fort physique (air-gapped)
    - ❌ **JAMAIS dans Git, Slack, Email**

**Auto-Unseal avec Cloud KMS (Production) :**

```hcl
# vault.hcl
seal "awskms" {
  region     = "eu-west-1"
  kms_key_id = "arn:aws:kms:eu-west-1:123456789012:key/abc-def-123"
}

# Avantage : Vault s'unseal automatiquement au démarrage
# Inconvénient : Dépendance au cloud provider
```

### Storage Backend : Raft (Integrated Storage)

**Évolution des backends :**

```
2015 : Consul (complexe, infrastructure supplémentaire)
2019 : Raft Integrated Storage (simple, tout-en-un)
2024 : Raft = Standard recommandé
```

**Configuration Raft (HA Cluster) :**

```hcl
# vault.hcl (Node 1)
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-node-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 0
  tls_cert_file = "/etc/vault/tls/vault.crt"
  tls_key_file  = "/etc/vault/tls/vault.key"
}

api_addr = "https://vault-1.company.com:8200"
cluster_addr = "https://vault-1.company.com:8201"

ui = true
```

**Créer un cluster HA (3 nodes) :**

```bash
# Node 1 : Initialiser
vault operator init

# Node 2 & 3 : Rejoindre le cluster
vault operator raft join https://vault-1.company.com:8200

# Vérifier le cluster
vault operator raft list-peers

Node       Address                  State     Voter
----       -------                  -----     -----
vault-1    vault-1.company.com:8201 leader    true
vault-2    vault-2.company.com:8201 follower  true
vault-3    vault-3.company.com:8201 follower  true
```

---

## Section 3 : Les Moteurs de Secrets (Secrets Engines)

### 1. KV (Key-Value) v2 : Stockage Statique Versionné

**Le secret engine le plus utilisé (équivalent d'un coffre-fort).**

```bash
# Activer le secret engine KV v2
vault secrets enable -path=secret kv-v2

# Écrire un secret
vault kv put secret/database/config \
  username="admin" \
  password="SuperSecret123" \
  host="db.internal.company.com"

# Lire le secret
vault kv get secret/database/config

# Output
====== Data ======
Key         Value
---         -----
host        db.internal.company.com
password    SuperSecret123
username    admin
```

**Versioning (rollback en cas d'erreur) :**

```bash
# Mettre à jour le secret (crée la version 2)
vault kv put secret/database/config password="NewPassword456"

# Voir l'historique des versions
vault kv metadata get secret/database/config

# Output
======= Metadata =======
Key              Value
---              -----
created_time     2024-01-15T10:30:00Z
current_version  2
oldest_version   1
versions         1, 2

# Rollback vers la version 1
vault kv rollback -version=1 secret/database/config

# Supprimer définitivement une version (GDPR compliance)
vault kv destroy -versions=2 secret/database/config
```

**Politique d'accès (read-only) :**

```hcl
# policy-readonly.hcl
path "secret/data/database/*" {
  capabilities = ["read", "list"]
}

# Appliquer la policy
vault policy write readonly policy-readonly.hcl
```

### 2. PKI (Public Key Infrastructure) : Certificats TLS à la Volée

**Remplace les Certificate Authorities (CA) internes.**

```bash
# Activer le PKI engine
vault secrets enable pki

# Configurer le TTL max (10 ans)
vault secrets tune -max-lease-ttl=87600h pki

# Générer le Root CA
vault write pki/root/generate/internal \
  common_name="Company Internal Root CA" \
  ttl=87600h

# Configurer les URLs du CA
vault write pki/config/urls \
  issuing_certificates="https://vault.company.com:8200/v1/pki/ca" \
  crl_distribution_points="https://vault.company.com:8200/v1/pki/crl"

# Créer un rôle pour générer des certificats (*.company.com)
vault write pki/roles/company-dot-com \
  allowed_domains="company.com" \
  allow_subdomains=true \
  max_ttl="720h"  # 30 jours
```

**Générer un certificat pour un service :**

```bash
# Demander un certificat pour api.company.com
vault write pki/issue/company-dot-com \
  common_name="api.company.com" \
  ttl="720h"

# Output
Key                 Value
---                 -----
certificate         -----BEGIN CERTIFICATE-----
                    MIIDXTCCAkWgAwIBAgIUZQ3...
                    -----END CERTIFICATE-----
private_key         -----BEGIN RSA PRIVATE KEY-----
                    MIIEpAIBAAKCAQEA1tZ3K...
                    -----END RSA PRIVATE KEY-----
ca_chain            [-----BEGIN CERTIFICATE-----
                    MIIDNTCCAh2gAwIBAgIUf...
                    -----END CERTIFICATE-----]
```

**Cas d'usage (mTLS entre microservices) :**

```yaml
# kubernetes/deployment.yaml
apiVersion: v1
kind: Pod
metadata:
  name: api-service
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: "api-service"
    vault.hashicorp.com/agent-inject-secret-tls.crt: "pki/issue/company-dot-com"
    vault.hashicorp.com/agent-inject-template-tls.crt: |
      {{- with secret "pki/issue/company-dot-com" "common_name=api.company.com" }}
      {{ .Data.certificate }}
      {{- end }}
spec:
  containers:
  - name: api
    image: api-service:latest
    volumeMounts:
    - name: vault-tls
      mountPath: /vault/secrets
```

**Avantages PKI avec Vault :**
- ✅ Certificats générés en 100ms (vs 2 semaines avec une CA classique)
- ✅ Rotation automatique (TTL court = meilleure sécurité)
- ✅ Révocation instantanée
- ✅ Audit de tous les certificats émis

### 3. Database : Rotation Automatique des Mots de Passe

**Configuration PostgreSQL :**

```bash
# Activer le database engine
vault secrets enable database

# Configurer la connexion à PostgreSQL
vault write database/config/my-postgresql-database \
  plugin_name=postgresql-database-plugin \
  allowed_roles="readonly,readwrite" \
  connection_url="postgresql://{{username}}:{{password}}@postgres:5432/mydb?sslmode=require" \
  username="vault_admin" \
  password="VaultAdminPassword"

# Créer un rôle "readonly" (génère des users temporaires)
vault write database/roles/readonly \
  db_name=my-postgresql-database \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; \
    GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"
```

**Utilisation par une application :**

```python
# app.py
import hvac
import psycopg2

# Se connecter à Vault
client = hvac.Client(url='https://vault.company.com:8200')
client.auth.approle.login(role_id='...', secret_id='...')

# Demander des credentials temporaires
db_creds = client.secrets.database.generate_credentials(name='readonly')

# Utiliser les credentials (valides 1h)
conn = psycopg2.connect(
    host="postgres",
    database="mydb",
    user=db_creds['data']['username'],  # v-token-readonly-abc123...
    password=db_creds['data']['password']
)

# Après 1h : Le user PostgreSQL est automatiquement supprimé
```

**Rotation du mot de passe Root :**

```bash
# Vault peut changer son propre mot de passe de connexion (zéro downtime)
vault write -f database/rotate-root/my-postgresql-database

# → Le mot de passe "vault_admin" est changé
# → Personne ne connaît le nouveau mot de passe (pas même l'admin)
# → Vault est le seul à avoir accès
```

---

## Section 4 : Authentification & Policies (RBAC)

### Auth Methods : Comment se Connecter à Vault

#### 1. Token Auth (Admin / Bootstrap)

```bash
# Se connecter avec le root token (DANGEREUX)
vault login hvs.CAESIKqP3mN2vB9kXyZ1...

# Créer un token temporaire pour un collègue (TTL 8h)
vault token create -ttl=8h -policy=readonly

# Output
Key                  Value
---                  -----
token                hvs.CAESIJ3kP9mVzQ2nBxR...
token_accessor       abc123def456
token_duration       8h
token_policies       [readonly]

# Révoquer le root token (OBLIGATOIRE en production)
vault token revoke <ROOT_TOKEN>
```

#### 2. AppRole (Machines / CI/CD / Ansible)

**Le standard pour l'authentification des applications.**

```bash
# Activer AppRole auth
vault auth enable approle

# Créer un rôle pour Ansible
vault write auth/approle/role/ansible \
  token_policies="ansible-policy" \
  token_ttl=1h \
  token_max_ttl=4h

# Récupérer le RoleID (identifiant public)
vault read auth/approle/role/ansible/role-id

# Output
role_id: 12345678-abcd-1234-abcd-1234567890ab

# Générer un SecretID (mot de passe temporaire)
vault write -f auth/approle/role/ansible/secret-id

# Output
secret_id: 98765432-dcba-4321-dcba-0987654321ba
secret_id_ttl: 0s
```

**Utilisation dans Ansible :**

```yaml
# playbook.yml
- name: Get secret from Vault
  hosts: localhost
  vars:
    vault_addr: "https://vault.company.com:8200"
    role_id: "12345678-abcd-1234-abcd-1234567890ab"
    secret_id: "{{ lookup('env', 'VAULT_SECRET_ID') }}"  # From CI/CD secret
  tasks:
    - name: Authenticate to Vault
      uri:
        url: "{{ vault_addr }}/v1/auth/approle/login"
        method: POST
        body_format: json
        body:
          role_id: "{{ role_id }}"
          secret_id: "{{ secret_id }}"
      register: vault_login

    - name: Get database password
      uri:
        url: "{{ vault_addr }}/v1/secret/data/database/config"
        method: GET
        headers:
          X-Vault-Token: "{{ vault_login.json.auth.client_token }}"
      register: db_secret

    - debug:
        msg: "DB Password: {{ db_secret.json.data.data.password }}"
```

#### 3. Kubernetes Auth (Pods)

**Authentification via ServiceAccount (le plus élégant).**

```bash
# Activer Kubernetes auth
vault auth enable kubernetes

# Configurer la connexion au cluster K8s
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  token_reviewer_jwt=@/var/run/secrets/kubernetes.io/serviceaccount/token

# Créer un rôle lié à un ServiceAccount
vault write auth/kubernetes/role/myapp \
  bound_service_account_names=myapp-sa \
  bound_service_account_namespaces=production \
  policies=myapp-policy \
  ttl=1h
```

**Déploiement Kubernetes (Agent Injector) :**

```yaml
# deployment.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: myapp-sa
  namespace: production
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: production
spec:
  template:
    metadata:
      annotations:
        # Activer l'injection Vault
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "myapp"

        # Injecter le secret database/config
        vault.hashicorp.com/agent-inject-secret-db.env: "secret/data/database/config"

        # Template pour formater le secret en .env
        vault.hashicorp.com/agent-inject-template-db.env: |
          {{- with secret "secret/data/database/config" }}
          export DB_HOST="{{ .Data.data.host }}"
          export DB_USER="{{ .Data.data.username }}"
          export DB_PASS="{{ .Data.data.password }}"
          {{- end }}
    spec:
      serviceAccountName: myapp-sa
      containers:
      - name: app
        image: myapp:latest
        command: ["/bin/sh"]
        args:
          - -c
          - |
            source /vault/secrets/db.env
            ./start-app.sh
```

**Ce qui se passe :**
1. Vault Agent Injector ajoute un sidecar au pod
2. Le sidecar s'authentifie avec le ServiceAccount JWT
3. Il récupère les secrets et les écrit dans `/vault/secrets/`
4. L'app lit les secrets (jamais d'API call dans le code)

### Policies (HCL) : RBAC Granulaire

**Exemple de policy read-only stricte :**

```hcl
# policy-developer.hcl

# Lire les secrets dev uniquement
path "secret/data/dev/*" {
  capabilities = ["read", "list"]
}

# Interdire l'accès à la prod
path "secret/data/prod/*" {
  capabilities = ["deny"]
}

# Créer des secrets temporaires (auto-expiration)
path "secret/data/dev/temp/*" {
  capabilities = ["create", "update", "delete"]

  # Limiter le TTL à 1h
  allowed_parameters = {
    "ttl" = ["1h"]
  }
}

# Lire ses propres métadonnées de token
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Renouveler son token
path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

**Appliquer la policy :**

```bash
vault policy write developer policy-developer.hcl

# Créer un token avec cette policy
vault token create -policy=developer

# Tester la policy
vault login <TOKEN>
vault kv get secret/dev/api-key     # ✅ Autorisé
vault kv get secret/prod/api-key    # ❌ Permission denied
```

**Policy avancée (Sentinel pour SecNumCloud) :**

```hcl
# policy-prod-admin.hcl

# Accès complet à la prod (mais audit obligatoire)
path "secret/data/prod/*" {
  capabilities = ["create", "read", "update", "delete", "list"]

  # Forcer le Multi-Factor Authentication (MFA)
  mfa_methods = ["totp"]

  # Logging renforcé
  control_group = {
    ttl = "4h"
    authorizations_required = 2  # 2 approbations nécessaires
  }
}

# Interdire la suppression des secrets de paiement
path "secret/data/prod/payment/*" {
  capabilities = ["read", "list"]

  # Deny deletion
  denied_parameters = {
    "delete" = ["*"]
  }
}
```

---

## Section 5 : Intégration DevOps (Les Patterns)

### Pattern 1 : Ansible avec hashi_vault Lookup

**Ne jamais écrire de secret dans un playbook.**

```yaml
# playbook.yml
- name: Deploy application with Vault secrets
  hosts: webservers
  vars:
    vault_addr: "https://vault.company.com:8200"
  tasks:
    - name: Get database password from Vault
      set_fact:
        db_password: "{{ lookup('hashi_vault', 'secret=secret/data/database/config:password auth_method=approle role_id={{ role_id }} secret_id={{ secret_id }} url={{ vault_addr }}') }}"
      no_log: true  # Ne pas logger le mot de passe

    - name: Configure application
      template:
        src: app.conf.j2
        dest: /etc/app/app.conf
        mode: '0600'
      vars:
        database_password: "{{ db_password }}"
```

**Template app.conf.j2 :**

```ini
# app.conf.j2
[database]
host = {{ database_host }}
username = {{ database_user }}
password = {{ database_password }}  # Injecté depuis Vault
```

**Avantages :**
- ✅ Pas de secret dans Git
- ✅ Rotation sans redéploiement (relancer le playbook)
- ✅ Audit Vault de chaque accès

### Pattern 2 : Kubernetes Agent Injector (Sidecar)

**Architecture :**

```
┌─────────────────────────────────────────┐
│               Pod                        │
│  ┌────────────┐      ┌────────────┐     │
│  │  Vault     │      │            │     │
│  │  Agent     │─────>│  App       │     │
│  │  (Sidecar) │      │  Container │     │
│  └────────────┘      └────────────┘     │
│        │                    │            │
│        │ Writes secrets     │            │
│        ▼                    ▼            │
│  /vault/secrets/      Reads files       │
│    ├─ db.env                             │
│    └─ api-key.txt                        │
└─────────────────────────────────────────┘
         │
         ▼
   HashiCorp Vault
```

**Exemple complet :**

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: webapp
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: webapp
  template:
    metadata:
      labels:
        app: webapp
      annotations:
        # Activer l'injection
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "webapp"

        # Injecter la DB config
        vault.hashicorp.com/agent-inject-secret-db.json: "secret/data/database/config"
        vault.hashicorp.com/agent-inject-template-db.json: |
          {{- with secret "secret/data/database/config" }}
          {
            "host": "{{ .Data.data.host }}",
            "username": "{{ .Data.data.username }}",
            "password": "{{ .Data.data.password }}"
          }
          {{- end }}

        # Injecter une API key
        vault.hashicorp.com/agent-inject-secret-api-key.txt: "secret/data/api/stripe"
        vault.hashicorp.com/agent-inject-template-api-key.txt: |
          {{- with secret "secret/data/api/stripe" }}
          {{ .Data.data.key }}
          {{- end }}

        # Auto-rotation toutes les 5 minutes
        vault.hashicorp.com/agent-cache-enable: "true"
        vault.hashicorp.com/agent-cache-ttl: "5m"

    spec:
      serviceAccountName: webapp-sa
      containers:
      - name: webapp
        image: webapp:latest
        env:
        - name: DB_CONFIG_FILE
          value: /vault/secrets/db.json
        - name: STRIPE_API_KEY_FILE
          value: /vault/secrets/api-key.txt
```

**Code application (lecture des secrets) :**

```python
# app.py
import json
import os

# Lire la config DB (injectée par Vault)
with open(os.getenv('DB_CONFIG_FILE')) as f:
    db_config = json.load(f)

# Lire l'API key Stripe
with open(os.getenv('STRIPE_API_KEY_FILE')) as f:
    stripe_api_key = f.read().strip()

# Utiliser les secrets
import psycopg2
conn = psycopg2.connect(
    host=db_config['host'],
    user=db_config['username'],
    password=db_config['password']
)
```

**Avantages :**
- ✅ Aucun code Vault dans l'application
- ✅ Secrets mis à jour automatiquement
- ✅ Zero-trust (ServiceAccount = identité forte)

### Pattern 3 : CI/CD (GitLab/GitHub Actions)

**GitHub Actions avec Vault :**

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      # Importer les secrets depuis Vault
      - name: Import Secrets from Vault
        uses: hashicorp/vault-action@v2
        with:
          url: https://vault.company.com:8200
          method: approle
          roleId: ${{ secrets.VAULT_ROLE_ID }}
          secretId: ${{ secrets.VAULT_SECRET_ID }}
          secrets: |
            secret/data/aws/production access_key | AWS_ACCESS_KEY_ID ;
            secret/data/aws/production secret_key | AWS_SECRET_ACCESS_KEY ;
            secret/data/docker/registry password | DOCKER_PASSWORD

      # Les secrets sont maintenant disponibles comme variables d'environnement
      - name: Configure AWS CLI
        run: |
          aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID
          aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY

      - name: Deploy to ECS
        run: |
          ./deploy.sh
```

**GitLab CI avec Vault :**

```yaml
# .gitlab-ci.yml
deploy_production:
  stage: deploy
  image: vault:latest
  script:
    # Authentification avec JWT (GitLab OIDC)
    - export VAULT_TOKEN=$(vault write -field=token auth/jwt/login role=gitlab-ci jwt=$CI_JOB_JWT)

    # Récupérer les secrets
    - export DB_PASSWORD=$(vault kv get -field=password secret/database/prod)
    - export API_KEY=$(vault kv get -field=key secret/api/stripe)

    # Déployer
    - ./deploy.sh
  only:
    - main
```

---

## Référence Rapide

### Commandes Essentielles

```bash
# État du serveur
vault status                          # Vérifier si Vault est unsealed
vault operator unseal                 # Unsealer Vault (3x avec différentes clés)
vault operator seal                   # Sealer Vault (urgence)

# Authentification
vault login <TOKEN>                   # Se connecter avec un token
vault token lookup                    # Voir les infos de son token
vault token renew                     # Renouveler son token

# KV Secrets
vault kv put secret/path key=value    # Écrire un secret
vault kv get secret/path              # Lire un secret
vault kv get -field=key secret/path   # Lire une clé spécifique
vault kv list secret/                 # Lister les secrets
vault kv delete secret/path           # Soft delete (récupérable)
vault kv destroy -versions=1 secret/path  # Hard delete (définitif)
vault kv metadata get secret/path     # Voir l'historique

# Policies
vault policy list                     # Lister les policies
vault policy read <NAME>              # Voir une policy
vault policy write <NAME> file.hcl    # Créer/Mettre à jour une policy

# Lease Management
vault lease lookup <LEASE_ID>         # Voir les détails d'un lease
vault lease renew <LEASE_ID>          # Renouveler un lease
vault lease revoke <LEASE_ID>         # Révoquer un lease
vault lease revoke -prefix path/      # Révoquer tous les leases d'un path

# Secrets Engines
vault secrets list                    # Lister les engines actifs
vault secrets enable <TYPE>           # Activer un engine
vault secrets disable <PATH>          # Désactiver un engine

# Auth Methods
vault auth list                       # Lister les méthodes d'auth
vault auth enable <TYPE>              # Activer une méthode
vault auth disable <PATH>             # Désactiver une méthode

# High Availability
vault operator raft list-peers        # Voir les nodes du cluster
vault operator raft join <ADDR>       # Rejoindre un cluster
vault operator step-down              # Forcer l'élection d'un nouveau leader
```

### Secrets Engines Courants

| Engine | Usage | Commande d'activation |
|--------|-------|----------------------|
| **kv-v2** | Secrets statiques versionnés | `vault secrets enable -path=secret kv-v2` |
| **database** | Credentials dynamiques BDD | `vault secrets enable database` |
| **pki** | Certificats TLS/mTLS | `vault secrets enable pki` |
| **transit** | Encryption as a Service | `vault secrets enable transit` |
| **ssh** | Clés SSH temporaires | `vault secrets enable ssh` |
| **aws** | IAM credentials dynamiques | `vault secrets enable aws` |
| **azure** | Azure credentials | `vault secrets enable azure` |
| **gcp** | GCP service accounts | `vault secrets enable gcp` |

### Auth Methods par Cas d'Usage

| Cas d'Usage | Auth Method | Commande |
|-------------|-------------|----------|
| **Humain** | Token, OIDC, LDAP | `vault auth enable oidc` |
| **CI/CD** | AppRole, JWT | `vault auth enable approle` |
| **Kubernetes** | Kubernetes | `vault auth enable kubernetes` |
| **Cloud** | AWS IAM, Azure MSI | `vault auth enable aws` |
| **Terraform** | Token, AppRole | `vault token create` |

### Dépannage

| Problème | Diagnostic | Solution |
|----------|------------|----------|
| `Error: Vault is sealed` | Vault verrouillé après reboot | `vault operator unseal` (3x) |
| `Permission denied` | Policy insuffisante | Vérifier avec `vault token lookup` |
| `Invalid lease ID` | Lease expiré ou révoqué | Régénérer le secret |
| `Connection refused` | Vault pas démarré | `systemctl start vault` |
| `TLS certificate verify failed` | Certificat invalide | `export VAULT_SKIP_VERIFY=1` (dev only) |

---

## Ressources

**Documentation Officielle :**
- [HashiCorp Vault Docs](https://developer.hashicorp.com/vault/docs)
- [Vault Tutorials](https://developer.hashicorp.com/vault/tutorials)
- [Vault API Reference](https://developer.hashicorp.com/vault/api-docs)

**Formations :**
- [HashiCorp Certified: Vault Associate](https://www.hashicorp.com/certification/vault-associate)
- [Vault on Kubernetes](https://learn.hashicorp.com/tutorials/vault/kubernetes-raft-deployment-guide)

**Outils Complémentaires :**
- `vault-k8s` : Helm chart officiel
- `external-secrets` : Sync Vault → Kubernetes Secrets
- `vaultenv` : Charger secrets Vault comme variables d'environnement
- `consul-template` : Templates dynamiques avec secrets Vault

**Bonnes Pratiques SecNumCloud :**
- [ANSSI - Recommandations de sécurité](https://www.ssi.gouv.fr/)
- [SecNumCloud Référentiel](https://www.ssi.gouv.fr/entreprise/qualifications/prestataires-de-services-de-confiance-qualifies/secnumcloud/)

---

**Next Steps :**
- Déployer Vault en HA avec Raft (3+ nodes)
- Configurer Auto-Unseal avec Cloud KMS
- Implémenter le pattern Agent Injector sur Kubernetes
- Migrer tous les secrets statiques vers Vault
- Activer l'audit logging (fichier + Splunk/ELK)
- Mettre en place des Control Groups (approbation multi-parties)
