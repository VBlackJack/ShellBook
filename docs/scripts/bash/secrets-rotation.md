---
tags:
  - scripts
  - bash
  - security
  - secrets
  - automation
---

# secrets-rotation.sh

Script de rotation automatique des secrets (mots de passe, API keys). Maintient la sécurité sans intervention manuelle.

## Cas d'Usage

- **Rotation planifiée** des mots de passe de service
- **Mise à jour** des API keys
- **Synchronisation** avec gestionnaire de secrets (Vault, AWS SSM)
- **Audit** des dernières rotations

## Prérequis

- Bash 4.0+
- `openssl` pour la génération de secrets
- Accès aux services cibles (DB, API, etc.)
- Optionnel: `vault`, `aws` CLI

## Script

```bash
#!/bin/bash
#===============================================================================
# secrets-rotation.sh - Rotation automatique des secrets
#
# Usage: ./secrets-rotation.sh [COMMAND] [OPTIONS]
#
# Commands:
#   rotate      Effectuer une rotation
#   audit       Auditer les rotations
#   list        Lister les secrets gérés
#
# Options:
#   -t, --type TYPE        Type de secret (db|api|ssh|all)
#   -s, --service NAME     Service spécifique
#   -d, --dry-run          Simulation sans changement
#   -b, --backend BACKEND  Backend (file|vault|ssm)
#   -l, --log FILE         Fichier de log
#===============================================================================

set -euo pipefail

# === CONFIGURATION ===
SECRET_TYPE="all"
SERVICE=""
DRY_RUN=false
BACKEND="file"
LOG_FILE="/var/log/secrets-rotation.log"
SECRETS_DIR="/etc/secrets"
ROTATION_HISTORY="$SECRETS_DIR/.rotation-history"

# Paramètres de génération
PASSWORD_LENGTH=32
API_KEY_LENGTH=48

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# === FONCTIONS UTILITAIRES ===

log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    echo -e "$msg"
    echo "$msg" >> "$LOG_FILE"
}

log_ok() { log "${GREEN}[OK]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; }
log_fail() { log "${RED}[FAIL]${NC} $1"; }

generate_password() {
    openssl rand -base64 48 | tr -dc 'a-zA-Z0-9!@#$%^&*' | head -c "$PASSWORD_LENGTH"
}

generate_api_key() {
    openssl rand -hex "$((API_KEY_LENGTH / 2))"
}

generate_ssh_key() {
    local name=$1
    local key_file="$SECRETS_DIR/ssh/$name"
    mkdir -p "$(dirname "$key_file")"
    ssh-keygen -t ed25519 -f "$key_file" -N "" -C "$name@$(hostname)" -q
    echo "$key_file"
}

# === BACKENDS ===

# Backend fichier (simple)
file_store() {
    local key=$1
    local value=$2
    local secret_file="$SECRETS_DIR/${key//\//_}"

    mkdir -p "$SECRETS_DIR"
    chmod 700 "$SECRETS_DIR"

    echo "$value" > "$secret_file"
    chmod 600 "$secret_file"

    log "Secret stocké: $secret_file"
}

file_get() {
    local key=$1
    local secret_file="$SECRETS_DIR/${key//\//_}"
    [[ -f "$secret_file" ]] && cat "$secret_file"
}

# Backend HashiCorp Vault
vault_store() {
    local key=$1
    local value=$2

    if command -v vault &>/dev/null; then
        vault kv put "secret/$key" value="$value"
        log "Secret stocké dans Vault: secret/$key"
    else
        log_fail "Vault CLI non disponible"
        return 1
    fi
}

vault_get() {
    local key=$1
    vault kv get -field=value "secret/$key" 2>/dev/null
}

# Backend AWS SSM Parameter Store
ssm_store() {
    local key=$1
    local value=$2

    if command -v aws &>/dev/null; then
        aws ssm put-parameter \
            --name "/secrets/$key" \
            --value "$value" \
            --type SecureString \
            --overwrite
        log "Secret stocké dans SSM: /secrets/$key"
    else
        log_fail "AWS CLI non disponible"
        return 1
    fi
}

ssm_get() {
    local key=$1
    aws ssm get-parameter --name "/secrets/$key" --with-decryption --query 'Parameter.Value' --output text 2>/dev/null
}

# Fonction de stockage générique
store_secret() {
    local key=$1
    local value=$2

    case "$BACKEND" in
        file) file_store "$key" "$value" ;;
        vault) vault_store "$key" "$value" ;;
        ssm) ssm_store "$key" "$value" ;;
    esac
}

get_secret() {
    local key=$1

    case "$BACKEND" in
        file) file_get "$key" ;;
        vault) vault_get "$key" ;;
        ssm) ssm_get "$key" ;;
    esac
}

# === ROTATION PAR TYPE ===

rotate_db_password() {
    local service=$1
    local config_file="/etc/secrets/db/$service.conf"

    if [[ ! -f "$config_file" ]]; then
        log_warn "Config non trouvée pour DB $service"
        return 1
    fi

    source "$config_file"  # DB_HOST, DB_PORT, DB_USER, DB_NAME

    local new_password=$(generate_password)

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Rotation mot de passe DB $service"
        return 0
    fi

    # MySQL
    if command -v mysql &>/dev/null && [[ "${DB_TYPE:-mysql}" == "mysql" ]]; then
        mysql -h "$DB_HOST" -P "${DB_PORT:-3306}" -u root -e \
            "ALTER USER '$DB_USER'@'%' IDENTIFIED BY '$new_password';"
    fi

    # PostgreSQL
    if command -v psql &>/dev/null && [[ "${DB_TYPE:-}" == "postgres" ]]; then
        PGPASSWORD="$DB_ADMIN_PASS" psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U postgres -c \
            "ALTER USER $DB_USER WITH PASSWORD '$new_password';"
    fi

    store_secret "db/$service" "$new_password"
    record_rotation "db" "$service"

    log_ok "Mot de passe DB $service roté"
}

rotate_api_key() {
    local service=$1
    local config_file="/etc/secrets/api/$service.conf"

    if [[ ! -f "$config_file" ]]; then
        log_warn "Config non trouvée pour API $service"
        return 1
    fi

    source "$config_file"  # API_ENDPOINT, API_METHOD

    local new_key=$(generate_api_key)

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Rotation API key $service"
        return 0
    fi

    # Si le service a un endpoint de rotation
    if [[ -n "${API_ROTATE_ENDPOINT:-}" ]]; then
        curl -s -X POST "$API_ROTATE_ENDPOINT" \
            -H "Authorization: Bearer $(get_secret "api/$service")" \
            -H "Content-Type: application/json" \
            -d "{\"new_key\": \"$new_key\"}"
    fi

    store_secret "api/$service" "$new_key"
    record_rotation "api" "$service"

    log_ok "API key $service rotée"
}

rotate_ssh_key() {
    local service=$1

    if [[ "$DRY_RUN" == "true" ]]; then
        log "[DRY-RUN] Rotation SSH key $service"
        return 0
    fi

    local old_key="$SECRETS_DIR/ssh/$service"
    local backup_dir="$SECRETS_DIR/ssh/backup"

    # Backup de l'ancienne clé
    if [[ -f "$old_key" ]]; then
        mkdir -p "$backup_dir"
        mv "$old_key" "$backup_dir/${service}.$(date +%Y%m%d%H%M%S)"
        mv "$old_key.pub" "$backup_dir/${service}.$(date +%Y%m%d%H%M%S).pub" 2>/dev/null || true
    fi

    # Génération nouvelle clé
    local new_key=$(generate_ssh_key "$service")

    record_rotation "ssh" "$service"
    log_ok "SSH key $service rotée: $new_key"
}

# === HISTORIQUE ===

record_rotation() {
    local type=$1
    local service=$2

    mkdir -p "$(dirname "$ROTATION_HISTORY")"
    echo "$(date -Iseconds)|$type|$service|$(whoami)" >> "$ROTATION_HISTORY"
}

# === COMMANDES ===

cmd_rotate() {
    log "=== Rotation des secrets ==="

    case "$SECRET_TYPE" in
        db)
            if [[ -n "$SERVICE" ]]; then
                rotate_db_password "$SERVICE"
            else
                for conf in /etc/secrets/db/*.conf; do
                    [[ -f "$conf" ]] && rotate_db_password "$(basename "$conf" .conf)"
                done
            fi
            ;;
        api)
            if [[ -n "$SERVICE" ]]; then
                rotate_api_key "$SERVICE"
            else
                for conf in /etc/secrets/api/*.conf; do
                    [[ -f "$conf" ]] && rotate_api_key "$(basename "$conf" .conf)"
                done
            fi
            ;;
        ssh)
            if [[ -n "$SERVICE" ]]; then
                rotate_ssh_key "$SERVICE"
            else
                log_warn "SSH: Spécifiez un service avec -s"
            fi
            ;;
        all)
            for conf in /etc/secrets/db/*.conf; do
                [[ -f "$conf" ]] && rotate_db_password "$(basename "$conf" .conf)"
            done
            for conf in /etc/secrets/api/*.conf; do
                [[ -f "$conf" ]] && rotate_api_key "$(basename "$conf" .conf)"
            done
            ;;
    esac
}

cmd_audit() {
    log "=== Audit des rotations ==="

    if [[ ! -f "$ROTATION_HISTORY" ]]; then
        log_warn "Aucun historique trouvé"
        return
    fi

    echo ""
    echo "| Date | Type | Service | User |"
    echo "|------|------|---------|------|"

    tail -20 "$ROTATION_HISTORY" | while IFS='|' read -r date type service user; do
        echo "| $date | $type | $service | $user |"
    done
}

cmd_list() {
    log "=== Secrets gérés ==="

    echo ""
    echo "## Bases de données"
    for conf in /etc/secrets/db/*.conf 2>/dev/null; do
        [[ -f "$conf" ]] && echo "- $(basename "$conf" .conf)"
    done

    echo ""
    echo "## API Keys"
    for conf in /etc/secrets/api/*.conf 2>/dev/null; do
        [[ -f "$conf" ]] && echo "- $(basename "$conf" .conf)"
    done

    echo ""
    echo "## SSH Keys"
    for key in "$SECRETS_DIR"/ssh/*.pub 2>/dev/null; do
        [[ -f "$key" ]] && echo "- $(basename "$key" .pub)"
    done
}

# === MAIN ===

COMMAND="${1:-rotate}"
shift || true

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type) SECRET_TYPE="$2"; shift 2 ;;
        -s|--service) SERVICE="$2"; shift 2 ;;
        -d|--dry-run) DRY_RUN=true; shift ;;
        -b|--backend) BACKEND="$2"; shift 2 ;;
        -l|--log) LOG_FILE="$2"; shift 2 ;;
        -h|--help) grep '^#' "$0" | grep -v '#!/' | sed 's/^# //' | head -20; exit 0 ;;
        *) shift ;;
    esac
done

case "$COMMAND" in
    rotate) cmd_rotate ;;
    audit) cmd_audit ;;
    list) cmd_list ;;
    *) echo "Commande inconnue: $COMMAND"; exit 1 ;;
esac
```

## Configuration

Créez des fichiers de configuration dans `/etc/secrets/` :

### Base de données
```bash
# /etc/secrets/db/myapp.conf
DB_TYPE=postgres
DB_HOST=db.example.com
DB_PORT=5432
DB_USER=myapp
DB_NAME=myapp_prod
DB_ADMIN_PASS=xxx  # Pour la rotation
```

### API
```bash
# /etc/secrets/api/stripe.conf
API_ENDPOINT=https://api.stripe.com
API_ROTATE_ENDPOINT=https://api.stripe.com/v1/api_keys/rotate
```

## Exemples d'Utilisation

```bash
# Rotation de tous les secrets DB
sudo ./secrets-rotation.sh rotate -t db

# Rotation d'un service spécifique
sudo ./secrets-rotation.sh rotate -t db -s myapp

# Simulation (dry-run)
sudo ./secrets-rotation.sh rotate -t all -d

# Avec Vault comme backend
sudo ./secrets-rotation.sh rotate -t api -b vault

# Audit des rotations
sudo ./secrets-rotation.sh audit
```

## Intégration Cron

```bash
# Rotation mensuelle des mots de passe DB
0 2 1 * * /opt/scripts/secrets-rotation.sh rotate -t db

# Rotation hebdomadaire des API keys
0 3 * * 0 /opt/scripts/secrets-rotation.sh rotate -t api
```

## Voir Aussi

- [HashiCorp Vault](../../security/hashicorp-vault.md)
- [security-audit.sh](security-audit.md)
