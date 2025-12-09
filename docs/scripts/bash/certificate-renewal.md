---
tags:
  - scripts
  - bash
  - ssl
  - certificates
  - security
  - automation
---

# certificate-renewal.sh

Script de surveillance et renouvellement automatique des certificats SSL/TLS. Évite les expirations surprises.

## Cas d'Usage

- **Monitoring** des dates d'expiration
- **Alerting** proactif (30/15/7 jours avant)
- **Renouvellement automatique** (Let's Encrypt/ACME)
- **Rapport** de tous les certificats d'un serveur

## Prérequis

- `openssl`
- `certbot` (optionnel, pour Let's Encrypt)
- Accès aux certificats ou aux endpoints HTTPS

## Script

```bash
#!/bin/bash
#===============================================================================
# certificate-renewal.sh - Surveillance et renouvellement des certificats
#
# Usage: ./certificate-renewal.sh [COMMAND] [OPTIONS]
#
# Commands:
#   check       Vérifier l'expiration des certificats
#   renew       Renouveler les certificats (Let's Encrypt)
#   report      Générer un rapport complet
#
# Options:
#   -d, --domain DOMAIN    Domaine à vérifier
#   -f, --file FILE        Fichier certificat local
#   -l, --list FILE        Liste de domaines (un par ligne)
#   -w, --warn DAYS        Seuil d'alerte (défaut: 30)
#   -c, --critical DAYS    Seuil critique (défaut: 7)
#   -r, --reload SERVICE   Service à recharger après renouvellement
#   -m, --mail EMAIL       Email pour les alertes
#   -q, --quiet            Mode silencieux
#===============================================================================

set -euo pipefail

# === CONFIGURATION ===
WARN_DAYS=30
CRITICAL_DAYS=7
RELOAD_SERVICE=""
MAIL_TO=""
QUIET=false
CERTBOT_CMD="certbot"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# === FONCTIONS ===

log() {
    [[ "$QUIET" == "true" ]] && return
    echo -e "$1"
}

log_ok() { log "${GREEN}[OK]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; }
log_crit() { log "${RED}[CRIT]${NC} $1"; }
log_info() { log "${BLUE}[INFO]${NC} $1"; }

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# //' | head -25
    exit 0
}

# Obtenir la date d'expiration d'un certificat distant
get_remote_expiry() {
    local domain=$1
    local port=${2:-443}

    echo | openssl s_client -servername "$domain" -connect "$domain:$port" 2>/dev/null | \
        openssl x509 -noout -enddate 2>/dev/null | \
        cut -d= -f2
}

# Obtenir la date d'expiration d'un fichier certificat
get_file_expiry() {
    local file=$1
    openssl x509 -in "$file" -noout -enddate 2>/dev/null | cut -d= -f2
}

# Calculer les jours restants
days_until_expiry() {
    local expiry_date=$1
    local expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s 2>/dev/null)
    local now_epoch=$(date +%s)
    echo $(( (expiry_epoch - now_epoch) / 86400 ))
}

# Obtenir les infos du certificat
get_cert_info() {
    local domain=$1
    local port=${2:-443}

    echo | openssl s_client -servername "$domain" -connect "$domain:$port" 2>/dev/null | \
        openssl x509 -noout -subject -issuer -dates 2>/dev/null
}

# Vérifier un certificat
check_certificate() {
    local target=$1
    local is_file=${2:-false}
    local expiry_date
    local days_left
    local status="OK"
    local color="$GREEN"

    if [[ "$is_file" == "true" ]]; then
        expiry_date=$(get_file_expiry "$target")
        [[ -z "$expiry_date" ]] && { log_crit "$target - Impossible de lire le certificat"; return 1; }
    else
        expiry_date=$(get_remote_expiry "$target")
        [[ -z "$expiry_date" ]] && { log_crit "$target - Connexion impossible"; return 1; }
    fi

    days_left=$(days_until_expiry "$expiry_date")

    if [[ $days_left -le 0 ]]; then
        status="EXPIRED"
        color="$RED"
    elif [[ $days_left -le $CRITICAL_DAYS ]]; then
        status="CRITICAL"
        color="$RED"
    elif [[ $days_left -le $WARN_DAYS ]]; then
        status="WARNING"
        color="$YELLOW"
    fi

    log "${color}[$status]${NC} $target - Expire dans ${days_left} jours ($expiry_date)"

    # Retourner le status pour le rapport
    echo "$target,$days_left,$status,$expiry_date"

    [[ "$status" == "OK" ]] && return 0 || return 1
}

# Renouveler avec certbot
renew_certificate() {
    local domain=$1

    log_info "Renouvellement de $domain..."

    if ! command -v "$CERTBOT_CMD" &>/dev/null; then
        log_crit "certbot non trouvé"
        return 1
    fi

    # Essayer le renouvellement
    if $CERTBOT_CMD renew --cert-name "$domain" --quiet; then
        log_ok "$domain renouvelé avec succès"

        # Recharger le service si spécifié
        if [[ -n "$RELOAD_SERVICE" ]]; then
            log_info "Rechargement de $RELOAD_SERVICE..."
            systemctl reload "$RELOAD_SERVICE" || systemctl restart "$RELOAD_SERVICE"
        fi
        return 0
    else
        log_crit "Échec du renouvellement de $domain"
        return 1
    fi
}

# Générer un rapport
generate_report() {
    local results=("$@")
    local report=""
    local critical=0
    local warning=0
    local ok=0

    report+="=== RAPPORT CERTIFICATS SSL/TLS ===\n"
    report+="Date: $(date '+%Y-%m-%d %H:%M:%S')\n"
    report+="Host: $(hostname)\n\n"
    report+="| Domaine | Jours | Status | Expiration |\n"
    report+="|---------|-------|--------|------------|\n"

    for result in "${results[@]}"; do
        IFS=',' read -r domain days status expiry <<< "$result"
        report+="| $domain | $days | $status | $expiry |\n"

        case "$status" in
            CRITICAL|EXPIRED) ((critical++)) ;;
            WARNING) ((warning++)) ;;
            OK) ((ok++)) ;;
        esac
    done

    report+="\n"
    report+="Résumé: $ok OK, $warning Warning, $critical Critical\n"

    echo -e "$report"
}

# Envoyer une alerte
send_alert() {
    local message=$1
    local subject=$2

    if [[ -n "$MAIL_TO" ]]; then
        echo -e "$message" | mail -s "$subject" "$MAIL_TO" 2>/dev/null || \
            log_warn "Impossible d'envoyer l'email"
    fi
}

# === COMMANDES ===

cmd_check() {
    local targets=()
    local results=()
    local has_issues=false

    # Collecter les cibles
    if [[ -n "${DOMAIN:-}" ]]; then
        targets+=("$DOMAIN")
    fi

    if [[ -n "${CERT_FILE:-}" ]]; then
        targets+=("file:$CERT_FILE")
    fi

    if [[ -n "${LIST_FILE:-}" ]] && [[ -f "$LIST_FILE" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && targets+=("$line")
        done < "$LIST_FILE"
    fi

    if [[ ${#targets[@]} -eq 0 ]]; then
        log_crit "Aucune cible spécifiée. Utilisez -d, -f ou -l"
        exit 1
    fi

    log "=== Vérification des certificats ===\n"

    for target in "${targets[@]}"; do
        local is_file=false
        local check_target="$target"

        if [[ "$target" == file:* ]]; then
            is_file=true
            check_target="${target#file:}"
        fi

        result=$(check_certificate "$check_target" "$is_file") || has_issues=true
        results+=("$result")
    done

    # Alerting si problèmes
    if [[ "$has_issues" == "true" && -n "$MAIL_TO" ]]; then
        report=$(generate_report "${results[@]}")
        send_alert "$report" "[CERT ALERT] Certificats en expiration - $(hostname)"
    fi

    $has_issues && exit 1 || exit 0
}

cmd_renew() {
    if [[ -z "${DOMAIN:-}" ]]; then
        # Renouveler tous les certificats proches de l'expiration
        log_info "Renouvellement automatique de tous les certificats..."
        $CERTBOT_CMD renew --quiet

        if [[ -n "$RELOAD_SERVICE" ]]; then
            systemctl reload "$RELOAD_SERVICE" 2>/dev/null || true
        fi
    else
        renew_certificate "$DOMAIN"
    fi
}

cmd_report() {
    local targets=()
    local results=()

    # Scanner les certificats Let's Encrypt locaux
    if [[ -d "/etc/letsencrypt/live" ]]; then
        for dir in /etc/letsencrypt/live/*/; do
            [[ -f "${dir}cert.pem" ]] && targets+=("file:${dir}cert.pem")
        done
    fi

    # Ajouter les domaines de la liste
    if [[ -n "${LIST_FILE:-}" ]] && [[ -f "$LIST_FILE" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" && ! "$line" =~ ^# ]] && targets+=("$line")
        done < "$LIST_FILE"
    fi

    for target in "${targets[@]}"; do
        local is_file=false
        local check_target="$target"

        if [[ "$target" == file:* ]]; then
            is_file=true
            check_target="${target#file:}"
        fi

        result=$(check_certificate "$check_target" "$is_file" 2>/dev/null) || true
        [[ -n "$result" ]] && results+=("$result")
    done

    generate_report "${results[@]}"
}

# === MAIN ===

COMMAND="${1:-check}"
shift || true

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -f|--file) CERT_FILE="$2"; shift 2 ;;
        -l|--list) LIST_FILE="$2"; shift 2 ;;
        -w|--warn) WARN_DAYS="$2"; shift 2 ;;
        -c|--critical) CRITICAL_DAYS="$2"; shift 2 ;;
        -r|--reload) RELOAD_SERVICE="$2"; shift 2 ;;
        -m|--mail) MAIL_TO="$2"; shift 2 ;;
        -q|--quiet) QUIET=true; shift ;;
        -h|--help) usage ;;
        *) DOMAIN="$1"; shift ;;
    esac
done

case "$COMMAND" in
    check) cmd_check ;;
    renew) cmd_renew ;;
    report) cmd_report ;;
    *) usage ;;
esac
```

## Exemples d'Utilisation

### Vérification simple

```bash
# Vérifier un domaine
./certificate-renewal.sh check -d example.com

# Vérifier un fichier certificat local
./certificate-renewal.sh check -f /etc/ssl/certs/mysite.crt

# Vérifier une liste de domaines
./certificate-renewal.sh check -l /etc/ssl/domains.txt
```

### Monitoring avec alertes

```bash
# Alerte si expiration < 30 jours
./certificate-renewal.sh check -d example.com -w 30 -m admin@example.com

# Seuils personnalisés
./certificate-renewal.sh check -l domains.txt -w 60 -c 14
```

### Renouvellement automatique

```bash
# Renouveler un certificat Let's Encrypt
./certificate-renewal.sh renew -d example.com -r nginx

# Renouveler tous les certificats
./certificate-renewal.sh renew -r nginx
```

### Rapport complet

```bash
# Générer un rapport de tous les certificats
./certificate-renewal.sh report -l domains.txt
```

## Exemple de Sortie

```text
=== Vérification des certificats ===

[OK] example.com - Expire dans 85 jours (Apr 15 12:00:00 2024 GMT)
[WARNING] api.example.com - Expire dans 21 jours (Jan 30 12:00:00 2024 GMT)
[CRITICAL] old.example.com - Expire dans 5 jours (Jan 14 12:00:00 2024 GMT)
```

## Intégration Cron

```bash
# Vérification quotidienne à 8h
0 8 * * * /opt/scripts/certificate-renewal.sh check -l /etc/ssl/domains.txt -m admin@example.com

# Renouvellement automatique 2x/jour (Let's Encrypt recommandé)
0 0,12 * * * /opt/scripts/certificate-renewal.sh renew -r nginx -q
```

## Voir Aussi

- [ssl-csr-wizard.sh](ssl-csr-wizard.md) - Génération de CSR
- [cert_checker.py](../python/cert_checker.md) - Version Python
- [Guide OpenSSL](../../security/openssl-cli.md)
