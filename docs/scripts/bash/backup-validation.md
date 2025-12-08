---
tags:
  - scripts
  - bash
  - backup
  - validation
  - disaster-recovery
---

# backup-validation.sh

Script de validation d'intégrité des sauvegardes. Vérifie que vos backups sont exploitables avant qu'il ne soit trop tard.

## Cas d'Usage

- **Validation quotidienne** des sauvegardes nocturnes
- **Test de restauration** automatisé
- **Audit de conformité** (RPO/RTO)
- **Alerting** en cas de backup corrompu

## Prérequis

- Bash 4.0+
- `md5sum` ou `sha256sum`
- `tar`, `gzip` (selon format de backup)
- Accès en lecture au répertoire de backups

## Script

```bash
#!/bin/bash
#===============================================================================
# backup-validation.sh - Validation d'intégrité des sauvegardes
#
# Usage: ./backup-validation.sh [OPTIONS]
#   -d, --directory DIR    Répertoire des backups (défaut: /backup)
#   -a, --max-age HOURS    Âge maximum acceptable (défaut: 25h)
#   -s, --min-size SIZE    Taille minimum (défaut: 1M)
#   -t, --test-extract     Tester l'extraction (plus lent)
#   -m, --mail EMAIL       Envoyer rapport par email
#   -q, --quiet            Mode silencieux (exit code only)
#   -h, --help             Afficher l'aide
#===============================================================================

set -euo pipefail

# === CONFIGURATION ===
BACKUP_DIR="${BACKUP_DIR:-/backup}"
MAX_AGE_HOURS=25
MIN_SIZE="1M"
TEST_EXTRACT=false
MAIL_TO=""
QUIET=false
CHECKSUM_FILE=".checksums"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Compteurs
TOTAL=0
VALID=0
INVALID=0
WARNINGS=0

# === FONCTIONS ===

log() {
    [[ "$QUIET" == "true" ]] && return
    echo -e "$1"
}

log_ok() { log "${GREEN}[OK]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; ((WARNINGS++)); }
log_fail() { log "${RED}[FAIL]${NC} $1"; ((INVALID++)); }

usage() {
    grep '^#' "$0" | grep -v '#!/' | sed 's/^# //' | head -20
    exit 0
}

parse_size() {
    local size=$1
    case ${size: -1} in
        K|k) echo $((${size%?} * 1024)) ;;
        M|m) echo $((${size%?} * 1024 * 1024)) ;;
        G|g) echo $((${size%?} * 1024 * 1024 * 1024)) ;;
        *) echo "$size" ;;
    esac
}

check_age() {
    local file=$1
    local max_seconds=$((MAX_AGE_HOURS * 3600))
    local file_age=$(($(date +%s) - $(stat -c %Y "$file")))

    if [[ $file_age -gt $max_seconds ]]; then
        return 1
    fi
    return 0
}

check_size() {
    local file=$1
    local min_bytes=$(parse_size "$MIN_SIZE")
    local file_size=$(stat -c %s "$file")

    if [[ $file_size -lt $min_bytes ]]; then
        return 1
    fi
    return 0
}

check_integrity() {
    local file=$1
    local ext="${file##*.}"

    case "$ext" in
        gz|tgz)
            gzip -t "$file" 2>/dev/null
            ;;
        bz2)
            bzip2 -t "$file" 2>/dev/null
            ;;
        xz)
            xz -t "$file" 2>/dev/null
            ;;
        zip)
            unzip -t "$file" >/dev/null 2>&1
            ;;
        tar)
            tar -tf "$file" >/dev/null 2>&1
            ;;
        *)
            # Fichier non compressé, vérifier existence
            [[ -s "$file" ]]
            ;;
    esac
}

check_checksum() {
    local file=$1
    local checksum_file="$(dirname "$file")/$CHECKSUM_FILE"

    if [[ ! -f "$checksum_file" ]]; then
        return 2  # Pas de checksum disponible
    fi

    local filename=$(basename "$file")
    local expected=$(grep "$filename" "$checksum_file" 2>/dev/null | awk '{print $1}')

    if [[ -z "$expected" ]]; then
        return 2
    fi

    local actual=$(sha256sum "$file" | awk '{print $1}')
    [[ "$expected" == "$actual" ]]
}

test_extraction() {
    local file=$1
    local tmp_dir=$(mktemp -d)
    local result=0

    case "${file##*.}" in
        gz|tgz)
            tar -xzf "$file" -C "$tmp_dir" --one-top-level 2>/dev/null || result=1
            ;;
        tar)
            tar -xf "$file" -C "$tmp_dir" --one-top-level 2>/dev/null || result=1
            ;;
        zip)
            unzip -q "$file" -d "$tmp_dir" 2>/dev/null || result=1
            ;;
    esac

    rm -rf "$tmp_dir"
    return $result
}

validate_backup() {
    local file=$1
    local filename=$(basename "$file")
    ((TOTAL++))

    # 1. Vérifier l'âge
    if ! check_age "$file"; then
        log_fail "$filename - Trop ancien (>$MAX_AGE_HOURS heures)"
        return 1
    fi

    # 2. Vérifier la taille
    if ! check_size "$file"; then
        log_fail "$filename - Taille insuffisante (<$MIN_SIZE)"
        return 1
    fi

    # 3. Vérifier l'intégrité
    if ! check_integrity "$file"; then
        log_fail "$filename - Archive corrompue"
        return 1
    fi

    # 4. Vérifier le checksum (si disponible)
    check_checksum "$file"
    local checksum_result=$?
    if [[ $checksum_result -eq 1 ]]; then
        log_fail "$filename - Checksum invalide"
        return 1
    elif [[ $checksum_result -eq 2 ]]; then
        log_warn "$filename - Pas de checksum de référence"
    fi

    # 5. Test d'extraction (optionnel)
    if [[ "$TEST_EXTRACT" == "true" ]]; then
        if ! test_extraction "$file"; then
            log_fail "$filename - Échec extraction test"
            return 1
        fi
    fi

    log_ok "$filename - Valide ($(stat -c %s "$file" | numfmt --to=iec))"
    ((VALID++))
    return 0
}

generate_report() {
    local report=""
    report+="=== RAPPORT DE VALIDATION DES BACKUPS ===\n"
    report+="Date: $(date '+%Y-%m-%d %H:%M:%S')\n"
    report+="Répertoire: $BACKUP_DIR\n"
    report+="\n"
    report+="Total analysés: $TOTAL\n"
    report+="Valides: $VALID\n"
    report+="Invalides: $INVALID\n"
    report+="Warnings: $WARNINGS\n"
    report+="\n"

    if [[ $INVALID -gt 0 ]]; then
        report+="STATUT: ÉCHEC - $INVALID backup(s) invalide(s)\n"
    elif [[ $WARNINGS -gt 0 ]]; then
        report+="STATUT: WARNING - $WARNINGS avertissement(s)\n"
    else
        report+="STATUT: OK - Tous les backups sont valides\n"
    fi

    echo -e "$report"
}

send_mail() {
    local report=$1
    if command -v mail &>/dev/null; then
        echo -e "$report" | mail -s "[Backup] Rapport de validation - $(hostname)" "$MAIL_TO"
    elif command -v sendmail &>/dev/null; then
        echo -e "Subject: [Backup] Rapport de validation - $(hostname)\n\n$report" | sendmail "$MAIL_TO"
    else
        log_warn "Impossible d'envoyer l'email (mail/sendmail non trouvé)"
    fi
}

# === PARSING ARGUMENTS ===
while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--directory) BACKUP_DIR="$2"; shift 2 ;;
        -a|--max-age) MAX_AGE_HOURS="$2"; shift 2 ;;
        -s|--min-size) MIN_SIZE="$2"; shift 2 ;;
        -t|--test-extract) TEST_EXTRACT=true; shift ;;
        -m|--mail) MAIL_TO="$2"; shift 2 ;;
        -q|--quiet) QUIET=true; shift ;;
        -h|--help) usage ;;
        *) echo "Option inconnue: $1"; usage ;;
    esac
done

# === MAIN ===
log "=== Validation des backups : $BACKUP_DIR ===\n"

if [[ ! -d "$BACKUP_DIR" ]]; then
    log_fail "Répertoire inexistant: $BACKUP_DIR"
    exit 2
fi

# Trouver et valider les fichiers
shopt -s nullglob
for backup in "$BACKUP_DIR"/*.{tar,tar.gz,tgz,tar.bz2,tar.xz,zip,sql.gz,dump.gz}; do
    [[ -f "$backup" ]] && validate_backup "$backup"
done

# Générer le rapport
log ""
report=$(generate_report)
log "$report"

# Envoyer par mail si demandé
if [[ -n "$MAIL_TO" ]]; then
    send_mail "$report"
    log "Rapport envoyé à $MAIL_TO"
fi

# Exit code
if [[ $INVALID -gt 0 ]]; then
    exit 1
elif [[ $WARNINGS -gt 0 ]]; then
    exit 0  # Warnings ne sont pas bloquants
else
    exit 0
fi
```

## Exemples d'Utilisation

### Validation simple

```bash
# Valider les backups dans /backup
./backup-validation.sh -d /backup

# Avec test d'extraction
./backup-validation.sh -d /backup -t
```

### Validation avec alerting

```bash
# Envoyer un rapport par email
./backup-validation.sh -d /backup -m admin@example.com

# En cron (silencieux, alerte uniquement si erreur)
0 6 * * * /opt/scripts/backup-validation.sh -d /backup -q || mail -s "Backup FAIL" admin@example.com
```

### Critères personnalisés

```bash
# Backups de moins de 12h, minimum 100Mo
./backup-validation.sh -d /backup -a 12 -s 100M

# Test complet avec extraction
./backup-validation.sh -d /backup -a 25 -s 10M -t
```

## Exemple de Sortie

```
=== Validation des backups : /backup ===

[OK] db-daily-2024-01-15.sql.gz - Valide (245M)
[OK] files-daily-2024-01-15.tar.gz - Valide (1.2G)
[WARN] config-backup.tar.gz - Pas de checksum de référence
[FAIL] old-backup.tar.gz - Trop ancien (>25 heures)

=== RAPPORT DE VALIDATION DES BACKUPS ===
Date: 2024-01-15 08:00:01
Répertoire: /backup

Total analysés: 4
Valides: 2
Invalides: 1
Warnings: 1

STATUT: ÉCHEC - 1 backup(s) invalide(s)
```

## Intégration

### Fichier de checksums

Créez un fichier `.checksums` dans le répertoire de backup :

```bash
# Générer les checksums après backup
sha256sum /backup/*.tar.gz > /backup/.checksums
```

### Systemd Timer

```ini
# /etc/systemd/system/backup-validation.timer
[Unit]
Description=Validation quotidienne des backups

[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

## Voir Aussi

- [backup_validator.py](../python/backup_validator.md) - Version Python avancée
- [backup-directory.sh](backup-directory.md) - Création de backups
