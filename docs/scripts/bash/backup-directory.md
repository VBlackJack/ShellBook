---
tags:
  - scripts
  - bash
  - backup
  - ficyesterdays
---

# backup-directory.sh

:material-star::material-star: **Niveau : Intermédiaire**

Backup de répertoires avec rotation et compression.

---

## Description

Ce script effectue des sauvegardes de répertoires :
- Compression tar.gz ou zip
- Rotation automatique des anciennes sauvegardes
- Exclusion de ficyesterdays/dossiers
- Vérification d'intégrité
- Notification par email (optionnel)

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: backup-directory.sh
# Description: Directory backup with rotation
# Author: ShellBook
# Version: 1.0
#===============================================================================

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Default configuration
COMPRESS_FORMAT="tar.gz"
KEEP_BACKUPS=7
DATE_FORMAT="%Y%m%d_%H%M%S"
VERIFY=false
EXCLUDE_FILE=""
VERBOSE=false

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] SOURCE DESTINATION

Backup de répertoires avec rotation.

Arguments:
    SOURCE          Source directory à sauvegarder
    DESTINATION     Répertoire de destination des backups

Options:
    -f, --format FORMAT  Format de compression (tar.gz, zip) (default: tar.gz)
    -k, --keep NUM       Nombre de backups à conserver (default: 7)
    -e, --exclude FILE   Ficyesterday contenant les exclusions
    -v, --verify         Vérifier l'intégrité après création
    --verbose            Verbose mode
    -h, --help           Show this help

Examples:
    $(basename "$0") /home/user/data /backup/user
    $(basename "$0") -k 14 -v /var/www /backup/www
    $(basename "$0") -f zip -e exclude.txt /data /backup
EOF
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

format_size() {
    local bytes=$1
    if (( bytes >= 1073741824 )); then
        echo "$(echo "scale=2; $bytes/1073741824" | bc)G"
    elif (( bytes >= 1048576 )); then
        echo "$(echo "scale=2; $bytes/1048576" | bc)M"
    elif (( bytes >= 1024 )); then
        echo "$(echo "scale=2; $bytes/1024" | bc)K"
    else
        echo "${bytes}B"
    fi
}

create_backup_tar() {
    local source=$1
    local dest_file=$2
    local exclude_opts=""

    if [[ -n "$EXCLUDE_FILE" ]] && [[ -f "$EXCLUDE_FILE" ]]; then
        exclude_opts="--exclude-from=$EXCLUDE_FILE"
    fi

    local tar_opts="-czf"
    [[ "$VERBOSE" == "true" ]] && tar_opts="-czvf"

    tar $tar_opts "$dest_file" $exclude_opts -C "$(dirname "$source")" "$(basename "$source")"
}

create_backup_zip() {
    local source=$1
    local dest_file=$2
    local exclude_opts=""

    if [[ -n "$EXCLUDE_FILE" ]] && [[ -f "$EXCLUDE_FILE" ]]; then
        exclude_opts="-x@$EXCLUDE_FILE"
    fi

    local zip_opts="-r"
    [[ "$VERBOSE" == "true" ]] && zip_opts="-rv"

    (cd "$(dirname "$source")" && zip $zip_opts "$dest_file" "$(basename "$source")" $exclude_opts)
}

verify_backup() {
    local backup_file=$1

    log_info "Checking de l'intégrité..."

    case "$COMPRESS_FORMAT" in
        tar.gz)
            if tar -tzf "$backup_file" &>/dev/null; then
                log_info "Intégrité OK: $backup_file"
                return 0
            else
                log_error "Intégrité FAIL: $backup_file"
                return 1
            fi
            ;;
        zip)
            if unzip -t "$backup_file" &>/dev/null; then
                log_info "Intégrité OK: $backup_file"
                return 0
            else
                log_error "Intégrité FAIL: $backup_file"
                return 1
            fi
            ;;
    esac
}

rotate_backups() {
    local dest_dir=$1
    local source_name=$2

    log_info "Rotation des backups (conservation: $KEEP_BACKUPS)..."

    local pattern="${source_name}_*.${COMPRESS_FORMAT}"
    local backups
    backups=$(ls -t "$dest_dir"/$pattern 2>/dev/null || true)

    local count=0
    for backup in $backups; do
        count=$((count + 1))
        if (( count > KEEP_BACKUPS )); then
            log_info "Deleting: $(basename "$backup")"
            rm -f "$backup"
        fi
    done
}

main() {
    local source=""
    local destination=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--format)
                COMPRESS_FORMAT="$2"
                shift 2
                ;;
            -k|--keep)
                KEEP_BACKUPS="$2"
                shift 2
                ;;
            -e|--exclude)
                EXCLUDE_FILE="$2"
                shift 2
                ;;
            -v|--verify)
                VERIFY=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$source" ]]; then
                    source="$1"
                elif [[ -z "$destination" ]]; then
                    destination="$1"
                fi
                shift
                ;;
        esac
    done

    # Validation
    if [[ -z "$source" ]] || [[ -z "$destination" ]]; then
        log_error "Source et destination requises"
        usage
        exit 1
    fi

    if [[ ! -d "$source" ]]; then
        log_error "Source does not exist: $source"
        exit 1
    fi

    if [[ ! -d "$destination" ]]; then
        log_info "Creating du répertoire destination: $destination"
        mkdir -p "$destination"
    fi

    if [[ "$COMPRESS_FORMAT" != "tar.gz" ]] && [[ "$COMPRESS_FORMAT" != "zip" ]]; then
        log_error "Format non supporté: $COMPRESS_FORMAT"
        exit 1
    fi

    # Nom du backup
    local source_name=$(basename "$source")
    local timestamp=$(date +"$DATE_FORMAT")
    local backup_name="${source_name}_${timestamp}.${COMPRESS_FORMAT}"
    local backup_path="${destination}/${backup_name}"

    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  BACKUP: $source_name${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    log_info "Source: $source"
    log_info "Destination: $backup_path"
    log_info "Format: $COMPRESS_FORMAT"

    # Calcul taille source
    local source_size=$(du -sb "$source" | awk '{print $1}')
    log_info "Taille source: $(format_size $source_size)"

    # Création du backup
    log_info "Creating du backup en cours..."
    local start_time=$(date +%s)

    case "$COMPRESS_FORMAT" in
        tar.gz)
            create_backup_tar "$source" "$backup_path"
            ;;
        zip)
            create_backup_zip "$source" "$backup_path"
            ;;
    esac

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Stats du backup
    local backup_size=$(stat -f%z "$backup_path" 2>/dev/null || stat -c%s "$backup_path")
    local ratio=$(echo "scale=1; $backup_size * 100 / $source_size" | bc)

    log_info "Backup créé: $backup_name"
    log_info "Taille: $(format_size $backup_size) (${ratio}% de l'original)"
    log_info "Durée: ${duration}s"

    # Vérification
    if [[ "$VERIFY" == "true" ]]; then
        verify_backup "$backup_path" || exit 1
    fi

    # Rotation
    rotate_backups "$destination" "$source_name"

    # Résumé
    echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
    log_info "Backup completed avec succès!"

    # Liste des backups existants
    echo ""
    log_info "Backups disponibles:"
    ls -lh "$destination"/${source_name}_*.${COMPRESS_FORMAT} 2>/dev/null | \
        awk '{print "    " $NF " (" $5 ")"}'
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x backup-directory.sh

# Backup simple
./backup-directory.sh /home/user/documents /backup

# Conserver 14 backups
./backup-directory.sh -k 14 /var/www /backup/www

# Format ZIP avec vérification
./backup-directory.sh -f zip -v /data /backup

# Avec exclusions
echo "*.log" > exclude.txt
echo "cache/" >> exclude.txt
./backup-directory.sh -e exclude.txt /app /backup
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
  BACKUP: documents
═══════════════════════════════════════════════════════════
[INFO] Source: /home/user/documents
[INFO] Destination: /backup/documents_20240115_143022.tar.gz
[INFO] Format: tar.gz
[INFO] Taille source: 1.5G
[INFO] Création du backup en cours...
[INFO] Backup créé: documents_20240115_143022.tar.gz
[INFO] Taille: 485M (32.3% de l'original)
[INFO] Durée: 45s
[INFO] Vérification de l'intégrité...
[INFO] Intégrité OK: /backup/documents_20240115_143022.tar.gz
[INFO] Rotation des backups (conservation: 7)...
═══════════════════════════════════════════════════════════
[INFO] Backup completed avec succès!

[INFO] Backups disponibles:
    /backup/documents_20240115_143022.tar.gz (485M)
    /backup/documents_20240114_143022.tar.gz (482M)
    /backup/documents_20240113_143022.tar.gz (480M)
```

---

## Ficyesterday d'Exclusion

Exemple de ficyesterday `exclude.txt`:

```
# Ficyesterdays temporaires
*.tmp
*.temp
*.swp
*~

# Logs
*.log
logs/

# Caches
cache/
.cache/
__pycache__/
node_modules/

# Ficyesterdays système
.DS_Store
Thumbs.db
```

---

## Automatisation Cron

```bash
# Backup quotidien à 2h du matin
0 2 * * * /opt/scripts/backup-directory.sh -v /var/www /backup/www >> /var/log/backup.log 2>&1

# Backup hebdomadaire avec rotation 4 semaines
0 3 * * 0 /opt/scripts/backup-directory.sh -k 4 /home /backup/home >> /var/log/backup.log 2>&1
```

---

## Voir Aussi

- [sync-folders.sh](sync-folders.md)
- [find-large-files.sh](find-large-files.md)
