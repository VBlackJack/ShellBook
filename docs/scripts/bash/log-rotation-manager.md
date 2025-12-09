---
tags:
  - scripts
  - bash
  - logs
  - rotation
  - maintenance
---

# log-rotation-manager.sh

:material-star::material-star: **Niveau : Intermédiaire**

Gestion intelligente de la rotation des logs avec compression et archivage.

---

## Description

Ce script gère le cycle de vie complet des logs :
- Rotation basée sur taille ou âge
- Compression automatique (gzip/zstd)
- Archivage vers stockage distant (S3/NFS)
- Nettoyage des anciens logs
- Support multi-répertoires
- Mode dry-run pour prévisualisation
- Rapport d'espace récupéré

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Droits d'écriture sur les répertoires de logs à gérer
- **Dépendances** : `gzip` ou `zstd`, `aws-cli` (pour archivage S3), `bc`

---

## Cas d'Usage

- **Gestion automatisée des logs** : Rotation, compression et archivage sans intervention manuelle
- **Optimisation d'espace disque** : Compression et nettoyage régulier pour libérer de l'espace
- **Archivage long terme** : Transfert automatique vers stockage froid (S3, NFS) pour conformité
- **Complémentation logrotate** : Ajout de fonctionnalités avancées (archivage S3, multi-répertoires)

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: log-rotation-manager.sh
# Description: Intelligent log rotation with compression and archival
# Author: ShellBook
# Version: 1.0
#===============================================================================

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Default configuration
DRY_RUN=false
VERBOSE=false
COMPRESS_METHOD="gzip"
COMPRESS_EXT="gz"
ROTATE_SIZE="100M"
ROTATE_AGE=7
KEEP_ROTATED=4
ARCHIVE_DIR=""
ARCHIVE_S3=""

# Statistics
TOTAL_ORIGINAL=0
TOTAL_COMPRESSED=0
FILES_ROTATED=0
FILES_DELETED=0

usage() {
    cat << 'EOF'
Usage: log-rotation-manager.sh [OPTIONS] DIR [DIR...]

Intelligent log rotation with compression and archival.

Options:
    -d, --dry-run           Dry-run mode (no changes)
    -v, --verbose           Verbose output
    -s, --size SIZE         Rotate files larger than SIZE (default: 100M)
    -a, --age DAYS          Rotate files older than DAYS (default: 7)
    -k, --keep NUM          Keep NUM rotated versions (default: 4)
    -c, --compress METHOD   Compression: gzip|zstd|none (default: gzip)
    -A, --archive DIR       Archive to local directory
    -S, --s3 BUCKET         Archive to S3 bucket
    -p, --pattern PATTERN   File pattern to match (default: *.log)
    -h, --help              Show this help

Size suffixes: K (KB), M (MB), G (GB)

Examples:
    # Rotate logs in /var/log/myapp
    log-rotation-manager.sh /var/log/myapp

    # Dry-run with verbose output
    log-rotation-manager.sh -d -v /var/log/myapp

    # Rotate files > 50MB, keep 7 versions
    log-rotation-manager.sh -s 50M -k 7 /var/log/myapp

    # Use zstd compression and archive
    log-rotation-manager.sh -c zstd -A /archive/logs /var/log/myapp

    # Multiple directories
    log-rotation-manager.sh /var/log/nginx /var/log/apache2 /var/log/mysql
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

log_action() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${CYAN}[DRY-RUN]${NC} $1"
    else
        [[ "$VERBOSE" == "true" ]] && echo -e "${GREEN}[ACTION]${NC} $1"
    fi
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

parse_size() {
    local size="$1"
    local num="${size%[KMGkmg]}"
    local suffix="${size: -1}"

    case "$suffix" in
        K|k) echo $((num * 1024)) ;;
        M|m) echo $((num * 1048576)) ;;
        G|g) echo $((num * 1073741824)) ;;
        *)   echo "$size" ;;
    esac
}

get_file_size() {
    stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null || echo 0
}

get_file_age_days() {
    local file="$1"
    local now mtime
    now=$(date +%s)
    mtime=$(stat -f%m "$file" 2>/dev/null || stat -c%Y "$file" 2>/dev/null || echo "$now")
    echo $(( (now - mtime) / 86400 ))
}

compress_file() {
    local file="$1"
    local original_size
    original_size=$(get_file_size "$file")

    case "$COMPRESS_METHOD" in
        gzip)
            if [[ "$DRY_RUN" == "true" ]]; then
                log_action "Would compress: $file"
            else
                gzip -9 "$file"
            fi
            ;;
        zstd)
            if [[ "$DRY_RUN" == "true" ]]; then
                log_action "Would compress: $file"
            else
                zstd -19 --rm "$file"
            fi
            ;;
        none)
            log_action "Skipping compression for: $file"
            return
            ;;
    esac

    TOTAL_ORIGINAL=$((TOTAL_ORIGINAL + original_size))

    if [[ "$DRY_RUN" != "true" ]]; then
        local compressed_size
        compressed_size=$(get_file_size "${file}.${COMPRESS_EXT}")
        TOTAL_COMPRESSED=$((TOTAL_COMPRESSED + compressed_size))

        if [[ "$VERBOSE" == "true" ]]; then
            local ratio
            ratio=$(echo "scale=1; $compressed_size * 100 / $original_size" | bc)
            log_info "Compressed: $(format_size $original_size) -> $(format_size $compressed_size) (${ratio}%)"
        fi
    fi
}

rotate_file() {
    local file="$1"
    local basename="${file##*/}"
    local dirname="${file%/*}"
    local timestamp
    timestamp=$(date +%Y%m%d_%H%M%S)

    local rotated_name="${file}.${timestamp}"

    log_action "Rotating: $file -> ${rotated_name}"

    if [[ "$DRY_RUN" != "true" ]]; then
        mv "$file" "$rotated_name"
        FILES_ROTATED=$((FILES_ROTATED + 1))

        # Create empty file to replace
        touch "$file"
        chmod --reference="${rotated_name}" "$file" 2>/dev/null || true

        # Compress rotated file
        if [[ "$COMPRESS_METHOD" != "none" ]]; then
            compress_file "$rotated_name"
        fi

        # Signal app to reopen logs (if it's a known service)
        signal_log_reopen "$file"
    fi
}

signal_log_reopen() {
    local file="$1"

    # Try to signal common services to reopen their logs
    case "$file" in
        */nginx/*)
            [[ "$DRY_RUN" != "true" ]] && nginx -s reopen 2>/dev/null || true
            ;;
        */apache2/*|*/httpd/*)
            [[ "$DRY_RUN" != "true" ]] && apachectl graceful 2>/dev/null || true
            ;;
        */mysql/*)
            # MySQL flush logs via mysqladmin
            [[ "$DRY_RUN" != "true" ]] && mysqladmin flush-logs 2>/dev/null || true
            ;;
    esac
}

cleanup_old_rotated() {
    local dir="$1"
    local pattern="$2"

    # Find rotated files (with timestamp suffix)
    local rotated_pattern="${pattern%.log}*.log.[0-9]*"

    # Group by base name and keep only KEEP_ROTATED versions
    local base_files
    base_files=$(find "$dir" -maxdepth 1 -name "$pattern" -type f 2>/dev/null | sort -u)

    for base_file in $base_files; do
        local base_name="${base_file##*/}"

        # Find all rotated versions
        local rotated
        rotated=$(find "$dir" -maxdepth 1 -name "${base_name}.*" -type f 2>/dev/null | \
                  grep -E '\.[0-9]{8}_[0-9]{6}' | sort -r)

        # Skip if nothing to cleanup
        [[ -z "$rotated" ]] && continue

        # Delete old versions beyond KEEP_ROTATED
        local count=0
        echo "$rotated" | while read -r rotated_file; do
            count=$((count + 1))
            if [[ $count -gt $KEEP_ROTATED ]]; then
                local size
                size=$(get_file_size "$rotated_file")

                log_action "Deleting old: $rotated_file ($(format_size $size))"

                if [[ "$DRY_RUN" != "true" ]]; then
                    rm -f "$rotated_file"
                    FILES_DELETED=$((FILES_DELETED + 1))
                fi
            fi
        done
    done
}

archive_rotated() {
    local dir="$1"
    local pattern="$2"

    # Find compressed rotated files older than 1 day
    local rotated
    rotated=$(find "$dir" -maxdepth 1 -name "*.${COMPRESS_EXT}" -type f -mtime +1 2>/dev/null || true)

    [[ -z "$rotated" ]] && return

    echo "$rotated" | while read -r file; do
        [[ -z "$file" ]] && continue

        # Archive to local directory
        if [[ -n "$ARCHIVE_DIR" ]]; then
            local archive_subdir="$ARCHIVE_DIR/$(date +%Y/%m)"

            if [[ "$DRY_RUN" != "true" ]]; then
                mkdir -p "$archive_subdir"
                mv "$file" "$archive_subdir/"
                log_action "Archived to: $archive_subdir/${file##*/}"
            else
                log_action "Would archive: $file -> $archive_subdir/"
            fi
        fi

        # Archive to S3
        if [[ -n "$ARCHIVE_S3" ]]; then
            local s3_path="s3://${ARCHIVE_S3}/$(date +%Y/%m)/${file##*/}"

            if [[ "$DRY_RUN" != "true" ]]; then
                if command -v aws &>/dev/null; then
                    aws s3 cp "$file" "$s3_path" --storage-class STANDARD_IA
                    rm -f "$file"
                    log_action "Archived to: $s3_path"
                else
                    log_warn "AWS CLI not found, skipping S3 archive"
                fi
            else
                log_action "Would archive: $file -> $s3_path"
            fi
        fi
    done
}

process_directory() {
    local dir="$1"
    local pattern="${2:-*.log}"

    if [[ ! -d "$dir" ]]; then
        log_error "Directory not found: $dir"
        return 1
    fi

    log_info "Processing: $dir (pattern: $pattern)"

    local size_threshold
    size_threshold=$(parse_size "$ROTATE_SIZE")

    # Find matching files
    local files
    files=$(find "$dir" -maxdepth 1 -name "$pattern" -type f 2>/dev/null || true)

    [[ -z "$files" ]] && {
        log_warn "No files matching pattern in $dir"
        return 0
    }

    echo "$files" | while read -r file; do
        [[ -z "$file" ]] && continue
        [[ ! -f "$file" ]] && continue

        # Skip already rotated files
        [[ "$file" =~ \.[0-9]{8}_[0-9]{6} ]] && continue
        [[ "$file" =~ \.(gz|zst)$ ]] && continue

        local file_size file_age
        file_size=$(get_file_size "$file")
        file_age=$(get_file_age_days "$file")

        local should_rotate=false
        local reason=""

        # Check size threshold
        if [[ $file_size -gt $size_threshold ]]; then
            should_rotate=true
            reason="size $(format_size $file_size) > $(format_size $size_threshold)"
        fi

        # Check age threshold
        if [[ $file_age -gt $ROTATE_AGE ]]; then
            should_rotate=true
            reason="${reason:+$reason, }age ${file_age}d > ${ROTATE_AGE}d"
        fi

        if [[ "$should_rotate" == "true" ]]; then
            [[ "$VERBOSE" == "true" ]] && log_info "Rotating ${file##*/}: $reason"
            rotate_file "$file"
        fi
    done

    # Cleanup old rotated files
    cleanup_old_rotated "$dir" "$pattern"

    # Archive old compressed files
    if [[ -n "$ARCHIVE_DIR" ]] || [[ -n "$ARCHIVE_S3" ]]; then
        archive_rotated "$dir" "$pattern"
    fi
}

show_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  LOG ROTATION SUMMARY${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  Mode: ${YELLOW}DRY-RUN${NC}"
    else
        echo -e "  Mode: ${GREEN}EXECUTED${NC}"
    fi

    echo ""
    echo "  Files Rotated: $FILES_ROTATED"
    echo "  Files Deleted: $FILES_DELETED"

    if [[ $TOTAL_ORIGINAL -gt 0 ]]; then
        local saved=$((TOTAL_ORIGINAL - TOTAL_COMPRESSED))
        local ratio
        ratio=$(echo "scale=1; $TOTAL_COMPRESSED * 100 / $TOTAL_ORIGINAL" | bc)

        echo ""
        echo "  Compression:"
        echo "    Original:   $(format_size $TOTAL_ORIGINAL)"
        echo "    Compressed: $(format_size $TOTAL_COMPRESSED)"
        echo "    Saved:      $(format_size $saved) (${ratio}% ratio)"
    fi

    echo ""
    echo "  Current disk usage:"
    df -h / | tail -1 | awk '{printf "    Used: %s / %s (%s)\n", $3, $2, $5}'

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

main() {
    local directories=()
    local pattern="*.log"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -s|--size)
                ROTATE_SIZE="$2"
                shift 2
                ;;
            -a|--age)
                ROTATE_AGE="$2"
                shift 2
                ;;
            -k|--keep)
                KEEP_ROTATED="$2"
                shift 2
                ;;
            -c|--compress)
                COMPRESS_METHOD="$2"
                case "$COMPRESS_METHOD" in
                    gzip) COMPRESS_EXT="gz" ;;
                    zstd) COMPRESS_EXT="zst" ;;
                    none) COMPRESS_EXT="" ;;
                    *)
                        log_error "Unknown compression: $COMPRESS_METHOD"
                        exit 1
                        ;;
                esac
                shift 2
                ;;
            -A|--archive)
                ARCHIVE_DIR="$2"
                shift 2
                ;;
            -S|--s3)
                ARCHIVE_S3="$2"
                shift 2
                ;;
            -p|--pattern)
                pattern="$2"
                shift 2
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
                directories+=("$1")
                shift
                ;;
        esac
    done

    if [[ ${#directories[@]} -eq 0 ]]; then
        log_error "No directories specified"
        usage
        exit 1
    fi

    # Banner
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  LOG ROTATION MANAGER${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${YELLOW}Dry-run mode enabled${NC}"
    fi
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    # Process each directory
    for dir in "${directories[@]}"; do
        process_directory "$dir" "$pattern"
    done

    show_summary
}

main "$@"
```

---

## Utilisation

```bash
# Rendre exécutable
chmod +x log-rotation-manager.sh

# Rotation basique
./log-rotation-manager.sh /var/log/myapp

# Dry-run avec verbose
./log-rotation-manager.sh -d -v /var/log/myapp

# Rotation si fichier > 50MB ou > 3 jours
./log-rotation-manager.sh -s 50M -a 3 /var/log/myapp

# Garder 7 versions, compression zstd
./log-rotation-manager.sh -k 7 -c zstd /var/log/myapp

# Archiver vers répertoire local
./log-rotation-manager.sh -A /archive/logs /var/log/myapp

# Archiver vers S3
./log-rotation-manager.sh -S mybucket/logs /var/log/myapp

# Pattern personnalisé
./log-rotation-manager.sh -p "access*.log" /var/log/nginx

# Plusieurs répertoires
./log-rotation-manager.sh /var/log/nginx /var/log/apache2 /var/log/mysql
```

---

## Sortie Exemple

```text
═══════════════════════════════════════════════════════════
  LOG ROTATION MANAGER
  Dry-run mode enabled
═══════════════════════════════════════════════════════════

[INFO] Processing: /var/log/myapp (pattern: *.log)
[INFO] Rotating app.log: size 256M > 100M
[DRY-RUN] Rotating: /var/log/myapp/app.log -> /var/log/myapp/app.log.20240115_143022
[DRY-RUN] Would compress: /var/log/myapp/app.log.20240115_143022
[DRY-RUN] Deleting old: /var/log/myapp/app.log.20240108_020015.gz (45M)

[INFO] Processing: /var/log/nginx (pattern: *.log)
[INFO] Rotating access.log: age 8d > 7d
[DRY-RUN] Rotating: /var/log/nginx/access.log -> /var/log/nginx/access.log.20240115_143022

═══════════════════════════════════════════════════════════
  LOG ROTATION SUMMARY
═══════════════════════════════════════════════════════════
  Mode: DRY-RUN

  Files Rotated: 2
  Files Deleted: 1

  Compression:
    Original:   301M
    Compressed: 45M
    Saved:      256M (15.0% ratio)

  Current disk usage:
    Used: 22G / 50G (44%)
═══════════════════════════════════════════════════════════
```

---

## Automatisation Cron

```bash
# Rotation quotidienne à 3h
0 3 * * * /opt/scripts/log-rotation-manager.sh -s 100M -k 7 -A /archive/logs /var/log/myapp >> /var/log/log-rotation.log 2>&1

# Rotation hebdomadaire des logs nginx
0 4 * * 0 /opt/scripts/log-rotation-manager.sh -a 7 -k 4 -c zstd /var/log/nginx >> /var/log/log-rotation.log 2>&1

# Rotation multi-applications
0 3 * * * /opt/scripts/log-rotation-manager.sh -s 50M -a 3 -k 10 \
    /var/log/nginx \
    /var/log/apache2 \
    /var/log/mysql \
    /var/log/postgresql \
    >> /var/log/log-rotation.log 2>&1
```

---

## Intégration avec Logrotate

Ce script peut compléter logrotate pour des cas spécifiques :

```bash
# /etc/logrotate.d/custom-apps
/var/log/myapp/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    postrotate
        # Notification custom ou actions supplémentaires
        /opt/scripts/log-rotation-manager.sh --archive-only /var/log/myapp
    endscript
}
```

---

## Voir Aussi

- [cleanup-system.sh](cleanup-system.md)
- [logrotate-builder.sh](logrotate-builder.md)
- [logs-extractor.sh](logs-extractor.md)
