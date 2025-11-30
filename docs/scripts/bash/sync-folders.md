---
tags:
  - scripts
  - bash
  - fichiers
  - synchronisation
---

# sync-folders.sh

:material-star: **Niveau : Débutant**

Synchronisation de dossiers avec rsync.

---

## Description

Ce script synchronise des dossiers :
- Wrapper autour de rsync
- Modes de synchronisation configurables
- Prévisualisation avant exécution
- Support SSH pour synchronisation distante

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: sync-folders.sh
# Description: Synchronisation de dossiers avec rsync
# Author: ShellBook
# Version: 1.0
#===============================================================================

set -euo pipefail

# Couleurs
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Configuration
DRY_RUN=false
DELETE=false
VERBOSE=false
COMPRESS=false
EXCLUDE_FILE=""
SSH_PORT=22

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] SOURCE DESTINATION

Synchronisation de dossiers avec rsync.

Arguments:
    SOURCE          Dossier source (local ou user@host:path)
    DESTINATION     Dossier destination (local ou user@host:path)

Options:
    -d, --dry-run       Simulation sans modification
    --delete            Supprimer les fichiers absents de la source
    -v, --verbose       Mode verbeux
    -z, --compress      Compresser pendant le transfert
    -e, --exclude FILE  Fichier d'exclusions
    -p, --port NUM      Port SSH (défaut: 22)
    -h, --help          Affiche cette aide

Exemples:
    $(basename "$0") /home/user/docs /backup/docs
    $(basename "$0") -v --delete /var/www /backup/www
    $(basename "$0") /data user@server:/backup
    $(basename "$0") -d user@server:/data /local/backup
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
        printf "%.2fG" $(echo "scale=2; $bytes/1073741824" | bc)
    elif (( bytes >= 1048576 )); then
        printf "%.2fM" $(echo "scale=2; $bytes/1048576" | bc)
    elif (( bytes >= 1024 )); then
        printf "%.2fK" $(echo "scale=2; $bytes/1024" | bc)
    else
        printf "%dB" "$bytes"
    fi
}

is_remote() {
    [[ "$1" == *":"* ]]
}

build_rsync_options() {
    local opts="-a --progress --stats"

    [[ "$DRY_RUN" == "true" ]] && opts="$opts --dry-run"
    [[ "$DELETE" == "true" ]] && opts="$opts --delete"
    [[ "$VERBOSE" == "true" ]] && opts="$opts -v"
    [[ "$COMPRESS" == "true" ]] && opts="$opts -z"

    if [[ -n "$EXCLUDE_FILE" ]] && [[ -f "$EXCLUDE_FILE" ]]; then
        opts="$opts --exclude-from=$EXCLUDE_FILE"
    fi

    # SSH options si transfert distant
    if is_remote "$SOURCE" || is_remote "$DESTINATION"; then
        opts="$opts -e 'ssh -p $SSH_PORT'"
    fi

    echo "$opts"
}

get_dir_info() {
    local path=$1

    if is_remote "$path"; then
        # Pour chemins distants
        local host=${path%%:*}
        local remote_path=${path#*:}
        ssh -p "$SSH_PORT" "$host" "du -sb '$remote_path' 2>/dev/null" | awk '{print $1}' || echo "0"
    else
        if [[ -d "$path" ]]; then
            du -sb "$path" 2>/dev/null | awk '{print $1}' || echo "0"
        else
            echo "0"
        fi
    fi
}

main() {
    local SOURCE=""
    local DESTINATION=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            --delete)
                DELETE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -z|--compress)
                COMPRESS=true
                shift
                ;;
            -e|--exclude)
                EXCLUDE_FILE="$2"
                shift 2
                ;;
            -p|--port)
                SSH_PORT="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                log_error "Option inconnue: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$SOURCE" ]]; then
                    SOURCE="$1"
                elif [[ -z "$DESTINATION" ]]; then
                    DESTINATION="$1"
                fi
                shift
                ;;
        esac
    done

    # Validation
    if [[ -z "$SOURCE" ]] || [[ -z "$DESTINATION" ]]; then
        log_error "Source et destination requises"
        usage
        exit 1
    fi

    # Vérification source
    if ! is_remote "$SOURCE" && [[ ! -d "$SOURCE" ]]; then
        log_error "Source n'existe pas: $SOURCE"
        exit 1
    fi

    # Header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  SYNCHRONISATION DE DOSSIERS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  Source:      $SOURCE"
    echo -e "  Destination: $DESTINATION"
    echo -e "  Mode:        ${DRY_RUN:+SIMULATION}${DRY_RUN:-EXÉCUTION}"
    [[ "$DELETE" == "true" ]] && echo -e "  ${YELLOW}⚠ Delete mode activé${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────────${NC}"

    # Info sur la source
    if ! is_remote "$SOURCE"; then
        local source_size=$(get_dir_info "$SOURCE")
        log_info "Taille source: $(format_size $source_size)"
    fi

    # Construction options rsync
    local rsync_opts=$(build_rsync_options)

    if [[ "$DRY_RUN" == "true" ]]; then
        log_warn "Mode simulation - aucune modification ne sera effectuée"
    fi

    echo ""
    log_info "Démarrage de la synchronisation..."
    echo ""

    # Exécution rsync
    local start_time=$(date +%s)

    # S'assurer que la source a un / final pour synchroniser le contenu
    [[ "$SOURCE" != */ ]] && SOURCE="$SOURCE/"

    eval rsync $rsync_opts "$SOURCE" "$DESTINATION"

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Résumé
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Simulation terminée (aucune modification)"
    else
        log_info "Synchronisation terminée!"
    fi
    log_info "Durée: ${duration}s"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

main "$@"
```

---

## Utilisation

```bash
# Rendre exécutable
chmod +x sync-folders.sh

# Synchronisation locale
./sync-folders.sh /home/user/documents /backup/documents

# Avec suppression des fichiers absents
./sync-folders.sh --delete /var/www /backup/www

# Simulation d'abord
./sync-folders.sh -d --delete /data /backup

# Vers un serveur distant
./sync-folders.sh -z /home/user user@server:/backup

# Depuis un serveur distant
./sync-folders.sh user@server:/data /local/backup

# Avec exclusions
./sync-folders.sh -e exclude.txt /source /dest
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
  SYNCHRONISATION DE DOSSIERS
═══════════════════════════════════════════════════════════
  Source:      /home/user/documents/
  Destination: /backup/documents
  Mode:        EXÉCUTION
───────────────────────────────────────────────────────────
[INFO] Taille source: 2.34G
[INFO] Démarrage de la synchronisation...

sending incremental file list
./
document1.pdf
         12,456,789 100%   45.23MB/s    0:00:00 (xfr#1, to-chk=142/145)
document2.docx
          3,456,123 100%   12.45MB/s    0:00:00 (xfr#2, to-chk=141/145)
...

Number of files: 145 (reg: 138, dir: 7)
Number of created files: 5
Number of deleted files: 0
Number of regular files transferred: 8
Total file size: 2,456,789,123 bytes
Total transferred file size: 45,678,901 bytes
Literal data: 45,678,901 bytes
Matched data: 0 bytes
Total bytes sent: 45,789,012
Total bytes received: 1,234

═══════════════════════════════════════════════════════════
[INFO] Synchronisation terminée!
[INFO] Durée: 23s
═══════════════════════════════════════════════════════════
```

---

## Fichier d'Exclusion

Exemple de fichier `exclude.txt`:

```
# Fichiers temporaires
*.tmp
*.temp
*~
.*.swp

# Caches
.cache/
__pycache__/
node_modules/

# Fichiers système
.DS_Store
Thumbs.db

# Logs
*.log
logs/
```

---

## Voir Aussi

- [backup-directory.sh](backup-directory.md)
- [find-large-files.sh](find-large-files.md)
