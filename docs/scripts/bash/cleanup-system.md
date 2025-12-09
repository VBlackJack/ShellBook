---
tags:
  - scripts
  - bash
  - système
  - maintenance
  - nettoyage
---

# cleanup-system.sh

:material-star::material-star: **Niveau : Intermédiaire**

Nettoyage système automatisé avec gestion des logs et caches.

---

## Description

Ce script effectue un nettoyage complet du système :
- Suppression des ficyesterdays temporaires
- Nettoyage des anciens logs
- Purge des caches package manager
- Nettoyage des kernels obsolètes (optionnel)
- Mode dry-run pour prévisualisation

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Droits root ou sudo pour nettoyage complet du système
- **Dépendances** : `du`, `find`, `bc`, package manager (`apt`, `yum`, `dnf`, ou `pacman`)

---

## Cas d'Usage

- **Maintenance hebdomadaire** : Nettoyage automatisé via cron pour libérer de l'espace disque
- **Libération d'espace urgente** : Récupération rapide d'espace lors de saturation disque
- **Nettoyage post-upgrade** : Suppression des anciens kernels et caches après mise à jour système
- **Automatisation serveurs** : Intégration dans playbooks Ansible pour maintenance de parc

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: cleanup-system.sh
# Description: Automated system cleanup
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

# Configuration
DRY_RUN=false
VERBOSE=false
CLEAN_LOGS=true
CLEAN_TEMP=true
CLEAN_CACHE=true
CLEAN_KERNELS=false
LOG_DAYS=30
TEMP_DAYS=7

# Counters
SPACE_FREED=0

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Automated system cleanup.

Options:
    -d, --dry-run        Dry-run mode (no deletion)
    -v, --verbose        Verbose mode
    --no-logs            Skip log cleanup
    --no-temp            Skip temp files cleanup
    --no-cache           Skip cache cleanup
    -k, --kernels        Clean old kernels
    --log-days NUM       Max age for logs (default: 30)
    --temp-days NUM      Max age for temp files (default: 7)
    -h, --help           Show this help

Examples:
    $(basename "$0")              # Standard cleanup
    $(basename "$0") -d           # Dry-run simulation
    $(basename "$0") -v -k        # Verbose + kernels
    $(basename "$0") --log-days 7 # Logs > 7 days
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
        echo -e "${GREEN}[ACTION]${NC} $1"
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

get_dir_size() {
    local dir=$1
    if [[ -d "$dir" ]]; then
        du -sb "$dir" 2>/dev/null | awk '{print $1}' || echo 0
    else
        echo 0
    fi
}

clean_temp_files() {
    log_info "Cleaning temporary files (> ${TEMP_DAYS} days)..."

    local dirs=("/tmp" "/var/tmp")

    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local size_before=$(get_dir_size "$dir")

            if [[ "$DRY_RUN" == "true" ]]; then
                local count=$(find "$dir" -type f -atime +${TEMP_DAYS} 2>/dev/null | wc -l)
                log_action "Would delete $count files in $dir"
            else
                find "$dir" -type f -atime +${TEMP_DAYS} -delete 2>/dev/null || true
                find "$dir" -type d -empty -delete 2>/dev/null || true
            fi

            local size_after=$(get_dir_size "$dir")
            local freed=$((size_before - size_after))
            SPACE_FREED=$((SPACE_FREED + freed))

            [[ "$VERBOSE" == "true" ]] && log_info "  $dir: $(format_size $freed) freed"
        fi
    done
}

clean_log_files() {
    log_info "Cleaning old logs (> ${LOG_DAYS} days)..."

    local log_dir="/var/log"
    local size_before=$(get_dir_size "$log_dir")

    if [[ "$DRY_RUN" == "true" ]]; then
        # Old .log files
        local count=$(find "$log_dir" -name "*.log" -type f -mtime +${LOG_DAYS} 2>/dev/null | wc -l)
        log_action "Would delete $count old .log files"

        # .gz files
        count=$(find "$log_dir" -name "*.gz" -type f -mtime +${LOG_DAYS} 2>/dev/null | wc -l)
        log_action "Would delete $count old .gz files"

        # Systemd journals
        if command -v journalctl &>/dev/null; then
            log_action "Would clean systemd journals > ${LOG_DAYS} days"
        fi
    else
        # Delete old logs
        find "$log_dir" -name "*.log" -type f -mtime +${LOG_DAYS} -delete 2>/dev/null || true
        find "$log_dir" -name "*.log.[0-9]*" -type f -mtime +${LOG_DAYS} -delete 2>/dev/null || true
        find "$log_dir" -name "*.gz" -type f -mtime +${LOG_DAYS} -delete 2>/dev/null || true

        # Clean journald
        if command -v journalctl &>/dev/null; then
            journalctl --vacuum-time=${LOG_DAYS}d 2>/dev/null || true
        fi
    fi

    local size_after=$(get_dir_size "$log_dir")
    local freed=$((size_before - size_after))
    SPACE_FREED=$((SPACE_FREED + freed))

    [[ "$VERBOSE" == "true" ]] && log_info "  Logs: $(format_size $freed) freed"
}

clean_package_cache() {
    log_info "Cleaning package manager caches..."

    # APT (Debian/Ubuntu)
    if command -v apt-get &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_action "apt-get clean"
            log_action "apt-get autoremove"
        else
            apt-get clean 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
        fi
        [[ "$VERBOSE" == "true" ]] && log_info "  APT cache cleaned"
    fi

    # YUM/DNF (RHEL/CentOS/Fedora)
    if command -v dnf &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_action "dnf clean all"
        else
            dnf clean all 2>/dev/null || true
        fi
        [[ "$VERBOSE" == "true" ]] && log_info "  DNF cache cleaned"
    elif command -v yum &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_action "yum clean all"
        else
            yum clean all 2>/dev/null || true
        fi
        [[ "$VERBOSE" == "true" ]] && log_info "  YUM cache cleaned"
    fi

    # Pacman (Arch)
    if command -v pacman &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_action "pacman -Sc"
        else
            pacman -Sc --noconfirm 2>/dev/null || true
        fi
        [[ "$VERBOSE" == "true" ]] && log_info "  Pacman cache cleaned"
    fi
}

clean_user_caches() {
    log_info "Cleaning user caches..."

    local cache_dirs=(
        "/root/.cache"
        "/home/*/.cache/thumbnails"
        "/home/*/.cache/pip"
        "/home/*/.npm/_cacache"
    )

    for pattern in "${cache_dirs[@]}"; do
        for dir in $pattern; do
            if [[ -d "$dir" ]]; then
                local size_before=$(get_dir_size "$dir")

                if [[ "$DRY_RUN" == "true" ]]; then
                    log_action "Would clean $dir ($(format_size $size_before))"
                else
                    rm -rf "$dir"/* 2>/dev/null || true
                fi

                SPACE_FREED=$((SPACE_FREED + size_before))
            fi
        done
    done
}

clean_old_kernels() {
    log_info "Cleaning old kernels..."

    if command -v apt-get &>/dev/null; then
        local current_kernel=$(uname -r)
        local old_kernels=$(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -v "$current_kernel" | grep -v 'linux-image-generic' || true)

        if [[ -n "$old_kernels" ]]; then
            if [[ "$DRY_RUN" == "true" ]]; then
                log_action "Would remove kernels: $old_kernels"
            else
                echo "$old_kernels" | xargs apt-get remove -y 2>/dev/null || true
            fi
        else
            log_info "  No old kernels to remove"
        fi
    fi
}

show_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  CLEANUP SUMMARY${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  Mode: ${YELLOW}DRY-RUN${NC}"
        echo -e "  Potential space freed: ${GREEN}$(format_size $SPACE_FREED)${NC}"
    else
        echo -e "  Mode: ${GREEN}EXECUTED${NC}"
        echo -e "  Space freed: ${GREEN}$(format_size $SPACE_FREED)${NC}"
    fi

    echo ""
    echo -e "  Current disk space:"
    df -h / | tail -1 | awk '{printf "    Used: %s / %s (%s)\n", $3, $2, $5}'

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

main() {
    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_warn "This script should be run as root for complete cleanup"
    fi

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
            --no-logs)
                CLEAN_LOGS=false
                shift
                ;;
            --no-temp)
                CLEAN_TEMP=false
                shift
                ;;
            --no-cache)
                CLEAN_CACHE=false
                shift
                ;;
            -k|--kernels)
                CLEAN_KERNELS=true
                shift
                ;;
            --log-days)
                LOG_DAYS="$2"
                shift 2
                ;;
            --temp-days)
                TEMP_DAYS="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  SYSTEM CLEANUP${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${YELLOW}Dry-run mode enabled${NC}"
    fi
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    # Execute cleanup tasks
    [[ "$CLEAN_TEMP" == "true" ]] && clean_temp_files
    [[ "$CLEAN_LOGS" == "true" ]] && clean_log_files
    [[ "$CLEAN_CACHE" == "true" ]] && clean_package_cache
    [[ "$CLEAN_CACHE" == "true" ]] && clean_user_caches
    [[ "$CLEAN_KERNELS" == "true" ]] && clean_old_kernels

    show_summary
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x cleanup-system.sh

# Nettoyage standard
sudo ./cleanup-system.sh

# Simulation (dry-run)
sudo ./cleanup-system.sh -d

# Nettoyage verbeux avec kernels
sudo ./cleanup-system.sh -v -k

# Logs de plus de 7 days
sudo ./cleanup-system.sh --log-days 7

# Sans nettoyage des caches
sudo ./cleanup-system.sh --no-cache
```

---

## Sortie Exemple

```text
═══════════════════════════════════════════════════════════
  NETTOYAGE SYSTÈME
═══════════════════════════════════════════════════════════

[INFO] Nettoyage des ficyesterdays temporaires (> 7 days)...
[INFO]   /tmp: 234M freed
[INFO]   /var/tmp: 45M freed
[INFO] Nettoyage des anciens logs (> 30 days)...
[INFO]   Logs: 1.2G freed
[INFO] Nettoyage des caches package manager...
[INFO]   APT cache nettoyé
[INFO] Nettoyage des caches utilisateur...

═══════════════════════════════════════════════════════════
  RÉSUMÉ DU NETTOYAGE
═══════════════════════════════════════════════════════════
  Mode: EXÉCUTION
  Espace libéré: 1.5G

  Disk space actuel:
    Utilisé: 22G / 50G (44%)
═══════════════════════════════════════════════════════════
```

---

## Automatisation Cron

```bash
# Nettoyage hebdomadaire
0 3 * * 0 /opt/scripts/cleanup-system.sh --log-days 14 >> /var/log/cleanup.log 2>&1

# Nettoyage mensuel complet
0 4 1 * * /opt/scripts/cleanup-system.sh -k --log-days 30 >> /var/log/cleanup.log 2>&1
```

---

## Voir Aussi

- [check-disk-space.sh](check-disk-space.md)
- [find-large-files.sh](find-large-files.md)
