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
- Suppression des fichiers temporaires
- Nettoyage des anciens logs
- Purge des caches package manager
- Nettoyage des kernels obsolètes (optionnel)
- Mode dry-run pour prévisualisation

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: cleanup-system.sh
# Description: Nettoyage système automatisé
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
VERBOSE=false
CLEAN_LOGS=true
CLEAN_TEMP=true
CLEAN_CACHE=true
CLEAN_KERNELS=false
LOG_DAYS=30
TEMP_DAYS=7

# Compteurs
SPACE_FREED=0

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Nettoyage système automatisé.

Options:
    -d, --dry-run        Simulation sans suppression
    -v, --verbose        Mode verbeux
    --no-logs            Ne pas nettoyer les logs
    --no-temp            Ne pas nettoyer les fichiers temporaires
    --no-cache           Ne pas nettoyer les caches
    -k, --kernels        Nettoyer les anciens kernels
    --log-days NUM       Âge des logs à supprimer (défaut: 30)
    --temp-days NUM      Âge des fichiers temp (défaut: 7)
    -h, --help           Affiche cette aide

Exemples:
    $(basename "$0")              # Nettoyage standard
    $(basename "$0") -d           # Simulation
    $(basename "$0") -v -k        # Verbeux + kernels
    $(basename "$0") --log-days 7 # Logs > 7 jours
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
    log_info "Nettoyage des fichiers temporaires (> ${TEMP_DAYS} jours)..."

    local dirs=("/tmp" "/var/tmp")

    for dir in "${dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            local size_before=$(get_dir_size "$dir")

            if [[ "$DRY_RUN" == "true" ]]; then
                local count=$(find "$dir" -type f -atime +${TEMP_DAYS} 2>/dev/null | wc -l)
                log_action "Supprimerait $count fichiers dans $dir"
            else
                find "$dir" -type f -atime +${TEMP_DAYS} -delete 2>/dev/null || true
                find "$dir" -type d -empty -delete 2>/dev/null || true
            fi

            local size_after=$(get_dir_size "$dir")
            local freed=$((size_before - size_after))
            SPACE_FREED=$((SPACE_FREED + freed))

            [[ "$VERBOSE" == "true" ]] && log_info "  $dir: $(format_size $freed) libérés"
        fi
    done
}

clean_log_files() {
    log_info "Nettoyage des anciens logs (> ${LOG_DAYS} jours)..."

    local log_dir="/var/log"
    local size_before=$(get_dir_size "$log_dir")

    if [[ "$DRY_RUN" == "true" ]]; then
        # Fichiers .log anciens
        local count=$(find "$log_dir" -name "*.log" -type f -mtime +${LOG_DAYS} 2>/dev/null | wc -l)
        log_action "Supprimerait $count fichiers .log anciens"

        # Fichiers .gz
        count=$(find "$log_dir" -name "*.gz" -type f -mtime +${LOG_DAYS} 2>/dev/null | wc -l)
        log_action "Supprimerait $count fichiers .gz anciens"

        # Journaux systemd
        if command -v journalctl &>/dev/null; then
            log_action "Nettoierait les journaux systemd > ${LOG_DAYS} jours"
        fi
    else
        # Supprimer les vieux logs
        find "$log_dir" -name "*.log" -type f -mtime +${LOG_DAYS} -delete 2>/dev/null || true
        find "$log_dir" -name "*.log.[0-9]*" -type f -mtime +${LOG_DAYS} -delete 2>/dev/null || true
        find "$log_dir" -name "*.gz" -type f -mtime +${LOG_DAYS} -delete 2>/dev/null || true

        # Nettoyer journald
        if command -v journalctl &>/dev/null; then
            journalctl --vacuum-time=${LOG_DAYS}d 2>/dev/null || true
        fi
    fi

    local size_after=$(get_dir_size "$log_dir")
    local freed=$((size_before - size_after))
    SPACE_FREED=$((SPACE_FREED + freed))

    [[ "$VERBOSE" == "true" ]] && log_info "  Logs: $(format_size $freed) libérés"
}

clean_package_cache() {
    log_info "Nettoyage des caches package manager..."

    # APT (Debian/Ubuntu)
    if command -v apt-get &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_action "apt-get clean"
            log_action "apt-get autoremove"
        else
            apt-get clean 2>/dev/null || true
            apt-get autoremove -y 2>/dev/null || true
        fi
        [[ "$VERBOSE" == "true" ]] && log_info "  APT cache nettoyé"
    fi

    # YUM/DNF (RHEL/CentOS/Fedora)
    if command -v dnf &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_action "dnf clean all"
        else
            dnf clean all 2>/dev/null || true
        fi
        [[ "$VERBOSE" == "true" ]] && log_info "  DNF cache nettoyé"
    elif command -v yum &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_action "yum clean all"
        else
            yum clean all 2>/dev/null || true
        fi
        [[ "$VERBOSE" == "true" ]] && log_info "  YUM cache nettoyé"
    fi

    # Pacman (Arch)
    if command -v pacman &>/dev/null; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_action "pacman -Sc"
        else
            pacman -Sc --noconfirm 2>/dev/null || true
        fi
        [[ "$VERBOSE" == "true" ]] && log_info "  Pacman cache nettoyé"
    fi
}

clean_user_caches() {
    log_info "Nettoyage des caches utilisateur..."

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
                    log_action "Nettoierait $dir ($(format_size $size_before))"
                else
                    rm -rf "$dir"/* 2>/dev/null || true
                fi

                SPACE_FREED=$((SPACE_FREED + size_before))
            fi
        done
    done
}

clean_old_kernels() {
    log_info "Nettoyage des anciens kernels..."

    if command -v apt-get &>/dev/null; then
        local current_kernel=$(uname -r)
        local old_kernels=$(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii' | awk '{print $2}' | grep -v "$current_kernel" | grep -v 'linux-image-generic' || true)

        if [[ -n "$old_kernels" ]]; then
            if [[ "$DRY_RUN" == "true" ]]; then
                log_action "Supprimerait les kernels: $old_kernels"
            else
                echo "$old_kernels" | xargs apt-get remove -y 2>/dev/null || true
            fi
        else
            log_info "  Aucun ancien kernel à supprimer"
        fi
    fi
}

show_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  RÉSUMÉ DU NETTOYAGE${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  Mode: ${YELLOW}SIMULATION${NC}"
        echo -e "  Espace potentiellement libéré: ${GREEN}$(format_size $SPACE_FREED)${NC}"
    else
        echo -e "  Mode: ${GREEN}EXÉCUTION${NC}"
        echo -e "  Espace libéré: ${GREEN}$(format_size $SPACE_FREED)${NC}"
    fi

    echo ""
    echo -e "  Espace disque actuel:"
    df -h / | tail -1 | awk '{printf "    Utilisé: %s / %s (%s)\n", $3, $2, $5}'

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

main() {
    # Vérifier root
    if [[ $EUID -ne 0 ]]; then
        log_warn "Ce script devrait être exécuté en tant que root pour un nettoyage complet"
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
                log_error "Option inconnue: $1"
                usage
                exit 1
                ;;
        esac
    done

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  NETTOYAGE SYSTÈME${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${YELLOW}Mode simulation activé${NC}"
    fi
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    # Exécution des nettoyages
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

## Utilisation

```bash
# Rendre exécutable
chmod +x cleanup-system.sh

# Nettoyage standard
sudo ./cleanup-system.sh

# Simulation (dry-run)
sudo ./cleanup-system.sh -d

# Nettoyage verbeux avec kernels
sudo ./cleanup-system.sh -v -k

# Logs de plus de 7 jours
sudo ./cleanup-system.sh --log-days 7

# Sans nettoyage des caches
sudo ./cleanup-system.sh --no-cache
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
  NETTOYAGE SYSTÈME
═══════════════════════════════════════════════════════════

[INFO] Nettoyage des fichiers temporaires (> 7 jours)...
[INFO]   /tmp: 234M libérés
[INFO]   /var/tmp: 45M libérés
[INFO] Nettoyage des anciens logs (> 30 jours)...
[INFO]   Logs: 1.2G libérés
[INFO] Nettoyage des caches package manager...
[INFO]   APT cache nettoyé
[INFO] Nettoyage des caches utilisateur...

═══════════════════════════════════════════════════════════
  RÉSUMÉ DU NETTOYAGE
═══════════════════════════════════════════════════════════
  Mode: EXÉCUTION
  Espace libéré: 1.5G

  Espace disque actuel:
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
