---
tags:
  - scripts
  - bash
  - sécurité
  - logs
---

# log-analyzer.sh

:material-star::material-star: **Niveau : Intermédiaire**

Analyse des logs système pour détecter les anomalies.

---

## Description

Ce script analyse les logs système :
- Détection des tentatives de connexion failedes
- Analyse des erreurs critiques
- Statistiques d'accès
- Rapport d'anomalies

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: log-analyzer.sh
# Description: Analyse des logs système
# Author: ShellBook
# Version: 1.0
#===============================================================================

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m'

# Configuration
LOG_DIR="/var/log"
HOURS=24
TOP_N=10
OUTPUT_FILE=""

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Analyse des logs système.

Options:
    -d, --dir PATH      Répertoire des logs (default: /var/log)
    -t, --time HOURS    Analyser les N lasts hours (default: 24)
    -n, --top NUM       Nombre de résultats top (default: 10)
    -o, --output FILE   Sauvegarder le rapport
    -h, --help          Show this help

Examples:
    $(basename "$0")                    # Analyse 24h
    $(basename "$0") -t 1               # Dernière heure
    $(basename "$0") -n 20 -o report.txt
EOF
}

print_header() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

print_section() {
    echo -e "\n${YELLOW}▶ $1${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# ANALYSE AUTH/SSH
# ══════════════════════════════════════════════════════════════════════════════
analyze_auth_logs() {
    print_header "ANALYSE AUTHENTIFICATION"

    local auth_log=""
    for log in "$LOG_DIR/auth.log" "$LOG_DIR/secure" "$LOG_DIR/auth.log.1"; do
        [[ -f "$log" ]] && auth_log="$log" && break
    done

    if [[ -z "$auth_log" ]]; then
        echo "Aucun ficyesterday de log d'authentification trouvé"
        return
    fi

    # Tentatives failedes SSH
    print_section "Tentatives SSH Échouées (Top $TOP_N IPs)"
    grep -h "Failed password" "$auth_log" "$LOG_DIR/auth.log.1" 2>/dev/null | \
        grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | \
        sort | uniq -c | sort -rn | head -n "$TOP_N" | \
        while read -r count ip; do
            printf "  ${RED}%-6s${NC} %s\n" "$count" "$ip"
        done

    # Utilisateurs invalides
    print_section "Utilisateurs Invalides Tentés"
    grep -h "Invalid user" "$auth_log" 2>/dev/null | \
        grep -oP "Invalid user \K\w+" | \
        sort | uniq -c | sort -rn | head -n "$TOP_N" | \
        while read -r count user; do
            printf "  ${YELLOW}%-6s${NC} %s\n" "$count" "$user"
        done

    # Connections succeededes
    print_section "Connections SSH Réussies"
    local success_count=$(grep -c "Accepted" "$auth_log" 2>/dev/null || echo "0")
    echo "  Total: $success_count"

    grep -h "Accepted" "$auth_log" 2>/dev/null | \
        awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}' | \
        sort | uniq -c | sort -rn | head -n 5 | \
        while read -r count ip; do
            printf "  ${GREEN}%-6s${NC} %s\n" "$count" "$ip"
        done

    # Sudo
    print_section "Commandes Sudo"
    grep -h "sudo:" "$auth_log" 2>/dev/null | \
        grep "COMMAND" | \
        awk -F'COMMAND=' '{print $2}' | \
        sort | uniq -c | sort -rn | head -n 5 | \
        while read -r count cmd; do
            printf "  ${CYAN}%-6s${NC} %s\n" "$count" "${cmd:0:60}"
        done
}

# ══════════════════════════════════════════════════════════════════════════════
# ANALYSE SYSLOG
# ══════════════════════════════════════════════════════════════════════════════
analyze_syslog() {
    print_header "ANALYSE SYSLOG"

    local syslog=""
    for log in "$LOG_DIR/syslog" "$LOG_DIR/messages"; do
        [[ -f "$log" ]] && syslog="$log" && break
    done

    if [[ -z "$syslog" ]]; then
        echo "Aucun ficyesterday syslog trouvé"
        return
    fi

    # Erreurs critiques
    print_section "Erreurs Critiques"
    grep -iE "(error|critical|emergency|alert)" "$syslog" 2>/dev/null | \
        tail -n 20 | \
        while read -r line; do
            echo "  ${line:0:80}"
        done

    # Services avec erreurs
    print_section "Services avec Erreurs"
    grep -i "error" "$syslog" 2>/dev/null | \
        awk '{print $5}' | \
        sed 's/\[.*//; s/:$//' | \
        sort | uniq -c | sort -rn | head -n "$TOP_N" | \
        while read -r count service; do
            printf "  ${RED}%-6s${NC} %s\n" "$count" "$service"
        done

    # Kernel messages
    print_section "Messages Kernel"
    grep -i "kernel" "$syslog" 2>/dev/null | \
        grep -iE "(error|warning|fail)" | \
        tail -n 5 | \
        while read -r line; do
            echo "  ${line:0:80}"
        done
}

# ══════════════════════════════════════════════════════════════════════════════
# ANALYSE NGINX/APACHE
# ══════════════════════════════════════════════════════════════════════════════
analyze_web_logs() {
    print_header "ANALYSE SERVEUR WEB"

    local access_log=""
    local error_log=""

    # Chercher les logs web
    for log in "$LOG_DIR/nginx/access.log" "$LOG_DIR/apache2/access.log" "$LOG_DIR/httpd/access_log"; do
        [[ -f "$log" ]] && access_log="$log" && break
    done

    for log in "$LOG_DIR/nginx/error.log" "$LOG_DIR/apache2/error.log" "$LOG_DIR/httpd/error_log"; do
        [[ -f "$log" ]] && error_log="$log" && break
    done

    if [[ -z "$access_log" ]]; then
        echo "Aucun log de serveur web trouvé"
        return
    fi

    # Top IPs
    print_section "Top $TOP_N IPs (Requêtes)"
    awk '{print $1}' "$access_log" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -n "$TOP_N" | \
        while read -r count ip; do
            printf "  ${CYAN}%-8s${NC} %s\n" "$count" "$ip"
        done

    # Codes HTTP
    print_section "Codes HTTP"
    awk '{print $9}' "$access_log" 2>/dev/null | \
        grep -E "^[0-9]{3}$" | \
        sort | uniq -c | sort -rn | head -n 10 | \
        while read -r count code; do
            local color=$GREEN
            [[ "$code" == 4* ]] && color=$YELLOW
            [[ "$code" == 5* ]] && color=$RED
            printf "  ${color}%-8s${NC} HTTP %s\n" "$count" "$code"
        done

    # URLs les plus demandées
    print_section "Top URLs"
    awk '{print $7}' "$access_log" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -n "$TOP_N" | \
        while read -r count url; do
            printf "  ${GREEN}%-8s${NC} %s\n" "$count" "${url:0:50}"
        done

    # Erreurs 4xx/5xx
    print_section "Erreurs HTTP (4xx/5xx)"
    awk '$9 ~ /^[45]/ {print $9, $7}' "$access_log" 2>/dev/null | \
        sort | uniq -c | sort -rn | head -n "$TOP_N" | \
        while read -r count code url; do
            printf "  ${RED}%-6s${NC} %s %s\n" "$count" "$code" "${url:0:40}"
        done

    # User agents suspects
    print_section "User Agents Suspects"
    grep -iE "(sqlmap|nikto|nmap|scanner|bot|crawler)" "$access_log" 2>/dev/null | \
        awk -F'"' '{print $6}' | \
        sort | uniq -c | sort -rn | head -n 5 | \
        while read -r count ua; do
            printf "  ${YELLOW}%-6s${NC} %s\n" "$count" "${ua:0:50}"
        done
}

# ══════════════════════════════════════════════════════════════════════════════
# ANALYSE JOURNALD
# ══════════════════════════════════════════════════════════════════════════════
analyze_journald() {
    print_header "ANALYSE JOURNALD"

    if ! command -v journalctl &>/dev/null; then
        echo "journalctl non disponible"
        return
    fi

    local since="$HOURS hours ago"

    # Erreurs système
    print_section "Erreurs Système (lasts ${HOURS}h)"
    journalctl --since "$since" -p err --no-pager 2>/dev/null | \
        tail -n 20 | \
        while read -r line; do
            echo "  ${line:0:80}"
        done

    # Services faileds
    print_section "Services Échoués"
    journalctl --since "$since" | \
        grep -i "failed" | \
        awk '{print $5}' | \
        sed 's/\[.*//; s/:$//' | \
        sort | uniq -c | sort -rn | head -n 5 | \
        while read -r count svc; do
            printf "  ${RED}%-6s${NC} %s\n" "$count" "$svc"
        done

    # Boot messages
    print_section "Dernier Boot"
    local boot_time=$(journalctl --list-boots 2>/dev/null | tail -1 | awk '{print $3, $4}')
    echo "  Démarré: $boot_time"
}

# ══════════════════════════════════════════════════════════════════════════════
# STATISTIQUES GÉNÉRALES
# ══════════════════════════════════════════════════════════════════════════════
show_statistics() {
    print_header "STATISTIQUES GÉNÉRALES"

    # Taille des logs
    print_section "Taille des Logs"
    du -sh "$LOG_DIR"/* 2>/dev/null | sort -rh | head -n 10 | \
        while read -r size path; do
            printf "  %-10s %s\n" "$size" "$(basename "$path")"
        done

    # Logs modifiés récemment
    print_section "Logs Modifiés (last heure)"
    find "$LOG_DIR" -type f -mmin -60 2>/dev/null | head -n 10 | \
        while read -r log; do
            echo "  $(basename "$log")"
        done
}

show_summary() {
    print_header "RÉSUMÉ"

    echo "  Période analysée: lasts ${HOURS}h"
    echo "  Répertoire logs: $LOG_DIR"
    echo "  Date rapport: $(date '+%Y-%m-%d %H:%M:%S')"

    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "  Rapport sauvegardé: $OUTPUT_FILE"
    fi
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dir)
                LOG_DIR="$2"
                shift 2
                ;;
            -t|--time)
                HOURS="$2"
                shift 2
                ;;
            -n|--top)
                TOP_N="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Redirection vers ficyesterday si demandé
    if [[ -n "$OUTPUT_FILE" ]]; then
        exec > >(tee "$OUTPUT_FILE")
    fi

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}          ANALYSEUR DE LOGS SYSTÈME${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  Host: $(hostname)"
    echo -e "  Période: lasts ${HOURS}h"

    analyze_auth_logs
    analyze_syslog
    analyze_web_logs
    analyze_journald
    show_statistics
    show_summary
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x log-analyzer.sh

# Analyse standard (24h)
sudo ./log-analyzer.sh

# Dernière heure
sudo ./log-analyzer.sh -t 1

# Top 20 avec rapport
sudo ./log-analyzer.sh -n 20 -o report.txt

# Répertoire personnalisé
sudo ./log-analyzer.sh -d /var/log/myapp
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
          ANALYSEUR DE LOGS SYSTÈME
═══════════════════════════════════════════════════════════
  Date: 2024-01-15 14:30:22
  Host: webserver01
  Période: lasts 24h

═══════════════════════════════════════════════════════════
  ANALYSE AUTHENTIFICATION
═══════════════════════════════════════════════════════════

▶ Tentatives SSH Échouées (Top 10 IPs)
  1523   203.0.113.45
  892    198.51.100.23
  456    192.0.2.100

▶ Utilisateurs Invalides Tentés
  234    admin
  189    root
  145    test
  98     user

▶ Connections SSH Réussies
  Total: 45
  23     192.168.1.10
  15     10.0.0.5
  7      192.168.1.20

═══════════════════════════════════════════════════════════
  ANALYSE SERVEUR WEB
═══════════════════════════════════════════════════════════

▶ Codes HTTP
  125000   HTTP 200
  3500     HTTP 304
  890      HTTP 404
  23       HTTP 500

▶ Erreurs HTTP (4xx/5xx)
  890    404 /wp-admin/
  234    404 /phpmyadmin/
  23     500 /api/users
```

---

## Voir Aussi

- [security-audit.sh](security-audit.md)
- [check-permissions.sh](check-permissions.md)
