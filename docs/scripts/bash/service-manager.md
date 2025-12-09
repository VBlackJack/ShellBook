---
tags:
  - scripts
  - bash
  - services
  - systemd
---

# service-manager.sh

:material-star: **Niveau : Débutant**

Gestion simplifiée des services systemd.

---

## Description

Ce script facilite la gestion des services :
- Liste des services avec statut
- Démarrage/arrêt/redémarrage
- Affichage des logs
- Vérification santé

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Utilisateur standard pour consultation, sudo pour modifications
- **Dépendances** : `systemctl`, `journalctl`

---

## Cas d'Usage

- **Interface simplifiée systemd** : Gestion intuitive des services sans mémoriser les commandes systemctl
- **Monitoring rapide** : Vue d'ensemble rapide de l'état des services critiques
- **Investigation de pannes** : Consultation rapide des logs et statuts lors d'incidents
- **Administration quotidienne** : Restart, enable/disable de services en quelques commandes

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: service-manager.sh
# Description: Gestion des services systemd
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

usage() {
    cat << EOF
Usage: $(basename "$0") [COMMAND] [SERVICE]

Gestion simplifiée des services systemd.

Commands:
    list                    Liste tous les services
    status [SERVICE]        Affiche le statut d'un service
    start SERVICE           Démarre un service
    stop SERVICE            Arrête un service
    restart SERVICE         Redémarre un service
    enable SERVICE          Active au démarrage
    disable SERVICE         Désactive au démarrage
    logs SERVICE            Affiche les logs
    health                  Vérifie la santé des services

Options:
    -h, --help              Show this help

Examples:
    $(basename "$0") list
    $(basename "$0") status nginx
    $(basename "$0") restart apache2
    $(basename "$0") logs mysql -f
EOF
}

print_header() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

status_color() {
    local status=$1
    case "$status" in
        active|running)     echo -e "${GREEN}●${NC}" ;;
        inactive|dead)      echo -e "${RED}○${NC}" ;;
        failed)             echo -e "${RED}✗${NC}" ;;
        *)                  echo -e "${YELLOW}?${NC}" ;;
    esac
}

list_services() {
    print_header "SERVICES SYSTEMD"

    echo ""
    printf "  ${CYAN}%-4s %-30s %-10s %-10s${NC}\n" "ST" "SERVICE" "STATE" "ENABLED"
    printf "  %-4s %-30s %-10s %-10s\n" "----" "------------------------------" "----------" "----------"

    systemctl list-units --type=service --all --no-pager 2>/dev/null | \
        grep "\.service" | \
        while read -r line; do
            local unit=$(echo "$line" | awk '{print $1}' | sed 's/\.service//')
            local load=$(echo "$line" | awk '{print $2}')
            local active=$(echo "$line" | awk '{print $3}')
            local sub=$(echo "$line" | awk '{print $4}')

            local enabled=$(systemctl is-enabled "$unit" 2>/dev/null || echo "unknown")
            local status_icon=$(status_color "$active")

            printf "  %s  %-30s %-10s %-10s\n" "$status_icon" "${unit:0:30}" "$active" "$enabled"
        done | head -30

    echo ""
    echo "  ... (limité à 30 services)"
    echo ""

    # Résumé
    local running=$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep -c "\.service" || echo "0")
    local failed=$(systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | grep -c "\.service" || echo "0")

    echo -e "  ${GREEN}Running:${NC} $running  ${RED}Failed:${NC} $failed"
}

show_status() {
    local service=$1

    print_header "STATUS: $service"

    # Statut détaillé
    systemctl status "$service" --no-pager 2>/dev/null || true

    echo ""

    # Informations supplémentaires
    echo -e "${CYAN}───────────────────────────────────────────────────────────${NC}"

    local enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "unknown")
    local active=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
    local pid=$(systemctl show "$service" --property=MainPID --value 2>/dev/null || echo "N/A")
    local memory=$(systemctl show "$service" --property=MemoryCurrent --value 2>/dev/null || echo "N/A")

    echo -e "  ${BOLD}Enabled:${NC}     $enabled"
    echo -e "  ${BOLD}Active:${NC}      $active"
    echo -e "  ${BOLD}Main PID:${NC}    $pid"

    if [[ "$memory" != "N/A" ]] && [[ "$memory" != "[not set]" ]]; then
        local mem_mb=$((memory / 1048576))
        echo -e "  ${BOLD}Memory:${NC}      ${mem_mb}M"
    fi
}

service_action() {
    local action=$1
    local service=$2

    echo -e "${CYAN}Exécution: systemctl $action $service${NC}"

    if systemctl "$action" "$service"; then
        echo -e "${GREEN}[OK]${NC} $service $action"

        # Display le nouveau statut
        sleep 1
        local status=$(systemctl is-active "$service" 2>/dev/null || echo "unknown")
        echo -e "  Nouveau statut: $status"
    else
        echo -e "${RED}[FAIL]${NC} $service $action"
        return 1
    fi
}

show_logs() {
    local service=$1
    shift
    local extra_args="$@"

    print_header "LOGS: $service"

    journalctl -u "$service" --no-pager -n 50 $extra_args
}

health_check() {
    print_header "SANTÉ DES SERVICES"

    # Services critiques
    local critical_services=("sshd" "ssh" "systemd-journald" "systemd-logind" "dbus" "cron" "rsyslog")

    echo ""
    echo -e "  ${BOLD}Services Critiques:${NC}"

    for svc in "${critical_services[@]}"; do
        if systemctl list-units --type=service --all 2>/dev/null | grep -q "$svc"; then
            local status=$(systemctl is-active "$svc" 2>/dev/null || echo "not found")
            local icon=$(status_color "$status")
            printf "    %s %-20s %s\n" "$icon" "$svc" "$status"
        fi
    done

    # Services faileds
    echo ""
    echo -e "  ${BOLD}Services Échoués:${NC}"

    local failed_services=$(systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | grep "\.service" || true)

    if [[ -n "$failed_services" ]]; then
        echo "$failed_services" | while read -r line; do
            local unit=$(echo "$line" | awk '{print $2}')
            echo -e "    ${RED}✗${NC} $unit"
        done
    else
        echo -e "    ${GREEN}Aucun service failed${NC}"
    fi

    # Services avec beaucoup de mémoire
    echo ""
    echo -e "  ${BOLD}Top 5 Services (Memory):${NC}"

    systemctl list-units --type=service --state=running --no-pager 2>/dev/null | \
        grep "\.service" | \
        awk '{print $1}' | \
        while read -r svc; do
            local mem=$(systemctl show "$svc" --property=MemoryCurrent --value 2>/dev/null)
            if [[ -n "$mem" ]] && [[ "$mem" != "[not set]" ]] && [[ "$mem" -gt 0 ]]; then
                echo "$mem $svc"
            fi
        done | sort -rn | head -5 | \
        while read -r mem svc; do
            local mem_mb=$((mem / 1048576))
            printf "    %-30s %sM\n" "${svc%.service}" "$mem_mb"
        done

    # Résumé
    echo ""
    echo -e "${CYAN}───────────────────────────────────────────────────────────${NC}"

    local total=$(systemctl list-units --type=service --no-pager 2>/dev/null | grep -c "\.service" || echo "0")
    local running=$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep -c "\.service" || echo "0")
    local failed_count=$(systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | grep -c "\.service" || echo "0")

    echo -e "  Total: $total | ${GREEN}Running: $running${NC} | ${RED}Failed: $failed_count${NC}"
}

main() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 0
    fi

    local command=$1
    shift

    case "$command" in
        list)
            list_services
            ;;
        status)
            if [[ $# -eq 0 ]]; then
                health_check
            else
                show_status "$1"
            fi
            ;;
        start|stop|restart|enable|disable|reload)
            if [[ $# -eq 0 ]]; then
                echo "Error: Service requis"
                exit 1
            fi
            service_action "$command" "$1"
            ;;
        logs)
            if [[ $# -eq 0 ]]; then
                echo "Error: Service requis"
                exit 1
            fi
            show_logs "$@"
            ;;
        health)
            health_check
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Commande inconnue: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x service-manager.sh

# Liste des services
./service-manager.sh list

# Statut d'un service
./service-manager.sh status nginx

# Gérer un service
sudo ./service-manager.sh start nginx
sudo ./service-manager.sh restart mysql
sudo ./service-manager.sh stop apache2

# Logs
./service-manager.sh logs nginx
./service-manager.sh logs mysql -f  # Follow

# Santé globale
./service-manager.sh health
```

---

## Sortie Exemple

```text
═══════════════════════════════════════════════════════════
  SERVICES SYSTEMD
═══════════════════════════════════════════════════════════

  ST   SERVICE                        STATE      ENABLED
  ---- ------------------------------ ---------- ----------
  ●    cron                           active     enabled
  ●    dbus                           active     static
  ●    nginx                          active     enabled
  ○    apache2                        inactive   disabled
  ●    mysql                          active     enabled
  ●    ssh                            active     enabled
  ✗    my-app                         failed     enabled

  ... (limité à 30 services)

  Running: 45  Failed: 1
```

---

## Voir Aussi

- [health-check.sh](health-check.md)
- [system-info.sh](system-info.md)
