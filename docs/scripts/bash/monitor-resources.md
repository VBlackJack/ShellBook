---
tags:
  - scripts
  - bash
  - système
  - monitoring
  - performance
---

# monitor-resources.sh

:material-star::material-star: **Niveau : Intermédiaire**

Monitoring CPU/RAM en temps réel avec historique.

---

## Description

Ce script surveille les ressources système en continu :
- CPU, mémoire, swap en temps réel
- Rafraîchissement configurable
- Alertes sur seuils dépassés
- Export des données pour analyse

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Utilisateur standard (pas de sudo requis)
- **Dépendances** : `bc`, `/proc/stat`, `/proc/meminfo`

---

## Cas d'Usage

- **Monitoring temps réel** : Surveillance continue des ressources CPU et mémoire avec affichage visuel
- **Diagnostic de performance** : Identification rapide des processus consommant le plus de ressources
- **Collection de métriques** : Export CSV pour analyse historique et création de graphiques
- **Investigation de pics** : Surveillance pendant tests de charge ou résolution d'incidents

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: monitor-resources.sh
# Description: Monitoring CPU/RAM en temps réel
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

# Default configuration
INTERVAL=2
COUNT=0  # 0 = infini
LOG_FILE=""
CPU_WARN=80
MEM_WARN=85
QUIET=false

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Monitoring CPU/RAM en temps réel.

Options:
    -i, --interval SEC   Intervalle de rafraîchissement (default: 2s)
    -n, --count NUM      Nombre d'itérations (default: infini)
    -l, --log FILE       Enregistrer dans un ficyesterday
    -cw, --cpu-warn NUM  Seuil CPU warning (default: 80%)
    -mw, --mem-warn NUM  Seuil mémoire warning (default: 85%)
    -q, --quiet          Mode silencieux (log uniquement)
    -h, --help           Show this help

Examples:
    $(basename "$0")                     # Monitoring continu
    $(basename "$0") -i 5 -n 100         # 100 mesures, 5s d'intervalle
    $(basename "$0") -l monitor.csv      # Avec logging
EOF
}

get_cpu_usage() {
    # Calcul basé sur /proc/stat
    local cpu_line=$(head -1 /proc/stat)
    local cpu_values=($cpu_line)

    local user=${cpu_values[1]}
    local nice=${cpu_values[2]}
    local system=${cpu_values[3]}
    local idle=${cpu_values[4]}
    local iowait=${cpu_values[5]:-0}

    local total=$((user + nice + system + idle + iowait))
    local used=$((user + nice + system))

    echo "$used $total"
}

get_memory_info() {
    local mem_total mem_available mem_used mem_percent
    local swap_total swap_free swap_used swap_percent

    mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    mem_available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    mem_used=$((mem_total - mem_available))
    mem_percent=$((mem_used * 100 / mem_total))

    swap_total=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
    swap_free=$(grep SwapFree /proc/meminfo | awk '{print $2}')
    swap_used=$((swap_total - swap_free))

    if [[ $swap_total -gt 0 ]]; then
        swap_percent=$((swap_used * 100 / swap_total))
    else
        swap_percent=0
    fi

    echo "$mem_used $mem_total $mem_percent $swap_used $swap_total $swap_percent"
}

format_bytes() {
    local kb=$1
    if (( kb >= 1048576 )); then
        echo "$(echo "scale=1; $kb/1048576" | bc)G"
    elif (( kb >= 1024 )); then
        echo "$(echo "scale=1; $kb/1024" | bc)M"
    else
        echo "${kb}K"
    fi
}

draw_bar() {
    local percent=$1
    local width=30
    local filled=$((percent * width / 100))
    local empty=$((width - filled))
    local color=$GREEN

    if (( percent >= 90 )); then
        color=$RED
    elif (( percent >= 75 )); then
        color=$YELLOW
    fi

    printf "${color}["
    printf "%${filled}s" | tr ' ' '█'
    printf "%${empty}s" | tr ' ' '░'
    printf "]${NC} %3d%%" "$percent"
}

print_header() {
    clear
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}                    SYSTEM RESOURCE MONITOR                     ${NC}"
    echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  Host: $(hostname)  |  $(date '+%Y-%m-%d %H:%M:%S')  |  Interval: ${INTERVAL}s"
    echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
}

monitor_once() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # CPU (nécessite deux mesures)
    read cpu_used1 cpu_total1 <<< $(get_cpu_usage)
    sleep 0.5
    read cpu_used2 cpu_total2 <<< $(get_cpu_usage)

    local cpu_delta_used=$((cpu_used2 - cpu_used1))
    local cpu_delta_total=$((cpu_total2 - cpu_total1))
    local cpu_percent=0

    if (( cpu_delta_total > 0 )); then
        cpu_percent=$((cpu_delta_used * 100 / cpu_delta_total))
    fi

    # Memory
    read mem_used mem_total mem_percent swap_used swap_total swap_percent <<< $(get_memory_info)

    # Load average
    local load_avg=$(cat /proc/loadavg | awk '{print $1, $2, $3}')

    # Affichage
    if [[ "$QUIET" == "false" ]]; then
        print_header

        echo ""
        echo -e "  ${BOLD}CPU Usage:${NC}"
        printf "    "
        draw_bar $cpu_percent
        if (( cpu_percent >= CPU_WARN )); then
            echo -e " ${RED}⚠ HIGH${NC}"
        else
            echo ""
        fi
        echo -e "    Load Average: $load_avg"

        echo ""
        echo -e "  ${BOLD}Memory:${NC}"
        printf "    "
        draw_bar $mem_percent
        if (( mem_percent >= MEM_WARN )); then
            echo -e " ${RED}⚠ HIGH${NC}"
        else
            echo ""
        fi
        echo -e "    Used: $(format_bytes $mem_used) / $(format_bytes $mem_total)"

        echo ""
        echo -e "  ${BOLD}Swap:${NC}"
        printf "    "
        draw_bar $swap_percent
        echo ""
        echo -e "    Used: $(format_bytes $swap_used) / $(format_bytes $swap_total)"

        # Top processus
        echo ""
        echo -e "${CYAN}───────────────────────────────────────────────────────────────${NC}"
        echo -e "  ${BOLD}Top 5 CPU Consumers:${NC}"
        ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "    %-12s %5s%% CPU  %s\n", $1, $3, $11}'

        echo ""
        echo -e "  ${BOLD}Top 5 Memory Consumers:${NC}"
        ps aux --sort=-%mem | head -6 | tail -5 | awk '{printf "    %-12s %5s%% MEM  %s\n", $1, $4, $11}'

        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "  Press ${BOLD}Ctrl+C${NC} to exit"
    fi

    # Logging
    if [[ -n "$LOG_FILE" ]]; then
        echo "$timestamp,$cpu_percent,$mem_percent,$swap_percent,$load_avg" >> "$LOG_FILE"
    fi
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interval)
                INTERVAL="$2"
                shift 2
                ;;
            -n|--count)
                COUNT="$2"
                shift 2
                ;;
            -l|--log)
                LOG_FILE="$2"
                shift 2
                ;;
            -cw|--cpu-warn)
                CPU_WARN="$2"
                shift 2
                ;;
            -mw|--mem-warn)
                MEM_WARN="$2"
                shift 2
                ;;
            -q|--quiet)
                QUIET=true
                shift
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

    # Create le ficyesterday de log avec header
    if [[ -n "$LOG_FILE" ]]; then
        echo "timestamp,cpu_percent,mem_percent,swap_percent,load_avg" > "$LOG_FILE"
    fi

    # Boucle de monitoring
    local iteration=0

    trap 'echo -e "\n\nMonitoring arrêté."; exit 0' INT

    while true; do
        monitor_once

        iteration=$((iteration + 1))

        if (( COUNT > 0 && iteration >= COUNT )); then
            echo -e "\n${GREEN}Monitoring completed après $COUNT itérations.${NC}"
            break
        fi

        sleep "$INTERVAL"
    done
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x monitor-resources.sh

# Monitoring continu (Ctrl+C pour arrêter)
./monitor-resources.sh

# Rafraîchissement toutes les 5 seconds
./monitor-resources.sh -i 5

# 100 mesures puis arrêt
./monitor-resources.sh -n 100

# Avec logging CSV
./monitor-resources.sh -l /var/log/resources.csv

# Mode silencieux (logging uniquement)
./monitor-resources.sh -q -l resources.csv
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════════
                    SYSTEM RESOURCE MONITOR
═══════════════════════════════════════════════════════════════
  Host: webserver01  |  2024-01-15 14:30:22  |  Interval: 2s
───────────────────────────────────────────────────────────────

  CPU Usage:
    [████████████░░░░░░░░░░░░░░░░░░]  42%
    Load Average: 0.52 0.48 0.45

  Memory:
    [██████████████████████░░░░░░░░]  73%
    Used: 11.7G / 16.0G

  Swap:
    [███░░░░░░░░░░░░░░░░░░░░░░░░░░░]  12%
    Used: 245M / 2.0G

───────────────────────────────────────────────────────────────
  Top 5 CPU Consumers:
    mysql         8.2% CPU  /usr/sbin/mysqld
    apache2       3.1% CPU  /usr/sbin/apache2
    php-fpm       2.8% CPU  php-fpm: pool www
    node          1.5% CPU  /usr/bin/node
    prometheus    0.8% CPU  /usr/bin/prometheus

  Top 5 Memory Consumers:
    mysql        42.3% MEM  /usr/sbin/mysqld
    java         12.8% MEM  /usr/bin/java
    prometheus    5.2% MEM  /usr/bin/prometheus
    apache2       3.1% MEM  /usr/sbin/apache2
    grafana       2.4% MEM  /usr/sbin/grafana

═══════════════════════════════════════════════════════════════
  Press Ctrl+C to exit
```

---

## Format CSV de Log

```csv
timestamp,cpu_percent,mem_percent,swap_percent,load_avg
2024-01-15 14:30:22,42,73,12,0.52 0.48 0.45
2024-01-15 14:30:24,45,73,12,0.54 0.49 0.45
2024-01-15 14:30:26,38,74,12,0.51 0.48 0.45
```

---

## Voir Aussi

- [system-info.sh](system-info.md)
- [check-disk-space.sh](check-disk-space.md)
