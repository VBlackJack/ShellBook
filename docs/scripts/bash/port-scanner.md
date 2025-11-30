---
tags:
  - scripts
  - bash
  - réseau
  - sécurité
---

# port-scanner.sh

:material-star::material-star: **Niveau : Intermédiaire**

Scanner de ports simple en Bash.

---

## Description

Ce script scanne les ports ouverts sur une cible :
- Scan de ports individuels ou plages
- Timeout configurable
- Détection de services courants
- Export des résultats

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: port-scanner.sh
# Description: Scanner de ports simple
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
TIMEOUT=1
OUTPUT_FILE=""
VERBOSE=false

# Services courants
declare -A SERVICES=(
    [21]="FTP"
    [22]="SSH"
    [23]="Telnet"
    [25]="SMTP"
    [53]="DNS"
    [80]="HTTP"
    [110]="POP3"
    [143]="IMAP"
    [443]="HTTPS"
    [465]="SMTPS"
    [587]="SMTP/TLS"
    [993]="IMAPS"
    [995]="POP3S"
    [3306]="MySQL"
    [3389]="RDP"
    [5432]="PostgreSQL"
    [6379]="Redis"
    [8080]="HTTP-Alt"
    [8443]="HTTPS-Alt"
    [27017]="MongoDB"
)

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] HOST [PORTS]

Scanner de ports simple.

Arguments:
    HOST            Adresse IP ou hostname à scanner
    PORTS           Ports à scanner (défaut: ports courants)
                    Formats: 80 | 80,443,8080 | 1-1024 | common

Options:
    -t, --timeout SEC   Timeout par port (défaut: 1s)
    -o, --output FILE   Sauvegarder résultats dans un fichier
    -v, --verbose       Mode verbeux
    -h, --help          Affiche cette aide

Exemples:
    $(basename "$0") 192.168.1.1                  # Ports courants
    $(basename "$0") example.com 80,443,8080      # Ports spécifiques
    $(basename "$0") 10.0.0.1 1-1024              # Plage de ports
    $(basename "$0") -t 2 -o scan.txt host.local  # Avec options
EOF
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_open() {
    echo -e "${GREEN}[OPEN]${NC} $1"
}

log_closed() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${RED}[CLOSED]${NC} $1"
    fi
}

get_service_name() {
    local port=$1
    echo "${SERVICES[$port]:-unknown}"
}

scan_port() {
    local host=$1
    local port=$2

    if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

parse_ports() {
    local port_spec=$1
    local ports=()

    case "$port_spec" in
        common|"")
            # Ports courants
            ports=(21 22 23 25 53 80 110 143 443 465 587 993 995 3306 3389 5432 6379 8080 8443 27017)
            ;;
        *-*)
            # Plage de ports (ex: 1-1024)
            local start=${port_spec%-*}
            local end=${port_spec#*-}
            for ((i=start; i<=end; i++)); do
                ports+=($i)
            done
            ;;
        *,*)
            # Liste de ports (ex: 80,443,8080)
            IFS=',' read -ra ports <<< "$port_spec"
            ;;
        *)
            # Port unique
            ports=($port_spec)
            ;;
    esac

    echo "${ports[@]}"
}

main() {
    local host=""
    local port_spec=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                echo "Option inconnue: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$host" ]]; then
                    host="$1"
                else
                    port_spec="$1"
                fi
                shift
                ;;
        esac
    done

    # Validation
    if [[ -z "$host" ]]; then
        echo "Erreur: Host requis"
        usage
        exit 1
    fi

    # Parser les ports
    local ports
    read -ra ports <<< "$(parse_ports "$port_spec")"
    local total_ports=${#ports[@]}

    # Header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  PORT SCANNER${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  Target: $host"
    echo -e "  Ports: $total_ports"
    echo -e "  Timeout: ${TIMEOUT}s"
    echo -e "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${CYAN}───────────────────────────────────────────────────────────${NC}"

    # Vérifier que l'host est joignable
    if ! ping -c 1 -W 2 "$host" &>/dev/null; then
        echo -e "${YELLOW}[WARN]${NC} Host peut ne pas répondre au ping (scan continue)"
    fi

    # Initialiser fichier output
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo "# Port Scan Results" > "$OUTPUT_FILE"
        echo "# Target: $host" >> "$OUTPUT_FILE"
        echo "# Date: $(date '+%Y-%m-%d %H:%M:%S')" >> "$OUTPUT_FILE"
        echo "# Port,Status,Service" >> "$OUTPUT_FILE"
    fi

    # Scan
    local open_ports=()
    local scanned=0

    echo ""
    echo -e "${CYAN}Scanning...${NC}"
    echo ""

    for port in "${ports[@]}"; do
        scanned=$((scanned + 1))

        # Progress indicator
        if (( total_ports > 100 && scanned % 100 == 0 )); then
            echo -ne "\r  Progress: $scanned / $total_ports ports scanned..."
        fi

        if scan_port "$host" "$port"; then
            local service=$(get_service_name "$port")
            open_ports+=($port)
            log_open "Port $port ($service)"

            if [[ -n "$OUTPUT_FILE" ]]; then
                echo "$port,open,$service" >> "$OUTPUT_FILE"
            fi
        else
            log_closed "Port $port"

            if [[ -n "$OUTPUT_FILE" ]] && [[ "$VERBOSE" == "true" ]]; then
                echo "$port,closed,-" >> "$OUTPUT_FILE"
            fi
        fi
    done

    # Clear progress line
    if (( total_ports > 100 )); then
        echo -ne "\r                                                          \r"
    fi

    # Résumé
    echo ""
    echo -e "${CYAN}───────────────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}  RÉSUMÉ${NC}"
    echo -e "${CYAN}───────────────────────────────────────────────────────────${NC}"
    echo -e "  Ports scannés: $total_ports"
    echo -e "  Ports ouverts: ${#open_ports[@]}"

    if [[ ${#open_ports[@]} -gt 0 ]]; then
        echo ""
        echo -e "  ${GREEN}Ports ouverts:${NC}"
        printf "    %-8s %-15s\n" "PORT" "SERVICE"
        printf "    %-8s %-15s\n" "----" "-------"
        for port in "${open_ports[@]}"; do
            printf "    %-8s %-15s\n" "$port" "$(get_service_name "$port")"
        done
    fi

    if [[ -n "$OUTPUT_FILE" ]]; then
        echo ""
        log_info "Résultats sauvegardés dans: $OUTPUT_FILE"
    fi

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

main "$@"
```

---

## Utilisation

```bash
# Rendre exécutable
chmod +x port-scanner.sh

# Scanner les ports courants
./port-scanner.sh 192.168.1.1

# Scanner des ports spécifiques
./port-scanner.sh example.com 22,80,443,3306

# Scanner une plage
./port-scanner.sh 10.0.0.1 1-1024

# Avec options
./port-scanner.sh -t 2 -v -o results.txt server.local
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
  PORT SCANNER
═══════════════════════════════════════════════════════════
  Target: 192.168.1.100
  Ports: 20
  Timeout: 1s
  Date: 2024-01-15 14:30:22
───────────────────────────────────────────────────────────

Scanning...

[OPEN] Port 22 (SSH)
[OPEN] Port 80 (HTTP)
[OPEN] Port 443 (HTTPS)
[OPEN] Port 3306 (MySQL)

───────────────────────────────────────────────────────────
  RÉSUMÉ
───────────────────────────────────────────────────────────
  Ports scannés: 20
  Ports ouverts: 4

  Ports ouverts:
    PORT     SERVICE
    ----     -------
    22       SSH
    80       HTTP
    443      HTTPS
    3306     MySQL

═══════════════════════════════════════════════════════════
```

---

## Note de Sécurité

!!! warning "Usage Responsable"
    Ce script est destiné à des fins éducatives et d'audit de vos propres systèmes.
    Scanner des systèmes sans autorisation est illégal.

---

## Voir Aussi

- [check-connectivity.sh](check-connectivity.md)
- [dns-lookup.sh](dns-lookup.md)
