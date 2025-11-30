---
tags:
  - scripts
  - bash
  - services
  - monitoring
---

# health-check.sh

:material-star::material-star: **Niveau : Intermédiaire**

Vérification de la santé des services et applications.

---

## Description

Ce script vérifie la santé de l'infrastructure :
- Services systemd
- Endpoints HTTP
- Ports réseau
- Disk space et mémoire
- Rapport global

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: health-check.sh
# Description: Service health checker
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

# Counters
CHECKS_PASSED=0
CHECKS_FAILED=0
CHECKS_WARN=0

# Configuration
CONFIG_FILE=""
QUIET=false

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Vérification de la santé des services.

Options:
    -c, --config FILE   Configuration file
    -q, --quiet         Mode silencieux (erreurs uniquement)
    -h, --help          Show this help

Configuration:
    Si pas de ficyesterday config, vérifie les services courants.
    Format du ficyesterday config:

    # Services systemd
    service:nginx
    service:mysql

    # Endpoints HTTP
    http:http://localhost/health
    http:https://api.example.com/status

    # Ports TCP
    port:localhost:3306
    port:192.168.1.1:22

    # Disque (chemin:seuil%)
    disk:/home:90
    disk:/:85

Examples:
    $(basename "$0")                    # Vérifications par défaut
    $(basename "$0") -c checks.conf     # Avec configuration
    $(basename "$0") -q                 # Mode silencieux
EOF
}

log_pass() {
    CHECKS_PASSED=$((CHECKS_PASSED + 1))
    [[ "$QUIET" == "false" ]] && echo -e "${GREEN}[PASS]${NC} $1"
}

log_fail() {
    CHECKS_FAILED=$((CHECKS_FAILED + 1))
    echo -e "${RED}[FAIL]${NC} $1"
}

log_warn() {
    CHECKS_WARN=$((CHECKS_WARN + 1))
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_header() {
    [[ "$QUIET" == "false" ]] && echo -e "\n${CYAN}▶ $1${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# VÉRIFICATIONS
# ══════════════════════════════════════════════════════════════════════════════
check_service() {
    local service=$1

    if systemctl is-active "$service" &>/dev/null; then
        log_pass "Service $service: running"
        return 0
    else
        log_fail "Service $service: not running"
        return 1
    fi
}

check_http() {
    local url=$1
    local timeout=${2:-5}

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "$timeout" "$url" 2>/dev/null || echo "000")

    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "204" ]]; then
        log_pass "HTTP $url: $http_code"
        return 0
    elif [[ "$http_code" == "301" ]] || [[ "$http_code" == "302" ]]; then
        log_warn "HTTP $url: $http_code (redirect)"
        return 0
    else
        log_fail "HTTP $url: $http_code"
        return 1
    fi
}

check_port() {
    local host=$1
    local port=$2
    local timeout=${3:-3}

    if timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
        log_pass "Port $host:$port: open"
        return 0
    else
        log_fail "Port $host:$port: closed"
        return 1
    fi
}

check_disk() {
    local path=$1
    local threshold=${2:-90}

    if [[ ! -d "$path" ]]; then
        log_warn "Disk $path: path not found"
        return 1
    fi

    local usage=$(df "$path" 2>/dev/null | awk 'NR==2 {print $5}' | tr -d '%')

    if (( usage >= threshold )); then
        log_fail "Disk $path: ${usage}% (threshold: ${threshold}%)"
        return 1
    elif (( usage >= threshold - 10 )); then
        log_warn "Disk $path: ${usage}% (approaching ${threshold}%)"
        return 0
    else
        log_pass "Disk $path: ${usage}%"
        return 0
    fi
}

check_memory() {
    local threshold=${1:-90}

    local usage=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2*100}')

    if (( usage >= threshold )); then
        log_fail "Memory: ${usage}% (threshold: ${threshold}%)"
        return 1
    elif (( usage >= threshold - 10 )); then
        log_warn "Memory: ${usage}%"
        return 0
    else
        log_pass "Memory: ${usage}%"
        return 0
    fi
}

check_load() {
    local threshold=${1:-$(nproc)}

    local load=$(cat /proc/loadavg | awk '{print $1}')
    local load_int=${load%.*}

    if (( load_int >= threshold )); then
        log_fail "Load: $load (threshold: $threshold)"
        return 1
    else
        log_pass "Load: $load"
        return 0
    fi
}

check_process() {
    local process=$1

    if pgrep -x "$process" &>/dev/null; then
        log_pass "Process $process: running"
        return 0
    else
        log_fail "Process $process: not running"
        return 1
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# EXÉCUTION
# ══════════════════════════════════════════════════════════════════════════════
run_default_checks() {
    print_header "SYSTÈME"
    check_memory 90
    check_load
    check_disk "/" 85

    print_header "SERVICES CRITIQUES"
    local services=("sshd" "cron" "rsyslog" "systemd-journald")
    for svc in "${services[@]}"; do
        if systemctl list-units --type=service --all 2>/dev/null | grep -q "$svc"; then
            check_service "$svc"
        fi
    done

    # Services web courants
    for svc in "nginx" "apache2" "httpd"; do
        if systemctl list-units --type=service --all 2>/dev/null | grep -q "$svc"; then
            check_service "$svc" || true
        fi
    done

    # Bases de données
    for svc in "mysql" "mariadb" "postgresql" "redis" "mongodb"; do
        if systemctl list-units --type=service --all 2>/dev/null | grep -q "$svc"; then
            check_service "$svc" || true
        fi
    done

    print_header "CONNECTIVITÉ"
    check_port "127.0.0.1" "22" || true

    # Check localhost web si service actif
    if systemctl is-active nginx &>/dev/null || systemctl is-active apache2 &>/dev/null; then
        check_http "http://localhost/" || true
    fi
}

run_config_checks() {
    local config=$1

    if [[ ! -f "$config" ]]; then
        echo "Configuration file not found: $config"
        exit 1
    fi

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Ignorer commentaires et lignes vides
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "$line" ]] && continue

        local type=${line%%:*}
        local value=${line#*:}

        case "$type" in
            service)
                check_service "$value" || true
                ;;
            http)
                check_http "$value" || true
                ;;
            port)
                local host=${value%%:*}
                local port=${value##*:}
                check_port "$host" "$port" || true
                ;;
            disk)
                local path=${value%%:*}
                local threshold=${value##*:}
                check_disk "$path" "$threshold" || true
                ;;
            memory)
                check_memory "$value" || true
                ;;
            process)
                check_process "$value" || true
                ;;
            *)
                echo "Type inconnu: $type"
                ;;
        esac
    done < "$config"
}

show_summary() {
    local total=$((CHECKS_PASSED + CHECKS_FAILED + CHECKS_WARN))

    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  RÉSUMÉ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  ${GREEN}Passed:${NC}  $CHECKS_PASSED"
    echo -e "  ${YELLOW}Warnings:${NC} $CHECKS_WARN"
    echo -e "  ${RED}Failed:${NC}  $CHECKS_FAILED"
    echo -e "  ${CYAN}Total:${NC}   $total"
    echo ""

    if (( CHECKS_FAILED > 0 )); then
        echo -e "  ${RED}${BOLD}⚠ HEALTH CHECK FAILED${NC}"
        return 2
    elif (( CHECKS_WARN > 0 )); then
        echo -e "  ${YELLOW}${BOLD}⚡ HEALTH CHECK WARNING${NC}"
        return 1
    else
        echo -e "  ${GREEN}${BOLD}✓ HEALTH CHECK PASSED${NC}"
        return 0
    fi
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--config)
                CONFIG_FILE="$2"
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

    if [[ "$QUIET" == "false" ]]; then
        echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}${GREEN}          HEALTH CHECK${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
        echo -e "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo -e "  Host: $(hostname)"
    fi

    if [[ -n "$CONFIG_FILE" ]]; then
        run_config_checks "$CONFIG_FILE"
    else
        run_default_checks
    fi

    show_summary
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x health-check.sh

# Vérifications par défaut
./health-check.sh

# Avec ficyesterday de configuration
./health-check.sh -c /etc/health-checks.conf

# Mode silencieux (pour cron)
./health-check.sh -q
```

---

## Ficyesterday de Configuration

Exemple `checks.conf`:

```bash
# Services
service:nginx
service:mysql
service:redis

# Endpoints HTTP
http:http://localhost/health
http:https://api.example.com/status

# Ports
port:localhost:3306
port:localhost:6379
port:db.example.com:5432

# Disques (chemin:seuil)
disk:/:85
disk:/home:90
disk:/var:80

# Memory (seuil)
memory:85

# Processus
process:java
process:node
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
          HEALTH CHECK
═══════════════════════════════════════════════════════════
  Date: 2024-01-15 14:30:22
  Host: webserver01

▶ SYSTÈME
[PASS] Memory: 67%
[PASS] Load: 0.45
[PASS] Disk /: 54%

▶ SERVICES CRITIQUES
[PASS] Service sshd: running
[PASS] Service cron: running
[PASS] Service nginx: running
[PASS] Service mysql: running

▶ CONNECTIVITÉ
[PASS] Port 127.0.0.1:22: open
[PASS] HTTP http://localhost/: 200

═══════════════════════════════════════════════════════════
  RÉSUMÉ
═══════════════════════════════════════════════════════════
  Passed:  8
  Warnings: 0
  Failed:  0
  Total:   8

  ✓ HEALTH CHECK PASSED
```

---

## Intégration Cron

```bash
# Vérification toutes les 5 minutes
*/5 * * * * /opt/scripts/health-check.sh -q -c /etc/health.conf || echo "Health check failed" | mail -s "Alert" admin@example.com
```

---

## Voir Aussi

- [service-manager.sh](service-manager.md)
- [monitor-resources.sh](monitor-resources.md)
