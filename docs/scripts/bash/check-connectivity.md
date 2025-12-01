---
tags:
  - scripts
  - bash
  - réseau
  - diagnostic
---

# check-connectivity.sh

:material-star: **Niveau : Débutant**

Test de connectivité réseau avec diagnostic complet.

---

## Description

Ce script vérifie la connectivité réseau :
- Test de la passerelle locale
- Test DNS
- Test de connexion Internet
- Latence et perte de paquets
- Rapport détaillé

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Utilisateur standard (pas de sudo requis)
- **Dépendances** : `ping`, `ip`, `nslookup`, `curl` (optionnel)

---

## Cas d'Usage

- **Diagnostic de connexion** : Test rapide de la connectivité lors de problèmes réseau
- **Validation post-installation** : Vérification que la configuration réseau fonctionne correctement
- **Monitoring automatisé** : Intégration dans des systèmes de surveillance pour alertes réseau
- **Troubleshooting utilisateur** : Script simple pour support technique de premier niveau

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: check-connectivity.sh
# Description: Network connectivity test
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
PING_COUNT=4
TIMEOUT=5
DNS_SERVERS=("8.8.8.8" "1.1.1.1")
TEST_HOSTS=("google.com" "cloudflare.com" "github.com")

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Test de connectivité réseau avec diagnostic.

Options:
    -c, --count NUM      Nombre de pings (default: 4)
    -t, --timeout SEC    Timeout en seconds (default: 5)
    -h, --help           Show this help

Examples:
    $(basename "$0")              # Test standard
    $(basename "$0") -c 10        # 10 pings par test
EOF
}

log_ok() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_fail() {
    echo -e "${RED}[✗]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_info() {
    echo -e "${CYAN}[i]${NC} $1"
}

print_header() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

get_default_gateway() {
    ip route | grep default | awk '{print $3}' | head -1
}

get_dns_servers() {
    grep "nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | head -2
}

test_ping() {
    local host=$1
    local name=$2

    local result
    if result=$(ping -c "$PING_COUNT" -W "$TIMEOUT" "$host" 2>&1); then
        local latency=$(echo "$result" | grep "avg" | awk -F'/' '{print $5}')
        local loss=$(echo "$result" | grep "packet loss" | awk '{print $6}')

        if [[ "$loss" == "0%" ]]; then
            log_ok "$name ($host): ${latency}ms avg, $loss loss"
            return 0
        else
            log_warn "$name ($host): ${latency}ms avg, $loss loss"
            return 1
        fi
    else
        log_fail "$name ($host): Non joignable"
        return 2
    fi
}

test_dns_resolution() {
    local domain=$1
    local dns_server=$2

    if nslookup "$domain" "$dns_server" &>/dev/null; then
        local ip=$(nslookup "$domain" "$dns_server" 2>/dev/null | grep -A1 "Name:" | grep "Address" | awk '{print $2}' | head -1)
        log_ok "Résolution DNS ($dns_server): $domain -> $ip"
        return 0
    else
        log_fail "Résolution DNS ($dns_server): Échec pour $domain"
        return 1
    fi
}

test_http() {
    local url=$1

    if command -v curl &>/dev/null; then
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout "$TIMEOUT" "https://$url" 2>/dev/null || echo "000")

        if [[ "$http_code" == "200" ]] || [[ "$http_code" == "301" ]] || [[ "$http_code" == "302" ]]; then
            log_ok "HTTP $url: Code $http_code"
            return 0
        else
            log_fail "HTTP $url: Code $http_code"
            return 1
        fi
    else
        log_warn "curl non disponible, test HTTP ignoré"
        return 0
    fi
}

check_local_network() {
    print_header "RÉSEAU LOCAL"

    local status=0

    # Interface active
    local interface=$(ip route | grep default | awk '{print $5}' | head -1)
    if [[ -n "$interface" ]]; then
        local ip_addr=$(ip addr show "$interface" | grep "inet " | awk '{print $2}')
        log_info "Interface active: $interface ($ip_addr)"
    else
        log_fail "Aucune interface réseau active"
        status=1
    fi

    # Passerelle
    local gateway=$(get_default_gateway)
    if [[ -n "$gateway" ]]; then
        test_ping "$gateway" "Passerelle" || status=1
    else
        log_fail "Aucune passerelle par défaut"
        status=1
    fi

    return $status
}

check_dns() {
    print_header "RÉSOLUTION DNS"

    local status=0
    local system_dns

    # DNS système
    system_dns=$(get_dns_servers)
    if [[ -n "$system_dns" ]]; then
        log_info "DNS configurés: $system_dns"

        for dns in $system_dns; do
            test_ping "$dns" "DNS $dns" || true
        done
    fi

    # Test de résolution
    for dns in "${DNS_SERVERS[@]}"; do
        test_dns_resolution "google.com" "$dns" || status=1
    done

    return $status
}

check_internet() {
    print_header "CONNECTIVITÉ INTERNET"

    local status=0

    # Ping hosts externes
    for host in "${TEST_HOSTS[@]}"; do
        test_ping "$host" "$host" || status=1
    done

    # Test HTTP
    echo ""
    log_info "Test HTTP/HTTPS:"
    for host in "${TEST_HOSTS[@]}"; do
        test_http "$host" || status=1
    done

    return $status
}

check_ports() {
    print_header "PORTS COURANTS"

    local test_host="google.com"
    local ports=("80:HTTP" "443:HTTPS" "53:DNS")

    for port_info in "${ports[@]}"; do
        local port=${port_info%%:*}
        local name=${port_info##*:}

        if timeout "$TIMEOUT" bash -c "echo >/dev/tcp/$test_host/$port" 2>/dev/null; then
            log_ok "Port $port ($name): Ouvert"
        else
            log_warn "Port $port ($name): Filtré ou fermé"
        fi
    done
}

show_network_info() {
    print_header "INFORMATIONS RÉSEAU"

    # IP publique
    if command -v curl &>/dev/null; then
        local public_ip
        public_ip=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "Non disponible")
        log_info "IP Publique: $public_ip"
    fi

    # Interfaces
    echo ""
    log_info "Interfaces réseau:"
    ip -4 addr show | grep -E "inet " | while read -r line; do
        local ip=$(echo "$line" | awk '{print $2}')
        local iface=$(echo "$line" | awk '{print $NF}')
        echo "    $iface: $ip"
    done
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--count)
                PING_COUNT="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
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

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}          DIAGNOSTIC DE CONNECTIVITÉ RÉSEAU               ${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  Host: $(hostname)"

    local global_status=0

    check_local_network || global_status=1
    check_dns || global_status=1
    check_internet || global_status=1
    check_ports || true
    show_network_info

    # Résumé
    print_header "RÉSUMÉ"
    if [[ $global_status -eq 0 ]]; then
        log_ok "Connectivité réseau: OK"
    else
        log_fail "Connectivité réseau: Problèmes détectés"
    fi

    exit $global_status
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x check-connectivity.sh

# Test standard
./check-connectivity.sh

# Plus de pings
./check-connectivity.sh -c 10

# Timeout plus long
./check-connectivity.sh -t 10
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
          DIAGNOSTIC DE CONNECTIVITÉ RÉSEAU
═══════════════════════════════════════════════════════════
  Date: 2024-01-15 14:30:22
  Host: workstation01

═══════════════════════════════════════════════════════════
  RÉSEAU LOCAL
═══════════════════════════════════════════════════════════
[i] Interface active: eth0 (192.168.1.100/24)
[✓] Passerelle (192.168.1.1): 0.845ms avg, 0% loss

═══════════════════════════════════════════════════════════
  RÉSOLUTION DNS
═══════════════════════════════════════════════════════════
[i] DNS configurés: 192.168.1.1
[✓] DNS 192.168.1.1 (192.168.1.1): 1.234ms avg, 0% loss
[✓] Résolution DNS (8.8.8.8): google.com -> 142.250.185.78
[✓] Résolution DNS (1.1.1.1): google.com -> 142.250.185.78

═══════════════════════════════════════════════════════════
  CONNECTIVITÉ INTERNET
═══════════════════════════════════════════════════════════
[✓] google.com (google.com): 12.345ms avg, 0% loss
[✓] cloudflare.com (cloudflare.com): 8.234ms avg, 0% loss
[✓] github.com (github.com): 45.678ms avg, 0% loss

[i] Test HTTP/HTTPS:
[✓] HTTP google.com: Code 200
[✓] HTTP cloudflare.com: Code 200
[✓] HTTP github.com: Code 200

═══════════════════════════════════════════════════════════
  PORTS COURANTS
═══════════════════════════════════════════════════════════
[✓] Port 80 (HTTP): Ouvert
[✓] Port 443 (HTTPS): Ouvert
[✓] Port 53 (DNS): Ouvert

═══════════════════════════════════════════════════════════
  INFORMATIONS RÉSEAU
═══════════════════════════════════════════════════════════
[i] IP Publique: 203.0.113.45

[i] Interfaces réseau:
    lo: 127.0.0.1/8
    eth0: 192.168.1.100/24

═══════════════════════════════════════════════════════════
  RÉSUMÉ
═══════════════════════════════════════════════════════════
[✓] Connectivité réseau: OK
```

---

## Voir Aussi

- [dns-lookup.sh](dns-lookup.md)
- [port-scanner.sh](port-scanner.md)
