---
tags:
  - scripts
  - bash
  - réseau
  - dns
---

# dns-lookup.sh

:material-star: **Niveau : Débutant**

Résolution DNS avancée avec plusieurs types de requêtes.

---

## Description

Ce script effectue des requêtes DNS détaillées :
- Résolution A, AAAA, MX, NS, TXT, CNAME
- Interrogation de serveurs DNS spécifiques
- Reverse DNS lookup
- Vérification de propagation

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Utilisateur standard (pas de sudo requis)
- **Dépendances** : `dig`, `nslookup`

---

## Cas d'Usage

- **Diagnostic DNS** : Résolution rapide de problèmes de connectivité liés au DNS
- **Validation de propagation** : Vérification de la propagation DNS après changement de zone
- **Troubleshooting email** : Analyse des enregistrements MX pour problèmes d'envoi mail
- **Audit de zone** : Vérification complète de la configuration DNS d'un domaine

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: dns-lookup.sh
# Description: Advanced DNS lookup
# Author: ShellBook
# Version: 1.0
#===============================================================================

set -euo pipefail

# Colors
readonly GREEN='\033[0;32m'
readonly CYAN='\033[0;36m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly NC='\033[0m'

# Configuration
DNS_SERVER=""
RECORD_TYPE="all"

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] DOMAIN

Résolution DNS avancée.

Arguments:
    DOMAIN          Domaine à résoudre

Options:
    -t, --type TYPE     Type d'enregistrement (A, AAAA, MX, NS, TXT, CNAME, SOA, PTR, all)
    -s, --server DNS    Server DNS à utiliser
    -r, --reverse IP    Reverse DNS lookup
    -p, --propagation   Vérifier la propagation DNS
    -h, --help          Show this help

Examples:
    $(basename "$0") google.com                    # Tous les enregistrements
    $(basename "$0") -t MX gmail.com               # Enregistrements MX
    $(basename "$0") -s 8.8.8.8 example.com        # Server DNS spécifique
    $(basename "$0") -r 8.8.8.8                    # Reverse lookup
    $(basename "$0") -p example.com                # Propagation
EOF
}

print_header() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

print_section() {
    echo -e "\n${YELLOW}▶ $1${NC}"
}

query_dns() {
    local domain=$1
    local type=$2
    local server=${3:-}

    local cmd="dig +short"
    [[ -n "$server" ]] && cmd="$cmd @$server"
    cmd="$cmd $domain $type"

    eval "$cmd" 2>/dev/null
}

query_dns_full() {
    local domain=$1
    local type=$2
    local server=${3:-}

    local cmd="dig +noall +answer"
    [[ -n "$server" ]] && cmd="$cmd @$server"
    cmd="$cmd $domain $type"

    eval "$cmd" 2>/dev/null
}

lookup_a() {
    local domain=$1
    print_section "A Records (IPv4)"

    local result=$(query_dns "$domain" "A" "$DNS_SERVER")
    if [[ -n "$result" ]]; then
        echo "$result" | while read -r ip; do
            echo -e "  ${GREEN}✓${NC} $ip"
        done
    else
        echo -e "  ${RED}✗${NC} Aucun enregistrement A"
    fi
}

lookup_aaaa() {
    local domain=$1
    print_section "AAAA Records (IPv6)"

    local result=$(query_dns "$domain" "AAAA" "$DNS_SERVER")
    if [[ -n "$result" ]]; then
        echo "$result" | while read -r ip; do
            echo -e "  ${GREEN}✓${NC} $ip"
        done
    else
        echo -e "  ${YELLOW}○${NC} Aucun enregistrement AAAA"
    fi
}

lookup_mx() {
    local domain=$1
    print_section "MX Records (Mail)"

    local result=$(query_dns "$domain" "MX" "$DNS_SERVER")
    if [[ -n "$result" ]]; then
        echo "$result" | sort -n | while read -r line; do
            local priority=$(echo "$line" | awk '{print $1}')
            local server=$(echo "$line" | awk '{print $2}')
            echo -e "  ${GREEN}✓${NC} [$priority] $server"
        done
    else
        echo -e "  ${YELLOW}○${NC} Aucun enregistrement MX"
    fi
}

lookup_ns() {
    local domain=$1
    print_section "NS Records (Name Servers)"

    local result=$(query_dns "$domain" "NS" "$DNS_SERVER")
    if [[ -n "$result" ]]; then
        echo "$result" | while read -r ns; do
            local ns_ip=$(query_dns "$ns" "A")
            echo -e "  ${GREEN}✓${NC} $ns (${ns_ip:-N/A})"
        done
    else
        echo -e "  ${RED}✗${NC} Aucun enregistrement NS"
    fi
}

lookup_txt() {
    local domain=$1
    print_section "TXT Records"

    local result=$(query_dns "$domain" "TXT" "$DNS_SERVER")
    if [[ -n "$result" ]]; then
        echo "$result" | while read -r txt; do
            # Tronquer si trop long
            if [[ ${#txt} -gt 80 ]]; then
                echo -e "  ${GREEN}✓${NC} ${txt:0:77}..."
            else
                echo -e "  ${GREEN}✓${NC} $txt"
            fi
        done
    else
        echo -e "  ${YELLOW}○${NC} Aucun enregistrement TXT"
    fi
}

lookup_cname() {
    local domain=$1
    print_section "CNAME Record"

    local result=$(query_dns "$domain" "CNAME" "$DNS_SERVER")
    if [[ -n "$result" ]]; then
        echo -e "  ${GREEN}✓${NC} $result"
    else
        echo -e "  ${YELLOW}○${NC} Pas de CNAME (enregistrement direct)"
    fi
}

lookup_soa() {
    local domain=$1
    print_section "SOA Record"

    local result=$(query_dns_full "$domain" "SOA" "$DNS_SERVER")
    if [[ -n "$result" ]]; then
        echo "$result" | awk '{
            printf "  Primary NS: %s\n", $5
            printf "  Admin: %s\n", $6
            printf "  Serial: %s\n", $7
            printf "  Refresh: %s\n", $8
            printf "  Retry: %s\n", $9
            printf "  Expire: %s\n", $10
            printf "  TTL: %s\n", $11
        }'
    else
        echo -e "  ${RED}✗${NC} Aucun enregistrement SOA"
    fi
}

reverse_lookup() {
    local ip=$1
    print_header "REVERSE DNS LOOKUP: $ip"

    local result=$(query_dns "$ip" "PTR" "$DNS_SERVER" 2>/dev/null || dig +short -x "$ip" 2>/dev/null)
    if [[ -n "$result" ]]; then
        echo -e "\n  ${GREEN}✓${NC} $ip -> $result"
    else
        echo -e "\n  ${RED}✗${NC} Pas de PTR pour $ip"
    fi
}

check_propagation() {
    local domain=$1
    print_header "DNS PROPAGATION: $domain"

    local dns_servers=(
        "8.8.8.8:Google"
        "1.1.1.1:Cloudflare"
        "9.9.9.9:Quad9"
        "208.67.222.222:OpenDNS"
        "8.26.56.26:Comodo"
    )

    echo ""
    printf "  %-20s %-15s %s\n" "DNS SERVER" "PROVIDER" "RESULT"
    printf "  %-20s %-15s %s\n" "----------" "--------" "------"

    for entry in "${dns_servers[@]}"; do
        local server=${entry%%:*}
        local name=${entry##*:}

        local result=$(query_dns "$domain" "A" "$server")
        if [[ -n "$result" ]]; then
            result=$(echo "$result" | head -1)
            echo -e "  ${GREEN}✓${NC} $server    $name    $result"
        else
            echo -e "  ${RED}✗${NC} $server    $name    N/A"
        fi
    done
}

main() {
    local domain=""
    local reverse_ip=""
    local propagation=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--type)
                RECORD_TYPE="$2"
                shift 2
                ;;
            -s|--server)
                DNS_SERVER="$2"
                shift 2
                ;;
            -r|--reverse)
                reverse_ip="$2"
                shift 2
                ;;
            -p|--propagation)
                propagation=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                domain="$1"
                shift
                ;;
        esac
    done

    # Reverse lookup
    if [[ -n "$reverse_ip" ]]; then
        reverse_lookup "$reverse_ip"
        exit 0
    fi

    # Propagation check
    if [[ "$propagation" == "true" ]]; then
        if [[ -z "$domain" ]]; then
            echo "Error: Domaine requis pour vérification propagation"
            exit 1
        fi
        check_propagation "$domain"
        exit 0
    fi

    # Validation
    if [[ -z "$domain" ]]; then
        echo "Error: Domaine requis"
        usage
        exit 1
    fi

    # Header
    print_header "DNS LOOKUP: $domain"
    [[ -n "$DNS_SERVER" ]] && echo -e "  Using DNS Server: $DNS_SERVER"

    # Lookup par type
    case "${RECORD_TYPE,,}" in
        a)      lookup_a "$domain" ;;
        aaaa)   lookup_aaaa "$domain" ;;
        mx)     lookup_mx "$domain" ;;
        ns)     lookup_ns "$domain" ;;
        txt)    lookup_txt "$domain" ;;
        cname)  lookup_cname "$domain" ;;
        soa)    lookup_soa "$domain" ;;
        all|*)
            lookup_a "$domain"
            lookup_aaaa "$domain"
            lookup_cname "$domain"
            lookup_mx "$domain"
            lookup_ns "$domain"
            lookup_txt "$domain"
            lookup_soa "$domain"
            ;;
    esac

    echo ""
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x dns-lookup.sh

# Tous les enregistrements
./dns-lookup.sh google.com

# Type spécifique
./dns-lookup.sh -t MX gmail.com
./dns-lookup.sh -t A example.com

# Server DNS spécifique
./dns-lookup.sh -s 8.8.8.8 example.com

# Reverse lookup
./dns-lookup.sh -r 8.8.8.8

# Check la propagation
./dns-lookup.sh -p example.com
```

---

## Sortie Exemple

```text
═══════════════════════════════════════════════════════════
  DNS LOOKUP: github.com
═══════════════════════════════════════════════════════════

▶ A Records (IPv4)
  ✓ 140.82.112.4

▶ AAAA Records (IPv6)
  ○ Aucun enregistrement AAAA

▶ CNAME Record
  ○ Pas de CNAME (enregistrement direct)

▶ MX Records (Mail)
  ✓ [1] aspmx.l.google.com.
  ✓ [5] alt1.aspmx.l.google.com.
  ✓ [5] alt2.aspmx.l.google.com.

▶ NS Records (Name Servers)
  ✓ dns1.p08.nsone.net. (198.51.44.8)
  ✓ dns2.p08.nsone.net. (198.51.45.8)
  ✓ ns-1283.awsdns-32.org. (205.251.197.3)
  ✓ ns-1707.awsdns-21.co.uk. (205.251.198.171)

▶ TXT Records
  ✓ "v=spf1 include:_spf.google.com include:servers.mcsv.net ~all"
  ✓ "MS=ms58704441"

▶ SOA Record
  Primary NS: dns1.p08.nsone.net.
  Admin: hostmaster.nsone.net.
  Serial: 1705317600
  Refresh: 43200
  Retry: 7200
  Expire: 1209600
  TTL: 3600
```

---

## Voir Aussi

- [check-connectivity.sh](check-connectivity.md)
- [port-scanner.sh](port-scanner.md)
