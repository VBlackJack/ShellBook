---
tags:
  - scripts
  - bash
  - bind
  - dns
  - linux
---

# check-bind.sh

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète d'un serveur DNS BIND.

---

## Description

Ce script vérifie l'état d'un serveur BIND :
- Service named et processus
- Configuration syntaxique
- Zones et fichiers de zone
- Résolution (forward et reverse)
- DNSSEC
- Statistiques et logs

---

## Script

```bash
#!/bin/bash
#===============================================================================
# check-bind.sh - Vérification santé serveur DNS BIND
#===============================================================================
# Usage: ./check-bind.sh [-c config] [-d test_domain]
#===============================================================================

set -o pipefail

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

# Paramètres par défaut
NAMED_CONF="/etc/bind/named.conf"
[[ ! -f "$NAMED_CONF" ]] && NAMED_CONF="/etc/named.conf"
TEST_DOMAINS=("google.com" "cloudflare.com")
DNS_SERVER="127.0.0.1"

# Compteurs
TOTAL=0
PASSED=0
WARNINGS=0
FAILED=0

#===============================================================================
# Fonctions
#===============================================================================
usage() {
    cat << EOF
Usage: $0 [options]

Options:
    -c CONFIG    Chemin named.conf
    -s SERVER    Serveur DNS à tester (défaut: 127.0.0.1)
    -d DOMAIN    Domaine de test (peut être répété)
    --help       Afficher cette aide
EOF
    exit 0
}

check_result() {
    local name="$1"
    local status="$2"
    local message="$3"

    ((TOTAL++))

    case $status in
        pass)
            echo -e "${GREEN}[OK]  ${NC} $name${GRAY} - $message${NC}"
            ((PASSED++))
            ;;
        warn)
            echo -e "${YELLOW}[WARN]${NC} $name${GRAY} - $message${NC}"
            ((WARNINGS++))
            ;;
        fail)
            echo -e "${RED}[FAIL]${NC} $name${GRAY} - $message${NC}"
            ((FAILED++))
            ;;
        info)
            echo -e "${CYAN}[INFO]${NC} $name${GRAY} - $message${NC}"
            ;;
    esac
}

#===============================================================================
# Parse arguments
#===============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        -c) NAMED_CONF="$2"; shift 2 ;;
        -s) DNS_SERVER="$2"; shift 2 ;;
        -d) TEST_DOMAINS+=("$2"); shift 2 ;;
        --help) usage ;;
        *) echo "Option inconnue: $1"; usage ;;
    esac
done

#===============================================================================
# Main
#===============================================================================
echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${GREEN}  BIND DNS SERVER HEALTH CHECK${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo "  Config: $NAMED_CONF"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${CYAN}-----------------------------------------------------------------${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Service BIND
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Service BIND]${NC}"

if systemctl is-active --quiet named 2>/dev/null; then
    check_result "Service named" "pass" "Running"
elif systemctl is-active --quiet bind9 2>/dev/null; then
    check_result "Service bind9" "pass" "Running"
elif pgrep -x named > /dev/null; then
    check_result "Process named" "pass" "Running"
else
    check_result "Service BIND" "fail" "Not running"
fi

# Version
bind_version=$(named -v 2>/dev/null | head -1)
if [[ -n "$bind_version" ]]; then
    echo -e "       ${GRAY}$bind_version${NC}"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Connectivité DNS
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Connectivité]${NC}"

# Port 53 TCP
if nc -z -w 3 "$DNS_SERVER" 53 2>/dev/null; then
    check_result "Port 53/TCP" "pass" "Open"
else
    check_result "Port 53/TCP" "fail" "Closed"
fi

# Port 53 UDP (via dig)
udp_test=$(dig @"$DNS_SERVER" +short +time=3 version.bind txt chaos 2>/dev/null)
if [[ -n "$udp_test" ]] || dig @"$DNS_SERVER" +short +time=3 localhost 2>/dev/null | grep -q .; then
    check_result "Port 53/UDP" "pass" "Responding"
else
    check_result "Port 53/UDP" "warn" "No response"
fi

# Port 953 (rndc)
if nc -z -w 3 "$DNS_SERVER" 953 2>/dev/null; then
    check_result "Port 953 (rndc)" "pass" "Open"
else
    check_result "Port 953 (rndc)" "info" "Not accessible"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: Configuration
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Configuration]${NC}"

# Fichier de config
if [[ -f "$NAMED_CONF" ]]; then
    check_result "Config file" "pass" "$NAMED_CONF"
else
    check_result "Config file" "fail" "Not found: $NAMED_CONF"
fi

# Vérification syntaxe
config_check=$(named-checkconf "$NAMED_CONF" 2>&1)
if [[ -z "$config_check" ]]; then
    check_result "Configuration syntax" "pass" "Valid"
else
    check_result "Configuration syntax" "fail" "Errors found"
    echo -e "       ${RED}$config_check${NC}"
fi

# Options importantes
if grep -q "recursion yes" "$NAMED_CONF" 2>/dev/null; then
    check_result "Recursion" "info" "Enabled"

    # Vérifier ACL
    if grep -qE "allow-recursion|allow-query" "$NAMED_CONF" 2>/dev/null; then
        check_result "Recursion ACL" "pass" "Configured"
    else
        check_result "Recursion ACL" "warn" "Open recursion?"
    fi
else
    check_result "Recursion" "info" "Disabled"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Zones
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Zones DNS]${NC}"

# Lister les zones depuis la config
zones=$(grep -E "^\s*zone\s+" "$NAMED_CONF" /etc/bind/named.conf.local /etc/named.rfc1912.zones 2>/dev/null | \
    grep -v "in-addr.arpa\|ip6.arpa\|localhost\|0.0.127\|255\|hint" | \
    grep -oP 'zone\s+"\K[^"]+' | sort -u)

zone_count=$(echo "$zones" | grep -c . || echo 0)
check_result "Configured zones" "info" "$zone_count zone(s)"

# Vérifier chaque zone
if [[ -n "$zones" ]]; then
    while read -r zone; do
        [[ -z "$zone" ]] && continue

        # Trouver le fichier de zone
        zone_file=$(grep -A5 "zone \"$zone\"" "$NAMED_CONF" /etc/bind/named.conf.local 2>/dev/null | \
            grep -oP 'file\s+"\K[^"]+' | head -1)

        if [[ -n "$zone_file" ]]; then
            # Chemin absolu si nécessaire
            [[ ! "$zone_file" =~ ^/ ]] && zone_file="/var/cache/bind/$zone_file"
            [[ ! -f "$zone_file" ]] && zone_file="/var/named/$zone_file"

            if [[ -f "$zone_file" ]]; then
                # Vérifier la syntaxe de la zone
                zone_check=$(named-checkzone "$zone" "$zone_file" 2>&1)
                if echo "$zone_check" | grep -q "OK"; then
                    serial=$(echo "$zone_check" | grep -oP 'serial \K\d+')
                    check_result "Zone $zone" "pass" "Serial: $serial"
                else
                    check_result "Zone $zone" "fail" "Invalid"
                fi
            else
                check_result "Zone $zone" "warn" "Zone file not found"
            fi
        fi
    done <<< "$zones"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Résolution forward
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Résolution Forward]${NC}"

for domain in "${TEST_DOMAINS[@]}"; do
    start_time=$(date +%s%N)
    result=$(dig @"$DNS_SERVER" +short +time=5 "$domain" A 2>/dev/null | head -1)
    end_time=$(date +%s%N)
    query_time=$(( (end_time - start_time) / 1000000 ))

    if [[ -n "$result" ]]; then
        if [[ $query_time -gt 2000 ]]; then
            check_result "Resolve $domain" "warn" "${query_time}ms (slow)"
        else
            check_result "Resolve $domain" "pass" "${query_time}ms"
        fi
        echo -e "       ${GRAY}$result${NC}"
    else
        check_result "Resolve $domain" "fail" "No response"
    fi
done

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Résolution reverse
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Résolution Reverse]${NC}"

# Tester reverse pour 8.8.8.8
reverse_result=$(dig @"$DNS_SERVER" +short -x 8.8.8.8 2>/dev/null | head -1)
if [[ -n "$reverse_result" ]]; then
    check_result "Reverse 8.8.8.8" "pass" "$reverse_result"
else
    check_result "Reverse 8.8.8.8" "warn" "No response"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Forwarders
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Forwarders]${NC}"

forwarders=$(grep -A10 "forwarders" "$NAMED_CONF" 2>/dev/null | \
    grep -oP '\d+\.\d+\.\d+\.\d+' | head -5)

if [[ -n "$forwarders" ]]; then
    check_result "Forwarders configured" "info" "$(echo "$forwarders" | wc -l) server(s)"

    while read -r fw; do
        [[ -z "$fw" ]] && continue
        fw_test=$(dig @"$fw" +short +time=3 google.com 2>/dev/null | head -1)
        if [[ -n "$fw_test" ]]; then
            check_result "Forwarder $fw" "pass" "Responding"
        else
            check_result "Forwarder $fw" "fail" "Not responding"
        fi
    done <<< "$forwarders"
else
    check_result "Forwarders" "info" "Not configured (root hints)"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: DNSSEC
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[DNSSEC]${NC}"

# Validation DNSSEC activée
if grep -q "dnssec-validation" "$NAMED_CONF" 2>/dev/null; then
    dnssec_val=$(grep "dnssec-validation" "$NAMED_CONF" | head -1)
    if echo "$dnssec_val" | grep -q "auto\|yes"; then
        check_result "DNSSEC validation" "pass" "Enabled"

        # Tester validation
        dnssec_test=$(dig @"$DNS_SERVER" +dnssec +short dnssec-failed.org A 2>/dev/null)
        if [[ -z "$dnssec_test" ]] || echo "$dnssec_test" | grep -qi "servfail"; then
            check_result "DNSSEC test" "pass" "Working (rejects invalid)"
        else
            check_result "DNSSEC test" "warn" "May not validate properly"
        fi
    else
        check_result "DNSSEC validation" "info" "Disabled"
    fi
else
    check_result "DNSSEC validation" "info" "Not configured"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 9: Statistiques (rndc)
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Statistiques]${NC}"

if command -v rndc > /dev/null 2>&1; then
    rndc_status=$(rndc status 2>&1)

    if echo "$rndc_status" | grep -q "version:"; then
        check_result "rndc status" "pass" "Accessible"

        # Extraire quelques stats
        queries=$(echo "$rndc_status" | grep "recursive clients" | awk '{print $NF}')
        [[ -n "$queries" ]] && echo -e "       ${GRAY}Recursive clients: $queries${NC}"

        xfers=$(echo "$rndc_status" | grep "xfers running" | awk '{print $NF}')
        [[ -n "$xfers" ]] && echo -e "       ${GRAY}Zone transfers: $xfers${NC}"
    else
        check_result "rndc status" "warn" "Not accessible"
    fi
else
    check_result "rndc" "info" "Not installed"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 10: Logs
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Logs]${NC}"

# Trouver le fichier de log
log_files=("/var/log/named/named.log" "/var/log/named.log" "/var/log/bind.log" "/var/log/messages")

for log_file in "${log_files[@]}"; do
    if [[ -f "$log_file" ]]; then
        log_size=$(du -h "$log_file" 2>/dev/null | awk '{print $1}')
        check_result "Log file" "info" "$log_file ($log_size)"

        # Erreurs récentes
        recent_errors=$(tail -500 "$log_file" 2>/dev/null | grep -ci "error\|failed\|refused" || echo 0)
        if [[ $recent_errors -gt 50 ]]; then
            check_result "Recent errors" "warn" "$recent_errors"
        else
            check_result "Recent errors" "pass" "$recent_errors"
        fi

        # Dernières erreurs
        echo -e "       ${GRAY}Recent issues:${NC}"
        tail -100 "$log_file" 2>/dev/null | grep -iE "error|failed|refused" | tail -3 | \
            while read line; do
                echo -e "       ${GRAY}  ${line:0:70}...${NC}"
            done

        break
    fi
done

# ═══════════════════════════════════════════════════════════════════
# RÉSUMÉ
# ═══════════════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${GREEN}  RÉSUMÉ${NC}"
echo -e "${CYAN}=================================================================${NC}"

echo "  Checks: $TOTAL total"
echo -e "    - ${GREEN}Passed: $PASSED${NC}"
echo -e "    - ${YELLOW}Warnings: $WARNINGS${NC}"
echo -e "    - ${RED}Failed: $FAILED${NC}"

echo ""
if [[ $FAILED -gt 0 ]]; then
    echo -e "  ${RED}BIND STATUS: CRITICAL${NC}"
    exit 2
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${YELLOW}BIND STATUS: DEGRADED${NC}"
    exit 1
else
    echo -e "  ${GREEN}BIND STATUS: HEALTHY${NC}"
    exit 0
fi
```

---

## Utilisation

```bash
# Vérification basique
./check-bind.sh

# Config personnalisée
./check-bind.sh -c /etc/named.conf

# Serveur distant
./check-bind.sh -s 192.168.1.1

# Domaines de test supplémentaires
./check-bind.sh -d internal.domain.local -d example.com
```

---

## Voir Aussi

- [check-ldap.sh](check-ldap.md)
- [check-postfix.sh](check-postfix.md)
