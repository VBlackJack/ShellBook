---
tags:
  - scripts
  - bash
  - ldap
  - linux
  - infrastructure
---

# check-ldap.sh

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète d'un serveur LDAP/OpenLDAP.

---

## Description

Ce script vérifie l'état d'un serveur LDAP :
- Service slapd et connectivité
- Connexion anonyme et authentifiée
- Réplication (syncrepl)
- Recherches de base
- Certificats TLS
- Statistiques

---

## Prérequis

```bash
# Debian/Ubuntu
sudo apt install ldap-utils openssl

# RHEL/Rocky
sudo dnf install openldap-clients openssl
```

---

## Script

```bash
#!/bin/bash
#===============================================================================
# check-ldap.sh - Vérification santé serveur LDAP
#===============================================================================
# Usage: ./check-ldap.sh [-h host] [-p port] [-D binddn] [-w password] [-b basedn]
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
LDAP_HOST="localhost"
LDAP_PORT="389"
LDAP_BIND_DN=""
LDAP_BIND_PW=""
LDAP_BASE_DN=""
USE_TLS=false
LDAPS_PORT="636"

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
    -h HOST      Serveur LDAP (défaut: localhost)
    -p PORT      Port LDAP (défaut: 389)
    -D BINDDN    DN pour bind authentifié
    -w PASSWORD  Mot de passe bind
    -b BASEDN    Base DN pour recherches
    -s           Utiliser LDAPS (port 636)
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

detect_base_dn() {
    # Tenter de détecter le base DN via rootDSE
    local result
    result=$(ldapsearch -x -H "ldap://$LDAP_HOST:$LDAP_PORT" \
        -s base -b "" "(objectclass=*)" namingContexts 2>/dev/null | \
        grep "namingContexts:" | head -1 | cut -d: -f2 | tr -d ' ')
    echo "$result"
}

#===============================================================================
# Parse arguments
#===============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        -h) LDAP_HOST="$2"; shift 2 ;;
        -p) LDAP_PORT="$2"; shift 2 ;;
        -D) LDAP_BIND_DN="$2"; shift 2 ;;
        -w) LDAP_BIND_PW="$2"; shift 2 ;;
        -b) LDAP_BASE_DN="$2"; shift 2 ;;
        -s) USE_TLS=true; LDAP_PORT="$LDAPS_PORT"; shift ;;
        --help) usage ;;
        *) echo "Option inconnue: $1"; usage ;;
    esac
done

#===============================================================================
# Main
#===============================================================================
echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${GREEN}  LDAP SERVER HEALTH CHECK${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo "  Host: $LDAP_HOST:$LDAP_PORT"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${CYAN}-----------------------------------------------------------------${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Service slapd (si local)
# ═══════════════════════════════════════════════════════════════════
if [[ "$LDAP_HOST" == "localhost" ]] || [[ "$LDAP_HOST" == "127.0.0.1" ]]; then
    echo -e "\n${CYAN}[Service LDAP]${NC}"

    if systemctl is-active --quiet slapd 2>/dev/null; then
        check_result "Service slapd" "pass" "Running"
    elif systemctl is-active --quiet dirsrv 2>/dev/null; then
        check_result "Service 389-ds" "pass" "Running"
    elif pgrep -x slapd > /dev/null; then
        check_result "Process slapd" "pass" "Running"
    else
        check_result "Service LDAP" "fail" "Not running"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Connectivité
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Connectivité]${NC}"

# Test port LDAP
if nc -z -w 3 "$LDAP_HOST" "$LDAP_PORT" 2>/dev/null; then
    check_result "Port $LDAP_PORT" "pass" "Open"
else
    check_result "Port $LDAP_PORT" "fail" "Closed or unreachable"
    echo -e "\n${RED}[FATAL] Cannot connect to LDAP server. Aborting.${NC}"
    exit 2
fi

# Test port LDAPS si disponible
if nc -z -w 3 "$LDAP_HOST" 636 2>/dev/null; then
    check_result "Port 636 (LDAPS)" "pass" "Open"
else
    check_result "Port 636 (LDAPS)" "info" "Not available"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: RootDSE et Base DN
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[RootDSE]${NC}"

LDAP_URI="ldap://$LDAP_HOST:$LDAP_PORT"
[[ "$USE_TLS" == true ]] && LDAP_URI="ldaps://$LDAP_HOST:$LDAP_PORT"

rootdse=$(ldapsearch -x -H "$LDAP_URI" -s base -b "" "(objectclass=*)" 2>/dev/null)
if [[ $? -eq 0 ]]; then
    check_result "RootDSE Query" "pass" "Accessible"

    # Extraire infos
    naming_contexts=$(echo "$rootdse" | grep "namingContexts:" | head -1 | cut -d: -f2 | tr -d ' ')
    subschema=$(echo "$rootdse" | grep "subschemaSubentry:" | cut -d: -f2 | tr -d ' ')

    if [[ -z "$LDAP_BASE_DN" ]] && [[ -n "$naming_contexts" ]]; then
        LDAP_BASE_DN="$naming_contexts"
    fi

    echo -e "       ${GRAY}Base DN: $LDAP_BASE_DN${NC}"
    echo -e "       ${GRAY}Subschema: $subschema${NC}"
else
    check_result "RootDSE Query" "fail" "Failed"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Connexion anonyme
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Connexion Anonyme]${NC}"

anon_result=$(ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" -s base "(objectclass=*)" 2>&1)
if [[ $? -eq 0 ]]; then
    check_result "Anonymous Bind" "pass" "Allowed"
else
    if echo "$anon_result" | grep -qi "confidentiality required\|strong.*auth"; then
        check_result "Anonymous Bind" "pass" "Disabled (secure)"
    else
        check_result "Anonymous Bind" "warn" "Failed: $anon_result"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Connexion authentifiée
# ═══════════════════════════════════════════════════════════════════
if [[ -n "$LDAP_BIND_DN" ]] && [[ -n "$LDAP_BIND_PW" ]]; then
    echo -e "\n${CYAN}[Connexion Authentifiée]${NC}"

    auth_result=$(ldapsearch -x -H "$LDAP_URI" -D "$LDAP_BIND_DN" -w "$LDAP_BIND_PW" \
        -b "$LDAP_BASE_DN" -s base "(objectclass=*)" 2>&1)

    if [[ $? -eq 0 ]]; then
        check_result "Authenticated Bind" "pass" "Success"
    else
        check_result "Authenticated Bind" "fail" "Failed"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: TLS/SSL
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[TLS/SSL]${NC}"

# Test StartTLS
starttls_result=$(ldapsearch -x -H "ldap://$LDAP_HOST:389" -ZZ -b "" -s base 2>&1)
if [[ $? -eq 0 ]]; then
    check_result "StartTLS" "pass" "Supported"
else
    check_result "StartTLS" "info" "Not available"
fi

# Vérifier certificat LDAPS
if nc -z -w 3 "$LDAP_HOST" 636 2>/dev/null; then
    cert_info=$(echo | openssl s_client -connect "$LDAP_HOST:636" 2>/dev/null | \
        openssl x509 -noout -dates -subject 2>/dev/null)

    if [[ -n "$cert_info" ]]; then
        not_after=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
        subject=$(echo "$cert_info" | grep "subject" | sed 's/subject=//')

        if [[ -n "$not_after" ]]; then
            expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null)
            now_epoch=$(date +%s)
            days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

            if [[ $days_left -lt 0 ]]; then
                check_result "LDAPS Certificate" "fail" "EXPIRED"
            elif [[ $days_left -lt 30 ]]; then
                check_result "LDAPS Certificate" "warn" "Expires in $days_left days"
            else
                check_result "LDAPS Certificate" "pass" "Valid ($days_left days)"
            fi
            echo -e "       ${GRAY}Subject: $subject${NC}"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Recherches de base
# ═══════════════════════════════════════════════════════════════════
if [[ -n "$LDAP_BASE_DN" ]]; then
    echo -e "\n${CYAN}[Recherches]${NC}"

    LDAP_OPTS="-x -H $LDAP_URI"
    [[ -n "$LDAP_BIND_DN" ]] && LDAP_OPTS="$LDAP_OPTS -D $LDAP_BIND_DN -w $LDAP_BIND_PW"

    # Compter les entrées
    entry_count=$(ldapsearch $LDAP_OPTS -b "$LDAP_BASE_DN" "(objectclass=*)" dn 2>/dev/null | \
        grep -c "^dn:")

    if [[ $entry_count -gt 0 ]]; then
        check_result "Total Entries" "info" "$entry_count"
    else
        check_result "Total Entries" "warn" "0 or query failed"
    fi

    # Compter les utilisateurs
    user_count=$(ldapsearch $LDAP_OPTS -b "$LDAP_BASE_DN" \
        "(|(objectclass=inetOrgPerson)(objectclass=posixAccount)(objectclass=user))" dn 2>/dev/null | \
        grep -c "^dn:")
    echo -e "       ${GRAY}Users: $user_count${NC}"

    # Compter les groupes
    group_count=$(ldapsearch $LDAP_OPTS -b "$LDAP_BASE_DN" \
        "(|(objectclass=groupOfNames)(objectclass=posixGroup)(objectclass=group))" dn 2>/dev/null | \
        grep -c "^dn:")
    echo -e "       ${GRAY}Groups: $group_count${NC}"

    # Test de performance
    start_time=$(date +%s%N)
    ldapsearch $LDAP_OPTS -b "$LDAP_BASE_DN" "(objectclass=*)" dn -l 10 > /dev/null 2>&1
    end_time=$(date +%s%N)
    query_time=$(( (end_time - start_time) / 1000000 ))

    if [[ $query_time -gt 5000 ]]; then
        check_result "Query Performance" "warn" "${query_time}ms (slow)"
    else
        check_result "Query Performance" "pass" "${query_time}ms"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: Réplication (si applicable)
# ═══════════════════════════════════════════════════════════════════
if [[ "$LDAP_HOST" == "localhost" ]] || [[ "$LDAP_HOST" == "127.0.0.1" ]]; then
    echo -e "\n${CYAN}[Réplication]${NC}"

    # Vérifier syncrepl (OpenLDAP)
    if [[ -d /etc/ldap/slapd.d ]] || [[ -f /etc/openldap/slapd.conf ]]; then
        syncrepl_config=$(ldapsearch -Y EXTERNAL -H ldapi:/// -b "cn=config" \
            "(olcSyncrepl=*)" olcSyncrepl 2>/dev/null | grep -c "olcSyncrepl")

        if [[ $syncrepl_config -gt 0 ]]; then
            check_result "Syncrepl Config" "info" "$syncrepl_config provider(s)"

            # Vérifier contextCSN
            csn=$(ldapsearch -x -H "$LDAP_URI" -b "$LDAP_BASE_DN" -s base \
                "(objectclass=*)" contextCSN 2>/dev/null | grep "contextCSN:")

            if [[ -n "$csn" ]]; then
                check_result "ContextCSN" "pass" "Present"
                echo -e "       ${GRAY}$csn${NC}"
            fi
        else
            check_result "Replication" "info" "Not configured"
        fi
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 9: Statistiques (si local)
# ═══════════════════════════════════════════════════════════════════
if [[ "$LDAP_HOST" == "localhost" ]] || [[ "$LDAP_HOST" == "127.0.0.1" ]]; then
    echo -e "\n${CYAN}[Statistiques]${NC}"

    # Monitor backend OpenLDAP
    monitor=$(ldapsearch -Y EXTERNAL -H ldapi:/// -b "cn=Monitor" \
        "(objectClass=*)" 2>/dev/null)

    if [[ $? -eq 0 ]]; then
        connections=$(echo "$monitor" | grep "monitorCounter" | head -1 | cut -d: -f2 | tr -d ' ')
        operations=$(echo "$monitor" | grep -A1 "cn=Operations" | grep "monitorOpInitiated" | \
            cut -d: -f2 | tr -d ' ')

        [[ -n "$connections" ]] && echo -e "       ${GRAY}Connections: $connections${NC}"
        [[ -n "$operations" ]] && echo -e "       ${GRAY}Operations: $operations${NC}"

        check_result "Monitor Backend" "pass" "Accessible"
    else
        check_result "Monitor Backend" "info" "Not enabled"
    fi
fi

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
    echo -e "  ${RED}LDAP STATUS: CRITICAL${NC}"
    exit 2
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${YELLOW}LDAP STATUS: DEGRADED${NC}"
    exit 1
else
    echo -e "  ${GREEN}LDAP STATUS: HEALTHY${NC}"
    exit 0
fi
```

---

## Utilisation

```bash
# Serveur local
./check-ldap.sh

# Serveur distant
./check-ldap.sh -h ldap.domain.local -p 389

# Avec authentification
./check-ldap.sh -h ldap.domain.local -D "cn=admin,dc=domain,dc=local" -w "password"

# LDAPS
./check-ldap.sh -h ldap.domain.local -s
```

---

## Voir Aussi

- [check-dns.sh](check-dns.md)
- [check-mysql.sh](check-mysql.md)
