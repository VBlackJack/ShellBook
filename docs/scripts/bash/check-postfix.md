---
tags:
  - scripts
  - bash
  - postfix
  - mail
  - linux
---

# check-postfix.sh

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète d'un serveur mail Postfix.

---

## Description

Ce script vérifie l'état d'un serveur Postfix :
- Services Postfix et dépendances
- Configuration et domaines
- Files d'attente (queues)
- Logs et erreurs
- Connectivité SMTP
- TLS et certificats
- Restrictions et sécurité

---

## Script

```bash
#!/bin/bash
#===============================================================================
# check-postfix.sh - Vérification santé serveur Postfix
#===============================================================================
# Usage: ./check-postfix.sh [-q queue_warning] [-c cert_days]
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
QUEUE_WARNING=100
QUEUE_CRITICAL=500
CERT_WARNING_DAYS=30

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
    -q NUMBER    Seuil d'alerte queue (défaut: 100)
    -c DAYS      Jours avant alerte expiration cert (défaut: 30)
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

postconf_value() {
    postconf -h "$1" 2>/dev/null
}

#===============================================================================
# Parse arguments
#===============================================================================
while [[ $# -gt 0 ]]; do
    case $1 in
        -q) QUEUE_WARNING="$2"; shift 2 ;;
        -c) CERT_WARNING_DAYS="$2"; shift 2 ;;
        --help) usage ;;
        *) echo "Option inconnue: $1"; usage ;;
    esac
done

#===============================================================================
# Main
#===============================================================================
echo ""
echo -e "${CYAN}=================================================================${NC}"
echo -e "${GREEN}  POSTFIX MAIL SERVER HEALTH CHECK${NC}"
echo -e "${CYAN}=================================================================${NC}"
echo "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${CYAN}-----------------------------------------------------------------${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Service Postfix
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Service Postfix]${NC}"

if systemctl is-active --quiet postfix 2>/dev/null; then
    check_result "Service postfix" "pass" "Running"
elif pgrep -x master > /dev/null; then
    check_result "Process master" "pass" "Running"
else
    check_result "Service postfix" "fail" "Not running"
fi

# Version
postfix_version=$(postconf -d mail_version 2>/dev/null | cut -d= -f2 | tr -d ' ')
if [[ -n "$postfix_version" ]]; then
    echo -e "       ${GRAY}Version: $postfix_version${NC}"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Processus Postfix
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Processus]${NC}"

# Vérifier les daemons essentiels
daemons=("master" "pickup" "qmgr")
for daemon in "${daemons[@]}"; do
    if pgrep -f "postfix.*$daemon" > /dev/null 2>&1 || pgrep -x "$daemon" > /dev/null 2>&1; then
        check_result "Daemon $daemon" "pass" "Running"
    else
        check_result "Daemon $daemon" "warn" "Not running"
    fi
done

# Nombre total de processus
proc_count=$(pgrep -c -f postfix 2>/dev/null || echo 0)
echo -e "       ${GRAY}Total processes: $proc_count${NC}"

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: Configuration
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Configuration]${NC}"

# Hostname
myhostname=$(postconf_value myhostname)
check_result "Hostname" "info" "$myhostname"

# Domaine
mydomain=$(postconf_value mydomain)
echo -e "       ${GRAY}Domain: $mydomain${NC}"

# Destination
mydestination=$(postconf_value mydestination)
echo -e "       ${GRAY}Destinations: ${mydestination:0:60}...${NC}"

# Relay host
relayhost=$(postconf_value relayhost)
if [[ -n "$relayhost" ]]; then
    check_result "Relay host" "info" "$relayhost"
else
    check_result "Relay host" "info" "Direct delivery"
fi

# Vérifier la config
config_check=$(postfix check 2>&1)
if [[ -z "$config_check" ]]; then
    check_result "Configuration check" "pass" "Valid"
else
    check_result "Configuration check" "warn" "Issues found"
    echo -e "       ${YELLOW}$config_check${NC}"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Ports d'écoute
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Ports SMTP]${NC}"

# Port 25
if ss -tlnp 2>/dev/null | grep -q ":25 "; then
    check_result "Port 25 (SMTP)" "pass" "Listening"
else
    check_result "Port 25 (SMTP)" "warn" "Not listening"
fi

# Port 587
if ss -tlnp 2>/dev/null | grep -q ":587 "; then
    check_result "Port 587 (Submission)" "pass" "Listening"
else
    check_result "Port 587 (Submission)" "info" "Not listening"
fi

# Port 465
if ss -tlnp 2>/dev/null | grep -q ":465 "; then
    check_result "Port 465 (SMTPS)" "pass" "Listening"
else
    check_result "Port 465 (SMTPS)" "info" "Not listening"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Files d'attente
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Files d'Attente (Queues)]${NC}"

# Queue totale
queue_count=$(mailq 2>/dev/null | tail -1 | grep -oP '\d+(?= Request)' || echo 0)
[[ -z "$queue_count" ]] && queue_count=0

if [[ $queue_count -ge $QUEUE_CRITICAL ]]; then
    check_result "Mail queue" "fail" "$queue_count messages (critical)"
elif [[ $queue_count -ge $QUEUE_WARNING ]]; then
    check_result "Mail queue" "warn" "$queue_count messages"
else
    check_result "Mail queue" "pass" "$queue_count messages"
fi

# Détail par queue
if command -v qshape > /dev/null 2>&1; then
    active=$(find /var/spool/postfix/active -type f 2>/dev/null | wc -l)
    deferred=$(find /var/spool/postfix/deferred -type f 2>/dev/null | wc -l)
    hold=$(find /var/spool/postfix/hold -type f 2>/dev/null | wc -l)
    corrupt=$(find /var/spool/postfix/corrupt -type f 2>/dev/null | wc -l)

    echo -e "       ${GRAY}Active: $active | Deferred: $deferred | Hold: $hold | Corrupt: $corrupt${NC}"

    if [[ $deferred -gt 50 ]]; then
        check_result "Deferred queue" "warn" "$deferred messages"
    fi

    if [[ $corrupt -gt 0 ]]; then
        check_result "Corrupt queue" "warn" "$corrupt messages"
    fi
fi

# Plus vieux message
if [[ $queue_count -gt 0 ]]; then
    oldest=$(mailq 2>/dev/null | grep -oP '^\w+\s+\d+\s+\w+\s+\w+\s+\d+\s+\d+:\d+:\d+' | head -1)
    [[ -n "$oldest" ]] && echo -e "       ${GRAY}Oldest: $oldest${NC}"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: TLS/SSL
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[TLS/SSL]${NC}"

# TLS sortant
smtp_tls=$(postconf_value smtp_tls_security_level)
if [[ "$smtp_tls" == "encrypt" ]] || [[ "$smtp_tls" == "dane" ]]; then
    check_result "Outbound TLS" "pass" "$smtp_tls"
elif [[ "$smtp_tls" == "may" ]]; then
    check_result "Outbound TLS" "info" "Opportunistic ($smtp_tls)"
else
    check_result "Outbound TLS" "warn" "Disabled or $smtp_tls"
fi

# TLS entrant
smtpd_tls=$(postconf_value smtpd_tls_security_level)
if [[ "$smtpd_tls" == "encrypt" ]]; then
    check_result "Inbound TLS" "pass" "Required ($smtpd_tls)"
elif [[ "$smtpd_tls" == "may" ]]; then
    check_result "Inbound TLS" "pass" "Opportunistic ($smtpd_tls)"
else
    check_result "Inbound TLS" "warn" "Disabled or $smtpd_tls"
fi

# Certificat
cert_file=$(postconf_value smtpd_tls_cert_file)
if [[ -n "$cert_file" ]] && [[ -f "$cert_file" ]]; then
    cert_info=$(openssl x509 -in "$cert_file" -noout -dates -subject 2>/dev/null)
    not_after=$(echo "$cert_info" | grep "notAfter" | cut -d= -f2)
    subject=$(echo "$cert_info" | grep "subject" | sed 's/.*CN\s*=\s*//' | cut -d',' -f1)

    if [[ -n "$not_after" ]]; then
        expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null)
        now_epoch=$(date +%s)
        days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

        if [[ $days_left -lt 0 ]]; then
            check_result "TLS Certificate" "fail" "EXPIRED"
        elif [[ $days_left -lt $CERT_WARNING_DAYS ]]; then
            check_result "TLS Certificate" "warn" "Expires in $days_left days"
        else
            check_result "TLS Certificate" "pass" "$subject ($days_left days)"
        fi
    fi
else
    check_result "TLS Certificate" "info" "Not configured"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Restrictions et sécurité
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Sécurité]${NC}"

# Recipient restrictions
recipient_restrictions=$(postconf_value smtpd_recipient_restrictions)
if [[ -n "$recipient_restrictions" ]]; then
    check_result "Recipient restrictions" "pass" "Configured"
    echo -e "       ${GRAY}${recipient_restrictions:0:60}...${NC}"
else
    check_result "Recipient restrictions" "warn" "Not configured"
fi

# Relay restrictions
relay_restrictions=$(postconf_value smtpd_relay_restrictions)
if echo "$relay_restrictions" | grep -q "reject_unauth_destination"; then
    check_result "Relay restrictions" "pass" "Open relay protected"
else
    check_result "Relay restrictions" "warn" "Check open relay protection!"
fi

# SASL
smtpd_sasl=$(postconf_value smtpd_sasl_auth_enable)
if [[ "$smtpd_sasl" == "yes" ]]; then
    check_result "SASL Authentication" "pass" "Enabled"
else
    check_result "SASL Authentication" "info" "Disabled"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: Logs
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Logs]${NC}"

# Trouver le fichier de log
log_file="/var/log/mail.log"
[[ ! -f "$log_file" ]] && log_file="/var/log/maillog"

if [[ -f "$log_file" ]]; then
    log_size=$(du -h "$log_file" 2>/dev/null | awk '{print $1}')
    check_result "Mail log" "info" "$log_file ($log_size)"

    # Statistiques dernière heure
    hour_ago=$(date -d '1 hour ago' '+%b %e %H')

    sent=$(grep -c "status=sent" "$log_file" 2>/dev/null || echo 0)
    bounced=$(grep -c "status=bounced" "$log_file" 2>/dev/null || echo 0)
    deferred_log=$(grep -c "status=deferred" "$log_file" 2>/dev/null || echo 0)
    rejected=$(grep -c "reject:" "$log_file" 2>/dev/null || echo 0)

    echo -e "       ${GRAY}Today: sent=$sent bounced=$bounced deferred=$deferred_log rejected=$rejected${NC}"

    # Erreurs récentes
    recent_errors=$(tail -500 "$log_file" 2>/dev/null | grep -ci "error\|fatal\|panic" || echo 0)
    if [[ $recent_errors -gt 10 ]]; then
        check_result "Recent errors" "warn" "$recent_errors"
    else
        check_result "Recent errors" "pass" "$recent_errors"
    fi

    # Top destinations en erreur
    echo -e "       ${GRAY}Top deferred destinations:${NC}"
    grep "status=deferred" "$log_file" 2>/dev/null | \
        grep -oP 'to=<[^>]+>' | sort | uniq -c | sort -rn | head -3 | \
        while read count dest; do
            echo -e "       ${GRAY}  $count: $dest${NC}"
        done
else
    check_result "Mail log" "warn" "Not found"
fi

# ═══════════════════════════════════════════════════════════════════
# CHECK 9: Test connectivité SMTP
# ═══════════════════════════════════════════════════════════════════
echo -e "\n${CYAN}[Test SMTP]${NC}"

# Test local
smtp_test=$(echo "QUIT" | timeout 5 nc -w 3 localhost 25 2>/dev/null | head -1)
if echo "$smtp_test" | grep -q "220"; then
    banner=$(echo "$smtp_test" | sed 's/220 //')
    check_result "SMTP localhost" "pass" "${banner:0:50}"
else
    check_result "SMTP localhost" "fail" "No response"
fi

# Test EHLO
ehlo_test=$(echo -e "EHLO test\nQUIT" | timeout 5 nc -w 3 localhost 25 2>/dev/null)
if echo "$ehlo_test" | grep -q "250-STARTTLS"; then
    check_result "STARTTLS advertised" "pass" "Yes"
else
    check_result "STARTTLS advertised" "info" "No"
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
    echo -e "  ${RED}POSTFIX STATUS: CRITICAL${NC}"
    exit 2
elif [[ $WARNINGS -gt 0 ]]; then
    echo -e "  ${YELLOW}POSTFIX STATUS: DEGRADED${NC}"
    exit 1
else
    echo -e "  ${GREEN}POSTFIX STATUS: HEALTHY${NC}"
    exit 0
fi
```

---

## Utilisation

```bash
# Vérification basique
./check-postfix.sh

# Seuils personnalisés
./check-postfix.sh -q 50 -c 60
```

---

## Voir Aussi

- [check-dns.sh](check-dns.md)
- [check-ssl-cert.sh](../check-ssl-cert.md)
