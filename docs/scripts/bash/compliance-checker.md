---
tags:
  - scripts
  - bash
  - security
  - compliance
  - audit
  - cis
---

# compliance-checker.sh

Script d'audit de conformité basé sur les benchmarks CIS. Vérifie automatiquement les configurations de sécurité d'un serveur Linux.

## Cas d'Usage

- **Audit de conformité** CIS Benchmark
- **Hardening** verification
- **Pre-deployment** security check
- **Rapport** pour audits externes

## Prérequis

- Bash 4.0+
- Accès root (pour certains checks)
- Linux (RHEL/CentOS/Rocky, Debian/Ubuntu)

## Script

```bash
#!/bin/bash
#===============================================================================
# compliance-checker.sh - Audit de conformité CIS Benchmark
#
# Usage: ./compliance-checker.sh [OPTIONS]
#   -p, --profile PROFILE   Profil (server|workstation) [défaut: server]
#   -l, --level LEVEL       Niveau CIS (1|2) [défaut: 1]
#   -c, --category CAT      Catégorie spécifique
#   -o, --output FILE       Fichier de sortie
#   -f, --format FORMAT     Format (text|json|html) [défaut: text]
#   -q, --quiet             Mode silencieux
#===============================================================================

set -uo pipefail

# === CONFIGURATION ===
PROFILE="server"
LEVEL=1
CATEGORY=""
OUTPUT=""
FORMAT="text"
QUIET=false

# Compteurs
PASSED=0
FAILED=0
SKIPPED=0
MANUAL=0

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Résultats
declare -a RESULTS=()

# === FONCTIONS UTILITAIRES ===

log() { [[ "$QUIET" == "true" ]] || echo -e "$1"; }
log_pass() { log "${GREEN}[PASS]${NC} $1"; ((PASSED++)); RESULTS+=("PASS|$1"); }
log_fail() { log "${RED}[FAIL]${NC} $1"; ((FAILED++)); RESULTS+=("FAIL|$1"); }
log_skip() { log "${YELLOW}[SKIP]${NC} $1"; ((SKIPPED++)); RESULTS+=("SKIP|$1"); }
log_manual() { log "${BLUE}[MANUAL]${NC} $1"; ((MANUAL++)); RESULTS+=("MANUAL|$1"); }
log_info() { log "${BLUE}[INFO]${NC} $1"; }

# Vérifier si un service est actif
is_service_active() {
    systemctl is-active "$1" &>/dev/null
}

# Vérifier si un service est enabled
is_service_enabled() {
    systemctl is-enabled "$1" &>/dev/null 2>&1
}

# Vérifier si un package est installé
is_package_installed() {
    if command -v rpm &>/dev/null; then
        rpm -q "$1" &>/dev/null
    elif command -v dpkg &>/dev/null; then
        dpkg -l "$1" 2>/dev/null | grep -q "^ii"
    fi
}

# Vérifier une ligne dans un fichier
check_file_content() {
    local file=$1
    local pattern=$2
    [[ -f "$file" ]] && grep -qE "$pattern" "$file"
}

# Vérifier les permissions d'un fichier
check_file_perms() {
    local file=$1
    local expected=$2
    [[ -f "$file" ]] && [[ "$(stat -c %a "$file")" == "$expected" ]]
}

# === CHECKS CIS ===

# 1.1 - Filesystem Configuration
check_filesystem() {
    log_info "=== 1.1 Filesystem Configuration ==="

    # 1.1.1.1 - cramfs disabled
    if ! lsmod | grep -q cramfs && ! modprobe -n -v cramfs 2>&1 | grep -q "insmod"; then
        log_pass "1.1.1.1 cramfs est désactivé"
    else
        log_fail "1.1.1.1 cramfs n'est pas désactivé"
    fi

    # 1.1.2 - /tmp séparé
    if findmnt -n /tmp &>/dev/null; then
        log_pass "1.1.2 /tmp est une partition séparée"
    else
        log_fail "1.1.2 /tmp n'est pas une partition séparée"
    fi

    # 1.1.3-5 - Options /tmp
    if findmnt -n /tmp | grep -q nodev; then
        log_pass "1.1.3 nodev sur /tmp"
    else
        log_fail "1.1.3 nodev manquant sur /tmp"
    fi

    # 1.1.8 - /var/tmp séparé
    if findmnt -n /var/tmp &>/dev/null || findmnt -n /var | grep -q "/var"; then
        log_pass "1.1.8 /var/tmp configuré"
    else
        log_skip "1.1.8 /var/tmp non vérifié"
    fi
}

# 1.3 - Filesystem Integrity
check_integrity() {
    log_info "=== 1.3 Filesystem Integrity ==="

    # AIDE installed
    if is_package_installed aide || is_package_installed aide-common; then
        log_pass "1.3.1 AIDE est installé"
    else
        log_fail "1.3.1 AIDE n'est pas installé"
    fi

    # AIDE cron
    if [[ -f /etc/cron.daily/aide ]] || crontab -l 2>/dev/null | grep -q aide; then
        log_pass "1.3.2 AIDE est planifié"
    else
        log_fail "1.3.2 AIDE n'est pas planifié"
    fi
}

# 1.4 - Secure Boot Settings
check_bootloader() {
    log_info "=== 1.4 Secure Boot Settings ==="

    # GRUB permissions
    local grub_cfg=""
    [[ -f /boot/grub2/grub.cfg ]] && grub_cfg="/boot/grub2/grub.cfg"
    [[ -f /boot/grub/grub.cfg ]] && grub_cfg="/boot/grub/grub.cfg"

    if [[ -n "$grub_cfg" ]]; then
        local perms=$(stat -c %a "$grub_cfg")
        if [[ "$perms" == "600" || "$perms" == "400" ]]; then
            log_pass "1.4.1 Permissions GRUB correctes ($perms)"
        else
            log_fail "1.4.1 Permissions GRUB incorrectes ($perms, attendu: 600)"
        fi
    else
        log_skip "1.4.1 Fichier GRUB non trouvé"
    fi

    # Boot password
    if grep -q "^set superusers" /boot/grub2/grub.cfg 2>/dev/null || \
       grep -q "^password" /boot/grub2/user.cfg 2>/dev/null; then
        log_pass "1.4.2 Mot de passe boot configuré"
    else
        log_fail "1.4.2 Mot de passe boot non configuré"
    fi
}

# 2.1 - Services spéciaux
check_services() {
    log_info "=== 2.1 Special Purpose Services ==="

    local unwanted_services=(
        "avahi-daemon"
        "cups"
        "dhcpd"
        "slapd"
        "nfs"
        "rpcbind"
        "named"
        "vsftpd"
        "httpd"
        "dovecot"
        "smb"
        "squid"
        "snmpd"
        "ypserv"
        "telnet.socket"
    )

    for svc in "${unwanted_services[@]}"; do
        if is_service_enabled "$svc"; then
            log_fail "2.1.x Service $svc est activé"
        else
            log_pass "2.1.x Service $svc est désactivé"
        fi
    done
}

# 3.1-3.3 - Network Configuration
check_network() {
    log_info "=== 3.x Network Configuration ==="

    # IP forwarding disabled
    local ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [[ "$ip_forward" == "0" ]]; then
        log_pass "3.1.1 IP forwarding désactivé"
    else
        log_fail "3.1.1 IP forwarding activé ($ip_forward)"
    fi

    # ICMP redirects
    local icmp_redirect=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
    if [[ "$icmp_redirect" == "0" ]]; then
        log_pass "3.2.2 ICMP redirects désactivés"
    else
        log_fail "3.2.2 ICMP redirects activés"
    fi

    # TCP SYN Cookies
    local syn_cookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
    if [[ "$syn_cookies" == "1" ]]; then
        log_pass "3.2.8 TCP SYN cookies activés"
    else
        log_fail "3.2.8 TCP SYN cookies désactivés"
    fi
}

# 4.1 - Firewall
check_firewall() {
    log_info "=== 4.x Firewall Configuration ==="

    # Firewall installé et actif
    if is_service_active firewalld; then
        log_pass "4.1.1 firewalld est actif"
    elif is_service_active ufw; then
        log_pass "4.1.1 ufw est actif"
    elif iptables -L &>/dev/null && [[ $(iptables -L -n | wc -l) -gt 8 ]]; then
        log_pass "4.1.1 iptables configuré"
    else
        log_fail "4.1.1 Aucun firewall actif"
    fi
}

# 5.1 - SSH Configuration
check_ssh() {
    log_info "=== 5.2 SSH Server Configuration ==="

    local sshd_config="/etc/ssh/sshd_config"

    # Permissions sshd_config
    if check_file_perms "$sshd_config" "600"; then
        log_pass "5.2.1 Permissions sshd_config (600)"
    else
        log_fail "5.2.1 Permissions sshd_config incorrectes"
    fi

    # PermitRootLogin
    if grep -qE "^PermitRootLogin\s+(no|prohibit-password)" "$sshd_config" 2>/dev/null; then
        log_pass "5.2.10 PermitRootLogin désactivé"
    else
        log_fail "5.2.10 PermitRootLogin non restreint"
    fi

    # PermitEmptyPasswords
    if grep -qE "^PermitEmptyPasswords\s+no" "$sshd_config" 2>/dev/null || \
       ! grep -qE "^PermitEmptyPasswords\s+yes" "$sshd_config" 2>/dev/null; then
        log_pass "5.2.11 PermitEmptyPasswords désactivé"
    else
        log_fail "5.2.11 PermitEmptyPasswords activé"
    fi

    # Protocol 2
    if ! grep -qE "^Protocol\s+1" "$sshd_config" 2>/dev/null; then
        log_pass "5.2.4 SSH Protocol 2"
    else
        log_fail "5.2.4 SSH Protocol 1 activé"
    fi

    # MaxAuthTries
    local max_auth=$(grep -E "^MaxAuthTries" "$sshd_config" 2>/dev/null | awk '{print $2}')
    if [[ -n "$max_auth" && "$max_auth" -le 4 ]]; then
        log_pass "5.2.7 MaxAuthTries <= 4 ($max_auth)"
    else
        log_fail "5.2.7 MaxAuthTries trop élevé ou non défini"
    fi
}

# 5.3 - PAM Configuration
check_pam() {
    log_info "=== 5.3 PAM Configuration ==="

    # Password quality
    if is_package_installed libpam-pwquality || is_package_installed pam_pwquality; then
        log_pass "5.3.1 pam_pwquality installé"
    else
        log_fail "5.3.1 pam_pwquality non installé"
    fi

    # Faillock/pam_tally
    if grep -rq "pam_faillock\|pam_tally" /etc/pam.d/ 2>/dev/null; then
        log_pass "5.3.2 Verrouillage de compte configuré"
    else
        log_fail "5.3.2 Verrouillage de compte non configuré"
    fi
}

# 5.4 - User Accounts
check_accounts() {
    log_info "=== 5.4 User Accounts ==="

    # Password expiration
    local pass_max=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [[ -n "$pass_max" && "$pass_max" -le 365 ]]; then
        log_pass "5.4.1.1 PASS_MAX_DAYS <= 365 ($pass_max)"
    else
        log_fail "5.4.1.1 PASS_MAX_DAYS trop élevé"
    fi

    # Password minimum days
    local pass_min=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}')
    if [[ -n "$pass_min" && "$pass_min" -ge 1 ]]; then
        log_pass "5.4.1.2 PASS_MIN_DAYS >= 1 ($pass_min)"
    else
        log_fail "5.4.1.2 PASS_MIN_DAYS trop bas"
    fi

    # Root is only UID 0
    local uid0_count=$(awk -F: '($3 == 0) {print}' /etc/passwd | wc -l)
    if [[ "$uid0_count" -eq 1 ]]; then
        log_pass "5.4.3 Seul root a UID 0"
    else
        log_fail "5.4.3 $uid0_count utilisateurs avec UID 0"
    fi
}

# 6.1 - File Permissions
check_permissions() {
    log_info "=== 6.1 System File Permissions ==="

    # /etc/passwd
    if check_file_perms "/etc/passwd" "644"; then
        log_pass "6.1.2 /etc/passwd permissions (644)"
    else
        log_fail "6.1.2 /etc/passwd permissions incorrectes"
    fi

    # /etc/shadow
    local shadow_perms=$(stat -c %a /etc/shadow 2>/dev/null)
    if [[ "$shadow_perms" == "000" || "$shadow_perms" == "640" || "$shadow_perms" == "600" ]]; then
        log_pass "6.1.3 /etc/shadow permissions ($shadow_perms)"
    else
        log_fail "6.1.3 /etc/shadow permissions incorrectes ($shadow_perms)"
    fi

    # /etc/group
    if check_file_perms "/etc/group" "644"; then
        log_pass "6.1.4 /etc/group permissions (644)"
    else
        log_fail "6.1.4 /etc/group permissions incorrectes"
    fi

    # World-writable files
    local ww_count=$(find / -xdev -type f -perm -0002 2>/dev/null | wc -l)
    if [[ "$ww_count" -eq 0 ]]; then
        log_pass "6.1.10 Pas de fichiers world-writable"
    else
        log_fail "6.1.10 $ww_count fichiers world-writable trouvés"
    fi
}

# 6.2 - User and Group Settings
check_users() {
    log_info "=== 6.2 User and Group Settings ==="

    # Empty passwords
    local empty_pass=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
    if [[ -z "$empty_pass" ]]; then
        log_pass "6.2.1 Pas de mots de passe vides"
    else
        log_fail "6.2.1 Utilisateurs sans mot de passe: $empty_pass"
    fi

    # Duplicate UIDs
    local dup_uid=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
    if [[ -z "$dup_uid" ]]; then
        log_pass "6.2.15 Pas d'UIDs dupliqués"
    else
        log_fail "6.2.15 UIDs dupliqués: $dup_uid"
    fi
}

# === RAPPORT ===

generate_report() {
    local total=$((PASSED + FAILED + SKIPPED + MANUAL))
    local score=0
    [[ $total -gt 0 ]] && score=$((PASSED * 100 / (PASSED + FAILED)))

    case "$FORMAT" in
        json)
            echo "{"
            echo "  \"date\": \"$(date -Iseconds)\","
            echo "  \"hostname\": \"$(hostname)\","
            echo "  \"profile\": \"$PROFILE\","
            echo "  \"level\": $LEVEL,"
            echo "  \"summary\": {"
            echo "    \"passed\": $PASSED,"
            echo "    \"failed\": $FAILED,"
            echo "    \"skipped\": $SKIPPED,"
            echo "    \"manual\": $MANUAL,"
            echo "    \"score\": $score"
            echo "  },"
            echo "  \"results\": ["
            local first=true
            for r in "${RESULTS[@]}"; do
                IFS='|' read -r status desc <<< "$r"
                $first || echo ","
                echo -n "    {\"status\": \"$status\", \"description\": \"$desc\"}"
                first=false
            done
            echo ""
            echo "  ]"
            echo "}"
            ;;
        *)
            echo ""
            echo "=============================================="
            echo " RAPPORT DE CONFORMITÉ CIS"
            echo "=============================================="
            echo " Date     : $(date '+%Y-%m-%d %H:%M:%S')"
            echo " Host     : $(hostname)"
            echo " Profile  : $PROFILE"
            echo " Level    : $LEVEL"
            echo "=============================================="
            echo " PASSED   : $PASSED"
            echo " FAILED   : $FAILED"
            echo " SKIPPED  : $SKIPPED"
            echo " MANUAL   : $MANUAL"
            echo "----------------------------------------------"
            echo " SCORE    : $score%"
            echo "=============================================="
            ;;
    esac
}

# === MAIN ===

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--profile) PROFILE="$2"; shift 2 ;;
        -l|--level) LEVEL="$2"; shift 2 ;;
        -c|--category) CATEGORY="$2"; shift 2 ;;
        -o|--output) OUTPUT="$2"; shift 2 ;;
        -f|--format) FORMAT="$2"; shift 2 ;;
        -q|--quiet) QUIET=true; shift ;;
        -h|--help) grep '^#' "$0" | grep -v '#!/' | sed 's/^# //' | head -15; exit 0 ;;
        *) shift ;;
    esac
done

log "=============================================="
log " Audit de Conformité CIS - ShellBook"
log " Profil: $PROFILE | Niveau: $LEVEL"
log "==============================================\n"

# Exécuter les checks
check_filesystem
check_integrity
check_bootloader
check_services
check_network
check_firewall
check_ssh
check_pam
check_accounts
check_permissions
check_users

# Générer le rapport
report=$(generate_report)

if [[ -n "$OUTPUT" ]]; then
    echo "$report" > "$OUTPUT"
    log "\nRapport sauvegardé dans $OUTPUT"
else
    echo "$report"
fi

# Exit code basé sur les échecs
[[ $FAILED -eq 0 ]] && exit 0 || exit 1
```

## Exemples d'Utilisation

```bash
# Audit de base
sudo ./compliance-checker.sh

# Audit niveau 2
sudo ./compliance-checker.sh -l 2

# Export JSON
sudo ./compliance-checker.sh -f json -o /var/log/compliance.json

# Mode silencieux (pour cron)
sudo ./compliance-checker.sh -q -o /var/log/cis-audit.txt
```

## Voir Aussi

- [security-audit.sh](security-audit.md)
- [Guide ANSSI](../../security/anssi-guides.md)
- [Hardening Linux](../../formations/linux-hardening/index.md)
