---
tags:
  - scripts
  - bash
  - sécurité
  - audit
---

# security-audit.sh

:material-star::material-star::material-star: **Niveau : Avancé**

Audit de sécurité basique du système.

---

## Description

Ce script effectue un audit de sécurité :
- Vérification des utilisateurs et permissions
- Analyse des services réseau
- Détection de ficyesterdays sensibles
- Vérification de configuration SSH
- Rapport détaillé avec recommandations

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: security-audit.sh
# Description: Audit de sécurité basique
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
WARNINGS=0
CRITICALS=0
PASSED=0

# Configuration
OUTPUT_FILE=""
VERBOSE=false

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Audit de sécurité basique du système.

Options:
    -o, --output FILE   Sauvegarder le rapport
    -v, --verbose       Verbose mode
    -h, --help          Show this help

Examples:
    $(basename "$0")                    # Audit standard
    $(basename "$0") -o report.txt      # Avec rapport
    $(basename "$0") -v                 # Verbose mode
EOF
}

log_pass() {
    PASSED=$((PASSED + 1))
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_warn() {
    WARNINGS=$((WARNINGS + 1))
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_critical() {
    CRITICALS=$((CRITICALS + 1))
    echo -e "${RED}[CRIT]${NC} $1"
}

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

print_header() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT UTILISATEURS
# ══════════════════════════════════════════════════════════════════════════════
audit_users() {
    print_header "AUDIT UTILISATEURS"

    # Root avec mot de passe vide
    local empty_pass=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow 2>/dev/null || true)
    if [[ -n "$empty_pass" ]]; then
        log_critical "Utilisateurs sans mot de passe: $empty_pass"
    else
        log_pass "Aucun utilisateur sans mot de passe"
    fi

    # Utilisateurs avec UID 0 (autres que root)
    local uid0_users=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd)
    if [[ -n "$uid0_users" ]]; then
        log_critical "Utilisateurs avec UID 0 (autre que root): $uid0_users"
    else
        log_pass "Seul root a UID 0"
    fi

    # Comptes système avec shell de connexion
    local system_shells=$(awk -F: '($3 < 1000 && $7 != "/usr/sbin/nologin" && $7 != "/bin/false" && $7 != "/sbin/nologin" && $1 != "root") { print $1 ":" $7 }' /etc/passwd)
    if [[ -n "$system_shells" ]]; then
        log_warn "Comptes système avec shell actif:"
        echo "$system_shells" | while read -r line; do
            echo "    $line"
        done
    else
        log_pass "Comptes système correctement configurés"
    fi

    # Check /etc/passwd permissions
    local passwd_perms=$(stat -c %a /etc/passwd)
    if [[ "$passwd_perms" == "644" ]]; then
        log_pass "/etc/passwd permissions OK (644)"
    else
        log_warn "/etc/passwd permissions: $passwd_perms (attendu: 644)"
    fi

    # Check /etc/shadow permissions
    local shadow_perms=$(stat -c %a /etc/shadow 2>/dev/null || echo "N/A")
    if [[ "$shadow_perms" == "640" ]] || [[ "$shadow_perms" == "600" ]]; then
        log_pass "/etc/shadow permissions OK ($shadow_perms)"
    elif [[ "$shadow_perms" != "N/A" ]]; then
        log_critical "/etc/shadow permissions: $shadow_perms (attendu: 640 ou 600)"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT SSH
# ══════════════════════════════════════════════════════════════════════════════
audit_ssh() {
    print_header "AUDIT SSH"

    local sshd_config="/etc/ssh/sshd_config"

    if [[ ! -f "$sshd_config" ]]; then
        log_info "SSH non installé ou configuration not founde"
        return
    fi

    # Root login
    local root_login=$(grep -E "^PermitRootLogin" "$sshd_config" 2>/dev/null | awk '{print $2}' || echo "not set")
    if [[ "$root_login" == "no" ]]; then
        log_pass "SSH PermitRootLogin désactivé"
    elif [[ "$root_login" == "prohibit-password" ]]; then
        log_pass "SSH PermitRootLogin: prohibit-password (clés uniquement)"
    else
        log_warn "SSH PermitRootLogin: $root_login (recommandé: no)"
    fi

    # Password authentication
    local pass_auth=$(grep -E "^PasswordAuthentication" "$sshd_config" 2>/dev/null | awk '{print $2}' || echo "not set")
    if [[ "$pass_auth" == "no" ]]; then
        log_pass "SSH PasswordAuthentication désactivé"
    else
        log_info "SSH PasswordAuthentication: $pass_auth"
    fi

    # Protocol version
    local protocol=$(grep -E "^Protocol" "$sshd_config" 2>/dev/null | awk '{print $2}' || echo "2")
    if [[ "$protocol" == "2" ]] || [[ "$protocol" == "not set" ]]; then
        log_pass "SSH Protocol 2"
    else
        log_critical "SSH Protocol: $protocol (doit être 2)"
    fi

    # Port
    local ssh_port=$(grep -E "^Port" "$sshd_config" 2>/dev/null | awk '{print $2}' || echo "22")
    if [[ "$ssh_port" != "22" ]]; then
        log_pass "SSH sur port non-standard: $ssh_port"
    else
        log_info "SSH sur port par défaut (22)"
    fi

    # Clés SSH root
    if [[ -f /root/.ssh/authorized_keys ]]; then
        local key_count=$(wc -l < /root/.ssh/authorized_keys)
        log_info "Root: $key_count clé(s) SSH autorisée(s)"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT RÉSEAU
# ══════════════════════════════════════════════════════════════════════════════
audit_network() {
    print_header "AUDIT RÉSEAU"

    # Ports en écoute
    log_info "Ports en écoute:"
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep LISTEN | while read -r line; do
            echo "    $line"
        done
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep LISTEN | while read -r line; do
            echo "    $line"
        done
    fi

    # Services sur ports sensibles
    local sensitive_ports=(23 21 25 110 143)
    for port in "${sensitive_ports[@]}"; do
        if ss -tln 2>/dev/null | grep -q ":$port "; then
            log_warn "Service non sécurisé sur port $port"
        fi
    done

    # IP forwarding
    local ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    if [[ "$ip_forward" == "0" ]]; then
        log_pass "IP forwarding désactivé"
    else
        log_info "IP forwarding activé (normal pour routeur/conteneur)"
    fi

    # Firewall
    if command -v ufw &>/dev/null; then
        local ufw_status=$(ufw status 2>/dev/null | head -1)
        if [[ "$ufw_status" == *"active"* ]]; then
            log_pass "UFW firewall actif"
        else
            log_warn "UFW firewall inactif"
        fi
    elif command -v firewalld &>/dev/null; then
        if systemctl is-active firewalld &>/dev/null; then
            log_pass "firewalld actif"
        else
            log_warn "firewalld inactif"
        fi
    elif iptables -L &>/dev/null; then
        local rules=$(iptables -L INPUT -n 2>/dev/null | wc -l)
        if (( rules > 2 )); then
            log_pass "iptables configuré ($rules règles INPUT)"
        else
            log_warn "iptables avec peu de règles"
        fi
    else
        log_warn "Aucun firewall détecté"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT FICHIERS
# ══════════════════════════════════════════════════════════════════════════════
audit_files() {
    print_header "AUDIT FICHIERS"

    # Ficyesterdays SUID
    log_info "Searching ficyesterdays SUID..."
    local suid_count=$(find / -perm -4000 -type f 2>/dev/null | wc -l)
    log_info "Ficyesterdays SUID found: $suid_count"

    if [[ "$VERBOSE" == "true" ]]; then
        find / -perm -4000 -type f 2>/dev/null | head -10 | while read -r f; do
            echo "    $f"
        done
        echo "    ... (limité à 10)"
    fi

    # Ficyesterdays world-writable
    log_info "Searching ficyesterdays world-writable (hors /tmp, /var/tmp)..."
    local ww_files=$(find / -xdev -type f -perm -0002 \
        ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/proc/*" \
        2>/dev/null | head -20)

    if [[ -n "$ww_files" ]]; then
        log_warn "Ficyesterdays world-writable found:"
        echo "$ww_files" | while read -r f; do
            echo "    $f"
        done
    else
        log_pass "Pas de ficyesterdays world-writable suspects"
    fi

    # Ficyesterdays sans propriétaire
    local no_owner=$(find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -5)
    if [[ -n "$no_owner" ]]; then
        log_warn "Ficyesterdays sans propriétaire valide:"
        echo "$no_owner" | while read -r f; do
            echo "    $f"
        done
    else
        log_pass "Tous les ficyesterdays ont un propriétaire valide"
    fi

    # Permissions /etc/crontab
    if [[ -f /etc/crontab ]]; then
        local cron_perms=$(stat -c %a /etc/crontab)
        if [[ "$cron_perms" == "600" ]] || [[ "$cron_perms" == "644" ]]; then
            log_pass "/etc/crontab permissions OK ($cron_perms)"
        else
            log_warn "/etc/crontab permissions: $cron_perms"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT SERVICES
# ══════════════════════════════════════════════════════════════════════════════
audit_services() {
    print_header "AUDIT SERVICES"

    # Services actifs
    if command -v systemctl &>/dev/null; then
        local running=$(systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep -c "running")
        log_info "Services systemd actifs: $running"

        # Services potentiellement risqués
        local risky_services=("telnet" "rsh" "rlogin" "tftp" "vsftpd" "proftpd")
        for svc in "${risky_services[@]}"; do
            if systemctl is-active "$svc" &>/dev/null; then
                log_warn "Service potentiellement risqué actif: $svc"
            fi
        done
    fi

    # Mises à jour disponibles
    if command -v apt-get &>/dev/null; then
        local updates=$(apt-get -s upgrade 2>/dev/null | grep -c "^Inst" || echo "0")
        if (( updates > 0 )); then
            log_warn "$updates mise(s) à jour disponible(s)"
        else
            log_pass "Système à jour"
        fi
    elif command -v yum &>/dev/null; then
        local updates=$(yum check-update 2>/dev/null | grep -c "." || echo "0")
        if (( updates > 10 )); then
            log_warn "Mises à jour disponibles"
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# RAPPORT FINAL
# ══════════════════════════════════════════════════════════════════════════════
show_summary() {
    print_header "RÉSUMÉ DE L'AUDIT"

    local total=$((PASSED + WARNINGS + CRITICALS))

    echo -e "  ${GREEN}Passed:${NC}    $PASSED"
    echo -e "  ${YELLOW}Warnings:${NC}  $WARNINGS"
    echo -e "  ${RED}Critical:${NC}  $CRITICALS"
    echo -e "  ${CYAN}Total:${NC}     $total checks"
    echo ""

    if (( CRITICALS > 0 )); then
        echo -e "  ${RED}${BOLD}⚠ ATTENTION: $CRITICALS problème(s) critique(s) détecté(s)!${NC}"
    elif (( WARNINGS > 0 )); then
        echo -e "  ${YELLOW}${BOLD}⚡ $WARNINGS avertissement(s) à examiner${NC}"
    else
        echo -e "  ${GREEN}${BOLD}✓ Audit passé sans problème majeur${NC}"
    fi
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
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
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${GREEN}          AUDIT DE SÉCURITÉ SYSTÈME${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  Host: $(hostname)"
    echo -e "  OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -s)"

    # Exécuter les audits
    audit_users
    audit_ssh
    audit_network
    audit_files
    audit_services
    show_summary

    # Sauvegarder si demandé
    if [[ -n "$OUTPUT_FILE" ]]; then
        exec > >(tee -a "$OUTPUT_FILE")
        log_info "Rapport sauvegardé: $OUTPUT_FILE"
    fi

    # Code de retour
    if (( CRITICALS > 0 )); then
        exit 2
    elif (( WARNINGS > 0 )); then
        exit 1
    else
        exit 0
    fi
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x security-audit.sh

# Audit standard (root recommandé)
sudo ./security-audit.sh

# Verbose mode
sudo ./security-audit.sh -v

# Avec rapport
sudo ./security-audit.sh -o /var/log/security-audit.txt
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
          AUDIT DE SÉCURITÉ SYSTÈME
═══════════════════════════════════════════════════════════
  Date: 2024-01-15 14:30:22
  Host: webserver01
  OS: Ubuntu 22.04.3 LTS

═══════════════════════════════════════════════════════════
  AUDIT UTILISATEURS
═══════════════════════════════════════════════════════════
[PASS] Aucun utilisateur sans mot de passe
[PASS] Seul root a UID 0
[PASS] Comptes système correctement configurés
[PASS] /etc/passwd permissions OK (644)
[PASS] /etc/shadow permissions OK (640)

═══════════════════════════════════════════════════════════
  AUDIT SSH
═══════════════════════════════════════════════════════════
[PASS] SSH PermitRootLogin désactivé
[PASS] SSH PasswordAuthentication désactivé
[PASS] SSH Protocol 2
[PASS] SSH sur port non-standard: 2222

═══════════════════════════════════════════════════════════
  AUDIT RÉSEAU
═══════════════════════════════════════════════════════════
[INFO] Ports en écoute:
    LISTEN  0  128  *:2222  *:*  users:(("sshd",pid=1234,fd=3))
    LISTEN  0  511  *:80    *:*  users:(("nginx",pid=5678,fd=6))
    LISTEN  0  511  *:443   *:*  users:(("nginx",pid=5678,fd=7))
[PASS] IP forwarding désactivé
[PASS] UFW firewall actif

═══════════════════════════════════════════════════════════
  RÉSUMÉ DE L'AUDIT
═══════════════════════════════════════════════════════════
  Passed:    18
  Warnings:  2
  Critical:  0
  Total:     20 checks

  ⚡ 2 avertissement(s) à examiner
```

---

## Voir Aussi

- [check-permissions.sh](check-permissions.md)
- [log-analyzer.sh](log-analyzer.md)
