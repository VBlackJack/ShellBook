---
tags:
  - scripts
  - bash
  - sécurité
  - permissions
---

# check-permissions.sh

:material-star::material-star: **Niveau : Intermédiaire**

Vérification des permissions sensibles.

---

## Description

Ce script vérifie les permissions de ficyesterdays sensibles :
- Ficyesterdays système critiques
- Clés SSH et certificats
- Ficyesterdays de configuration
- Détection d'anomalies

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Droits root ou sudo pour accéder à tous les fichiers système
- **Dépendances** : `stat`, `find`, `grep`

---

## Cas d'Usage

- **Audit de sécurité régulier** : Vérification automatisée des permissions critiques avec alertes
- **Validation post-installation** : Test après déploiement pour s'assurer de la conformité de sécurité
- **Conformité réglementaire** : Documentation et preuve des permissions correctes pour audits
- **Détection d'anomalies** : Identification de fichiers sensibles avec permissions incorrectes

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: check-permissions.sh
# Description: Vérification permissions sensibles
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

# Counters
ERRORS=0
WARNINGS=0
OK=0

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [PATH]

Vérification des permissions sensibles.

Arguments:
    PATH            Chemin à vérifier (default: système)

Options:
    -f, --fix       Proposer les corrections
    -v, --verbose   Verbose mode
    -h, --help      Show this help

Examples:
    $(basename "$0")              # Vérification système
    $(basename "$0") /home/user   # Check un répertoire
    $(basename "$0") -f           # Avec suggestions de fix
EOF
}

log_ok() {
    OK=$((OK + 1))
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    WARNINGS=$((WARNINGS + 1))
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    ERRORS=$((ERRORS + 1))
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

check_file_perms() {
    local file=$1
    local expected=$2
    local description=$3
    local fix_suggest=${4:-}

    if [[ ! -e "$file" ]]; then
        [[ "$VERBOSE" == "true" ]] && echo -e "${CYAN}[SKIP]${NC} $file (does not exist)"
        return
    fi

    local actual=$(stat -c %a "$file" 2>/dev/null)

    if [[ "$actual" == "$expected" ]]; then
        log_ok "$description: $file ($actual)"
    else
        log_error "$description: $file ($actual, attendu: $expected)"
        if [[ "$FIX_MODE" == "true" ]] && [[ -n "$fix_suggest" ]]; then
            echo -e "    ${YELLOW}Fix: $fix_suggest${NC}"
        fi
    fi
}

check_owner() {
    local file=$1
    local expected_user=$2
    local expected_group=$3
    local description=$4

    if [[ ! -e "$file" ]]; then
        return
    fi

    local actual_user=$(stat -c %U "$file" 2>/dev/null)
    local actual_group=$(stat -c %G "$file" 2>/dev/null)

    if [[ "$actual_user" == "$expected_user" ]] && [[ "$actual_group" == "$expected_group" ]]; then
        [[ "$VERBOSE" == "true" ]] && log_ok "$description owner: $actual_user:$actual_group"
    else
        log_warn "$description owner: $actual_user:$actual_group (attendu: $expected_user:$expected_group)"
    fi
}

# ══════════════════════════════════════════════════════════════════════════════
# VÉRIFICATIONS SYSTÈME
# ══════════════════════════════════════════════════════════════════════════════
check_system_files() {
    print_header "FICHIERS SYSTÈME"

    check_file_perms "/etc/passwd" "644" "passwd" "chmod 644 /etc/passwd"
    check_file_perms "/etc/shadow" "640" "shadow" "chmod 640 /etc/shadow"
    check_file_perms "/etc/group" "644" "group" "chmod 644 /etc/group"
    check_file_perms "/etc/gshadow" "640" "gshadow" "chmod 640 /etc/gshadow"
    check_file_perms "/etc/sudoers" "440" "sudoers" "chmod 440 /etc/sudoers"
    check_file_perms "/etc/crontab" "644" "crontab" "chmod 644 /etc/crontab"
}

check_ssh_files() {
    print_header "FICHIERS SSH"

    # Config SSH
    check_file_perms "/etc/ssh/sshd_config" "600" "sshd_config" "chmod 600 /etc/ssh/sshd_config"

    # Host keys
    for key in /etc/ssh/ssh_host_*_key; do
        if [[ -f "$key" ]]; then
            check_file_perms "$key" "600" "SSH host key" "chmod 600 $key"
        fi
    done

    # Clés publiques
    for pubkey in /etc/ssh/ssh_host_*_key.pub; do
        if [[ -f "$pubkey" ]]; then
            check_file_perms "$pubkey" "644" "SSH host pubkey" "chmod 644 $pubkey"
        fi
    done
}

check_user_ssh() {
    print_header "SSH UTILISATEURS"

    for user_home in /home/* /root; do
        if [[ -d "$user_home/.ssh" ]]; then
            local user=$(basename "$user_home")
            [[ "$user_home" == "/root" ]] && user="root"

            # Répertoire .ssh
            local ssh_dir="$user_home/.ssh"
            local ssh_perms=$(stat -c %a "$ssh_dir" 2>/dev/null)
            if [[ "$ssh_perms" != "700" ]]; then
                log_error "$user/.ssh: permissions $ssh_perms (attendu: 700)"
            else
                log_ok "$user/.ssh: permissions OK"
            fi

            # Clés privées
            for key in "$ssh_dir"/id_* "$ssh_dir"/*_key; do
                if [[ -f "$key" ]] && [[ "$key" != *.pub ]]; then
                    check_file_perms "$key" "600" "$user clé privée" "chmod 600 $key"
                fi
            done

            # authorized_keys
            if [[ -f "$ssh_dir/authorized_keys" ]]; then
                check_file_perms "$ssh_dir/authorized_keys" "600" "$user authorized_keys" "chmod 600 $ssh_dir/authorized_keys"
            fi

            # known_hosts
            if [[ -f "$ssh_dir/known_hosts" ]]; then
                local kh_perms=$(stat -c %a "$ssh_dir/known_hosts")
                if [[ "$kh_perms" != "600" ]] && [[ "$kh_perms" != "644" ]]; then
                    log_warn "$user known_hosts: $kh_perms"
                fi
            fi
        fi
    done
}

check_config_files() {
    print_header "FICHIERS DE CONFIGURATION"

    # Ficyesterdays sensibles dans /etc
    local sensitive_files=(
        "/etc/mysql/my.cnf:640"
        "/etc/postgresql/*/main/pg_hba.conf:640"
        "/etc/nginx/nginx.conf:644"
        "/etc/apache2/apache2.conf:644"
        "/etc/ssl/private:700"
    )

    for entry in "${sensitive_files[@]}"; do
        local pattern=${entry%%:*}
        local expected=${entry##*:}

        for file in $pattern; do
            if [[ -e "$file" ]]; then
                check_file_perms "$file" "$expected" "$(basename "$file")"
            fi
        done
    done

    # Certificats SSL
    if [[ -d "/etc/ssl/private" ]]; then
        for key in /etc/ssl/private/*.key /etc/ssl/private/*.pem; do
            if [[ -f "$key" ]]; then
                check_file_perms "$key" "600" "SSL key" "chmod 600 $key"
            fi
        done
    fi
}

check_world_writable() {
    print_header "FICHIERS WORLD-WRITABLE"

    echo "Recherche en cours (peut prendre du temps)..."

    local ww_files=$(find /etc /var /usr -type f -perm -0002 2>/dev/null | head -20)

    if [[ -n "$ww_files" ]]; then
        log_error "Ficyesterdays world-writable found:"
        echo "$ww_files" | while read -r f; do
            echo "    $f"
        done
    else
        log_ok "Aucun ficyesterday world-writable dans /etc, /var, /usr"
    fi
}

check_suid_sgid() {
    print_header "FICHIERS SUID/SGID"

    # SUID
    local suid_count=$(find / -perm -4000 -type f 2>/dev/null | wc -l)
    echo "Ficyesterdays SUID found: $suid_count"

    # SGID
    local sgid_count=$(find / -perm -2000 -type f 2>/dev/null | wc -l)
    echo "Ficyesterdays SGID found: $sgid_count"

    # SUID suspects (hors chemins standard)
    local suspect_suid=$(find / -perm -4000 -type f \
        ! -path "/usr/*" ! -path "/bin/*" ! -path "/sbin/*" \
        2>/dev/null | head -10)

    if [[ -n "$suspect_suid" ]]; then
        log_warn "Ficyesterdays SUID hors chemins standard:"
        echo "$suspect_suid" | while read -r f; do
            echo "    $f"
        done
    else
        log_ok "Pas de SUID suspect"
    fi
}

check_directory() {
    local dir=$1
    print_header "VÉRIFICATION: $dir"

    # Permissions du répertoire
    local dir_perms=$(stat -c %a "$dir")
    local dir_owner=$(stat -c %U:%G "$dir")
    echo "Répertoire: $dir ($dir_perms, $dir_owner)"

    # Ficyesterdays sensibles
    find "$dir" -type f \( -name "*.key" -o -name "*.pem" -o -name "*password*" -o -name "*secret*" -o -name "*.env" \) 2>/dev/null | \
    while read -r f; do
        local perms=$(stat -c %a "$f")
        if [[ "$perms" != "600" ]] && [[ "$perms" != "400" ]]; then
            log_warn "Ficyesterday sensible: $f ($perms)"
        else
            log_ok "Ficyesterday sensible: $f ($perms)"
        fi
    done

    # World readable
    local readable=$(find "$dir" -type f -perm -004 -name "*.key" -o -name "*secret*" 2>/dev/null | head -5)
    if [[ -n "$readable" ]]; then
        log_error "Ficyesterdays sensibles lisibles par tous:"
        echo "$readable"
    fi
}

show_summary() {
    print_header "RÉSUMÉ"

    echo -e "  ${GREEN}OK:${NC}       $OK"
    echo -e "  ${YELLOW}Warnings:${NC} $WARNINGS"
    echo -e "  ${RED}Errors:${NC}   $ERRORS"

    if (( ERRORS > 0 )); then
        echo -e "\n  ${RED}⚠ $ERRORS problème(s) de permissions détecté(s)!${NC}"
    elif (( WARNINGS > 0 )); then
        echo -e "\n  ${YELLOW}⚡ $WARNINGS avertissement(s)${NC}"
    else
        echo -e "\n  ${GREEN}✓ Permissions OK${NC}"
    fi
}

# Variables globales
FIX_MODE=false
VERBOSE=false
CHECK_PATH=""

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--fix)
                FIX_MODE=true
                shift
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
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                CHECK_PATH="$1"
                shift
                ;;
        esac
    done

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  VÉRIFICATION DES PERMISSIONS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "  Host: $(hostname)"

    if [[ -n "$CHECK_PATH" ]]; then
        check_directory "$CHECK_PATH"
    else
        check_system_files
        check_ssh_files
        check_user_ssh
        check_config_files
        check_world_writable
        check_suid_sgid
    fi

    show_summary

    # Code de retour
    (( ERRORS > 0 )) && exit 2
    (( WARNINGS > 0 )) && exit 1
    exit 0
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x check-permissions.sh

# Vérification système complète
sudo ./check-permissions.sh

# Check un répertoire spécifique
./check-permissions.sh /home/user/app

# Avec suggestions de fix
sudo ./check-permissions.sh -f

# Verbose mode
sudo ./check-permissions.sh -v
```

---

## Sortie Exemple

```text
═══════════════════════════════════════════════════════════
  VÉRIFICATION DES PERMISSIONS
═══════════════════════════════════════════════════════════
  Date: 2024-01-15 14:30:22
  Host: webserver01

═══════════════════════════════════════════════════════════
  FICHIERS SYSTÈME
═══════════════════════════════════════════════════════════
[OK] passwd: /etc/passwd (644)
[OK] shadow: /etc/shadow (640)
[OK] group: /etc/group (644)
[OK] gshadow: /etc/gshadow (640)
[OK] sudoers: /etc/sudoers (440)

═══════════════════════════════════════════════════════════
  FICHIERS SSH
═══════════════════════════════════════════════════════════
[OK] sshd_config: /etc/ssh/sshd_config (600)
[OK] SSH host key: /etc/ssh/ssh_host_ed25519_key (600)
[OK] SSH host key: /etc/ssh/ssh_host_rsa_key (600)

═══════════════════════════════════════════════════════════
  SSH UTILISATEURS
═══════════════════════════════════════════════════════════
[OK] admin/.ssh: permissions OK
[OK] admin clé privée: /home/admin/.ssh/id_ed25519 (600)
[ERROR] deploy/.ssh: permissions 755 (attendu: 700)

═══════════════════════════════════════════════════════════
  RÉSUMÉ
═══════════════════════════════════════════════════════════
  OK:       15
  Warnings: 2
  Errors:   1

  ⚠ 1 problème(s) de permissions détecté(s)!
```

---

## Voir Aussi

- [security-audit.sh](security-audit.md)
- [log-analyzer.sh](log-analyzer.md)
