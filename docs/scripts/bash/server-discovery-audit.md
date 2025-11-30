---
tags:
  - scripts
  - bash
  - audit
  - discovery
  - sysadmin
  - documentation
---

# server-discovery.sh

Script de découverte complète d'un serveur Linux inconnu - génère un rapport Markdown prêt à documenter.

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | Bash |
| **Catégorie** | Audit / Documentation |
| **Niveau** | :material-star::material-star::material-star: Avancé |
| **Dépendances** | Outils standard Linux (ss, ps, systemctl) |

---

## Description

Ce "God Script" est conçu pour être exécuté sur un serveur Linux inconnu afin de révéler rapidement son identité, sa configuration et son rôle. Il produit un rapport au format **Markdown** directement exploitable dans votre documentation.

**Fonctionnalités :**

- **Détection heuristique des rôles** : Identifie automatiquement le type de serveur (Web, DB, Container Host, etc.)
- **Inventaire matériel** : CPU, RAM, Disques
- **Cartographie réseau** : IPs, ports ouverts avec services associés
- **Baseline sécurité** : SELinux/AppArmor, Firewall, utilisateurs sudo
- **Analyse des services** : Top consommateurs, services en échec
- **Sortie Markdown** : Prêt à copier/coller dans votre wiki

---

## Prérequis

```bash
# Le script utilise des outils standards Linux
# Aucune dépendance externe requise

# Exécution recommandée en root pour un audit complet
sudo ./server-discovery.sh > server-audit.md
```

---

## Cas d'Usage

- **Reprise de serveur** : Comprendre rapidement un serveur hérité
- **Audit initial** : Documenter un nouveau serveur avant mise en production
- **Troubleshooting** : Obtenir une vue d'ensemble lors d'un incident
- **Conformité** : Générer une baseline de documentation

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: server-discovery.sh
# Description: Comprehensive server discovery audit with Markdown output
# Author: ShellBook
# Date: 2024-01-15
# Version: 1.0
#===============================================================================

set -uo pipefail
# Note: Not using -e to ensure full report even if some commands fail

# ============================================================================
# CONFIGURATION
# ============================================================================

# Known services for role detection
declare -A ROLE_PATTERNS=(
    ["dockerd"]="Container Host (Docker)"
    ["containerd"]="Container Host (containerd)"
    ["kubelet"]="Kubernetes Node"
    ["kube-apiserver"]="Kubernetes Master"
    ["nginx"]="Web Server (Nginx)"
    ["apache2"]="Web Server (Apache)"
    ["httpd"]="Web Server (Apache)"
    ["mysqld"]="Database Server (MySQL)"
    ["mariadbd"]="Database Server (MariaDB)"
    ["postgres"]="Database Server (PostgreSQL)"
    ["mongod"]="Database Server (MongoDB)"
    ["redis-server"]="Cache Server (Redis)"
    ["memcached"]="Cache Server (Memcached)"
    ["rabbitmq-server"]="Message Queue (RabbitMQ)"
    ["named"]="DNS Server (BIND)"
    ["sshd"]="SSH Server"
    ["postfix"]="Mail Server (Postfix)"
    ["dovecot"]="Mail Server (Dovecot)"
    ["haproxy"]="Load Balancer (HAProxy)"
    ["keepalived"]="HA Cluster (Keepalived)"
    ["prometheus"]="Monitoring (Prometheus)"
    ["grafana-server"]="Monitoring (Grafana)"
    ["elasticsearch"]="Search Engine (Elasticsearch)"
    ["gitlab-workhorse"]="GitLab Server"
    ["jenkins"]="CI/CD (Jenkins)"
    ["zabbix_server"]="Monitoring (Zabbix)"
    ["nagios"]="Monitoring (Nagios)"
    ["openvpn"]="VPN Server (OpenVPN)"
    ["wireguard"]="VPN Server (WireGuard)"
    ["samba"]="File Server (Samba)"
    ["nfsd"]="File Server (NFS)"
    ["squid"]="Proxy Server (Squid)"
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Check if command exists
cmd_exists() {
    command -v "$1" &> /dev/null
}

# Format bytes to human readable
format_bytes() {
    local bytes=$1
    if [[ $bytes -ge 1073741824 ]]; then
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1073741824}") GB"
    elif [[ $bytes -ge 1048576 ]]; then
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1048576}") MB"
    else
        echo "$(awk "BEGIN {printf \"%.1f\", $bytes/1024}") KB"
    fi
}

# Safe command execution with fallback
safe_exec() {
    local cmd="$1"
    local fallback="${2:-N/A}"
    eval "$cmd" 2>/dev/null || echo "$fallback"
}

# ============================================================================
# DISCOVERY FUNCTIONS
# ============================================================================

# Detect server roles based on running processes
detect_roles() {
    local roles=()
    local procs
    procs=$(ps aux 2>/dev/null | awk '{print $11}' | sort -u)

    for pattern in "${!ROLE_PATTERNS[@]}"; do
        if echo "$procs" | grep -q "$pattern"; then
            roles+=("${ROLE_PATTERNS[$pattern]}")
        fi
    done

    # Remove duplicates and format
    if [[ ${#roles[@]} -eq 0 ]]; then
        echo "Generic Linux Server"
    else
        printf '%s\n' "${roles[@]}" | sort -u | tr '\n' ', ' | sed 's/,$//' | sed 's/,/, /g'
    fi
}

# Get distribution info
get_distro() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        echo "${PRETTY_NAME:-$NAME $VERSION}"
    elif [[ -f /etc/redhat-release ]]; then
        cat /etc/redhat-release
    elif [[ -f /etc/debian_version ]]; then
        echo "Debian $(cat /etc/debian_version)"
    else
        echo "Unknown"
    fi
}

# Get CPU info
get_cpu_info() {
    local count model
    count=$(nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo "?")
    model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | sed 's/^[ \t]*//' || echo "Unknown")
    echo "$count x $model"
}

# Get memory info
get_memory_info() {
    if [[ -f /proc/meminfo ]]; then
        local total used available
        total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')

        if [[ -n "$total" && -n "$available" ]]; then
            used=$((total - available))
            echo "$(format_bytes $((used * 1024))) / $(format_bytes $((total * 1024)))"
        else
            echo "N/A"
        fi
    else
        echo "N/A"
    fi
}

# Get IP addresses
get_ip_addresses() {
    local public_ip private_ips

    # Get private IPs
    if cmd_exists ip; then
        private_ips=$(ip -4 addr show 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | tr '\n' ', ' | sed 's/,$//')
    elif cmd_exists hostname; then
        private_ips=$(hostname -I 2>/dev/null | tr ' ' ',' | sed 's/,$//')
    else
        private_ips="N/A"
    fi

    # Try to get public IP (with timeout)
    if cmd_exists curl; then
        public_ip=$(timeout 3 curl -s ifconfig.me 2>/dev/null || echo "N/A")
    elif cmd_exists wget; then
        public_ip=$(timeout 3 wget -qO- ifconfig.me 2>/dev/null || echo "N/A")
    else
        public_ip="N/A"
    fi

    echo "Public: ${public_ip:-N/A}"
    echo "Private: ${private_ips:-N/A}"
}

# Get listening ports with services
get_listening_ports() {
    if cmd_exists ss; then
        ss -tlnp 2>/dev/null | awk 'NR>1 {
            split($4, addr, ":");
            port = addr[length(addr)];
            proto = "TCP";
            # Extract process name
            match($0, /users:\(\("([^"]+)"/, arr);
            proc = arr[1] ? arr[1] : "unknown";
            if (port != "" && port ~ /^[0-9]+$/) {
                printf "| %-6s | %-5s | %-20s |\n", port, proto, proc
            }
        }' | sort -t'|' -k2 -n | uniq
    elif cmd_exists netstat; then
        netstat -tlnp 2>/dev/null | awk 'NR>2 {
            split($4, addr, ":");
            port = addr[length(addr)];
            proto = "TCP";
            proc = $7;
            gsub(/.*\//, "", proc);
            if (port != "" && port ~ /^[0-9]+$/) {
                printf "| %-6s | %-5s | %-20s |\n", port, proto, proc
            }
        }' | sort -t'|' -k2 -n | uniq
    else
        echo "| N/A    | N/A   | ss/netstat not found |"
    fi

    # UDP ports
    if cmd_exists ss; then
        ss -ulnp 2>/dev/null | awk 'NR>1 {
            split($4, addr, ":");
            port = addr[length(addr)];
            proto = "UDP";
            match($0, /users:\(\("([^"]+)"/, arr);
            proc = arr[1] ? arr[1] : "unknown";
            if (port != "" && port ~ /^[0-9]+$/) {
                printf "| %-6s | %-5s | %-20s |\n", port, proto, proc
            }
        }' | sort -t'|' -k2 -n | uniq
    fi
}

# Get disk usage for mounts > 1GB
get_disk_usage() {
    df -h 2>/dev/null | awk 'NR>1 {
        # Skip small filesystems and virtual ones
        if ($2 ~ /[0-9]+G/ || $2 ~ /[0-9]+T/) {
            gsub(/G|T/, "", $2);
            size = $2;
            if ($2 ~ /T/) size = size * 1024;
            if (size >= 1) {
                printf "| %-20s | %-8s | %-8s | %-6s |\n", $6, $2, $4, $5
            }
        }
    }' | head -10
}

# Get SELinux/AppArmor status
get_mac_status() {
    local status="None detected"

    # Check SELinux
    if cmd_exists getenforce; then
        local selinux
        selinux=$(getenforce 2>/dev/null)
        if [[ -n "$selinux" ]]; then
            status="SELinux: $selinux"
        fi
    elif [[ -f /etc/selinux/config ]]; then
        local selinux
        selinux=$(grep "^SELINUX=" /etc/selinux/config 2>/dev/null | cut -d= -f2)
        status="SELinux: ${selinux:-unknown}"
    fi

    # Check AppArmor
    if cmd_exists aa-status; then
        if aa-status --enabled 2>/dev/null; then
            local profiles
            profiles=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
            status="AppArmor: Enabled ($profiles profiles)"
        fi
    elif [[ -d /etc/apparmor.d ]]; then
        status="AppArmor: Installed (status unknown)"
    fi

    echo "$status"
}

# Get firewall status
get_firewall_status() {
    local status="None detected"

    # Check UFW
    if cmd_exists ufw; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)
        if [[ "$ufw_status" == *"active"* ]]; then
            status="UFW: Active"
        elif [[ "$ufw_status" == *"inactive"* ]]; then
            status="UFW: Inactive"
        fi
    fi

    # Check firewalld
    if cmd_exists firewall-cmd; then
        if systemctl is-active firewalld &>/dev/null; then
            local zone
            zone=$(firewall-cmd --get-default-zone 2>/dev/null)
            status="Firewalld: Active (zone: $zone)"
        else
            status="Firewalld: Inactive"
        fi
    fi

    # Check iptables rules count
    if cmd_exists iptables && [[ "$status" == "None detected" ]]; then
        local rules
        rules=$(iptables -L -n 2>/dev/null | grep -c "^[A-Z]" || echo "0")
        if [[ $rules -gt 3 ]]; then
            status="IPTables: $rules rules"
        fi
    fi

    # Check nftables
    if cmd_exists nft && [[ "$status" == "None detected" ]]; then
        local tables
        tables=$(nft list tables 2>/dev/null | wc -l)
        if [[ $tables -gt 0 ]]; then
            status="nftables: $tables tables"
        fi
    fi

    echo "$status"
}

# Get sudo users
get_sudo_users() {
    local users=""

    # Check /etc/group for sudo/wheel
    if grep -q "^sudo:" /etc/group 2>/dev/null; then
        users=$(grep "^sudo:" /etc/group | cut -d: -f4)
    fi

    if grep -q "^wheel:" /etc/group 2>/dev/null; then
        local wheel_users
        wheel_users=$(grep "^wheel:" /etc/group | cut -d: -f4)
        if [[ -n "$wheel_users" ]]; then
            users="${users:+$users,}$wheel_users"
        fi
    fi

    # Check sudoers for NOPASSWD
    local nopasswd=""
    if [[ -r /etc/sudoers ]]; then
        nopasswd=$(grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | wc -l)
    fi

    echo "Users: ${users:-root}"
    if [[ "$nopasswd" -gt 0 ]]; then
        echo "NOPASSWD rules: $nopasswd"
    fi
}

# Get top processes by memory
get_top_processes() {
    ps aux --sort=-%mem 2>/dev/null | awk 'NR>1 && NR<=6 {
        printf "| %-20s | %-6s | %-6s | %-8s |\n", substr($11,1,20), $2, $3"%", $4"%"
    }'
}

# Get failed systemd units
get_failed_units() {
    if cmd_exists systemctl; then
        local failed
        failed=$(systemctl --failed --no-pager --no-legend 2>/dev/null | head -5)
        if [[ -n "$failed" ]]; then
            echo "$failed" | awk '{printf "| %-30s | %-10s |\n", $1, $2}'
        else
            echo "| None                          | -          |"
        fi
    else
        echo "| systemctl not available       | -          |"
    fi
}

# ============================================================================
# MAIN REPORT GENERATION
# ============================================================================

generate_report() {
    local hostname distro kernel uptime_str roles
    local date_str

    # Gather basic info
    hostname=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "unknown")
    distro=$(get_distro)
    kernel=$(uname -r 2>/dev/null || echo "unknown")
    uptime_str=$(uptime -p 2>/dev/null || uptime 2>/dev/null | awk -F'up' '{print $2}' | awk -F',' '{print $1}')
    roles=$(detect_roles)
    date_str=$(date "+%Y-%m-%d %H:%M:%S %Z")

    # ========================================================================
    # OUTPUT MARKDOWN REPORT
    # ========================================================================

    cat << EOF
# Audit Report: ${hostname}

**Generated:** ${date_str}
**Auditor:** server-discovery.sh v1.0

---

## Executive Summary

| Property | Value |
|----------|-------|
| **Hostname** | ${hostname} |
| **Distribution** | ${distro} |
| **Kernel** | ${kernel} |
| **Uptime** | ${uptime_str} |
| **Detected Roles** | ${roles} |

---

## 1. System Hardware

### CPU
$(get_cpu_info)

### Memory (Used / Total)
$(get_memory_info)

### Disk Usage (Mounts > 1GB)

| Mount Point          | Size     | Available | Used   |
|----------------------|----------|-----------|--------|
$(get_disk_usage)

---

## 2. Network Configuration

### IP Addresses
$(get_ip_addresses)

### Listening Ports

| Port   | Proto | Service              |
|--------|-------|----------------------|
$(get_listening_ports)

---

## 3. Security Baseline

### Mandatory Access Control
$(get_mac_status)

### Firewall Status
$(get_firewall_status)

### Sudo Access
$(get_sudo_users)

---

## 4. Running Services

### Top 5 Processes by Memory

| Process              | PID    | CPU    | Memory   |
|----------------------|--------|--------|----------|
$(get_top_processes)

### Failed Systemd Units

| Unit                           | Load State |
|--------------------------------|------------|
$(get_failed_units)

---

## 5. Additional Information

### Installed Package Managers
EOF

    # Package managers
    for pm in apt yum dnf zypper pacman apk; do
        if cmd_exists $pm; then
            echo "- $pm"
        fi
    done

    cat << EOF

### Virtualization / Container
EOF

    # Check virtualization
    if cmd_exists systemd-detect-virt; then
        echo "- Platform: $(systemd-detect-virt 2>/dev/null || echo 'physical/unknown')"
    fi

    if cmd_exists docker; then
        echo "- Docker: $(docker --version 2>/dev/null | cut -d, -f1)"
    fi

    if cmd_exists podman; then
        echo "- Podman: $(podman --version 2>/dev/null)"
    fi

    if cmd_exists kubectl; then
        echo "- Kubectl: $(kubectl version --client --short 2>/dev/null || kubectl version --client 2>/dev/null | head -1)"
    fi

    cat << EOF

---

## Appendix: Quick Commands

\`\`\`bash
# Check recent logins
last -10

# Check listening services
ss -tlnp

# Check disk I/O
iostat -x 1 3

# Check system logs
journalctl -p err -b

# Check failed services
systemctl --failed
\`\`\`

---

*Report generated by [ShellBook](https://github.com/VBlackJack/ShellBook) server-discovery.sh*
EOF
}

# ============================================================================
# ENTRY POINT
# ============================================================================

main() {
    # Check if running as root (warning only)
    if [[ $EUID -ne 0 ]]; then
        echo "<!-- WARNING: Running without root privileges. Some information may be incomplete. -->" >&2
    fi

    generate_report
}

main "$@"
```

---

## Usage

### Exécution Basique

```bash
# Exécuter et afficher le rapport
./server-discovery.sh

# Sauvegarder dans un ficyesterday Markdown
./server-discovery.sh > audit-$(hostname)-$(date +%Y%m%d).md

# Avec sudo pour un audit complet
sudo ./server-discovery.sh > server-audit.md
```

### Copier sur un Server Distant

```bash
# Via SSH
ssh user@server 'bash -s' < server-discovery.sh > remote-server-audit.md

# Ou avec scp
scp server-discovery.sh user@server:/tmp/
ssh user@server 'sudo /tmp/server-discovery.sh' > remote-audit.md
```

### Intégration avec Ansible

```yaml
- name: Run server discovery
  script: server-discovery.sh
  register: discovery_output
  become: yes

- name: Save audit report
  copy:
    content: "{{ discovery_output.stdout }}"
    dest: "/var/log/audit-{{ inventory_hostname }}.md"
```

---

## Exemple de Sortie

```markdown
# Audit Report: web-prod-01.example.com

**Generated:** 2024-01-15 14:30:00 UTC
**Auditor:** server-discovery.sh v1.0

---

## Executive Summary

| Property | Value |
|----------|-------|
| **Hostname** | web-prod-01.example.com |
| **Distribution** | Ubuntu 22.04.3 LTS |
| **Kernel** | 5.15.0-91-generic |
| **Uptime** | up 45 days, 3 hours |
| **Detected Roles** | Web Server (Nginx), Container Host (Docker), SSH Server |

---

## 1. System Hardware

### CPU
4 x Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz

### Memory (Used / Total)
6.2 GB / 16.0 GB

### Disk Usage (Mounts > 1GB)

| Mount Point          | Size     | Available | Used   |
|----------------------|----------|-----------|--------|
| /                    | 50G      | 32G       | 36%    |
| /var/lib/docker      | 100G     | 45G       | 55%    |

---

## 2. Network Configuration

### IP Addresses
Public: 203.0.113.42
Private: 10.0.1.15, 172.17.0.1

### Listening Ports

| Port   | Proto | Service              |
|--------|-------|----------------------|
| 22     | TCP   | sshd                 |
| 80     | TCP   | nginx                |
| 443    | TCP   | nginx                |
| 3000   | TCP   | node                 |

---

## 3. Security Baseline

### Mandatory Access Control
AppArmor: Enabled (42 profiles)

### Firewall Status
UFW: Active

### Sudo Access
Users: admin,deploy
NOPASSWD rules: 1
```

---

## Rôles Détectés Automatiquement

Le script reconnaît automatiquement les services suivants :

| Processus | Rôle Assigné |
|-----------|--------------|
| `dockerd` | Container Host (Docker) |
| `kubelet` | Kubernetes Node |
| `nginx`, `apache2`, `httpd` | Web Server |
| `mysqld`, `postgres`, `mongod` | Database Server |
| `redis-server`, `memcached` | Cache Server |
| `haproxy`, `keepalived` | Load Balancer / HA |
| `prometheus`, `grafana-server` | Monitoring |
| `postfix`, `dovecot` | Mail Server |
| `named` | DNS Server |
| `openvpn`, `wireguard` | VPN Server |

---

!!! tip "Bonnes Pratiques"
    - **Exécutez en tant que root** pour un audit complet (accès aux ports, sudoers, etc.)
    - **Sauvegardez le rapport** avec la date : `audit-$(date +%Y%m%d).md`
    - **Versionnez les rapports** dans Git pour suivre l'évolution du serveur

!!! warning "Confidentialité"
    Le rapport peut contenir des informations sensibles :

    - Adresses IP internes
    - Ports ouverts et services
    - Liste des utilisateurs sudo

    **Ne partagez pas ce rapport publiquement !**

---

## Personnalisation

### Ajouter de Nouveaux Rôles

Modifiez le tableau `ROLE_PATTERNS` au début du script :

```bash
declare -A ROLE_PATTERNS=(
    # ... patterns existants ...
    ["myapp"]="Custom Application Server"
    ["custom-daemon"]="My Custom Service"
)
```

### Désactiver la Détection IP Publique

Si vous êtes sur un réseau isolé :

```bash
# Commentez ou modifiez la ligne :
# public_ip=$(timeout 3 curl -s ifconfig.me 2>/dev/null || echo "N/A")
public_ip="(disabled)"
```

---

## Voir Aussi

- [system-info.sh](system-info.md) - Informations système de base
- [security-audit.sh](security-audit.md) - Audit de sécurité détaillé
- [health-check.sh](health-check.md) - Vérification santé des services
