---
tags:
  - scripts
  - bash
  - système
  - monitoring
---

# system-info.sh

:material-star: **Niveau : Débutant**

Affiche les informations système complètes.

---

## Description

Ce script collecte et affiche les informations essentielles du système :
- Hostname et OS
- CPU et mémoire
- Disk space
- Network
- Uptime et charge

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Utilisateur standard (pas de sudo requis)
- **Dépendances** : `free`, `df`, `uptime`, `ps`

---

## Cas d'Usage

- **Prise de connaissance serveur** : Rapport rapide des caractéristiques d'un serveur lors de première connexion
- **Documentation infrastructure** : Génération automatique de rapports d'inventaire pour documentation
- **Diagnostic initial** : Vue d'ensemble rapide lors de troubleshooting ou investigation de problèmes
- **Baseline système** : Capture de l'état système avant modifications ou maintenance

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: system-info.sh
# Description: Affiche les informations système complètes
# Author: ShellBook
# Version: 1.0
#===============================================================================

set -euo pipefail

# Colors
readonly GREEN='\033[0;32m'
readonly CYAN='\033[0;36m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

print_header() {
    echo -e "\n${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  $1${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

print_info() {
    printf "${YELLOW}%-20s${NC} : %s\n" "$1" "$2"
}

# ══════════════════════════════════════════════════════════════
# INFORMATIONS SYSTÈME
# ══════════════════════════════════════════════════════════════
print_header "INFORMATIONS SYSTÈME"

print_info "Hostname" "$(hostname)"
print_info "Kernel" "$(uname -r)"
print_info "OS" "$(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -s)"
print_info "Architecture" "$(uname -m)"
print_info "Uptime" "$(uptime -p 2>/dev/null || uptime | awk '{print $3,$4}' | sed 's/,//')"
print_info "Date" "$(date '+%Y-%m-%d %H:%M:%S')"

# ══════════════════════════════════════════════════════════════
# CPU
# ══════════════════════════════════════════════════════════════
print_header "CPU"

if [[ -f /proc/cpuinfo ]]; then
    cpu_model=$(grep "model name" /proc/cpuinfo | head -1 | cut -d':' -f2 | xargs)
    cpu_cores=$(grep -c "processor" /proc/cpuinfo)
    print_info "Modèle" "$cpu_model"
    print_info "Cores" "$cpu_cores"
fi

load_avg=$(cat /proc/loadavg | awk '{print $1, $2, $3}')
print_info "Load Average" "$load_avg"

# ══════════════════════════════════════════════════════════════
# MÉMOIRE
# ══════════════════════════════════════════════════════════════
print_header "MÉMOIRE"

if command -v free &>/dev/null; then
    mem_total=$(free -h | awk '/^Mem:/ {print $2}')
    mem_used=$(free -h | awk '/^Mem:/ {print $3}')
    mem_free=$(free -h | awk '/^Mem:/ {print $4}')
    mem_percent=$(free | awk '/^Mem:/ {printf "%.1f%%", $3/$2*100}')

    print_info "Total" "$mem_total"
    print_info "Utilisée" "$mem_used ($mem_percent)"
    print_info "Available" "$mem_free"

    # Swap
    swap_total=$(free -h | awk '/^Swap:/ {print $2}')
    swap_used=$(free -h | awk '/^Swap:/ {print $3}')
    print_info "Swap Total" "$swap_total"
    print_info "Swap Utilisée" "$swap_used"
fi

# ══════════════════════════════════════════════════════════════
# DISQUES
# ══════════════════════════════════════════════════════════════
print_header "ESPACE DISQUE"

df -h --output=source,size,used,avail,pcent,target 2>/dev/null | \
    grep -E "^/dev" | \
    while read -r line; do
        echo "  $line"
    done

# ══════════════════════════════════════════════════════════════
# RÉSEAU
# ══════════════════════════════════════════════════════════════
print_header "RÉSEAU"

# Interfaces
if command -v ip &>/dev/null; then
    ip -4 addr show | grep -E "inet " | while read -r line; do
        iface=$(echo "$line" | awk '{print $NF}')
        ip_addr=$(echo "$line" | awk '{print $2}')
        print_info "$iface" "$ip_addr"
    done
elif command -v ifconfig &>/dev/null; then
    ifconfig | grep -E "inet " | while read -r line; do
        ip_addr=$(echo "$line" | awk '{print $2}')
        print_info "IP" "$ip_addr"
    done
fi

# DNS
if [[ -f /etc/resolv.conf ]]; then
    dns=$(grep "nameserver" /etc/resolv.conf | head -1 | awk '{print $2}')
    print_info "DNS" "$dns"
fi

# ══════════════════════════════════════════════════════════════
# PROCESSUS
# ══════════════════════════════════════════════════════════════
print_header "PROCESSUS"

total_procs=$(ps aux | wc -l)
running_procs=$(ps aux | awk '$8 ~ /R/ {count++} END {print count+0}')
print_info "Total" "$total_procs"
print_info "Running" "$running_procs"

# Top 5 CPU
echo -e "\n${YELLOW}Top 5 CPU :${NC}"
ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "  %-10s %5s%% %s\n", $1, $3, $11}'

# Top 5 Memory
echo -e "\n${YELLOW}Top 5 Memory :${NC}"
ps aux --sort=-%mem | head -6 | tail -5 | awk '{printf "  %-10s %5s%% %s\n", $1, $4, $11}'

echo ""
```

---

## Usage

```bash
# Rendre exécutable
chmod +x system-info.sh

# Exécuter
./system-info.sh

# Sauvegarder dans un ficyesterday
./system-info.sh > system-report.txt
```

---

## Sortie Exemple

```text
═══════════════════════════════════════════════════════════
  INFORMATIONS SYSTÈME
═══════════════════════════════════════════════════════════
Hostname             : webserver01
Kernel               : 5.15.0-91-generic
OS                   : Ubuntu 22.04.3 LTS
Architecture         : x86_64
Uptime               : up 45 days, 3 hours
Date                 : 2024-01-15 14:30:22

═══════════════════════════════════════════════════════════
  CPU
═══════════════════════════════════════════════════════════
Modèle               : Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
Cores                : 4
Load Average         : 0.52 0.48 0.45

═══════════════════════════════════════════════════════════
  MÉMOIRE
═══════════════════════════════════════════════════════════
Total                : 16Gi
Utilisée             : 8.2Gi (51.3%)
Available           : 7.3Gi
```

---

## Personnalisation

### Ajouter des Sections

```bash
# Ajouter les utilisateurs connectés
print_header "UTILISATEURS CONNECTÉS"
who | awk '{print "  " $1 " - " $2 " (" $5 ")"}'

# Ajouter les services actifs
print_header "SERVICES"
systemctl list-units --type=service --state=running | head -10
```

---

## Voir Aussi

- [check-disk-space.sh](check-disk-space.md)
- [monitor-resources.sh](monitor-resources.md)
