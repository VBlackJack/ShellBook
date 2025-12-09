---
tags:
  - scripts
  - bash
  - système
  - monitoring
  - disque
---

# check-disk-space.sh

:material-star: **Niveau : Débutant**

Vérifie l'espace disque et envoie des alertes si les seuils sont dépassés.

---

## Description

Ce script surveille l'utilisation des disques et génère des alertes :
- Vérification de toutes les partitions ou d'une partition spécifique
- Alertes configurable (warning/critical)
- Sortie colorée ou format machine
- Code de retour pour intégration monitoring

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Utilisateur standard (pas de sudo requis pour lecture)
- **Dépendances** : `df`, `awk`

---

## Cas d'Usage

- **Monitoring proactif** : Détection précoce de saturation disque avant incidents
- **Intégration Nagios/Icinga** : Plugin de monitoring avec codes de retour standardisés
- **Automatisation cron** : Vérification régulière avec alertes email en cas de dépassement
- **Audit de serveurs** : Vérification rapide de l'espace disponible sur un parc de machines

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: check-disk-space.sh
# Description: Vérifie l'espace disque avec alertes
# Author: ShellBook
# Version: 1.0
#===============================================================================

set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Seuils par défaut (en pourcentage)
WARNING_THRESHOLD=80
CRITICAL_THRESHOLD=90

# Variables
MACHINE_OUTPUT=false
PARTITION=""
EXIT_CODE=0

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Vérifie l'espace disque et génère des alertes.

Options:
    -w, --warning NUM    Seuil d'avertissement (default: 80%)
    -c, --critical NUM   Seuil critique (default: 90%)
    -p, --partition PATH Vérifier une partition spécifique
    -m, --machine        Sortie format machine (CSV)
    -h, --help           Show this help

Examples:
    $(basename "$0")                    # Vérifie tous les disques
    $(basename "$0") -w 70 -c 85        # Seuils personnalisés
    $(basename "$0") -p /home           # Vérifie /home uniquement
    $(basename "$0") -m                 # Sortie CSV

Codes de retour:
    0 - OK (tout est sous le seuil warning)
    1 - WARNING (au moins un disque > warning)
    2 - CRITICAL (au moins un disque > critical)
EOF
}

log_ok() {
    if [[ "$MACHINE_OUTPUT" == "false" ]]; then
        echo -e "${GREEN}[OK]${NC} $1"
    fi
}

log_warn() {
    if [[ "$MACHINE_OUTPUT" == "false" ]]; then
        echo -e "${YELLOW}[WARNING]${NC} $1"
    fi
}

log_critical() {
    if [[ "$MACHINE_OUTPUT" == "false" ]]; then
        echo -e "${RED}[CRITICAL]${NC} $1"
    fi
}

check_partition() {
    local mount_point="$1"
    local usage size used avail

    # Récupérer les informations
    read -r size used avail usage <<< $(df -h "$mount_point" 2>/dev/null | awk 'NR==2 {print $2, $3, $4, $5}')

    # Enlever le %
    usage=${usage%\%}

    if [[ "$MACHINE_OUTPUT" == "true" ]]; then
        echo "$mount_point,$size,$used,$avail,$usage%"
    else
        local status="OK"
        if (( usage >= CRITICAL_THRESHOLD )); then
            log_critical "$mount_point: ${usage}% utilisé (${used}/${size}) - Seuil critique dépassé!"
            status="CRITICAL"
            [[ $EXIT_CODE -lt 2 ]] && EXIT_CODE=2
        elif (( usage >= WARNING_THRESHOLD )); then
            log_warn "$mount_point: ${usage}% utilisé (${used}/${size}) - Seuil warning dépassé"
            status="WARNING"
            [[ $EXIT_CODE -lt 1 ]] && EXIT_CODE=1
        else
            log_ok "$mount_point: ${usage}% utilisé (${used}/${size})"
        fi
    fi
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -w|--warning)
                WARNING_THRESHOLD="$2"
                shift 2
                ;;
            -c|--critical)
                CRITICAL_THRESHOLD="$2"
                shift 2
                ;;
            -p|--partition)
                PARTITION="$2"
                shift 2
                ;;
            -m|--machine)
                MACHINE_OUTPUT=true
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

    # Validation des seuils
    if ! [[ "$WARNING_THRESHOLD" =~ ^[0-9]+$ ]] || ! [[ "$CRITICAL_THRESHOLD" =~ ^[0-9]+$ ]]; then
        echo "Error: Les seuils doivent être des nombres entiers"
        exit 1
    fi

    if (( WARNING_THRESHOLD >= CRITICAL_THRESHOLD )); then
        echo "Error: Le seuil warning doit être inférieur au seuil critical"
        exit 1
    fi

    # Header pour sortie machine
    if [[ "$MACHINE_OUTPUT" == "true" ]]; then
        echo "mount_point,size,used,available,usage"
    else
        echo "Vérification de l'espace disque (Warning: ${WARNING_THRESHOLD}%, Critical: ${CRITICAL_THRESHOLD}%)"
        echo "=============================================================="
    fi

    # Vérification
    if [[ -n "$PARTITION" ]]; then
        # Partition spécifique
        if [[ ! -d "$PARTITION" ]] && [[ ! -b "$PARTITION" ]]; then
            echo "Error: $PARTITION does not exist"
            exit 1
        fi
        check_partition "$PARTITION"
    else
        # Toutes les partitions
        df -h --output=target 2>/dev/null | tail -n +2 | grep -E "^/" | while read -r mount; do
            check_partition "$mount"
        done
    fi

    # Résumé
    if [[ "$MACHINE_OUTPUT" == "false" ]]; then
        echo "=============================================================="
        case $EXIT_CODE in
            0) echo -e "Statut global: ${GREEN}OK${NC}" ;;
            1) echo -e "Statut global: ${YELLOW}WARNING${NC}" ;;
            2) echo -e "Statut global: ${RED}CRITICAL${NC}" ;;
        esac
    fi

    exit $EXIT_CODE
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x check-disk-space.sh

# Check tous les disques
./check-disk-space.sh

# Seuils personnalisés
./check-disk-space.sh -w 70 -c 85

# Check une partition spécifique
./check-disk-space.sh -p /home

# Sortie CSV pour parsing
./check-disk-space.sh -m

# Intégration cron avec notification
./check-disk-space.sh || echo "Alerte disque!" | mail -s "Disk Alert" admin@example.com
```

---

## Sortie Exemple

### Mode Normal

```text
Vérification de l'espace disque (Warning: 80%, Critical: 90%)
==============================================================
[OK] /: 45% utilisé (22G/50G)
[OK] /home: 62% utilisé (124G/200G)
[WARNING] /var: 83% utilisé (8.3G/10G) - Seuil warning dépassé
[CRITICAL] /tmp: 95% utilisé (950M/1G) - Seuil critique dépassé!
==============================================================
Statut global: CRITICAL
```

### Mode Machine (CSV)

```text
mount_point,size,used,available,usage
/,50G,22G,28G,45%
/home,200G,124G,76G,62%
/var,10G,8.3G,1.7G,83%
/tmp,1G,950M,50M,95%
```

---

## Intégration Monitoring

### Nagios/Icinga

```bash
#!/bin/bash
# check_disk_nagios.sh
OUTPUT=$(./check-disk-space.sh -m | tail -n +2)
EXIT=$?

case $EXIT in
    0) echo "DISK OK - All partitions within limits" ;;
    1) echo "DISK WARNING - Some partitions above warning threshold" ;;
    2) echo "DISK CRITICAL - Some partitions above critical threshold" ;;
esac
echo "$OUTPUT"
exit $EXIT
```

### Crontab

```bash
# Vérification toutes les hours
0 * * * * /opt/scripts/check-disk-space.sh -w 75 -c 90 >> /var/log/disk-check.log 2>&1
```

---

## Voir Aussi

- [system-info.sh](system-info.md)
- [cleanup-system.sh](cleanup-system.md)
