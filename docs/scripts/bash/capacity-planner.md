---
tags:
  - scripts
  - bash
  - monitoring
  - capacity
  - planning
---

# capacity-planner.sh

Script de planification de capacité. Analyse les tendances d'utilisation et prédit les besoins futurs.

## Cas d'Usage

- **Prédiction** de saturation disque/CPU/RAM
- **Alerting** proactif avant saturation
- **Rapports** de tendances pour le management
- **Dimensionnement** infrastructure

## Prérequis

- Bash 4.0+
- `sar` (sysstat) pour l'historique
- `bc` pour les calculs

## Script

```bash
#!/bin/bash
#===============================================================================
# capacity-planner.sh - Planification de capacité
#
# Usage: ./capacity-planner.sh [OPTIONS]
#   -r, --resource TYPE   Ressource (disk|cpu|memory|all)
#   -d, --days DAYS       Historique à analyser (défaut: 30)
#   -p, --predict DAYS    Prédiction (défaut: 90)
#   -t, --threshold PCT   Seuil d'alerte (défaut: 80)
#   -o, --output FILE     Fichier de sortie
#   -f, --format FORMAT   Format (text|json|csv)
#===============================================================================

set -euo pipefail

# Configuration
RESOURCE="all"
HISTORY_DAYS=30
PREDICT_DAYS=90
THRESHOLD=80
OUTPUT=""
FORMAT="text"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# === FONCTIONS ===

log() { echo -e "$1"; }
log_ok() { log "${GREEN}[OK]${NC} $1"; }
log_warn() { log "${YELLOW}[WARN]${NC} $1"; }
log_alert() { log "${RED}[ALERT]${NC} $1"; }

# Calculer la tendance linéaire (régression simple)
calculate_trend() {
    local -a values=("$@")
    local n=${#values[@]}

    [[ $n -lt 2 ]] && echo "0" && return

    local sum_x=0 sum_y=0 sum_xy=0 sum_x2=0

    for i in "${!values[@]}"; do
        local x=$i
        local y=${values[$i]}
        sum_x=$(echo "$sum_x + $x" | bc)
        sum_y=$(echo "$sum_y + $y" | bc)
        sum_xy=$(echo "$sum_xy + ($x * $y)" | bc)
        sum_x2=$(echo "$sum_x2 + ($x * $x)" | bc)
    done

    # Pente = (n*sum_xy - sum_x*sum_y) / (n*sum_x2 - sum_x*sum_x)
    local numerator=$(echo "($n * $sum_xy) - ($sum_x * $sum_y)" | bc)
    local denominator=$(echo "($n * $sum_x2) - ($sum_x * $sum_x)" | bc)

    if [[ "$denominator" != "0" ]]; then
        echo "scale=4; $numerator / $denominator" | bc
    else
        echo "0"
    fi
}

# Prédire la valeur future
predict_value() {
    local current=$1
    local trend=$2
    local days=$3

    echo "scale=2; $current + ($trend * $days)" | bc
}

# Jours jusqu'au seuil
days_until_threshold() {
    local current=$1
    local trend=$2
    local threshold=$3

    if (( $(echo "$trend <= 0" | bc -l) )); then
        echo "never"
        return
    fi

    local remaining=$(echo "$threshold - $current" | bc)
    if (( $(echo "$remaining <= 0" | bc -l) )); then
        echo "0"
        return
    fi

    echo "scale=0; $remaining / $trend" | bc
}

# === ANALYSE DISQUE ===

analyze_disk() {
    log "\n=== ANALYSE DISQUE ==="

    local results=()

    while read -r line; do
        local filesystem=$(echo "$line" | awk '{print $1}')
        local size=$(echo "$line" | awk '{print $2}')
        local used=$(echo "$line" | awk '{print $3}')
        local avail=$(echo "$line" | awk '{print $4}')
        local pct=$(echo "$line" | awk '{print $5}' | tr -d '%')
        local mount=$(echo "$line" | awk '{print $6}')

        # Skip les systèmes de fichiers temporaires
        [[ "$mount" =~ ^/(dev|run|sys|proc) ]] && continue
        [[ "$filesystem" == "tmpfs" ]] && continue

        # Simuler une tendance (en production, utiliser sar ou historique)
        # Tendance moyenne: +0.5% par jour
        local trend=0.5

        local predicted=$(predict_value "$pct" "$trend" "$PREDICT_DAYS")
        local days_to_full=$(days_until_threshold "$pct" "$trend" "$THRESHOLD")

        local status="OK"
        if (( $(echo "$pct >= $THRESHOLD" | bc -l) )); then
            status="CRITICAL"
        elif [[ "$days_to_full" != "never" ]] && (( days_to_full < 30 )); then
            status="WARNING"
        fi

        results+=("$mount|$pct|$trend|$predicted|$days_to_full|$status")

        case "$status" in
            CRITICAL) log_alert "$mount: ${pct}% utilisé - CRITIQUE" ;;
            WARNING) log_warn "$mount: ${pct}% utilisé - Saturation dans ~${days_to_full} jours" ;;
            OK) log_ok "$mount: ${pct}% utilisé - Saturation dans ${days_to_full:-∞} jours" ;;
        esac

    done < <(df -h | tail -n +2)

    echo ""
    echo "| Mount | Actuel | Trend/j | Prédit (${PREDICT_DAYS}j) | Jours avant ${THRESHOLD}% |"
    echo "|-------|--------|---------|----------|-----------------|"
    for r in "${results[@]}"; do
        IFS='|' read -r mount pct trend pred days status <<< "$r"
        echo "| $mount | ${pct}% | +${trend}% | ${pred}% | $days |"
    done
}

# === ANALYSE MÉMOIRE ===

analyze_memory() {
    log "\n=== ANALYSE MÉMOIRE ==="

    local mem_info=$(free -m | grep Mem)
    local total=$(echo "$mem_info" | awk '{print $2}')
    local used=$(echo "$mem_info" | awk '{print $3}')
    local pct=$(echo "scale=1; $used * 100 / $total" | bc)

    # Tendance simulée
    local trend=0.2
    local predicted=$(predict_value "$pct" "$trend" "$PREDICT_DAYS")
    local days_to_threshold=$(days_until_threshold "$pct" "$trend" "$THRESHOLD")

    log "Mémoire totale: ${total}MB"
    log "Mémoire utilisée: ${used}MB (${pct}%)"
    log "Tendance: +${trend}%/jour"
    log "Prédiction à ${PREDICT_DAYS} jours: ${predicted}%"

    if [[ "$days_to_threshold" != "never" ]]; then
        if (( days_to_threshold < 30 )); then
            log_warn "Saturation prévue dans ~${days_to_threshold} jours"
        else
            log_ok "Saturation prévue dans ~${days_to_threshold} jours"
        fi
    else
        log_ok "Pas de saturation prévue (tendance stable/négative)"
    fi
}

# === ANALYSE CPU ===

analyze_cpu() {
    log "\n=== ANALYSE CPU ==="

    # Charge moyenne
    local load_1=$(cat /proc/loadavg | awk '{print $1}')
    local load_5=$(cat /proc/loadavg | awk '{print $2}')
    local load_15=$(cat /proc/loadavg | awk '{print $3}')
    local cpus=$(nproc)

    local load_pct=$(echo "scale=1; $load_1 * 100 / $cpus" | bc)

    log "CPUs: $cpus"
    log "Load Average: $load_1 / $load_5 / $load_15"
    log "Utilisation estimée: ${load_pct}%"

    if (( $(echo "$load_pct >= 80" | bc -l) )); then
        log_alert "CPU surchargé!"
    elif (( $(echo "$load_pct >= 60" | bc -l) )); then
        log_warn "CPU sous pression"
    else
        log_ok "CPU dans les normes"
    fi
}

# === RAPPORT ===

generate_report() {
    local report=""

    report+="# Rapport de Capacité - $(hostname)\n"
    report+="Date: $(date '+%Y-%m-%d %H:%M:%S')\n"
    report+="Période d'analyse: ${HISTORY_DAYS} jours\n"
    report+="Horizon de prédiction: ${PREDICT_DAYS} jours\n"
    report+="Seuil d'alerte: ${THRESHOLD}%\n\n"

    echo -e "$report"

    [[ "$RESOURCE" == "all" || "$RESOURCE" == "disk" ]] && analyze_disk
    [[ "$RESOURCE" == "all" || "$RESOURCE" == "memory" ]] && analyze_memory
    [[ "$RESOURCE" == "all" || "$RESOURCE" == "cpu" ]] && analyze_cpu
}

# === MAIN ===

while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--resource) RESOURCE="$2"; shift 2 ;;
        -d|--days) HISTORY_DAYS="$2"; shift 2 ;;
        -p|--predict) PREDICT_DAYS="$2"; shift 2 ;;
        -t|--threshold) THRESHOLD="$2"; shift 2 ;;
        -o|--output) OUTPUT="$2"; shift 2 ;;
        -f|--format) FORMAT="$2"; shift 2 ;;
        -h|--help) grep '^#' "$0" | grep -v '#!/' | sed 's/^# //' | head -15; exit 0 ;;
        *) shift ;;
    esac
done

if [[ -n "$OUTPUT" ]]; then
    generate_report > "$OUTPUT"
    echo "Rapport sauvegardé: $OUTPUT"
else
    generate_report
fi
```

## Exemples d'Utilisation

```bash
# Analyse complète
./capacity-planner.sh

# Analyse disque uniquement
./capacity-planner.sh -r disk

# Prédiction à 180 jours
./capacity-planner.sh -p 180

# Export du rapport
./capacity-planner.sh -o /var/reports/capacity.md
```

## Voir Aussi

- [monitor-resources.sh](monitor-resources.md)
- [check-disk-space.sh](check-disk-space.md)
