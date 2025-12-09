---
tags:
  - scripts
  - bash
  - cron
  - monitoring
  - scheduled-tasks
---

# cron-watchdog.sh

:material-star::material-star: **Niveau : Intermédiaire**

Surveillance des jobs cron avec alertes sur échecs et durée.

---

## Description

Ce script surveille l'exécution des tâches planifiées :
- Détection des jobs échoués (exit code != 0)
- Mesure de la durée d'exécution
- Alertes sur dépassement de durée
- Détection des jobs manqués
- Historique des exécutions
- Rapport journalier

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Utilisateur avec droits d'exécution des jobs cron à surveiller
- **Dépendances** : `bash`, `timeout`, `mail` (optionnel pour alertes email)

---

## Cas d'Usage

- **Surveillance cron jobs** : Monitoring automatique de toutes les tâches planifiées avec alertes
- **Détection d'échecs** : Notification immédiate lors d'échec de jobs critiques
- **Analyse de performance** : Mesure des durées d'exécution pour optimisation
- **Reporting automatisé** : Génération de rapports quotidiens sur l'état des jobs cron

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: cron-watchdog.sh
# Description: Cron job monitoring and alerting
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

# Configuration
WATCHDOG_DIR="${WATCHDOG_DIR:-/var/lib/cron-watchdog}"
LOG_FILE="${LOG_FILE:-/var/log/cron-watchdog.log}"
ALERT_EMAIL="${ALERT_EMAIL:-}"
MAX_HISTORY=100
DEFAULT_TIMEOUT=3600  # 1 hour

# Ensure directories exist
mkdir -p "$WATCHDOG_DIR"/{jobs,history}

usage() {
    cat << 'EOF'
Usage: cron-watchdog.sh COMMAND [OPTIONS]

Commands:
    wrap JOBNAME COMMAND    Wrap a cron job with monitoring
    status [JOBNAME]        Show job status
    history JOBNAME         Show job execution history
    failed                  List failed jobs
    report                  Generate daily report
    clean                   Clean old history

Options:
    -t, --timeout SEC       Timeout for job (default: 3600)
    -e, --email EMAIL       Alert email address
    -w, --warn-duration SEC Warning threshold for duration
    -c, --critical-duration SEC Critical threshold for duration
    -h, --help              Show this help

Examples:
    # In crontab, wrap your job:
    0 2 * * * /opt/scripts/cron-watchdog.sh wrap "backup-daily" /opt/scripts/backup.sh

    # Check status
    cron-watchdog.sh status

    # View history
    cron-watchdog.sh history backup-daily

    # List failed jobs
    cron-watchdog.sh failed
EOF
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"

    case "$level" in
        INFO)  echo -e "${GREEN}[INFO]${NC} $message" ;;
        WARN)  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        ERROR) echo -e "${RED}[ERROR]${NC} $message" ;;
        *)     echo "$message" ;;
    esac
}

send_alert() {
    local subject="$1"
    local body="$2"

    if [[ -n "$ALERT_EMAIL" ]]; then
        echo "$body" | mail -s "$subject" "$ALERT_EMAIL" 2>/dev/null || true
    fi

    log "ALERT" "$subject: $body"
}

# Wrap and monitor a cron job
wrap_job() {
    local job_name="$1"
    shift
    local command="$*"

    local job_file="$WATCHDOG_DIR/jobs/$job_name"
    local history_file="$WATCHDOG_DIR/history/${job_name}.log"
    local lock_file="/tmp/cron-watchdog-${job_name}.lock"

    # Prevent concurrent execution
    if [[ -f "$lock_file" ]]; then
        local lock_pid
        lock_pid=$(cat "$lock_file" 2>/dev/null || echo "")
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            log "WARN" "Job '$job_name' is already running (PID: $lock_pid)"
            send_alert "Cron Overlap: $job_name" "Job is still running from previous execution"
            exit 1
        fi
        rm -f "$lock_file"
    fi

    echo $$ > "$lock_file"
    trap 'rm -f "$lock_file"' EXIT

    local start_time
    start_time=$(date +%s)
    local start_timestamp
    start_timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    log "INFO" "Starting job: $job_name"

    # Create temp file for output
    local output_file
    output_file=$(mktemp)

    # Execute with timeout
    local exit_code=0
    if [[ -n "${TIMEOUT:-}" ]]; then
        timeout "$TIMEOUT" bash -c "$command" > "$output_file" 2>&1 || exit_code=$?
    else
        bash -c "$command" > "$output_file" 2>&1 || exit_code=$?
    fi

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))
    local end_timestamp
    end_timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Determine status
    local status="SUCCESS"
    if [[ $exit_code -eq 124 ]]; then
        status="TIMEOUT"
    elif [[ $exit_code -ne 0 ]]; then
        status="FAILED"
    fi

    # Check duration thresholds
    local duration_status="OK"
    if [[ -n "${CRITICAL_DURATION:-}" ]] && [[ $duration -gt $CRITICAL_DURATION ]]; then
        duration_status="CRITICAL"
    elif [[ -n "${WARN_DURATION:-}" ]] && [[ $duration -gt $WARN_DURATION ]]; then
        duration_status="WARNING"
    fi

    # Save job status
    cat > "$job_file" << EOJSON
{
    "name": "$job_name",
    "last_run": "$end_timestamp",
    "duration_seconds": $duration,
    "exit_code": $exit_code,
    "status": "$status",
    "duration_status": "$duration_status"
}
EOJSON

    # Append to history
    echo "$end_timestamp|$duration|$exit_code|$status" >> "$history_file"

    # Trim history
    if [[ -f "$history_file" ]]; then
        tail -n "$MAX_HISTORY" "$history_file" > "${history_file}.tmp"
        mv "${history_file}.tmp" "$history_file"
    fi

    # Log result
    if [[ "$status" == "SUCCESS" ]]; then
        log "INFO" "Job '$job_name' completed successfully in ${duration}s"
    else
        log "ERROR" "Job '$job_name' $status (exit: $exit_code) after ${duration}s"

        # Send alert
        local alert_body
        alert_body=$(cat << EOALERT
Job: $job_name
Status: $status
Exit Code: $exit_code
Duration: ${duration}s
Start: $start_timestamp
End: $end_timestamp
Command: $command

Last Output:
$(tail -50 "$output_file")
EOALERT
)
        send_alert "Cron FAILED: $job_name" "$alert_body"
    fi

    # Alert on duration
    if [[ "$duration_status" != "OK" ]]; then
        send_alert "Cron Duration $duration_status: $job_name" \
            "Job took ${duration}s (threshold exceeded)"
    fi

    # Cleanup
    rm -f "$output_file"

    return $exit_code
}

# Show job status
show_status() {
    local job_filter="${1:-}"

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  CRON WATCHDOG STATUS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    printf "%-20s %-20s %-10s %-8s %-10s\n" "JOB NAME" "LAST RUN" "DURATION" "EXIT" "STATUS"
    printf "%-20s %-20s %-10s %-8s %-10s\n" "--------" "--------" "--------" "----" "------"

    local found=0
    for job_file in "$WATCHDOG_DIR/jobs"/*; do
        [[ -f "$job_file" ]] || continue

        local job_name
        job_name=$(basename "$job_file")

        # Filter if specified
        if [[ -n "$job_filter" ]] && [[ "$job_name" != *"$job_filter"* ]]; then
            continue
        fi

        found=1

        # Parse JSON (simple extraction)
        local last_run duration exit_code status
        last_run=$(grep -o '"last_run": "[^"]*"' "$job_file" | cut -d'"' -f4)
        duration=$(grep -o '"duration_seconds": [0-9]*' "$job_file" | awk '{print $2}')
        exit_code=$(grep -o '"exit_code": [0-9]*' "$job_file" | awk '{print $2}')
        status=$(grep -o '"status": "[^"]*"' "$job_file" | cut -d'"' -f4)

        # Format duration
        local duration_fmt="${duration}s"
        if [[ $duration -gt 3600 ]]; then
            duration_fmt="$((duration / 3600))h$((duration % 3600 / 60))m"
        elif [[ $duration -gt 60 ]]; then
            duration_fmt="$((duration / 60))m$((duration % 60))s"
        fi

        # Color status
        local status_color
        case "$status" in
            SUCCESS) status_color="${GREEN}$status${NC}" ;;
            FAILED|TIMEOUT) status_color="${RED}$status${NC}" ;;
            *) status_color="$status" ;;
        esac

        printf "%-20s %-20s %-10s %-8s " "$job_name" "${last_run:0:19}" "$duration_fmt" "$exit_code"
        echo -e "$status_color"
    done

    if [[ $found -eq 0 ]]; then
        echo "No jobs found."
    fi

    echo ""
}

# Show job history
show_history() {
    local job_name="$1"
    local history_file="$WATCHDOG_DIR/history/${job_name}.log"

    if [[ ! -f "$history_file" ]]; then
        echo "No history found for job: $job_name"
        return 1
    fi

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  HISTORY: $job_name${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    printf "%-20s %-10s %-8s %-10s\n" "TIMESTAMP" "DURATION" "EXIT" "STATUS"
    printf "%-20s %-10s %-8s %-10s\n" "---------" "--------" "----" "------"

    # Show last 20 entries
    tail -20 "$history_file" | while IFS='|' read -r timestamp duration exit_code status; do
        local duration_fmt="${duration}s"
        if [[ $duration -gt 60 ]]; then
            duration_fmt="$((duration / 60))m$((duration % 60))s"
        fi

        local status_color
        case "$status" in
            SUCCESS) status_color="${GREEN}$status${NC}" ;;
            FAILED|TIMEOUT) status_color="${RED}$status${NC}" ;;
            *) status_color="$status" ;;
        esac

        printf "%-20s %-10s %-8s " "${timestamp:0:19}" "$duration_fmt" "$exit_code"
        echo -e "$status_color"
    done

    echo ""

    # Statistics
    local total success failed
    total=$(wc -l < "$history_file")
    success=$(grep -c "|SUCCESS$" "$history_file" || echo 0)
    failed=$((total - success))

    echo "Statistics (last $total runs):"
    echo "  Success: $success ($((success * 100 / total))%)"
    echo "  Failed: $failed"
}

# List failed jobs
list_failed() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${RED}  FAILED JOBS${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    local found=0
    for job_file in "$WATCHDOG_DIR/jobs"/*; do
        [[ -f "$job_file" ]] || continue

        local status
        status=$(grep -o '"status": "[^"]*"' "$job_file" | cut -d'"' -f4)

        if [[ "$status" != "SUCCESS" ]]; then
            found=1
            local job_name last_run exit_code
            job_name=$(basename "$job_file")
            last_run=$(grep -o '"last_run": "[^"]*"' "$job_file" | cut -d'"' -f4)
            exit_code=$(grep -o '"exit_code": [0-9]*' "$job_file" | awk '{print $2}')

            echo -e "${RED}✗${NC} $job_name"
            echo "    Last Run: $last_run"
            echo "    Exit Code: $exit_code"
            echo "    Status: $status"
            echo ""
        fi
    done

    if [[ $found -eq 0 ]]; then
        echo -e "${GREEN}All jobs are healthy!${NC}"
    fi
}

# Generate daily report
generate_report() {
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  DAILY CRON REPORT${NC}"
    echo -e "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo ""

    local total=0 success=0 failed=0 total_duration=0

    for job_file in "$WATCHDOG_DIR/jobs"/*; do
        [[ -f "$job_file" ]] || continue
        total=$((total + 1))

        local status duration
        status=$(grep -o '"status": "[^"]*"' "$job_file" | cut -d'"' -f4)
        duration=$(grep -o '"duration_seconds": [0-9]*' "$job_file" | awk '{print $2}')

        total_duration=$((total_duration + duration))

        if [[ "$status" == "SUCCESS" ]]; then
            success=$((success + 1))
        else
            failed=$((failed + 1))
        fi
    done

    echo "Summary:"
    echo "  Total Jobs: $total"
    echo -e "  Successful: ${GREEN}$success${NC}"
    echo -e "  Failed: ${RED}$failed${NC}"
    echo "  Total Runtime: ${total_duration}s"
    echo ""

    if [[ $failed -gt 0 ]]; then
        echo "Failed Jobs:"
        list_failed | grep -A3 "^✗" || true
    fi

    # Send report email if configured
    if [[ -n "$ALERT_EMAIL" ]]; then
        generate_report 2>/dev/null | mail -s "Cron Watchdog Daily Report" "$ALERT_EMAIL"
    fi
}

# Clean old history
clean_history() {
    local days="${1:-30}"

    log "INFO" "Cleaning history older than $days days"

    find "$WATCHDOG_DIR/history" -type f -mtime +"$days" -delete 2>/dev/null || true

    # Trim history files
    for history_file in "$WATCHDOG_DIR/history"/*.log; do
        [[ -f "$history_file" ]] || continue
        tail -n "$MAX_HISTORY" "$history_file" > "${history_file}.tmp"
        mv "${history_file}.tmp" "$history_file"
    done

    log "INFO" "History cleanup completed"
}

# Main
main() {
    local command="${1:-}"
    shift || true

    # Parse global options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -e|--email)
                ALERT_EMAIL="$2"
                shift 2
                ;;
            -w|--warn-duration)
                WARN_DURATION="$2"
                shift 2
                ;;
            -c|--critical-duration)
                CRITICAL_DURATION="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                break
                ;;
        esac
    done

    case "$command" in
        wrap)
            [[ $# -ge 2 ]] || { echo "Usage: $0 wrap JOBNAME COMMAND"; exit 1; }
            local job_name="$1"
            shift
            wrap_job "$job_name" "$@"
            ;;
        status)
            show_status "${1:-}"
            ;;
        history)
            [[ $# -ge 1 ]] || { echo "Usage: $0 history JOBNAME"; exit 1; }
            show_history "$1"
            ;;
        failed)
            list_failed
            ;;
        report)
            generate_report
            ;;
        clean)
            clean_history "${1:-30}"
            ;;
        ""|help|-h|--help)
            usage
            ;;
        *)
            echo "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

main "$@"
```

---

## Utilisation

### Dans le Crontab

```bash
# Remplacer vos jobs cron existants par des appels wrappés
# AVANT:
# 0 2 * * * /opt/scripts/backup.sh

# APRÈS:
0 2 * * * /opt/scripts/cron-watchdog.sh wrap "backup-daily" /opt/scripts/backup.sh

# Avec timeout et alertes email
0 3 * * * /opt/scripts/cron-watchdog.sh wrap "etl-job" -t 7200 -e ops@example.com /opt/scripts/etl.sh

# Avec seuils de durée
*/5 * * * * /opt/scripts/cron-watchdog.sh wrap "health-check" -w 60 -c 300 /opt/scripts/check.sh
```

### Commandes Standalone

```bash
# Voir le status de tous les jobs
./cron-watchdog.sh status

# Filtrer par nom
./cron-watchdog.sh status backup

# Historique d'un job
./cron-watchdog.sh history backup-daily

# Liste des jobs en échec
./cron-watchdog.sh failed

# Rapport quotidien
./cron-watchdog.sh report

# Nettoyage de l'historique
./cron-watchdog.sh clean 30  # Plus de 30 jours
```

---

## Sortie Exemple

### Status

```text
═══════════════════════════════════════════════════════════
  CRON WATCHDOG STATUS
═══════════════════════════════════════════════════════════

JOB NAME             LAST RUN             DURATION   EXIT     STATUS
--------             --------             --------   ----     ------
backup-daily         2024-01-15 02:15:33  12m45s     0        SUCCESS
etl-job              2024-01-15 03:45:12  45m22s     0        SUCCESS
health-check         2024-01-15 14:30:01  8s         1        FAILED
log-rotate           2024-01-15 00:00:05  2s         0        SUCCESS
```

### Failed Jobs

```text
═══════════════════════════════════════════════════════════
  FAILED JOBS
═══════════════════════════════════════════════════════════

✗ health-check
    Last Run: 2024-01-15 14:30:01
    Exit Code: 1
    Status: FAILED

✗ cleanup-old
    Last Run: 2024-01-14 23:00:15
    Exit Code: 124
    Status: TIMEOUT
```

### History

```text
═══════════════════════════════════════════════════════════
  HISTORY: backup-daily
═══════════════════════════════════════════════════════════

TIMESTAMP            DURATION   EXIT     STATUS
---------            --------   ----     ------
2024-01-15 02:15:33  12m45s     0        SUCCESS
2024-01-14 02:14:22  12m30s     0        SUCCESS
2024-01-13 02:16:01  12m55s     0        SUCCESS
2024-01-12 02:13:44  12m12s     0        SUCCESS
2024-01-11 02:45:33  35m22s     1        FAILED

Statistics (last 20 runs):
  Success: 19 (95%)
  Failed: 1
```

---

## Structure des Données

```text
/var/lib/cron-watchdog/
├── jobs/
│   ├── backup-daily      # Status JSON du job
│   ├── etl-job
│   └── health-check
└── history/
    ├── backup-daily.log  # Historique des exécutions
    ├── etl-job.log
    └── health-check.log
```

Format du fichier job (JSON):
```json
{
    "name": "backup-daily",
    "last_run": "2024-01-15 02:15:33",
    "duration_seconds": 765,
    "exit_code": 0,
    "status": "SUCCESS",
    "duration_status": "OK"
}
```

---

## Automatisation

```bash
# Rapport quotidien à 8h
0 8 * * * /opt/scripts/cron-watchdog.sh report -e ops@example.com

# Nettoyage hebdomadaire
0 0 * * 0 /opt/scripts/cron-watchdog.sh clean 60
```

---

## Voir Aussi

- [service-manager.sh](service-manager.md)
- [health-check.sh](health-check.md)
