---
tags:
  - scripts
  - bash
  - logs
  - linux
  - sysadmin
---

# logs-extractor.sh

:material-star::material-star: **Niveau : Intermédiaire**

Extraction de logs basée sur une plage horaire.

---

## Description

Ce script permet d'extraire des entrées de logs en fonction d'une plage horaire définie. Il supporte plusieurs formats de logs courants :

- **Syslog** : Format standard Linux (`/var/log/syslog`, `/var/log/messages`)
- **Auth logs** : Journaux d'authentification (`/var/log/auth.log`)
- **Logs web** : Format Apache/Nginx combined (`access.log`, `error.log`)

---

## Prérequis

```bash
# Outils standards (présents sur la plupart des distributions)
awk --version
sed --version

# Optionnel : pour les logs compressés
zcat --version
```

---

## Script

```bash
#!/bin/bash
#===============================================================================
# logs-extractor.sh - Extract logs based on time range
#===============================================================================
# Author: ShellBook
# Version: 1.0
# Description: Filter log entries between start and end times
#===============================================================================

set -euo pipefail

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Default values
START_TIME=""
END_TIME=""
LOG_FILE=""
LOG_FORMAT="auto"
OUTPUT_FILE=""
INCLUDE_PATTERN=""
EXCLUDE_PATTERN=""
SHOW_COUNT=false

#===============================================================================
# Functions
#===============================================================================

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Extract log entries based on a time range.

Required:
    -s, --start TIME      Start time in HH:MM format (24h)
    -e, --end TIME        End time in HH:MM format (24h)
    -f, --file PATH       Path to the log file

Optional:
    -F, --format FORMAT   Log format: auto, syslog, apache, nginx (default: auto)
    -o, --output FILE     Output file (default: stdout)
    -i, --include REGEX   Only include lines matching regex
    -x, --exclude REGEX   Exclude lines matching regex
    -c, --count           Show line count statistics
    -h, --help            Show this help message

Examples:
    $(basename "$0") -s 08:00 -e 12:00 -f /var/log/syslog
    $(basename "$0") --start 14:30 --end 16:45 --file /var/log/auth.log -c
    $(basename "$0") -s 00:00 -e 06:00 -f /var/log/nginx/access.log -F nginx

Supported formats:
    syslog  - Standard syslog (Mon DD HH:MM:SS)
    apache  - Apache combined log format
    nginx   - Nginx combined log format
    auto    - Auto-detect based on file content
EOF
    exit 0
}

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

validate_time() {
    local time="$1"
    local name="$2"

    if [[ ! "$time" =~ ^([01]?[0-9]|2[0-3]):[0-5][0-9]$ ]]; then
        log_error "Invalid $name time format: $time (expected HH:MM)"
        exit 1
    fi
}

detect_format() {
    local file="$1"
    local sample

    # Read first non-empty line
    if [[ "$file" == *.gz ]]; then
        sample=$(zcat "$file" 2>/dev/null | head -20 | grep -v '^$' | head -1)
    else
        sample=$(head -20 "$file" 2>/dev/null | grep -v '^$' | head -1)
    fi

    # Detect format based on pattern
    if [[ "$sample" =~ ^[A-Z][a-z]{2}\ +[0-9]+\ [0-9]{2}:[0-9]{2}:[0-9]{2} ]]; then
        echo "syslog"
    elif [[ "$sample" =~ \[[0-9]{2}/[A-Z][a-z]{2}/[0-9]{4}:[0-9]{2}:[0-9]{2}:[0-9]{2} ]]; then
        echo "apache"
    elif [[ "$sample" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\ -\ - ]]; then
        echo "nginx"
    else
        echo "syslog"  # Default fallback
    fi
}

extract_syslog() {
    local file="$1"
    local start="$2"
    local end="$3"

    # Convert HH:MM to comparable format
    local start_mins=$((10#${start%:*} * 60 + 10#${start#*:}))
    local end_mins=$((10#${end%:*} * 60 + 10#${end#*:}))

    # Handle overnight ranges (e.g., 23:00 to 02:00)
    local overnight=false
    if [[ $end_mins -lt $start_mins ]]; then
        overnight=true
    fi

    # AWK script for syslog format extraction
    local awk_script='
    {
        # Extract time from syslog format: Mon DD HH:MM:SS
        if (match($0, /^[A-Za-z]{3} +[0-9]+ ([0-9]{2}):([0-9]{2}):[0-9]{2}/, arr)) {
            hour = arr[1]
            min = arr[2]
            current_mins = (hour * 60) + min

            if (overnight == "true") {
                # Overnight: include if >= start OR <= end
                if (current_mins >= start_mins || current_mins <= end_mins) {
                    print
                }
            } else {
                # Normal: include if >= start AND <= end
                if (current_mins >= start_mins && current_mins <= end_mins) {
                    print
                }
            }
        }
    }'

    if [[ "$file" == *.gz ]]; then
        zcat "$file" | awk -v start_mins="$start_mins" -v end_mins="$end_mins" \
            -v overnight="$overnight" "$awk_script"
    else
        awk -v start_mins="$start_mins" -v end_mins="$end_mins" \
            -v overnight="$overnight" "$awk_script" "$file"
    fi
}

extract_apache_nginx() {
    local file="$1"
    local start="$2"
    local end="$3"

    local start_mins=$((10#${start%:*} * 60 + 10#${start#*:}))
    local end_mins=$((10#${end%:*} * 60 + 10#${end#*:}))

    local overnight=false
    if [[ $end_mins -lt $start_mins ]]; then
        overnight=true
    fi

    # AWK script for Apache/Nginx combined log format
    # Format: IP - - [DD/Mon/YYYY:HH:MM:SS +0000] "REQUEST" ...
    local awk_script='
    {
        # Extract time from Apache/Nginx format: [DD/Mon/YYYY:HH:MM:SS
        if (match($0, /\[[0-9]{2}\/[A-Za-z]{3}\/[0-9]{4}:([0-9]{2}):([0-9]{2}):[0-9]{2}/, arr)) {
            hour = arr[1]
            min = arr[2]
            current_mins = (hour * 60) + min

            if (overnight == "true") {
                if (current_mins >= start_mins || current_mins <= end_mins) {
                    print
                }
            } else {
                if (current_mins >= start_mins && current_mins <= end_mins) {
                    print
                }
            }
        }
    }'

    if [[ "$file" == *.gz ]]; then
        zcat "$file" | awk -v start_mins="$start_mins" -v end_mins="$end_mins" \
            -v overnight="$overnight" "$awk_script"
    else
        awk -v start_mins="$start_mins" -v end_mins="$end_mins" \
            -v overnight="$overnight" "$awk_script" "$file"
    fi
}

apply_filters() {
    local input="$1"

    if [[ -n "$INCLUDE_PATTERN" ]] && [[ -n "$EXCLUDE_PATTERN" ]]; then
        echo "$input" | grep -E "$INCLUDE_PATTERN" | grep -Ev "$EXCLUDE_PATTERN"
    elif [[ -n "$INCLUDE_PATTERN" ]]; then
        echo "$input" | grep -E "$INCLUDE_PATTERN"
    elif [[ -n "$EXCLUDE_PATTERN" ]]; then
        echo "$input" | grep -Ev "$EXCLUDE_PATTERN"
    else
        echo "$input"
    fi
}

#===============================================================================
# Parse arguments
#===============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--start)
            START_TIME="$2"
            shift 2
            ;;
        -e|--end)
            END_TIME="$2"
            shift 2
            ;;
        -f|--file)
            LOG_FILE="$2"
            shift 2
            ;;
        -F|--format)
            LOG_FORMAT="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        -i|--include)
            INCLUDE_PATTERN="$2"
            shift 2
            ;;
        -x|--exclude)
            EXCLUDE_PATTERN="$2"
            shift 2
            ;;
        -c|--count)
            SHOW_COUNT=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information."
            exit 1
            ;;
    esac
done

#===============================================================================
# Validation
#===============================================================================

# Check required arguments
if [[ -z "$START_TIME" ]] || [[ -z "$END_TIME" ]] || [[ -z "$LOG_FILE" ]]; then
    log_error "Missing required arguments."
    echo "Use --help for usage information."
    exit 1
fi

# Validate time formats
validate_time "$START_TIME" "start"
validate_time "$END_TIME" "end"

# Check if file exists
if [[ ! -f "$LOG_FILE" ]]; then
    log_error "Log file not found: $LOG_FILE"
    exit 1
fi

# Check if file is readable
if [[ ! -r "$LOG_FILE" ]]; then
    log_error "Cannot read log file: $LOG_FILE (permission denied)"
    exit 1
fi

#===============================================================================
# Main extraction
#===============================================================================

log_info "Extracting logs from: $LOG_FILE"
log_info "Time range: $START_TIME - $END_TIME"

# Auto-detect format if needed
if [[ "$LOG_FORMAT" == "auto" ]]; then
    LOG_FORMAT=$(detect_format "$LOG_FILE")
    log_info "Detected format: $LOG_FORMAT"
fi

# Extract based on format
case "$LOG_FORMAT" in
    syslog)
        extracted=$(extract_syslog "$LOG_FILE" "$START_TIME" "$END_TIME")
        ;;
    apache|nginx)
        extracted=$(extract_apache_nginx "$LOG_FILE" "$START_TIME" "$END_TIME")
        ;;
    *)
        log_error "Unknown format: $LOG_FORMAT"
        exit 1
        ;;
esac

# Apply include/exclude filters
filtered=$(apply_filters "$extracted")

# Output results
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "$filtered" > "$OUTPUT_FILE"
    log_info "Output written to: $OUTPUT_FILE"
else
    echo "$filtered"
fi

# Show statistics
if [[ "$SHOW_COUNT" == true ]]; then
    total_lines=$(wc -l < "$LOG_FILE")
    extracted_lines=$(echo "$extracted" | grep -c . || echo 0)
    filtered_lines=$(echo "$filtered" | grep -c . || echo 0)

    echo ""
    log_info "Statistics:"
    echo -e "  ${CYAN}Total lines in file:${NC} $total_lines"
    echo -e "  ${CYAN}Lines in time range:${NC} $extracted_lines"
    echo -e "  ${CYAN}Lines after filters:${NC} $filtered_lines"
fi
```

---

## Usage

### Extraction simple

```bash
# Extraire les logs syslog entre 08:00 et 12:00
./logs-extractor.sh -s 08:00 -e 12:00 -f /var/log/syslog

# Avec statistiques
./logs-extractor.sh --start 14:30 --end 16:45 --file /var/log/auth.log -c
```

### Logs web (Apache/Nginx)

```bash
# Logs d'accès Nginx
./logs-extractor.sh -s 00:00 -e 06:00 -f /var/log/nginx/access.log -F nginx

# Logs Apache avec export
./logs-extractor.sh -s 10:00 -e 11:00 -f /var/log/apache2/access.log -o extracted.log
```

### Filtrage avancé

```bash
# Inclure uniquement les erreurs SSH
./logs-extractor.sh -s 08:00 -e 18:00 -f /var/log/auth.log -i "sshd.*Failed"

# Exclure les requêtes de healthcheck
./logs-extractor.sh -s 00:00 -e 23:59 -f /var/log/nginx/access.log -x "healthcheck|monitoring"

# Combiner inclusion et exclusion
./logs-extractor.sh -s 09:00 -e 17:00 -f /var/log/syslog -i "error|warning" -x "cron"
```

### Plages horaires nocturnes

```bash
# Extraction sur la nuit (23:00 -> 06:00)
./logs-extractor.sh -s 23:00 -e 06:00 -f /var/log/auth.log
```

---

## Sortie exemple

```bash
[INFO] Extracting logs from: /var/log/auth.log
[INFO] Time range: 08:00 - 12:00
[INFO] Detected format: syslog
Nov 30 08:15:22 server sshd[1234]: Accepted publickey for admin from 192.168.1.10
Nov 30 09:30:45 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; COMMAND=/bin/systemctl restart nginx
Nov 30 11:45:12 server sshd[5678]: Failed password for invalid user test from 10.0.0.5

[INFO] Statistics:
  Total lines in file: 15234
  Lines in time range: 127
  Lines after filters: 127
```

---

!!! warning "Permissions requises"
    Ce script nécessite les droits de lecture sur les ficyesterdays de logs ciblés.
    La plupart des logs système (`/var/log/syslog`, `/var/log/auth.log`) requièrent
    des privilèges `root` ou l'appartenance au groupe `adm`.

    ```bash
    # Check l'accès
    sudo ./logs-extractor.sh -s 08:00 -e 12:00 -f /var/log/auth.log

    # Ou ajouter l'utilisateur au groupe adm
    sudo usermod -aG adm $USER
    ```

---

## Voir Aussi

- [log-analyzer.sh](log-analyzer.md) - Analyse statistique des logs
- [security-audit.sh](security-audit.md) - Audit de sécurité incluant l'analyse des logs
