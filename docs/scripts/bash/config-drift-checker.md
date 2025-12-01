# Config Drift Checker

Script de détection des dérives de configuration par rapport à une baseline.

## Description

- **Baseline Management** : Capture et stockage de l'état de référence
- **Multi-fichiers** : Surveillance de plusieurs fichiers/répertoires
- **Diff intelligent** : Ignorance des commentaires et lignes vides optionnelle
- **Alerting** : Notification des changements détectés
- **Rapport détaillé** : Export JSON/Markdown des différences
- **Restauration** : Option de rollback vers la baseline

## Utilisation

```bash
# Capture baseline initiale
./config-drift-checker.sh baseline /etc/nginx /etc/ssh/sshd_config

# Vérification des dérives
./config-drift-checker.sh check

# Vérification avec rapport détaillé
./config-drift-checker.sh check --report drift-report.md

# Afficher les différences d'un fichier
./config-drift-checker.sh diff /etc/nginx/nginx.conf

# Restaurer un fichier depuis la baseline
./config-drift-checker.sh restore /etc/nginx/nginx.conf

# Mettre à jour la baseline (accepter les changements)
./config-drift-checker.sh accept /etc/nginx/nginx.conf

# Lister les fichiers surveillés
./config-drift-checker.sh list
```

## Configuration

Fichier `~/.config/drift-checker/config.yaml` :

```yaml
baseline_dir: /var/lib/drift-checker/baselines
ignore_patterns:
  - "^#"           # Comments
  - "^\\s*$"       # Empty lines
  - "^;.*"         # INI comments
watch_paths:
  - /etc/nginx
  - /etc/ssh/sshd_config
  - /etc/hosts
  - /etc/resolv.conf
exclude_patterns:
  - "*.swp"
  - "*.bak"
  - "*~"
alert_command: "echo 'Drift detected: {file}' | mail -s 'Config Drift Alert' admin@example.com"
```

## Code Source

```bash
#!/usr/bin/env bash
#===============================================================================
# Config Drift Checker - Detect configuration changes against baseline
# Author: ShellBook
# Version: 1.0.0
#===============================================================================

set -euo pipefail

# Configuration
SCRIPT_NAME="config-drift-checker"
VERSION="1.0.0"
CONFIG_DIR="${HOME}/.config/drift-checker"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
DEFAULT_BASELINE_DIR="/var/lib/drift-checker/baselines"
BASELINE_DIR="${DEFAULT_BASELINE_DIR}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Counters
TOTAL_FILES=0
DRIFTED_FILES=0
MISSING_FILES=0
NEW_FILES=0

#-------------------------------------------------------------------------------
# Logging functions
#-------------------------------------------------------------------------------
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_drift() { echo -e "${RED}[DRIFT]${NC} $*"; }

#-------------------------------------------------------------------------------
# Display help message
#-------------------------------------------------------------------------------
show_help() {
    cat << EOF
${CYAN}Config Drift Checker v${VERSION}${NC}

Detect configuration file changes against a stored baseline.

${YELLOW}USAGE:${NC}
    $SCRIPT_NAME <command> [options] [paths...]

${YELLOW}COMMANDS:${NC}
    baseline <paths...>     Capture baseline for specified files/directories
    check                   Check all watched files for drift
    diff <file>             Show differences for a specific file
    restore <file>          Restore file from baseline (requires sudo)
    accept <file>           Update baseline with current file state
    list                    List all files in baseline
    status                  Show overall drift status

${YELLOW}OPTIONS:${NC}
    -r, --report <file>     Generate report (supports .md and .json)
    -i, --ignore-comments   Ignore comment lines in comparison
    -i, --ignore-whitespace Ignore whitespace differences
    -q, --quiet             Suppress output, exit code only
    -v, --verbose           Show detailed output
    -h, --help              Show this help message

${YELLOW}EXAMPLES:${NC}
    # Create baseline for critical configs
    $SCRIPT_NAME baseline /etc/nginx /etc/ssh/sshd_config

    # Check for drift
    $SCRIPT_NAME check

    # Generate JSON report for CI/CD
    $SCRIPT_NAME check --report drift.json

    # View specific file drift
    $SCRIPT_NAME diff /etc/nginx/nginx.conf

    # Accept current state as new baseline
    $SCRIPT_NAME accept /etc/nginx/nginx.conf

${YELLOW}EXIT CODES:${NC}
    0 - No drift detected
    1 - Drift detected
    2 - Error occurred

EOF
}

#-------------------------------------------------------------------------------
# Initialize configuration directory
#-------------------------------------------------------------------------------
init_config() {
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${BASELINE_DIR}"

    # Create default config if not exists
    if [[ ! -f "${CONFIG_FILE}" ]]; then
        cat > "${CONFIG_FILE}" << 'YAML'
baseline_dir: /var/lib/drift-checker/baselines
ignore_patterns:
  - "^#"
  - "^\\s*$"
watch_paths: []
exclude_patterns:
  - "*.swp"
  - "*.bak"
  - "*~"
  - ".git"
alert_command: ""
YAML
        log_info "Created default config at ${CONFIG_FILE}"
    fi

    # Load baseline directory from config if available
    if command -v yq &>/dev/null; then
        local dir
        dir=$(yq -r '.baseline_dir // empty' "${CONFIG_FILE}" 2>/dev/null || true)
        [[ -n "${dir}" ]] && BASELINE_DIR="${dir}"
    fi

    mkdir -p "${BASELINE_DIR}"
}

#-------------------------------------------------------------------------------
# Get baseline path for a file
#-------------------------------------------------------------------------------
get_baseline_path() {
    local file="$1"
    local abs_path
    abs_path=$(realpath -m "${file}")
    echo "${BASELINE_DIR}${abs_path}"
}

#-------------------------------------------------------------------------------
# Capture baseline for a file
#-------------------------------------------------------------------------------
capture_file_baseline() {
    local file="$1"
    local baseline_path

    if [[ ! -f "${file}" ]]; then
        log_error "File not found: ${file}"
        return 1
    fi

    baseline_path=$(get_baseline_path "${file}")
    mkdir -p "$(dirname "${baseline_path}")"

    # Copy file with metadata
    cp -p "${file}" "${baseline_path}"

    # Store metadata
    local meta_file="${baseline_path}.meta"
    cat > "${meta_file}" << EOF
captured_at: $(date -Iseconds)
original_path: $(realpath "${file}")
permissions: $(stat -c '%a' "${file}")
owner: $(stat -c '%U:%G' "${file}")
size: $(stat -c '%s' "${file}")
md5: $(md5sum "${file}" | cut -d' ' -f1)
sha256: $(sha256sum "${file}" | cut -d' ' -f1)
EOF

    log_success "Captured baseline: ${file}"
}

#-------------------------------------------------------------------------------
# Capture baseline for a directory
#-------------------------------------------------------------------------------
capture_directory_baseline() {
    local dir="$1"
    local count=0

    if [[ ! -d "${dir}" ]]; then
        log_error "Directory not found: ${dir}"
        return 1
    fi

    log_info "Scanning directory: ${dir}"

    while IFS= read -r -d '' file; do
        # Skip excluded patterns
        local skip=false
        for pattern in "*.swp" "*.bak" "*~" ".git"; do
            if [[ "${file}" == ${pattern} ]]; then
                skip=true
                break
            fi
        done

        if [[ "${skip}" == "false" ]]; then
            capture_file_baseline "${file}"
            ((count++))
        fi
    done < <(find "${dir}" -type f -print0 2>/dev/null)

    log_info "Captured ${count} files from ${dir}"
}

#-------------------------------------------------------------------------------
# Command: baseline
#-------------------------------------------------------------------------------
cmd_baseline() {
    local paths=("$@")

    if [[ ${#paths[@]} -eq 0 ]]; then
        log_error "No paths specified"
        echo "Usage: $SCRIPT_NAME baseline <path> [path...]"
        return 1
    fi

    for path in "${paths[@]}"; do
        if [[ -d "${path}" ]]; then
            capture_directory_baseline "${path}"
        elif [[ -f "${path}" ]]; then
            capture_file_baseline "${path}"
        else
            log_error "Path not found: ${path}"
        fi
    done

    log_success "Baseline capture complete"
}

#-------------------------------------------------------------------------------
# Check single file for drift
#-------------------------------------------------------------------------------
check_file_drift() {
    local file="$1"
    local ignore_comments="${2:-false}"
    local ignore_whitespace="${3:-false}"
    local verbose="${4:-false}"

    local baseline_path
    baseline_path=$(get_baseline_path "${file}")

    ((TOTAL_FILES++))

    # Check if baseline exists
    if [[ ! -f "${baseline_path}" ]]; then
        if [[ -f "${file}" ]]; then
            log_warning "No baseline for: ${file} (new file?)"
            ((NEW_FILES++))
            return 1
        fi
        return 0
    fi

    # Check if file exists
    if [[ ! -f "${file}" ]]; then
        log_drift "File missing: ${file}"
        ((MISSING_FILES++))
        return 1
    fi

    # Compare files
    local diff_opts=()
    [[ "${ignore_whitespace}" == "true" ]] && diff_opts+=("-w")

    local diff_output
    if [[ "${ignore_comments}" == "true" ]]; then
        # Filter comments before comparison
        diff_output=$(diff "${diff_opts[@]}" \
            <(grep -v '^\s*#' "${baseline_path}" | grep -v '^\s*$') \
            <(grep -v '^\s*#' "${file}" | grep -v '^\s*$') 2>/dev/null || true)
    else
        diff_output=$(diff "${diff_opts[@]}" "${baseline_path}" "${file}" 2>/dev/null || true)
    fi

    if [[ -n "${diff_output}" ]]; then
        log_drift "Drift detected: ${file}"
        ((DRIFTED_FILES++))

        if [[ "${verbose}" == "true" ]]; then
            echo "${diff_output}" | head -20
            local lines
            lines=$(echo "${diff_output}" | wc -l)
            if [[ ${lines} -gt 20 ]]; then
                echo "... (${lines} total lines changed)"
            fi
        fi

        return 1
    else
        [[ "${verbose}" == "true" ]] && log_success "No drift: ${file}"
        return 0
    fi
}

#-------------------------------------------------------------------------------
# Command: check
#-------------------------------------------------------------------------------
cmd_check() {
    local report_file=""
    local ignore_comments=false
    local ignore_whitespace=false
    local quiet=false
    local verbose=false

    # Parse options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -r|--report) report_file="$2"; shift 2 ;;
            -i|--ignore-comments) ignore_comments=true; shift ;;
            -w|--ignore-whitespace) ignore_whitespace=true; shift ;;
            -q|--quiet) quiet=true; shift ;;
            -v|--verbose) verbose=true; shift ;;
            *) shift ;;
        esac
    done

    [[ "${quiet}" == "false" ]] && log_info "Checking for configuration drift..."

    local has_drift=false
    local drift_details=()

    # Find all baseline files
    while IFS= read -r -d '' baseline; do
        local original_path="${baseline#${BASELINE_DIR}}"
        original_path="${original_path%.meta}"

        # Skip metadata files
        [[ "${baseline}" == *.meta ]] && continue

        if ! check_file_drift "${original_path}" "${ignore_comments}" "${ignore_whitespace}" "${verbose}"; then
            has_drift=true
            drift_details+=("${original_path}")
        fi
    done < <(find "${BASELINE_DIR}" -type f ! -name "*.meta" -print0 2>/dev/null)

    # Print summary
    if [[ "${quiet}" == "false" ]]; then
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "${CYAN}DRIFT CHECK SUMMARY${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Total files checked:  ${TOTAL_FILES}"
        echo -e "Files with drift:     ${RED}${DRIFTED_FILES}${NC}"
        echo -e "Missing files:        ${YELLOW}${MISSING_FILES}${NC}"
        echo -e "New files (no base):  ${BLUE}${NEW_FILES}${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        if [[ "${has_drift}" == "true" ]]; then
            echo -e "\n${RED}⚠ DRIFT DETECTED${NC}"
        else
            echo -e "\n${GREEN}✓ NO DRIFT DETECTED${NC}"
        fi
    fi

    # Generate report if requested
    if [[ -n "${report_file}" ]]; then
        generate_report "${report_file}" "${drift_details[@]}"
    fi

    [[ "${has_drift}" == "true" ]] && return 1
    return 0
}

#-------------------------------------------------------------------------------
# Generate report
#-------------------------------------------------------------------------------
generate_report() {
    local report_file="$1"
    shift
    local drift_files=("$@")

    local timestamp
    timestamp=$(date -Iseconds)

    if [[ "${report_file}" == *.json ]]; then
        # JSON report
        cat > "${report_file}" << EOF
{
  "timestamp": "${timestamp}",
  "hostname": "$(hostname)",
  "summary": {
    "total_files": ${TOTAL_FILES},
    "drifted_files": ${DRIFTED_FILES},
    "missing_files": ${MISSING_FILES},
    "new_files": ${NEW_FILES}
  },
  "drift_detected": $([ ${DRIFTED_FILES} -gt 0 ] && echo "true" || echo "false"),
  "files_with_drift": [
$(printf '    "%s",\n' "${drift_files[@]}" | sed '$ s/,$//')
  ]
}
EOF
    else
        # Markdown report
        cat > "${report_file}" << EOF
# Configuration Drift Report

**Generated:** ${timestamp}
**Host:** $(hostname)

## Summary

| Metric | Value |
|--------|-------|
| Total Files | ${TOTAL_FILES} |
| Files with Drift | ${DRIFTED_FILES} |
| Missing Files | ${MISSING_FILES} |
| New Files | ${NEW_FILES} |

## Status

EOF
        if [[ ${DRIFTED_FILES} -gt 0 ]]; then
            echo "⚠️ **DRIFT DETECTED**" >> "${report_file}"
            echo "" >> "${report_file}"
            echo "### Files with Drift" >> "${report_file}"
            echo "" >> "${report_file}"
            for f in "${drift_files[@]}"; do
                echo "- \`${f}\`" >> "${report_file}"
            done
        else
            echo "✅ **No drift detected**" >> "${report_file}"
        fi
    fi

    log_success "Report generated: ${report_file}"
}

#-------------------------------------------------------------------------------
# Command: diff
#-------------------------------------------------------------------------------
cmd_diff() {
    local file="$1"
    local baseline_path
    baseline_path=$(get_baseline_path "${file}")

    if [[ ! -f "${baseline_path}" ]]; then
        log_error "No baseline found for: ${file}"
        return 1
    fi

    if [[ ! -f "${file}" ]]; then
        log_error "File not found: ${file}"
        log_info "Baseline exists at: ${baseline_path}"
        return 1
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${CYAN}Diff: ${file}${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Show metadata
    if [[ -f "${baseline_path}.meta" ]]; then
        echo -e "${YELLOW}Baseline captured:${NC} $(grep 'captured_at' "${baseline_path}.meta" | cut -d' ' -f2-)"
    fi
    echo ""

    # Use colordiff if available
    if command -v colordiff &>/dev/null; then
        diff -u "${baseline_path}" "${file}" | colordiff || true
    else
        diff -u "${baseline_path}" "${file}" || true
    fi
}

#-------------------------------------------------------------------------------
# Command: restore
#-------------------------------------------------------------------------------
cmd_restore() {
    local file="$1"
    local baseline_path
    baseline_path=$(get_baseline_path "${file}")

    if [[ ! -f "${baseline_path}" ]]; then
        log_error "No baseline found for: ${file}"
        return 1
    fi

    log_warning "This will overwrite: ${file}"
    echo -n "Continue? [y/N] "
    read -r confirm

    if [[ "${confirm}" =~ ^[Yy]$ ]]; then
        # Backup current file
        if [[ -f "${file}" ]]; then
            cp "${file}" "${file}.drift-backup.$(date +%Y%m%d%H%M%S)"
            log_info "Backed up current file"
        fi

        # Restore from baseline
        cp -p "${baseline_path}" "${file}"

        # Restore permissions if metadata exists
        if [[ -f "${baseline_path}.meta" ]]; then
            local perms owner
            perms=$(grep 'permissions' "${baseline_path}.meta" | cut -d' ' -f2)
            owner=$(grep 'owner' "${baseline_path}.meta" | cut -d' ' -f2)
            chmod "${perms}" "${file}" 2>/dev/null || true
            chown "${owner}" "${file}" 2>/dev/null || true
        fi

        log_success "Restored: ${file}"
    else
        log_info "Restore cancelled"
    fi
}

#-------------------------------------------------------------------------------
# Command: accept
#-------------------------------------------------------------------------------
cmd_accept() {
    local file="$1"

    if [[ ! -f "${file}" ]]; then
        log_error "File not found: ${file}"
        return 1
    fi

    capture_file_baseline "${file}"
    log_success "Baseline updated for: ${file}"
}

#-------------------------------------------------------------------------------
# Command: list
#-------------------------------------------------------------------------------
cmd_list() {
    log_info "Files in baseline:"
    echo ""

    local count=0
    while IFS= read -r -d '' baseline; do
        [[ "${baseline}" == *.meta ]] && continue

        local original_path="${baseline#${BASELINE_DIR}}"
        local status="${GREEN}✓${NC}"

        if [[ ! -f "${original_path}" ]]; then
            status="${RED}✗ MISSING${NC}"
        elif ! diff -q "${baseline}" "${original_path}" &>/dev/null; then
            status="${YELLOW}⚠ DRIFTED${NC}"
        fi

        echo -e "  ${status} ${original_path}"
        ((count++))
    done < <(find "${BASELINE_DIR}" -type f ! -name "*.meta" -print0 2>/dev/null | sort -z)

    echo ""
    log_info "Total: ${count} files"
}

#-------------------------------------------------------------------------------
# Command: status
#-------------------------------------------------------------------------------
cmd_status() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${CYAN}Config Drift Checker Status${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Config file:   ${CONFIG_FILE}"
    echo "Baseline dir:  ${BASELINE_DIR}"

    local file_count
    file_count=$(find "${BASELINE_DIR}" -type f ! -name "*.meta" 2>/dev/null | wc -l)
    echo "Files tracked: ${file_count}"

    local size
    size=$(du -sh "${BASELINE_DIR}" 2>/dev/null | cut -f1)
    echo "Baseline size: ${size:-0}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

#-------------------------------------------------------------------------------
# Main
#-------------------------------------------------------------------------------
main() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi

    init_config

    local command="$1"
    shift

    case "${command}" in
        baseline)
            cmd_baseline "$@"
            ;;
        check)
            cmd_check "$@"
            ;;
        diff)
            [[ $# -eq 0 ]] && { log_error "File path required"; exit 2; }
            cmd_diff "$1"
            ;;
        restore)
            [[ $# -eq 0 ]] && { log_error "File path required"; exit 2; }
            cmd_restore "$1"
            ;;
        accept)
            [[ $# -eq 0 ]] && { log_error "File path required"; exit 2; }
            cmd_accept "$1"
            ;;
        list)
            cmd_list
            ;;
        status)
            cmd_status
            ;;
        -h|--help|help)
            show_help
            ;;
        -v|--version)
            echo "${SCRIPT_NAME} v${VERSION}"
            ;;
        *)
            log_error "Unknown command: ${command}"
            echo "Use '$SCRIPT_NAME --help' for usage"
            exit 2
            ;;
    esac
}

main "$@"
```

## Intégration CI/CD

### GitLab CI

```yaml
drift_check:
  stage: compliance
  script:
    - ./config-drift-checker.sh check --report drift.json
  artifacts:
    paths:
      - drift.json
    reports:
      dotenv: drift.json
  allow_failure: false
```

### Cron Job

```bash
# Check drift daily at 6 AM
0 6 * * * /usr/local/bin/config-drift-checker.sh check --report /var/log/drift-$(date +\%Y\%m\%d).json
```

## Cas d'Usage

1. **Compliance Auditing** : Vérifier que les configurations n'ont pas changé depuis l'audit
2. **Change Management** : Détecter les modifications non autorisées
3. **Disaster Recovery** : Valider la restauration des configurations
4. **Security Monitoring** : Alerter sur les modifications de fichiers sensibles
