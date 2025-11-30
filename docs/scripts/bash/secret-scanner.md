# Secret Scanner

Script Bash de détection de secrets et credentials dans les repositories git et fichiers.

## Fonctionnalités

- **Patterns étendus** : Détection de 30+ types de secrets (API keys, tokens, passwords)
- **Git-aware** : Scan de l'historique git complet
- **Multi-format** : Support JSON, YAML, .env, code source
- **Pre-commit** : Intégration comme hook git
- **Exclusions** : Fichiers de test et faux positifs configurables
- **CI/CD Ready** : Exit codes et rapports JSON

## Utilisation

```bash
# Scan du répertoire courant
./secret-scanner.sh scan

# Scan d'un répertoire spécifique
./secret-scanner.sh scan /path/to/project

# Scan de l'historique git
./secret-scanner.sh scan --git-history

# Mode strict (fail on any finding)
./secret-scanner.sh scan --strict

# Export rapport JSON
./secret-scanner.sh scan --output report.json

# Vérifier un fichier spécifique
./secret-scanner.sh check file.yaml

# Installer comme pre-commit hook
./secret-scanner.sh install-hook
```

## Patterns Détectés

| Type | Exemple |
|------|---------|
| AWS Access Key | `AKIA...` |
| AWS Secret Key | `aws_secret_access_key = ...` |
| GitHub Token | `ghp_...`, `gho_...` |
| GitLab Token | `glpat-...` |
| Slack Token | `xoxb-...`, `xoxp-...` |
| Private Keys | `-----BEGIN RSA PRIVATE KEY-----` |
| Generic API Key | `api_key`, `apikey`, `api-key` |
| Database URLs | `postgres://user:pass@...` |
| JWT Tokens | `eyJ...` (long base64) |
| Basic Auth | `Authorization: Basic ...` |

## Code Source

```bash
#!/usr/bin/env bash
#===============================================================================
# Secret Scanner - Detect secrets and credentials in code
# Author: ShellBook
# Version: 1.0.0
#===============================================================================

set -euo pipefail

# Configuration
SCRIPT_NAME="secret-scanner"
VERSION="1.0.0"
CONFIG_DIR="${HOME}/.config/secret-scanner"
PATTERNS_FILE="${CONFIG_DIR}/patterns.txt"
EXCLUSIONS_FILE="${CONFIG_DIR}/exclusions.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Counters
TOTAL_FILES=0
SECRETS_FOUND=0
FILES_WITH_SECRETS=0

# Findings storage
declare -a FINDINGS=()

#-------------------------------------------------------------------------------
# Secret Detection Patterns (regex)
#-------------------------------------------------------------------------------
declare -A SECRET_PATTERNS=(
    # AWS
    ["AWS Access Key ID"]='AKIA[0-9A-Z]{16}'
    ["AWS Secret Access Key"]='aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}'
    ["AWS MWS Key"]='amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

    # GitHub
    ["GitHub Personal Token"]='ghp_[0-9a-zA-Z]{36}'
    ["GitHub OAuth Token"]='gho_[0-9a-zA-Z]{36}'
    ["GitHub App Token"]='ghu_[0-9a-zA-Z]{36}'
    ["GitHub Refresh Token"]='ghr_[0-9a-zA-Z]{36}'

    # GitLab
    ["GitLab Personal Token"]='glpat-[0-9a-zA-Z\-]{20}'
    ["GitLab Pipeline Token"]='glptt-[0-9a-f]{40}'

    # Slack
    ["Slack Bot Token"]='xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}'
    ["Slack User Token"]='xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}'
    ["Slack Webhook"]='https://hooks\.slack\.com/services/T[0-9A-Z]{8}/B[0-9A-Z]{8}/[0-9a-zA-Z]{24}'

    # Google
    ["Google API Key"]='AIza[0-9A-Za-z\-_]{35}'
    ["Google OAuth ID"]='[0-9]+-[0-9a-z]+\.apps\.googleusercontent\.com'

    # Azure
    ["Azure Subscription Key"]='[a-f0-9]{32}'

    # Private Keys
    ["RSA Private Key"]='-----BEGIN RSA PRIVATE KEY-----'
    ["DSA Private Key"]='-----BEGIN DSA PRIVATE KEY-----'
    ["EC Private Key"]='-----BEGIN EC PRIVATE KEY-----'
    ["PGP Private Key"]='-----BEGIN PGP PRIVATE KEY BLOCK-----'
    ["OpenSSH Private Key"]='-----BEGIN OPENSSH PRIVATE KEY-----'

    # Generic Secrets
    ["Generic API Key"]='[aA][pP][iI][-_]?[kK][eE][yY]\s*[=:]\s*['\''"][0-9a-zA-Z]{16,}['\''"]'
    ["Generic Secret"]='[sS][eE][cC][rR][eE][tT]\s*[=:]\s*['\''"][0-9a-zA-Z]{8,}['\''"]'
    ["Generic Password"]='[pP][aA][sS][sS][wW][oO][rR][dD]\s*[=:]\s*['\''"][^'\''"]{8,}['\''"]'
    ["Generic Token"]='[tT][oO][kK][eE][nN]\s*[=:]\s*['\''"][0-9a-zA-Z]{16,}['\''"]'

    # Database URLs
    ["PostgreSQL URL"]='postgres(ql)?://[^:]+:[^@]+@[^/]+/[^\s]+'
    ["MySQL URL"]='mysql://[^:]+:[^@]+@[^/]+/[^\s]+'
    ["MongoDB URL"]='mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+'
    ["Redis URL"]='redis://[^:]+:[^@]+@[^\s]+'

    # JWT
    ["JWT Token"]='eyJ[0-9a-zA-Z]{10,}\.eyJ[0-9a-zA-Z]{10,}\.[0-9a-zA-Z_-]{10,}'

    # Basic Auth
    ["Basic Auth Header"]='[aA]uthorization:\s*[bB]asic\s+[A-Za-z0-9+/=]{20,}'
    ["Bearer Token"]='[aA]uthorization:\s*[bB]earer\s+[A-Za-z0-9\-_.]{20,}'

    # Heroku
    ["Heroku API Key"]='[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'

    # Stripe
    ["Stripe API Key"]='sk_live_[0-9a-zA-Z]{24}'
    ["Stripe Restricted Key"]='rk_live_[0-9a-zA-Z]{24}'

    # Twilio
    ["Twilio API Key"]='SK[0-9a-fA-F]{32}'
    ["Twilio Auth Token"]='[a-f0-9]{32}'

    # SendGrid
    ["SendGrid API Key"]='SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}'

    # NPM
    ["NPM Token"]='npm_[0-9a-zA-Z]{36}'

    # Docker
    ["Docker Registry Auth"]='"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'

    # SSH
    ["SSH Password in URL"]='ssh://[^:]+:[^@]+@'

    # Environment Variables
    ["Hardcoded Password Env"]='(PASSWORD|PASSWD|PWD)\s*=\s*['\''"]?[^\s'\''"]{8,}['\''"]?'
    ["Hardcoded Secret Env"]='(SECRET|API_KEY|TOKEN)\s*=\s*['\''"]?[^\s'\''"]{8,}['\''"]?'
)

# File patterns to exclude
DEFAULT_EXCLUSIONS=(
    "*.test.js"
    "*.test.ts"
    "*.spec.js"
    "*.spec.ts"
    "*_test.go"
    "*_test.py"
    "test_*.py"
    "*.md"
    "*.lock"
    "package-lock.json"
    "yarn.lock"
    "*.min.js"
    "*.min.css"
    "node_modules/*"
    "vendor/*"
    ".git/*"
    "*.svg"
    "*.png"
    "*.jpg"
    "*.ico"
)

#-------------------------------------------------------------------------------
# Logging functions
#-------------------------------------------------------------------------------
log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_secret() { echo -e "${RED}[SECRET]${NC} $*"; }

#-------------------------------------------------------------------------------
# Display help message
#-------------------------------------------------------------------------------
show_help() {
    cat << EOF
${CYAN}Secret Scanner v${VERSION}${NC}

Detect secrets and credentials in code repositories.

${YELLOW}USAGE:${NC}
    $SCRIPT_NAME <command> [options] [path]

${YELLOW}COMMANDS:${NC}
    scan [path]         Scan directory for secrets (default: current dir)
    check <file>        Check a specific file
    install-hook        Install as git pre-commit hook
    list-patterns       List all detection patterns
    add-pattern         Add custom pattern
    version             Show version

${YELLOW}OPTIONS:${NC}
    -g, --git-history   Scan git history (all commits)
    -s, --strict        Exit with error if any secret found
    -o, --output FILE   Export findings to JSON file
    -e, --exclude PAT   Additional exclusion pattern
    -q, --quiet         Minimal output
    -v, --verbose       Show all scanned files
    -h, --help          Show this help message

${YELLOW}EXAMPLES:${NC}
    # Scan current directory
    $SCRIPT_NAME scan

    # Scan with git history
    $SCRIPT_NAME scan --git-history /path/to/repo

    # CI/CD pipeline usage
    $SCRIPT_NAME scan --strict --output secrets.json

    # Check single file
    $SCRIPT_NAME check config.yaml

${YELLOW}EXIT CODES:${NC}
    0 - No secrets found (or non-strict mode)
    1 - Secrets found (strict mode)
    2 - Error occurred

EOF
}

#-------------------------------------------------------------------------------
# Initialize configuration
#-------------------------------------------------------------------------------
init_config() {
    mkdir -p "${CONFIG_DIR}"

    # Create default exclusions file
    if [[ ! -f "${EXCLUSIONS_FILE}" ]]; then
        printf '%s\n' "${DEFAULT_EXCLUSIONS[@]}" > "${EXCLUSIONS_FILE}"
    fi
}

#-------------------------------------------------------------------------------
# Check if file should be excluded
#-------------------------------------------------------------------------------
should_exclude() {
    local file="$1"
    local filename
    filename=$(basename "${file}")

    # Check against exclusion patterns
    while IFS= read -r pattern || [[ -n "${pattern}" ]]; do
        [[ -z "${pattern}" || "${pattern}" == \#* ]] && continue

        # Handle glob patterns
        if [[ "${file}" == ${pattern} ]] || [[ "${filename}" == ${pattern} ]]; then
            return 0
        fi
    done < "${EXCLUSIONS_FILE}"

    # Skip binary files
    if file "${file}" 2>/dev/null | grep -q "binary"; then
        return 0
    fi

    return 1
}

#-------------------------------------------------------------------------------
# Scan a single file for secrets
#-------------------------------------------------------------------------------
scan_file() {
    local file="$1"
    local verbose="${2:-false}"
    local file_has_secrets=false
    local line_num=0

    [[ ! -f "${file}" ]] && return

    # Check exclusions
    if should_exclude "${file}"; then
        [[ "${verbose}" == "true" ]] && log_info "Skipping: ${file}"
        return
    fi

    ((TOTAL_FILES++))
    [[ "${verbose}" == "true" ]] && log_info "Scanning: ${file}"

    # Read file and check each pattern
    while IFS= read -r line || [[ -n "${line}" ]]; do
        ((line_num++))

        for pattern_name in "${!SECRET_PATTERNS[@]}"; do
            pattern="${SECRET_PATTERNS[${pattern_name}]}"

            if echo "${line}" | grep -qE "${pattern}"; then
                # Mask the actual secret value
                masked_line=$(echo "${line}" | sed -E "s/${pattern}/***REDACTED***/g")

                # Store finding
                FINDINGS+=("${file}:${line_num}:${pattern_name}:${masked_line}")

                if [[ "${file_has_secrets}" == "false" ]]; then
                    ((FILES_WITH_SECRETS++))
                    file_has_secrets=true
                fi

                ((SECRETS_FOUND++))
                log_secret "${file}:${line_num} - ${pattern_name}"
            fi
        done
    done < "${file}"
}

#-------------------------------------------------------------------------------
# Scan directory recursively
#-------------------------------------------------------------------------------
scan_directory() {
    local dir="${1:-.}"
    local verbose="${2:-false}"

    log_info "Scanning directory: ${dir}"

    # Find all files
    while IFS= read -r -d '' file; do
        scan_file "${file}" "${verbose}"
    done < <(find "${dir}" -type f -print0 2>/dev/null)
}

#-------------------------------------------------------------------------------
# Scan git history
#-------------------------------------------------------------------------------
scan_git_history() {
    local dir="${1:-.}"

    if [[ ! -d "${dir}/.git" ]]; then
        log_error "Not a git repository: ${dir}"
        return 1
    fi

    log_info "Scanning git history..."

    # Get all commits
    local commits
    commits=$(git -C "${dir}" rev-list --all 2>/dev/null | head -100)
    local commit_count
    commit_count=$(echo "${commits}" | wc -l)

    log_info "Checking ${commit_count} commits (limited to 100)..."

    for commit in ${commits}; do
        # Get changed files in commit
        local files
        files=$(git -C "${dir}" diff-tree --no-commit-id --name-only -r "${commit}" 2>/dev/null)

        for file in ${files}; do
            # Get file content at that commit
            local content
            content=$(git -C "${dir}" show "${commit}:${file}" 2>/dev/null) || continue

            # Check each pattern
            local line_num=0
            while IFS= read -r line; do
                ((line_num++))

                for pattern_name in "${!SECRET_PATTERNS[@]}"; do
                    pattern="${SECRET_PATTERNS[${pattern_name}]}"

                    if echo "${line}" | grep -qE "${pattern}"; then
                        local short_commit="${commit:0:8}"
                        FINDINGS+=("${file}@${short_commit}:${line_num}:${pattern_name}:***REDACTED***")
                        ((SECRETS_FOUND++))
                        log_secret "${file}@${short_commit}:${line_num} - ${pattern_name}"
                    fi
                done
            done <<< "${content}"
        done
    done
}

#-------------------------------------------------------------------------------
# Generate JSON report
#-------------------------------------------------------------------------------
generate_json_report() {
    local output_file="$1"

    cat > "${output_file}" << EOF
{
  "scan_time": "$(date -Iseconds)",
  "total_files_scanned": ${TOTAL_FILES},
  "files_with_secrets": ${FILES_WITH_SECRETS},
  "total_secrets_found": ${SECRETS_FOUND},
  "findings": [
EOF

    local first=true
    for finding in "${FINDINGS[@]}"; do
        IFS=':' read -r file line type detail <<< "${finding}"

        [[ "${first}" == "true" ]] || echo "," >> "${output_file}"
        first=false

        cat >> "${output_file}" << EOF
    {
      "file": "${file}",
      "line": ${line},
      "type": "${type}",
      "detail": "${detail//\"/\\\"}"
    }
EOF
    done

    cat >> "${output_file}" << EOF

  ]
}
EOF

    log_success "Report saved to: ${output_file}"
}

#-------------------------------------------------------------------------------
# Install as git pre-commit hook
#-------------------------------------------------------------------------------
install_hook() {
    local git_dir="${1:-.}/.git"

    if [[ ! -d "${git_dir}" ]]; then
        log_error "Not a git repository"
        return 1
    fi

    local hook_file="${git_dir}/hooks/pre-commit"

    cat > "${hook_file}" << 'HOOK'
#!/usr/bin/env bash
# Secret Scanner Pre-commit Hook

# Get the directory of the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [[ -z "${STAGED_FILES}" ]]; then
    exit 0
fi

echo "🔍 Scanning staged files for secrets..."

SECRETS_FOUND=0

# Patterns to check
declare -A PATTERNS=(
    ["AWS Key"]='AKIA[0-9A-Z]{16}'
    ["Private Key"]='-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
    ["GitHub Token"]='gh[pousr]_[0-9a-zA-Z]{36}'
    ["Generic Secret"]='(password|secret|api_key|token)\s*[=:]\s*['\''"][^'\''"]{8,}['\''"]'
)

for file in ${STAGED_FILES}; do
    [[ ! -f "${file}" ]] && continue

    for pattern_name in "${!PATTERNS[@]}"; do
        if grep -qE "${PATTERNS[${pattern_name}]}" "${file}" 2>/dev/null; then
            echo "❌ Potential secret found in ${file}: ${pattern_name}"
            ((SECRETS_FOUND++))
        fi
    done
done

if [[ ${SECRETS_FOUND} -gt 0 ]]; then
    echo ""
    echo "⚠️  ${SECRETS_FOUND} potential secret(s) detected!"
    echo "   Review the files above and remove secrets before committing."
    echo "   To bypass this check (not recommended): git commit --no-verify"
    exit 1
fi

echo "✅ No secrets detected in staged files"
exit 0
HOOK

    chmod +x "${hook_file}"
    log_success "Pre-commit hook installed: ${hook_file}"
}

#-------------------------------------------------------------------------------
# List all patterns
#-------------------------------------------------------------------------------
list_patterns() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${CYAN}Secret Detection Patterns${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    for pattern_name in "${!SECRET_PATTERNS[@]}"; do
        echo -e "${YELLOW}${pattern_name}${NC}"
        echo "  Pattern: ${SECRET_PATTERNS[${pattern_name}]}"
        echo ""
    done
}

#-------------------------------------------------------------------------------
# Command: scan
#-------------------------------------------------------------------------------
cmd_scan() {
    local path="."
    local git_history=false
    local strict=false
    local output=""
    local verbose=false
    local quiet=false

    # Parse options
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -g|--git-history) git_history=true; shift ;;
            -s|--strict) strict=true; shift ;;
            -o|--output) output="$2"; shift 2 ;;
            -v|--verbose) verbose=true; shift ;;
            -q|--quiet) quiet=true; shift ;;
            -*) shift ;;
            *) path="$1"; shift ;;
        esac
    done

    [[ "${quiet}" == "false" ]] && log_info "Starting secret scan..."

    # Scan files
    scan_directory "${path}" "${verbose}"

    # Scan git history if requested
    if [[ "${git_history}" == "true" ]]; then
        scan_git_history "${path}"
    fi

    # Print summary
    if [[ "${quiet}" == "false" ]]; then
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "${CYAN}SCAN SUMMARY${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo -e "Files scanned:      ${TOTAL_FILES}"
        echo -e "Files with secrets: ${RED}${FILES_WITH_SECRETS}${NC}"
        echo -e "Total secrets:      ${RED}${SECRETS_FOUND}${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

        if [[ ${SECRETS_FOUND} -eq 0 ]]; then
            echo -e "\n${GREEN}✓ No secrets detected${NC}"
        else
            echo -e "\n${RED}⚠ ${SECRETS_FOUND} secret(s) detected!${NC}"
        fi
    fi

    # Generate report if requested
    if [[ -n "${output}" ]]; then
        generate_json_report "${output}"
    fi

    # Exit code
    if [[ "${strict}" == "true" && ${SECRETS_FOUND} -gt 0 ]]; then
        return 1
    fi

    return 0
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
        scan)
            cmd_scan "$@"
            ;;
        check)
            [[ $# -eq 0 ]] && { log_error "File path required"; exit 2; }
            scan_file "$1" true
            ;;
        install-hook)
            install_hook "$@"
            ;;
        list-patterns)
            list_patterns
            ;;
        -h|--help|help)
            show_help
            ;;
        -v|--version|version)
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

### GitHub Actions

```yaml
name: Secret Scan
on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git scan

      - name: Run secret scanner
        run: |
          chmod +x ./scripts/secret-scanner.sh
          ./scripts/secret-scanner.sh scan --strict --output secrets.json

      - name: Upload report
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: secret-scan-report
          path: secrets.json
```

### GitLab CI

```yaml
secret_scan:
  stage: security
  script:
    - ./secret-scanner.sh scan --strict --output gl-secret-report.json
  artifacts:
    reports:
      secret_detection: gl-secret-report.json
  allow_failure: false
```

## Cas d'Usage

1. **Pre-commit Hook** : Bloquer les commits contenant des secrets
2. **CI/CD Gate** : Échouer le pipeline si des secrets sont détectés
3. **Audit Régulier** : Scanner périodiquement les repos existants
4. **Onboarding** : Vérifier les nouveaux projets avant intégration
