---
tags:
  - bash
  - best-practices
  - error-handling
  - boilerplate
---

# Robust Bash Scripting

Écrire des scripts Bash robustes et maintenables.

---

## Bash Strict Mode

### Le Shebang

```bash
#!/usr/bin/env bash
```

Pourquoi `env bash` ? Portabilité. Bash n'est pas toujours dans `/bin/bash` (ex: NixOS, FreeBSD).

### Les Options de Sécurité

```bash
set -euo pipefail
```

| Option | Effet | Sans cette option |
|--------|-------|-------------------|
| `-e` | Exit immédiat si une commande échoue | Le script continue malgré les erreurs |
| `-u` | Exit si variable non définie | Variables vides = bugs silencieux |
| `-o pipefail` | Erreur si une commande du pipe échoue | Seule la dernière commande est vérifiée |

#### -e : Exit on Error

```bash
set -e

rm /fichier/inexistant    # Script s'arrête ici
echo "Jamais affiché"      # Non exécuté
```

#### -u : Exit on Unset Variable

```bash
set -u

echo "$VARIABLE_INEXISTANTE"   # Erreur immédiate
# bash: VARIABLE_INEXISTANTE: unbound variable
```

#### -o pipefail : Catch Pipe Errors

```bash
set -o pipefail

# SANS pipefail : exit code = 0 (grep réussit)
cat /fichier/inexistant | grep "test"

# AVEC pipefail : exit code = 1 (cat échoue)
cat /fichier/inexistant | grep "test"
```

### Header Standard

```bash
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
```

`IFS=$'\n\t'` : Séparateur de champs = newline et tab seulement (évite les surprises avec les espaces).

---

## Structure Type (Boilerplate)

```bash
#!/usr/bin/env bash
#
# Script: backup.sh
# Description: Daily backup to remote server
# Author: SysOps Team
# Version: 1.0.0
#

set -euo pipefail
IFS=$'\n\t'

# =============================================================================
# VARIABLES
# =============================================================================

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly LOG_FILE="/var/log/${SCRIPT_NAME%.sh}.log"

readonly BACKUP_SRC="/data"
readonly BACKUP_DST="backup@remote:/backups"
readonly RETENTION_DAYS=30

# =============================================================================
# FUNCTIONS
# =============================================================================

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Daily backup script to remote server.

OPTIONS:
    -h, --help      Show this help message
    -v, --verbose   Enable verbose output
    -d, --dry-run   Show what would be done without doing it

EXAMPLES:
    ${SCRIPT_NAME}              # Run backup
    ${SCRIPT_NAME} --dry-run    # Test run

EOF
    exit 0
}

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"

    echo "[${timestamp}] [${level}] ${message}" | tee -a "${LOG_FILE}"
}

info()  { log "INFO"  "$@"; }
warn()  { log "WARN"  "$@"; }
error() { log "ERROR" "$@"; }

die() {
    error "$@"
    exit 1
}

cleanup() {
    # Actions de nettoyage en cas d'erreur ou fin normale
    log "INFO" "Cleanup completed"
}

check_requirements() {
    local missing=()

    for cmd in rsync ssh; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing+=("${cmd}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required commands: ${missing[*]}"
    fi
}

do_backup() {
    local src="$1"
    local dst="$2"

    info "Starting backup: ${src} -> ${dst}"

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        info "[DRY-RUN] Would run: rsync -avz ${src} ${dst}"
        return 0
    fi

    rsync -avz --delete "${src}/" "${dst}/"

    info "Backup completed successfully"
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help)
                usage
                ;;
            -v|--verbose)
                set -x
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    # Setup
    trap cleanup EXIT
    check_requirements

    # Execute
    info "=== ${SCRIPT_NAME} started ==="
    do_backup "${BACKUP_SRC}" "${BACKUP_DST}"
    info "=== ${SCRIPT_NAME} finished ==="
}

# Entry point
main "$@"
```

---

## Bonnes Pratiques

### Toujours Quoter les Variables

```bash
# MAUVAIS - Casse si espaces ou caractères spéciaux
rm $FILE
cp $SRC $DST

# BON
rm "$FILE"
cp "$SRC" "$DST"

# Arrays aussi
files=("file 1.txt" "file 2.txt")
for f in "${files[@]}"; do   # Guillemets + @
    echo "$f"
done
```

### Utiliser [[ ]] au lieu de [ ]

| `[ ]` (POSIX) | `[[ ]]` (Bash) |
|---------------|----------------|
| Portable mais limité | Bash uniquement, plus puissant |
| Nécessite quoting strict | Pas de word splitting |
| Pas de regex | Supporte `=~` (regex) |
| Pas de pattern matching | Supporte `==` avec globs |

```bash
# MAUVAIS - Peut casser
[ $var = "test" ]
[ -z $var ]

# BON
[[ "$var" == "test" ]]
[[ -z "$var" ]]

# Pattern matching (uniquement [[]])
[[ "$file" == *.log ]]

# Regex (uniquement [[]])
[[ "$email" =~ ^[a-z]+@[a-z]+\.[a-z]+$ ]]

# AND/OR propres
[[ -f "$file" && -r "$file" ]]
[[ "$a" == "x" || "$a" == "y" ]]
```

### ShellCheck : Le Linter Indispensable

```bash
# Installation
sudo apt install shellcheck    # Debian/Ubuntu
brew install shellcheck        # macOS

# Utilisation
shellcheck script.sh

# Output:
# In script.sh line 10:
# rm $FILE
#    ^---^ SC2086: Double quote to prevent globbing and word splitting.
```

!!! tip "ShellCheck est non-négociable"
    Intégrez ShellCheck dans votre CI/CD. Aucun script ne devrait être mergé sans passer ShellCheck.

    ```yaml
    # .github/workflows/lint.yml
    - name: ShellCheck
      run: shellcheck scripts/*.sh
    ```

### Autres Bonnes Pratiques

```bash
# Utiliser des noms de variables explicites
readonly MAX_RETRY_COUNT=3    # Pas juste "N"
readonly CONFIG_FILE_PATH="/etc/app/config.yml"

# Préférer $() à ``
result=$(command)    # BON
result=`command`     # OBSOLÈTE

# Utiliser readonly pour les constantes
readonly DATABASE_URL="postgres://localhost/db"

# Utiliser local dans les fonctions
my_function() {
    local temp_file
    temp_file=$(mktemp)
}

# Toujours vérifier les commandes critiques
cd "$dir" || exit 1
mkdir -p "$path" || die "Cannot create $path"

# Utiliser trap pour le cleanup
trap 'rm -f "$temp_file"' EXIT
```

---

## Référence Rapide

```bash
#!/usr/bin/env bash
set -euo pipefail

# Variables
readonly VAR="value"
local var="value"         # Dans fonctions

# Tests
[[ -f "$file" ]]          # Fichier existe
[[ -d "$dir" ]]           # Répertoire existe
[[ -z "$var" ]]           # Variable vide
[[ -n "$var" ]]           # Variable non vide
[[ "$a" == "$b" ]]        # Égalité
[[ "$a" =~ regex ]]       # Match regex

# Fonctions
func() { local x="$1"; echo "$x"; }

# Logging
log() { echo "[$(date '+%F %T')] $*"; }

# Cleanup
trap 'cleanup_function' EXIT

# ShellCheck
shellcheck script.sh
```
