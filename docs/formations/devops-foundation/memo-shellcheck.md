---
tags:
  - formation
  - devops
  - bash
  - shellcheck
  - linting
  - memo
---

# Fiche Memo : ShellCheck

Référence rapide des règles ShellCheck les plus courantes et leurs corrections.

---

## Installation

=== "Linux (Debian/Ubuntu)"

    ```bash
    sudo apt install shellcheck
    ```

=== "Linux (RHEL/Rocky)"

    ```bash
    sudo dnf install epel-release
    sudo dnf install ShellCheck
    ```

=== "macOS"

    ```bash
    brew install shellcheck
    ```

=== "Windows"

    ```powershell
    choco install shellcheck
    # ou
    scoop install shellcheck
    ```

---

## Utilisation

```bash
# Vérifier un script
shellcheck script.sh

# Vérifier plusieurs scripts
shellcheck scripts/*.sh

# Format de sortie
shellcheck -f gcc script.sh      # Format GCC (pour IDE)
shellcheck -f json script.sh     # JSON (pour CI/CD)
shellcheck -f diff script.sh     # Diff (pour patches)

# Exclure des règles
shellcheck -e SC2034 script.sh   # Ignorer SC2034
shellcheck -e SC2034,SC2086 script.sh

# Spécifier le shell
shellcheck -s bash script.sh     # Bash
shellcheck -s sh script.sh       # POSIX sh
shellcheck -s dash script.sh     # Dash
```

---

## Règles Critiques (Sécurité)

### SC2086 - Variables non quotées

**Problème :** Word splitting et globbing non intentionnels.

```bash
# Mauvais
echo $USER
rm -rf $PATH

# Bon
echo "$USER"
rm -rf "$PATH"
```

**Risque :** Injection de commande si la variable contient des espaces ou caractères spéciaux.

### SC2046 - Command substitution non quotée

**Problème :** Le résultat de `$(...)` peut contenir des espaces.

```bash
# Mauvais
files=$(find . -name "*.txt")
rm $files

# Bon
files=$(find . -name "*.txt")
rm "$files"

# Mieux : utiliser un tableau
mapfile -t files < <(find . -name "*.txt")
rm "${files[@]}"
```

### SC2091 - Exécution accidentelle

**Problème :** `$(...)` dans un test exécute la commande.

```bash
# Mauvais (exécute la commande!)
if $(which node); then
  echo "Node installed"
fi

# Bon
if which node > /dev/null; then
  echo "Node installed"
fi

# Ou
if command -v node > /dev/null; then
  echo "Node installed"
fi
```

### SC2155 - Declare et assign en même temps

**Problème :** Le code retour de la commande est masqué.

```bash
# Mauvais
local result=$(some_command)

# Bon
local result
result=$(some_command)
```

---

## Règles Courantes (Qualité)

### SC2034 - Variable non utilisée

**Problème :** Variable déclarée mais jamais utilisée.

```bash
# Mauvais
UNUSED_VAR="test"
echo "Hello"

# Bon : supprimer ou utiliser
VERSION="1.0"
echo "Version: $VERSION"

# Si export intentionnel
export PATH_CUSTOM="/opt/bin"  # Utilisée par sous-processus
```

### SC2181 - Vérification indirecte de $?

**Problème :** Moins lisible et plus fragile.

```bash
# Mauvais
some_command
if [ $? -ne 0 ]; then
  echo "Erreur"
fi

# Bon
if ! some_command; then
  echo "Erreur"
fi

# Ou
if some_command; then
  echo "Succès"
else
  echo "Erreur"
fi
```

### SC2164 - cd sans vérification

**Problème :** Le script continue si le cd échoue.

```bash
# Mauvais
cd /some/directory
rm -rf *  # Danger si cd a échoué !

# Bon
cd /some/directory || exit 1
rm -rf *

# Ou avec set -e
set -e
cd /some/directory
rm -rf *
```

### SC2166 - Utilisation de -a/-o dans test

**Problème :** Opérateurs obsolètes et ambigus.

```bash
# Mauvais
if [ "$a" = "x" -a "$b" = "y" ]; then
  echo "Both"
fi

# Bon
if [ "$a" = "x" ] && [ "$b" = "y" ]; then
  echo "Both"
fi

# Mieux (Bash)
if [[ "$a" == "x" && "$b" == "y" ]]; then
  echo "Both"
fi
```

### SC2068 - Array expansion sans quotes

**Problème :** Les éléments avec espaces sont splitées.

```bash
# Mauvais
files=("file 1.txt" "file 2.txt")
for f in ${files[@]}; do  # Split chaque élément
  echo "$f"
done

# Bon
for f in "${files[@]}"; do  # Préserve les espaces
  echo "$f"
done
```

---

## Règles de Style

### SC2006 - Backticks obsolètes

**Problème :** Syntaxe ancienne, difficile à imbriquer.

```bash
# Mauvais
today=`date +%Y-%m-%d`

# Bon
today=$(date +%Y-%m-%d)

# Imbrication propre
result=$(echo $(date +%Y))
```

### SC2039 - Extensions Bash en mode sh

**Problème :** Fonctionnalités Bash utilisées avec `#!/bin/sh`.

```bash
# Mauvais avec #!/bin/sh
#!/bin/sh
if [[ "$x" == "test" ]]; then  # [[ est Bash
  echo "Match"
fi

# Bon : utiliser Bash
#!/bin/bash
if [[ "$x" == "test" ]]; then
  echo "Match"
fi

# Ou : syntaxe POSIX
#!/bin/sh
if [ "$x" = "test" ]; then
  echo "Match"
fi
```

### SC2162 - read sans -r

**Problème :** Les backslashes sont interprétés.

```bash
# Mauvais
read line

# Bon
read -r line

# Avec prompt
read -r -p "Enter name: " name
```

---

## Bonnes Pratiques Recommandées

### Header Standard

```bash
#!/bin/bash
# Description: Script de déploiement
# Usage: ./deploy.sh <env> [options]
# Author: Team DevOps

set -euo pipefail  # Strict mode

# Constantes
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="/var/log/deploy.log"
```

### Explication de `set -euo pipefail`

| Option | Effet |
|--------|-------|
| `-e` | Exit immédiat si une commande échoue |
| `-u` | Erreur si variable non définie utilisée |
| `-o pipefail` | Propager les erreurs dans les pipes |

```bash
# Sans -u
echo "$UNDEFINED_VAR"  # Vide, pas d'erreur

# Avec -u
set -u
echo "$UNDEFINED_VAR"  # Erreur: unbound variable

# Sans -o pipefail
false | true  # Code retour: 0 (true)

# Avec -o pipefail
set -o pipefail
false | true  # Code retour: 1 (false)
```

### Variables avec Valeurs par Défaut

```bash
# Valeur par défaut si vide
ENV="${1:-production}"

# Valeur par défaut si non définie
DEBUG="${DEBUG:-false}"

# Erreur si non définie
: "${API_KEY:?API_KEY must be set}"
```

### Fonctions avec Validation

```bash
deploy() {
  local env="${1:?Environment required}"
  local version="${2:-latest}"

  if [[ ! "$env" =~ ^(staging|production)$ ]]; then
    echo "Error: Invalid environment '$env'" >&2
    return 1
  fi

  echo "Deploying version $version to $env"
}
```

---

## Désactiver ShellCheck (à éviter)

### Pour une ligne

```bash
# shellcheck disable=SC2086
echo $UNQUOTED_VAR  # Ignoré pour cette ligne
```

### Pour un bloc

```bash
# shellcheck disable=SC2034
UNUSED_VAR1="test"
UNUSED_VAR2="test"
# shellcheck enable=SC2034
```

### Pour tout le fichier

```bash
#!/bin/bash
# shellcheck disable=SC2034,SC2086

# Le reste du script...
```

### Dans .shellcheckrc

```ini
# .shellcheckrc
disable=SC2034
shell=bash
```

**Attention :** Ne désactivez que si vous comprenez le risque et avez une bonne raison.

---

## Intégration CI/CD

### GitHub Actions

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: ShellCheck
        run: |
          find scripts/ -name "*.sh" -exec shellcheck {} +
```

### GitLab CI

```yaml
shellcheck:
  image: koalaman/shellcheck-alpine
  script:
    - find scripts/ -name "*.sh" -exec shellcheck {} +
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Trouver les scripts modifiés
scripts=$(git diff --cached --name-only --diff-filter=ACM | grep '\.sh$')

if [[ -n "$scripts" ]]; then
  echo "Running ShellCheck..."
  echo "$scripts" | xargs shellcheck || exit 1
fi
```

---

## Codes d'Erreur Courants

| Code | Description | Sévérité |
|------|-------------|----------|
| SC2086 | Variable non quotée | Erreur |
| SC2046 | Command substitution non quotée | Erreur |
| SC2034 | Variable non utilisée | Warning |
| SC2181 | Vérification indirecte $? | Style |
| SC2164 | cd sans vérification | Warning |
| SC2155 | Declare et assign | Warning |
| SC2006 | Backticks obsolètes | Style |
| SC2039 | Extension Bash en mode sh | Erreur |
| SC2162 | read sans -r | Warning |

---

## Template Script Sécurisé

```bash
#!/bin/bash
#
# Description: [Description du script]
# Usage: script.sh <arg1> [arg2]
# Author: [Auteur]
#

set -euo pipefail

# === CONSTANTS ===
readonly SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# === FUNCTIONS ===
log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

error() {
  echo "[ERROR] $*" >&2
}

usage() {
  cat << EOF
Usage: ${SCRIPT_NAME} <arg1> [arg2]

Arguments:
  arg1    Description de arg1 (obligatoire)
  arg2    Description de arg2 (optionnel, défaut: value)

Options:
  -h, --help    Afficher cette aide

Examples:
  ${SCRIPT_NAME} value1
  ${SCRIPT_NAME} value1 value2
EOF
}

main() {
  # Validation des arguments
  if [[ $# -lt 1 ]]; then
    error "Argument manquant"
    usage
    exit 1
  fi

  local arg1="${1}"
  local arg2="${2:-default}"

  log "Starting with arg1=${arg1}, arg2=${arg2}"

  # ... logique du script ...

  log "Done"
}

# === MAIN ===
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
```

---

**Retour au :** [Programme de la Formation](index.md) | [Catalogue](../index.md)
