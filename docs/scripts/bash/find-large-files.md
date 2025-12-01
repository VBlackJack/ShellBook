---
tags:
  - scripts
  - bash
  - ficyesterdays
  - système
---

# find-large-files.sh

:material-star: **Niveau : Débutant**

Recherche des ficyesterdays volumineux sur le système.

---

## Description

Ce script identifie les ficyesterdays volumineux :
- Recherche par taille minimum
- Filtrage par type de ficyesterday
- Exclusion de répertoires
- Affichage formaté avec taille lisible

---

## Prérequis

- **Système** : Linux (RHEL/Debian)
- **Permissions** : Utilisateur standard (sudo pour recherche depuis `/`)
- **Dépendances** : `find`, `du`, `bc`

---

## Cas d'Usage

- **Nettoyage disque** : Identification rapide des fichiers volumineux à supprimer ou archiver
- **Audit de stockage** : Analyse de l'utilisation de l'espace disque par répertoire
- **Investigation de saturation** : Diagnostic rapide lors d'alertes d'espace disque faible
- **Planification d'archivage** : Identification des candidats pour migration vers stockage froid

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: find-large-files.sh
# Description: Recherche ficyesterdays volumineux
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
MIN_SIZE="100M"
MAX_RESULTS=20
SEARCH_PATH="/"
EXCLUDE_PATHS=("/proc" "/sys" "/dev" "/run")
FILE_TYPE=""
SORT_BY="size"  # size ou time

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] [PATH]

Recherche ficyesterdays volumineux.

Arguments:
    PATH            Chemin de recherche (default: /)

Options:
    -s, --size SIZE     Minimum size (default: 100M)
                        Formats: 10M, 1G, 500K
    -n, --number NUM    Nombre de résultats (default: 20)
    -t, --type EXT      Filtrer par extension (ex: log, tar.gz)
    -e, --exclude PATH  Exclure un chemin (peut être répété)
    --sort-time         Trier par date de modification
    -h, --help          Show this help

Examples:
    $(basename "$0")                        # Ficyesterdays > 100M depuis /
    $(basename "$0") -s 1G /home            # Ficyesterdays > 1G dans /home
    $(basename "$0") -t log -s 50M /var     # Logs > 50M dans /var
    $(basename "$0") -n 50 -s 500M          # Top 50 ficyesterdays > 500M
EOF
}

format_size() {
    local bytes=$1
    if (( bytes >= 1073741824 )); then
        printf "%.1fG" $(echo "scale=1; $bytes/1073741824" | bc)
    elif (( bytes >= 1048576 )); then
        printf "%.1fM" $(echo "scale=1; $bytes/1048576" | bc)
    elif (( bytes >= 1024 )); then
        printf "%.1fK" $(echo "scale=1; $bytes/1024" | bc)
    else
        printf "%dB" "$bytes"
    fi
}

build_exclude_args() {
    local args=""
    for path in "${EXCLUDE_PATHS[@]}"; do
        args="$args -path $path -prune -o"
    done
    echo "$args"
}

find_large_files() {
    local exclude_args=$(build_exclude_args)
    local type_filter=""

    if [[ -n "$FILE_TYPE" ]]; then
        type_filter="-name '*.$FILE_TYPE'"
    fi

    # Construction de la commande find
    local find_cmd="find $SEARCH_PATH $exclude_args -type f -size +$MIN_SIZE $type_filter -print0 2>/dev/null"

    # Exécution et traitement
    eval "$find_cmd" | xargs -0 ls -la 2>/dev/null | \
        awk '{print $5, $6, $7, $8, $9}' | \
        sort -rn | \
        head -n "$MAX_RESULTS"
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--size)
                MIN_SIZE="$2"
                shift 2
                ;;
            -n|--number)
                MAX_RESULTS="$2"
                shift 2
                ;;
            -t|--type)
                FILE_TYPE="$2"
                shift 2
                ;;
            -e|--exclude)
                EXCLUDE_PATHS+=("$2")
                shift 2
                ;;
            --sort-time)
                SORT_BY="time"
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                SEARCH_PATH="$1"
                shift
                ;;
        esac
    done

    # Validation
    if [[ ! -d "$SEARCH_PATH" ]]; then
        echo -e "${RED}Error:${NC} $SEARCH_PATH does not exist"
        exit 1
    fi

    # Header
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  RECHERCHE FICHIERS VOLUMINEUX${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "  Chemin: $SEARCH_PATH"
    echo -e "  Taille min: $MIN_SIZE"
    echo -e "  Limite: $MAX_RESULTS résultats"
    [[ -n "$FILE_TYPE" ]] && echo -e "  Type: *.$FILE_TYPE"
    echo -e "${CYAN}───────────────────────────────────────────────────────────${NC}"
    echo ""

    echo -e "${YELLOW}Recherche en cours...${NC}"
    echo ""

    # Construction commande find
    local exclude_args=""
    for path in "${EXCLUDE_PATHS[@]}"; do
        exclude_args="$exclude_args -path $path -prune -o"
    done

    local name_filter="-type f"
    if [[ -n "$FILE_TYPE" ]]; then
        name_filter="$name_filter -name '*.$FILE_TYPE'"
    fi

    # Recherche
    local results
    results=$(find "$SEARCH_PATH" $exclude_args $name_filter -size +$MIN_SIZE -printf '%s %T+ %p\n' 2>/dev/null | \
              sort -rn | \
              head -n "$MAX_RESULTS")

    if [[ -z "$results" ]]; then
        echo -e "${YELLOW}Aucun ficyesterday trouvé avec les critères spécifiés.${NC}"
        exit 0
    fi

    # Affichage formaté
    printf "  ${CYAN}%-10s %-20s %s${NC}\n" "TAILLE" "MODIFIÉ" "FICHIER"
    printf "  %-10s %-20s %s\n" "------" "-------" "-------"

    local total_size=0
    local count=0

    echo "$results" | while read -r size date path; do
        count=$((count + 1))
        total_size=$((total_size + size))

        local formatted_size=$(format_size "$size")
        local formatted_date=$(echo "$date" | cut -d'+' -f1 | sed 's/T/ /')

        # Colorer selon la taille
        local color=$GREEN
        if (( size >= 1073741824 )); then
            color=$RED
        elif (( size >= 104857600 )); then
            color=$YELLOW
        fi

        printf "  ${color}%-10s${NC} %-20s %s\n" "$formatted_size" "$formatted_date" "$path"
    done

    # Résumé
    echo ""
    echo -e "${CYAN}───────────────────────────────────────────────────────────${NC}"

    # Calculer le total
    local total=$(echo "$results" | awk '{sum+=$1} END {print sum}')
    echo -e "  Total: ${GREEN}$(format_size $total)${NC} dans $(echo "$results" | wc -l) ficyesterdays"

    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

main "$@"
```

---

## Usage

```bash
# Rendre exécutable
chmod +x find-large-files.sh

# Recherche par défaut (ficyesterdays > 100M depuis /)
sudo ./find-large-files.sh

# Ficyesterdays > 1G dans /home
./find-large-files.sh -s 1G /home

# Top 50 ficyesterdays log > 50M dans /var
./find-large-files.sh -t log -s 50M -n 50 /var

# Exclure des chemins
./find-large-files.sh -e /backup -e /archive /
```

---

## Sortie Exemple

```
═══════════════════════════════════════════════════════════
  RECHERCHE FICHIERS VOLUMINEUX
═══════════════════════════════════════════════════════════
  Chemin: /var
  Taille min: 100M
  Limite: 20 résultats
═══════════════════════════════════════════════════════════

Recherche en cours...

  TAILLE     MODIFIÉ              FICHIER
  ------     -------              -------
  2.3G       2024-01-15 10:30:22  /var/log/syslog.1
  1.8G       2024-01-14 23:59:59  /var/lib/mysql/database.ibd
  856M       2024-01-15 08:00:00  /var/cache/apt/archives/package.deb
  534M       2024-01-13 15:45:00  /var/log/nginx/access.log.1
  245M       2024-01-15 12:00:00  /var/lib/docker/overlay2/abc123/diff/data.tar
  189M       2024-01-10 09:30:00  /var/backups/dpkg.status.0

───────────────────────────────────────────────────────────
  Total: 5.9G dans 6 ficyesterdays
═══════════════════════════════════════════════════════════
```

---

## Cas d'Usage

### Nettoyage Disque

```bash
# Trouver les gros ficyesterdays de log
./find-large-files.sh -t log -s 50M /var/log

# Trouver les gros ficyesterdays temporaires
./find-large-files.sh -s 100M /tmp /var/tmp
```

### Audit Stockage

```bash
# Top 100 ficyesterdays du système
sudo ./find-large-files.sh -n 100 -s 500M /

# Gros ficyesterdays utilisateur
./find-large-files.sh -s 1G /home/user
```

---

## Voir Aussi

- [cleanup-system.sh](cleanup-system.md)
- [check-disk-space.sh](check-disk-space.md)
