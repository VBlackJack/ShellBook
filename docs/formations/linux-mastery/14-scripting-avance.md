---
tags:
  - formation
  - linux
  - bash
  - scripting
  - advanced
---

# Module 14 : Scripting Avancé

## Objectifs du Module

À l'issue de ce module, vous serez capable de :

- Écrire des scripts robustes et maintenables
- Gérer les erreurs et les signaux
- Implémenter le logging et le debugging
- Utiliser les patterns avancés Bash
- Tester et valider vos scripts

**Durée :** 8 heures

**Niveau :** Ingénierie

---

## 1. Mode Strict et Bonnes Pratiques

### Header Standard

```bash
#!/bin/bash
#
# script.sh - Description du script
# Usage: script.sh [options] <arguments>
# Author: Votre Nom
# Date: 2024-11-29
#

set -euo pipefail
IFS=$'\n\t'

# -e : Arrêter sur erreur
# -u : Erreur si variable non définie
# -o pipefail : Propager erreurs dans les pipes
# IFS : Séparateur pour éviter les surprises
```

### Constantes et Variables

```bash
# Constantes (readonly)
readonly SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly VERSION="1.0.0"

# Variables avec valeurs par défaut
LOG_LEVEL="${LOG_LEVEL:-INFO}"
CONFIG_FILE="${CONFIG_FILE:-/etc/myapp/config.conf}"
DEBUG="${DEBUG:-false}"
```

---

## 2. Gestion des Erreurs

### Trap pour le Nettoyage

```bash
#!/bin/bash
set -euo pipefail

# Fichiers temporaires
TEMP_DIR=""

cleanup() {
    local exit_code=$?
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    exit $exit_code
}

# Trap EXIT, SIGINT (Ctrl+C), SIGTERM
trap cleanup EXIT INT TERM

# Créer le répertoire temporaire
TEMP_DIR=$(mktemp -d)
echo "Working in $TEMP_DIR"

# ... reste du script ...
```

### Gestion d'Erreurs Personnalisée

```bash
#!/bin/bash
set -uo pipefail  # Pas -e, on gère manuellement

error_handler() {
    local line_no=$1
    local error_code=$2
    echo "[ERROR] Line $line_no: Command exited with status $error_code" >&2
}

trap 'error_handler ${LINENO} $?' ERR

run_with_retry() {
    local max_attempts=$1
    shift
    local cmd=("$@")
    local attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        if "${cmd[@]}"; then
            return 0
        fi
        echo "[WARN] Attempt $attempt failed, retrying..." >&2
        ((attempt++))
        sleep $((attempt * 2))
    done

    echo "[ERROR] Command failed after $max_attempts attempts" >&2
    return 1
}

# Usage
run_with_retry 3 curl -sf https://api.example.com/health
```

---

## 3. Logging

### Système de Log Complet

```bash
#!/bin/bash

# Niveaux de log
declare -A LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [FATAL]=4)
LOG_LEVEL="${LOG_LEVEL:-INFO}"
LOG_FILE="${LOG_FILE:-/var/log/myapp.log}"

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Vérifier le niveau
    if [[ ${LOG_LEVELS[$level]} -ge ${LOG_LEVELS[$LOG_LEVEL]} ]]; then
        # Couleurs pour stderr
        local color=""
        local reset="\033[0m"
        case $level in
            DEBUG) color="\033[36m" ;;  # Cyan
            INFO)  color="\033[32m" ;;  # Vert
            WARN)  color="\033[33m" ;;  # Jaune
            ERROR) color="\033[31m" ;;  # Rouge
            FATAL) color="\033[35m" ;;  # Magenta
        esac

        # Afficher et logger
        echo -e "${color}[$timestamp] [$level] $message${reset}" >&2
        echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    fi
}

# Usage
log INFO "Starting application"
log DEBUG "Config loaded from $CONFIG_FILE"
log WARN "Disk usage above 80%"
log ERROR "Failed to connect to database"
```

---

## 4. Parsing d'Arguments

### Avec getopts

```bash
#!/bin/bash

usage() {
    cat << EOF
Usage: $0 [OPTIONS] <input_file>

Options:
    -o, --output FILE    Output file (default: stdout)
    -v, --verbose        Enable verbose mode
    -d, --debug          Enable debug mode
    -h, --help           Show this help

Example:
    $0 -v -o result.txt input.txt
EOF
    exit 1
}

# Valeurs par défaut
OUTPUT=""
VERBOSE=false
DEBUG=false

# Parser les arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -o|--output)
            OUTPUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "Unknown option: $1" >&2
            usage
            ;;
        *)
            INPUT_FILE="$1"
            shift
            ;;
    esac
done

# Vérifier les arguments obligatoires
if [[ -z "${INPUT_FILE:-}" ]]; then
    echo "Error: Input file required" >&2
    usage
fi

# Debug
if [[ "$DEBUG" == true ]]; then
    set -x
fi

echo "Processing $INPUT_FILE..."
```

---

## 5. Tableaux et Structures

### Tableaux Indexés

```bash
# Déclaration
files=()
files+=("file1.txt")
files+=("file2.txt")
files=("a.txt" "b.txt" "c.txt")

# Accès
echo "${files[0]}"          # Premier élément
echo "${files[@]}"          # Tous les éléments
echo "${#files[@]}"         # Nombre d'éléments
echo "${!files[@]}"         # Indices

# Itération
for file in "${files[@]}"; do
    echo "Processing: $file"
done

# Slicing
echo "${files[@]:1:2}"      # Éléments 1 et 2
```

### Tableaux Associatifs

```bash
declare -A config

config[host]="localhost"
config[port]="5432"
config[database]="myapp"

# Accès
echo "${config[host]}"
echo "${config[@]}"         # Toutes les valeurs
echo "${!config[@]}"        # Toutes les clés

# Itération
for key in "${!config[@]}"; do
    echo "$key = ${config[$key]}"
done

# Charger depuis un fichier
while IFS='=' read -r key value; do
    config[$key]="$value"
done < config.ini
```

---

## 6. Fonctions Avancées

### Retourner des Valeurs Complexes

```bash
# Méthode 1 : nameref (Bash 4.3+)
get_user_info() {
    local -n result=$1
    local username=$2

    result[name]="$username"
    result[uid]=$(id -u "$username")
    result[home]=$(getent passwd "$username" | cut -d: -f6)
}

declare -A user_info
get_user_info user_info "root"
echo "${user_info[name]} has UID ${user_info[uid]}"

# Méthode 2 : Sortie parseable
get_disk_usage() {
    local path=$1
    df -h "$path" | awk 'NR==2 {print $3 ":" $4 ":" $5}'
}

IFS=':' read -r used available percent <<< "$(get_disk_usage /)"
echo "Used: $used, Available: $available, Percent: $percent"
```

### Fonctions avec Validation

```bash
validate_ip() {
    local ip=$1
    local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

    if [[ ! $ip =~ $regex ]]; then
        return 1
    fi

    IFS='.' read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if [[ $octet -gt 255 ]]; then
            return 1
        fi
    done

    return 0
}

validate_email() {
    local email=$1
    local regex='^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    [[ $email =~ $regex ]]
}
```

---

## 7. Parallélisation

### Exécution Parallèle Simple

```bash
#!/bin/bash

process_file() {
    local file=$1
    echo "Processing $file..."
    sleep 2  # Simulation de travail
    echo "Done: $file"
}

# Lancer en parallèle
for file in *.txt; do
    process_file "$file" &
done

# Attendre tous les jobs
wait
echo "All files processed"
```

### Avec Contrôle de Concurrence

```bash
#!/bin/bash

MAX_JOBS=4
job_count=0

process_file() {
    local file=$1
    # ... traitement ...
    sleep 2
    echo "Done: $file"
}

for file in *.txt; do
    process_file "$file" &
    ((job_count++))

    # Limiter le parallélisme
    if [[ $job_count -ge $MAX_JOBS ]]; then
        wait -n  # Attendre un job (Bash 4.3+)
        ((job_count--))
    fi
done

wait
echo "All done"
```

---

## 8. Tests et Validation

### ShellCheck

```bash
# Installer
sudo dnf install ShellCheck

# Utiliser
shellcheck script.sh
shellcheck -x script.sh    # Suivre les sources

# Ignorer une règle
# shellcheck disable=SC2086
echo $VARIABLE
```

### Tests avec BATS

```bash
# Installer
git clone https://github.com/bats-core/bats-core.git
./bats-core/install.sh /usr/local

# test_script.bats
#!/usr/bin/env bats

@test "validate_ip accepts valid IP" {
    source ./functions.sh
    run validate_ip "192.168.1.1"
    [ "$status" -eq 0 ]
}

@test "validate_ip rejects invalid IP" {
    source ./functions.sh
    run validate_ip "999.999.999.999"
    [ "$status" -eq 1 ]
}

# Exécuter
bats test_script.bats
```

---

## 9. Template de Script Complet

```bash
#!/bin/bash
#
# myapp.sh - Application de démonstration
# Usage: myapp.sh [-v] [-c config] <action>
#

set -euo pipefail

# === CONSTANTS ===
readonly SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
readonly VERSION="1.0.0"

# === CONFIGURATION ===
VERBOSE=false
CONFIG_FILE="/etc/myapp/config.conf"
LOG_FILE="/var/log/myapp.log"

# === LOGGING ===
log() {
    local level=$1; shift
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $*" | tee -a "$LOG_FILE" >&2
}

# === CLEANUP ===
cleanup() {
    log INFO "Cleanup..."
}
trap cleanup EXIT

# === FUNCTIONS ===
usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS] <action>

Actions:
    start     Start the service
    stop      Stop the service
    status    Show status

Options:
    -c FILE   Config file (default: $CONFIG_FILE)
    -v        Verbose mode
    -h        Show this help

Version: $VERSION
EOF
    exit 0
}

action_start() {
    log INFO "Starting..."
    # ...
}

action_stop() {
    log INFO "Stopping..."
    # ...
}

# === MAIN ===
main() {
    # Parse arguments
    while getopts "c:vh" opt; do
        case $opt in
            c) CONFIG_FILE="$OPTARG" ;;
            v) VERBOSE=true ;;
            h) usage ;;
            *) usage ;;
        esac
    done
    shift $((OPTIND - 1))

    [[ $# -lt 1 ]] && usage
    local action=$1

    # Execute
    case $action in
        start)  action_start ;;
        stop)   action_stop ;;
        status) echo "Running" ;;
        *)      log ERROR "Unknown action: $action"; exit 1 ;;
    esac
}

main "$@"
```

---

## 10. Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Créer un script de monitoring système robuste et maintenable

    **Contexte** : Vous devez créer un script de surveillance qui collecte et log les métriques système (CPU, RAM, disque, processus) toutes les 5 minutes, avec gestion d'erreurs, rotation des logs et notifications en cas de dépassement de seuils.

    **Tâches à réaliser** :

    1. Créer un script `system-monitor.sh` avec mode strict et gestion d'erreurs complète
    2. Implémenter un système de logging avec niveaux (DEBUG, INFO, WARN, ERROR)
    3. Ajouter le parsing d'arguments : `-i interval`, `-t threshold`, `-o output`, `-v verbose`
    4. Collecter les métriques : CPU, RAM, disque, top 5 processus gourmands
    5. Envoyer une alerte (log ERROR) si CPU > seuil ou RAM > seuil
    6. Implémenter la rotation des logs (garder 7 jours)
    7. Ajouter un fichier de configuration optionnel
    8. Valider le script avec `shellcheck`

    **Critères de validation** :

    - [ ] Le script utilise `set -euo pipefail` et gère les erreurs avec `trap`
    - [ ] Système de logging fonctionnel avec timestamps et niveaux
    - [ ] Arguments parsés correctement avec validation
    - [ ] Métriques collectées et stockées dans un fichier log
    - [ ] Alertes générées quand les seuils sont dépassés
    - [ ] Pas d'erreurs `shellcheck`
    - [ ] Documentation (usage, exemples) dans le header

??? quote "Solution"
    ```bash
    #!/bin/bash
    #
    # system-monitor.sh - Script de monitoring système avancé
    # Usage: system-monitor.sh [-i interval] [-t threshold] [-o output] [-v]
    # Author: Expert Linux
    # Date: 2024-11-29
    #

    set -euo pipefail
    IFS=$'\n\t'

    # === CONSTANTS ===
    readonly SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
    readonly SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
    readonly VERSION="1.0.0"

    # === CONFIGURATION ===
    INTERVAL=300           # 5 minutes par défaut
    CPU_THRESHOLD=80
    MEM_THRESHOLD=80
    OUTPUT_DIR="/var/log/monitoring"
    LOG_FILE="${OUTPUT_DIR}/system-monitor.log"
    METRICS_FILE="${OUTPUT_DIR}/metrics.log"
    VERBOSE=false
    LOG_LEVEL="INFO"
    RETENTION_DAYS=7

    # Fichier de configuration optionnel
    CONFIG_FILE="${CONFIG_FILE:-/etc/monitoring/config.conf}"

    # === LOGGING ===
    declare -A LOG_LEVELS=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3 [FATAL]=4)

    log() {
        local level=$1
        shift
        local message="$*"
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

        if [[ ${LOG_LEVELS[$level]} -ge ${LOG_LEVELS[$LOG_LEVEL]} ]]; then
            local color=""
            local reset="\033[0m"
            case $level in
                DEBUG) color="\033[36m" ;;
                INFO)  color="\033[32m" ;;
                WARN)  color="\033[33m" ;;
                ERROR) color="\033[31m" ;;
                FATAL) color="\033[35m" ;;
            esac

            echo -e "${color}[$timestamp] [$level] $message${reset}" >&2
            echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
        fi
    }

    # === CLEANUP ===
    cleanup() {
        local exit_code=$?
        log INFO "Arrêt du monitoring (exit code: $exit_code)"
        exit $exit_code
    }

    trap cleanup EXIT INT TERM

    # === FUNCTIONS ===
    usage() {
        cat << EOF
    Usage: $SCRIPT_NAME [OPTIONS]

    Options:
        -i, --interval SECONDS   Intervalle entre collectes (défaut: 300)
        -t, --threshold PERCENT  Seuil d'alerte CPU/RAM (défaut: 80)
        -o, --output DIR         Répertoire de sortie (défaut: /var/log/monitoring)
        -c, --config FILE        Fichier de configuration
        -v, --verbose            Mode verbeux (DEBUG)
        -h, --help               Afficher cette aide

    Exemples:
        $SCRIPT_NAME -i 60 -t 90 -v
        $SCRIPT_NAME --config /etc/custom-monitor.conf

    Version: $VERSION
    EOF
        exit 0
    }

    load_config() {
        if [[ -f "$CONFIG_FILE" ]]; then
            log INFO "Chargement de la configuration depuis $CONFIG_FILE"
            # Charger les variables depuis le fichier (format KEY=VALUE)
            while IFS='=' read -r key value; do
                [[ $key =~ ^#.*$ ]] && continue
                [[ -z "$key" ]] && continue
                case $key in
                    INTERVAL) INTERVAL="$value" ;;
                    CPU_THRESHOLD) CPU_THRESHOLD="$value" ;;
                    MEM_THRESHOLD) MEM_THRESHOLD="$value" ;;
                    OUTPUT_DIR) OUTPUT_DIR="$value" ;;
                esac
            done < "$CONFIG_FILE"
        fi
    }

    collect_metrics() {
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

        # CPU
        local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
        cpu_usage=${cpu_usage%.*}  # Arrondir

        # Memory
        local mem_total=$(free -m | awk '/Mem:/ {print $2}')
        local mem_used=$(free -m | awk '/Mem:/ {print $3}')
        local mem_percent=$((mem_used * 100 / mem_total))

        # Disk
        local disk_usage=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')

        # Top 5 processus CPU
        local top_procs=$(ps aux --sort=-%cpu | head -6 | tail -5 | awk '{printf "%s(%s%%) ", $11, $3}')

        # Logger les métriques
        log DEBUG "CPU=${cpu_usage}% MEM=${mem_percent}% DISK=${disk_usage}%"
        echo "$timestamp,CPU=$cpu_usage,MEM=$mem_percent,DISK=$disk_usage,TOP_PROCS=$top_procs" >> "$METRICS_FILE"

        # Vérifier les seuils
        if [[ $cpu_usage -gt $CPU_THRESHOLD ]]; then
            log ERROR "ALERTE: CPU usage critique: ${cpu_usage}% (seuil: ${CPU_THRESHOLD}%)"
        fi

        if [[ $mem_percent -gt $MEM_THRESHOLD ]]; then
            log ERROR "ALERTE: Mémoire critique: ${mem_percent}% (seuil: ${MEM_THRESHOLD}%)"
        fi

        log INFO "Métriques collectées: CPU=${cpu_usage}% MEM=${mem_percent}% DISK=${disk_usage}%"
    }

    rotate_logs() {
        log INFO "Rotation des logs (rétention: $RETENTION_DAYS jours)"
        find "$OUTPUT_DIR" -name "*.log" -type f -mtime +$RETENTION_DAYS -delete
    }

    validate_threshold() {
        local threshold=$1
        if [[ ! $threshold =~ ^[0-9]+$ ]] || [[ $threshold -lt 1 ]] || [[ $threshold -gt 100 ]]; then
            log ERROR "Seuil invalide: $threshold (doit être entre 1 et 100)"
            exit 1
        fi
    }

    # === MAIN ===
    main() {
        # Charger la config si elle existe
        load_config

        # Parser les arguments
        while [[ $# -gt 0 ]]; do
            case $1 in
                -i|--interval)
                    INTERVAL="$2"
                    shift 2
                    ;;
                -t|--threshold)
                    CPU_THRESHOLD="$2"
                    MEM_THRESHOLD="$2"
                    validate_threshold "$2"
                    shift 2
                    ;;
                -o|--output)
                    OUTPUT_DIR="$2"
                    LOG_FILE="${OUTPUT_DIR}/system-monitor.log"
                    METRICS_FILE="${OUTPUT_DIR}/metrics.log"
                    shift 2
                    ;;
                -c|--config)
                    CONFIG_FILE="$2"
                    shift 2
                    ;;
                -v|--verbose)
                    VERBOSE=true
                    LOG_LEVEL="DEBUG"
                    shift
                    ;;
                -h|--help)
                    usage
                    ;;
                *)
                    log ERROR "Option inconnue: $1"
                    usage
                    ;;
            esac
        done

        # Créer le répertoire de sortie si nécessaire
        if [[ ! -d "$OUTPUT_DIR" ]]; then
            mkdir -p "$OUTPUT_DIR" || {
                log FATAL "Impossible de créer $OUTPUT_DIR"
                exit 1
            }
        fi

        log INFO "=== Démarrage du monitoring système ==="
        log INFO "Intervalle: ${INTERVAL}s, Seuils: CPU=${CPU_THRESHOLD}% MEM=${MEM_THRESHOLD}%"
        log INFO "Logs: $LOG_FILE, Métriques: $METRICS_FILE"

        # Boucle de monitoring
        while true; do
            collect_metrics
            rotate_logs

            if [[ "$VERBOSE" == true ]]; then
                log DEBUG "Prochaine collecte dans ${INTERVAL}s"
            fi

            sleep "$INTERVAL"
        done
    }

    main "$@"
    ```

    **Test du script :**

    ```bash
    # Valider avec shellcheck
    shellcheck system-monitor.sh

    # Tester en mode verbeux avec intervalle court
    ./system-monitor.sh -v -i 10 -t 75

    # Vérifier les logs
    tail -f /var/log/monitoring/system-monitor.log
    tail -f /var/log/monitoring/metrics.log

    # Tester avec un fichier de config
    cat > /etc/monitoring/config.conf << 'EOF'
    INTERVAL=60
    CPU_THRESHOLD=85
    MEM_THRESHOLD=90
    OUTPUT_DIR=/var/log/custom-monitoring
    EOF

    ./system-monitor.sh -c /etc/monitoring/config.conf -v
    ```

    **Améliorations possibles :**

    1. Ajouter des tests unitaires avec BATS
    2. Implémenter l'envoi d'emails/Slack pour les alertes
    3. Exporter les métriques vers Prometheus
    4. Ajouter un mode daemon avec systemd
    5. Implémenter un fichier de lock pour éviter les exécutions multiples
    6. Ajouter le support de multiples machines (SSH)

---

## Points Clés à Retenir

| Concept | Implémentation |
|---------|----------------|
| Mode strict | `set -euo pipefail` |
| Cleanup | `trap cleanup EXIT` |
| Logging | Fonction avec niveaux |
| Arguments | `getopts` ou boucle while |
| Validation | `shellcheck`, BATS |
| Parallélisme | `&` + `wait` |

---

[:octicons-arrow-right-24: Module 15 : Backup & Disaster Recovery](15-backup.md)

---

**Retour au :** [Programme de la Formation](index.md)
