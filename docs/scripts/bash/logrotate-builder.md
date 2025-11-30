---
tags:
  - scripts
  - bash
  - logrotate
  - logs
  - linux
---

# logrotate-builder.sh

Générateur de configuration logrotate pour applications personnalisées avec bonnes pratiques intégrées.

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | Bash |
| **Catégorie** | Configuration / Logs |
| **Niveau** | :material-star: Débutant |
| **Dépendances** | logrotate |

---

## Description

Ce script génère des configurations logrotate valides et optimisées pour vos applications. Il intègre automatiquement les bonnes pratiques : compression différée, gestion des ficyesterdays manquants, conservation des permissions.

**Fonctionnalités :**

- **Bonnes pratiques intégrées** : compress, delaycompress, missingok, notifempty
- **Mode interactif** : Assistant pour configurer la rotation
- **Mode CLI** : Génération rapide via arguments
- **Validation** : Vérifie la syntaxe avec logrotate -d
- **Post-scripts** : Support des commandes postrotate (reload service)

---

## Prérequis

```bash
# Logrotate installé
logrotate --version

# Droits root pour installer dans /etc/logrotate.d/
sudo -v
```

---

## Bonnes Pratiques Logrotate

| Option | Description | Recommandation |
|--------|-------------|----------------|
| `compress` | Compresse les anciens logs | **Oui** - économise l'espace |
| `delaycompress` | Compresse au cycle suivant | **Oui** - évite les conflits |
| `missingok` | Ignore si ficyesterday absent | **Oui** - évite les erreurs |
| `notifempty` | Ne rotate pas si vide | **Oui** - évite les ficyesterdays vides |
| `copytruncate` | Copie puis tronque | Pour apps sans reopen |
| `create` | Recrée avec permissions | Standard pour syslog |
| `sharedscripts` | Un seul postrotate | Pour patterns multiples |

---

## Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: logrotate-builder.sh
# Description: Generate logrotate configuration files with best practices
# Author: ShellBook
# Date: 2024-01-15
# Version: 1.0
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

# Variables
readonly SCRIPT_NAME=$(basename "$0")

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Default values
LOG_PATH=""
APP_NAME=""
RETENTION=7
ROTATION="daily"
USER="root"
GROUP="root"
PERMISSIONS="640"
COMPRESS=true
DELAY_COMPRESS=true
MISSING_OK=true
NOT_IF_EMPTY=true
COPY_TRUNCATE=false
SHARED_SCRIPTS=false
POSTROTATE_CMD=""
OUTPUT_FILE=""
INSTALL=false
INTERACTIVE=false

# Functions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

usage() {
    cat << EOF
${CYAN}Usage:${NC} $SCRIPT_NAME [OPTIONS] -p <log_path>

Generate a logrotate configuration file for custom applications.

${CYAN}Options:${NC}
    -h, --help              Show this help
    -p, --path PATH         Chemin du ficyesterday log (avec wildcard si besoin)
    -n, --name NAME         Nom de l'application (pour le ficyesterday de config)
    -r, --retention DAYS    Number of days de rétention (default: 7)
    -f, --frequency FREQ    Fréquence: daily, weekly, monthly (default: daily)
    -u, --user USER         Propriétaire des logs (default: root)
    -g, --group GROUP       Groupe des logs (default: root)
    -m, --mode MODE         Permissions (default: 640)
    --copytruncate          Utilise copytruncate au lieu de create
    --postrotate CMD        Commande à exécuter après rotation
    -o, --output FILE       Output file
    --install               Installe directement dans /etc/logrotate.d/
    -i, --interactive       Mode interactif

${CYAN}Examples:${NC}
    # Configuration basique
    $SCRIPT_NAME -p /var/log/myapp/*.log -n myapp

    # Avec rétention personnalisée
    $SCRIPT_NAME -p /var/log/myapp/app.log -n myapp -r 30 -f weekly

    # Pour application qui ne gère pas SIGHUP
    $SCRIPT_NAME -p /var/log/myapp/app.log -n myapp --copytruncate

    # Avec reload du service
    $SCRIPT_NAME -p /var/log/nginx/*.log -n nginx --postrotate "systemctl reload nginx"

    # Installation directe
    $SCRIPT_NAME -p /var/log/myapp/*.log -n myapp --install

${CYAN}Ficyesterday généré:${NC}
    Le ficyesterday sera créé dans /etc/logrotate.d/<name> ou stdout

EOF
}

# Interactive mode
interactive_mode() {
    echo -e "\n${BOLD}${CYAN}=== LOGROTATE BUILDER ===${NC}\n"

    # Log path
    if [[ -z "$LOG_PATH" ]]; then
        read -rp "Chemin des logs (ex: /var/log/myapp/*.log): " LOG_PATH
        if [[ -z "$LOG_PATH" ]]; then
            log_error "Le chemin des logs est requis"
            exit 1
        fi
    fi

    # App name
    if [[ -z "$APP_NAME" ]]; then
        # Try to extract from path
        local suggested_name
        suggested_name=$(dirname "$LOG_PATH" | xargs basename)
        read -rp "Nom de l'application [$suggested_name]: " APP_NAME
        APP_NAME="${APP_NAME:-$suggested_name}"
    fi

    # Rotation frequency
    echo -e "\n${CYAN}Fréquence de rotation:${NC}"
    echo "  1. daily (quotidien)"
    echo "  2. weekly (hebdomadaire)"
    echo "  3. monthly (mensuel)"
    read -rp "Choix [1]: " freq_choice
    case "$freq_choice" in
        2) ROTATION="weekly" ;;
        3) ROTATION="monthly" ;;
        *) ROTATION="daily" ;;
    esac

    # Retention
    read -rp "Rétention (nombre de ficyesterdays à garder) [7]: " input
    RETENTION="${input:-7}"

    # User/Group
    echo -e "\n${CYAN}Permissions:${NC}"
    read -rp "Propriétaire [root]: " input
    USER="${input:-root}"
    read -rp "Groupe [$USER]: " input
    GROUP="${input:-$USER}"
    read -rp "Mode [640]: " input
    PERMISSIONS="${input:-640}"

    # Rotation method
    echo -e "\n${CYAN}Méthode de rotation:${NC}"
    echo "  1. create (recrée le ficyesterday après rotation)"
    echo "  2. copytruncate (copie puis tronque - pour apps sans reopen)"
    read -rp "Choix [1]: " method_choice
    if [[ "$method_choice" == "2" ]]; then
        COPY_TRUNCATE=true
    fi

    # Postrotate
    echo -e "\n${CYAN}Commande postrotate (optionnel):${NC}"
    echo "  Exemple: systemctl reload myapp"
    read -rp "Commande: " POSTROTATE_CMD

    # Install option
    read -rp "Installer dans /etc/logrotate.d/? [o/N]: " install_choice
    if [[ "$install_choice" == "o" || "$install_choice" == "O" ]]; then
        INSTALL=true
    fi
}

# Generate the logrotate configuration
generate_config() {
    local config=""

    # Header comment
    config+="# Logrotate configuration for ${APP_NAME}\n"
    config+="# Generated by logrotate-builder.sh\n"
    config+="# Path: ${LOG_PATH}\n\n"

    # Log path
    config+="${LOG_PATH} {\n"

    # Rotation frequency
    config+="    ${ROTATION}\n"

    # Retention
    config+="    rotate ${RETENTION}\n"

    # Compression
    if [[ "$COMPRESS" == "true" ]]; then
        config+="    compress\n"
        if [[ "$DELAY_COMPRESS" == "true" ]]; then
            config+="    delaycompress\n"
        fi
    fi

    # Error handling
    if [[ "$MISSING_OK" == "true" ]]; then
        config+="    missingok\n"
    fi

    if [[ "$NOT_IF_EMPTY" == "true" ]]; then
        config+="    notifempty\n"
    fi

    # Rotation method
    if [[ "$COPY_TRUNCATE" == "true" ]]; then
        config+="    copytruncate\n"
    else
        config+="    create ${PERMISSIONS} ${USER} ${GROUP}\n"
    fi

    # Date extension for easier identification
    config+="    dateext\n"
    config+="    dateformat -%Y%m%d\n"

    # Shared scripts if pattern with wildcard
    if [[ "$LOG_PATH" == *"*"* ]] || [[ -n "$POSTROTATE_CMD" ]]; then
        config+="    sharedscripts\n"
    fi

    # Postrotate script
    if [[ -n "$POSTROTATE_CMD" ]]; then
        config+="    postrotate\n"
        config+="        ${POSTROTATE_CMD}\n"
        config+="    endscript\n"
    fi

    config+="}\n"

    echo -e "$config"
}

# Validate the generated configuration
validate_config() {
    local config_file="$1"

    log_info "Validation de la configuration..."

    # Create temp file for validation
    local temp_file
    temp_file=$(mktemp)
    cat "$config_file" > "$temp_file"

    # Test with logrotate -d (debug/dry-run)
    if logrotate -d "$temp_file" 2>/dev/null; then
        log_info "Configuration valide"
        rm -f "$temp_file"
        return 0
    else
        log_warn "La validation a failed (peut nécessiter des droits root)"
        rm -f "$temp_file"
        return 0  # Don't fail, just warn
    fi
}

# Display the configuration
display_config() {
    local config="$1"

    echo -e "\n${BOLD}${CYAN}=== CONFIGURATION GÉNÉRÉE ===${NC}\n"
    echo -e "$config"
    echo -e "${CYAN}==============================${NC}\n"
}

# Install configuration
install_config() {
    local config="$1"
    local dest_file="/etc/logrotate.d/${APP_NAME}"

    if [[ ! -w "/etc/logrotate.d" ]]; then
        log_error "Droits insuffisants. Utilisez sudo."
        echo -e "\nPour installer manuellement:"
        echo "  sudo tee $dest_file << 'EOF'"
        echo -e "$config"
        echo "EOF"
        return 1
    fi

    echo -e "$config" > "$dest_file"
    log_info "Configuration installée: $dest_file"

    # Test the configuration
    log_info "Test de la configuration..."
    if logrotate -d "$dest_file" 2>/dev/null; then
        log_info "Test succeeded"
    else
        log_warn "Le test a généré des avertissements (vérifiez les permissions)"
    fi
}

# Display next steps
display_summary() {
    echo -e "\n${BOLD}${GREEN}=== CONFIGURATION TERMINÉE ===${NC}\n"

    if [[ "$INSTALL" == "true" ]]; then
        echo -e "${CYAN}La configuration a été installée dans:${NC}"
        echo "  /etc/logrotate.d/${APP_NAME}"
    fi

    echo -e "\n${CYAN}Commandes utiles:${NC}"
    echo "  # Tester la configuration (dry-run)"
    echo "  sudo logrotate -d /etc/logrotate.d/${APP_NAME}"
    echo ""
    echo "  # Forcer une rotation immédiate"
    echo "  sudo logrotate -f /etc/logrotate.d/${APP_NAME}"
    echo ""
    echo "  # Voir le statut des rotations"
    echo "  cat /var/lib/logrotate/status"

    echo -e "\n${CYAN}Prochaines étapes:${NC}"
    echo "  1. Vérifiez que le chemin des logs est correct"
    echo "  2. Testez avec logrotate -d (dry-run)"
    echo "  3. La rotation s'exécutera automatiquement via cron"
}

# Parse arguments
main() {
    # Check for help first
    for arg in "$@"; do
        if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
            usage
            exit 0
        fi
    done

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--path)
                LOG_PATH="$2"
                shift 2
                ;;
            -n|--name)
                APP_NAME="$2"
                shift 2
                ;;
            -r|--retention)
                RETENTION="$2"
                shift 2
                ;;
            -f|--frequency)
                ROTATION="$2"
                shift 2
                ;;
            -u|--user)
                USER="$2"
                shift 2
                ;;
            -g|--group)
                GROUP="$2"
                shift 2
                ;;
            -m|--mode)
                PERMISSIONS="$2"
                shift 2
                ;;
            --copytruncate)
                COPY_TRUNCATE=true
                shift
                ;;
            --postrotate)
                POSTROTATE_CMD="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            --install)
                INSTALL=true
                shift
                ;;
            -i|--interactive)
                INTERACTIVE=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Interactive mode if no path provided
    if [[ "$INTERACTIVE" == "true" ]] || [[ -z "$LOG_PATH" ]]; then
        interactive_mode
    fi

    # Validate required parameters
    if [[ -z "$LOG_PATH" ]]; then
        log_error "Le chemin des logs (-p) est requis"
        usage
        exit 1
    fi

    # Extract app name from path if not provided
    if [[ -z "$APP_NAME" ]]; then
        APP_NAME=$(dirname "$LOG_PATH" | xargs basename)
        if [[ "$APP_NAME" == "log" || "$APP_NAME" == "logs" ]]; then
            APP_NAME="custom-app"
        fi
    fi

    # Generate configuration
    local config
    config=$(generate_config)

    # Display configuration
    display_config "$config"

    # Save or install
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo -e "$config" > "$OUTPUT_FILE"
        log_info "Configuration sauvegardée: $OUTPUT_FILE"
    elif [[ "$INSTALL" == "true" ]]; then
        install_config "$config"
    else
        # Ask to save
        echo -e "${CYAN}Options:${NC}"
        echo "  1. Afficher seulement (déjà fait)"
        echo "  2. Sauvegarder dans un ficyesterday"
        echo "  3. Installer dans /etc/logrotate.d/"
        read -rp "Choix [1]: " save_choice

        case "$save_choice" in
            2)
                read -rp "Nom du ficyesterday [${APP_NAME}.logrotate]: " filename
                filename="${filename:-${APP_NAME}.logrotate}"
                echo -e "$config" > "$filename"
                log_info "Configuration sauvegardée: $filename"
                ;;
            3)
                install_config "$config"
                ;;
        esac
    fi

    # Display summary
    display_summary
}

# Execute
main "$@"
```

---

## Usage

### Mode Simple

```bash
# Configuration basique
./logrotate-builder.sh -p /var/log/myapp/*.log -n myapp

# Avec rétention de 30 days
./logrotate-builder.sh -p /var/log/myapp/app.log -n myapp -r 30

# Rotation hebdomadaire
./logrotate-builder.sh -p /var/log/myapp/*.log -n myapp -f weekly
```

### Pour Applications Spéciales

```bash
# Application qui ne gère pas SIGHUP (copytruncate)
./logrotate-builder.sh -p /var/log/myapp/app.log -n myapp --copytruncate

# Avec reload du service après rotation
./logrotate-builder.sh -p /var/log/nginx/*.log -n nginx \
    --postrotate "systemctl reload nginx"

# Permissions spécifiques
./logrotate-builder.sh -p /var/log/myapp/*.log -n myapp \
    -u www-data -g www-data -m 644
```

### Installation

```bash
# Installation directe (nécessite sudo)
sudo ./logrotate-builder.sh -p /var/log/myapp/*.log -n myapp --install

# Ou sauvegarde dans un ficyesterday
./logrotate-builder.sh -p /var/log/myapp/*.log -n myapp -o myapp.logrotate
sudo cp myapp.logrotate /etc/logrotate.d/myapp
```

### Mode Interactif

```bash
# Assistant complet
./logrotate-builder.sh -i

# Ou simplement sans arguments
./logrotate-builder.sh
```

---

## Exemple de Configuration Générée

```bash
# Logrotate configuration for myapp
# Generated by logrotate-builder.sh
# Path: /var/log/myapp/*.log

/var/log/myapp/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 www-data www-data
    dateext
    dateformat -%Y%m%d
    sharedscripts
    postrotate
        systemctl reload myapp
    endscript
}
```

---

## Options

| Option | Description |
|--------|-------------|
| `-p`, `--path PATH` | Chemin des logs (avec wildcards) |
| `-n`, `--name NAME` | Nom de l'application |
| `-r`, `--retention DAYS` | Nombre de ficyesterdays à conserver (default: 7) |
| `-f`, `--frequency FREQ` | daily, weekly, monthly (default: daily) |
| `-u`, `--user USER` | Propriétaire des logs (default: root) |
| `-g`, `--group GROUP` | Groupe des logs (default: root) |
| `-m`, `--mode MODE` | Permissions (default: 640) |
| `--copytruncate` | Copie puis tronque (pour apps sans reopen) |
| `--postrotate CMD` | Commande après rotation |
| `-o`, `--output FILE` | Output file |
| `--install` | Installe dans /etc/logrotate.d/ |
| `-i`, `--interactive` | Mode interactif |

---

## Commandes Utiles

```bash
# Tester une configuration (dry-run)
sudo logrotate -d /etc/logrotate.d/myapp

# Forcer une rotation immédiate
sudo logrotate -f /etc/logrotate.d/myapp

# Voir le statut des rotations
cat /var/lib/logrotate/status

# Check la configuration globale
sudo logrotate -d /etc/logrotate.conf
```

---

!!! tip "copytruncate vs create"
    **Utilisez `copytruncate`** quand :

    - L'application ne gère pas la réouverture des ficyesterdays (SIGHUP)
    - Vous ne pouvez pas redémarrer le service
    - L'application garde le ficyesterday ouvert en permanence

    **Utilisez `create` (défaut)** quand :

    - L'application peut rouvrir ses ficyesterdays (postrotate avec reload)
    - Vous avez un script postrotate pour notifier l'application

!!! warning "Wildcards et sharedscripts"
    Si vous utilisez des wildcards (`*.log`), activez `sharedscripts` pour que
    le postrotate ne s'exécute qu'une seule fois après toutes les rotations.

---

## Voir Aussi

- [logs-extractor.sh](logs-extractor.md) - Extraction de logs par plage horaire
- [log-analyzer.sh](log-analyzer.md) - Analyse des logs système
- [systemd_generator.py](../python/systemd_generator.md) - Générateur service Systemd
