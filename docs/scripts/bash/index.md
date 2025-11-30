---
tags:
  - scripts
  - bash
  - linux
---

# Scripts Bash

Collection de scripts Bash pour l'administration Linux/Unix.

---

## Système

| Script | Description | Niveau |
|--------|-------------|--------|
| [system-info.sh](system-info.md) | Informations système complètes | :material-star: |
| [check-disk-space.sh](check-disk-space.md) | Vérification espace disque avec alertes | :material-star: |
| [monitor-resources.sh](monitor-resources.md) | Monitoring CPU/RAM en temps réel | :material-star::material-star: |
| [cleanup-system.sh](cleanup-system.md) | Nettoyage système automatisé | :material-star::material-star: |
| [logs-extractor.sh](logs-extractor.md) | Extraction de logs par plage horaire | :material-star::material-star: |

## Réseau

| Script | Description | Niveau |
|--------|-------------|--------|
| [check-connectivity.sh](check-connectivity.md) | Test de connectivité réseau | :material-star: |
| [port-scanner.sh](port-scanner.md) | Scanner de ports simple | :material-star::material-star: |
| [dns-lookup.sh](dns-lookup.md) | Résolution DNS avancée | :material-star: |

## Fichiers & Backup

| Script | Description | Niveau |
|--------|-------------|--------|
| [backup-directory.sh](backup-directory.md) | Backup avec rotation | :material-star::material-star: |
| [sync-folders.sh](sync-folders.md) | Synchronisation de dossiers | :material-star: |
| [find-large-files.sh](find-large-files.md) | Recherche fichiers volumineux | :material-star: |

## Sécurité

| Script | Description | Niveau |
|--------|-------------|--------|
| [security-audit.sh](security-audit.md) | Audit de sécurité basique | :material-star::material-star::material-star: |
| [check-permissions.sh](check-permissions.md) | Vérification permissions sensibles | :material-star::material-star: |
| [log-analyzer.sh](log-analyzer.md) | Analyse des logs système | :material-star::material-star: |

## Services

| Script | Description | Niveau |
|--------|-------------|--------|
| [service-manager.sh](service-manager.md) | Gestion des services systemd | :material-star: |
| [health-check.sh](health-check.md) | Vérification santé des services | :material-star::material-star: |

## Conteneurs & Kubernetes

| Script | Description | Niveau |
|--------|-------------|--------|
| [k8s-pod-inspector.sh](k8s-pod-inspector.md) | Diagnostic complet de pods Kubernetes | :material-star::material-star: |
| [container-net-debug.sh](container-net-debug.md) | Debug réseau avec sidecar netshoot | :material-star::material-star: |

## Base de Données

| Script | Description | Niveau |
|--------|-------------|--------|
| [pg-bloat-check.sh](pg-bloat-check.md) | Estimation bloat PostgreSQL (MVCC) | :material-star::material-star::material-star: |
| [mysql-security-audit.sh](mysql-security-audit.md) | Audit sécurité MySQL/MariaDB | :material-star::material-star: |

## Générateurs de Configuration

| Script | Description | Niveau |
|--------|-------------|--------|
| [ssl-csr-wizard.sh](ssl-csr-wizard.md) | Générateur CSR SSL avec support SANs | :material-star::material-star: |
| [logrotate-builder.sh](logrotate-builder.md) | Générateur config logrotate | :material-star: |

## Infrastructure Linux

| Script | Description | Niveau |
|--------|-------------|--------|
| [check-ldap.sh](check-ldap.md) | Vérification serveur LDAP/OpenLDAP | :material-star::material-star: |
| [check-bind.sh](check-bind.md) | Vérification serveur DNS BIND | :material-star::material-star: |
| [check-mysql.sh](check-mysql.md) | Vérification serveur MySQL/MariaDB | :material-star::material-star: |
| [check-postgresql.sh](check-postgresql.md) | Vérification serveur PostgreSQL | :material-star::material-star: |
| [check-nginx.sh](check-nginx.md) | Vérification serveur Nginx | :material-star::material-star: |
| [check-postfix.sh](check-postfix.md) | Vérification serveur mail Postfix | :material-star::material-star: |

---

## Template de Script

```bash
#!/bin/bash
#===============================================================================
# Script Name: script-name.sh
# Description: Description du script
# Author: Votre Nom
# Date: 2024-01-01
# Version: 1.0
#===============================================================================

set -euo pipefail
IFS=$'\n\t'

# Variables
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# Couleurs
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Fonctions
log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Description du script.

Options:
    -h, --help      Affiche cette aide
    -v, --verbose   Mode verbeux

Exemples:
    $SCRIPT_NAME -v
EOF
}

main() {
    # Code principal
    log_info "Script démarré"
}

# Exécution
main "$@"
```

---

## Voir Aussi

- [Scripts PowerShell](../powershell/index.md)
- [Scripts Python](../python/index.md)
