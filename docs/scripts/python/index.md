---
tags:
  - scripts
  - python
  - automation
---

# Scripts Python

Collection de scripts Python pour l'automatisation et l'administration système.

---

!!! tip "Installation des dépendances"
    Pour utiliser ces scripts, installez les librairies requises :

    ```bash
    # Depuis la racine du projet
    pip install -r docs/scripts/python/requirements.txt

    # Ou avec un environnement virtuel (recommandé)
    python -m venv .venv
    source .venv/bin/activate  # Linux/macOS
    # .venv\Scripts\activate   # Windows
    pip install -r docs/scripts/python/requirements.txt
    ```

    **Dépendances installées :**

    | Package | Version | Utilisé par |
    |---------|---------|-------------|
    | `rich` | >=13.0.0 | La plupart des scripts (UI console) |
    | `pyyaml` | >=6.0 | Configuration YAML |
    | `psutil` | >=5.9.0 | system_info, disk_io_analyzer, cost_analyzer |
    | `docker` | >=7.0.0 | docker_cleaner_pro, docker_health |
    | `kubernetes` | >=29.0.0 | kubernetes_health |
    | `redis` | >=5.0.0 | redis_key_auditor |
    | `mysql-connector-python` | >=8.0.0 | db_replication_monitor |
    | `psycopg2-binary` | >=2.9.0 | db_replication_monitor |
    | `cryptography` | >=42.0.0 | cert_checker |
    | `gitpython` | >=3.1.0 | git_repo_cleaner |
    | `requests` | >=2.31.0 | api_health_monitor, cost_analyzer |
    | `python-dateutil` | >=2.8.0 | log_anomaly_detector |
    | `jinja2` | >=3.1.0 | compliance_report_generator |

---

## Scripts Disponibles (20 scripts)

### Système & Performance

| Script | Description | Niveau |
|--------|-------------|--------|
| [system_info.py](system_info.md) | Informations système complètes | :material-star: |
| [system_tuning_advisor.py](system_tuning_advisor.md) | Recommandations tuning kernel/sysctl | :material-star::material-star::material-star: |
| [disk_io_analyzer.py](disk_io_analyzer.md) | Analyse performances I/O disque | :material-star::material-star::material-star: |
| [patch_compliance_report.py](patch_compliance_report.md) | Audit conformité patchs système | :material-star::material-star: |

### Monitoring & Alertes

| Script | Description | Niveau |
|--------|-------------|--------|
| [health_checker.py](health_checker.md) | Vérification santé services | :material-star::material-star: |
| [api_health_monitor.py](api_health_monitor.md) | Monitoring multi-endpoints API avec SSL | :material-star::material-star: |
| [log_anomaly_detector.py](log_anomaly_detector.md) | Détection anomalies statistiques dans logs | :material-star::material-star::material-star: |

### Fichiers & Backup

| Script | Description | Niveau |
|--------|-------------|--------|
| [backup_manager.py](backup_manager.md) | Gestion des sauvegardes avec Rich | :material-star::material-star: |
| [backup_validator.py](backup_validator.md) | Validation intégrité backups (checksum) | :material-star::material-star: |

### Conteneurs

| Script | Description | Niveau |
|--------|-------------|--------|
| [docker_cleaner_pro.py](docker_cleaner_pro.md) | Nettoyage Docker avancé avec dry-run | :material-star::material-star: |
| [docker_health.py](docker_health.md) | Vérification santé Docker | :material-star::material-star: |
| [kubernetes_health.py](kubernetes_health.md) | Vérification santé cluster Kubernetes | :material-star::material-star::material-star: |

### Bases de Données

| Script | Description | Niveau |
|--------|-------------|--------|
| [redis_key_auditor.py](redis_key_auditor.md) | Audit clés Redis (SCAN non-bloquant) | :material-star::material-star: |
| [db_replication_monitor.py](db_replication_monitor.md) | Monitoring lag réplication MySQL/PostgreSQL | :material-star::material-star::material-star: |

### Réseau & Sécurité

| Script | Description | Niveau |
|--------|-------------|--------|
| [network_topology_mapper.py](network_topology_mapper.md) | Cartographie réseau automatique (Mermaid) | :material-star::material-star::material-star: |
| [compliance_report_generator.py](compliance_report_generator.md) | Rapports conformité CIS/ANSSI | :material-star::material-star::material-star: |

### FinOps & Cloud

| Script | Description | Niveau |
|--------|-------------|--------|
| [infrastructure_cost_analyzer.py](infrastructure_cost_analyzer.md) | Analyse coûts infrastructure cloud/on-prem | :material-star::material-star::material-star: |

### Générateurs de Configuration

| Script | Description | Niveau |
|--------|-------------|--------|
| [systemd_generator.py](systemd_generator.md) | Générateur service Systemd avec hardening | :material-star::material-star: |

### DevOps & Git

| Script | Description | Niveau |
|--------|-------------|--------|
| [cert_checker.py](cert_checker.md) | Vérification certificats SSL/TLS | :material-star::material-star: |
| [git_repo_cleaner.py](git_repo_cleaner.md) | Nettoyage branches Git obsolètes | :material-star::material-star: |

---

## Template de Script

```python
#!/usr/bin/env python3
"""
Script Name: script_name.py
Description: Description du script
Author: ShellBook
Version: 1.0
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_args() -> argparse.Namespace:
    """Configure CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Description du script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s --option value
    %(prog)s -v --config config.yaml
        """
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose mode'
    )

    parser.add_argument(
        '-c', '--config',
        type=Path,
        help='Configuration file'
    )

    parser.add_argument(
        'target',
        nargs='?',
        default='.',
        help='Target (default: current directory)'
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    args = setup_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        logger.info("Script started")

        # Main logic here

        logger.info("Script completed successfully")
        return 0

    except KeyboardInterrupt:
        logger.warning("User interrupt")
        return 130

    except Exception as e:
        logger.error(f"Error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
```

---

## Bonnes Pratiques Python

### Structure de Projet

```text
mon_script/
├── __init__.py
├── __main__.py      # Entry point
├── cli.py           # CLI interface
├── core.py          # Business logic
├── utils.py         # Utilities
├── config.py        # Configuration
└── tests/
    └── test_core.py
```

### Configuration avec dotenv

```python
from pathlib import Path
from dotenv import load_dotenv
import os

# Load .env file
load_dotenv()

# Access variables
API_KEY = os.getenv('API_KEY')
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
```

### Sortie Colorée avec Rich

```python
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()

# Colored text
console.print("[green]Success![/green]")
console.print("[red]Error![/red]")

# Tables
table = Table(title="Results")
table.add_column("Name", style="cyan")
table.add_column("Status", style="green")
table.add_row("Service A", "OK")
console.print(table)

# Progress bar
for item in track(items, description="Processing..."):
    process(item)
```

---

## Voir Aussi

- [Scripts Bash](../bash/index.md)
- [Scripts PowerShell](../powershell/index.md)
- [Formation Python SysOps](../../formations/python-sysops/index.md)
