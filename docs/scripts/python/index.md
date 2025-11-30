---
tags:
  - scripts
  - python
  - automation
---

# Scripts Python

Collection de scripts Python pour l'automatisation et l'administration système.

---

## Système

| Script | Description | Niveau |
|--------|-------------|--------|
| [system_info.py](system_info.md) | Informations système complètes | :material-star: |
| [disk_monitor.py](disk_monitor.md) | Monitoring espace disque | :material-star: |
| [process_manager.py](process_manager.md) | Gestion des processus | :material-star::material-star: |

## Réseau

| Script | Description | Niveau |
|--------|-------------|--------|
| [network_scanner.py](network_scanner.md) | Scanner réseau | :material-star::material-star: |
| [port_checker.py](port_checker.md) | Vérification de ports | :material-star: |
| [dns_resolver.py](dns_resolver.md) | Résolution DNS avancée | :material-star: |

## Fichiers & Backup

| Script | Description | Niveau |
|--------|-------------|--------|
| [backup_manager.py](backup_manager.md) | Gestion des sauvegardes | :material-star::material-star: |
| [file_organizer.py](file_organizer.md) | Organisation automatique | :material-star: |
| [duplicate_finder.py](duplicate_finder.md) | Recherche de doublons | :material-star::material-star: |

## Monitoring & Alertes

| Script | Description | Niveau |
|--------|-------------|--------|
| [health_checker.py](health_checker.md) | Vérification santé services | :material-star::material-star: |
| [log_analyzer.py](log_analyzer.md) | Analyse de logs | :material-star::material-star: |
| [alert_sender.py](alert_sender.md) | Envoi d'alertes (email/Slack) | :material-star::material-star: |

## DevOps & Cloud

| Script | Description | Niveau |
|--------|-------------|--------|
| [cert_checker.py](cert_checker.md) | Vérification certificats SSL/TLS | :material-star::material-star: |
| [kubernetes_health.py](kubernetes_health.md) | Vérification santé cluster Kubernetes | :material-star::material-star::material-star: |
| [docker_health.py](docker_health.md) | Vérification santé Docker | :material-star::material-star: |

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
    """Configure les arguments CLI."""
    parser = argparse.ArgumentParser(
        description="Description du script",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
    %(prog)s --option value
    %(prog)s -v --config config.yaml
        """
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mode verbeux'
    )

    parser.add_argument(
        '-c', '--config',
        type=Path,
        help='Fichier de configuration'
    )

    parser.add_argument(
        'target',
        nargs='?',
        default='.',
        help='Cible (défaut: répertoire courant)'
    )

    return parser.parse_args()


def main() -> int:
    """Point d'entrée principal."""
    args = setup_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        logger.info("Script démarré")

        # Code principal ici

        logger.info("Script terminé avec succès")
        return 0

    except KeyboardInterrupt:
        logger.warning("Interruption utilisateur")
        return 130

    except Exception as e:
        logger.error(f"Erreur: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
```

---

## Bonnes Pratiques Python

### Structure de Projet

```
mon_script/
├── __init__.py
├── __main__.py      # Point d'entrée
├── cli.py           # Interface CLI
├── core.py          # Logique métier
├── utils.py         # Utilitaires
├── config.py        # Configuration
└── tests/
    └── test_core.py
```

### Gestion des Dépendances

```python
# requirements.txt
psutil>=5.9.0
requests>=2.28.0
python-dotenv>=1.0.0
rich>=13.0.0

# Installation
# pip install -r requirements.txt
```

### Configuration avec dotenv

```python
from pathlib import Path
from dotenv import load_dotenv
import os

# Charger .env
load_dotenv()

# Accéder aux variables
API_KEY = os.getenv('API_KEY')
DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
```

### Sortie Colorée avec Rich

```python
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()

# Texte coloré
console.print("[green]Succès![/green]")
console.print("[red]Erreur![/red]")

# Tableaux
table = Table(title="Résultats")
table.add_column("Nom", style="cyan")
table.add_column("Statut", style="green")
table.add_row("Service A", "OK")
console.print(table)

# Barre de progression
for item in track(items, description="Processing..."):
    process(item)
```

---

## Dépendances Communes

```bash
# Système
pip install psutil         # Informations système
pip install watchdog       # Surveillance fichiers

# Réseau
pip install requests       # HTTP
pip install paramiko       # SSH
pip install dnspython      # DNS

# CLI
pip install click          # CLI moderne
pip install rich           # Sortie formatée
pip install typer          # CLI avec types

# Configuration
pip install python-dotenv  # Variables d'environnement
pip install pyyaml         # Fichiers YAML

# Tests
pip install pytest         # Tests
pip install pytest-cov     # Couverture
```

---

## Voir Aussi

- [Scripts Bash](../bash/index.md)
- [Scripts PowerShell](../powershell/index.md)
- [Formation Python SysOps](../../formations/python-sysops/index.md)
