---
tags:
  - scripts
  - python
  - docker
  - cleanup
  - devops
---

# docker_cleaner_pro.py

Nettoyeur Docker avancé avec mode dry-run par défaut - alternative sûre à `docker system prune`.

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | Python 3.8+ |
| **Catégorie** | DevOps / Conteneurs |
| **Niveau** | :material-star::material-star: Intermédiaire |
| **Dépendances** | `docker` (Python SDK) |

---

## Description

Ce script offre un contrôle granulaire sur le nettoyage des ressources Docker inutilisées. Contrairement à `docker system prune` qui supprime tout aveuglément, `docker_cleaner_pro.py` :

- **Mode dry-run par défaut** : Affiche ce qui serait supprimé sans rien toucher
- **Filtres sélectifs** : Nettoie uniquement les types de ressources souhaités
- **Politique de rétention** : Garde les conteneurs stoppés récents (configurable)
- **Rapport détaillé** : Affiche l'espace récupéré et les ressources supprimées

---

## Prérequis

```bash
# Installation du SDK Docker Python
pip install docker

# Vérifier que Docker est accessible
docker info
```

---

## Script

```python
#!/usr/bin/env python3
"""
Script Name: docker_cleaner_pro.py
Description: Advanced Docker cleanup with dry-run mode and granular control
Author: ShellBook
Version: 1.0
"""

import argparse
import logging
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

try:
    import docker
    from docker.errors import APIError, NotFound
except ImportError:
    print("Error: docker package not installed. Run: pip install docker")
    sys.exit(1)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DockerCleaner:
    """
    Docker resource cleaner with safe defaults and granular control.
    """

    def __init__(self, dry_run: bool = True, container_age_days: int = 7):
        """
        Initialize the Docker cleaner.

        Args:
            dry_run: If True, only simulate cleanup (default: True)
            container_age_days: Minimum age in days for stopped containers to be removed
        """
        self.dry_run = dry_run
        self.container_age_days = container_age_days
        self.client = docker.from_env()
        self.stats: Dict[str, Dict] = {
            'images': {'count': 0, 'size': 0},
            'containers': {'count': 0, 'size': 0},
            'volumes': {'count': 0, 'size': 0},
            'networks': {'count': 0}
        }

    def _format_size(self, size_bytes: int) -> str:
        """
        Format bytes into human-readable size.

        Args:
            size_bytes: Size in bytes

        Returns:
            Formatted string (e.g., "1.5 GB")
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} PB"

    def _parse_docker_time(self, time_str: str) -> datetime:
        """
        Parse Docker timestamp to datetime.

        Args:
            time_str: Docker timestamp string

        Returns:
            Datetime object
        """
        # Handle various Docker time formats
        formats = [
            '%Y-%m-%dT%H:%M:%S.%fZ',
            '%Y-%m-%dT%H:%M:%SZ',
            '%Y-%m-%dT%H:%M:%S.%f',
            '%Y-%m-%dT%H:%M:%S'
        ]
        # Remove timezone suffix if present (e.g., +00:00)
        if '+' in time_str:
            time_str = time_str.split('+')[0]
        if 'Z' not in time_str and not time_str.endswith('Z'):
            time_str = time_str.rstrip('Z')

        for fmt in formats:
            try:
                return datetime.strptime(time_str.split('.')[0], '%Y-%m-%dT%H:%M:%S')
            except ValueError:
                continue

        # Fallback: return current time (resource will be kept)
        logger.warning(f"Could not parse time: {time_str}")
        return datetime.now(timezone.utc).replace(tzinfo=None)

    def clean_dangling_images(self) -> List[str]:
        """
        Remove dangling (untagged) images.

        Returns:
            List of removed image IDs
        """
        logger.info("Scanning for dangling images...")
        removed = []

        try:
            # Get dangling images
            images = self.client.images.list(filters={'dangling': True})

            for image in images:
                image_id = image.short_id
                size = image.attrs.get('Size', 0)

                logger.info(f"  {'[DRY-RUN] Would remove' if self.dry_run else 'Removing'}: {image_id} ({self._format_size(size)})")

                if not self.dry_run:
                    try:
                        self.client.images.remove(image.id, force=True)
                        removed.append(image_id)
                        self.stats['images']['count'] += 1
                        self.stats['images']['size'] += size
                    except APIError as e:
                        logger.warning(f"  Could not remove {image_id}: {e}")
                else:
                    removed.append(image_id)
                    self.stats['images']['count'] += 1
                    self.stats['images']['size'] += size

        except APIError as e:
            logger.error(f"Error listing images: {e}")

        return removed

    def clean_stopped_containers(self) -> List[str]:
        """
        Remove stopped containers older than the specified age.

        Returns:
            List of removed container IDs
        """
        logger.info(f"Scanning for stopped containers (older than {self.container_age_days} days)...")
        removed = []
        cutoff_date = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=self.container_age_days)

        try:
            # Get stopped containers (exited status)
            containers = self.client.containers.list(all=True, filters={'status': 'exited'})

            for container in containers:
                # Check container age
                finished_at = container.attrs.get('State', {}).get('FinishedAt', '')
                if finished_at:
                    finish_time = self._parse_docker_time(finished_at)
                    if finish_time > cutoff_date:
                        logger.debug(f"  Skipping {container.short_id} (stopped recently)")
                        continue

                # Get container size
                size = 0
                if container.attrs.get('SizeRw'):
                    size = container.attrs['SizeRw']

                logger.info(f"  {'[DRY-RUN] Would remove' if self.dry_run else 'Removing'}: {container.short_id} ({container.name})")

                if not self.dry_run:
                    try:
                        container.remove(force=True)
                        removed.append(container.short_id)
                        self.stats['containers']['count'] += 1
                        self.stats['containers']['size'] += size
                    except APIError as e:
                        logger.warning(f"  Could not remove {container.short_id}: {e}")
                else:
                    removed.append(container.short_id)
                    self.stats['containers']['count'] += 1
                    self.stats['containers']['size'] += size

        except APIError as e:
            logger.error(f"Error listing containers: {e}")

        return removed

    def clean_orphan_volumes(self) -> List[str]:
        """
        Remove volumes not attached to any container.

        Returns:
            List of removed volume names
        """
        logger.info("Scanning for orphan volumes...")
        removed = []

        try:
            # Get dangling volumes (not referenced by any container)
            volumes = self.client.volumes.list(filters={'dangling': True})

            for volume in volumes:
                volume_name = volume.name
                # Try to get volume size (may not be available)
                size = 0
                try:
                    # Docker doesn't provide volume size directly
                    # We would need to inspect the volume path on disk
                    pass
                except Exception:
                    pass

                logger.info(f"  {'[DRY-RUN] Would remove' if self.dry_run else 'Removing'}: {volume_name}")

                if not self.dry_run:
                    try:
                        volume.remove(force=True)
                        removed.append(volume_name)
                        self.stats['volumes']['count'] += 1
                    except APIError as e:
                        logger.warning(f"  Could not remove {volume_name}: {e}")
                else:
                    removed.append(volume_name)
                    self.stats['volumes']['count'] += 1

        except APIError as e:
            logger.error(f"Error listing volumes: {e}")

        return removed

    def clean_unused_networks(self) -> List[str]:
        """
        Remove networks not used by any container (excluding defaults).

        Returns:
            List of removed network names
        """
        logger.info("Scanning for unused networks...")
        removed = []
        # Default networks that should never be removed
        protected_networks = {'bridge', 'host', 'none'}

        try:
            networks = self.client.networks.list()

            for network in networks:
                # Skip protected networks
                if network.name in protected_networks:
                    continue

                # Check if network is in use
                if network.attrs.get('Containers'):
                    continue

                logger.info(f"  {'[DRY-RUN] Would remove' if self.dry_run else 'Removing'}: {network.name}")

                if not self.dry_run:
                    try:
                        network.remove()
                        removed.append(network.name)
                        self.stats['networks']['count'] += 1
                    except APIError as e:
                        logger.warning(f"  Could not remove {network.name}: {e}")
                else:
                    removed.append(network.name)
                    self.stats['networks']['count'] += 1

        except APIError as e:
            logger.error(f"Error listing networks: {e}")

        return removed

    def print_summary(self) -> None:
        """
        Print cleanup summary with statistics.
        """
        print("\n" + "=" * 60)
        print("CLEANUP SUMMARY")
        if self.dry_run:
            print("(DRY-RUN MODE - Nothing was actually removed)")
        print("=" * 60)

        total_size = 0

        if self.stats['images']['count'] > 0:
            print(f"\nDangling Images:")
            print(f"  Count: {self.stats['images']['count']}")
            print(f"  Space: {self._format_size(self.stats['images']['size'])}")
            total_size += self.stats['images']['size']

        if self.stats['containers']['count'] > 0:
            print(f"\nStopped Containers (>{self.container_age_days} days):")
            print(f"  Count: {self.stats['containers']['count']}")
            if self.stats['containers']['size'] > 0:
                print(f"  Space: {self._format_size(self.stats['containers']['size'])}")
                total_size += self.stats['containers']['size']

        if self.stats['volumes']['count'] > 0:
            print(f"\nOrphan Volumes:")
            print(f"  Count: {self.stats['volumes']['count']}")

        if self.stats['networks']['count'] > 0:
            print(f"\nUnused Networks:")
            print(f"  Count: {self.stats['networks']['count']}")

        if total_size > 0:
            print(f"\nTotal space {'to be reclaimed' if self.dry_run else 'reclaimed'}: {self._format_size(total_size)}")

        if self.dry_run:
            print("\n[!] To actually perform cleanup, run with --force")

        print("=" * 60)


def setup_args() -> argparse.Namespace:
    """
    Configure CLI arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Advanced Docker cleanup with safe defaults",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
    # Mode dry-run (défaut) - affiche ce qui serait supprimé
    %(prog)s

    # Nettoyer uniquement les images dangling
    %(prog)s --images --force

    # Nettoyer tout avec confirmation
    %(prog)s --all --force

    # Supprimer les conteneurs stoppés depuis plus de 30 jours
    %(prog)s --containers --age 30 --force

Note:
    Par défaut, le script fonctionne en mode DRY-RUN.
    Utilisez --force pour effectuer réellement les suppressions.
        """
    )

    # Cleanup targets
    parser.add_argument(
        '-i', '--images',
        action='store_true',
        help='Nettoyer les images dangling (non taguées)'
    )

    parser.add_argument(
        '-c', '--containers',
        action='store_true',
        help='Nettoyer les conteneurs stoppés'
    )

    parser.add_argument(
        '-v', '--volumes',
        action='store_true',
        help='Nettoyer les volumes orphelins'
    )

    parser.add_argument(
        '-n', '--networks',
        action='store_true',
        help='Nettoyer les réseaux inutilisés'
    )

    parser.add_argument(
        '-a', '--all',
        action='store_true',
        help='Nettoyer toutes les ressources'
    )

    # Options
    parser.add_argument(
        '--age',
        type=int,
        default=7,
        metavar='DAYS',
        help='Âge minimum des conteneurs stoppés en jours (défaut: 7)'
    )

    parser.add_argument(
        '-f', '--force',
        action='store_true',
        help='Effectuer réellement les suppressions (désactive dry-run)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Afficher les messages de debug'
    )

    return parser.parse_args()


def main() -> int:
    """
    Main entry point.

    Returns:
        Exit code (0 for success, non-zero for errors)
    """
    args = setup_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Determine what to clean
    clean_images = args.images or args.all
    clean_containers = args.containers or args.all
    clean_volumes = args.volumes or args.all
    clean_networks = args.networks or args.all

    # If nothing specified, default to --all in dry-run
    if not any([clean_images, clean_containers, clean_volumes, clean_networks]):
        clean_images = clean_containers = clean_volumes = clean_networks = True

    # Initialize cleaner
    dry_run = not args.force
    cleaner = DockerCleaner(dry_run=dry_run, container_age_days=args.age)

    print("=" * 60)
    print("DOCKER CLEANER PRO")
    print(f"Mode: {'DRY-RUN (simulation)' if dry_run else 'FORCE (suppression réelle)'}")
    print("=" * 60)

    try:
        # Verify Docker connection
        cleaner.client.ping()
        logger.info("Docker daemon connected successfully")
    except Exception as e:
        logger.error(f"Cannot connect to Docker daemon: {e}")
        return 1

    try:
        # Perform cleanup
        if clean_images:
            cleaner.clean_dangling_images()

        if clean_containers:
            cleaner.clean_stopped_containers()

        if clean_volumes:
            cleaner.clean_orphan_volumes()

        if clean_networks:
            cleaner.clean_unused_networks()

        # Print summary
        cleaner.print_summary()
        return 0

    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        return 130

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
```

---

## Utilisation

### Mode Dry-Run (Défaut)

```bash
# Afficher ce qui serait supprimé (aucune action)
python3 docker_cleaner_pro.py

# Dry-run sur un type spécifique
python3 docker_cleaner_pro.py --images
python3 docker_cleaner_pro.py --containers
```

### Mode Force (Suppression Réelle)

```bash
# Nettoyer toutes les ressources
python3 docker_cleaner_pro.py --all --force

# Nettoyer uniquement les images dangling
python3 docker_cleaner_pro.py --images --force

# Nettoyer les conteneurs stoppés depuis plus de 30 jours
python3 docker_cleaner_pro.py --containers --age 30 --force
```

### Options Combinées

```bash
# Images + Volumes uniquement
python3 docker_cleaner_pro.py -i -v --force

# Tout sauf les réseaux
python3 docker_cleaner_pro.py -i -c -v --force

# Mode verbeux pour debug
python3 docker_cleaner_pro.py --all --verbose
```

---

## Exemple de Sortie

### Mode Dry-Run

```
============================================================
DOCKER CLEANER PRO
Mode: DRY-RUN (simulation)
============================================================
2024-01-15 14:30:00 - INFO - Docker daemon connected successfully
2024-01-15 14:30:00 - INFO - Scanning for dangling images...
2024-01-15 14:30:01 - INFO -   [DRY-RUN] Would remove: sha256:a1b2 (256.00 MB)
2024-01-15 14:30:01 - INFO -   [DRY-RUN] Would remove: sha256:c3d4 (128.00 MB)
2024-01-15 14:30:01 - INFO - Scanning for stopped containers (older than 7 days)...
2024-01-15 14:30:01 - INFO -   [DRY-RUN] Would remove: abc123 (old_app_1)
2024-01-15 14:30:02 - INFO - Scanning for orphan volumes...
2024-01-15 14:30:02 - INFO -   [DRY-RUN] Would remove: myapp_data_old
2024-01-15 14:30:02 - INFO - Scanning for unused networks...

============================================================
CLEANUP SUMMARY
(DRY-RUN MODE - Nothing was actually removed)
============================================================

Dangling Images:
  Count: 2
  Space: 384.00 MB

Stopped Containers (>7 days):
  Count: 1

Orphan Volumes:
  Count: 1

Total space to be reclaimed: 384.00 MB

[!] To actually perform cleanup, run with --force
============================================================
```

---

## Comparaison avec docker system prune

| Fonctionnalité | docker system prune | docker_cleaner_pro.py |
|----------------|--------------------|-----------------------|
| Mode dry-run par défaut | Non | **Oui** |
| Filtre par âge | Non | **Oui** |
| Sélection granulaire | Limité | **Complet** |
| Rapport d'espace récupéré | Basique | **Détaillé** |
| Confirmation requise | -f pour skipper | --force pour exécuter |

---

## Arguments

| Argument | Description |
|----------|-------------|
| `-i`, `--images` | Nettoyer les images dangling (non taguées) |
| `-c`, `--containers` | Nettoyer les conteneurs stoppés |
| `-v`, `--volumes` | Nettoyer les volumes orphelins |
| `-n`, `--networks` | Nettoyer les réseaux inutilisés |
| `-a`, `--all` | Nettoyer toutes les ressources |
| `--age DAYS` | Âge minimum des conteneurs stoppés (défaut: 7) |
| `-f`, `--force` | Effectuer les suppressions (désactive dry-run) |
| `--verbose` | Mode verbeux avec détails de debug |

---

!!! warning "Précautions"
    - Toujours exécuter en mode dry-run d'abord pour vérifier ce qui sera supprimé
    - Les volumes supprimés sont **irrécupérables** - assurez-vous d'avoir des backups
    - Le script ne supprime jamais les réseaux protégés (`bridge`, `host`, `none`)

!!! tip "Intégration CI/CD"
    Ce script est idéal pour les pipelines CI/CD :
    ```yaml
    # GitLab CI example
    cleanup_docker:
      script:
        - python3 docker_cleaner_pro.py --all --age 3 --force
      only:
        - schedules  # Run weekly
    ```

---

## Voir Aussi

- [kubernetes_health.py](kubernetes_health.md) - Vérification santé cluster Kubernetes
- [docker_health.py](docker_health.md) - Vérification santé Docker
- [Scripts Bash - Container Network Debug](../bash/container-net-debug.md)
