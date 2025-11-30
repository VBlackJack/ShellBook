---
tags:
  - scripts
  - python
  - backup
  - fichiers
---

# backup_manager.py

:material-star::material-star: **Niveau : Intermédiaire**

Gestion des sauvegardes avec rotation et compression.

---

## Description

Ce script gère les sauvegardes :
- Compression ZIP ou tar.gz
- Rotation automatique
- Exclusions configurables
- Vérification d'intégrité
- Logging détaillé

---

## Dépendances

```bash
pip install rich pyyaml
```

---

## Script

```python
#!/usr/bin/env python3
"""
Script Name: backup_manager.py
Description: Gestion des sauvegardes avec rotation
Author: ShellBook
Version: 1.0

Dependencies:
    pip install rich pyyaml (optional)
"""

import argparse
import hashlib
import logging
import os
import shutil
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

try:
    from rich.console import Console
    from rich.progress import track
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class BackupResult:
    """Résultat d'une sauvegarde."""
    source: Path
    destination: Path
    size_original: int
    size_compressed: int
    duration: float
    success: bool
    checksum: Optional[str] = None
    error: Optional[str] = None


class BackupManager:
    """Gestionnaire de sauvegardes."""

    def __init__(
        self,
        source: Path,
        destination: Path,
        format: str = "zip",
        keep: int = 7,
        exclude: Optional[List[str]] = None
    ):
        self.source = Path(source)
        self.destination = Path(destination)
        self.format = format
        self.keep = keep
        self.exclude = exclude or []

        # Validation
        if not self.source.exists():
            raise ValueError(f"Source does not exist: {self.source}")

        # Créer le répertoire destination
        self.destination.mkdir(parents=True, exist_ok=True)

    def _should_exclude(self, path: Path) -> bool:
        """Check si un chemin doit être exclu."""
        path_str = str(path)
        for pattern in self.exclude:
            if pattern in path_str:
                return True
            if path.match(pattern):
                return True
        return False

    def _get_backup_name(self) -> str:
        """Génère le nom du fichier de sauvegarde."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        source_name = self.source.name
        extension = "zip" if self.format == "zip" else "tar.gz"
        return f"{source_name}_{timestamp}.{extension}"

    def _calculate_checksum(self, filepath: Path) -> str:
        """Calcule le checksum SHA256 d'un fichier."""
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def _get_directory_size(self, path: Path) -> int:
        """Calcule la taille totale d'un répertoire."""
        total = 0
        for entry in path.rglob('*'):
            if entry.is_file() and not self._should_exclude(entry):
                total += entry.stat().st_size
        return total

    def _create_zip(self, backup_path: Path) -> None:
        """Crée une archive ZIP."""
        with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in self.source.rglob('*'):
                if file_path.is_file() and not self._should_exclude(file_path):
                    arcname = file_path.relative_to(self.source)
                    zipf.write(file_path, arcname)

    def _create_targz(self, backup_path: Path) -> None:
        """Crée une archive tar.gz."""
        with tarfile.open(backup_path, "w:gz") as tar:
            for file_path in self.source.rglob('*'):
                if not self._should_exclude(file_path):
                    arcname = file_path.relative_to(self.source)
                    tar.add(file_path, arcname)

    def _verify_archive(self, backup_path: Path) -> bool:
        """Check l'intégrité de l'archive."""
        try:
            if self.format == "zip":
                with zipfile.ZipFile(backup_path, 'r') as zipf:
                    result = zipf.testzip()
                    return result is None
            else:
                with tarfile.open(backup_path, 'r:gz') as tar:
                    tar.getmembers()
                    return True
        except Exception:
            return False

    def _rotate_backups(self) -> int:
        """Supprime les anciennes sauvegardes."""
        pattern = f"{self.source.name}_*"
        backups = sorted(
            self.destination.glob(pattern),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )

        deleted = 0
        for backup in backups[self.keep:]:
            logger.info(f"Removing old backup: {backup.name}")
            backup.unlink()
            deleted += 1

        return deleted

    def create_backup(self, verify: bool = False) -> BackupResult:
        """Crée une sauvegarde."""
        backup_name = self._get_backup_name()
        backup_path = self.destination / backup_name

        logger.info(f"Starting backup: {self.source} -> {backup_path}")

        start_time = datetime.now()
        size_original = self._get_directory_size(self.source)

        try:
            if self.format == "zip":
                self._create_zip(backup_path)
            else:
                self._create_targz(backup_path)

            duration = (datetime.now() - start_time).total_seconds()
            size_compressed = backup_path.stat().st_size

            # Check optionnelle
            checksum = None
            if verify:
                logger.info("Verifying archive integrity...")
                if not self._verify_archive(backup_path):
                    raise Exception("Archive verification failed")
                checksum = self._calculate_checksum(backup_path)
                logger.info(f"Checksum: {checksum}")

            # Rotation
            deleted = self._rotate_backups()
            if deleted > 0:
                logger.info(f"Rotated {deleted} old backup(s)")

            result = BackupResult(
                source=self.source,
                destination=backup_path,
                size_original=size_original,
                size_compressed=size_compressed,
                duration=duration,
                success=True,
                checksum=checksum
            )

            logger.info(f"Backup completed: {backup_name}")
            logger.info(f"Size: {self._format_size(size_compressed)} "
                        f"({self._compression_ratio(size_original, size_compressed)})")

            return result

        except Exception as e:
            logger.error(f"Backup failed: {e}")

            # Nettoyer le fichier partiel
            if backup_path.exists():
                backup_path.unlink()

            return BackupResult(
                source=self.source,
                destination=backup_path,
                size_original=size_original,
                size_compressed=0,
                duration=(datetime.now() - start_time).total_seconds(),
                success=False,
                error=str(e)
            )

    def list_backups(self) -> List[dict]:
        """Liste les sauvegardes existantes."""
        pattern = f"{self.source.name}_*"
        backups = []

        for backup in sorted(self.destination.glob(pattern),
                            key=lambda x: x.stat().st_mtime, reverse=True):
            stat = backup.stat()
            age = datetime.now() - datetime.fromtimestamp(stat.st_mtime)

            backups.append({
                "name": backup.name,
                "path": backup,
                "size": stat.st_size,
                "size_formatted": self._format_size(stat.st_size),
                "created": datetime.fromtimestamp(stat.st_mtime),
                "age": str(age).split('.')[0]
            })

        return backups

    @staticmethod
    def _format_size(size: int) -> str:
        """Formate une taille en bytes."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    @staticmethod
    def _compression_ratio(original: int, compressed: int) -> str:
        """Calcule le ratio de compression."""
        if original == 0:
            return "N/A"
        ratio = (compressed / original) * 100
        return f"{ratio:.1f}% of original"


def display_results(result: BackupResult, backups: List[dict]) -> None:
    """Display les résultats."""
    if RICH_AVAILABLE:
        console = Console()

        if result.success:
            console.print(f"\n[green]✓ Backup completed successfully![/green]")
        else:
            console.print(f"\n[red]✗ Backup failed: {result.error}[/red]")
            return

        console.print(f"\n[cyan]Backup Details:[/cyan]")
        console.print(f"  Source: {result.source}")
        console.print(f"  Destination: {result.destination}")
        console.print(f"  Original Size: {BackupManager._format_size(result.size_original)}")
        console.print(f"  Compressed Size: {BackupManager._format_size(result.size_compressed)} "
                      f"({BackupManager._compression_ratio(result.size_original, result.size_compressed)})")
        console.print(f"  Duration: {result.duration:.1f}s")
        if result.checksum:
            console.print(f"  Checksum: {result.checksum[:16]}...")

        console.print(f"\n[cyan]Available Backups:[/cyan]")
        for backup in backups:
            console.print(f"  {backup['name']} ({backup['size_formatted']}) - {backup['age']} ago")

    else:
        if result.success:
            print(f"\n✓ Backup completed: {result.destination.name}")
            print(f"  Size: {BackupManager._format_size(result.size_compressed)}")
            print(f"  Duration: {result.duration:.1f}s")
        else:
            print(f"\n✗ Backup failed: {result.error}")


def main():
    parser = argparse.ArgumentParser(
        description="Backup Manager - Directory backup with rotation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    %(prog)s /home/user/data /backup
    %(prog)s -f tar.gz -k 14 /var/www /backup/www
    %(prog)s --exclude "*.log" --exclude "cache" /app /backup
        """
    )

    parser.add_argument('source', type=Path, help='Source directory')
    parser.add_argument('destination', type=Path, help='Backup destination')
    parser.add_argument('-f', '--format', choices=['zip', 'tar.gz'],
                        default='zip', help='Archive format')
    parser.add_argument('-k', '--keep', type=int, default=7,
                        help='Number of backups to keep')
    parser.add_argument('-e', '--exclude', action='append', default=[],
                        help='Patterns to exclude')
    parser.add_argument('-v', '--verify', action='store_true',
                        help='Verify archive after creation')
    parser.add_argument('-l', '--list', action='store_true',
                        help='List existing backups only')

    args = parser.parse_args()

    try:
        manager = BackupManager(
            source=args.source,
            destination=args.destination,
            format=args.format,
            keep=args.keep,
            exclude=args.exclude
        )

        if args.list:
            backups = manager.list_backups()
            print(f"\nBackups for {args.source.name}:")
            for backup in backups:
                print(f"  {backup['name']} ({backup['size_formatted']}) - {backup['age']} ago")
            return

        result = manager.create_backup(verify=args.verify)
        backups = manager.list_backups()

        display_results(result, backups)

        sys.exit(0 if result.success else 1)

    except Exception as e:
        logger.error(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
```

---

## Utilisation

```bash
# Backup simple
python backup_manager.py /home/user/data /backup

# Format tar.gz avec vérification
python backup_manager.py -f tar.gz -v /var/www /backup/www

# Avec exclusions
python backup_manager.py -e "*.log" -e "cache" -e "node_modules" /app /backup

# Conserver 14 sauvegardes
python backup_manager.py -k 14 /data /backup

# Lister les sauvegardes existantes
python backup_manager.py -l /data /backup
```

---

## Sortie Exemple

```
2024-01-15 14:30:22 - INFO - Starting backup: /home/user/data -> /backup/data_20240115_143022.zip
2024-01-15 14:31:15 - INFO - Verifying archive integrity...
2024-01-15 14:31:18 - INFO - Checksum: a1b2c3d4e5f6...
2024-01-15 14:31:18 - INFO - Rotated 1 old backup(s)
2024-01-15 14:31:18 - INFO - Backup completed: data_20240115_143022.zip
2024-01-15 14:31:18 - INFO - Size: 512.34 MB (35.2% of original)

✓ Backup completed successfully!

Backup Details:
  Source: /home/user/data
  Destination: /backup/data_20240115_143022.zip
  Original Size: 1.45 GB
  Compressed Size: 512.34 MB (35.2% of original)
  Duration: 53.2s
  Checksum: a1b2c3d4e5f6...

Available Backups:
  data_20240115_143022.zip (512.34 MB) - 0:00:00 ago
  data_20240114_143022.zip (508.12 MB) - 1 day, 0:00:00 ago
  data_20240113_143022.zip (505.89 MB) - 2 days, 0:00:00 ago
```

---

## Automatisation Cron

```bash
# Backup quotidien à 2h du matin
0 2 * * * /usr/bin/python3 /opt/scripts/backup_manager.py -v /var/www /backup/www >> /var/log/backup.log 2>&1

# Backup hebdomadaire avec plus de rétention
0 3 * * 0 /usr/bin/python3 /opt/scripts/backup_manager.py -k 4 /home /backup/home >> /var/log/backup.log 2>&1
```

---

## Voir Aussi

- [backup_validator.py](backup_validator.md) - Validation intégrité backups
- [git_repo_cleaner.py](git_repo_cleaner.md) - Nettoyage branches Git
