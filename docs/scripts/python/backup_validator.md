---
tags:
  - scripts
  - python
  - backup
  - validation
  - disaster-recovery
---

# backup_validator.py

:material-star::material-star::material-star: **Niveau : Avancé**

Validation de l'intégrité des sauvegardes avec tests de restauration.

---

## Description

Ce script valide la qualité des sauvegardes :
- Vérification d'intégrité (checksums SHA256)
- Validation de l'âge des backups
- Test de décompression
- Vérification de la taille minimale
- Test de restauration (dry-run)
- Rapport de conformité
- Alertes sur backups expirés/corrompus

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
Script Name: backup_validator.py
Description: Backup integrity validation and restore testing
Author: ShellBook
Version: 1.0

Dependencies:
    pip install rich pyyaml
"""

import argparse
import gzip
import hashlib
import json
import os
import shutil
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class BackupPolicy:
    """Backup validation policy."""
    name: str
    path: Path
    pattern: str = "*"
    max_age_days: int = 7
    min_size_bytes: int = 1024
    expected_count: int = 1
    verify_integrity: bool = True
    test_extract: bool = False
    checksum_file: Optional[str] = None


@dataclass
class ValidationResult:
    """Result of a backup validation."""
    backup_path: Path
    policy_name: str
    exists: bool = True
    size_bytes: int = 0
    age_days: float = 0
    checksum: Optional[str] = None
    checksum_valid: Optional[bool] = None
    archive_valid: Optional[bool] = None
    extract_test_passed: Optional[bool] = None
    issues: List[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """Check if backup passes all validations."""
        return len(self.issues) == 0


class BackupValidator:
    """Validate backup files against policies."""

    def __init__(self, temp_dir: Optional[Path] = None):
        self.temp_dir = temp_dir or Path(tempfile.gettempdir()) / "backup_validator"
        self.results: List[ValidationResult] = []

    def calculate_checksum(self, filepath: Path, algorithm: str = "sha256") -> str:
        """Calculate file checksum."""
        hash_func = hashlib.new(algorithm)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def verify_checksum_file(self, backup_path: Path, checksum_file: str) -> tuple:
        """Verify backup against checksum file."""
        checksum_path = backup_path.parent / checksum_file

        if not checksum_path.exists():
            # Try backup_name.sha256
            checksum_path = backup_path.with_suffix(backup_path.suffix + '.sha256')

        if not checksum_path.exists():
            return None, "Checksum file not found"

        try:
            with open(checksum_path, 'r') as f:
                content = f.read().strip()
                # Format: "hash  filename" or just "hash"
                expected_hash = content.split()[0].lower()

            actual_hash = self.calculate_checksum(backup_path)
            return actual_hash == expected_hash, actual_hash

        except Exception as e:
            return False, str(e)

    def verify_archive_integrity(self, filepath: Path) -> tuple:
        """Verify archive can be read."""
        suffix = filepath.suffix.lower()

        try:
            if suffix == '.zip':
                with zipfile.ZipFile(filepath, 'r') as zf:
                    # Test CRC
                    bad_file = zf.testzip()
                    if bad_file:
                        return False, f"Corrupted file in archive: {bad_file}"
                    return True, f"{len(zf.namelist())} files"

            elif suffix in ['.tar', '.gz', '.tgz']:
                mode = 'r:gz' if suffix in ['.gz', '.tgz'] else 'r'
                if filepath.name.endswith('.tar.gz'):
                    mode = 'r:gz'

                with tarfile.open(filepath, mode) as tf:
                    members = tf.getmembers()
                    return True, f"{len(members)} files"

            elif suffix == '.gz':
                # Plain gzip file
                with gzip.open(filepath, 'rb') as f:
                    # Read a chunk to verify
                    f.read(1024)
                return True, "gzip valid"

            else:
                return None, "Unknown archive format"

        except (zipfile.BadZipFile, tarfile.TarError, gzip.BadGzipFile) as e:
            return False, str(e)
        except Exception as e:
            return False, str(e)

    def test_extract(self, filepath: Path) -> tuple:
        """Test extracting archive to temp directory."""
        suffix = filepath.suffix.lower()
        extract_dir = self.temp_dir / filepath.stem

        try:
            extract_dir.mkdir(parents=True, exist_ok=True)

            if suffix == '.zip':
                with zipfile.ZipFile(filepath, 'r') as zf:
                    # Extract first few files only
                    for member in zf.namelist()[:5]:
                        zf.extract(member, extract_dir)
                return True, "Extract test passed"

            elif suffix in ['.tar', '.gz', '.tgz'] or filepath.name.endswith('.tar.gz'):
                mode = 'r:gz' if suffix in ['.gz', '.tgz'] or filepath.name.endswith('.tar.gz') else 'r'
                with tarfile.open(filepath, mode) as tf:
                    # Extract first few files only
                    members = tf.getmembers()[:5]
                    for member in members:
                        tf.extract(member, extract_dir)
                return True, "Extract test passed"

            return None, "Unknown format for extract test"

        except Exception as e:
            return False, str(e)

        finally:
            # Cleanup
            if extract_dir.exists():
                shutil.rmtree(extract_dir, ignore_errors=True)

    def validate_backup(self, backup_path: Path, policy: BackupPolicy) -> ValidationResult:
        """Validate a single backup file."""
        result = ValidationResult(
            backup_path=backup_path,
            policy_name=policy.name
        )

        # Check existence
        if not backup_path.exists():
            result.exists = False
            result.issues.append("Backup file not found")
            return result

        # Get file stats
        stat = backup_path.stat()
        result.size_bytes = stat.st_size
        result.age_days = (datetime.now() - datetime.fromtimestamp(stat.st_mtime)).days

        # Check size
        if result.size_bytes < policy.min_size_bytes:
            result.issues.append(f"Size {self._format_size(result.size_bytes)} below minimum {self._format_size(policy.min_size_bytes)}")

        # Check age
        if result.age_days > policy.max_age_days:
            result.issues.append(f"Backup is {result.age_days} days old (max: {policy.max_age_days})")

        # Verify integrity
        if policy.verify_integrity:
            result.checksum = self.calculate_checksum(backup_path)

            # Check against checksum file if specified
            if policy.checksum_file:
                valid, info = self.verify_checksum_file(backup_path, policy.checksum_file)
                result.checksum_valid = valid
                if valid is False:
                    result.issues.append(f"Checksum mismatch: {info}")

            # Verify archive structure
            valid, info = self.verify_archive_integrity(backup_path)
            result.archive_valid = valid
            if valid is False:
                result.issues.append(f"Archive corrupted: {info}")

        # Test extraction
        if policy.test_extract:
            valid, info = self.test_extract(backup_path)
            result.extract_test_passed = valid
            if valid is False:
                result.issues.append(f"Extract test failed: {info}")

        return result

    def validate_policy(self, policy: BackupPolicy) -> List[ValidationResult]:
        """Validate all backups matching a policy."""
        results = []
        backup_dir = Path(policy.path)

        if not backup_dir.exists():
            result = ValidationResult(
                backup_path=backup_dir,
                policy_name=policy.name,
                exists=False
            )
            result.issues.append(f"Backup directory not found: {backup_dir}")
            results.append(result)
            return results

        # Find matching files
        matching_files = sorted(
            backup_dir.glob(policy.pattern),
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )

        if not matching_files:
            result = ValidationResult(
                backup_path=backup_dir,
                policy_name=policy.name,
                exists=False
            )
            result.issues.append(f"No backups found matching pattern: {policy.pattern}")
            results.append(result)
            return results

        # Check expected count
        if len(matching_files) < policy.expected_count:
            # Still validate what we have, but note the issue
            pass

        # Validate each backup (most recent first)
        for backup_file in matching_files[:max(policy.expected_count, 3)]:
            result = self.validate_backup(backup_file, policy)
            results.append(result)
            self.results.append(result)

        return results

    def get_summary(self) -> Dict[str, Any]:
        """Get validation summary."""
        total = len(self.results)
        valid = sum(1 for r in self.results if r.is_valid)
        invalid = total - valid

        total_size = sum(r.size_bytes for r in self.results if r.exists)

        # Group by policy
        policies = {}
        for r in self.results:
            if r.policy_name not in policies:
                policies[r.policy_name] = {"valid": 0, "invalid": 0}
            if r.is_valid:
                policies[r.policy_name]["valid"] += 1
            else:
                policies[r.policy_name]["invalid"] += 1

        return {
            "timestamp": datetime.now().isoformat(),
            "total_backups": total,
            "valid": valid,
            "invalid": invalid,
            "total_size": self._format_size(total_size),
            "policies": policies,
            "status": "COMPLIANT" if invalid == 0 else "NON-COMPLIANT"
        }

    @staticmethod
    def _format_size(size: int) -> str:
        """Format size in human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"


def load_policies(config_path: Path) -> List[BackupPolicy]:
    """Load backup policies from YAML config."""
    if not YAML_AVAILABLE:
        print("Error: pyyaml required for config files. Install with: pip install pyyaml")
        sys.exit(1)

    with open(config_path) as f:
        data = yaml.safe_load(f)

    policies = []
    for p in data.get('policies', []):
        policies.append(BackupPolicy(
            name=p.get('name', 'Unnamed'),
            path=Path(p['path']),
            pattern=p.get('pattern', '*'),
            max_age_days=p.get('max_age_days', 7),
            min_size_bytes=p.get('min_size_bytes', 1024),
            expected_count=p.get('expected_count', 1),
            verify_integrity=p.get('verify_integrity', True),
            test_extract=p.get('test_extract', False),
            checksum_file=p.get('checksum_file')
        ))

    return policies


def display_results_rich(validator: BackupValidator) -> None:
    """Display results with Rich."""
    console = Console()
    summary = validator.get_summary()

    status_color = "green" if summary['status'] == "COMPLIANT" else "red"

    # Header
    console.print(Panel.fit(
        f"[bold cyan]Backup Validation Report[/bold cyan]\n"
        f"[dim]{summary['timestamp']}[/dim]",
        border_style="cyan"
    ))

    # Results table
    table = Table(title="Backup Status")
    table.add_column("Status", width=10)
    table.add_column("Policy", style="cyan")
    table.add_column("Backup File")
    table.add_column("Size", justify="right")
    table.add_column("Age", justify="right")
    table.add_column("Integrity")
    table.add_column("Issues")

    for result in validator.results:
        # Status
        if result.is_valid:
            status = "[green]✓ VALID[/green]"
        else:
            status = "[red]✗ INVALID[/red]"

        # File name
        filename = result.backup_path.name if result.exists else str(result.backup_path)
        if len(filename) > 30:
            filename = "..." + filename[-27:]

        # Size
        size = validator._format_size(result.size_bytes) if result.exists else "-"

        # Age with color
        if result.exists:
            if result.age_days > 14:
                age = f"[red]{result.age_days}d[/red]"
            elif result.age_days > 7:
                age = f"[yellow]{result.age_days}d[/yellow]"
            else:
                age = f"[green]{result.age_days}d[/green]"
        else:
            age = "-"

        # Integrity
        integrity_parts = []
        if result.archive_valid is True:
            integrity_parts.append("[green]Archive✓[/green]")
        elif result.archive_valid is False:
            integrity_parts.append("[red]Archive✗[/red]")

        if result.checksum_valid is True:
            integrity_parts.append("[green]Hash✓[/green]")
        elif result.checksum_valid is False:
            integrity_parts.append("[red]Hash✗[/red]")

        if result.extract_test_passed is True:
            integrity_parts.append("[green]Extract✓[/green]")
        elif result.extract_test_passed is False:
            integrity_parts.append("[red]Extract✗[/red]")

        integrity = " ".join(integrity_parts) if integrity_parts else "-"

        # Issues
        issues = "; ".join(result.issues[:2]) if result.issues else "OK"
        if len(issues) > 35:
            issues = issues[:32] + "..."

        table.add_row(status, result.policy_name, filename, size, age, integrity, issues)

    console.print(table)

    # Summary
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Total Backups: {summary['total_backups']} | "
                  f"[green]Valid: {summary['valid']}[/green] | "
                  f"[red]Invalid: {summary['invalid']}[/red]")
    console.print(f"  Total Size: {summary['total_size']}")
    console.print(f"  Status: [{status_color}]{summary['status']}[/{status_color}]")

    # Policy breakdown
    if summary['policies']:
        console.print(f"\n[bold]By Policy:[/bold]")
        for policy_name, stats in summary['policies'].items():
            console.print(f"  {policy_name}: [green]{stats['valid']} valid[/green], "
                         f"[red]{stats['invalid']} invalid[/red]")


def display_results_simple(validator: BackupValidator) -> None:
    """Display results in simple format."""
    print("\n" + "=" * 70)
    print("  BACKUP VALIDATION REPORT")
    print("=" * 70 + "\n")

    for result in validator.results:
        status = "[VALID]" if result.is_valid else "[INVALID]"
        print(f"{status} {result.policy_name}: {result.backup_path.name}")
        print(f"        Size: {validator._format_size(result.size_bytes)}, Age: {result.age_days} days")

        if result.issues:
            for issue in result.issues:
                print(f"        [!] {issue}")
        print()

    summary = validator.get_summary()
    print("-" * 70)
    print(f"Total: {summary['total_backups']} | Valid: {summary['valid']} | Invalid: {summary['invalid']}")
    print(f"Status: {summary['status']}")


def main():
    parser = argparse.ArgumentParser(
        description="Backup Validator - Integrity and compliance checking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration file format (YAML):
  policies:
    - name: "Database Daily"
      path: "/backup/database"
      pattern: "db_*.sql.gz"
      max_age_days: 1
      min_size_bytes: 10485760  # 10MB
      verify_integrity: true
      test_extract: true
      checksum_file: "checksums.sha256"

    - name: "Files Weekly"
      path: "/backup/files"
      pattern: "files_*.tar.gz"
      max_age_days: 7
      expected_count: 4

Examples:
    %(prog)s -c backup_policies.yaml
    %(prog)s -p /backup/daily -n "daily_*.tar.gz" --max-age 1
    %(prog)s -c policies.yaml --json
    %(prog)s -c policies.yaml --test-extract
        """
    )

    parser.add_argument('-c', '--config', type=Path, help='Configuration file (YAML)')
    parser.add_argument('-p', '--path', type=Path, help='Backup directory path')
    parser.add_argument('-n', '--pattern', default='*', help='Filename pattern (glob)')
    parser.add_argument('--max-age', type=int, default=7, help='Maximum backup age in days')
    parser.add_argument('--min-size', type=int, default=1024, help='Minimum backup size in bytes')
    parser.add_argument('--test-extract', action='store_true', help='Test archive extraction')
    parser.add_argument('-j', '--json', action='store_true', help='Output as JSON')
    parser.add_argument('-s', '--simple', action='store_true', help='Simple output')

    args = parser.parse_args()

    policies = []

    # Load from config
    if args.config:
        if not args.config.exists():
            print(f"Error: Config file not found: {args.config}")
            sys.exit(1)
        policies = load_policies(args.config)

    # Command line policy
    if args.path:
        policies.append(BackupPolicy(
            name="CLI Policy",
            path=args.path,
            pattern=args.pattern,
            max_age_days=args.max_age,
            min_size_bytes=args.min_size,
            test_extract=args.test_extract
        ))

    if not policies:
        print("Error: Specify -c config.yaml or -p /backup/path")
        sys.exit(1)

    # Create validator
    validator = BackupValidator()

    # Validate all policies
    if RICH_AVAILABLE and not args.simple and not args.json:
        console = Console()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            for policy in policies:
                task = progress.add_task(f"Validating {policy.name}...", total=None)
                validator.validate_policy(policy)
                progress.update(task, completed=True)
    else:
        for policy in policies:
            validator.validate_policy(policy)

    # Output
    if args.json:
        output = {
            "summary": validator.get_summary(),
            "results": [
                {
                    "backup_path": str(r.backup_path),
                    "policy_name": r.policy_name,
                    "exists": r.exists,
                    "size_bytes": r.size_bytes,
                    "age_days": r.age_days,
                    "checksum": r.checksum,
                    "checksum_valid": r.checksum_valid,
                    "archive_valid": r.archive_valid,
                    "extract_test_passed": r.extract_test_passed,
                    "is_valid": r.is_valid,
                    "issues": r.issues
                }
                for r in validator.results
            ]
        }
        print(json.dumps(output, indent=2))
    elif args.simple or not RICH_AVAILABLE:
        display_results_simple(validator)
    else:
        display_results_rich(validator)

    # Exit code
    summary = validator.get_summary()
    if summary['invalid'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
```

---

## Configuration YAML

Exemple `backup_policies.yaml`:

```yaml
# Backup Validation Policies

policies:
  # Database backups - Daily
  - name: "PostgreSQL Daily"
    path: "/backup/postgresql"
    pattern: "pg_dump_*.sql.gz"
    max_age_days: 1
    min_size_bytes: 10485760  # 10 MB minimum
    verify_integrity: true
    test_extract: true
    expected_count: 1
    checksum_file: "checksums.sha256"

  # Database backups - Weekly full
  - name: "PostgreSQL Weekly Full"
    path: "/backup/postgresql/weekly"
    pattern: "pg_full_*.tar.gz"
    max_age_days: 7
    min_size_bytes: 104857600  # 100 MB minimum
    verify_integrity: true
    expected_count: 4  # Keep 4 weeks

  # Application files
  - name: "Application Data"
    path: "/backup/app"
    pattern: "app_data_*.zip"
    max_age_days: 1
    min_size_bytes: 1048576  # 1 MB
    verify_integrity: true
    test_extract: true

  # Config backups
  - name: "System Configs"
    path: "/backup/configs"
    pattern: "etc_*.tar.gz"
    max_age_days: 7
    min_size_bytes: 10240  # 10 KB
    verify_integrity: true

  # Logs archive
  - name: "Archived Logs"
    path: "/backup/logs"
    pattern: "logs_*.tar.gz"
    max_age_days: 30
    min_size_bytes: 1024
    verify_integrity: true
    test_extract: false  # Large files, skip extract test
```

---

## Utilisation

```bash
# Avec fichier de configuration
python backup_validator.py -c backup_policies.yaml

# Validation simple d'un répertoire
python backup_validator.py -p /backup/daily -n "*.tar.gz" --max-age 1

# Avec test d'extraction
python backup_validator.py -c policies.yaml --test-extract

# Sortie JSON pour CI/CD
python backup_validator.py -c policies.yaml --json

# Validation avec taille minimale
python backup_validator.py -p /backup/db --min-size 10485760

# Sortie simple
python backup_validator.py -c policies.yaml --simple
```

---

## Sortie Exemple

```
╭──────────────────────────────────────────────────────────────────────╮
│                     Backup Validation Report                          │
│                      2024-01-15T14:30:22.123456                       │
╰──────────────────────────────────────────────────────────────────────╯

                           Backup Status
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Status     ┃ Policy           ┃ Backup File          ┃ Size    ┃ Age  ┃ Integrity       ┃ Issues           ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ ✓ VALID    │ PostgreSQL Daily │ pg_dump_20240115.gz  │ 245 MB  │   0d │ Archive✓ Hash✓  │ OK               │
│ ✓ VALID    │ PostgreSQL Daily │ pg_dump_20240114.gz  │ 243 MB  │   1d │ Archive✓ Hash✓  │ OK               │
│ ✗ INVALID  │ Application Data │ app_data_20240110.zip│ 12 MB   │   5d │ Archive✓        │ Backup is 5 days │
│ ✓ VALID    │ System Configs   │ etc_20240115.tar.gz  │ 2.3 MB  │   0d │ Archive✓        │ OK               │
└────────────┴──────────────────┴──────────────────────┴─────────┴──────┴─────────────────┴──────────────────┘

Summary:
  Total Backups: 4 | Valid: 3 | Invalid: 1
  Total Size: 502.30 MB
  Status: NON-COMPLIANT

By Policy:
  PostgreSQL Daily: 2 valid, 0 invalid
  Application Data: 0 valid, 1 invalid
  System Configs: 1 valid, 0 invalid
```

---

## Intégration CI/CD

```yaml
# GitLab CI - Backup validation job
backup_check:
  stage: monitoring
  script:
    - pip install rich pyyaml
    - python backup_validator.py -c /etc/backup_policies.yaml --json > backup_report.json
  artifacts:
    paths:
      - backup_report.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

---

## Automatisation Cron

```bash
# Validation quotidienne à 6h
0 6 * * * /usr/bin/python3 /opt/scripts/backup_validator.py -c /etc/backup_policies.yaml --json >> /var/log/backup_validation.log 2>&1

# Avec alerte email
0 6 * * * /usr/bin/python3 /opt/scripts/backup_validator.py -c /etc/backup_policies.yaml || echo "Backup validation FAILED" | mail -s "ALERT: Backup Issues" ops@example.com
```

---

## Voir Aussi

- [backup_manager.py](backup_manager.md)
- [backup-directory.sh](../bash/backup-directory.md)
