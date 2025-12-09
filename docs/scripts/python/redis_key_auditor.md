---
tags:
  - scripts
  - python
  - redis
  - database
  - audit
---

# redis_key_auditor.py

Outil d'analyse des patterns de clés et de la consommation mémoire Redis sans bloquer le serveur.

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | Python 3.8+ |
| **Catégorie** | Base de données / Audit |
| **Niveau** | :material-star::material-star: Intermédiaire |
| **Dépendances** | `redis` (redis-py) |

---

## Description

Ce script analyse les clés stockées dans Redis en utilisant la commande `SCAN` (itérative et non-bloquante) pour éviter de bloquer le serveur. Il regroupe les clés par préfixe et fournit des statistiques de mémoire détaillées.

**Fonctionnalités :**

- **Scan non-bloquant** : Utilise `SCAN` au lieu de `KEYS *` (jamais en production !)
- **Groupement par préfixe** : Agrège les clés par pattern (ex: `session:*`, `cache:*`)
- **Analyse mémoire** : Utilise `MEMORY USAGE` pour l'estimation précise
- **Séparateur configurable** : Supporte différentes conventions de nommage
- **Export CSV** : Génère un rapport exportable

---

## Prérequis

```bash
# Installation de redis-py
pip install redis

# Vérifier la connectivité Redis
redis-cli ping
```

---

!!! danger "Ne JAMAIS utiliser KEYS * en Production"
    La commande `KEYS *` parcourt **toutes les clés** en une seule opération bloquante.

    Sur une instance avec des millions de clés :

    - **Blocage complet** du serveur Redis pendant l'exécution
    - Latence de plusieurs secondes voire minutes
    - Impact sur toutes les applications connectées

    Ce script utilise `SCAN` qui itère par petits lots sans bloquer.

---

## Script

```python
#!/usr/bin/env python3
"""
Script Name: redis_key_auditor.py
Description: Analyze Redis key patterns and memory usage without blocking
Author: ShellBook
Version: 1.0
"""

import argparse
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional, Tuple

try:
    import redis
    from redis.exceptions import ConnectionError, ResponseError
except ImportError:
    print("Error: redis package not installed. Run: pip install redis")
    sys.exit(1)

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class KeyStats:
    """
    Statistics for a key pattern group.
    """
    count: int = 0
    total_memory: int = 0
    sample_keys: List[str] = field(default_factory=list)
    ttl_set: int = 0
    ttl_none: int = 0


class RedisKeyAuditor:
    """
    Audits Redis keys by pattern with non-blocking SCAN iteration.
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 6379,
        password: Optional[str] = None,
        db: int = 0,
        pattern_separator: str = ":",
        sample_size: int = 5
    ):
        """
        Initialize the Redis auditor.

        Args:
            host: Redis server hostname
            port: Redis server port
            password: Redis password (optional)
            db: Redis database number
            pattern_separator: Character used to separate key prefixes
            sample_size: Number of sample keys to keep per pattern
        """
        self.host = host
        self.port = port
        self.db = db
        self.pattern_separator = pattern_separator
        self.sample_size = sample_size
        self.stats: Dict[str, KeyStats] = defaultdict(KeyStats)
        self.total_keys = 0
        self.total_memory = 0

        # Connect to Redis
        self.client = redis.Redis(
            host=host,
            port=port,
            password=password,
            db=db,
            decode_responses=True,
            socket_timeout=30,
            socket_connect_timeout=10
        )

    def _get_pattern(self, key: str) -> str:
        """
        Extract pattern from key by replacing specific parts with wildcards.

        Args:
            key: The Redis key

        Returns:
            Pattern string (e.g., "session:*" from "session:abc123")
        """
        parts = key.split(self.pattern_separator)

        if len(parts) == 1:
            # No separator found, return as-is or group as "no_prefix"
            return key if len(key) < 20 else "no_prefix:*"

        # Keep first part(s) as prefix, replace the rest with *
        # Handle multi-level prefixes (e.g., "app:cache:user:123" -> "app:cache:user:*")
        if len(parts) >= 3:
            # Keep first two levels for better granularity
            return f"{parts[0]}{self.pattern_separator}{parts[1]}{self.pattern_separator}*"
        else:
            return f"{parts[0]}{self.pattern_separator}*"

    def _scan_keys(self, pattern: str = "*", count: int = 1000) -> Iterator[str]:
        """
        Iterate over keys using SCAN (non-blocking).

        Args:
            pattern: Key pattern to match
            count: Hint for number of keys per iteration

        Yields:
            Key names
        """
        cursor = 0
        while True:
            cursor, keys = self.client.scan(cursor=cursor, match=pattern, count=count)
            for key in keys:
                yield key

            if cursor == 0:
                break

    def _get_memory_usage(self, key: str) -> int:
        """
        Get memory usage for a key using MEMORY USAGE command.

        Args:
            key: The Redis key

        Returns:
            Memory usage in bytes (0 if unavailable)
        """
        try:
            # MEMORY USAGE requires Redis 4.0+
            usage = self.client.memory_usage(key)
            return usage if usage else 0
        except ResponseError:
            # MEMORY USAGE not available (Redis < 4.0)
            return 0
        except Exception:
            return 0

    def _get_ttl(self, key: str) -> int:
        """
        Get TTL for a key.

        Args:
            key: The Redis key

        Returns:
            TTL in seconds (-1 if no TTL, -2 if key doesn't exist)
        """
        try:
            return self.client.ttl(key)
        except Exception:
            return -2

    def audit(self, pattern: str = "*", memory_sampling: bool = True) -> None:
        """
        Perform the key audit.

        Args:
            pattern: Key pattern to scan
            memory_sampling: Whether to sample memory usage (slower but more accurate)
        """
        logger.info(f"Starting audit on {self.host}:{self.port} (db={self.db})")
        logger.info(f"Pattern: {pattern} | Separator: '{self.pattern_separator}'")

        # Get total key count for progress
        total_db_keys = self.client.dbsize()
        logger.info(f"Total keys in database: {total_db_keys}")

        processed = 0
        memory_sampled = 0
        max_memory_samples = 10000  # Limit memory sampling for performance

        for key in self._scan_keys(pattern=pattern):
            processed += 1

            # Extract pattern
            key_pattern = self._get_pattern(key)

            # Update stats
            self.stats[key_pattern].count += 1

            # Sample memory (limited for performance)
            if memory_sampling and memory_sampled < max_memory_samples:
                if self.stats[key_pattern].count <= 100 or processed % 100 == 0:
                    memory = self._get_memory_usage(key)
                    self.stats[key_pattern].total_memory += memory
                    self.total_memory += memory
                    memory_sampled += 1

            # Check TTL
            ttl = self._get_ttl(key)
            if ttl == -1:
                self.stats[key_pattern].ttl_none += 1
            elif ttl > 0:
                self.stats[key_pattern].ttl_set += 1

            # Keep sample keys
            if len(self.stats[key_pattern].sample_keys) < self.sample_size:
                self.stats[key_pattern].sample_keys.append(key)

            # Progress logging
            if processed % 10000 == 0:
                logger.info(f"Processed: {processed:,} keys...")

        self.total_keys = processed
        logger.info(f"Audit complete: {processed:,} keys analyzed")

    def _format_size(self, size_bytes: int) -> str:
        """
        Format bytes into human-readable size.

        Args:
            size_bytes: Size in bytes

        Returns:
            Formatted string (e.g., "1.5 MB")
        """
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"

    def print_report(self, top_n: int = 20) -> None:
        """
        Print the audit report.

        Args:
            top_n: Number of top patterns to show
        """
        print("\n" + "=" * 80)
        print("REDIS KEY AUDIT REPORT")
        print("=" * 80)
        print(f"Host: {self.host}:{self.port} | Database: {self.db}")
        print(f"Total Keys Scanned: {self.total_keys:,}")
        print(f"Total Memory Sampled: {self._format_size(self.total_memory)}")
        print(f"Unique Patterns: {len(self.stats)}")
        print("=" * 80)

        # Sort by count (descending)
        sorted_patterns = sorted(
            self.stats.items(),
            key=lambda x: x[1].count,
            reverse=True
        )[:top_n]

        print(f"\n{'Pattern':<40} {'Count':>12} {'Memory':>12} {'No TTL':>10}")
        print("-" * 80)

        for pattern, stats in sorted_patterns:
            # Truncate long patterns
            display_pattern = pattern if len(pattern) <= 38 else pattern[:35] + "..."

            print(
                f"{display_pattern:<40} "
                f"{stats.count:>12,} "
                f"{self._format_size(stats.total_memory):>12} "
                f"{stats.ttl_none:>10,}"
            )

        print("-" * 80)

        # Show patterns without TTL (potential memory leaks)
        no_ttl_patterns = [
            (p, s) for p, s in self.stats.items()
            if s.ttl_none > 0 and s.ttl_none == s.count
        ]

        if no_ttl_patterns:
            print(f"\n⚠️  PATTERNS WITHOUT TTL ({len(no_ttl_patterns)} patterns):")
            print("   These keys will never expire and may cause memory issues.")
            for pattern, stats in sorted(no_ttl_patterns, key=lambda x: x[1].count, reverse=True)[:10]:
                print(f"   - {pattern}: {stats.count:,} keys")

        print("\n" + "=" * 80)

    def export_csv(self, filename: str) -> None:
        """
        Export report to CSV file.

        Args:
            filename: Output CSV filename
        """
        import csv

        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Pattern', 'Key Count', 'Memory (bytes)', 'TTL Set', 'No TTL', 'Sample Keys'
            ])

            for pattern, stats in sorted(self.stats.items(), key=lambda x: x[1].count, reverse=True):
                writer.writerow([
                    pattern,
                    stats.count,
                    stats.total_memory,
                    stats.ttl_set,
                    stats.ttl_none,
                    ';'.join(stats.sample_keys)
                ])

        logger.info(f"Report exported to: {filename}")


def setup_args() -> argparse.Namespace:
    """
    Configure CLI arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Audit Redis keys by pattern without blocking the server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
    # Audit local Redis
    %(prog)s

    # Audit remote Redis with password
    %(prog)s --host redis.example.com --password secret

    # Audit specific pattern
    %(prog)s --pattern "session:*"

    # Custom separator (e.g., for keys like "app.cache.user.123")
    %(prog)s --pattern-separator "."

    # Export to CSV
    %(prog)s --export report.csv

Note:
    Ce script utilise SCAN (non-bloquant) et non KEYS * (bloquant).
    Il est sûr pour une utilisation en production.
        """
    )

    parser.add_argument(
        '-H', '--host',
        default='localhost',
        help='Hôte Redis (défaut: localhost)'
    )

    parser.add_argument(
        '-p', '--port',
        type=int,
        default=6379,
        help='Port Redis (défaut: 6379)'
    )

    parser.add_argument(
        '-a', '--password',
        help='Mot de passe Redis'
    )

    parser.add_argument(
        '-n', '--db',
        type=int,
        default=0,
        help='Numéro de base de données (défaut: 0)'
    )

    parser.add_argument(
        '--pattern',
        default='*',
        help='Pattern de clés à scanner (défaut: *)'
    )

    parser.add_argument(
        '-s', '--pattern-separator',
        default=':',
        metavar='CHAR',
        help='Séparateur de préfixe (défaut: ":")'
    )

    parser.add_argument(
        '-t', '--top',
        type=int,
        default=20,
        metavar='N',
        help='Nombre de patterns à afficher (défaut: 20)'
    )

    parser.add_argument(
        '--no-memory',
        action='store_true',
        help='Désactiver l\'échantillonnage mémoire (plus rapide)'
    )

    parser.add_argument(
        '-e', '--export',
        metavar='FILE',
        help='Exporter le rapport en CSV'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Mode verbeux'
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

    try:
        # Initialize auditor
        auditor = RedisKeyAuditor(
            host=args.host,
            port=args.port,
            password=args.password,
            db=args.db,
            pattern_separator=args.pattern_separator
        )

        # Test connection
        auditor.client.ping()
        logger.info("Connected to Redis")

        # Run audit
        auditor.audit(
            pattern=args.pattern,
            memory_sampling=not args.no_memory
        )

        # Print report
        auditor.print_report(top_n=args.top)

        # Export if requested
        if args.export:
            auditor.export_csv(args.export)

        return 0

    except ConnectionError as e:
        logger.error(f"Cannot connect to Redis: {e}")
        return 1

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

### Audit Basique

```bash
# Audit Redis local
python3 redis_key_auditor.py

# Audit instance distante
python3 redis_key_auditor.py --host redis.example.com --port 6379

# Avec authentification
python3 redis_key_auditor.py -H redis.example.com -a "mypassword"
```

### Options Avancées

```bash
# Scanner un pattern spécifique
python3 redis_key_auditor.py --pattern "session:*"

# Séparateur personnalisé (pour keys type "app.cache.user.123")
python3 redis_key_auditor.py --pattern-separator "."

# Afficher le top 50 des patterns
python3 redis_key_auditor.py --top 50

# Mode rapide (sans échantillonnage mémoire)
python3 redis_key_auditor.py --no-memory

# Exporter en CSV
python3 redis_key_auditor.py --export audit_report.csv
```

---

## Exemple de Sortie

```text
================================================================================
REDIS KEY AUDIT REPORT
================================================================================
Host: localhost:6379 | Database: 0
Total Keys Scanned: 1,245,678
Total Memory Sampled: 2.34 GB
Unique Patterns: 47
================================================================================

Pattern                                       Count       Memory      No TTL
--------------------------------------------------------------------------------
session:*                                   456,789     512.00 MB          0
cache:api:*                                 234,567     896.00 MB     34,567
user:profile:*                               89,012     128.00 MB          0
queue:jobs:*                                 67,890      64.00 MB     67,890
rate_limit:*                                 45,678      32.00 MB          0
analytics:daily:*                            34,567     256.00 MB     34,567
--------------------------------------------------------------------------------

⚠️  PATTERNS WITHOUT TTL (3 patterns):
   These keys will never expire and may cause memory issues.
   - queue:jobs:*: 67,890 keys
   - cache:api:*: 34,567 keys (subset without TTL)
   - analytics:daily:*: 34,567 keys

================================================================================
```

---

## Options

| Option | Description |
|--------|-------------|
| `-H`, `--host HOST` | Hôte Redis (défaut: localhost) |
| `-p`, `--port PORT` | Port Redis (défaut: 6379) |
| `-a`, `--password PWD` | Mot de passe Redis |
| `-n`, `--db NUM` | Numéro de base de données (défaut: 0) |
| `--pattern PATTERN` | Pattern de clés à scanner (défaut: *) |
| `-s`, `--pattern-separator` | Séparateur de préfixe (défaut: ":") |
| `-t`, `--top N` | Nombre de patterns à afficher (défaut: 20) |
| `--no-memory` | Désactiver l'échantillonnage mémoire |
| `-e`, `--export FILE` | Exporter en CSV |
| `-v`, `--verbose` | Mode verbeux |

---

!!! warning "SCAN vs KEYS"
    | Commande | Comportement | Production |
    |----------|--------------|------------|
    | `KEYS *` | Bloquant, parcourt tout | **INTERDIT** |
    | `SCAN` | Itératif, non-bloquant | **Recommandé** |

    Ce script utilise exclusivement `SCAN` avec un curseur itératif.

!!! tip "Bonnes Pratiques Redis"
    **Toujours définir un TTL** pour les clés temporaires :

    ```python
    # Python
    redis_client.setex("session:abc123", 3600, "data")  # Expire in 1h

    # CLI
    SET session:abc123 "data" EX 3600
    ```

    **Patterns de nommage** :

    - Utilisez des préfixes cohérents : `app:module:entity:id`
    - Exemple : `myapp:cache:user:12345`

---

## Voir Aussi

- [pg-bloat-check.sh](../bash/pg-bloat-check.md) - Analyse bloat PostgreSQL
- [mysql-security-audit.sh](../bash/mysql-security-audit.md) - Audit sécurité MySQL
- [health_checker.py](health_checker.md) - Vérification santé services
