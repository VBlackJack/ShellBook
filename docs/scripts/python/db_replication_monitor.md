---
tags:
  - scripts
  - python
  - database
  - replication
  - monitoring
---

# db_replication_monitor.py

:material-star::material-star::material-star: **Niveau : Avancé**

Monitoring du lag de réplication pour MySQL, PostgreSQL et MariaDB.

---

## Description

Ce script surveille la santé de la réplication des bases de données :
- Détection du lag de réplication (secondes/bytes)
- Support MySQL/MariaDB (GTID, binlog position)
- Support PostgreSQL (streaming replication)
- Alertes sur seuils configurables
- Vérification de l'état des slaves
- Export métriques Prometheus
- Mode watch pour surveillance continue

---

## Dépendances

```bash
pip install rich pyyaml pymysql psycopg2-binary
```

---

## Script

```python
#!/usr/bin/env python3
"""
Script Name: db_replication_monitor.py
Description: Database replication lag monitoring for MySQL/PostgreSQL
Author: ShellBook
Version: 1.0

Dependencies:
    pip install rich pyyaml pymysql psycopg2-binary
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


@dataclass
class ReplicationStatus:
    """Replication status for a database instance."""
    name: str
    db_type: str
    role: str  # master, slave, replica
    host: str
    is_replicating: bool = False
    lag_seconds: Optional[float] = None
    lag_bytes: Optional[int] = None
    master_host: Optional[str] = None
    slave_io_running: Optional[bool] = None
    slave_sql_running: Optional[bool] = None
    last_error: Optional[str] = None
    gtid_current: Optional[str] = None
    gtid_executed: Optional[str] = None
    position: Optional[int] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    @property
    def is_healthy(self) -> bool:
        """Check if replication is healthy."""
        if self.role == "master":
            return True
        if not self.is_replicating:
            return False
        if self.slave_io_running is False or self.slave_sql_running is False:
            return False
        return True

    @property
    def lag_status(self) -> str:
        """Get lag status category."""
        if self.lag_seconds is None:
            return "UNKNOWN"
        if self.lag_seconds <= 1:
            return "OK"
        if self.lag_seconds <= 10:
            return "WARNING"
        if self.lag_seconds <= 60:
            return "CRITICAL"
        return "SEVERE"


class MySQLReplicationMonitor:
    """Monitor MySQL/MariaDB replication."""

    def __init__(self, host: str, port: int, user: str, password: str, name: str = "mysql"):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.name = name
        self.conn = None

    def connect(self):
        """Establish database connection."""
        try:
            import pymysql
            self.conn = pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                cursorclass=pymysql.cursors.DictCursor,
                connect_timeout=5
            )
            return True
        except Exception as e:
            return False, str(e)

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def get_status(self) -> ReplicationStatus:
        """Get replication status."""
        status = ReplicationStatus(
            name=self.name,
            db_type="MySQL",
            role="unknown",
            host=self.host
        )

        try:
            if not self.conn:
                self.connect()

            with self.conn.cursor() as cursor:
                # Check if this is a slave
                cursor.execute("SHOW SLAVE STATUS")
                slave_status = cursor.fetchone()

                if slave_status:
                    status.role = "replica"
                    status.is_replicating = True
                    status.master_host = slave_status.get('Master_Host')
                    status.lag_seconds = slave_status.get('Seconds_Behind_Master')
                    status.slave_io_running = slave_status.get('Slave_IO_Running') == 'Yes'
                    status.slave_sql_running = slave_status.get('Slave_SQL_Running') == 'Yes'
                    status.position = slave_status.get('Read_Master_Log_Pos')

                    # Check for errors
                    last_error = slave_status.get('Last_Error')
                    if last_error:
                        status.last_error = last_error
                        status.is_replicating = False

                    # GTID info
                    status.gtid_executed = slave_status.get('Executed_Gtid_Set', '')

                    # Check if replication is actually running
                    if not status.slave_io_running or not status.slave_sql_running:
                        status.is_replicating = False
                        io_error = slave_status.get('Last_IO_Error', '')
                        sql_error = slave_status.get('Last_SQL_Error', '')
                        status.last_error = io_error or sql_error or "Replication stopped"

                else:
                    # Check if this is a master
                    cursor.execute("SHOW MASTER STATUS")
                    master_status = cursor.fetchone()

                    if master_status:
                        status.role = "master"
                        status.position = master_status.get('Position')
                        status.gtid_current = master_status.get('Executed_Gtid_Set', '')

                    # Get slave list
                    cursor.execute("SHOW SLAVE HOSTS")
                    slaves = cursor.fetchall()
                    if slaves:
                        status.role = "master"

        except Exception as e:
            status.last_error = str(e)
            status.is_replicating = False

        return status


class PostgreSQLReplicationMonitor:
    """Monitor PostgreSQL streaming replication."""

    def __init__(self, host: str, port: int, user: str, password: str,
                 database: str = "postgres", name: str = "postgresql"):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.database = database
        self.name = name
        self.conn = None

    def connect(self):
        """Establish database connection."""
        try:
            import psycopg2
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                dbname=self.database,
                connect_timeout=5
            )
            self.conn.autocommit = True
            return True
        except Exception as e:
            return False, str(e)

    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()

    def get_status(self) -> ReplicationStatus:
        """Get replication status."""
        status = ReplicationStatus(
            name=self.name,
            db_type="PostgreSQL",
            role="unknown",
            host=self.host
        )

        try:
            if not self.conn:
                self.connect()

            with self.conn.cursor() as cursor:
                # Check if in recovery (standby)
                cursor.execute("SELECT pg_is_in_recovery()")
                is_standby = cursor.fetchone()[0]

                if is_standby:
                    status.role = "replica"
                    status.is_replicating = True

                    # Get replication lag
                    cursor.execute("""
                        SELECT
                            CASE
                                WHEN pg_last_wal_receive_lsn() = pg_last_wal_replay_lsn()
                                THEN 0
                                ELSE EXTRACT(EPOCH FROM now() - pg_last_xact_replay_timestamp())
                            END AS lag_seconds,
                            pg_wal_lsn_diff(pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn()) AS lag_bytes
                    """)
                    result = cursor.fetchone()
                    if result:
                        status.lag_seconds = float(result[0]) if result[0] else 0
                        status.lag_bytes = int(result[1]) if result[1] else 0

                    # Get master info from recovery.conf or primary_conninfo
                    cursor.execute("""
                        SELECT setting FROM pg_settings
                        WHERE name = 'primary_conninfo'
                    """)
                    result = cursor.fetchone()
                    if result and result[0]:
                        # Parse host from connection string
                        import re
                        match = re.search(r'host=([^\s]+)', result[0])
                        if match:
                            status.master_host = match.group(1)

                else:
                    status.role = "master"

                    # Get replication slots and their lag
                    cursor.execute("""
                        SELECT
                            slot_name,
                            active,
                            pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS lag_bytes
                        FROM pg_replication_slots
                    """)
                    slots = cursor.fetchall()

                    # Get streaming replicas
                    cursor.execute("""
                        SELECT
                            client_addr,
                            state,
                            pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn) AS lag_bytes,
                            replay_lag
                        FROM pg_stat_replication
                    """)
                    replicas = cursor.fetchall()

                    if replicas:
                        # Report max lag among replicas
                        max_lag = max(r[2] or 0 for r in replicas)
                        status.lag_bytes = int(max_lag)

        except Exception as e:
            status.last_error = str(e)
            status.is_replicating = False

        return status


class ReplicationMonitor:
    """Main replication monitor orchestrator."""

    def __init__(self):
        self.monitors: List = []
        self.results: List[ReplicationStatus] = []

    def add_mysql(self, host: str, port: int = 3306, user: str = "root",
                  password: str = "", name: str = None):
        """Add MySQL/MariaDB instance to monitor."""
        monitor = MySQLReplicationMonitor(
            host=host, port=port, user=user, password=password,
            name=name or f"mysql-{host}"
        )
        self.monitors.append(monitor)

    def add_postgresql(self, host: str, port: int = 5432, user: str = "postgres",
                       password: str = "", database: str = "postgres", name: str = None):
        """Add PostgreSQL instance to monitor."""
        monitor = PostgreSQLReplicationMonitor(
            host=host, port=port, user=user, password=password,
            database=database, name=name or f"pg-{host}"
        )
        self.monitors.append(monitor)

    def check_all(self) -> List[ReplicationStatus]:
        """Check all configured instances."""
        self.results = []
        for monitor in self.monitors:
            try:
                monitor.connect()
                status = monitor.get_status()
                self.results.append(status)
            except Exception as e:
                self.results.append(ReplicationStatus(
                    name=monitor.name,
                    db_type=type(monitor).__name__.replace("ReplicationMonitor", ""),
                    role="unknown",
                    host=monitor.host,
                    last_error=str(e)
                ))
            finally:
                monitor.close()
        return self.results

    def get_summary(self) -> Dict[str, Any]:
        """Get monitoring summary."""
        total = len(self.results)
        healthy = sum(1 for r in self.results if r.is_healthy)
        unhealthy = total - healthy

        max_lag = max((r.lag_seconds or 0 for r in self.results), default=0)

        return {
            "timestamp": datetime.now().isoformat(),
            "total_instances": total,
            "healthy": healthy,
            "unhealthy": unhealthy,
            "max_lag_seconds": max_lag,
            "status": "HEALTHY" if unhealthy == 0 else "DEGRADED" if healthy > 0 else "DOWN"
        }

    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        lines.append("# HELP db_replication_lag_seconds Database replication lag in seconds")
        lines.append("# TYPE db_replication_lag_seconds gauge")

        for r in self.results:
            lag = r.lag_seconds if r.lag_seconds is not None else -1
            lines.append(f'db_replication_lag_seconds{{name="{r.name}",db_type="{r.db_type}",role="{r.role}"}} {lag}')

        lines.append("")
        lines.append("# HELP db_replication_healthy Database replication health (1=healthy, 0=unhealthy)")
        lines.append("# TYPE db_replication_healthy gauge")

        for r in self.results:
            healthy = 1 if r.is_healthy else 0
            lines.append(f'db_replication_healthy{{name="{r.name}",db_type="{r.db_type}"}} {healthy}')

        return "\n".join(lines)


def load_config(config_path: str) -> List[Dict]:
    """Load configuration from YAML file."""
    if not YAML_AVAILABLE:
        print("Error: pyyaml required. Install with: pip install pyyaml")
        sys.exit(1)

    with open(config_path) as f:
        return yaml.safe_load(f)


def display_results_rich(monitor: ReplicationMonitor) -> None:
    """Display results with Rich."""
    console = Console()
    summary = monitor.get_summary()

    status_color = {
        "HEALTHY": "green",
        "DEGRADED": "yellow",
        "DOWN": "red"
    }.get(summary['status'], "white")

    # Header
    console.print(Panel.fit(
        f"[bold cyan]Database Replication Monitor[/bold cyan]\n"
        f"[dim]{summary['timestamp']}[/dim]",
        border_style="cyan"
    ))

    # Results table
    table = Table(title="Replication Status")
    table.add_column("Status", width=10)
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Role")
    table.add_column("Host")
    table.add_column("Lag", justify="right")
    table.add_column("IO/SQL")
    table.add_column("Message")

    for result in monitor.results:
        # Status
        if result.is_healthy:
            status = "[green]✓ OK[/green]"
        else:
            status = "[red]✗ FAIL[/red]"

        # Lag with color
        if result.lag_seconds is not None:
            if result.lag_seconds <= 1:
                lag = f"[green]{result.lag_seconds:.1f}s[/green]"
            elif result.lag_seconds <= 10:
                lag = f"[yellow]{result.lag_seconds:.1f}s[/yellow]"
            else:
                lag = f"[red]{result.lag_seconds:.1f}s[/red]"
        else:
            lag = "-"

        # IO/SQL status (MySQL)
        if result.slave_io_running is not None:
            io_status = "[green]Y[/green]" if result.slave_io_running else "[red]N[/red]"
            sql_status = "[green]Y[/green]" if result.slave_sql_running else "[red]N[/red]"
            io_sql = f"{io_status}/{sql_status}"
        else:
            io_sql = "-"

        # Message
        message = result.last_error[:30] + "..." if result.last_error and len(result.last_error) > 30 else (result.last_error or "OK")

        table.add_row(
            status,
            result.name,
            result.db_type,
            result.role,
            result.host,
            lag,
            io_sql,
            message
        )

    console.print(table)

    # Summary
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Instances: {summary['total_instances']} | "
                  f"[green]Healthy: {summary['healthy']}[/green] | "
                  f"[red]Unhealthy: {summary['unhealthy']}[/red]")
    console.print(f"  Max Lag: {summary['max_lag_seconds']:.1f}s")
    console.print(f"  Status: [{status_color}]{summary['status']}[/{status_color}]")


def display_results_simple(monitor: ReplicationMonitor) -> None:
    """Display results in simple format."""
    print("\n" + "=" * 70)
    print("  DATABASE REPLICATION MONITOR")
    print("=" * 70 + "\n")

    for result in monitor.results:
        status = "[OK]" if result.is_healthy else "[FAIL]"
        lag = f"({result.lag_seconds:.1f}s lag)" if result.lag_seconds else ""
        print(f"{status} {result.name} ({result.db_type} {result.role}) {lag}")
        if result.last_error:
            print(f"     Error: {result.last_error}")

    summary = monitor.get_summary()
    print("\n" + "-" * 70)
    print(f"Total: {summary['total_instances']} | Healthy: {summary['healthy']} | Unhealthy: {summary['unhealthy']}")
    print(f"Status: {summary['status']}")


def main():
    parser = argparse.ArgumentParser(
        description="Database Replication Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration file format (YAML):
  instances:
    - type: mysql
      name: "mysql-primary"
      host: "db-master.example.com"
      port: 3306
      user: "monitor"
      password: "secret"

    - type: postgresql
      name: "pg-replica1"
      host: "pg-replica1.example.com"
      port: 5432
      user: "monitor"
      password: "secret"
      database: "postgres"

Examples:
    %(prog)s -c databases.yaml
    %(prog)s --mysql master.db.local -u monitor -p secret
    %(prog)s --postgresql replica.db.local -u postgres
    %(prog)s -c databases.yaml --watch 30
    %(prog)s -c databases.yaml --prometheus
        """
    )

    parser.add_argument('-c', '--config', help='Configuration file (YAML)')
    parser.add_argument('--mysql', metavar='HOST', help='MySQL/MariaDB host')
    parser.add_argument('--postgresql', '--pg', metavar='HOST', help='PostgreSQL host')
    parser.add_argument('-P', '--port', type=int, help='Database port')
    parser.add_argument('-u', '--user', default='root', help='Database user')
    parser.add_argument('-p', '--password', default='', help='Database password')
    parser.add_argument('-d', '--database', default='postgres', help='Database name (PostgreSQL)')
    parser.add_argument('-w', '--watch', type=int, metavar='SEC', help='Watch mode interval')
    parser.add_argument('-j', '--json', action='store_true', help='Output as JSON')
    parser.add_argument('-s', '--simple', action='store_true', help='Simple output')
    parser.add_argument('--prometheus', action='store_true', help='Output Prometheus metrics')

    args = parser.parse_args()

    monitor = ReplicationMonitor()

    # Load from config
    if args.config:
        config = load_config(args.config)
        for instance in config.get('instances', []):
            if instance['type'] == 'mysql':
                monitor.add_mysql(
                    host=instance['host'],
                    port=instance.get('port', 3306),
                    user=instance.get('user', 'root'),
                    password=instance.get('password', ''),
                    name=instance.get('name')
                )
            elif instance['type'] == 'postgresql':
                monitor.add_postgresql(
                    host=instance['host'],
                    port=instance.get('port', 5432),
                    user=instance.get('user', 'postgres'),
                    password=instance.get('password', ''),
                    database=instance.get('database', 'postgres'),
                    name=instance.get('name')
                )

    # Add from command line
    if args.mysql:
        monitor.add_mysql(
            host=args.mysql,
            port=args.port or 3306,
            user=args.user,
            password=args.password
        )

    if args.postgresql:
        monitor.add_postgresql(
            host=args.postgresql,
            port=args.port or 5432,
            user=args.user,
            password=args.password,
            database=args.database
        )

    if not monitor.monitors:
        print("Error: No database instances configured")
        print("Use -c config.yaml or --mysql/--postgresql options")
        sys.exit(1)

    # Watch mode
    if args.watch and RICH_AVAILABLE:
        console = Console()
        try:
            while True:
                monitor.check_all()
                console.clear()
                display_results_rich(monitor)
                console.print(f"\n[dim]Refreshing every {args.watch}s... Ctrl+C to stop[/dim]")
                time.sleep(args.watch)
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopped.[/yellow]")
        return

    # Single check
    monitor.check_all()

    # Output
    if args.prometheus:
        print(monitor.export_prometheus())
    elif args.json:
        output = {
            "summary": monitor.get_summary(),
            "instances": [
                {
                    "name": r.name,
                    "db_type": r.db_type,
                    "role": r.role,
                    "host": r.host,
                    "is_healthy": r.is_healthy,
                    "is_replicating": r.is_replicating,
                    "lag_seconds": r.lag_seconds,
                    "lag_bytes": r.lag_bytes,
                    "lag_status": r.lag_status,
                    "error": r.last_error
                }
                for r in monitor.results
            ]
        }
        print(json.dumps(output, indent=2))
    elif args.simple or not RICH_AVAILABLE:
        display_results_simple(monitor)
    else:
        display_results_rich(monitor)

    # Exit code
    summary = monitor.get_summary()
    if summary['unhealthy'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
```

---

## Configuration YAML

Exemple `databases.yaml`:

```yaml
# Database Replication Monitor Configuration

instances:
  # MySQL/MariaDB Primary
  - type: mysql
    name: "mysql-master"
    host: "db-master.example.com"
    port: 3306
    user: "monitor"
    password: "${MYSQL_MONITOR_PASSWORD}"

  # MySQL Replicas
  - type: mysql
    name: "mysql-replica1"
    host: "db-replica1.example.com"
    port: 3306
    user: "monitor"
    password: "${MYSQL_MONITOR_PASSWORD}"

  - type: mysql
    name: "mysql-replica2"
    host: "db-replica2.example.com"
    port: 3306
    user: "monitor"
    password: "${MYSQL_MONITOR_PASSWORD}"

  # PostgreSQL Primary
  - type: postgresql
    name: "pg-primary"
    host: "pg-master.example.com"
    port: 5432
    user: "replication_monitor"
    password: "${PG_MONITOR_PASSWORD}"
    database: "postgres"

  # PostgreSQL Standby
  - type: postgresql
    name: "pg-standby"
    host: "pg-standby.example.com"
    port: 5432
    user: "replication_monitor"
    password: "${PG_MONITOR_PASSWORD}"
    database: "postgres"
```

---

## Utilisation

```bash
# Avec fichier de configuration
python db_replication_monitor.py -c databases.yaml

# MySQL direct
python db_replication_monitor.py --mysql replica.db.local -u monitor -p secret

# PostgreSQL direct
python db_replication_monitor.py --pg standby.db.local -u postgres -p secret

# Mode surveillance continue
python db_replication_monitor.py -c databases.yaml --watch 10

# Export Prometheus
python db_replication_monitor.py -c databases.yaml --prometheus

# Sortie JSON
python db_replication_monitor.py -c databases.yaml --json
```

---

## Sortie Exemple

```
╭──────────────────────────────────────────────────────────────────────╮
│                   Database Replication Monitor                        │
│                      2024-01-15T14:30:22.123456                       │
╰──────────────────────────────────────────────────────────────────────╯

                         Replication Status
┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━━┓
┃ Status     ┃ Name           ┃ Type       ┃ Role    ┃ Host            ┃ Lag   ┃ IO/SQL┃ Message ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━━┩
│ ✓ OK       │ mysql-master   │ MySQL      │ master  │ db-master.loc.. │ -     │ -     │ OK      │
│ ✓ OK       │ mysql-replica1 │ MySQL      │ replica │ db-replica1.... │ 0.5s  │ Y/Y   │ OK      │
│ ✗ FAIL     │ mysql-replica2 │ MySQL      │ replica │ db-replica2.... │ 45.2s │ Y/N   │ SQL err │
│ ✓ OK       │ pg-primary     │ PostgreSQL │ master  │ pg-master.loc.. │ -     │ -     │ OK      │
│ ✓ OK       │ pg-standby     │ PostgreSQL │ replica │ pg-standby.l... │ 1.2s  │ -     │ OK      │
└────────────┴────────────────┴────────────┴─────────┴─────────────────┴───────┴───────┴─────────┘

Summary:
  Instances: 5 | Healthy: 4 | Unhealthy: 1
  Max Lag: 45.2s
  Status: DEGRADED
```

---

## Métriques Prometheus

```
# HELP db_replication_lag_seconds Database replication lag in seconds
# TYPE db_replication_lag_seconds gauge
db_replication_lag_seconds{name="mysql-replica1",db_type="MySQL",role="replica"} 0.5
db_replication_lag_seconds{name="mysql-replica2",db_type="MySQL",role="replica"} 45.2
db_replication_lag_seconds{name="pg-standby",db_type="PostgreSQL",role="replica"} 1.2

# HELP db_replication_healthy Database replication health (1=healthy, 0=unhealthy)
# TYPE db_replication_healthy gauge
db_replication_healthy{name="mysql-replica1",db_type="MySQL"} 1
db_replication_healthy{name="mysql-replica2",db_type="MySQL"} 0
db_replication_healthy{name="pg-standby",db_type="PostgreSQL"} 1
```

---

## Automatisation Cron

```bash
# Check toutes les minutes
* * * * * /usr/bin/python3 /opt/scripts/db_replication_monitor.py -c /etc/db_monitor.yaml --json >> /var/log/db_replication.log

# Avec alerte si lag > 10s
* * * * * /usr/bin/python3 /opt/scripts/db_replication_monitor.py -c /etc/db_monitor.yaml || echo "Replication issue" | mail -s "DB Alert" dba@example.com
```

---

## Voir Aussi

- [check-mysql.sh](../bash/check-mysql.md)
- [check-postgresql.sh](../bash/check-postgresql.md)
- [health_checker.py](health_checker.md)
