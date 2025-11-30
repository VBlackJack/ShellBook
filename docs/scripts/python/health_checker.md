---
tags:
  - scripts
  - python
  - monitoring
  - services
---

# health_checker.py

:material-star::material-star: **Niveau : Intermédiaire**

Vérification de la santé des services et endpoints.

---

## Description

Ce script vérifie la santé de l'infrastructure :
- Endpoints HTTP/HTTPS
- Ports TCP
- Services système
- Fichier de configuration YAML
- Alertes configurable

---

## Dépendances

```bash
pip install requests pyyaml rich
```

---

## Script

```python
#!/usr/bin/env python3
"""
Script Name: health_checker.py
Description: Vérification santé des services
Author: ShellBook
Version: 1.0

Dependencies:
    pip install requests pyyaml rich
"""

import argparse
import json
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    import requests
except ImportError:
    print("Error: requests required. Install with: pip install requests")
    sys.exit(1)

try:
    import yaml
except ImportError:
    yaml = None

try:
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


@dataclass
class CheckResult:
    """Résultat d'une vérification."""
    name: str
    check_type: str
    target: str
    success: bool
    message: str
    response_time: Optional[float] = None


class HealthChecker:
    """Gestionnaire de vérifications de santé."""

    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.results: List[CheckResult] = []

    def check_http(self, name: str, url: str,
                   expected_status: int = 200,
                   method: str = "GET") -> CheckResult:
        """Check un endpoint HTTP."""
        start = datetime.now()

        try:
            response = requests.request(
                method=method,
                url=url,
                timeout=self.timeout,
                allow_redirects=True
            )

            elapsed = (datetime.now() - start).total_seconds() * 1000
            success = response.status_code == expected_status

            result = CheckResult(
                name=name,
                check_type="HTTP",
                target=url,
                success=success,
                message=f"HTTP {response.status_code}",
                response_time=elapsed
            )

        except requests.exceptions.Timeout:
            result = CheckResult(
                name=name,
                check_type="HTTP",
                target=url,
                success=False,
                message="Timeout"
            )
        except requests.exceptions.ConnectionError:
            result = CheckResult(
                name=name,
                check_type="HTTP",
                target=url,
                success=False,
                message="Connection refused"
            )
        except Exception as e:
            result = CheckResult(
                name=name,
                check_type="HTTP",
                target=url,
                success=False,
                message=str(e)
            )

        self.results.append(result)
        return result

    def check_port(self, name: str, host: str, port: int) -> CheckResult:
        """Check si un port est ouvert."""
        start = datetime.now()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex((host, port))
            sock.close()

            elapsed = (datetime.now() - start).total_seconds() * 1000
            success = result_code == 0

            result = CheckResult(
                name=name,
                check_type="TCP",
                target=f"{host}:{port}",
                success=success,
                message="Open" if success else "Closed/Filtered",
                response_time=elapsed if success else None
            )

        except socket.timeout:
            result = CheckResult(
                name=name,
                check_type="TCP",
                target=f"{host}:{port}",
                success=False,
                message="Timeout"
            )
        except Exception as e:
            result = CheckResult(
                name=name,
                check_type="TCP",
                target=f"{host}:{port}",
                success=False,
                message=str(e)
            )

        self.results.append(result)
        return result

    def check_dns(self, name: str, domain: str) -> CheckResult:
        """Check la résolution DNS."""
        start = datetime.now()

        try:
            ip = socket.gethostbyname(domain)
            elapsed = (datetime.now() - start).total_seconds() * 1000

            result = CheckResult(
                name=name,
                check_type="DNS",
                target=domain,
                success=True,
                message=f"Resolved to {ip}",
                response_time=elapsed
            )

        except socket.gaierror:
            result = CheckResult(
                name=name,
                check_type="DNS",
                target=domain,
                success=False,
                message="Resolution failed"
            )

        self.results.append(result)
        return result

    def check_command(self, name: str, command: str) -> CheckResult:
        """Exécute une commande et vérifie le code retour."""
        start = datetime.now()

        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                timeout=self.timeout
            )
            elapsed = (datetime.now() - start).total_seconds() * 1000
            success = proc.returncode == 0

            result = CheckResult(
                name=name,
                check_type="CMD",
                target=command[:30],
                success=success,
                message=f"Exit code: {proc.returncode}",
                response_time=elapsed
            )

        except subprocess.TimeoutExpired:
            result = CheckResult(
                name=name,
                check_type="CMD",
                target=command[:30],
                success=False,
                message="Timeout"
            )
        except Exception as e:
            result = CheckResult(
                name=name,
                check_type="CMD",
                target=command[:30],
                success=False,
                message=str(e)
            )

        self.results.append(result)
        return result

    def get_summary(self) -> Dict[str, Any]:
        """Retourne un résumé des vérifications."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.success)
        failed = total - passed

        return {
            "timestamp": datetime.now().isoformat(),
            "total": total,
            "passed": passed,
            "failed": failed,
            "success_rate": f"{(passed/total)*100:.1f}%" if total > 0 else "N/A",
            "status": "HEALTHY" if failed == 0 else "DEGRADED" if passed > failed else "UNHEALTHY"
        }


def load_config(config_path: Path) -> Dict[str, Any]:
    """Charge la configuration depuis un fichier YAML."""
    if yaml is None:
        print("Error: pyyaml required for config files. Install with: pip install pyyaml")
        sys.exit(1)

    with open(config_path) as f:
        return yaml.safe_load(f)


def run_checks_from_config(checker: HealthChecker, config: Dict[str, Any]) -> None:
    """Exécute les vérifications depuis la configuration."""
    checks = config.get('checks', [])

    for check in checks:
        check_type = check.get('type', '').lower()
        name = check.get('name', 'Unnamed')

        if check_type == 'http':
            checker.check_http(
                name=name,
                url=check['url'],
                expected_status=check.get('expected_status', 200),
                method=check.get('method', 'GET')
            )

        elif check_type == 'port':
            checker.check_port(
                name=name,
                host=check['host'],
                port=check['port']
            )

        elif check_type == 'dns':
            checker.check_dns(
                name=name,
                domain=check['domain']
            )

        elif check_type == 'command':
            checker.check_command(
                name=name,
                command=check['command']
            )


def display_results_rich(checker: HealthChecker) -> None:
    """Display les résultats avec Rich."""
    console = Console()
    summary = checker.get_summary()

    # Table des résultats
    table = Table(title="Health Check Results")
    table.add_column("Status", width=8)
    table.add_column("Name", style="cyan")
    table.add_column("Type", width=6)
    table.add_column("Target")
    table.add_column("Message")
    table.add_column("Time", justify="right")

    for result in checker.results:
        status = "[green]✓ PASS[/green]" if result.success else "[red]✗ FAIL[/red]"
        time_str = f"{result.response_time:.0f}ms" if result.response_time else "-"

        table.add_row(
            status,
            result.name,
            result.check_type,
            result.target[:40],
            result.message,
            time_str
        )

    console.print(table)

    # Résumé
    status_color = {
        "HEALTHY": "green",
        "DEGRADED": "yellow",
        "UNHEALTHY": "red"
    }.get(summary['status'], "white")

    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Total: {summary['total']} | "
                  f"[green]Passed: {summary['passed']}[/green] | "
                  f"[red]Failed: {summary['failed']}[/red]")
    console.print(f"  Status: [{status_color}]{summary['status']}[/{status_color}]")


def display_results_simple(checker: HealthChecker) -> None:
    """Display les résultats en mode simple."""
    print("\n" + "=" * 60)
    print("  HEALTH CHECK RESULTS")
    print("=" * 60 + "\n")

    for result in checker.results:
        status = "[PASS]" if result.success else "[FAIL]"
        time_str = f"({result.response_time:.0f}ms)" if result.response_time else ""
        print(f"{status} {result.name}: {result.message} {time_str}")

    summary = checker.get_summary()
    print("\n" + "-" * 60)
    print(f"Total: {summary['total']} | Passed: {summary['passed']} | Failed: {summary['failed']}")
    print(f"Status: {summary['status']}")


def main():
    parser = argparse.ArgumentParser(
        description="Health Checker - Service monitoring tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration file format (YAML):
  checks:
    - name: "Google"
      type: http
      url: "https://www.google.com"

    - name: "SSH"
      type: port
      host: localhost
      port: 22

    - name: "DNS Google"
      type: dns
      domain: "www.google.com"
        """
    )

    parser.add_argument('-c', '--config', type=Path, help='Configuration file (YAML)')
    parser.add_argument('-u', '--url', action='append', help='HTTP URL to check')
    parser.add_argument('-p', '--port', action='append', help='Port to check (host:port)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Timeout in seconds')
    parser.add_argument('-j', '--json', action='store_true', help='Output as JSON')
    parser.add_argument('-s', '--simple', action='store_true', help='Simple output')

    args = parser.parse_args()

    checker = HealthChecker(timeout=args.timeout)

    # Charger config si fournie
    if args.config:
        if not args.config.exists():
            print(f"Error: Config file not found: {args.config}")
            sys.exit(1)
        config = load_config(args.config)
        run_checks_from_config(checker, config)

    # URLs en ligne de commande
    if args.url:
        for i, url in enumerate(args.url):
            checker.check_http(f"URL {i+1}", url)

    # Ports en ligne de commande
    if args.port:
        for i, port_spec in enumerate(args.port):
            try:
                host, port = port_spec.rsplit(':', 1)
                checker.check_port(f"Port {i+1}", host, int(port))
            except ValueError:
                print(f"Invalid port format: {port_spec} (expected host:port)")

    # Checks par défaut si rien n'est spécifié
    if not checker.results:
        checker.check_http("Google", "https://www.google.com")
        checker.check_dns("DNS", "www.google.com")
        checker.check_port("Local SSH", "127.0.0.1", 22)

    # Affichage
    if args.json:
        output = {
            "summary": checker.get_summary(),
            "results": [
                {
                    "name": r.name,
                    "type": r.check_type,
                    "target": r.target,
                    "success": r.success,
                    "message": r.message,
                    "response_time_ms": r.response_time
                }
                for r in checker.results
            ]
        }
        print(json.dumps(output, indent=2))
    elif args.simple or not RICH_AVAILABLE:
        display_results_simple(checker)
    else:
        display_results_rich(checker)

    # Code de retour
    summary = checker.get_summary()
    if summary['failed'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
```

---

## Configuration YAML

Exemple `checks.yaml`:

```yaml
# Health Check Configuration
timeout: 5

checks:
  # HTTP Endpoints
  - name: "Website"
    type: http
    url: "https://example.com"
    expected_status: 200

  - name: "API Health"
    type: http
    url: "https://api.example.com/health"
    method: GET

  # TCP Ports
  - name: "SSH Server"
    type: port
    host: localhost
    port: 22

  - name: "MySQL"
    type: port
    host: db.example.com
    port: 3306

  - name: "Redis"
    type: port
    host: localhost
    port: 6379

  # DNS Resolution
  - name: "DNS Example"
    type: dns
    domain: "www.example.com"

  # Commands
  - name: "Disk Space"
    type: command
    command: "df -h / | awk 'NR==2 {exit ($5+0 > 90)}'"
```

---

## Utilisation

```bash
# Checks par défaut
python health_checker.py

# Avec fichier de configuration
python health_checker.py -c checks.yaml

# URLs en ligne de commande
python health_checker.py -u https://google.com -u https://github.com

# Ports en ligne de commande
python health_checker.py -p localhost:22 -p db.example.com:3306

# Sortie JSON
python health_checker.py -c checks.yaml --json

# Timeout personnalisé
python health_checker.py -t 10 -c checks.yaml
```

---

## Sortie Exemple

```
              Health Check Results
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Status   ┃ Name           ┃ Type   ┃ Target            ┃ Message      ┃  Time ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━┩
│ ✓ PASS   │ Website        │ HTTP   │ https://example.. │ HTTP 200     │  234ms│
│ ✓ PASS   │ API Health     │ HTTP   │ https://api.exam..│ HTTP 200     │  156ms│
│ ✓ PASS   │ SSH Server     │ TCP    │ localhost:22      │ Open         │   12ms│
│ ✓ PASS   │ MySQL          │ TCP    │ db.example.com:3..│ Open         │   45ms│
│ ✗ FAIL   │ Redis          │ TCP    │ localhost:6379    │ Closed/Filt..│     - │
│ ✓ PASS   │ DNS Example    │ DNS    │ www.example.com   │ Resolved to..│   23ms│
└──────────┴────────────────┴────────┴───────────────────┴──────────────┴───────┘

Summary:
  Total: 6 | Passed: 5 | Failed: 1
  Status: DEGRADED
```

---

## Intégration Cron

```bash
# Check toutes les 5 minutes avec alerte
*/5 * * * * /usr/bin/python3 /opt/scripts/health_checker.py -c /etc/health_checks.yaml -j >> /var/log/health_checks.log 2>&1

# Avec envoi d'email en cas d'échec
*/5 * * * * /usr/bin/python3 /opt/scripts/health_checker.py -c /etc/checks.yaml || echo "Health check failed" | mail -s "Alert" admin@example.com
```

---

## Voir Aussi

- [log_anomaly_detector.py](log_anomaly_detector.md) - Détection anomalies logs
- [api_health_monitor.py](api_health_monitor.md) - Monitoring API
