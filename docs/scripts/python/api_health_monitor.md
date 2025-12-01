---
tags:
  - scripts
  - python
  - monitoring
  - api
  - http
---

# api_health_monitor.py

:material-star::material-star::material-star: **Niveau : Avancé**

Monitoring multi-endpoint avec temps de réponse, validation SSL et alertes.

---

## Description

Ce script surveille la santé de multiples APIs et endpoints :
- Vérification HTTP/HTTPS avec codes de réponse attendus
- Mesure des temps de réponse (latence)
- Validation des certificats SSL (expiration)
- Support des headers personnalisés et authentification
- Alertes configurables (seuils de latence, échecs)
- Export JSON pour intégration monitoring
- Mode watch pour surveillance continue

---

## Prérequis

- **Python** : Version 3.8+
- **Modules** : `requests`, `rich`, `pyyaml`
- **Système** : Linux, macOS ou Windows
- **Permissions** : Accès réseau pour interroger les APIs et endpoints

---

## Cas d'Usage

- **Monitoring production** : Surveillance continue de la santé des APIs critiques avec mesure de latence et validation SSL
- **Audit de conformité** : Vérification automatique de l'expiration des certificats SSL sur l'ensemble des endpoints
- **Intégration CI/CD** : Validation des endpoints après déploiement avec export JSON pour intégration dans les pipelines
- **Alertes proactives** : Détection des dégradations de performance et des anomalies de disponibilité avec seuils configurables
- **Documentation d'infrastructure** : Génération de rapports sur l'état de santé de l'ensemble des services exposés

---

## Dépendances

```bash
pip install requests rich pyyaml
```

---

## Script

```python
#!/usr/bin/env python3
"""
Script Name: api_health_monitor.py
Description: Multi-endpoint API health monitoring with SSL validation
Author: ShellBook
Version: 1.0

Dependencies:
    pip install requests rich pyyaml
"""

import argparse
import json
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("Error: requests required. Install with: pip install requests")
    sys.exit(1)

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.live import Live
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


@dataclass
class EndpointConfig:
    """Configuration for an endpoint to monitor."""
    name: str
    url: str
    method: str = "GET"
    expected_status: int = 200
    timeout: int = 10
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    verify_ssl: bool = True
    check_ssl_expiry: bool = True
    ssl_warning_days: int = 30
    latency_warning_ms: int = 1000
    latency_critical_ms: int = 3000


@dataclass
class HealthResult:
    """Result of a health check."""
    name: str
    url: str
    success: bool
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    error: Optional[str] = None
    ssl_days_remaining: Optional[int] = None
    ssl_valid: bool = True
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class APIHealthMonitor:
    """Monitor health of multiple API endpoints."""

    def __init__(self, timeout: int = 10, retries: int = 1):
        self.timeout = timeout
        self.retries = retries
        self.results: List[HealthResult] = []
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        retry_strategy = Retry(
            total=self.retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def check_ssl_certificate(self, hostname: str, port: int = 443) -> tuple:
        """Check SSL certificate expiration."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()

            # Parse expiration date
            not_after = cert.get('notAfter')
            if not_after:
                # Format: 'Sep 30 12:00:00 2024 GMT'
                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry_date - datetime.now()).days
                return True, days_remaining
            return True, None

        except ssl.SSLCertVerificationError as e:
            return False, str(e)
        except Exception as e:
            return None, str(e)

    def check_endpoint(self, config: EndpointConfig) -> HealthResult:
        """Check a single endpoint."""
        start_time = time.time()

        try:
            # Prepare request
            kwargs = {
                'timeout': config.timeout,
                'verify': config.verify_ssl,
                'headers': config.headers
            }

            if config.body and config.method in ['POST', 'PUT', 'PATCH']:
                kwargs['data'] = config.body

            # Make request
            response = self.session.request(
                method=config.method,
                url=config.url,
                **kwargs
            )

            latency_ms = (time.time() - start_time) * 1000
            success = response.status_code == config.expected_status

            result = HealthResult(
                name=config.name,
                url=config.url,
                success=success,
                status_code=response.status_code,
                latency_ms=round(latency_ms, 2),
                error=None if success else f"Expected {config.expected_status}, got {response.status_code}"
            )

            # Check SSL if HTTPS
            if config.check_ssl_expiry and config.url.startswith('https://'):
                parsed = urlparse(config.url)
                hostname = parsed.hostname
                port = parsed.port or 443

                ssl_valid, ssl_info = self.check_ssl_certificate(hostname, port)
                if ssl_valid is True and isinstance(ssl_info, int):
                    result.ssl_days_remaining = ssl_info
                    result.ssl_valid = ssl_info > 0
                elif ssl_valid is False:
                    result.ssl_valid = False
                    result.error = f"SSL Error: {ssl_info}"
                    result.success = False

        except requests.exceptions.Timeout:
            result = HealthResult(
                name=config.name,
                url=config.url,
                success=False,
                latency_ms=(time.time() - start_time) * 1000,
                error="Timeout"
            )
        except requests.exceptions.SSLError as e:
            result = HealthResult(
                name=config.name,
                url=config.url,
                success=False,
                error=f"SSL Error: {str(e)[:50]}",
                ssl_valid=False
            )
        except requests.exceptions.ConnectionError:
            result = HealthResult(
                name=config.name,
                url=config.url,
                success=False,
                error="Connection refused"
            )
        except Exception as e:
            result = HealthResult(
                name=config.name,
                url=config.url,
                success=False,
                error=str(e)[:50]
            )

        self.results.append(result)
        return result

    def check_all(self, endpoints: List[EndpointConfig]) -> List[HealthResult]:
        """Check all endpoints."""
        self.results = []
        for endpoint in endpoints:
            self.check_endpoint(endpoint)
        return self.results

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        total = len(self.results)
        healthy = sum(1 for r in self.results if r.success)
        unhealthy = total - healthy

        latencies = [r.latency_ms for r in self.results if r.latency_ms is not None]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0

        ssl_warnings = [r for r in self.results
                        if r.ssl_days_remaining is not None and r.ssl_days_remaining < 30]

        return {
            "timestamp": datetime.now().isoformat(),
            "total": total,
            "healthy": healthy,
            "unhealthy": unhealthy,
            "success_rate": f"{(healthy/total)*100:.1f}%" if total > 0 else "N/A",
            "avg_latency_ms": round(avg_latency, 2),
            "ssl_warnings": len(ssl_warnings),
            "status": "HEALTHY" if unhealthy == 0 else "DEGRADED" if healthy > unhealthy else "DOWN"
        }


def load_config(config_path: Path) -> List[EndpointConfig]:
    """Load endpoints configuration from YAML file."""
    if not YAML_AVAILABLE:
        print("Error: pyyaml required for config files. Install with: pip install pyyaml")
        sys.exit(1)

    with open(config_path) as f:
        data = yaml.safe_load(f)

    endpoints = []
    for ep in data.get('endpoints', []):
        endpoints.append(EndpointConfig(
            name=ep.get('name', 'Unnamed'),
            url=ep['url'],
            method=ep.get('method', 'GET'),
            expected_status=ep.get('expected_status', 200),
            timeout=ep.get('timeout', 10),
            headers=ep.get('headers', {}),
            body=ep.get('body'),
            verify_ssl=ep.get('verify_ssl', True),
            check_ssl_expiry=ep.get('check_ssl_expiry', True),
            ssl_warning_days=ep.get('ssl_warning_days', 30),
            latency_warning_ms=ep.get('latency_warning_ms', 1000),
            latency_critical_ms=ep.get('latency_critical_ms', 3000)
        ))

    return endpoints


def display_results_rich(monitor: APIHealthMonitor, endpoints: List[EndpointConfig]) -> None:
    """Display results with Rich."""
    console = Console()
    summary = monitor.get_summary()

    # Status color
    status_colors = {
        "HEALTHY": "green",
        "DEGRADED": "yellow",
        "DOWN": "red"
    }
    status_color = status_colors.get(summary['status'], "white")

    # Header
    console.print(Panel.fit(
        f"[bold cyan]API Health Monitor[/bold cyan]\n"
        f"[dim]{summary['timestamp']}[/dim]",
        border_style="cyan"
    ))

    # Results table
    table = Table(title="Endpoint Status")
    table.add_column("Status", width=8)
    table.add_column("Name", style="cyan")
    table.add_column("URL")
    table.add_column("Code", justify="center")
    table.add_column("Latency", justify="right")
    table.add_column("SSL", justify="center")
    table.add_column("Message")

    # Find configs for thresholds
    config_map = {ep.url: ep for ep in endpoints}

    for result in monitor.results:
        # Status icon
        if result.success:
            status = "[green]✓ OK[/green]"
        else:
            status = "[red]✗ FAIL[/red]"

        # Latency with color
        if result.latency_ms is not None:
            config = config_map.get(result.url)
            warn_ms = config.latency_warning_ms if config else 1000
            crit_ms = config.latency_critical_ms if config else 3000

            if result.latency_ms > crit_ms:
                latency = f"[red]{result.latency_ms:.0f}ms[/red]"
            elif result.latency_ms > warn_ms:
                latency = f"[yellow]{result.latency_ms:.0f}ms[/yellow]"
            else:
                latency = f"[green]{result.latency_ms:.0f}ms[/green]"
        else:
            latency = "-"

        # SSL status
        if result.ssl_days_remaining is not None:
            if result.ssl_days_remaining < 7:
                ssl_status = f"[red]{result.ssl_days_remaining}d[/red]"
            elif result.ssl_days_remaining < 30:
                ssl_status = f"[yellow]{result.ssl_days_remaining}d[/yellow]"
            else:
                ssl_status = f"[green]{result.ssl_days_remaining}d[/green]"
        elif not result.ssl_valid:
            ssl_status = "[red]Invalid[/red]"
        else:
            ssl_status = "-"

        # Code
        code = str(result.status_code) if result.status_code else "-"

        # Message
        message = result.error if result.error else "OK"
        if len(message) > 30:
            message = message[:27] + "..."

        table.add_row(
            status,
            result.name,
            result.url[:40] + "..." if len(result.url) > 40 else result.url,
            code,
            latency,
            ssl_status,
            message
        )

    console.print(table)

    # Summary
    console.print(f"\n[bold]Summary:[/bold]")
    console.print(f"  Total: {summary['total']} | "
                  f"[green]Healthy: {summary['healthy']}[/green] | "
                  f"[red]Unhealthy: {summary['unhealthy']}[/red]")
    console.print(f"  Avg Latency: {summary['avg_latency_ms']:.0f}ms | "
                  f"SSL Warnings: {summary['ssl_warnings']}")
    console.print(f"  Status: [{status_color}]{summary['status']}[/{status_color}]")


def display_results_simple(monitor: APIHealthMonitor) -> None:
    """Display results in simple format."""
    print("\n" + "=" * 70)
    print("  API HEALTH MONITOR")
    print("=" * 70 + "\n")

    for result in monitor.results:
        status = "[OK]" if result.success else "[FAIL]"
        latency = f"({result.latency_ms:.0f}ms)" if result.latency_ms else ""
        ssl_info = f"[SSL: {result.ssl_days_remaining}d]" if result.ssl_days_remaining else ""

        print(f"{status} {result.name}: {result.status_code or 'N/A'} {latency} {ssl_info}")
        if result.error:
            print(f"     Error: {result.error}")

    summary = monitor.get_summary()
    print("\n" + "-" * 70)
    print(f"Total: {summary['total']} | Healthy: {summary['healthy']} | Unhealthy: {summary['unhealthy']}")
    print(f"Status: {summary['status']}")


def watch_mode(monitor: APIHealthMonitor, endpoints: List[EndpointConfig],
               interval: int, console: Console) -> None:
    """Continuous monitoring mode."""
    try:
        while True:
            monitor.check_all(endpoints)

            # Clear and redisplay
            console.clear()
            display_results_rich(monitor, endpoints)
            console.print(f"\n[dim]Refreshing every {interval}s... Press Ctrl+C to stop[/dim]")

            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/yellow]")


def main():
    parser = argparse.ArgumentParser(
        description="API Health Monitor - Multi-endpoint monitoring",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Configuration file format (YAML):
  endpoints:
    - name: "Production API"
      url: "https://api.example.com/health"
      method: GET
      expected_status: 200
      timeout: 5
      latency_warning_ms: 500
      latency_critical_ms: 2000

    - name: "Auth Service"
      url: "https://auth.example.com/status"
      headers:
        Authorization: "Bearer token123"

Examples:
    %(prog)s -c endpoints.yaml
    %(prog)s -u https://api.example.com/health
    %(prog)s -c endpoints.yaml --watch 30
    %(prog)s -c endpoints.yaml --json
        """
    )

    parser.add_argument('-c', '--config', type=Path, help='Configuration file (YAML)')
    parser.add_argument('-u', '--url', action='append', help='URL to check (can repeat)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('-w', '--watch', type=int, metavar='SEC',
                        help='Watch mode: refresh every N seconds')
    parser.add_argument('-j', '--json', action='store_true', help='Output as JSON')
    parser.add_argument('-s', '--simple', action='store_true', help='Simple output')
    parser.add_argument('--no-ssl-check', action='store_true', help='Skip SSL expiry check')

    args = parser.parse_args()

    # Build endpoint list
    endpoints = []

    if args.config:
        if not args.config.exists():
            print(f"Error: Config file not found: {args.config}")
            sys.exit(1)
        endpoints = load_config(args.config)

    if args.url:
        for i, url in enumerate(args.url):
            endpoints.append(EndpointConfig(
                name=f"Endpoint {i+1}",
                url=url,
                timeout=args.timeout,
                check_ssl_expiry=not args.no_ssl_check
            ))

    # Default endpoints if nothing specified
    if not endpoints:
        endpoints = [
            EndpointConfig(name="Google", url="https://www.google.com"),
            EndpointConfig(name="GitHub", url="https://api.github.com"),
            EndpointConfig(name="Cloudflare", url="https://1.1.1.1/dns-query",
                          headers={"Accept": "application/dns-json"})
        ]

    # Create monitor
    monitor = APIHealthMonitor(timeout=args.timeout)

    # Watch mode
    if args.watch and RICH_AVAILABLE:
        console = Console()
        watch_mode(monitor, endpoints, args.watch, console)
        return

    # Single check
    monitor.check_all(endpoints)

    # Output
    if args.json:
        output = {
            "summary": monitor.get_summary(),
            "results": [
                {
                    "name": r.name,
                    "url": r.url,
                    "success": r.success,
                    "status_code": r.status_code,
                    "latency_ms": r.latency_ms,
                    "ssl_days_remaining": r.ssl_days_remaining,
                    "ssl_valid": r.ssl_valid,
                    "error": r.error,
                    "timestamp": r.timestamp
                }
                for r in monitor.results
            ]
        }
        print(json.dumps(output, indent=2))
    elif args.simple or not RICH_AVAILABLE:
        display_results_simple(monitor)
    else:
        display_results_rich(monitor, endpoints)

    # Exit code based on health
    summary = monitor.get_summary()
    if summary['unhealthy'] > 0:
        sys.exit(1)


if __name__ == '__main__':
    main()
```

---

## Configuration YAML

Exemple `endpoints.yaml`:

```yaml
# API Health Monitor Configuration

endpoints:
  # Production APIs
  - name: "Main API"
    url: "https://api.mycompany.com/health"
    method: GET
    expected_status: 200
    timeout: 5
    latency_warning_ms: 500
    latency_critical_ms: 2000

  - name: "Auth Service"
    url: "https://auth.mycompany.com/status"
    expected_status: 200
    headers:
      Authorization: "Bearer ${AUTH_TOKEN}"
      X-Request-ID: "health-check"

  - name: "Payment Gateway"
    url: "https://payments.mycompany.com/ping"
    method: HEAD
    expected_status: 204
    timeout: 3
    ssl_warning_days: 45

  # External Dependencies
  - name: "Stripe API"
    url: "https://api.stripe.com/v1/health"
    expected_status: 200

  - name: "AWS S3"
    url: "https://s3.amazonaws.com"
    method: HEAD
    expected_status: 405  # S3 returns 405 for HEAD on bucket root

  # Internal Services
  - name: "Redis Health"
    url: "http://localhost:6379/ping"
    verify_ssl: false
    check_ssl_expiry: false
    timeout: 2

  - name: "Database Proxy"
    url: "http://internal-db-proxy:8080/health"
    verify_ssl: false
    check_ssl_expiry: false
```

---

## Utilisation

```bash
# Check par défaut (Google, GitHub, Cloudflare)
python api_health_monitor.py

# Avec fichier de configuration
python api_health_monitor.py -c endpoints.yaml

# URLs en ligne de commande
python api_health_monitor.py -u https://api.example.com -u https://api2.example.com

# Mode surveillance continue (refresh toutes les 30s)
python api_health_monitor.py -c endpoints.yaml --watch 30

# Sortie JSON (pour intégration CI/CD)
python api_health_monitor.py -c endpoints.yaml --json

# Sans vérification SSL
python api_health_monitor.py -u https://self-signed.example.com --no-ssl-check

# Timeout personnalisé
python api_health_monitor.py -c endpoints.yaml -t 15
```

---

## Sortie Exemple

```
╭──────────────────────────────────────────────────────────────────────╮
│                         API Health Monitor                            │
│                      2024-01-15T14:30:22.123456                       │
╰──────────────────────────────────────────────────────────────────────╯

                           Endpoint Status
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━┓
┃ Status   ┃ Name            ┃ URL                  ┃ Code ┃ Latency ┃ SSL  ┃ Message   ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━┩
│ ✓ OK     │ Main API        │ https://api.mycom... │ 200  │   145ms │  89d │ OK        │
│ ✓ OK     │ Auth Service    │ https://auth.myco... │ 200  │   234ms │  89d │ OK        │
│ ✗ FAIL   │ Payment Gateway │ https://payments.... │ 503  │  2341ms │  15d │ Expected  │
│ ✓ OK     │ Stripe API      │ https://api.strip... │ 200  │   456ms │ 120d │ OK        │
│ ✓ OK     │ Redis Health    │ http://localhost:... │ 200  │    12ms │    - │ OK        │
└──────────┴─────────────────┴──────────────────────┴──────┴─────────┴──────┴───────────┘

Summary:
  Total: 5 | Healthy: 4 | Unhealthy: 1
  Avg Latency: 638ms | SSL Warnings: 1
  Status: DEGRADED
```

---

## Intégration CI/CD

```yaml
# GitLab CI
health_check:
  stage: test
  script:
    - pip install requests pyyaml rich
    - python api_health_monitor.py -c endpoints.yaml --json > health_report.json
  artifacts:
    paths:
      - health_report.json
    when: always
```

```yaml
# GitHub Actions
- name: API Health Check
  run: |
    pip install requests pyyaml
    python api_health_monitor.py -c endpoints.yaml --json
  continue-on-error: true
```

---

## Automatisation Cron

```bash
# Check toutes les 5 minutes avec alerte
*/5 * * * * /usr/bin/python3 /opt/scripts/api_health_monitor.py -c /etc/endpoints.yaml --json >> /var/log/api_health.log 2>&1

# Avec notification email en cas d'échec
*/5 * * * * /usr/bin/python3 /opt/scripts/api_health_monitor.py -c /etc/endpoints.yaml || echo "API Health Check Failed" | mail -s "Alert: API Down" ops@example.com
```

---

## Voir Aussi

- [health_checker.py](health_checker.md)
- [cert_checker.py](cert_checker.md)
