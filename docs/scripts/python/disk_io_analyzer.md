---
tags:
  - script
  - python
  - monitoring
  - performance
  - disk
---

# Disk I/O Analyzer

Script Python d'analyse avancée des performances I/O disque.

## Description

- **Monitoring temps réel** : IOPS, throughput, latence par disque
- **Analyse par processus** : Identification des processus les plus I/O intensifs
- **Détection d'anomalies** : Alertes sur latence élevée ou saturation
- **Historique** : Collecte et analyse des tendances
- **Export Prometheus** : Métriques pour monitoring externe
- **Rapport détaillé** : HTML/JSON avec graphiques

## Prérequis

```bash
pip install rich psutil pyyaml
```

## Utilisation

```bash
# Analyse instantanée
python disk_io_analyzer.py

# Mode watch (rafraîchissement continu)
python disk_io_analyzer.py --watch --interval 2

# Analyse par processus
python disk_io_analyzer.py --processes

# Analyse d'un disque spécifique
python disk_io_analyzer.py --disk sda

# Export JSON pour CI/CD
python disk_io_analyzer.py --format json --output io-report.json

# Mode benchmark (test de performance)
python disk_io_analyzer.py --benchmark /tmp

# Prometheus metrics
python disk_io_analyzer.py --prometheus --port 9200
```

## Configuration

Fichier `io_analyzer.yaml` :

```yaml
thresholds:
  latency_warning_ms: 20
  latency_critical_ms: 100
  iops_warning: 5000
  utilization_warning: 80
  utilization_critical: 95

monitoring:
  interval_seconds: 5
  history_size: 1000  # Points to keep

alerting:
  enabled: true
  webhook_url: ""

prometheus:
  enabled: false
  port: 9200
```

## Code Source

```python
#!/usr/bin/env python3
"""
Disk I/O Analyzer - Advanced disk performance analysis tool.

Features:
- Real-time I/O monitoring (IOPS, throughput, latency)
- Per-process I/O analysis
- Anomaly detection
- Historical trends
- Prometheus metrics export
"""

import os
import sys
import time
import threading
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import deque

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.layout import Layout
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    import psutil
    import yaml
except ImportError:
    print("Missing dependencies. Install with: pip install rich psutil pyyaml")
    sys.exit(1)

console = Console()

# =============================================================================
# Data Models
# =============================================================================

@dataclass
class DiskStats:
    """Statistics for a single disk."""
    device: str
    read_iops: float = 0.0
    write_iops: float = 0.0
    read_throughput_mb: float = 0.0
    write_throughput_mb: float = 0.0
    read_latency_ms: float = 0.0
    write_latency_ms: float = 0.0
    utilization: float = 0.0
    queue_depth: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def total_iops(self) -> float:
        return self.read_iops + self.write_iops

    @property
    def total_throughput_mb(self) -> float:
        return self.read_throughput_mb + self.write_throughput_mb

    @property
    def avg_latency_ms(self) -> float:
        if self.total_iops > 0:
            return (self.read_latency_ms + self.write_latency_ms) / 2
        return 0.0

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "read_iops": round(self.read_iops, 2),
            "write_iops": round(self.write_iops, 2),
            "total_iops": round(self.total_iops, 2),
            "read_throughput_mb": round(self.read_throughput_mb, 2),
            "write_throughput_mb": round(self.write_throughput_mb, 2),
            "total_throughput_mb": round(self.total_throughput_mb, 2),
            "read_latency_ms": round(self.read_latency_ms, 3),
            "write_latency_ms": round(self.write_latency_ms, 3),
            "utilization": round(self.utilization, 1),
            "queue_depth": round(self.queue_depth, 2),
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ProcessIOStats:
    """I/O statistics for a process."""
    pid: int
    name: str
    read_bytes: int = 0
    write_bytes: int = 0
    read_rate_mb: float = 0.0
    write_rate_mb: float = 0.0

    @property
    def total_rate_mb(self) -> float:
        return self.read_rate_mb + self.write_rate_mb

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "name": self.name,
            "read_bytes": self.read_bytes,
            "write_bytes": self.write_bytes,
            "read_rate_mb": round(self.read_rate_mb, 2),
            "write_rate_mb": round(self.write_rate_mb, 2),
            "total_rate_mb": round(self.total_rate_mb, 2)
        }


@dataclass
class Alert:
    """I/O alert."""
    timestamp: datetime
    device: str
    metric: str
    value: float
    threshold: float
    severity: str  # warning, critical

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "device": self.device,
            "metric": self.metric,
            "value": round(self.value, 2),
            "threshold": self.threshold,
            "severity": self.severity
        }


# =============================================================================
# Disk I/O Collector
# =============================================================================

class DiskIOCollector:
    """Collect disk I/O statistics."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.thresholds = self.config.get("thresholds", {
            "latency_warning_ms": 20,
            "latency_critical_ms": 100,
            "iops_warning": 5000,
            "utilization_warning": 80,
            "utilization_critical": 95
        })
        self.history: dict = {}  # device -> deque of DiskStats
        self.history_size = self.config.get("monitoring", {}).get("history_size", 1000)
        self.alerts: list = []
        self._prev_counters: dict = {}
        self._prev_time: float = time.time()

    def collect(self) -> list:
        """Collect current disk I/O statistics."""
        stats = []
        current_time = time.time()
        interval = current_time - self._prev_time

        if interval < 0.1:
            return stats

        try:
            counters = psutil.disk_io_counters(perdisk=True)
        except Exception:
            return stats

        for device, counter in counters.items():
            # Skip partitions, only use whole disks
            if any(c.isdigit() for c in device) and not device.startswith("nvme"):
                continue
            if device.startswith("loop") or device.startswith("dm-"):
                continue

            # Calculate deltas
            prev = self._prev_counters.get(device)
            if prev:
                read_ios = counter.read_count - prev.read_count
                write_ios = counter.write_count - prev.write_count
                read_bytes = counter.read_bytes - prev.read_bytes
                write_bytes = counter.write_bytes - prev.write_bytes
                read_time = counter.read_time - prev.read_time
                write_time = counter.write_time - prev.write_time

                # Calculate rates
                read_iops = read_ios / interval
                write_iops = write_ios / interval
                read_throughput = read_bytes / interval / (1024 * 1024)
                write_throughput = write_bytes / interval / (1024 * 1024)

                # Calculate latencies (ms per operation)
                read_latency = (read_time / read_ios) if read_ios > 0 else 0
                write_latency = (write_time / write_ios) if write_ios > 0 else 0

                # Utilization (percentage of time doing I/O)
                busy_time = (read_time + write_time - prev.read_time - prev.write_time) if hasattr(counter, 'busy_time') else 0
                utilization = min(100, (busy_time / (interval * 1000)) * 100) if busy_time else 0

                disk_stats = DiskStats(
                    device=device,
                    read_iops=read_iops,
                    write_iops=write_iops,
                    read_throughput_mb=read_throughput,
                    write_throughput_mb=write_throughput,
                    read_latency_ms=read_latency,
                    write_latency_ms=write_latency,
                    utilization=utilization,
                    queue_depth=self._get_queue_depth(device),
                    timestamp=datetime.now()
                )

                stats.append(disk_stats)

                # Store in history
                if device not in self.history:
                    self.history[device] = deque(maxlen=self.history_size)
                self.history[device].append(disk_stats)

                # Check thresholds and generate alerts
                self._check_alerts(disk_stats)

            self._prev_counters[device] = counter

        self._prev_time = current_time
        return stats

    def _get_queue_depth(self, device: str) -> float:
        """Get current I/O queue depth from sysfs."""
        try:
            # Handle NVMe naming
            base_device = device.replace("p", "").rstrip("0123456789") if "nvme" in device else device
            queue_path = Path(f"/sys/block/{base_device}/queue/nr_requests")
            if queue_path.exists():
                return float(queue_path.read_text().strip())
        except Exception:
            pass
        return 0.0

    def _check_alerts(self, stats: DiskStats):
        """Check thresholds and generate alerts."""
        # Latency alerts
        if stats.avg_latency_ms > self.thresholds.get("latency_critical_ms", 100):
            self.alerts.append(Alert(
                timestamp=datetime.now(),
                device=stats.device,
                metric="latency",
                value=stats.avg_latency_ms,
                threshold=self.thresholds["latency_critical_ms"],
                severity="critical"
            ))
        elif stats.avg_latency_ms > self.thresholds.get("latency_warning_ms", 20):
            self.alerts.append(Alert(
                timestamp=datetime.now(),
                device=stats.device,
                metric="latency",
                value=stats.avg_latency_ms,
                threshold=self.thresholds["latency_warning_ms"],
                severity="warning"
            ))

        # Utilization alerts
        if stats.utilization > self.thresholds.get("utilization_critical", 95):
            self.alerts.append(Alert(
                timestamp=datetime.now(),
                device=stats.device,
                metric="utilization",
                value=stats.utilization,
                threshold=self.thresholds["utilization_critical"],
                severity="critical"
            ))
        elif stats.utilization > self.thresholds.get("utilization_warning", 80):
            self.alerts.append(Alert(
                timestamp=datetime.now(),
                device=stats.device,
                metric="utilization",
                value=stats.utilization,
                threshold=self.thresholds["utilization_warning"],
                severity="warning"
            ))

        # Keep only recent alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]


# =============================================================================
# Process I/O Analyzer
# =============================================================================

class ProcessIOAnalyzer:
    """Analyze I/O by process."""

    def __init__(self):
        self._prev_io: dict = {}
        self._prev_time: float = time.time()

    def collect_top_processes(self, limit: int = 10) -> list:
        """Get top processes by I/O rate."""
        current_time = time.time()
        interval = current_time - self._prev_time

        if interval < 0.1:
            return []

        processes = []

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']

                io_counters = proc.io_counters()
                prev = self._prev_io.get(pid)

                if prev:
                    read_rate = (io_counters.read_bytes - prev[0]) / interval / (1024 * 1024)
                    write_rate = (io_counters.write_bytes - prev[1]) / interval / (1024 * 1024)

                    if read_rate > 0.01 or write_rate > 0.01:  # Filter noise
                        processes.append(ProcessIOStats(
                            pid=pid,
                            name=name,
                            read_bytes=io_counters.read_bytes,
                            write_bytes=io_counters.write_bytes,
                            read_rate_mb=read_rate,
                            write_rate_mb=write_rate
                        ))

                self._prev_io[pid] = (io_counters.read_bytes, io_counters.write_bytes)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self._prev_time = current_time

        # Sort by total I/O rate
        processes.sort(key=lambda p: p.total_rate_mb, reverse=True)
        return processes[:limit]


# =============================================================================
# Benchmark Module
# =============================================================================

class DiskBenchmark:
    """Simple disk benchmark."""

    def __init__(self, path: str):
        self.path = Path(path)
        self.test_file = self.path / ".io_benchmark_test"

    def run(self, size_mb: int = 100) -> dict:
        """Run basic read/write benchmark."""
        results = {
            "path": str(self.path),
            "test_size_mb": size_mb,
            "timestamp": datetime.now().isoformat()
        }

        console.print(f"[blue]Running benchmark on {self.path}...[/blue]")

        # Write test
        data = os.urandom(1024 * 1024)  # 1MB random data
        start = time.time()

        with open(self.test_file, 'wb') as f:
            for _ in range(size_mb):
                f.write(data)
                f.flush()
                os.fsync(f.fileno())

        write_time = time.time() - start
        results["write_throughput_mb"] = round(size_mb / write_time, 2)
        results["write_time_seconds"] = round(write_time, 2)

        console.print(f"  Write: {results['write_throughput_mb']} MB/s")

        # Read test
        start = time.time()
        with open(self.test_file, 'rb') as f:
            while f.read(1024 * 1024):
                pass

        read_time = time.time() - start
        results["read_throughput_mb"] = round(size_mb / read_time, 2)
        results["read_time_seconds"] = round(read_time, 2)

        console.print(f"  Read: {results['read_throughput_mb']} MB/s")

        # IOPS test (4K random)
        start = time.time()
        iops_count = 1000

        with open(self.test_file, 'r+b') as f:
            for i in range(iops_count):
                f.seek((i * 4096) % (size_mb * 1024 * 1024))
                f.read(4096)

        iops_time = time.time() - start
        results["read_iops_4k"] = round(iops_count / iops_time, 0)

        console.print(f"  4K Random Read IOPS: {results['read_iops_4k']}")

        # Cleanup
        try:
            self.test_file.unlink()
        except Exception:
            pass

        return results


# =============================================================================
# Prometheus Exporter
# =============================================================================

class PrometheusExporter:
    """Export metrics in Prometheus format."""

    def __init__(self, collector: DiskIOCollector, port: int = 9200):
        self.collector = collector
        self.port = port
        self._server = None

    def start(self):
        """Start HTTP server for Prometheus scraping."""
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import threading

        class MetricsHandler(BaseHTTPRequestHandler):
            def __init__(self, collector, *args, **kwargs):
                self.collector = collector
                super().__init__(*args, **kwargs)

            def do_GET(self):
                if self.path == '/metrics':
                    metrics = self._generate_metrics()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(metrics.encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def _generate_metrics(self):
                lines = [
                    "# HELP disk_read_iops Disk read IOPS",
                    "# TYPE disk_read_iops gauge",
                    "# HELP disk_write_iops Disk write IOPS",
                    "# TYPE disk_write_iops gauge",
                    "# HELP disk_read_throughput_bytes Disk read throughput in bytes/sec",
                    "# TYPE disk_read_throughput_bytes gauge",
                    "# HELP disk_write_throughput_bytes Disk write throughput in bytes/sec",
                    "# TYPE disk_write_throughput_bytes gauge",
                    "# HELP disk_latency_ms Disk latency in milliseconds",
                    "# TYPE disk_latency_ms gauge",
                    "# HELP disk_utilization Disk utilization percentage",
                    "# TYPE disk_utilization gauge"
                ]

                stats = self.collector.collect()
                for s in stats:
                    lines.append(f'disk_read_iops{{device="{s.device}"}} {s.read_iops}')
                    lines.append(f'disk_write_iops{{device="{s.device}"}} {s.write_iops}')
                    lines.append(f'disk_read_throughput_bytes{{device="{s.device}"}} {s.read_throughput_mb * 1024 * 1024}')
                    lines.append(f'disk_write_throughput_bytes{{device="{s.device}"}} {s.write_throughput_mb * 1024 * 1024}')
                    lines.append(f'disk_latency_ms{{device="{s.device}",type="read"}} {s.read_latency_ms}')
                    lines.append(f'disk_latency_ms{{device="{s.device}",type="write"}} {s.write_latency_ms}')
                    lines.append(f'disk_utilization{{device="{s.device}"}} {s.utilization}')

                return "\n".join(lines) + "\n"

            def log_message(self, format, *args):
                pass  # Suppress logging

        def handler(*args, **kwargs):
            MetricsHandler(self.collector, *args, **kwargs)

        self._server = HTTPServer(('', self.port), handler)
        thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        thread.start()
        console.print(f"[green]Prometheus metrics available at http://localhost:{self.port}/metrics[/green]")

    def stop(self):
        if self._server:
            self._server.shutdown()


# =============================================================================
# Display Functions
# =============================================================================

def create_dashboard(disk_stats: list, process_stats: list, alerts: list) -> Layout:
    """Create rich dashboard layout."""
    layout = Layout()

    # Disk stats table
    disk_table = Table(title="💾 Disk I/O Statistics", expand=True)
    disk_table.add_column("Device", style="cyan", width=12)
    disk_table.add_column("Read IOPS", justify="right", width=10)
    disk_table.add_column("Write IOPS", justify="right", width=10)
    disk_table.add_column("Read MB/s", justify="right", width=10)
    disk_table.add_column("Write MB/s", justify="right", width=10)
    disk_table.add_column("Latency", justify="right", width=10)
    disk_table.add_column("Util %", justify="right", width=8)

    for stats in disk_stats:
        latency_style = "green"
        if stats.avg_latency_ms > 100:
            latency_style = "bold red"
        elif stats.avg_latency_ms > 20:
            latency_style = "yellow"

        util_style = "green"
        if stats.utilization > 95:
            util_style = "bold red"
        elif stats.utilization > 80:
            util_style = "yellow"

        disk_table.add_row(
            stats.device,
            f"{stats.read_iops:.0f}",
            f"{stats.write_iops:.0f}",
            f"{stats.read_throughput_mb:.1f}",
            f"{stats.write_throughput_mb:.1f}",
            f"[{latency_style}]{stats.avg_latency_ms:.1f}ms[/]",
            f"[{util_style}]{stats.utilization:.0f}%[/]"
        )

    # Process table
    proc_table = Table(title="📊 Top I/O Processes", expand=True)
    proc_table.add_column("PID", style="dim", width=8)
    proc_table.add_column("Process", style="cyan", width=20)
    proc_table.add_column("Read MB/s", justify="right", width=12)
    proc_table.add_column("Write MB/s", justify="right", width=12)
    proc_table.add_column("Total MB/s", justify="right", width=12)

    for proc in process_stats[:8]:
        proc_table.add_row(
            str(proc.pid),
            proc.name[:20],
            f"{proc.read_rate_mb:.2f}",
            f"{proc.write_rate_mb:.2f}",
            f"[bold]{proc.total_rate_mb:.2f}[/]"
        )

    return disk_table, proc_table


def display_snapshot(collector: DiskIOCollector, proc_analyzer: ProcessIOAnalyzer):
    """Display single snapshot of I/O statistics."""
    # Collect data (need two collections for rate calculation)
    collector.collect()
    proc_analyzer.collect_top_processes()
    time.sleep(1)

    disk_stats = collector.collect()
    process_stats = proc_analyzer.collect_top_processes()

    disk_table, proc_table = create_dashboard(disk_stats, process_stats, collector.alerts)

    console.print(Panel(
        disk_table,
        title="[bold blue]Disk I/O Analyzer[/bold blue]",
        border_style="blue"
    ))

    console.print(proc_table)

    # Show recent alerts
    if collector.alerts:
        console.print("\n[bold red]⚠ Recent Alerts:[/bold red]")
        for alert in collector.alerts[-5:]:
            console.print(f"  [{alert.severity.upper()}] {alert.device}: {alert.metric} = {alert.value:.2f} (threshold: {alert.threshold})")


def watch_mode(collector: DiskIOCollector, proc_analyzer: ProcessIOAnalyzer, interval: float = 2.0):
    """Continuous monitoring mode."""
    console.print("[bold]Starting watch mode. Press Ctrl+C to exit.[/bold]\n")

    # Initial collection
    collector.collect()
    proc_analyzer.collect_top_processes()
    time.sleep(0.5)

    try:
        with Live(console=console, refresh_per_second=1) as live:
            while True:
                disk_stats = collector.collect()
                process_stats = proc_analyzer.collect_top_processes()

                disk_table, proc_table = create_dashboard(disk_stats, process_stats, collector.alerts)

                # Build layout
                layout = Layout()
                layout.split_column(
                    Layout(Panel(disk_table, title="[bold blue]Disk I/O Analyzer - Watch Mode[/bold blue]", border_style="blue")),
                    Layout(proc_table)
                )

                live.update(layout)
                time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[yellow]Watch mode stopped.[/yellow]")


# =============================================================================
# Export Functions
# =============================================================================

def export_json(collector: DiskIOCollector, proc_analyzer: ProcessIOAnalyzer, output_path: str):
    """Export current statistics to JSON."""
    import json

    # Collect fresh data
    collector.collect()
    proc_analyzer.collect_top_processes()
    time.sleep(1)

    disk_stats = collector.collect()
    process_stats = proc_analyzer.collect_top_processes()

    data = {
        "timestamp": datetime.now().isoformat(),
        "hostname": os.uname().nodename if hasattr(os, 'uname') else "unknown",
        "disks": [s.to_dict() for s in disk_stats],
        "top_processes": [p.to_dict() for p in process_stats],
        "alerts": [a.to_dict() for a in collector.alerts[-10:]]
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]JSON report exported:[/green] {output_path}")


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Disk I/O Analyzer - Advanced disk performance analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-c", "--config", help="Configuration file (YAML)")
    parser.add_argument("-w", "--watch", action="store_true",
                        help="Continuous monitoring mode")
    parser.add_argument("-i", "--interval", type=float, default=2.0,
                        help="Refresh interval in seconds (default: 2)")
    parser.add_argument("-p", "--processes", action="store_true",
                        help="Show per-process I/O")
    parser.add_argument("-d", "--disk", help="Monitor specific disk only")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", choices=["table", "json"],
                        default="table", help="Output format")
    parser.add_argument("--benchmark", metavar="PATH",
                        help="Run benchmark on specified path")
    parser.add_argument("--prometheus", action="store_true",
                        help="Enable Prometheus metrics endpoint")
    parser.add_argument("--port", type=int, default=9200,
                        help="Prometheus metrics port (default: 9200)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress terminal output")
    parser.add_argument("-v", "--version", action="version",
                        version="disk-io-analyzer 1.0.0")

    args = parser.parse_args()

    # Load config
    config = {}
    if args.config:
        with open(args.config) as f:
            config = yaml.safe_load(f)

    console.print("[bold blue]💾 Disk I/O Analyzer[/bold blue]\n")

    # Benchmark mode
    if args.benchmark:
        benchmark = DiskBenchmark(args.benchmark)
        results = benchmark.run()
        if args.output:
            import json
            with open(args.output, "w") as f:
                json.dump(results, f, indent=2)
        return

    # Initialize collectors
    collector = DiskIOCollector(config)
    proc_analyzer = ProcessIOAnalyzer()

    # Prometheus mode
    if args.prometheus:
        exporter = PrometheusExporter(collector, args.port)
        exporter.start()
        console.print("[yellow]Running in Prometheus mode. Press Ctrl+C to exit.[/yellow]")
        try:
            while True:
                collector.collect()
                time.sleep(5)
        except KeyboardInterrupt:
            exporter.stop()
        return

    # JSON export
    if args.format == "json" and args.output:
        export_json(collector, proc_analyzer, args.output)
        return

    # Watch mode or snapshot
    if args.watch:
        watch_mode(collector, proc_analyzer, args.interval)
    else:
        display_snapshot(collector, proc_analyzer)


if __name__ == "__main__":
    main()
```

## Exemple de Sortie

```text
💾 Disk I/O Analyzer

╭──────────────────────── Disk I/O Statistics ────────────────────────╮
│ Device   │ Read IOPS │ Write IOPS │ Read MB/s │ Write MB/s │ Latency │ Util % │
├──────────┼───────────┼────────────┼───────────┼────────────┼─────────┼────────┤
│ nvme0n1  │     1,234 │        567 │     48.5  │      22.3  │  0.8ms  │   45%  │
│ sda      │       234 │        123 │      9.2  │       4.8  │ 12.5ms  │   78%  │
╰──────────┴───────────┴────────────┴───────────┴────────────┴─────────┴────────╯

📊 Top I/O Processes
┌─────────┬──────────────────────┬────────────┬─────────────┬────────────┐
│ PID     │ Process              │ Read MB/s  │ Write MB/s  │ Total MB/s │
├─────────┼──────────────────────┼────────────┼─────────────┼────────────┤
│ 1234    │ mysqld               │ 25.50      │ 12.30       │ 37.80      │
│ 5678    │ rsync                │ 18.20      │ 0.10        │ 18.30      │
│ 9012    │ elasticsearch        │ 8.50       │ 4.20        │ 12.70      │
└─────────┴──────────────────────┴────────────┴─────────────┴────────────┘
```

## Intégration

### Prometheus + Grafana

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'disk_io'
    static_configs:
      - targets: ['localhost:9200']
```

### Alertmanager

```yaml
groups:
  - name: disk_io
    rules:
      - alert: HighDiskLatency
        expr: disk_latency_ms > 100
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High disk latency on {{ $labels.device }}"
```

## Cas d'Usage

1. **Performance Debugging** : Identifier les bottlenecks I/O
2. **Capacity Planning** : Surveiller l'utilisation des disques
3. **Application Profiling** : Identifier les processus I/O intensifs
4. **SLA Monitoring** : Alerter sur les latences anormales

## Voir Aussi

- [system_tuning_advisor.py](./system_tuning_advisor.md) - Recommandations tuning kernel/sysctl
- [system_info.py](./system_info.md) - Informations système complètes
- [health_checker.py](./health_checker.md) - Vérification santé services
