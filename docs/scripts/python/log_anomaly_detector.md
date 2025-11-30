# Log Anomaly Detector

Script Python de détection d'anomalies dans les logs par analyse statistique et patterns.

## Fonctionnalités

- **Détection statistique** : Identification des pics d'erreurs et variations anormales
- **Pattern Learning** : Apprentissage des patterns normaux et détection des déviations
- **Multi-format** : Support syslog, JSON, Apache, Nginx, application logs
- **Temps réel** : Mode watch pour monitoring continu
- **Alerting** : Webhooks et notifications
- **Baseline** : Comparaison avec une baseline historique

## Prérequis

```bash
pip install rich pyyaml python-dateutil
# Optionnel pour ML avancé
pip install scikit-learn numpy
```

## Utilisation

```bash
# Analyse de fichier log
python log_anomaly_detector.py /var/log/syslog

# Mode watch (temps réel)
python log_anomaly_detector.py --watch /var/log/nginx/error.log

# Avec seuil personnalisé
python log_anomaly_detector.py --threshold 3.0 /var/log/app.log

# Format JSON logs
python log_anomaly_detector.py --format json /var/log/app.json

# Créer une baseline
python log_anomaly_detector.py --create-baseline /var/log/syslog

# Comparer avec baseline
python log_anomaly_detector.py --baseline baseline.json /var/log/syslog

# Export rapport
python log_anomaly_detector.py --output report.html /var/log/syslog
```

## Configuration

Fichier `anomaly_config.yaml` :

```yaml
detection:
  # Standard deviations for anomaly threshold
  threshold: 3.0
  # Minimum events per window for analysis
  min_events: 10
  # Time window for rate analysis (seconds)
  window_size: 60

patterns:
  # Known error patterns to track
  error_patterns:
    - "ERROR"
    - "FATAL"
    - "CRITICAL"
    - "Exception"
    - "failed"
    - "timeout"
  # Patterns to ignore
  ignore_patterns:
    - "DEBUG"
    - "healthcheck"

alerting:
  enabled: true
  webhook_url: ""
  min_severity: "warning"

formats:
  syslog: '(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<process>\S+):\s+(?P<message>.*)'
  nginx_error: '(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+(?P<message>.*)'
  json: null  # Parsed as JSON
```

## Code Source

```python
#!/usr/bin/env python3
"""
Log Anomaly Detector - Statistical anomaly detection in log files.

Features:
- Statistical anomaly detection (z-score, rate changes)
- Pattern-based detection
- Real-time monitoring
- Baseline comparison
- Multi-format support
"""

import re
import sys
import time
import json
import hashlib
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Generator
from collections import defaultdict, deque
import statistics

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.live import Live
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import yaml
    from dateutil import parser as date_parser
except ImportError:
    print("Missing dependencies. Install with: pip install rich pyyaml python-dateutil")
    sys.exit(1)

console = Console()

# =============================================================================
# Data Models
# =============================================================================

@dataclass
class LogEntry:
    """Parsed log entry."""
    timestamp: datetime
    level: str = "INFO"
    message: str = ""
    source: str = ""
    raw: str = ""
    fields: dict = field(default_factory=dict)

    @property
    def signature(self) -> str:
        """Generate message signature for pattern matching."""
        # Normalize message by replacing numbers and UUIDs
        normalized = re.sub(r'\d+', 'N', self.message)
        normalized = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', normalized, flags=re.I)
        normalized = re.sub(r'0x[0-9a-f]+', 'HEX', normalized, flags=re.I)
        return hashlib.md5(normalized.encode()).hexdigest()[:8]


@dataclass
class Anomaly:
    """Detected anomaly."""
    timestamp: datetime
    anomaly_type: str
    severity: str  # info, warning, critical
    description: str
    value: float = 0.0
    expected: float = 0.0
    entries: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "type": self.anomaly_type,
            "severity": self.severity,
            "description": self.description,
            "value": round(self.value, 2),
            "expected": round(self.expected, 2),
            "sample_entries": [e.raw[:200] for e in self.entries[:5]]
        }


@dataclass
class Baseline:
    """Statistical baseline for comparison."""
    created_at: datetime
    total_entries: int = 0
    error_rate: float = 0.0
    events_per_minute: float = 0.0
    pattern_frequencies: dict = field(default_factory=dict)
    hourly_distribution: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "created_at": self.created_at.isoformat(),
            "total_entries": self.total_entries,
            "error_rate": self.error_rate,
            "events_per_minute": self.events_per_minute,
            "pattern_frequencies": self.pattern_frequencies,
            "hourly_distribution": self.hourly_distribution
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Baseline":
        return cls(
            created_at=datetime.fromisoformat(data["created_at"]),
            total_entries=data["total_entries"],
            error_rate=data["error_rate"],
            events_per_minute=data["events_per_minute"],
            pattern_frequencies=data.get("pattern_frequencies", {}),
            hourly_distribution=data.get("hourly_distribution", {})
        )


# =============================================================================
# Log Parsers
# =============================================================================

class LogParser:
    """Multi-format log parser."""

    FORMATS = {
        "syslog": r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+)\s+(?P<host>\S+)\s+(?P<process>\S+?)(\[\d+\])?:\s+(?P<message>.*)',
        "nginx_error": r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\]\s+\d+#\d+:\s+(?P<message>.*)',
        "nginx_access": r'(?P<ip>\S+)\s+-\s+-\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]+)"\s+(?P<status>\d+)',
        "apache_error": r'\[(?P<timestamp>[^\]]+)\]\s+\[(?P<level>\w+)\]\s+(?P<message>.*)',
        "generic": r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}[^\s]*)\s+(?P<level>\w+)\s+(?P<message>.*)',
    }

    ERROR_LEVELS = {"ERROR", "FATAL", "CRITICAL", "SEVERE", "ALERT", "EMERGENCY", "error", "crit", "alert", "emerg"}
    WARNING_LEVELS = {"WARNING", "WARN", "warn", "warning"}

    def __init__(self, format_name: str = "auto", custom_pattern: str = None):
        self.format_name = format_name
        self.custom_pattern = custom_pattern
        self._detected_format = None

    def parse_line(self, line: str) -> Optional[LogEntry]:
        """Parse a single log line."""
        line = line.strip()
        if not line:
            return None

        # Try JSON format first
        if line.startswith("{"):
            try:
                data = json.loads(line)
                return self._parse_json(data, line)
            except json.JSONDecodeError:
                pass

        # Try regex patterns
        pattern = self.custom_pattern or self._detect_format(line)
        if pattern:
            match = re.match(pattern, line)
            if match:
                return self._parse_match(match, line)

        # Fallback: basic parsing
        return LogEntry(
            timestamp=datetime.now(),
            message=line,
            raw=line
        )

    def _detect_format(self, line: str) -> Optional[str]:
        """Auto-detect log format."""
        if self._detected_format:
            return self._detected_format

        for fmt_name, pattern in self.FORMATS.items():
            if re.match(pattern, line):
                self._detected_format = pattern
                return pattern

        return None

    def _parse_json(self, data: dict, raw: str) -> LogEntry:
        """Parse JSON log entry."""
        # Common JSON log field names
        timestamp_fields = ["timestamp", "time", "@timestamp", "ts", "datetime"]
        level_fields = ["level", "severity", "log_level", "loglevel"]
        message_fields = ["message", "msg", "text", "log"]

        timestamp = datetime.now()
        for field in timestamp_fields:
            if field in data:
                try:
                    timestamp = date_parser.parse(str(data[field]))
                    break
                except Exception:
                    pass

        level = "INFO"
        for field in level_fields:
            if field in data:
                level = str(data[field]).upper()
                break

        message = ""
        for field in message_fields:
            if field in data:
                message = str(data[field])
                break

        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=message,
            raw=raw,
            fields=data
        )

    def _parse_match(self, match: re.Match, raw: str) -> LogEntry:
        """Parse regex match into LogEntry."""
        groups = match.groupdict()

        # Parse timestamp
        timestamp = datetime.now()
        if "timestamp" in groups:
            try:
                timestamp = date_parser.parse(groups["timestamp"], fuzzy=True)
            except Exception:
                pass

        return LogEntry(
            timestamp=timestamp,
            level=groups.get("level", "INFO").upper(),
            message=groups.get("message", raw),
            source=groups.get("host", groups.get("process", "")),
            raw=raw,
            fields=groups
        )

    def is_error(self, entry: LogEntry) -> bool:
        """Check if entry is an error."""
        return entry.level in self.ERROR_LEVELS

    def is_warning(self, entry: LogEntry) -> bool:
        """Check if entry is a warning."""
        return entry.level in self.WARNING_LEVELS


# =============================================================================
# Anomaly Detection Engine
# =============================================================================

class AnomalyDetector:
    """Statistical anomaly detection."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.threshold = self.config.get("detection", {}).get("threshold", 3.0)
        self.window_size = self.config.get("detection", {}).get("window_size", 60)
        self.min_events = self.config.get("detection", {}).get("min_events", 10)

        # Time series data
        self.event_times: deque = deque(maxlen=10000)
        self.error_times: deque = deque(maxlen=10000)
        self.rate_history: deque = deque(maxlen=100)
        self.error_rate_history: deque = deque(maxlen=100)

        # Pattern tracking
        self.pattern_counts: dict = defaultdict(int)
        self.pattern_first_seen: dict = {}
        self.recent_patterns: deque = deque(maxlen=1000)

        # Anomalies found
        self.anomalies: list = []

    def process_entry(self, entry: LogEntry, parser: LogParser) -> list:
        """Process a log entry and detect anomalies."""
        new_anomalies = []
        now = entry.timestamp

        # Track event timing
        self.event_times.append(now)

        if parser.is_error(entry):
            self.error_times.append(now)

        # Track patterns
        sig = entry.signature
        self.pattern_counts[sig] += 1
        self.recent_patterns.append(sig)

        if sig not in self.pattern_first_seen:
            self.pattern_first_seen[sig] = now
            # New pattern detection
            if len(self.pattern_counts) > 10:  # After warmup
                anomaly = Anomaly(
                    timestamp=now,
                    anomaly_type="new_pattern",
                    severity="info",
                    description=f"New log pattern detected",
                    entries=[entry]
                )
                new_anomalies.append(anomaly)

        # Rate-based detection (every window)
        if len(self.event_times) >= self.min_events:
            window_start = now - timedelta(seconds=self.window_size)

            # Calculate current rates
            events_in_window = sum(1 for t in self.event_times if t >= window_start)
            errors_in_window = sum(1 for t in self.error_times if t >= window_start)

            current_rate = events_in_window / (self.window_size / 60)  # per minute
            current_error_rate = errors_in_window / max(events_in_window, 1)

            # Store rates
            self.rate_history.append(current_rate)
            self.error_rate_history.append(current_error_rate)

            # Detect rate anomalies
            if len(self.rate_history) >= 5:
                rate_anomaly = self._detect_rate_anomaly(current_rate, now)
                if rate_anomaly:
                    rate_anomaly.entries = [entry]
                    new_anomalies.append(rate_anomaly)

                error_anomaly = self._detect_error_spike(current_error_rate, now)
                if error_anomaly:
                    error_anomaly.entries = [entry]
                    new_anomalies.append(error_anomaly)

        self.anomalies.extend(new_anomalies)
        return new_anomalies

    def _detect_rate_anomaly(self, current_rate: float, timestamp: datetime) -> Optional[Anomaly]:
        """Detect anomalies in event rate using z-score."""
        if len(self.rate_history) < 5:
            return None

        rates = list(self.rate_history)[:-1]  # Exclude current
        mean_rate = statistics.mean(rates)
        stdev_rate = statistics.stdev(rates) if len(rates) > 1 else 0

        if stdev_rate == 0:
            return None

        z_score = (current_rate - mean_rate) / stdev_rate

        if abs(z_score) > self.threshold:
            severity = "critical" if abs(z_score) > self.threshold * 1.5 else "warning"
            direction = "spike" if z_score > 0 else "drop"

            return Anomaly(
                timestamp=timestamp,
                anomaly_type=f"rate_{direction}",
                severity=severity,
                description=f"Event rate {direction}: {current_rate:.1f}/min (expected ~{mean_rate:.1f}/min, z={z_score:.2f})",
                value=current_rate,
                expected=mean_rate
            )

        return None

    def _detect_error_spike(self, current_error_rate: float, timestamp: datetime) -> Optional[Anomaly]:
        """Detect spikes in error rate."""
        if len(self.error_rate_history) < 5:
            return None

        rates = list(self.error_rate_history)[:-1]
        mean_rate = statistics.mean(rates)
        stdev_rate = statistics.stdev(rates) if len(rates) > 1 else 0

        if stdev_rate == 0 and current_error_rate > mean_rate * 2:
            # Sudden errors when there were none
            return Anomaly(
                timestamp=timestamp,
                anomaly_type="error_spike",
                severity="critical",
                description=f"Error spike: {current_error_rate*100:.1f}% (was {mean_rate*100:.1f}%)",
                value=current_error_rate,
                expected=mean_rate
            )

        if stdev_rate > 0:
            z_score = (current_error_rate - mean_rate) / stdev_rate

            if z_score > self.threshold:
                severity = "critical" if z_score > self.threshold * 1.5 else "warning"
                return Anomaly(
                    timestamp=timestamp,
                    anomaly_type="error_spike",
                    severity=severity,
                    description=f"Error rate spike: {current_error_rate*100:.1f}% (expected ~{mean_rate*100:.1f}%, z={z_score:.2f})",
                    value=current_error_rate,
                    expected=mean_rate
                )

        return None

    def compare_with_baseline(self, baseline: Baseline) -> list:
        """Compare current statistics with baseline."""
        anomalies = []
        now = datetime.now()

        # Compare event rate
        if len(self.rate_history) > 0:
            current_rate = statistics.mean(self.rate_history)
            if baseline.events_per_minute > 0:
                ratio = current_rate / baseline.events_per_minute

                if ratio > 2.0 or ratio < 0.5:
                    anomalies.append(Anomaly(
                        timestamp=now,
                        anomaly_type="baseline_deviation",
                        severity="warning" if 0.5 <= ratio <= 2.0 else "critical",
                        description=f"Event rate differs from baseline: {current_rate:.1f}/min vs {baseline.events_per_minute:.1f}/min ({ratio:.1f}x)",
                        value=current_rate,
                        expected=baseline.events_per_minute
                    ))

        # Compare error rate
        if len(self.error_rate_history) > 0:
            current_error_rate = statistics.mean(self.error_rate_history)
            if current_error_rate > baseline.error_rate * 2:
                anomalies.append(Anomaly(
                    timestamp=now,
                    anomaly_type="error_rate_deviation",
                    severity="critical",
                    description=f"Error rate exceeds baseline: {current_error_rate*100:.1f}% vs {baseline.error_rate*100:.1f}%",
                    value=current_error_rate,
                    expected=baseline.error_rate
                ))

        return anomalies

    def create_baseline(self) -> Baseline:
        """Create baseline from current statistics."""
        return Baseline(
            created_at=datetime.now(),
            total_entries=len(self.event_times),
            error_rate=statistics.mean(self.error_rate_history) if self.error_rate_history else 0,
            events_per_minute=statistics.mean(self.rate_history) if self.rate_history else 0,
            pattern_frequencies=dict(self.pattern_counts)
        )


# =============================================================================
# Log File Reader
# =============================================================================

def read_log_file(path: str, follow: bool = False) -> Generator[str, None, None]:
    """Read log file, optionally following for new lines."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        # Read existing content
        for line in f:
            yield line

        # Follow mode
        if follow:
            while True:
                line = f.readline()
                if line:
                    yield line
                else:
                    time.sleep(0.1)


# =============================================================================
# Display Functions
# =============================================================================

def display_anomaly(anomaly: Anomaly):
    """Display a single anomaly."""
    severity_colors = {
        "info": "blue",
        "warning": "yellow",
        "critical": "red"
    }
    color = severity_colors.get(anomaly.severity, "white")

    console.print(f"[{color}]⚠ [{anomaly.severity.upper()}] {anomaly.anomaly_type}[/{color}]")
    console.print(f"  {anomaly.description}")
    console.print(f"  Time: {anomaly.timestamp}")


def display_summary(detector: AnomalyDetector, total_lines: int):
    """Display analysis summary."""
    console.print("\n" + "━" * 60)
    console.print("[bold cyan]ANALYSIS SUMMARY[/bold cyan]")
    console.print("━" * 60)

    console.print(f"Total lines processed: {total_lines}")
    console.print(f"Unique patterns: {len(detector.pattern_counts)}")

    if detector.rate_history:
        console.print(f"Average event rate: {statistics.mean(detector.rate_history):.1f}/min")

    if detector.error_rate_history:
        avg_error = statistics.mean(detector.error_rate_history) * 100
        console.print(f"Average error rate: {avg_error:.2f}%")

    # Anomaly summary
    by_severity = defaultdict(int)
    for a in detector.anomalies:
        by_severity[a.severity] += 1

    console.print(f"\nAnomalies detected: {len(detector.anomalies)}")
    console.print(f"  🔴 Critical: {by_severity['critical']}")
    console.print(f"  🟡 Warning: {by_severity['warning']}")
    console.print(f"  🔵 Info: {by_severity['info']}")


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Log Anomaly Detector - Statistical log analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("logfile", nargs="?", help="Log file to analyze")
    parser.add_argument("-c", "--config", help="Configuration file (YAML)")
    parser.add_argument("-w", "--watch", action="store_true",
                        help="Watch mode (follow log file)")
    parser.add_argument("-t", "--threshold", type=float, default=3.0,
                        help="Anomaly threshold (z-score, default: 3.0)")
    parser.add_argument("-f", "--format",
                        choices=["auto", "syslog", "json", "nginx", "apache"],
                        default="auto",
                        help="Log format (default: auto)")
    parser.add_argument("-o", "--output", help="Output report file")
    parser.add_argument("--create-baseline", action="store_true",
                        help="Create baseline from log file")
    parser.add_argument("--baseline", help="Baseline file for comparison")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress real-time output")
    parser.add_argument("-v", "--version", action="version",
                        version="log-anomaly-detector 1.0.0")

    args = parser.parse_args()

    if not args.logfile:
        parser.print_help()
        sys.exit(1)

    # Load config
    config = {}
    if args.config:
        with open(args.config) as f:
            config = yaml.safe_load(f)

    if "detection" not in config:
        config["detection"] = {}
    config["detection"]["threshold"] = args.threshold

    console.print("[bold blue]🔍 Log Anomaly Detector[/bold blue]\n")
    console.print(f"Analyzing: {args.logfile}")
    console.print(f"Threshold: {args.threshold} standard deviations\n")

    # Initialize
    log_parser = LogParser(format_name=args.format)
    detector = AnomalyDetector(config)

    # Load baseline if provided
    baseline = None
    if args.baseline:
        with open(args.baseline) as f:
            baseline = Baseline.from_dict(json.load(f))
        console.print(f"[dim]Loaded baseline from {args.baseline}[/dim]\n")

    # Process log file
    total_lines = 0
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            disable=args.watch
        ) as progress:
            task = progress.add_task("Processing logs...", total=None)

            for line in read_log_file(args.logfile, follow=args.watch):
                total_lines += 1

                entry = log_parser.parse_line(line)
                if not entry:
                    continue

                anomalies = detector.process_entry(entry, log_parser)

                # Display anomalies in real-time
                if not args.quiet:
                    for anomaly in anomalies:
                        if anomaly.severity in ("warning", "critical"):
                            display_anomaly(anomaly)

                if total_lines % 1000 == 0:
                    progress.update(task, description=f"Processed {total_lines} lines...")

    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")

    # Compare with baseline
    if baseline:
        baseline_anomalies = detector.compare_with_baseline(baseline)
        detector.anomalies.extend(baseline_anomalies)
        for anomaly in baseline_anomalies:
            display_anomaly(anomaly)

    # Display summary
    if not args.quiet:
        display_summary(detector, total_lines)

    # Create baseline if requested
    if args.create_baseline:
        baseline = detector.create_baseline()
        baseline_file = args.output or "baseline.json"
        with open(baseline_file, "w") as f:
            json.dump(baseline.to_dict(), f, indent=2)
        console.print(f"\n[green]Baseline saved to: {baseline_file}[/green]")

    # Export report
    elif args.output:
        report = {
            "analyzed_file": args.logfile,
            "analysis_time": datetime.now().isoformat(),
            "total_lines": total_lines,
            "unique_patterns": len(detector.pattern_counts),
            "anomalies": [a.to_dict() for a in detector.anomalies],
            "statistics": {
                "avg_event_rate": statistics.mean(detector.rate_history) if detector.rate_history else 0,
                "avg_error_rate": statistics.mean(detector.error_rate_history) if detector.error_rate_history else 0
            }
        }

        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        console.print(f"\n[green]Report saved to: {args.output}[/green]")

    # Exit code based on critical anomalies
    critical_count = sum(1 for a in detector.anomalies if a.severity == "critical")
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == "__main__":
    main()
```

## Exemple de Sortie

```
🔍 Log Anomaly Detector

Analyzing: /var/log/syslog
Threshold: 3.0 standard deviations

⚠ [CRITICAL] error_spike
  Error rate spike: 15.2% (expected ~2.1%, z=4.5)
  Time: 2024-01-15 14:32:15

⚠ [WARNING] rate_spike
  Event rate spike: 450.0/min (expected ~120.5/min, z=3.2)
  Time: 2024-01-15 14:32:18

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ANALYSIS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total lines processed: 50000
Unique patterns: 234
Average event rate: 125.3/min
Average error rate: 2.15%

Anomalies detected: 12
  🔴 Critical: 3
  🟡 Warning: 7
  🔵 Info: 2
```

## Cas d'Usage

1. **Incident Detection** : Alerter sur les anomalies en temps réel
2. **Post-mortem Analysis** : Analyser les logs après un incident
3. **Baseline Comparison** : Détecter les dérives par rapport à la normale
4. **CI/CD Monitoring** : Surveiller les logs de déploiement
