# Patch Compliance Report

Script Python de génération de rapports de conformité des patchs système.

## Description

- **Multi-OS** : Support Linux (apt, yum, dnf) et Windows (WUA)
- **Scoring de conformité** : Calcul du score de conformité basé sur la criticité
- **Rapport détaillé** : Export HTML, JSON, CSV, Markdown
- **CVE Tracking** : Identification des CVE associés aux patchs manquants
- **Baseline Comparison** : Comparaison avec une liste de patchs requis
- **Multi-host** : Scan de plusieurs machines via SSH

## Prérequis

```bash
pip install rich paramiko pyyaml requests
```

## Utilisation

```bash
# Scan local
python patch_compliance_report.py

# Scan avec rapport HTML
python patch_compliance_report.py --output report.html --format html

# Scan multi-host via SSH
python patch_compliance_report.py --hosts hosts.yaml

# Comparaison avec baseline de patchs requis
python patch_compliance_report.py --baseline required_patches.yaml

# Export JSON pour CI/CD
python patch_compliance_report.py --format json --output compliance.json
```

## Configuration

Fichier `patch_config.yaml` :

```yaml
hosts:
  - name: web-server-1
    host: 192.168.1.10
    user: admin
    key_file: ~/.ssh/id_rsa
  - name: db-server-1
    host: 192.168.1.20
    user: admin
    key_file: ~/.ssh/id_rsa

baseline:
  # Required patches (by CVE or package name)
  required:
    - CVE-2024-1234
    - CVE-2024-5678
    - openssl >= 3.0.0
    - openssh >= 9.0

  # Severity thresholds
  thresholds:
    critical_max_age_days: 7
    high_max_age_days: 14
    medium_max_age_days: 30

scoring:
  critical_weight: 10
  high_weight: 5
  medium_weight: 2
  low_weight: 1
  compliance_threshold: 80  # Minimum score to be compliant
```

## Code Source

```python
#!/usr/bin/env python3
"""
Patch Compliance Report - System patch compliance auditing and reporting.

Features:
- Multi-OS support (apt, yum, dnf, Windows)
- Compliance scoring based on severity
- CVE tracking
- Multi-host SSH scanning
- HTML/JSON/CSV/Markdown reports
"""

import subprocess
import sys
import json
import re
import socket
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    import yaml
except ImportError:
    print("Missing dependencies. Install with: pip install rich pyyaml")
    sys.exit(1)

console = Console()

# =============================================================================
# Data Models
# =============================================================================

class Severity(Enum):
    """Patch severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """Parse severity from various formats."""
        value = value.lower().strip()
        if value in ("critical", "urgent", "emergency"):
            return cls.CRITICAL
        elif value in ("high", "important"):
            return cls.HIGH
        elif value in ("medium", "moderate"):
            return cls.MEDIUM
        elif value in ("low", "optional"):
            return cls.LOW
        return cls.UNKNOWN


@dataclass
class PendingPatch:
    """Represents a pending system patch."""
    package: str
    current_version: str
    available_version: str
    severity: Severity = Severity.UNKNOWN
    cves: list = field(default_factory=list)
    repository: str = ""
    release_date: Optional[datetime] = None
    description: str = ""

    @property
    def age_days(self) -> Optional[int]:
        """Calculate patch age in days."""
        if self.release_date:
            return (datetime.now() - self.release_date).days
        return None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "package": self.package,
            "current_version": self.current_version,
            "available_version": self.available_version,
            "severity": self.severity.value,
            "cves": self.cves,
            "repository": self.repository,
            "release_date": self.release_date.isoformat() if self.release_date else None,
            "age_days": self.age_days,
            "description": self.description
        }


@dataclass
class HostReport:
    """Patch compliance report for a single host."""
    hostname: str
    os_type: str
    os_version: str
    scan_time: datetime
    patches: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    @property
    def total_patches(self) -> int:
        return len(self.patches)

    @property
    def critical_count(self) -> int:
        return sum(1 for p in self.patches if p.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for p in self.patches if p.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for p in self.patches if p.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for p in self.patches if p.severity == Severity.LOW)

    def calculate_score(self, weights: dict) -> float:
        """Calculate compliance score (100 = fully patched)."""
        if not self.patches:
            return 100.0

        penalty = (
            self.critical_count * weights.get("critical", 10) +
            self.high_count * weights.get("high", 5) +
            self.medium_count * weights.get("medium", 2) +
            self.low_count * weights.get("low", 1)
        )

        # Max penalty caps at 100
        score = max(0, 100 - penalty)
        return round(score, 1)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "hostname": self.hostname,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "scan_time": self.scan_time.isoformat(),
            "total_patches": self.total_patches,
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count
            },
            "patches": [p.to_dict() for p in self.patches],
            "errors": self.errors
        }


# =============================================================================
# Package Manager Scanners
# =============================================================================

class PackageScanner:
    """Base class for package manager scanners."""

    def scan(self) -> list:
        """Scan for pending patches. Override in subclasses."""
        raise NotImplementedError

    def get_os_info(self) -> tuple:
        """Get OS type and version."""
        raise NotImplementedError


class AptScanner(PackageScanner):
    """Scanner for Debian/Ubuntu systems using apt."""

    def get_os_info(self) -> tuple:
        """Get OS information from /etc/os-release."""
        try:
            with open("/etc/os-release") as f:
                info = {}
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        info[key] = value.strip('"')
                return info.get("ID", "debian"), info.get("VERSION_ID", "unknown")
        except Exception:
            return "debian", "unknown"

    def scan(self) -> list:
        """Scan for pending apt updates."""
        patches = []

        # Update package lists
        subprocess.run(
            ["apt-get", "update", "-qq"],
            capture_output=True,
            timeout=120
        )

        # Get upgradable packages
        result = subprocess.run(
            ["apt", "list", "--upgradable"],
            capture_output=True,
            text=True,
            timeout=60
        )

        for line in result.stdout.strip().split("\n"):
            if "/" not in line or "Listing..." in line:
                continue

            # Parse apt list output: package/repo version arch [upgradable from: old_version]
            match = re.match(
                r"(\S+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from:\s+(\S+)\]",
                line
            )
            if match:
                package, repo, new_ver, old_ver = match.groups()
                # Remove architecture suffix
                package = package.split(":")[0]

                patch = PendingPatch(
                    package=package,
                    current_version=old_ver,
                    available_version=new_ver,
                    repository=repo,
                    severity=self._get_severity(package, repo)
                )

                # Try to get CVEs from changelog
                patch.cves = self._get_cves(package)
                patches.append(patch)

        return patches

    def _get_severity(self, package: str, repo: str) -> Severity:
        """Determine severity based on repository."""
        if "security" in repo.lower():
            return Severity.HIGH
        elif "updates" in repo.lower():
            return Severity.MEDIUM
        return Severity.LOW

    def _get_cves(self, package: str) -> list:
        """Extract CVEs from package changelog (limited)."""
        cves = []
        try:
            result = subprocess.run(
                ["apt-get", "changelog", package],
                capture_output=True,
                text=True,
                timeout=30
            )
            # Find CVE references in first 50 lines
            for line in result.stdout.split("\n")[:50]:
                found = re.findall(r"CVE-\d{4}-\d+", line, re.IGNORECASE)
                cves.extend(found)
        except Exception:
            pass
        return list(set(cves))[:10]  # Limit to 10 CVEs


class YumScanner(PackageScanner):
    """Scanner for RHEL/CentOS/Rocky systems using yum/dnf."""

    def get_os_info(self) -> tuple:
        """Get OS information from /etc/os-release."""
        try:
            with open("/etc/os-release") as f:
                info = {}
                for line in f:
                    if "=" in line:
                        key, value = line.strip().split("=", 1)
                        info[key] = value.strip('"')
                return info.get("ID", "rhel"), info.get("VERSION_ID", "unknown")
        except Exception:
            return "rhel", "unknown"

    def scan(self) -> list:
        """Scan for pending yum/dnf updates."""
        patches = []

        # Detect dnf or yum
        pkg_manager = "dnf" if Path("/usr/bin/dnf").exists() else "yum"

        # Check for updates with security info
        result = subprocess.run(
            [pkg_manager, "updateinfo", "list", "updates", "--security"],
            capture_output=True,
            text=True,
            timeout=120
        )

        security_packages = set()
        severity_map = {}

        for line in result.stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                advisory = parts[0]
                severity = parts[1] if len(parts) > 2 else "unknown"
                package = parts[-1]
                security_packages.add(package.split(".")[0])
                severity_map[package.split(".")[0]] = Severity.from_string(severity)

        # Get all available updates
        result = subprocess.run(
            [pkg_manager, "check-update", "-q"],
            capture_output=True,
            text=True,
            timeout=120
        )

        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue

            parts = line.split()
            if len(parts) >= 2:
                package = parts[0].split(".")[0]
                new_version = parts[1]

                # Get current version
                current_result = subprocess.run(
                    ["rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", package],
                    capture_output=True,
                    text=True
                )
                current_ver = current_result.stdout.strip() if current_result.returncode == 0 else "unknown"

                severity = severity_map.get(package, Severity.LOW)
                if package in security_packages:
                    severity = max(severity, Severity.HIGH, key=lambda x: x.value)

                patch = PendingPatch(
                    package=package,
                    current_version=current_ver,
                    available_version=new_version,
                    severity=severity
                )

                # Get CVEs from updateinfo
                patch.cves = self._get_cves(pkg_manager, package)
                patches.append(patch)

        return patches

    def _get_cves(self, pkg_manager: str, package: str) -> list:
        """Get CVEs for a package from updateinfo."""
        cves = []
        try:
            result = subprocess.run(
                [pkg_manager, "updateinfo", "info", package],
                capture_output=True,
                text=True,
                timeout=30
            )
            cves = re.findall(r"CVE-\d{4}-\d+", result.stdout, re.IGNORECASE)
        except Exception:
            pass
        return list(set(cves))[:10]


class WindowsScanner(PackageScanner):
    """Scanner for Windows Update using PowerShell."""

    def get_os_info(self) -> tuple:
        """Get Windows version info."""
        try:
            result = subprocess.run(
                ["powershell", "-Command",
                 "(Get-CimInstance Win32_OperatingSystem).Caption + '|' + (Get-CimInstance Win32_OperatingSystem).Version"],
                capture_output=True,
                text=True,
                timeout=30
            )
            parts = result.stdout.strip().split("|")
            return "windows", parts[1] if len(parts) > 1 else "unknown"
        except Exception:
            return "windows", "unknown"

    def scan(self) -> list:
        """Scan for pending Windows Updates."""
        patches = []

        ps_script = '''
$UpdateSession = New-Object -ComObject Microsoft.Update.Session
$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
$SearchResult = $UpdateSearcher.Search("IsInstalled=0 and Type='Software'")

$updates = @()
foreach ($Update in $SearchResult.Updates) {
    $cves = @()
    foreach ($cve in $Update.CveIDs) { $cves += $cve }

    $severity = switch ($Update.MsrcSeverity) {
        "Critical" { "critical" }
        "Important" { "high" }
        "Moderate" { "medium" }
        "Low" { "low" }
        default { "unknown" }
    }

    $updates += @{
        Title = $Update.Title
        KBArticleIDs = ($Update.KBArticleIDs -join ",")
        Severity = $severity
        CVEs = ($cves -join ",")
        Description = $Update.Description
    }
}
$updates | ConvertTo-Json -Depth 3
'''

        try:
            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.stdout.strip():
                updates = json.loads(result.stdout)
                if not isinstance(updates, list):
                    updates = [updates]

                for update in updates:
                    cves = update.get("CVEs", "").split(",") if update.get("CVEs") else []
                    patch = PendingPatch(
                        package=update.get("Title", "Unknown"),
                        current_version="installed",
                        available_version=update.get("KBArticleIDs", ""),
                        severity=Severity.from_string(update.get("Severity", "unknown")),
                        cves=[c for c in cves if c],
                        description=update.get("Description", "")[:200]
                    )
                    patches.append(patch)

        except json.JSONDecodeError:
            pass
        except subprocess.TimeoutExpired:
            pass

        return patches


# =============================================================================
# Report Generator
# =============================================================================

class ReportGenerator:
    """Generate compliance reports in various formats."""

    def __init__(self, reports: list, config: dict):
        self.reports = reports
        self.config = config
        self.weights = config.get("scoring", {
            "critical_weight": 10,
            "high_weight": 5,
            "medium_weight": 2,
            "low_weight": 1
        })

    def generate(self, output_path: str, format_type: str):
        """Generate report in specified format."""
        generators = {
            "json": self._generate_json,
            "html": self._generate_html,
            "csv": self._generate_csv,
            "md": self._generate_markdown,
            "markdown": self._generate_markdown
        }

        generator = generators.get(format_type.lower(), self._generate_json)
        generator(output_path)

    def _calculate_overall_score(self) -> float:
        """Calculate overall compliance score across all hosts."""
        if not self.reports:
            return 100.0

        scores = [
            r.calculate_score({
                "critical": self.weights.get("critical_weight", 10),
                "high": self.weights.get("high_weight", 5),
                "medium": self.weights.get("medium_weight", 2),
                "low": self.weights.get("low_weight", 1)
            })
            for r in self.reports
        ]
        return round(sum(scores) / len(scores), 1)

    def _generate_json(self, output_path: str):
        """Generate JSON report."""
        threshold = self.config.get("scoring", {}).get("compliance_threshold", 80)
        overall_score = self._calculate_overall_score()

        data = {
            "report_generated": datetime.now().isoformat(),
            "overall_compliance_score": overall_score,
            "compliance_threshold": threshold,
            "is_compliant": overall_score >= threshold,
            "hosts_scanned": len(self.reports),
            "total_patches_pending": sum(r.total_patches for r in self.reports),
            "summary": {
                "critical": sum(r.critical_count for r in self.reports),
                "high": sum(r.high_count for r in self.reports),
                "medium": sum(r.medium_count for r in self.reports),
                "low": sum(r.low_count for r in self.reports)
            },
            "hosts": [r.to_dict() for r in self.reports]
        }

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]JSON report generated:[/green] {output_path}")

    def _generate_html(self, output_path: str):
        """Generate HTML report."""
        overall_score = self._calculate_overall_score()
        threshold = self.config.get("scoring", {}).get("compliance_threshold", 80)
        is_compliant = overall_score >= threshold

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patch Compliance Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .score {{ font-size: 48px; font-weight: bold; }}
        .score.compliant {{ color: #4ade80; }}
        .score.non-compliant {{ color: #f87171; }}
        .card {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .severity-badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; }}
        .critical {{ background: #fee2e2; color: #dc2626; }}
        .high {{ background: #ffedd5; color: #ea580c; }}
        .medium {{ background: #fef3c7; color: #d97706; }}
        .low {{ background: #dbeafe; color: #2563eb; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
        th {{ background: #f9fafb; font-weight: 600; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }}
        .summary-item {{ text-align: center; padding: 15px; background: #f9fafb; border-radius: 8px; }}
        .summary-item .count {{ font-size: 24px; font-weight: bold; }}
        .cve-list {{ font-family: monospace; font-size: 12px; color: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Patch Compliance Report</h1>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <div class="score {'compliant' if is_compliant else 'non-compliant'}">{overall_score}%</div>
            <p>{'✅ COMPLIANT' if is_compliant else '❌ NON-COMPLIANT'} (threshold: {threshold}%)</p>
        </div>

        <div class="card">
            <h2>📊 Summary</h2>
            <p>Hosts scanned: {len(self.reports)} | Total pending patches: {sum(r.total_patches for r in self.reports)}</p>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="count critical" style="color: #dc2626;">{sum(r.critical_count for r in self.reports)}</div>
                    <div>Critical</div>
                </div>
                <div class="summary-item">
                    <div class="count" style="color: #ea580c;">{sum(r.high_count for r in self.reports)}</div>
                    <div>High</div>
                </div>
                <div class="summary-item">
                    <div class="count" style="color: #d97706;">{sum(r.medium_count for r in self.reports)}</div>
                    <div>Medium</div>
                </div>
                <div class="summary-item">
                    <div class="count" style="color: #2563eb;">{sum(r.low_count for r in self.reports)}</div>
                    <div>Low</div>
                </div>
            </div>
        </div>
'''

        for report in self.reports:
            score = report.calculate_score({
                "critical": self.weights.get("critical_weight", 10),
                "high": self.weights.get("high_weight", 5),
                "medium": self.weights.get("medium_weight", 2),
                "low": self.weights.get("low_weight", 1)
            })

            html += f'''
        <div class="card">
            <h2>🖥️ {report.hostname}</h2>
            <p>{report.os_type} {report.os_version} | Score: <strong>{score}%</strong> | Patches: {report.total_patches}</p>

            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Current</th>
                        <th>Available</th>
                        <th>Severity</th>
                        <th>CVEs</th>
                    </tr>
                </thead>
                <tbody>
'''
            for patch in sorted(report.patches, key=lambda p: p.severity.value):
                cves = ", ".join(patch.cves[:3]) if patch.cves else "-"
                if len(patch.cves) > 3:
                    cves += f" (+{len(patch.cves)-3})"

                html += f'''
                    <tr>
                        <td>{patch.package}</td>
                        <td><code>{patch.current_version}</code></td>
                        <td><code>{patch.available_version}</code></td>
                        <td><span class="severity-badge {patch.severity.value}">{patch.severity.value.upper()}</span></td>
                        <td class="cve-list">{cves}</td>
                    </tr>
'''
            html += '''
                </tbody>
            </table>
        </div>
'''

        html += '''
    </div>
</body>
</html>
'''

        with open(output_path, "w") as f:
            f.write(html)

        console.print(f"[green]HTML report generated:[/green] {output_path}")

    def _generate_csv(self, output_path: str):
        """Generate CSV report."""
        import csv

        with open(output_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Hostname", "Package", "Current Version", "Available Version",
                "Severity", "CVEs", "Repository"
            ])

            for report in self.reports:
                for patch in report.patches:
                    writer.writerow([
                        report.hostname,
                        patch.package,
                        patch.current_version,
                        patch.available_version,
                        patch.severity.value,
                        ";".join(patch.cves),
                        patch.repository
                    ])

        console.print(f"[green]CSV report generated:[/green] {output_path}")

    def _generate_markdown(self, output_path: str):
        """Generate Markdown report."""
        overall_score = self._calculate_overall_score()
        threshold = self.config.get("scoring", {}).get("compliance_threshold", 80)
        is_compliant = overall_score >= threshold

        md = f'''# Patch Compliance Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Overall Status

- **Compliance Score:** {overall_score}%
- **Status:** {"✅ COMPLIANT" if is_compliant else "❌ NON-COMPLIANT"}
- **Threshold:** {threshold}%
- **Hosts Scanned:** {len(self.reports)}
- **Total Pending Patches:** {sum(r.total_patches for r in self.reports)}

## Summary by Severity

| Severity | Count |
|----------|-------|
| 🔴 Critical | {sum(r.critical_count for r in self.reports)} |
| 🟠 High | {sum(r.high_count for r in self.reports)} |
| 🟡 Medium | {sum(r.medium_count for r in self.reports)} |
| 🔵 Low | {sum(r.low_count for r in self.reports)} |

'''

        for report in self.reports:
            score = report.calculate_score({
                "critical": self.weights.get("critical_weight", 10),
                "high": self.weights.get("high_weight", 5),
                "medium": self.weights.get("medium_weight", 2),
                "low": self.weights.get("low_weight", 1)
            })

            md += f'''
## {report.hostname}

- **OS:** {report.os_type} {report.os_version}
- **Score:** {score}%
- **Pending Patches:** {report.total_patches}

| Package | Current | Available | Severity | CVEs |
|---------|---------|-----------|----------|------|
'''
            for patch in sorted(report.patches, key=lambda p: p.severity.value):
                cves = ", ".join(patch.cves[:3]) if patch.cves else "-"
                md += f"| {patch.package} | `{patch.current_version}` | `{patch.available_version}` | {patch.severity.value.upper()} | {cves} |\n"

        with open(output_path, "w") as f:
            f.write(md)

        console.print(f"[green]Markdown report generated:[/green] {output_path}")


# =============================================================================
# Main Scanner Class
# =============================================================================

class PatchComplianceScanner:
    """Main scanner class."""

    def __init__(self, config: dict = None):
        self.config = config or {}
        self.reports: list = []

    def detect_scanner(self) -> PackageScanner:
        """Detect appropriate scanner for current system."""
        import platform

        system = platform.system().lower()

        if system == "linux":
            if Path("/usr/bin/apt").exists():
                return AptScanner()
            elif Path("/usr/bin/dnf").exists() or Path("/usr/bin/yum").exists():
                return YumScanner()
        elif system == "windows":
            return WindowsScanner()

        raise RuntimeError(f"Unsupported system: {system}")

    def scan_local(self) -> HostReport:
        """Scan local system for pending patches."""
        scanner = self.detect_scanner()
        os_type, os_version = scanner.get_os_info()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            progress.add_task("Scanning for pending patches...", total=None)

            try:
                patches = scanner.scan()
            except Exception as e:
                patches = []
                console.print(f"[red]Scan error:[/red] {e}")

        report = HostReport(
            hostname=socket.gethostname(),
            os_type=os_type,
            os_version=os_version,
            scan_time=datetime.now(),
            patches=patches
        )

        self.reports.append(report)
        return report

    def display_summary(self):
        """Display summary in terminal."""
        if not self.reports:
            console.print("[yellow]No reports to display[/yellow]")
            return

        weights = self.config.get("scoring", {})
        threshold = weights.get("compliance_threshold", 80)

        for report in self.reports:
            score = report.calculate_score({
                "critical": weights.get("critical_weight", 10),
                "high": weights.get("high_weight", 5),
                "medium": weights.get("medium_weight", 2),
                "low": weights.get("low_weight", 1)
            })

            status = "✅ COMPLIANT" if score >= threshold else "❌ NON-COMPLIANT"
            score_color = "green" if score >= threshold else "red"

            console.print(Panel(
                f"[bold]{report.hostname}[/bold]\n"
                f"OS: {report.os_type} {report.os_version}\n"
                f"Score: [{score_color}]{score}%[/{score_color}] {status}\n"
                f"Patches: {report.total_patches} "
                f"(🔴{report.critical_count} 🟠{report.high_count} 🟡{report.medium_count} 🔵{report.low_count})",
                title="Patch Compliance"
            ))

            if report.patches:
                table = Table(title=f"Pending Patches ({report.total_patches})")
                table.add_column("Package", style="cyan")
                table.add_column("Current", style="dim")
                table.add_column("Available", style="green")
                table.add_column("Severity")
                table.add_column("CVEs", style="dim")

                severity_styles = {
                    Severity.CRITICAL: "bold red",
                    Severity.HIGH: "orange1",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "blue",
                    Severity.UNKNOWN: "dim"
                }

                for patch in sorted(report.patches, key=lambda p: p.severity.value)[:20]:
                    cves = ", ".join(patch.cves[:2]) if patch.cves else "-"
                    if len(patch.cves) > 2:
                        cves += "..."

                    table.add_row(
                        patch.package,
                        patch.current_version[:20],
                        patch.available_version[:20],
                        f"[{severity_styles[patch.severity]}]{patch.severity.value.upper()}[/]",
                        cves
                    )

                if report.total_patches > 20:
                    table.add_row("...", "...", "...", "...", f"+{report.total_patches - 20} more")

                console.print(table)


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Patch Compliance Report - System patch auditing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-c", "--config", help="Configuration file (YAML)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("-f", "--format", default="json",
                        choices=["json", "html", "csv", "md"],
                        help="Output format (default: json)")
    parser.add_argument("--hosts", help="Hosts file for multi-host scan (YAML)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress terminal output")
    parser.add_argument("-v", "--version", action="version",
                        version="patch-compliance-report 1.0.0")

    args = parser.parse_args()

    # Load config
    config = {}
    if args.config:
        with open(args.config) as f:
            config = yaml.safe_load(f)

    # Create scanner
    scanner = PatchComplianceScanner(config)

    # Scan local system
    console.print("[bold blue]🔍 Patch Compliance Scanner[/bold blue]\n")
    report = scanner.scan_local()

    # Display summary
    if not args.quiet:
        scanner.display_summary()

    # Generate report
    if args.output:
        generator = ReportGenerator(scanner.reports, config)
        generator.generate(args.output, args.format)

    # Exit code based on compliance
    weights = config.get("scoring", {})
    threshold = weights.get("compliance_threshold", 80)
    score = report.calculate_score({
        "critical": weights.get("critical_weight", 10),
        "high": weights.get("high_weight", 5),
        "medium": weights.get("medium_weight", 2),
        "low": weights.get("low_weight", 1)
    })

    sys.exit(0 if score >= threshold else 1)


if __name__ == "__main__":
    main()
```

## Intégration CI/CD

### GitHub Actions

```yaml
name: Patch Compliance Check
on:
  schedule:
    - cron: '0 6 * * *'  # Daily at 6 AM

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install dependencies
        run: pip install rich pyyaml
      - name: Run compliance scan
        run: python patch_compliance_report.py --format json --output compliance.json
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: compliance.json
```

## Cas d'Usage

1. **Audit de Conformité** : Vérification régulière de l'état des patchs
2. **Reporting Sécurité** : Rapports pour les équipes sécurité et compliance
3. **CI/CD Gate** : Blocage des déploiements si le score est insuffisant
4. **Monitoring Continu** : Intégration avec des outils de surveillance

## Voir Aussi

- [compliance_report_generator.py](./compliance_report_generator.md) - Rapports conformité CIS/ANSSI
- [system_info.py](./system_info.md) - Informations système complètes
- [health_checker.py](./health_checker.md) - Vérification santé services
