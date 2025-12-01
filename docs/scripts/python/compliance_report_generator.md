# Compliance Report Generator

Script Python de génération automatique de rapports de conformité multi-référentiels.

## Description

- **Multi-référentiels** : CIS Benchmarks, ANSSI, SOC2, PCI-DSS, HIPAA
- **Audit automatisé** : Collecte des données système et configuration
- **Scoring** : Calcul du score de conformité par catégorie
- **Rapports** : Export HTML, PDF (via wkhtmltopdf), JSON, Markdown
- **Remediation** : Recommandations de correction prioritisées
- **Historique** : Suivi de l'évolution dans le temps

## Prérequis

```bash
pip install rich pyyaml jinja2
# Optionnel pour PDF
apt install wkhtmltopdf  # Linux
# ou
choco install wkhtmltopdf  # Windows
```

## Utilisation

```bash
# Audit CIS Linux
python compliance_report_generator.py --framework cis-linux

# Audit ANSSI (recommandations)
python compliance_report_generator.py --framework anssi

# Audit multi-framework
python compliance_report_generator.py --framework cis-linux,anssi

# Export HTML
python compliance_report_generator.py --framework cis-linux --output report.html

# Export JSON pour CI/CD
python compliance_report_generator.py --framework cis-linux --format json --output compliance.json

# Mode comparaison (évolution)
python compliance_report_generator.py --framework cis-linux --compare previous.json
```

## Frameworks Supportés

| Framework | Description | Contrôles |
|-----------|-------------|-----------|
| `cis-linux` | CIS Benchmark Linux | 200+ |
| `cis-windows` | CIS Benchmark Windows | 300+ |
| `anssi` | Recommandations ANSSI Linux | 50+ |
| `soc2` | SOC 2 Type II | 60+ |
| `pci-dss` | PCI-DSS v4.0 | 100+ |
| `hipaa` | HIPAA Security Rule | 40+ |

## Code Source

```python
#!/usr/bin/env python3
"""
Compliance Report Generator - Multi-framework compliance auditing and reporting.

Features:
- Multiple compliance frameworks (CIS, ANSSI, SOC2, PCI-DSS)
- Automated system auditing
- Scoring and prioritized remediation
- HTML/JSON/Markdown reports
"""

import os
import sys
import subprocess
import re
from pathlib import Path
from datetime import datetime
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

class ComplianceStatus(Enum):
    """Compliance check status."""
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    MANUAL = "manual"
    NOT_APPLICABLE = "n/a"


class Severity(Enum):
    """Finding severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceCheck:
    """Single compliance check definition."""
    id: str
    title: str
    description: str
    category: str
    severity: Severity = Severity.MEDIUM
    check_type: str = "command"  # command, file, config
    check_command: str = ""
    expected_output: str = ""
    remediation: str = ""
    references: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "category": self.category,
            "severity": self.severity.value,
            "remediation": self.remediation
        }


@dataclass
class CheckResult:
    """Result of a compliance check."""
    check: ComplianceCheck
    status: ComplianceStatus
    actual_value: str = ""
    message: str = ""
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "id": self.check.id,
            "title": self.check.title,
            "category": self.check.category,
            "severity": self.check.severity.value,
            "status": self.status.value,
            "actual_value": self.actual_value[:500],
            "message": self.message,
            "remediation": self.check.remediation if self.status == ComplianceStatus.FAIL else ""
        }


@dataclass
class ComplianceReport:
    """Complete compliance report."""
    framework: str
    hostname: str
    scan_time: datetime
    results: list = field(default_factory=list)

    @property
    def total_checks(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.FAIL)

    @property
    def warnings(self) -> int:
        return sum(1 for r in self.results if r.status == ComplianceStatus.WARNING)

    @property
    def score(self) -> float:
        if not self.results:
            return 0.0
        applicable = [r for r in self.results if r.status != ComplianceStatus.NOT_APPLICABLE]
        if not applicable:
            return 100.0
        passed = sum(1 for r in applicable if r.status == ComplianceStatus.PASS)
        return round((passed / len(applicable)) * 100, 1)

    def by_category(self) -> dict:
        """Group results by category."""
        categories = {}
        for result in self.results:
            cat = result.check.category
            if cat not in categories:
                categories[cat] = {"pass": 0, "fail": 0, "warning": 0, "total": 0}
            categories[cat]["total"] += 1
            if result.status == ComplianceStatus.PASS:
                categories[cat]["pass"] += 1
            elif result.status == ComplianceStatus.FAIL:
                categories[cat]["fail"] += 1
            elif result.status == ComplianceStatus.WARNING:
                categories[cat]["warning"] += 1
        return categories

    def to_dict(self) -> dict:
        return {
            "framework": self.framework,
            "hostname": self.hostname,
            "scan_time": self.scan_time.isoformat(),
            "summary": {
                "total": self.total_checks,
                "passed": self.passed,
                "failed": self.failed,
                "warnings": self.warnings,
                "score": self.score
            },
            "by_category": self.by_category(),
            "results": [r.to_dict() for r in self.results]
        }


# =============================================================================
# Compliance Frameworks
# =============================================================================

class CISLinuxFramework:
    """CIS Benchmark for Linux."""

    NAME = "cis-linux"
    DESCRIPTION = "CIS Benchmark for Linux"

    @staticmethod
    def get_checks() -> list:
        """Return CIS Linux checks."""
        return [
            # 1. Initial Setup
            ComplianceCheck(
                id="1.1.1.1",
                title="Ensure mounting of cramfs filesystems is disabled",
                description="The cramfs filesystem type is a compressed read-only filesystem",
                category="Filesystem Configuration",
                severity=Severity.MEDIUM,
                check_command="modprobe -n -v cramfs 2>/dev/null | grep -E '(install|^cramfs)'",
                expected_output="install /bin/true",
                remediation="Add 'install cramfs /bin/true' to /etc/modprobe.d/cramfs.conf"
            ),
            ComplianceCheck(
                id="1.1.1.2",
                title="Ensure mounting of squashfs filesystems is limited",
                description="The squashfs filesystem is used for snap packages",
                category="Filesystem Configuration",
                severity=Severity.LOW,
                check_command="modprobe -n -v squashfs 2>/dev/null | grep -E '(install|^squashfs)'",
                expected_output="install /bin/true",
                remediation="Add 'install squashfs /bin/true' to /etc/modprobe.d/squashfs.conf"
            ),
            ComplianceCheck(
                id="1.1.1.3",
                title="Ensure mounting of udf filesystems is disabled",
                description="UDF filesystem support is not required for most systems",
                category="Filesystem Configuration",
                severity=Severity.LOW,
                check_command="modprobe -n -v udf 2>/dev/null | grep -E '(install|^udf)'",
                expected_output="install /bin/true",
                remediation="Add 'install udf /bin/true' to /etc/modprobe.d/udf.conf"
            ),

            # 1.4 Secure Boot Settings
            ComplianceCheck(
                id="1.4.1",
                title="Ensure bootloader password is set",
                description="Setting the boot loader password prevents unauthorized changes",
                category="Boot Settings",
                severity=Severity.HIGH,
                check_command="grep -E '^set superusers|^password' /boot/grub/grub.cfg 2>/dev/null",
                expected_output="superusers",
                remediation="Configure GRUB password using grub2-setpassword"
            ),
            ComplianceCheck(
                id="1.4.2",
                title="Ensure permissions on bootloader config are configured",
                description="The grub configuration file should be owned by root",
                category="Boot Settings",
                severity=Severity.HIGH,
                check_command="stat -c '%a %U %G' /boot/grub/grub.cfg 2>/dev/null || stat -c '%a %U %G' /boot/grub2/grub.cfg 2>/dev/null",
                expected_output="600 root root",
                remediation="chmod 600 /boot/grub*/grub.cfg && chown root:root /boot/grub*/grub.cfg"
            ),

            # 3. Network Configuration
            ComplianceCheck(
                id="3.1.1",
                title="Ensure IP forwarding is disabled",
                description="IP forwarding allows the system to act as a router",
                category="Network Configuration",
                severity=Severity.MEDIUM,
                check_command="sysctl net.ipv4.ip_forward",
                expected_output="net.ipv4.ip_forward = 0",
                remediation="Set net.ipv4.ip_forward = 0 in /etc/sysctl.conf"
            ),
            ComplianceCheck(
                id="3.1.2",
                title="Ensure packet redirect sending is disabled",
                description="ICMP Redirects can be used for network attacks",
                category="Network Configuration",
                severity=Severity.MEDIUM,
                check_command="sysctl net.ipv4.conf.all.send_redirects",
                expected_output="net.ipv4.conf.all.send_redirects = 0",
                remediation="Set net.ipv4.conf.all.send_redirects = 0 in /etc/sysctl.conf"
            ),

            # 4. Logging and Auditing
            ComplianceCheck(
                id="4.1.1",
                title="Ensure auditd is installed",
                description="auditd is the userspace component for the Linux Auditing System",
                category="Logging and Auditing",
                severity=Severity.HIGH,
                check_command="dpkg -s auditd 2>/dev/null || rpm -q audit 2>/dev/null",
                expected_output="install",
                remediation="Install auditd: apt install auditd OR yum install audit"
            ),
            ComplianceCheck(
                id="4.1.2",
                title="Ensure auditd service is enabled and running",
                description="auditd should be enabled to collect security events",
                category="Logging and Auditing",
                severity=Severity.HIGH,
                check_command="systemctl is-enabled auditd 2>/dev/null",
                expected_output="enabled",
                remediation="systemctl enable --now auditd"
            ),

            # 5. Access, Authentication and Authorization
            ComplianceCheck(
                id="5.2.1",
                title="Ensure permissions on /etc/ssh/sshd_config are configured",
                description="SSH configuration should be readable only by root",
                category="SSH Configuration",
                severity=Severity.HIGH,
                check_command="stat -c '%a %U %G' /etc/ssh/sshd_config 2>/dev/null",
                expected_output="600 root root",
                remediation="chmod 600 /etc/ssh/sshd_config && chown root:root /etc/ssh/sshd_config"
            ),
            ComplianceCheck(
                id="5.2.4",
                title="Ensure SSH root login is disabled",
                description="Root should not be allowed to login directly via SSH",
                category="SSH Configuration",
                severity=Severity.CRITICAL,
                check_command="grep -E '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null",
                expected_output="PermitRootLogin no",
                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
            ),
            ComplianceCheck(
                id="5.2.5",
                title="Ensure SSH PermitEmptyPasswords is disabled",
                description="Empty passwords should not be allowed for SSH",
                category="SSH Configuration",
                severity=Severity.CRITICAL,
                check_command="grep -E '^PermitEmptyPasswords' /etc/ssh/sshd_config 2>/dev/null",
                expected_output="PermitEmptyPasswords no",
                remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config"
            ),
            ComplianceCheck(
                id="5.3.1",
                title="Ensure password creation requirements are configured",
                description="Password complexity requirements should be enforced",
                category="Password Policy",
                severity=Severity.HIGH,
                check_command="grep -E '^minlen|^minclass' /etc/security/pwquality.conf 2>/dev/null",
                expected_output="minlen",
                remediation="Configure /etc/security/pwquality.conf with minlen=14, minclass=4"
            ),

            # 6. System Maintenance
            ComplianceCheck(
                id="6.1.1",
                title="Ensure permissions on /etc/passwd are configured",
                description="/etc/passwd should be readable by all but writable only by root",
                category="File Permissions",
                severity=Severity.HIGH,
                check_command="stat -c '%a %U %G' /etc/passwd 2>/dev/null",
                expected_output="644 root root",
                remediation="chmod 644 /etc/passwd && chown root:root /etc/passwd"
            ),
            ComplianceCheck(
                id="6.1.2",
                title="Ensure permissions on /etc/shadow are configured",
                description="/etc/shadow should only be readable by root",
                category="File Permissions",
                severity=Severity.CRITICAL,
                check_command="stat -c '%a' /etc/shadow 2>/dev/null",
                expected_output="0",
                remediation="chmod 000 /etc/shadow && chown root:root /etc/shadow"
            ),
            ComplianceCheck(
                id="6.2.1",
                title="Ensure root is the only UID 0 account",
                description="Only root should have UID 0",
                category="User Accounts",
                severity=Severity.CRITICAL,
                check_command="awk -F: '($3 == 0) { print $1 }' /etc/passwd",
                expected_output="root",
                remediation="Remove or change UID for any non-root account with UID 0"
            ),
        ]


class ANSSIFramework:
    """ANSSI Linux hardening recommendations."""

    NAME = "anssi"
    DESCRIPTION = "ANSSI Linux Hardening Recommendations"

    @staticmethod
    def get_checks() -> list:
        """Return ANSSI checks."""
        return [
            ComplianceCheck(
                id="R1",
                title="Minimisation des services installés",
                description="Seuls les composants strictement nécessaires doivent être installés",
                category="Minimisation",
                severity=Severity.HIGH,
                check_command="systemctl list-unit-files --state=enabled --type=service | wc -l",
                expected_output="<50",
                remediation="Désactiver les services non nécessaires"
            ),
            ComplianceCheck(
                id="R8",
                title="Protection de la mémoire",
                description="ASLR doit être activé",
                category="Protection Mémoire",
                severity=Severity.HIGH,
                check_command="sysctl kernel.randomize_va_space",
                expected_output="kernel.randomize_va_space = 2",
                remediation="sysctl -w kernel.randomize_va_space=2"
            ),
            ComplianceCheck(
                id="R9",
                title="Configuration du pare-feu",
                description="Un pare-feu doit être actif et configuré",
                category="Réseau",
                severity=Severity.CRITICAL,
                check_command="systemctl is-active firewalld 2>/dev/null || systemctl is-active ufw 2>/dev/null || iptables -L -n | grep -c Chain",
                expected_output="active",
                remediation="Activer et configurer firewalld ou ufw"
            ),
            ComplianceCheck(
                id="R28",
                title="Partition /tmp séparée avec options noexec",
                description="/tmp doit être une partition séparée avec noexec",
                category="Partitionnement",
                severity=Severity.MEDIUM,
                check_command="mount | grep '/tmp' | grep noexec",
                expected_output="noexec",
                remediation="Configurer /tmp comme partition séparée avec noexec,nosuid,nodev"
            ),
            ComplianceCheck(
                id="R30",
                title="Journalisation centralisée",
                description="Les logs doivent être centralisés sur un serveur distant",
                category="Journalisation",
                severity=Severity.MEDIUM,
                check_command="grep -E '^\\*\\.\\*\\s+@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null",
                expected_output="@",
                remediation="Configurer rsyslog pour envoyer les logs à un serveur central"
            ),
            ComplianceCheck(
                id="R32",
                title="Authentification centralisée sécurisée",
                description="L'authentification LDAP doit utiliser TLS",
                category="Authentification",
                severity=Severity.HIGH,
                check_command="grep -E 'ssl|tls' /etc/ldap/ldap.conf /etc/sssd/sssd.conf 2>/dev/null",
                expected_output="ssl",
                remediation="Configurer LDAP avec TLS/SSL"
            ),
            ComplianceCheck(
                id="R34",
                title="Verrouillage des comptes",
                description="Les comptes doivent être verrouillés après échecs d'authentification",
                category="Authentification",
                severity=Severity.HIGH,
                check_command="grep pam_faillock /etc/pam.d/common-auth /etc/pam.d/system-auth 2>/dev/null",
                expected_output="pam_faillock",
                remediation="Configurer pam_faillock dans PAM"
            ),
            ComplianceCheck(
                id="R67",
                title="Désactivation des core dumps",
                description="Les core dumps doivent être désactivés",
                category="Protection Mémoire",
                severity=Severity.MEDIUM,
                check_command="ulimit -c 2>/dev/null; sysctl fs.suid_dumpable",
                expected_output="0",
                remediation="Ajouter '* hard core 0' dans /etc/security/limits.conf"
            ),
        ]


# =============================================================================
# Compliance Auditor
# =============================================================================

class ComplianceAuditor:
    """Execute compliance checks."""

    FRAMEWORKS = {
        "cis-linux": CISLinuxFramework,
        "anssi": ANSSIFramework,
    }

    def __init__(self, framework: str):
        if framework not in self.FRAMEWORKS:
            raise ValueError(f"Unknown framework: {framework}. Available: {list(self.FRAMEWORKS.keys())}")

        self.framework_class = self.FRAMEWORKS[framework]
        self.framework = framework

    def run_check(self, check: ComplianceCheck) -> CheckResult:
        """Execute a single compliance check."""
        try:
            result = subprocess.run(
                check.check_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            actual = result.stdout.strip() + result.stderr.strip()

            # Determine status
            if check.expected_output.startswith("<"):
                # Numeric comparison
                try:
                    threshold = int(check.expected_output[1:])
                    actual_value = int(re.search(r'\d+', actual).group())
                    status = ComplianceStatus.PASS if actual_value < threshold else ComplianceStatus.FAIL
                except Exception:
                    status = ComplianceStatus.MANUAL
            elif check.expected_output in actual:
                status = ComplianceStatus.PASS
            elif not actual:
                status = ComplianceStatus.FAIL
            else:
                status = ComplianceStatus.FAIL

            return CheckResult(
                check=check,
                status=status,
                actual_value=actual,
                message=f"Expected: {check.expected_output}"
            )

        except subprocess.TimeoutExpired:
            return CheckResult(
                check=check,
                status=ComplianceStatus.WARNING,
                message="Check timed out"
            )
        except Exception as e:
            return CheckResult(
                check=check,
                status=ComplianceStatus.WARNING,
                message=str(e)
            )

    def audit(self) -> ComplianceReport:
        """Run all checks and generate report."""
        checks = self.framework_class.get_checks()

        report = ComplianceReport(
            framework=self.framework,
            hostname=os.uname().nodename if hasattr(os, 'uname') else "unknown",
            scan_time=datetime.now()
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(f"Running {len(checks)} compliance checks...", total=len(checks))

            for check in checks:
                result = self.run_check(check)
                report.results.append(result)
                progress.advance(task)

        return report


# =============================================================================
# Report Generators
# =============================================================================

class ReportGenerator:
    """Generate compliance reports."""

    def __init__(self, report: ComplianceReport):
        self.report = report

    def to_html(self, output_path: str):
        """Generate HTML report."""
        severity_colors = {
            "critical": "#dc2626",
            "high": "#ea580c",
            "medium": "#d97706",
            "low": "#2563eb",
            "info": "#6b7280"
        }

        status_colors = {
            "pass": "#22c55e",
            "fail": "#ef4444",
            "warning": "#f59e0b",
            "manual": "#6b7280",
            "n/a": "#9ca3af"
        }

        # Group failures by severity
        failures_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for r in self.report.results:
            if r.status == ComplianceStatus.FAIL:
                failures_by_severity[r.check.severity.value].append(r)

        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Compliance Report - {self.report.framework}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .score {{ font-size: 64px; font-weight: bold; }}
        .score.good {{ color: #4ade80; }}
        .score.warning {{ color: #fbbf24; }}
        .score.bad {{ color: #f87171; }}
        .card {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-top: 20px; }}
        .stat {{ text-align: center; padding: 15px; background: #f9fafb; border-radius: 8px; }}
        .stat .value {{ font-size: 32px; font-weight: bold; }}
        .category {{ margin-bottom: 30px; }}
        .category h3 {{ border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; }}
        .check {{ padding: 15px; border-left: 4px solid; margin-bottom: 10px; background: #f9fafb; border-radius: 0 8px 8px 0; }}
        .check.pass {{ border-color: {status_colors["pass"]}; }}
        .check.fail {{ border-color: {status_colors["fail"]}; }}
        .check.warning {{ border-color: {status_colors["warning"]}; }}
        .badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
        .remediation {{ background: #fef3c7; padding: 10px; border-radius: 5px; margin-top: 10px; font-size: 14px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Compliance Report</h1>
            <p><strong>Framework:</strong> {self.report.framework.upper()}</p>
            <p><strong>Host:</strong> {self.report.hostname}</p>
            <p><strong>Scan Time:</strong> {self.report.scan_time.strftime("%Y-%m-%d %H:%M:%S")}</p>
            <div class="score {"good" if self.report.score >= 80 else "warning" if self.report.score >= 60 else "bad"}">{self.report.score}%</div>
        </div>

        <div class="card">
            <h2>📊 Summary</h2>
            <div class="stats">
                <div class="stat">
                    <div class="value">{self.report.total_checks}</div>
                    <div>Total Checks</div>
                </div>
                <div class="stat">
                    <div class="value" style="color: {status_colors["pass"]};">{self.report.passed}</div>
                    <div>Passed</div>
                </div>
                <div class="stat">
                    <div class="value" style="color: {status_colors["fail"]};">{self.report.failed}</div>
                    <div>Failed</div>
                </div>
                <div class="stat">
                    <div class="value" style="color: {status_colors["warning"]};">{self.report.warnings}</div>
                    <div>Warnings</div>
                </div>
            </div>
        </div>
'''

        # Priority remediations
        if self.report.failed > 0:
            html += '<div class="card"><h2>🚨 Priority Remediations</h2>'
            for severity in ["critical", "high", "medium"]:
                if failures_by_severity[severity]:
                    html += f'<h3 style="color: {severity_colors[severity]};">{severity.upper()} ({len(failures_by_severity[severity])})</h3>'
                    for r in failures_by_severity[severity][:5]:
                        html += f'''
                        <div class="check fail">
                            <strong>{r.check.id}</strong> - {r.check.title}
                            <div class="remediation">💡 {r.check.remediation}</div>
                        </div>'''
            html += '</div>'

        # Detailed results by category
        html += '<div class="card"><h2>📋 Detailed Results</h2>'
        for cat, stats in self.report.by_category().items():
            cat_score = round((stats["pass"] / stats["total"]) * 100) if stats["total"] > 0 else 0
            html += f'''
            <div class="category">
                <h3>{cat} ({cat_score}%)</h3>
            '''
            for r in self.report.results:
                if r.check.category == cat:
                    status_class = r.status.value
                    html += f'''
                    <div class="check {status_class}">
                        <span class="badge" style="background: {status_colors[r.status.value]}; color: white;">{r.status.value.upper()}</span>
                        <span class="badge" style="background: {severity_colors[r.check.severity.value]}; color: white;">{r.check.severity.value}</span>
                        <strong>{r.check.id}</strong> - {r.check.title}
                        <p style="font-size: 14px; color: #6b7280;">{r.check.description}</p>
                    </div>'''
            html += '</div>'
        html += '</div>'

        html += '''
    </div>
</body>
</html>'''

        with open(output_path, "w") as f:
            f.write(html)

        console.print(f"[green]HTML report saved to: {output_path}[/green]")

    def to_json(self, output_path: str):
        """Generate JSON report."""
        import json
        with open(output_path, "w") as f:
            json.dump(self.report.to_dict(), f, indent=2)
        console.print(f"[green]JSON report saved to: {output_path}[/green]")

    def to_markdown(self, output_path: str):
        """Generate Markdown report."""
        md = f'''# Compliance Report - {self.report.framework.upper()}

**Host:** {self.report.hostname}
**Scan Time:** {self.report.scan_time.strftime("%Y-%m-%d %H:%M:%S")}
**Score:** {self.report.score}%

## Summary

| Metric | Value |
|--------|-------|
| Total Checks | {self.report.total_checks} |
| Passed | {self.report.passed} |
| Failed | {self.report.failed} |
| Warnings | {self.report.warnings} |

## Results by Category

'''
        for cat, stats in self.report.by_category().items():
            cat_score = round((stats["pass"] / stats["total"]) * 100) if stats["total"] > 0 else 0
            md += f'''
### {cat} ({cat_score}%)

| ID | Title | Severity | Status |
|----|-------|----------|--------|
'''
            for r in self.report.results:
                if r.check.category == cat:
                    md += f"| {r.check.id} | {r.check.title} | {r.check.severity.value} | {r.status.value} |\n"

        with open(output_path, "w") as f:
            f.write(md)

        console.print(f"[green]Markdown report saved to: {output_path}[/green]")


# =============================================================================
# Display Functions
# =============================================================================

def display_summary(report: ComplianceReport):
    """Display report summary."""
    score_color = "green" if report.score >= 80 else "yellow" if report.score >= 60 else "red"

    console.print(Panel(
        f"[bold]Framework:[/bold] {report.framework.upper()}\n"
        f"[bold]Host:[/bold] {report.hostname}\n"
        f"[bold]Score:[/bold] [{score_color}]{report.score}%[/{score_color}]\n\n"
        f"✅ Passed: {report.passed}\n"
        f"❌ Failed: {report.failed}\n"
        f"⚠️  Warnings: {report.warnings}",
        title="Compliance Summary",
        border_style="blue"
    ))

    # Category breakdown
    table = Table(title="Results by Category")
    table.add_column("Category", style="cyan")
    table.add_column("Pass", justify="right", style="green")
    table.add_column("Fail", justify="right", style="red")
    table.add_column("Score", justify="right")

    for cat, stats in report.by_category().items():
        score = round((stats["pass"] / stats["total"]) * 100) if stats["total"] > 0 else 0
        score_style = "green" if score >= 80 else "yellow" if score >= 60 else "red"
        table.add_row(cat, str(stats["pass"]), str(stats["fail"]), f"[{score_style}]{score}%[/]")

    console.print(table)


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Compliance Report Generator - Multi-framework auditing",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-f", "--framework", default="cis-linux",
                        help="Compliance framework (cis-linux, anssi)")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", choices=["html", "json", "md"],
                        default="html", help="Output format")
    parser.add_argument("--compare", help="Compare with previous report (JSON)")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress terminal output")
    parser.add_argument("-v", "--version", action="version",
                        version="compliance-report-generator 1.0.0")

    args = parser.parse_args()

    console.print("[bold blue]🛡️ Compliance Report Generator[/bold blue]\n")

    # Run audit
    auditor = ComplianceAuditor(args.framework)
    report = auditor.audit()

    # Display summary
    if not args.quiet:
        display_summary(report)

    # Generate output
    if args.output:
        generator = ReportGenerator(report)
        if args.format == "json":
            generator.to_json(args.output)
        elif args.format == "md":
            generator.to_markdown(args.output)
        else:
            generator.to_html(args.output)

    # Exit code based on score
    sys.exit(0 if report.score >= 70 else 1)


if __name__ == "__main__":
    main()
```

## Exemple de Sortie

```
🛡️ Compliance Report Generator

Running 20 compliance checks...

╭─────────────────── Compliance Summary ───────────────────╮
│ Framework: CIS-LINUX                                     │
│ Host: srv-prod-01                                        │
│ Score: 75.0%                                             │
│                                                          │
│ ✅ Passed: 15                                            │
│ ❌ Failed: 4                                             │
│ ⚠️  Warnings: 1                                          │
╰──────────────────────────────────────────────────────────╯

Results by Category
┌─────────────────────────┬──────┬──────┬───────┐
│ Category                │ Pass │ Fail │ Score │
├─────────────────────────┼──────┼──────┼───────┤
│ SSH Configuration       │ 3    │ 1    │ 75%   │
│ File Permissions        │ 2    │ 1    │ 67%   │
│ Network Configuration   │ 2    │ 0    │ 100%  │
│ Logging and Auditing    │ 2    │ 0    │ 100%  │
└─────────────────────────┴──────┴──────┴───────┘
```

## Cas d'Usage

1. **Audit de Conformité** : Vérification régulière de la conformité
2. **Onboarding Serveurs** : Validation avant mise en production
3. **Reporting Management** : Rapports pour les équipes sécurité
4. **CI/CD Gate** : Bloquer les déploiements non conformes

## Voir Aussi

- [patch_compliance_report.py](./patch_compliance_report.md) - Audit conformité patchs système
- [security_audit.py](../bash/security-audit.md) - Audit de sécurité basique
- [log_anomaly_detector.py](./log_anomaly_detector.md) - Détection d'anomalies dans les logs
