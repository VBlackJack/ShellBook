# System Tuning Advisor

Script Python d'analyse et recommandations de tuning système Linux.

## Description

- **Analyse automatique** : Détection du profil d'usage (Web, DB, HPC, Container)
- **Recommandations sysctl** : Tuning kernel paramétré selon le workload
- **Limits.conf** : Ajustements des limites utilisateur
- **Scheduler I/O** : Recommandations de scheduler disque
- **NUMA-aware** : Optimisations pour systèmes multi-socket
- **Export** : Génération de scripts de tuning applicables

## Prérequis

```bash
pip install rich psutil pyyaml
```

## Utilisation

```bash
# Analyse complète avec recommandations
python system_tuning_advisor.py

# Mode spécifique pour serveur web
python system_tuning_advisor.py --profile web

# Mode serveur de base de données
python system_tuning_advisor.py --profile database

# Export des recommandations en script applicable
python system_tuning_advisor.py --export tuning.sh

# Comparaison avec configuration actuelle
python system_tuning_advisor.py --compare

# Mode JSON pour automation
python system_tuning_advisor.py --format json --output tuning.json
```

## Profils Disponibles

| Profil | Description | Cas d'usage |
|--------|-------------|-------------|
| `auto` | Détection automatique | Défaut |
| `web` | Serveur web/API | Nginx, Apache, API |
| `database` | Serveur BDD | PostgreSQL, MySQL, MongoDB |
| `hpc` | High Performance Computing | Calcul scientifique |
| `container` | Hôte de conteneurs | Docker, Kubernetes |
| `balanced` | Usage général | Workloads mixtes |

## Code Source

```python
#!/usr/bin/env python3
"""
System Tuning Advisor - Automated system performance tuning recommendations.

Features:
- Automatic workload detection
- Sysctl recommendations
- I/O scheduler optimization
- NUMA-aware tuning
- Export to executable scripts
"""

import os
import sys
import re
import subprocess
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.tree import Tree
    import psutil
    import yaml
except ImportError:
    print("Missing dependencies. Install with: pip install rich psutil pyyaml")
    sys.exit(1)

console = Console()

# =============================================================================
# Data Models
# =============================================================================

class WorkloadProfile(Enum):
    """System workload profiles."""
    AUTO = "auto"
    WEB = "web"
    DATABASE = "database"
    HPC = "hpc"
    CONTAINER = "container"
    BALANCED = "balanced"


class Priority(Enum):
    """Recommendation priority."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SystemInfo:
    """System hardware and configuration info."""
    cpu_count: int = 0
    cpu_model: str = ""
    memory_gb: float = 0.0
    swap_gb: float = 0.0
    numa_nodes: int = 1
    disk_type: str = "unknown"  # ssd, hdd, nvme
    hypervisor: Optional[str] = None
    kernel_version: str = ""
    architecture: str = ""


@dataclass
class Recommendation:
    """A single tuning recommendation."""
    category: str
    parameter: str
    current_value: str
    recommended_value: str
    description: str
    priority: Priority = Priority.MEDIUM
    apply_command: str = ""
    persistent_config: str = ""

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "parameter": self.parameter,
            "current_value": self.current_value,
            "recommended_value": self.recommended_value,
            "description": self.description,
            "priority": self.priority.value,
            "apply_command": self.apply_command,
            "persistent_config": self.persistent_config
        }


# =============================================================================
# System Analysis
# =============================================================================

class SystemAnalyzer:
    """Analyze system configuration and hardware."""

    def __init__(self):
        self.info = SystemInfo()
        self._gather_info()

    def _gather_info(self):
        """Gather system information."""
        # CPU info
        self.info.cpu_count = psutil.cpu_count(logical=True)
        try:
            with open("/proc/cpuinfo") as f:
                for line in f:
                    if "model name" in line:
                        self.info.cpu_model = line.split(":")[1].strip()
                        break
        except Exception:
            self.info.cpu_model = "Unknown"

        # Memory info
        mem = psutil.virtual_memory()
        self.info.memory_gb = round(mem.total / (1024**3), 1)

        swap = psutil.swap_memory()
        self.info.swap_gb = round(swap.total / (1024**3), 1)

        # NUMA nodes
        try:
            numa_path = Path("/sys/devices/system/node")
            if numa_path.exists():
                self.info.numa_nodes = len([
                    d for d in numa_path.iterdir()
                    if d.name.startswith("node")
                ])
        except Exception:
            self.info.numa_nodes = 1

        # Disk type detection
        self.info.disk_type = self._detect_disk_type()

        # Hypervisor detection
        self.info.hypervisor = self._detect_hypervisor()

        # Kernel version
        try:
            self.info.kernel_version = os.uname().release
        except Exception:
            self.info.kernel_version = "unknown"

        # Architecture
        self.info.architecture = os.uname().machine

    def _detect_disk_type(self) -> str:
        """Detect primary disk type."""
        try:
            for disk in Path("/sys/block").iterdir():
                if disk.name.startswith(("sd", "nvme", "vd")):
                    rotational = disk / "queue" / "rotational"
                    if rotational.exists():
                        is_rotational = rotational.read_text().strip() == "1"
                        if disk.name.startswith("nvme"):
                            return "nvme"
                        return "hdd" if is_rotational else "ssd"
        except Exception:
            pass
        return "unknown"

    def _detect_hypervisor(self) -> Optional[str]:
        """Detect if running in a VM."""
        try:
            result = subprocess.run(
                ["systemd-detect-virt"],
                capture_output=True,
                text=True,
                timeout=5
            )
            virt = result.stdout.strip()
            if virt and virt != "none":
                return virt
        except Exception:
            pass

        # Fallback detection
        try:
            with open("/proc/cpuinfo") as f:
                content = f.read().lower()
                if "hypervisor" in content:
                    return "unknown-vm"
        except Exception:
            pass

        return None

    def detect_workload(self) -> WorkloadProfile:
        """Auto-detect workload profile based on running services."""
        services = self._get_running_services()
        process_names = {p.name().lower() for p in psutil.process_iter(['name'])}

        # Database detection
        db_indicators = {"mysql", "mysqld", "postgres", "postgresql", "mongod", "redis-server"}
        if db_indicators & process_names:
            return WorkloadProfile.DATABASE

        # Web server detection
        web_indicators = {"nginx", "apache", "httpd", "caddy", "node", "gunicorn", "uvicorn"}
        if web_indicators & process_names:
            return WorkloadProfile.WEB

        # Container host detection
        container_indicators = {"dockerd", "containerd", "kubelet", "podman"}
        if container_indicators & process_names:
            return WorkloadProfile.CONTAINER

        # HPC detection (high CPU usage pattern)
        cpu_percent = psutil.cpu_percent(interval=1)
        if cpu_percent > 70 and self.info.cpu_count >= 8:
            return WorkloadProfile.HPC

        return WorkloadProfile.BALANCED

    def _get_running_services(self) -> set:
        """Get list of running systemd services."""
        services = set()
        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend"],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.strip().split("\n"):
                if line:
                    services.add(line.split()[0].replace(".service", ""))
        except Exception:
            pass
        return services

    def get_current_sysctl(self, param: str) -> str:
        """Get current sysctl value."""
        try:
            result = subprocess.run(
                ["sysctl", "-n", param],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"


# =============================================================================
# Tuning Profiles
# =============================================================================

class TuningAdvisor:
    """Generate tuning recommendations."""

    def __init__(self, analyzer: SystemAnalyzer, profile: WorkloadProfile):
        self.analyzer = analyzer
        self.profile = profile
        self.recommendations: list = []

    def analyze(self) -> list:
        """Generate all recommendations."""
        self.recommendations = []

        # Core kernel tuning
        self._analyze_memory()
        self._analyze_network()
        self._analyze_filesystem()
        self._analyze_scheduler()
        self._analyze_limits()

        # Profile-specific tuning
        if self.profile in (WorkloadProfile.DATABASE, WorkloadProfile.AUTO):
            self._analyze_database_tuning()
        if self.profile in (WorkloadProfile.WEB, WorkloadProfile.AUTO):
            self._analyze_web_tuning()
        if self.profile in (WorkloadProfile.CONTAINER, WorkloadProfile.AUTO):
            self._analyze_container_tuning()
        if self.profile in (WorkloadProfile.HPC, WorkloadProfile.AUTO):
            self._analyze_hpc_tuning()

        return self.recommendations

    def _add_recommendation(
        self,
        category: str,
        parameter: str,
        recommended: str,
        description: str,
        priority: Priority = Priority.MEDIUM
    ):
        """Add a recommendation if current value differs."""
        current = self.analyzer.get_current_sysctl(parameter)

        # Skip if already optimized
        if current == recommended:
            return

        # Build apply command
        if parameter.startswith("vm.") or parameter.startswith("net.") or parameter.startswith("kernel."):
            apply_cmd = f"sysctl -w {parameter}={recommended}"
            persistent = f"{parameter} = {recommended}"
        else:
            apply_cmd = ""
            persistent = ""

        self.recommendations.append(Recommendation(
            category=category,
            parameter=parameter,
            current_value=current,
            recommended_value=recommended,
            description=description,
            priority=priority,
            apply_command=apply_cmd,
            persistent_config=persistent
        ))

    def _analyze_memory(self):
        """Memory management tuning."""
        mem_gb = self.analyzer.info.memory_gb

        # Swappiness - lower for servers with enough RAM
        if mem_gb >= 8:
            self._add_recommendation(
                "Memory",
                "vm.swappiness",
                "10",
                "Reduce swap usage for servers with sufficient RAM",
                Priority.HIGH
            )
        elif mem_gb >= 4:
            self._add_recommendation(
                "Memory",
                "vm.swappiness",
                "30",
                "Moderate swap usage for medium memory systems"
            )

        # Dirty ratio tuning based on RAM
        if mem_gb >= 16:
            self._add_recommendation(
                "Memory",
                "vm.dirty_ratio",
                "10",
                "Reduce dirty page ratio to prevent I/O storms",
                Priority.MEDIUM
            )
            self._add_recommendation(
                "Memory",
                "vm.dirty_background_ratio",
                "5",
                "Start background writeback earlier"
            )

        # VFS cache pressure
        self._add_recommendation(
            "Memory",
            "vm.vfs_cache_pressure",
            "50",
            "Balance inode/dentry cache retention",
            Priority.LOW
        )

        # Overcommit settings
        if self.profile == WorkloadProfile.DATABASE:
            self._add_recommendation(
                "Memory",
                "vm.overcommit_memory",
                "2",
                "Disable overcommit for database stability",
                Priority.HIGH
            )

        # Transparent Huge Pages
        if self.profile in (WorkloadProfile.DATABASE, WorkloadProfile.CONTAINER):
            self.recommendations.append(Recommendation(
                category="Memory",
                parameter="transparent_hugepage",
                current_value=self._get_thp_status(),
                recommended_value="never",
                description="Disable THP for database/container workloads",
                priority=Priority.HIGH,
                apply_command="echo never > /sys/kernel/mm/transparent_hugepage/enabled",
                persistent_config="# Add to /etc/rc.local or systemd service"
            ))

    def _get_thp_status(self) -> str:
        """Get current THP status."""
        try:
            with open("/sys/kernel/mm/transparent_hugepage/enabled") as f:
                content = f.read()
                match = re.search(r'\[(\w+)\]', content)
                return match.group(1) if match else "unknown"
        except Exception:
            return "unknown"

    def _analyze_network(self):
        """Network stack tuning."""
        mem_gb = self.analyzer.info.memory_gb

        # Connection tracking
        if mem_gb >= 8:
            self._add_recommendation(
                "Network",
                "net.netfilter.nf_conntrack_max",
                str(min(1048576, int(mem_gb * 65536))),
                "Increase connection tracking table size",
                Priority.MEDIUM
            )

        # TCP tuning
        self._add_recommendation(
            "Network",
            "net.core.somaxconn",
            "65535",
            "Increase max socket connections queue",
            Priority.HIGH
        )

        self._add_recommendation(
            "Network",
            "net.core.netdev_max_backlog",
            "65535",
            "Increase network device backlog",
            Priority.MEDIUM
        )

        # TCP memory
        if mem_gb >= 8:
            tcp_mem = f"{int(mem_gb*1024*256)} {int(mem_gb*1024*512)} {int(mem_gb*1024*768)}"
            self._add_recommendation(
                "Network",
                "net.ipv4.tcp_mem",
                tcp_mem,
                "Scale TCP memory based on system RAM"
            )

        # TCP keepalive
        self._add_recommendation(
            "Network",
            "net.ipv4.tcp_keepalive_time",
            "600",
            "Reduce TCP keepalive time",
            Priority.LOW
        )

        # TCP performance
        self._add_recommendation(
            "Network",
            "net.ipv4.tcp_fastopen",
            "3",
            "Enable TCP Fast Open",
            Priority.LOW
        )

        self._add_recommendation(
            "Network",
            "net.ipv4.tcp_slow_start_after_idle",
            "0",
            "Disable slow start after idle",
            Priority.LOW
        )

        # Port range
        self._add_recommendation(
            "Network",
            "net.ipv4.ip_local_port_range",
            "1024 65535",
            "Increase ephemeral port range",
            Priority.MEDIUM
        )

        # TIME_WAIT optimization
        self._add_recommendation(
            "Network",
            "net.ipv4.tcp_tw_reuse",
            "1",
            "Enable TIME_WAIT socket reuse",
            Priority.MEDIUM
        )

    def _analyze_filesystem(self):
        """Filesystem tuning."""
        # File descriptors
        self._add_recommendation(
            "Filesystem",
            "fs.file-max",
            str(max(2097152, self.analyzer.info.memory_gb * 100000)),
            "Increase maximum file descriptors",
            Priority.HIGH
        )

        # Inotify limits
        self._add_recommendation(
            "Filesystem",
            "fs.inotify.max_user_watches",
            "524288",
            "Increase inotify watches for dev tools",
            Priority.LOW
        )

        self._add_recommendation(
            "Filesystem",
            "fs.inotify.max_user_instances",
            "1024",
            "Increase inotify instances"
        )

        # AIO limits
        self._add_recommendation(
            "Filesystem",
            "fs.aio-max-nr",
            "1048576",
            "Increase async I/O limit",
            Priority.MEDIUM
        )

    def _analyze_scheduler(self):
        """I/O scheduler recommendations."""
        disk_type = self.analyzer.info.disk_type

        if disk_type == "nvme":
            scheduler = "none"
            desc = "NVMe drives work best without I/O scheduler"
        elif disk_type == "ssd":
            scheduler = "mq-deadline"
            desc = "mq-deadline provides good SSD performance"
        else:
            scheduler = "bfq"
            desc = "BFQ provides fair scheduling for HDDs"

        for disk in Path("/sys/block").iterdir():
            if disk.name.startswith(("sd", "nvme", "vd")):
                sched_file = disk / "queue" / "scheduler"
                if sched_file.exists():
                    current = sched_file.read_text().strip()
                    # Extract active scheduler [scheduler]
                    match = re.search(r'\[(\w+)\]', current)
                    current_sched = match.group(1) if match else current

                    if current_sched != scheduler:
                        self.recommendations.append(Recommendation(
                            category="I/O Scheduler",
                            parameter=f"/sys/block/{disk.name}/queue/scheduler",
                            current_value=current_sched,
                            recommended_value=scheduler,
                            description=f"{desc} ({disk.name})",
                            priority=Priority.MEDIUM,
                            apply_command=f"echo {scheduler} > /sys/block/{disk.name}/queue/scheduler",
                            persistent_config=f"# Add udev rule for {disk.name}"
                        ))

    def _analyze_limits(self):
        """User limits recommendations."""
        self.recommendations.append(Recommendation(
            category="Limits",
            parameter="/etc/security/limits.conf",
            current_value="default",
            recommended_value="see below",
            description="Increase process limits for service users",
            priority=Priority.HIGH,
            apply_command="",
            persistent_config="* soft nofile 65535\n* hard nofile 65535\n* soft nproc 65535\n* hard nproc 65535"
        ))

    def _analyze_database_tuning(self):
        """Database-specific tuning."""
        mem_gb = self.analyzer.info.memory_gb

        # Huge pages for databases
        if mem_gb >= 16:
            huge_pages = int(mem_gb * 0.4 * 1024 / 2)  # 40% of RAM as 2MB pages
            self._add_recommendation(
                "Database",
                "vm.nr_hugepages",
                str(huge_pages),
                "Allocate huge pages for database shared buffers",
                Priority.MEDIUM
            )

        # Semaphores
        self._add_recommendation(
            "Database",
            "kernel.sem",
            "250 32000 100 128",
            "Increase semaphore limits for databases",
            Priority.MEDIUM
        )

        # Shared memory
        shmmax = int(mem_gb * 0.75 * 1024**3)
        self._add_recommendation(
            "Database",
            "kernel.shmmax",
            str(shmmax),
            "Increase max shared memory segment",
            Priority.HIGH
        )

    def _analyze_web_tuning(self):
        """Web server-specific tuning."""
        # Already covered by network tuning
        # Add web-specific items
        self._add_recommendation(
            "Web",
            "net.ipv4.tcp_fin_timeout",
            "15",
            "Reduce FIN timeout for high-traffic servers",
            Priority.MEDIUM
        )

    def _analyze_container_tuning(self):
        """Container host tuning."""
        # Bridge netfilter
        self._add_recommendation(
            "Container",
            "net.bridge.bridge-nf-call-iptables",
            "1",
            "Enable bridge netfilter for container networking",
            Priority.HIGH
        )

        self._add_recommendation(
            "Container",
            "net.bridge.bridge-nf-call-ip6tables",
            "1",
            "Enable IPv6 bridge netfilter"
        )

        # IP forwarding
        self._add_recommendation(
            "Container",
            "net.ipv4.ip_forward",
            "1",
            "Enable IP forwarding for containers",
            Priority.CRITICAL
        )

        # PID limits
        self._add_recommendation(
            "Container",
            "kernel.pid_max",
            "4194304",
            "Increase max PIDs for container workloads",
            Priority.MEDIUM
        )

    def _analyze_hpc_tuning(self):
        """HPC-specific tuning."""
        # NUMA balancing
        if self.analyzer.info.numa_nodes > 1:
            self._add_recommendation(
                "HPC",
                "kernel.numa_balancing",
                "0",
                "Disable NUMA balancing for HPC (manage manually)",
                Priority.HIGH
            )

        # Scheduler latency
        self._add_recommendation(
            "HPC",
            "kernel.sched_migration_cost_ns",
            "5000000",
            "Increase migration cost for CPU-bound tasks",
            Priority.MEDIUM
        )


# =============================================================================
# Report Generation
# =============================================================================

def export_script(recommendations: list, output_path: str):
    """Export recommendations as executable script."""
    script = '''#!/bin/bash
#===============================================================================
# System Tuning Script - Generated by System Tuning Advisor
# Generated: {timestamp}
#
# WARNING: Review all settings before applying!
# Run as root: sudo ./tuning.sh
#===============================================================================

set -euo pipefail

echo "🔧 Applying system tuning..."

# Create backup
BACKUP_DIR="/var/backup/sysctl-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
sysctl -a > "$BACKUP_DIR/sysctl-backup.conf" 2>/dev/null || true
echo "✅ Backup created: $BACKUP_DIR"

'''.format(timestamp=__import__('datetime').datetime.now().isoformat())

    # Group by category
    categories = {}
    for rec in recommendations:
        if rec.category not in categories:
            categories[rec.category] = []
        categories[rec.category].append(rec)

    for category, recs in categories.items():
        script += f"\n# === {category} ===\n"
        for rec in recs:
            script += f"# {rec.description}\n"
            if rec.apply_command:
                script += f"{rec.apply_command}\n"
            script += "\n"

    script += '''
# Generate persistent config
cat > /etc/sysctl.d/99-tuning.conf << 'SYSCTL'
# System Tuning - Generated by System Tuning Advisor
'''

    for rec in recommendations:
        if rec.persistent_config and "=" in rec.persistent_config:
            script += f"# {rec.description}\n"
            script += f"{rec.persistent_config}\n\n"

    script += '''SYSCTL

echo "✅ Persistent config written to /etc/sysctl.d/99-tuning.conf"
echo "🔄 Reload with: sysctl --system"
'''

    with open(output_path, "w") as f:
        f.write(script)

    os.chmod(output_path, 0o755)
    console.print(f"[green]Script exported:[/green] {output_path}")


def export_json(recommendations: list, system_info: SystemInfo, output_path: str):
    """Export recommendations as JSON."""
    import json

    data = {
        "generated": __import__('datetime').datetime.now().isoformat(),
        "system_info": {
            "cpu_count": system_info.cpu_count,
            "cpu_model": system_info.cpu_model,
            "memory_gb": system_info.memory_gb,
            "numa_nodes": system_info.numa_nodes,
            "disk_type": system_info.disk_type,
            "hypervisor": system_info.hypervisor,
            "kernel_version": system_info.kernel_version
        },
        "recommendations_count": len(recommendations),
        "by_priority": {
            "critical": sum(1 for r in recommendations if r.priority == Priority.CRITICAL),
            "high": sum(1 for r in recommendations if r.priority == Priority.HIGH),
            "medium": sum(1 for r in recommendations if r.priority == Priority.MEDIUM),
            "low": sum(1 for r in recommendations if r.priority == Priority.LOW)
        },
        "recommendations": [r.to_dict() for r in recommendations]
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    console.print(f"[green]JSON exported:[/green] {output_path}")


# =============================================================================
# Display Functions
# =============================================================================

def display_system_info(info: SystemInfo, profile: WorkloadProfile):
    """Display system information panel."""
    tree = Tree("🖥️  [bold]System Information[/bold]")
    tree.add(f"CPU: {info.cpu_count} cores - {info.cpu_model}")
    tree.add(f"Memory: {info.memory_gb} GB (Swap: {info.swap_gb} GB)")
    tree.add(f"NUMA Nodes: {info.numa_nodes}")
    tree.add(f"Primary Disk: {info.disk_type.upper()}")
    tree.add(f"Kernel: {info.kernel_version}")
    if info.hypervisor:
        tree.add(f"Hypervisor: {info.hypervisor}")
    tree.add(f"[cyan]Detected Profile: {profile.value.upper()}[/cyan]")

    console.print(Panel(tree, title="System Analysis", border_style="blue"))


def display_recommendations(recommendations: list):
    """Display recommendations table."""
    if not recommendations:
        console.print("[green]✅ System is already well-tuned![/green]")
        return

    # Group by category
    categories = {}
    for rec in recommendations:
        if rec.category not in categories:
            categories[rec.category] = []
        categories[rec.category].append(rec)

    priority_colors = {
        Priority.CRITICAL: "bold red",
        Priority.HIGH: "orange1",
        Priority.MEDIUM: "yellow",
        Priority.LOW: "dim"
    }

    for category, recs in categories.items():
        table = Table(title=f"📋 {category}", show_header=True)
        table.add_column("Parameter", style="cyan", width=35)
        table.add_column("Current", style="red", width=15)
        table.add_column("Recommended", style="green", width=15)
        table.add_column("Priority", width=10)
        table.add_column("Description", width=40)

        for rec in sorted(recs, key=lambda r: r.priority.value):
            table.add_row(
                rec.parameter[:35],
                rec.current_value[:15],
                rec.recommended_value[:15],
                f"[{priority_colors[rec.priority]}]{rec.priority.value.upper()}[/]",
                rec.description[:40]
            )

        console.print(table)
        console.print()


# =============================================================================
# CLI Entry Point
# =============================================================================

def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="System Tuning Advisor - Performance optimization recommendations",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("-p", "--profile",
                        choices=["auto", "web", "database", "hpc", "container", "balanced"],
                        default="auto",
                        help="Workload profile (default: auto)")
    parser.add_argument("-e", "--export",
                        help="Export tuning script to file")
    parser.add_argument("-o", "--output",
                        help="Output file for JSON/report")
    parser.add_argument("-f", "--format",
                        choices=["table", "json"],
                        default="table",
                        help="Output format (default: table)")
    parser.add_argument("-c", "--compare",
                        action="store_true",
                        help="Show comparison with current values")
    parser.add_argument("-q", "--quiet",
                        action="store_true",
                        help="Suppress terminal output")
    parser.add_argument("-v", "--version",
                        action="version",
                        version="system-tuning-advisor 1.0.0")

    args = parser.parse_args()

    # Check root for some operations
    if os.geteuid() != 0:
        console.print("[yellow]⚠ Running as non-root. Some values may not be readable.[/yellow]\n")

    # Analyze system
    console.print("[bold blue]🔍 System Tuning Advisor[/bold blue]\n")

    analyzer = SystemAnalyzer()

    # Determine profile
    profile_map = {
        "auto": WorkloadProfile.AUTO,
        "web": WorkloadProfile.WEB,
        "database": WorkloadProfile.DATABASE,
        "hpc": WorkloadProfile.HPC,
        "container": WorkloadProfile.CONTAINER,
        "balanced": WorkloadProfile.BALANCED
    }
    profile = profile_map.get(args.profile, WorkloadProfile.AUTO)

    if profile == WorkloadProfile.AUTO:
        profile = analyzer.detect_workload()

    # Display system info
    if not args.quiet:
        display_system_info(analyzer.info, profile)

    # Generate recommendations
    advisor = TuningAdvisor(analyzer, profile)
    recommendations = advisor.analyze()

    # Display or export
    if args.format == "json" and args.output:
        export_json(recommendations, analyzer.info, args.output)
    elif not args.quiet:
        display_recommendations(recommendations)

    # Export script if requested
    if args.export:
        export_script(recommendations, args.export)

    # Summary
    if not args.quiet:
        console.print(Panel(
            f"Total recommendations: {len(recommendations)}\n"
            f"🔴 Critical: {sum(1 for r in recommendations if r.priority == Priority.CRITICAL)}\n"
            f"🟠 High: {sum(1 for r in recommendations if r.priority == Priority.HIGH)}\n"
            f"🟡 Medium: {sum(1 for r in recommendations if r.priority == Priority.MEDIUM)}\n"
            f"🔵 Low: {sum(1 for r in recommendations if r.priority == Priority.LOW)}",
            title="Summary",
            border_style="green"
        ))

    # Return exit code based on critical issues
    critical_count = sum(1 for r in recommendations if r.priority == Priority.CRITICAL)
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == "__main__":
    main()
```

## Exemple de Sortie

```
🔍 System Tuning Advisor

╭─────────────────── System Analysis ───────────────────╮
│ 🖥️  System Information                                │
│ ├── CPU: 16 cores - Intel(R) Xeon(R) Gold 6248       │
│ ├── Memory: 64.0 GB (Swap: 4.0 GB)                   │
│ ├── NUMA Nodes: 2                                     │
│ ├── Primary Disk: NVME                               │
│ ├── Kernel: 5.15.0-generic                           │
│ └── Detected Profile: DATABASE                        │
╰───────────────────────────────────────────────────────╯

📋 Memory
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━┓
┃ Parameter             ┃ Current  ┃ Recommended ┃ Priority ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━┩
│ vm.swappiness         │ 60       │ 10          │ HIGH     │
│ vm.dirty_ratio        │ 20       │ 10          │ MEDIUM   │
│ transparent_hugepage  │ always   │ never       │ HIGH     │
└───────────────────────┴──────────┴─────────────┴──────────┘
```

## Cas d'Usage

1. **Audit Pre-Production** : Vérifier le tuning avant mise en production
2. **Baseline Configuration** : Établir une configuration de référence
3. **Troubleshooting** : Identifier les paramètres sous-optimaux
4. **Compliance** : Documenter les paramètres de performance
