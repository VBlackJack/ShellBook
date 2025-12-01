---
tags:
  - scripts
  - python
  - système
  - monitoring
---

# system_info.py

:material-star: **Niveau : Débutant**

Affiche les informations système complètes.

---

## Description

Ce script collecte et affiche les informations système :
- OS et hardware
- CPU et mémoire
- Disques
- Réseau
- Processus actifs

---

## Prérequis

- **Python** : Version 3.8+
- **Modules** : `psutil`, `rich` (optionnel pour l'affichage enrichi)
- **Système** : Linux, macOS ou Windows
- **Permissions** : Droits de lecture sur /proc (Linux) ou équivalent système pour accéder aux métriques

---

## Cas d'Usage

- **Audit système** : Collecte rapide des informations matérielles et logicielles pour documentation d'infrastructure
- **Monitoring de base** : Surveillance ponctuelle de l'utilisation CPU, mémoire et disques
- **Troubleshooting** : Diagnostic initial lors de problèmes de performance pour identifier les goulots d'étranglement
- **Inventaire IT** : Génération de rapports JSON pour centralisation dans un CMDB
- **Scripts d'installation** : Vérification des prérequis système avant déploiement d'applications

---

## Dépendances

```bash
pip install psutil rich
```

---

## Script

```python
#!/usr/bin/env python3
"""
Script Name: system_info.py
Description: Display comprehensive system information
Author: ShellBook
Version: 1.0

Dependencies:
    pip install psutil rich
"""

import argparse
import json
import platform
import socket
from datetime import datetime
from typing import Dict, Any

try:
    import psutil
except ImportError:
    print("Error: psutil required. Install with: pip install psutil")
    exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def get_size(bytes_value: int, suffix: str = "B") -> str:
    """Convertit les bytes en format lisible."""
    for unit in ["", "K", "M", "G", "T"]:
        if abs(bytes_value) < 1024.0:
            return f"{bytes_value:3.1f}{unit}{suffix}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f}P{suffix}"


def get_os_info() -> Dict[str, Any]:
    """Retrieve les informations OS."""
    uname = platform.uname()
    boot_time = datetime.fromtimestamp(psutil.boot_time())
    uptime = datetime.now() - boot_time

    return {
        "system": uname.system,
        "node_name": uname.node,
        "release": uname.release,
        "version": uname.version,
        "machine": uname.machine,
        "processor": uname.processor or platform.processor(),
        "boot_time": boot_time.strftime("%Y-%m-%d %H:%M:%S"),
        "uptime": str(uptime).split('.')[0]
    }


def get_cpu_info() -> Dict[str, Any]:
    """Retrieve les informations CPU."""
    cpu_freq = psutil.cpu_freq()

    return {
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "max_frequency": f"{cpu_freq.max:.0f} MHz" if cpu_freq else "N/A",
        "current_frequency": f"{cpu_freq.current:.0f} MHz" if cpu_freq else "N/A",
        "usage_percent": f"{psutil.cpu_percent(interval=1)}%",
        "per_core_usage": [f"{x}%" for x in psutil.cpu_percent(percpu=True, interval=0)]
    }


def get_memory_info() -> Dict[str, Any]:
    """Retrieve les informations mémoire."""
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()

    return {
        "total": get_size(mem.total),
        "available": get_size(mem.available),
        "used": get_size(mem.used),
        "percent": f"{mem.percent}%",
        "swap_total": get_size(swap.total),
        "swap_used": get_size(swap.used),
        "swap_percent": f"{swap.percent}%"
    }


def get_disk_info() -> list:
    """Retrieve les informations disques."""
    disks = []
    for partition in psutil.disk_partitions():
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disks.append({
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "fstype": partition.fstype,
                "total": get_size(usage.total),
                "used": get_size(usage.used),
                "free": get_size(usage.free),
                "percent": f"{usage.percent}%"
            })
        except PermissionError:
            continue
    return disks


def get_network_info() -> Dict[str, Any]:
    """Retrieve les informations réseau."""
    hostname = socket.gethostname()

    try:
        ip_address = socket.gethostbyname(hostname)
    except socket.gaierror:
        ip_address = "N/A"

    interfaces = {}
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                interfaces[name] = {
                    "ip": addr.address,
                    "netmask": addr.netmask
                }

    io = psutil.net_io_counters()

    return {
        "hostname": hostname,
        "ip_address": ip_address,
        "interfaces": interfaces,
        "bytes_sent": get_size(io.bytes_sent),
        "bytes_recv": get_size(io.bytes_recv)
    }


def get_top_processes(n: int = 5) -> list:
    """Retrieve les processus les plus gourmands."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = proc.info
            processes.append({
                "pid": pinfo['pid'],
                "name": pinfo['name'][:20],
                "cpu": pinfo['cpu_percent'] or 0,
                "memory": pinfo['memory_percent'] or 0
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Top CPU
    top_cpu = sorted(processes, key=lambda x: x['cpu'], reverse=True)[:n]
    # Top Memory
    top_mem = sorted(processes, key=lambda x: x['memory'], reverse=True)[:n]

    return {"cpu": top_cpu, "memory": top_mem}


def display_rich(info: Dict[str, Any]) -> None:
    """Affichage avec Rich."""
    console = Console()

    # Header
    console.print(Panel.fit(
        f"[bold cyan]System Information Report[/bold cyan]\n"
        f"[dim]Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
        border_style="cyan"
    ))

    # OS Info
    console.print("\n[bold green]▶ Operating System[/bold green]")
    os_table = Table(show_header=False, box=None)
    os_table.add_column(style="cyan", width=20)
    os_table.add_column()
    for key, value in info['os'].items():
        os_table.add_row(key.replace('_', ' ').title(), str(value))
    console.print(os_table)

    # CPU Info
    console.print("\n[bold green]▶ CPU[/bold green]")
    cpu_table = Table(show_header=False, box=None)
    cpu_table.add_column(style="cyan", width=20)
    cpu_table.add_column()
    cpu_info = info['cpu']
    cpu_table.add_row("Physical Cores", str(cpu_info['physical_cores']))
    cpu_table.add_row("Logical Cores", str(cpu_info['logical_cores']))
    cpu_table.add_row("Max Frequency", cpu_info['max_frequency'])
    cpu_table.add_row("Current Usage", cpu_info['usage_percent'])
    console.print(cpu_table)

    # Memory Info
    console.print("\n[bold green]▶ Memory[/bold green]")
    mem = info['memory']
    mem_percent = float(mem['percent'].rstrip('%'))
    color = "green" if mem_percent < 70 else "yellow" if mem_percent < 90 else "red"
    console.print(f"  RAM: [{color}]{mem['used']}[/{color}] / {mem['total']} ({mem['percent']})")
    console.print(f"  Swap: {mem['swap_used']} / {mem['swap_total']} ({mem['swap_percent']})")

    # Disk Info
    console.print("\n[bold green]▶ Disks[/bold green]")
    disk_table = Table()
    disk_table.add_column("Device", style="cyan")
    disk_table.add_column("Mount")
    disk_table.add_column("Total")
    disk_table.add_column("Used")
    disk_table.add_column("Free")
    disk_table.add_column("Usage")

    for disk in info['disks']:
        percent = float(disk['percent'].rstrip('%'))
        style = "green" if percent < 70 else "yellow" if percent < 90 else "red"
        disk_table.add_row(
            disk['device'],
            disk['mountpoint'],
            disk['total'],
            disk['used'],
            disk['free'],
            f"[{style}]{disk['percent']}[/{style}]"
        )
    console.print(disk_table)

    # Network Info
    console.print("\n[bold green]▶ Network[/bold green]")
    net = info['network']
    console.print(f"  Hostname: {net['hostname']}")
    console.print(f"  Primary IP: {net['ip_address']}")
    for iface, details in net['interfaces'].items():
        console.print(f"  {iface}: {details['ip']}")

    # Top Processes
    console.print("\n[bold green]▶ Top Processes (CPU)[/bold green]")
    proc_table = Table()
    proc_table.add_column("PID", style="cyan")
    proc_table.add_column("Name")
    proc_table.add_column("CPU %", justify="right")
    proc_table.add_column("Memory %", justify="right")

    for proc in info['processes']['cpu']:
        proc_table.add_row(
            str(proc['pid']),
            proc['name'],
            f"{proc['cpu']:.1f}%",
            f"{proc['memory']:.1f}%"
        )
    console.print(proc_table)


def display_simple(info: Dict[str, Any]) -> None:
    """Affichage simple sans Rich."""
    print("\n" + "=" * 60)
    print("  SYSTEM INFORMATION")
    print("=" * 60)

    print("\n▶ Operating System")
    for key, value in info['os'].items():
        print(f"  {key.replace('_', ' ').title():20}: {value}")

    print("\n▶ CPU")
    cpu = info['cpu']
    print(f"  {'Physical Cores':20}: {cpu['physical_cores']}")
    print(f"  {'Logical Cores':20}: {cpu['logical_cores']}")
    print(f"  {'Usage':20}: {cpu['usage_percent']}")

    print("\n▶ Memory")
    mem = info['memory']
    print(f"  {'RAM':20}: {mem['used']} / {mem['total']} ({mem['percent']})")
    print(f"  {'Swap':20}: {mem['swap_used']} / {mem['swap_total']}")

    print("\n▶ Disks")
    for disk in info['disks']:
        print(f"  {disk['device']:10} {disk['mountpoint']:15} "
              f"{disk['used']:>10} / {disk['total']:>10} ({disk['percent']})")

    print("\n▶ Network")
    net = info['network']
    print(f"  {'Hostname':20}: {net['hostname']}")
    print(f"  {'IP Address':20}: {net['ip_address']}")

    print("\n" + "=" * 60)


def main():
    parser = argparse.ArgumentParser(description="System Information Tool")
    parser.add_argument('-j', '--json', action='store_true', help='Output as JSON')
    parser.add_argument('-s', '--simple', action='store_true', help='Simple output (no colors)')
    args = parser.parse_args()

    # Collecter les informations
    info = {
        "timestamp": datetime.now().isoformat(),
        "os": get_os_info(),
        "cpu": get_cpu_info(),
        "memory": get_memory_info(),
        "disks": get_disk_info(),
        "network": get_network_info(),
        "processes": get_top_processes()
    }

    # Affichage
    if args.json:
        print(json.dumps(info, indent=2, default=str))
    elif args.simple or not RICH_AVAILABLE:
        display_simple(info)
    else:
        display_rich(info)


if __name__ == '__main__':
    main()
```

---

## Utilisation

```bash
# Affichage standard (avec Rich si disponible)
python system_info.py

# Sortie JSON
python system_info.py --json

# Sortie simple (sans couleurs)
python system_info.py --simple

# Sauvegarder en JSON
python system_info.py --json > system_info.json
```

---

## Sortie Exemple

```
╭───────────────────────────────────────────────────────────╮
│          System Information Report                        │
│          Generated: 2024-01-15 14:30:22                   │
╰───────────────────────────────────────────────────────────╯

▶ Operating System
System               Linux
Node Name            server01
Release              5.15.0-91-generic
Uptime               45 days, 3:25:30

▶ CPU
Physical Cores       4
Logical Cores        8
Max Frequency        3800 MHz
Current Usage        23.5%

▶ Memory
  RAM: 8.2GB / 16.0GB (51.3%)
  Swap: 245MB / 2.0GB (12.3%)

▶ Disks
┏━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━━┳━━━━━━━┓
┃ Device   ┃ Mount   ┃ Total  ┃ Used   ┃ Free   ┃ Usage ┃
┡━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━━╇━━━━━━━┩
│ /dev/sda │ /       │ 50.0GB │ 22.3GB │ 27.7GB │ 44.6% │
│ /dev/sdb │ /home   │ 200GB  │ 124GB  │ 76GB   │ 62.0% │
└──────────┴─────────┴────────┴────────┴────────┴───────┘

▶ Network
  Hostname: server01
  Primary IP: 192.168.1.100
  eth0: 192.168.1.100

▶ Top Processes (CPU)
┏━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━━━━┓
┃ PID  ┃ Name           ┃ CPU % ┃ Memory % ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━━━━┩
│ 1234 │ mysqld         │ 12.3% │    8.5%  │
│ 5678 │ nginx          │  5.2% │    2.1%  │
│ 9012 │ python3        │  3.8% │    1.5%  │
└──────┴────────────────┴───────┴──────────┘
```

---

## Voir Aussi

- [disk_io_analyzer.py](disk_io_analyzer.md) - Analyse performances I/O
- [system_tuning_advisor.py](system_tuning_advisor.md) - Recommandations tuning
