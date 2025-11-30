---
tags:
  - scripts
  - python
  - docker
  - containers
  - devops
  - monitoring
---

# docker_health.py

:material-star::material-star: **Niveau : Intermédiaire**

Vérification de la santé de Docker et des containers.

---

## Description

Ce script vérifie l'état de Docker :
- Daemon Docker et version
- Containers running/stopped/unhealthy
- Images et espace disque
- Réseaux et volumes
- Ressources (CPU/Memory)
- Logs récents des containers en erreur

---

## Prérequis

```bash
pip install docker
```

---

## Script

```python
#!/usr/bin/env python3
"""
docker_health.py - Vérification santé Docker
"""

import sys
import json
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field

try:
    import docker
    from docker.errors import DockerException, APIError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    print("Warning: docker module not installed. Run: pip install docker")


# Couleurs ANSI
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


@dataclass
class CheckResult:
    """Résultat d'une vérification"""
    name: str
    status: str  # pass, warn, fail, info
    message: str
    details: List[str] = field(default_factory=list)


def format_bytes(size: int) -> str:
    """Formate une taille en bytes en format lisible"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


class DockerHealthChecker:
    """Vérificateur de santé Docker"""

    def __init__(self, docker_host: str = None):
        self.results: List[CheckResult] = []

        try:
            if docker_host:
                self.client = docker.DockerClient(base_url=docker_host)
            else:
                self.client = docker.from_env()
            self.connected = True
        except DockerException as e:
            self.connected = False
            self.connection_error = str(e)

    def add_result(self, name: str, status: str, message: str,
                   details: List[str] = None):
        """Ajoute un résultat de vérification"""
        self.results.append(CheckResult(
            name=name,
            status=status,
            message=message,
            details=details or []
        ))

    def check_daemon(self) -> bool:
        """Vérifie la connectivité au daemon Docker"""
        if not self.connected:
            self.add_result(
                "Docker Daemon",
                "fail",
                f"Cannot connect: {self.connection_error}"
            )
            return False

        try:
            info = self.client.info()
            version = self.client.version()

            details = [
                f"Version: {version.get('Version', 'unknown')}",
                f"API: {version.get('ApiVersion', 'unknown')}",
                f"OS: {info.get('OperatingSystem', 'unknown')}",
                f"Kernel: {info.get('KernelVersion', 'unknown')}"
            ]

            self.add_result("Docker Daemon", "pass", "Running", details)
            return True

        except APIError as e:
            self.add_result("Docker Daemon", "fail", f"API error: {e}")
            return False

    def check_containers(self):
        """Vérifie l'état des containers"""
        try:
            containers = self.client.containers.list(all=True)

            running = 0
            stopped = 0
            unhealthy = []
            restarting = []
            exited_error = []

            for container in containers:
                status = container.status
                name = container.name

                if status == 'running':
                    running += 1
                    # Vérifier health status
                    health = container.attrs.get('State', {}).get('Health', {})
                    if health.get('Status') == 'unhealthy':
                        unhealthy.append(name)
                elif status == 'restarting':
                    restarting.append(name)
                elif status == 'exited':
                    stopped += 1
                    exit_code = container.attrs.get('State', {}).get('ExitCode', 0)
                    if exit_code != 0:
                        exited_error.append(f"{name} (exit: {exit_code})")
                else:
                    stopped += 1

            # Résultat
            details = []
            if unhealthy:
                details.append(f"Unhealthy: {', '.join(unhealthy)}")
            if restarting:
                details.append(f"Restarting: {', '.join(restarting)}")
            if exited_error:
                details.extend([f"Exited with error: {c}" for c in exited_error[:5]])

            if unhealthy or restarting:
                self.add_result(
                    "Containers",
                    "fail",
                    f"{running} running, {stopped} stopped",
                    details
                )
            elif exited_error:
                self.add_result(
                    "Containers",
                    "warn",
                    f"{running} running, {stopped} stopped",
                    details
                )
            else:
                self.add_result(
                    "Containers",
                    "pass",
                    f"{running} running, {stopped} stopped"
                )

        except APIError as e:
            self.add_result("Containers", "fail", f"Cannot list containers: {e}")

    def check_container_resources(self):
        """Vérifie les ressources des containers"""
        try:
            containers = self.client.containers.list()

            high_cpu = []
            high_memory = []

            for container in containers:
                try:
                    stats = container.stats(stream=False)

                    # CPU
                    cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - \
                                stats['precpu_stats']['cpu_usage']['total_usage']
                    system_delta = stats['cpu_stats']['system_cpu_usage'] - \
                                   stats['precpu_stats']['system_cpu_usage']
                    cpu_count = stats['cpu_stats'].get('online_cpus', 1)

                    if system_delta > 0:
                        cpu_percent = (cpu_delta / system_delta) * cpu_count * 100
                        if cpu_percent > 80:
                            high_cpu.append(f"{container.name}: {cpu_percent:.1f}%")

                    # Memory
                    mem_usage = stats['memory_stats'].get('usage', 0)
                    mem_limit = stats['memory_stats'].get('limit', 1)
                    mem_percent = (mem_usage / mem_limit) * 100

                    if mem_percent > 80:
                        high_memory.append(
                            f"{container.name}: {mem_percent:.1f}% "
                            f"({format_bytes(mem_usage)})"
                        )

                except Exception:
                    continue

            details = []
            if high_cpu:
                details.extend([f"High CPU: {c}" for c in high_cpu])
            if high_memory:
                details.extend([f"High Memory: {m}" for m in high_memory])

            if details:
                self.add_result(
                    "Container Resources",
                    "warn",
                    "High resource usage detected",
                    details
                )
            else:
                self.add_result(
                    "Container Resources",
                    "pass",
                    "Resources within limits"
                )

        except APIError as e:
            self.add_result("Container Resources", "fail", f"Cannot get stats: {e}")

    def check_images(self):
        """Vérifie les images Docker"""
        try:
            images = self.client.images.list()

            total_size = 0
            dangling = 0

            for image in images:
                total_size += image.attrs.get('Size', 0)
                if not image.tags:
                    dangling += 1

            details = [f"Total size: {format_bytes(total_size)}"]
            if dangling > 0:
                details.append(f"Dangling images: {dangling}")

            if dangling > 10:
                self.add_result(
                    "Images",
                    "warn",
                    f"{len(images)} images",
                    details
                )
            else:
                self.add_result(
                    "Images",
                    "pass",
                    f"{len(images)} images",
                    details
                )

        except APIError as e:
            self.add_result("Images", "fail", f"Cannot list images: {e}")

    def check_volumes(self):
        """Vérifie les volumes Docker"""
        try:
            volumes = self.client.volumes.list()

            unused = []
            for volume in volumes:
                # Vérifier si utilisé
                in_use = False
                for container in self.client.containers.list(all=True):
                    mounts = container.attrs.get('Mounts', [])
                    for mount in mounts:
                        if mount.get('Name') == volume.name:
                            in_use = True
                            break
                    if in_use:
                        break

                if not in_use:
                    unused.append(volume.name)

            if unused:
                self.add_result(
                    "Volumes",
                    "warn",
                    f"{len(volumes)} volumes ({len(unused)} unused)",
                    [f"Unused: {', '.join(unused[:5])}{'...' if len(unused) > 5 else ''}"]
                )
            else:
                self.add_result(
                    "Volumes",
                    "pass",
                    f"{len(volumes)} volumes"
                )

        except APIError as e:
            self.add_result("Volumes", "fail", f"Cannot list volumes: {e}")

    def check_networks(self):
        """Vérifie les réseaux Docker"""
        try:
            networks = self.client.networks.list()

            custom_networks = [n for n in networks if n.name not in
                             ['bridge', 'host', 'none']]

            self.add_result(
                "Networks",
                "info",
                f"{len(networks)} networks ({len(custom_networks)} custom)"
            )

        except APIError as e:
            self.add_result("Networks", "fail", f"Cannot list networks: {e}")

    def check_disk_usage(self):
        """Vérifie l'utilisation disque Docker"""
        try:
            df = self.client.df()

            images_size = sum(i.get('Size', 0) for i in df.get('Images', []))
            containers_size = sum(c.get('SizeRw', 0) for c in df.get('Containers', []))
            volumes_size = sum(v.get('UsageData', {}).get('Size', 0)
                             for v in df.get('Volumes', []))
            build_cache = sum(b.get('Size', 0) for b in df.get('BuildCache', []))

            total = images_size + containers_size + volumes_size + build_cache

            details = [
                f"Images: {format_bytes(images_size)}",
                f"Containers: {format_bytes(containers_size)}",
                f"Volumes: {format_bytes(volumes_size)}",
                f"Build cache: {format_bytes(build_cache)}"
            ]

            # Alerte si > 50GB
            if total > 50 * 1024 * 1024 * 1024:
                self.add_result(
                    "Disk Usage",
                    "warn",
                    f"Total: {format_bytes(total)}",
                    details
                )
            else:
                self.add_result(
                    "Disk Usage",
                    "pass",
                    f"Total: {format_bytes(total)}",
                    details
                )

        except APIError as e:
            self.add_result("Disk Usage", "fail", f"Cannot get disk usage: {e}")

    def check_container_logs(self, tail: int = 50):
        """Vérifie les logs des containers en erreur"""
        try:
            containers = self.client.containers.list(all=True)

            error_logs = []

            for container in containers:
                # Containers non-running avec exit code != 0
                if container.status != 'running':
                    exit_code = container.attrs.get('State', {}).get('ExitCode', 0)
                    if exit_code != 0:
                        logs = container.logs(tail=tail).decode('utf-8', errors='ignore')
                        if logs.strip():
                            # Dernières lignes pertinentes
                            last_lines = logs.strip().split('\n')[-5:]
                            error_logs.append(f"{container.name}:")
                            error_logs.extend([f"  {line[:80]}" for line in last_lines])

                # Containers unhealthy
                health = container.attrs.get('State', {}).get('Health', {})
                if health.get('Status') == 'unhealthy':
                    logs = health.get('Log', [])
                    if logs:
                        last_log = logs[-1]
                        error_logs.append(
                            f"{container.name} (healthcheck): {last_log.get('Output', '')[:100]}"
                        )

            if error_logs:
                self.add_result(
                    "Container Logs",
                    "warn",
                    "Errors detected in logs",
                    error_logs[:20]
                )
            else:
                self.add_result(
                    "Container Logs",
                    "pass",
                    "No critical errors in logs"
                )

        except APIError as e:
            self.add_result("Container Logs", "fail", f"Cannot get logs: {e}")

    def check_swarm(self):
        """Vérifie le mode Swarm si actif"""
        try:
            info = self.client.info()
            swarm_info = info.get('Swarm', {})

            if swarm_info.get('LocalNodeState') == 'active':
                nodes = swarm_info.get('Nodes', 0)
                managers = swarm_info.get('Managers', 0)

                self.add_result(
                    "Swarm Mode",
                    "info",
                    f"Active ({nodes} nodes, {managers} managers)"
                )
            else:
                self.add_result(
                    "Swarm Mode",
                    "info",
                    "Not active"
                )

        except APIError as e:
            self.add_result("Swarm Mode", "info", "Not available")

    def run_all_checks(self):
        """Exécute toutes les vérifications"""
        if not self.check_daemon():
            return

        self.check_containers()
        self.check_container_resources()
        self.check_images()
        self.check_volumes()
        self.check_networks()
        self.check_disk_usage()
        self.check_container_logs()
        self.check_swarm()

    def print_results(self):
        """Affiche les résultats"""
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}  DOCKER HEALTH CHECK{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Colors.CYAN}{'-'*70}{Colors.RESET}\n")

        for result in self.results:
            # Status icon
            if result.status == 'pass':
                status = f"{Colors.GREEN}[OK]  {Colors.RESET}"
            elif result.status == 'warn':
                status = f"{Colors.YELLOW}[WARN]{Colors.RESET}"
            elif result.status == 'fail':
                status = f"{Colors.RED}[FAIL]{Colors.RESET}"
            else:
                status = f"{Colors.CYAN}[INFO]{Colors.RESET}"

            print(f"{status} {Colors.BOLD}{result.name}{Colors.RESET} - {result.message}")

            for detail in result.details:
                print(f"    {Colors.GRAY}{detail}{Colors.RESET}")

        # Résumé
        passed = sum(1 for r in self.results if r.status == 'pass')
        warned = sum(1 for r in self.results if r.status == 'warn')
        failed = sum(1 for r in self.results if r.status == 'fail')

        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"  {Colors.GREEN}Passed: {passed}{Colors.RESET}  "
              f"{Colors.YELLOW}Warnings: {warned}{Colors.RESET}  "
              f"{Colors.RED}Failed: {failed}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*70}{Colors.RESET}\n")

    def get_exit_code(self) -> int:
        """Retourne le code de sortie"""
        if any(r.status == 'fail' for r in self.results):
            return 2
        elif any(r.status == 'warn' for r in self.results):
            return 1
        return 0


def main():
    parser = argparse.ArgumentParser(
        description='Check Docker health'
    )
    parser.add_argument(
        '-H', '--host',
        help='Docker host (e.g., unix:///var/run/docker.sock or tcp://localhost:2375)'
    )
    parser.add_argument(
        '--json',
        metavar='FILE',
        help='Export results to JSON file'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Only output errors and warnings'
    )

    args = parser.parse_args()

    if not DOCKER_AVAILABLE:
        print("Error: docker module required. Run: pip install docker")
        sys.exit(1)

    checker = DockerHealthChecker(docker_host=args.host)
    checker.run_all_checks()

    if not args.quiet:
        checker.print_results()
    else:
        for result in checker.results:
            if result.status in ('warn', 'fail'):
                print(f"{result.status.upper()} {result.name}: {result.message}")

    if args.json:
        data = {
            'timestamp': datetime.now().isoformat(),
            'results': [asdict(r) for r in checker.results]
        }
        with open(args.json, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Results exported to {args.json}")

    sys.exit(checker.get_exit_code())


if __name__ == '__main__':
    main()
```

---

## Utilisation

```bash
# Vérifier Docker local
python docker_health.py

# Docker distant
python docker_health.py -H tcp://docker.example.com:2375

# Export JSON
python docker_health.py --json docker-health.json

# Mode monitoring
python docker_health.py -q
```

---

## Voir Aussi

- [kubernetes_health.py](kubernetes_health.md)
- [cert_checker.py](cert_checker.md)
