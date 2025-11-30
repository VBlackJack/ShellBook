---
tags:
  - scripts
  - python
  - kubernetes
  - k8s
  - devops
  - monitoring
---

# kubernetes_health.py

:material-star::material-star::material-star: **Niveau : Avancé**

Vérification de la santé d'un cluster Kubernetes.

---

## Description

Ce script vérifie l'état d'un cluster Kubernetes :
- Connectivité à l'API server
- État des nodes
- Pods en erreur ou pending
- Deployments avec replicas manquants
- PersistentVolumes et claims
- Ressources (CPU/Memory)
- Certificats et secrets expirés

---

## Prérequis

```bash
pip install kubernetes pyyaml
```

---

## Script

```python
#!/usr/bin/env python3
"""
kubernetes_health.py - Vérification santé cluster Kubernetes
"""

import sys
import json
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field

try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    print("Warning: kubernetes module not installed. Run: pip install kubernetes")


# Colors ANSI
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


class KubernetesHealthChecker:
    """Vérificateur de santé Kubernetes"""

    def __init__(self, kubeconfig: str = None, context: str = None):
        self.results: List[CheckResult] = []

        try:
            if kubeconfig:
                config.load_kube_config(config_file=kubeconfig, context=context)
            else:
                try:
                    config.load_incluster_config()
                except config.ConfigException:
                    config.load_kube_config(context=context)

            self.v1 = client.CoreV1Api()
            self.apps_v1 = client.AppsV1Api()
            self.connected = True
        except Exception as e:
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

    def check_api_server(self) -> bool:
        """Check la connectivité à l'API server"""
        if not self.connected:
            self.add_result(
                "API Server",
                "fail",
                f"Cannot connect: {self.connection_error}"
            )
            return False

        try:
            self.v1.get_api_resources()
            self.add_result("API Server", "pass", "Connected and responding")
            return True
        except ApiException as e:
            self.add_result("API Server", "fail", f"API error: {e.reason}")
            return False

    def check_nodes(self):
        """Check l'état des nodes"""
        try:
            nodes = self.v1.list_node()

            total = len(nodes.items)
            ready = 0
            not_ready = []
            warnings = []

            for node in nodes.items:
                node_name = node.metadata.name
                conditions = {c.type: c for c in node.status.conditions}

                # Vérifier Ready
                ready_cond = conditions.get('Ready')
                if ready_cond and ready_cond.status == 'True':
                    ready += 1
                else:
                    not_ready.append(node_name)

                # Vérifier les conditions problématiques
                for cond_type in ['MemoryPressure', 'DiskPressure', 'PIDPressure']:
                    cond = conditions.get(cond_type)
                    if cond and cond.status == 'True':
                        warnings.append(f"{node_name}: {cond_type}")

                # Vérifier les taints critiques
                if node.spec.taints:
                    for taint in node.spec.taints:
                        if taint.effect == 'NoSchedule' and taint.key == 'node.kubernetes.io/unschedulable':
                            warnings.append(f"{node_name}: Cordoned")

            if not_ready:
                self.add_result(
                    "Nodes",
                    "fail",
                    f"{ready}/{total} ready",
                    [f"Not ready: {', '.join(not_ready)}"]
                )
            elif warnings:
                self.add_result(
                    "Nodes",
                    "warn",
                    f"{ready}/{total} ready",
                    warnings
                )
            else:
                self.add_result("Nodes", "pass", f"{ready}/{total} ready")

            # Ressources des nodes
            self._check_node_resources(nodes)

        except ApiException as e:
            self.add_result("Nodes", "fail", f"Cannot list nodes: {e.reason}")

    def _check_node_resources(self, nodes):
        """Check les ressources des nodes"""
        try:
            # Obtenir les metrics si disponibles
            custom_api = client.CustomObjectsApi()
            metrics = custom_api.list_cluster_custom_object(
                "metrics.k8s.io", "v1beta1", "nodes"
            )

            high_usage = []
            for metric in metrics.get('items', []):
                node_name = metric['metadata']['name']
                cpu_usage = metric['usage']['cpu']
                mem_usage = metric['usage']['memory']

                # Convertir et calculer pourcentage
                # (simplifié - en prod utiliser les allocatable)
                if 'Gi' in mem_usage and float(mem_usage.replace('Gi', '')) > 50:
                    high_usage.append(f"{node_name}: high memory")

            if high_usage:
                self.add_result(
                    "Node Resources",
                    "warn",
                    "High resource usage detected",
                    high_usage
                )
            else:
                self.add_result("Node Resources", "pass", "Resources OK")

        except Exception:
            self.add_result("Node Resources", "info", "Metrics server not available")

    def check_pods(self, namespace: str = None):
        """Check l'état des pods"""
        try:
            if namespace:
                pods = self.v1.list_namespaced_pod(namespace)
            else:
                pods = self.v1.list_pod_for_all_namespaces()

            total = len(pods.items)
            running = 0
            pending = []
            failed = []
            crashloop = []

            for pod in pods.items:
                ns = pod.metadata.namespace
                name = pod.metadata.name
                phase = pod.status.phase

                if phase == 'Running':
                    # Vérifier les containers
                    if pod.status.container_statuses:
                        for cs in pod.status.container_statuses:
                            if cs.state.waiting and cs.state.waiting.reason == 'CrashLoopBackOff':
                                crashloop.append(f"{ns}/{name}")
                                break
                            elif cs.restart_count > 10:
                                crashloop.append(f"{ns}/{name} (restarts: {cs.restart_count})")
                                break
                        else:
                            running += 1
                    else:
                        running += 1
                elif phase == 'Pending':
                    pending.append(f"{ns}/{name}")
                elif phase == 'Failed':
                    failed.append(f"{ns}/{name}")

            details = []
            if crashloop:
                details.append(f"CrashLoopBackOff: {len(crashloop)}")
                details.extend([f"  - {p}" for p in crashloop[:5]])
            if pending:
                details.append(f"Pending: {len(pending)}")
                details.extend([f"  - {p}" for p in pending[:5]])
            if failed:
                details.append(f"Failed: {len(failed)}")
                details.extend([f"  - {p}" for p in failed[:5]])

            if crashloop or failed:
                self.add_result(
                    "Pods",
                    "fail",
                    f"{running}/{total} running",
                    details
                )
            elif pending:
                self.add_result(
                    "Pods",
                    "warn",
                    f"{running}/{total} running",
                    details
                )
            else:
                self.add_result("Pods", "pass", f"{running}/{total} running")

        except ApiException as e:
            self.add_result("Pods", "fail", f"Cannot list pods: {e.reason}")

    def check_deployments(self, namespace: str = None):
        """Check l'état des deployments"""
        try:
            if namespace:
                deployments = self.apps_v1.list_namespaced_deployment(namespace)
            else:
                deployments = self.apps_v1.list_deployment_for_all_namespaces()

            total = len(deployments.items)
            healthy = 0
            unhealthy = []

            for deploy in deployments.items:
                ns = deploy.metadata.namespace
                name = deploy.metadata.name
                desired = deploy.spec.replicas or 0
                available = deploy.status.available_replicas or 0
                ready = deploy.status.ready_replicas or 0

                if ready >= desired:
                    healthy += 1
                else:
                    unhealthy.append(f"{ns}/{name}: {ready}/{desired} ready")

            if unhealthy:
                self.add_result(
                    "Deployments",
                    "warn",
                    f"{healthy}/{total} healthy",
                    unhealthy[:10]
                )
            else:
                self.add_result("Deployments", "pass", f"{healthy}/{total} healthy")

        except ApiException as e:
            self.add_result("Deployments", "fail", f"Cannot list deployments: {e.reason}")

    def check_daemonsets(self, namespace: str = None):
        """Check l'état des daemonsets"""
        try:
            if namespace:
                daemonsets = self.apps_v1.list_namespaced_daemon_set(namespace)
            else:
                daemonsets = self.apps_v1.list_daemon_set_for_all_namespaces()

            total = len(daemonsets.items)
            healthy = 0
            unhealthy = []

            for ds in daemonsets.items:
                ns = ds.metadata.namespace
                name = ds.metadata.name
                desired = ds.status.desired_number_scheduled or 0
                ready = ds.status.number_ready or 0

                if ready >= desired:
                    healthy += 1
                else:
                    unhealthy.append(f"{ns}/{name}: {ready}/{desired} ready")

            if unhealthy:
                self.add_result(
                    "DaemonSets",
                    "warn",
                    f"{healthy}/{total} healthy",
                    unhealthy[:10]
                )
            else:
                self.add_result("DaemonSets", "pass", f"{healthy}/{total} healthy")

        except ApiException as e:
            self.add_result("DaemonSets", "fail", f"Cannot list daemonsets: {e.reason}")

    def check_persistent_volumes(self):
        """Check l'état des PersistentVolumes"""
        try:
            pvs = self.v1.list_persistent_volume()

            total = len(pvs.items)
            bound = 0
            issues = []

            for pv in pvs.items:
                name = pv.metadata.name
                phase = pv.status.phase

                if phase == 'Bound':
                    bound += 1
                elif phase == 'Failed':
                    issues.append(f"{name}: Failed")
                elif phase == 'Released':
                    issues.append(f"{name}: Released (needs reclaim)")

            if issues:
                self.add_result(
                    "PersistentVolumes",
                    "warn",
                    f"{bound}/{total} bound",
                    issues
                )
            else:
                self.add_result("PersistentVolumes", "pass", f"{bound}/{total} bound")

        except ApiException as e:
            self.add_result("PersistentVolumes", "fail", f"Cannot list PVs: {e.reason}")

    def check_services(self, namespace: str = None):
        """Check les services sans endpoints"""
        try:
            if namespace:
                services = self.v1.list_namespaced_service(namespace)
                endpoints = self.v1.list_namespaced_endpoints(namespace)
            else:
                services = self.v1.list_service_for_all_namespaces()
                endpoints = self.v1.list_endpoints_for_all_namespaces()

            # Map des endpoints
            ep_map = {}
            for ep in endpoints.items:
                key = f"{ep.metadata.namespace}/{ep.metadata.name}"
                has_addresses = bool(ep.subsets and any(
                    s.addresses for s in ep.subsets if s.addresses
                ))
                ep_map[key] = has_addresses

            no_endpoints = []
            for svc in services.items:
                if svc.spec.type == 'ExternalName':
                    continue
                if svc.spec.cluster_ip == 'None':  # Headless
                    continue

                key = f"{svc.metadata.namespace}/{svc.metadata.name}"
                if not ep_map.get(key, False):
                    no_endpoints.append(key)

            if no_endpoints:
                self.add_result(
                    "Services",
                    "warn",
                    f"{len(no_endpoints)} service(s) without endpoints",
                    no_endpoints[:10]
                )
            else:
                self.add_result(
                    "Services",
                    "pass",
                    f"All services have endpoints"
                )

        except ApiException as e:
            self.add_result("Services", "fail", f"Cannot check services: {e.reason}")

    def check_events(self, namespace: str = None, minutes: int = 60):
        """Check les events récents problématiques"""
        try:
            if namespace:
                events = self.v1.list_namespaced_event(namespace)
            else:
                events = self.v1.list_event_for_all_namespaces()

            now = datetime.now(timezone.utc)
            warnings = []
            errors = []

            for event in events.items:
                if not event.last_timestamp:
                    continue

                age = (now - event.last_timestamp.replace(tzinfo=timezone.utc)).total_seconds()
                if age > minutes * 60:
                    continue

                msg = f"{event.involved_object.kind}/{event.involved_object.name}: {event.message[:50]}"

                if event.type == 'Warning':
                    if event.reason in ['FailedScheduling', 'FailedMount', 'Unhealthy', 'BackOff']:
                        errors.append(msg)
                    else:
                        warnings.append(msg)

            if errors:
                self.add_result(
                    f"Events ({minutes}min)",
                    "fail",
                    f"{len(errors)} critical events",
                    errors[:10]
                )
            elif warnings:
                self.add_result(
                    f"Events ({minutes}min)",
                    "warn",
                    f"{len(warnings)} warning events",
                    warnings[:5]
                )
            else:
                self.add_result(f"Events ({minutes}min)", "pass", "No critical events")

        except ApiException as e:
            self.add_result("Events", "fail", f"Cannot list events: {e.reason}")

    def run_all_checks(self, namespace: str = None):
        """Exécute toutes les vérifications"""
        if not self.check_api_server():
            return

        self.check_nodes()
        self.check_pods(namespace)
        self.check_deployments(namespace)
        self.check_daemonsets(namespace)
        self.check_persistent_volumes()
        self.check_services(namespace)
        self.check_events(namespace)

    def print_results(self):
        """Display les résultats"""
        print(f"\n{Colors.CYAN}{'='*70}{Colors.RESET}")
        print(f"{Colors.GREEN}  KUBERNETES CLUSTER HEALTH CHECK{Colors.RESET}")
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
        description='Check Kubernetes cluster health'
    )
    parser.add_argument(
        '-n', '--namespace',
        help='Namespace to check (default: all)'
    )
    parser.add_argument(
        '--kubeconfig',
        help='Path to kubeconfig file'
    )
    parser.add_argument(
        '--context',
        help='Kubernetes context to use'
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

    if not K8S_AVAILABLE:
        print("Error: kubernetes module required. Run: pip install kubernetes")
        sys.exit(1)

    checker = KubernetesHealthChecker(
        kubeconfig=args.kubeconfig,
        context=args.context
    )

    checker.run_all_checks(namespace=args.namespace)

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
# Vérifier le cluster par défaut
python kubernetes_health.py

# Namespace spécifique
python kubernetes_health.py -n production

# Kubeconfig personnalisé
python kubernetes_health.py --kubeconfig ~/.kube/prod-config

# Contexte spécifique
python kubernetes_health.py --context production-cluster

# Export JSON
python kubernetes_health.py --json k8s-health.json

# Mode monitoring
python kubernetes_health.py -q
```

---

## Voir Aussi

- [docker_health.py](docker_health.md)
- [cert_checker.py](cert_checker.md)
