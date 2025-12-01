---
tags:
  - formation
  - python
  - tp
  - sysops
  - automation
---

# TP Final : Infrastructure Health Reporter

## Objectifs

À la fin de ce TP, vous aurez validé les compétences suivantes :

- Structurer un projet Python professionnel
- Manipuler des fichiers de configuration (YAML, JSON)
- Interagir avec des APIs REST
- Exécuter des commandes système et SSH distantes
- Créer une CLI professionnelle avec argparse/click
- Générer des rapports multi-formats (HTML, JSON, Markdown)
- Tester et documenter le code

**Durée :** 3 heures

---

## Contexte

Vous êtes SysOps Engineer dans une entreprise qui gère une infrastructure hybride (on-premise + cloud AWS). Votre mission : créer un outil Python CLI qui collecte des métriques de santé depuis différentes sources et génère un rapport consolidé.

### Architecture de l'Infrastructure

```
┌─────────────────────────────────────────────────────────────────────┐
│                    INFRASTRUCTURE HYBRIDE                            │
│                                                                      │
│  ┌──────────────────────┐      ┌──────────────────────┐            │
│  │    ON-PREMISE        │      │        AWS           │            │
│  │                      │      │                      │            │
│  │  ┌────────────────┐  │      │  ┌────────────────┐  │            │
│  │  │ srv-web-01     │  │      │  │ EC2 instances  │  │            │
│  │  │ srv-web-02     │  │      │  │ (via API)      │  │            │
│  │  │ srv-db-01      │  │      │  └────────────────┘  │            │
│  │  └────────────────┘  │      │                      │            │
│  │      (SSH)           │      │  ┌────────────────┐  │            │
│  └──────────────────────┘      │  │ RDS databases  │  │            │
│                                │  │ (via API)      │  │            │
│                                │  └────────────────┘  │            │
│                                └──────────────────────┘            │
│                                                                      │
│  ┌──────────────────────────────────────────────────────┐          │
│  │              APIs de Monitoring                       │          │
│  │  - Prometheus (métriques)                            │          │
│  │  - Healthcheck endpoints (/health)                   │          │
│  └──────────────────────────────────────────────────────┘          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Cahier des Charges

### Partie 1 : Structure du Projet (30 min)

**Objectif :** Créer une structure de projet Python professionnelle.

#### 1.1 Arborescence

Créez la structure suivante :

```
infra-reporter/
├── pyproject.toml          # Configuration du projet
├── README.md
├── config/
│   └── config.yaml         # Configuration des cibles
├── src/
│   └── infra_reporter/
│       ├── __init__.py
│       ├── cli.py          # Point d'entrée CLI
│       ├── collectors/
│       │   ├── __init__.py
│       │   ├── ssh.py      # Collecteur SSH
│       │   ├── api.py      # Collecteur API REST
│       │   └── aws.py      # Collecteur AWS
│       ├── reporters/
│       │   ├── __init__.py
│       │   ├── html.py     # Générateur HTML
│       │   ├── json.py     # Générateur JSON
│       │   └── markdown.py # Générateur Markdown
│       └── models.py       # Dataclasses
├── tests/
│   ├── __init__.py
│   ├── test_collectors.py
│   └── test_reporters.py
└── output/                 # Rapports générés
```

#### 1.2 Configuration (config.yaml)

```yaml
targets:
  ssh:
    - name: srv-web-01
      host: 192.168.1.10
      user: admin
      key_file: ~/.ssh/id_rsa
    - name: srv-web-02
      host: 192.168.1.11
      user: admin
      key_file: ~/.ssh/id_rsa
    - name: srv-db-01
      host: 192.168.1.20
      user: admin
      key_file: ~/.ssh/id_rsa

  api:
    - name: api-gateway
      url: https://api.example.com/health
      timeout: 10
    - name: prometheus
      url: http://prometheus.local:9090/api/v1/query
      query: up

  aws:
    region: eu-west-1
    profile: production
    services:
      - ec2
      - rds

thresholds:
  cpu_warning: 70
  cpu_critical: 90
  memory_warning: 80
  memory_critical: 95
  disk_warning: 80
  disk_critical: 90

output:
  format: html  # html, json, markdown
  directory: ./output
```

#### 1.3 Modèles de Données (models.py)

```python
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

class Status(Enum):
    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    UNKNOWN = "unknown"

@dataclass
class Metric:
    name: str
    value: float
    unit: str
    status: Status
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None

@dataclass
class HostReport:
    hostname: str
    ip: str
    timestamp: datetime
    status: Status
    metrics: list[Metric] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

@dataclass
class InfraReport:
    generated_at: datetime
    total_hosts: int
    hosts_ok: int
    hosts_warning: int
    hosts_critical: int
    hosts: list[HostReport] = field(default_factory=list)
```

---

### Partie 2 : Collecteurs de Données (1h)

**Objectif :** Implémenter les collecteurs pour chaque source de données.

#### 2.1 Collecteur SSH (collectors/ssh.py)

Ce collecteur doit :

- Se connecter via SSH avec Paramiko
- Collecter les métriques système :
  - CPU : `top -bn1 | grep "Cpu(s)"`
  - Mémoire : `free -m`
  - Disque : `df -h /`
  - Uptime : `uptime`
- Retourner un objet `HostReport`

**Métriques à collecter :**

| Métrique | Commande | Parsing |
|----------|----------|---------|
| cpu_usage | `top -bn1` | Extraire le % utilisé |
| memory_usage | `free -m` | Calculer % utilisé |
| disk_usage | `df -h /` | Extraire le % |
| load_average | `uptime` | Extraire load 1min |
| uptime_days | `uptime` | Extraire le nombre de jours |

**Signature attendue :**

```python
def collect_ssh(host: dict, thresholds: dict) -> HostReport:
    """
    Collecte les métriques d'un hôte via SSH.

    Args:
        host: Configuration de l'hôte (name, host, user, key_file)
        thresholds: Seuils d'alerte (cpu_warning, cpu_critical, etc.)

    Returns:
        HostReport avec les métriques collectées
    """
    pass
```

#### 2.2 Collecteur API (collectors/api.py)

Ce collecteur doit :

- Appeler des endpoints HTTP avec requests
- Gérer les timeouts et erreurs
- Supporter l'authentification (Bearer token, Basic)
- Parser les réponses JSON

**Signature attendue :**

```python
def collect_api(endpoint: dict) -> HostReport:
    """
    Collecte les métriques depuis une API REST.

    Args:
        endpoint: Configuration (name, url, timeout, auth)

    Returns:
        HostReport avec le statut du service
    """
    pass
```

#### 2.3 Collecteur AWS (collectors/aws.py)

Ce collecteur doit :

- Utiliser boto3 pour interroger AWS
- Lister les instances EC2 et leur état
- Lister les instances RDS et leur statut
- Collecter les métriques CloudWatch (optionnel)

**Signature attendue :**

```python
def collect_aws(config: dict) -> list[HostReport]:
    """
    Collecte les informations des ressources AWS.

    Args:
        config: Configuration AWS (region, profile, services)

    Returns:
        Liste de HostReport pour chaque ressource
    """
    pass
```

---

### Partie 3 : Générateurs de Rapports (45 min)

**Objectif :** Générer des rapports dans différents formats.

#### 3.1 Rapport HTML (reporters/html.py)

Générez un rapport HTML responsive avec :

- En-tête avec date et statistiques globales
- Tableau des hôtes avec code couleur (vert/orange/rouge)
- Détail des métriques par hôte
- Graphiques optionnels (avec une lib comme matplotlib)

**Template HTML suggéré :**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Infrastructure Report - {{ date }}</title>
    <style>
        .status-ok { color: green; }
        .status-warning { color: orange; }
        .status-critical { color: red; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
    </style>
</head>
<body>
    <h1>Infrastructure Health Report</h1>
    <p>Generated: {{ date }}</p>

    <h2>Summary</h2>
    <ul>
        <li>Total hosts: {{ total }}</li>
        <li class="status-ok">OK: {{ ok }}</li>
        <li class="status-warning">Warning: {{ warning }}</li>
        <li class="status-critical">Critical: {{ critical }}</li>
    </ul>

    <h2>Host Details</h2>
    <table>
        <tr>
            <th>Host</th>
            <th>IP</th>
            <th>Status</th>
            <th>CPU</th>
            <th>Memory</th>
            <th>Disk</th>
        </tr>
        {% for host in hosts %}
        <tr>
            <td>{{ host.hostname }}</td>
            <td>{{ host.ip }}</td>
            <td class="status-{{ host.status }}">{{ host.status }}</td>
            <!-- ... -->
        </tr>
        {% endfor %}
    </table>
</body>
</html>
```

#### 3.2 Rapport JSON (reporters/json.py)

Export JSON structuré pour intégration avec d'autres outils :

```json
{
    "generated_at": "2024-01-15T10:30:00Z",
    "summary": {
        "total": 10,
        "ok": 7,
        "warning": 2,
        "critical": 1
    },
    "hosts": [
        {
            "hostname": "srv-web-01",
            "ip": "192.168.1.10",
            "status": "ok",
            "metrics": {
                "cpu_usage": {"value": 45.2, "unit": "%", "status": "ok"},
                "memory_usage": {"value": 62.1, "unit": "%", "status": "ok"},
                "disk_usage": {"value": 78.5, "unit": "%", "status": "warning"}
            }
        }
    ]
}
```

#### 3.3 Rapport Markdown (reporters/markdown.py)

Export Markdown pour documentation ou wiki :

```markdown
# Infrastructure Health Report

**Generated:** 2024-01-15 10:30:00

## Summary

| Status | Count |
|--------|-------|
| ✅ OK | 7 |
| ⚠️ Warning | 2 |
| ❌ Critical | 1 |

## Host Details

### srv-web-01 (192.168.1.10) - ✅ OK

| Metric | Value | Status |
|--------|-------|--------|
| CPU | 45.2% | ✅ |
| Memory | 62.1% | ✅ |
| Disk | 78.5% | ⚠️ |
```

---

### Partie 4 : CLI et Intégration (45 min)

**Objectif :** Créer une interface CLI professionnelle.

#### 4.1 CLI avec Click (cli.py)

```python
import click
from rich.console import Console

console = Console()

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """Infrastructure Health Reporter - Collect and report infrastructure metrics."""
    pass

@cli.command()
@click.option("-c", "--config", default="config/config.yaml", help="Configuration file")
@click.option("-o", "--output", default="output", help="Output directory")
@click.option("-f", "--format", type=click.Choice(["html", "json", "md", "all"]), default="html")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def collect(config, output, format, verbose):
    """Collect metrics and generate report."""
    console.print("[bold blue]Starting infrastructure scan...[/bold blue]")
    # Implementation
    pass

@cli.command()
@click.argument("host")
@click.option("-u", "--user", default="admin")
@click.option("-k", "--key-file", default="~/.ssh/id_rsa")
def test_ssh(host, user, key_file):
    """Test SSH connection to a host."""
    pass

@cli.command()
@click.argument("url")
def test_api(url):
    """Test API endpoint connectivity."""
    pass

if __name__ == "__main__":
    cli()
```

#### 4.2 Utilisation

```bash
# Installation
pip install -e .

# Collecter et générer rapport HTML
infra-reporter collect -c config/config.yaml -f html

# Collecter tous les formats
infra-reporter collect -f all -v

# Tester une connexion SSH
infra-reporter test-ssh 192.168.1.10 -u admin

# Tester une API
infra-reporter test-api https://api.example.com/health
```

#### 4.3 Tests (tests/test_collectors.py)

```python
import pytest
from unittest.mock import Mock, patch
from infra_reporter.collectors.ssh import collect_ssh
from infra_reporter.models import Status

class TestSSHCollector:

    @patch("paramiko.SSHClient")
    def test_collect_ssh_success(self, mock_ssh):
        # Arrange
        mock_ssh.return_value.exec_command.return_value = (
            None,
            Mock(read=lambda: b"Cpu(s): 45.2%"),
            None
        )

        host = {"name": "test", "host": "192.168.1.1", "user": "admin"}
        thresholds = {"cpu_warning": 70, "cpu_critical": 90}

        # Act
        result = collect_ssh(host, thresholds)

        # Assert
        assert result.status == Status.OK
        assert len(result.metrics) > 0

    def test_collect_ssh_connection_error(self):
        # Test comportement en cas d'erreur de connexion
        pass
```

---

## Livrables Attendus

- [ ] Structure de projet Python complète
- [ ] Fichier de configuration YAML fonctionnel
- [ ] Collecteur SSH avec parsing des métriques système
- [ ] Collecteur API REST avec gestion des erreurs
- [ ] Collecteur AWS (EC2 + RDS)
- [ ] Générateur de rapport HTML
- [ ] Générateur de rapport JSON
- [ ] Générateur de rapport Markdown
- [ ] CLI avec commandes collect, test-ssh, test-api
- [ ] Tests unitaires (couverture > 70%)
- [ ] README.md avec documentation

---

## Critères d'Évaluation

| Critère | Points |
|---------|--------|
| Structure projet et organisation du code | /2 |
| Collecteur SSH fonctionnel avec parsing | /3 |
| Collecteur API REST avec gestion erreurs | /2 |
| Collecteur AWS (EC2/RDS) | /2 |
| Générateurs de rapports (HTML, JSON, MD) | /3 |
| CLI professionnelle avec options | /2 |
| Tests unitaires pertinents | /2 |
| Gestion des erreurs et logging | /2 |
| Documentation (README, docstrings) | /2 |
| **Total** | **/20** |

---

## Commandes Utiles

```bash
# Créer l'environnement virtuel
python -m venv venv
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows

# Installer les dépendances
pip install paramiko requests boto3 pyyaml click rich pytest

# Installer en mode développement
pip install -e .

# Lancer les tests
pytest -v --cov=infra_reporter

# Linter
pip install flake8 black
black src/
flake8 src/
```

---

## Ressources

- [Module 05 - Fichiers & I/O](05-fichiers.md)
- [Module 06 - Formats de Données](06-formats.md)
- [Module 07 - Sous-processus](07-subprocess.md)
- [Module 10 - Réseau de Base](10-reseau.md)
- [Module 11 - APIs REST](11-api-rest.md)
- [Module 12 - SSH & Automatisation](12-ssh.md)
- [Module 13 - CLI Professionnels](13-cli.md)
- [Module 14 - Cloud & Boto3](14-cloud.md)
- [Module 15 - Tests & Qualité](15-tests.md)
- [Cheatsheet Python](cheatsheet-python.md)
- [Cheatsheet Libs SysOps](cheatsheet-libs.md)

---

## Bonus (Points Supplémentaires)

- **+1 point** : Ajout de notifications (Slack, email) en cas de status CRITICAL
- **+1 point** : Mode watch avec actualisation automatique
- **+1 point** : Export des métriques vers Prometheus (format OpenMetrics)
- **+1 point** : Interface web simple avec Flask pour visualiser les rapports

---

**Précédent :** [Module 15 - Tests & Qualité](15-tests.md)

**Retour au programme :** [Index](index.md)
