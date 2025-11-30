---
tags:
  - python
  - scripting
  - automation
---

# Python Fondamentaux pour Ops

Les bases Python essentielles pour l'automatisation système.

---

## Syntaxe de Base

### Variables et Types

```python
# Strings
hostname = "srv-web-01"
fqdn = f"{hostname}.example.com"  # f-string

# Nombres
port = 443
memory_gb = 16.5

# Booléens
is_active = True
is_maintenance = False

# Listes
servers = ["web01", "web02", "web03"]
ports = [80, 443, 8080]

# Dictionnaires
server = {
    "hostname": "srv-web-01",
    "ip": "10.0.0.10",
    "ports": [80, 443],
    "active": True
}

# Tuples (immutables)
coordinates = (48.8566, 2.3522)
```

### Structures de Contrôle

```python
# Conditions
status_code = 200

if status_code == 200:
    print("OK")
elif status_code >= 400 and status_code < 500:
    print("Client Error")
elif status_code >= 500:
    print("Server Error")
else:
    print("Unknown")

# Opérateur ternaire
status = "UP" if is_active else "DOWN"
```

### Boucles

```python
# For sur une liste
servers = ["web01", "web02", "db01"]
for server in servers:
    print(f"Checking {server}...")

# For avec index
for i, server in enumerate(servers):
    print(f"{i}: {server}")

# For sur un dictionnaire
config = {"host": "localhost", "port": 5432}
for key, value in config.items():
    print(f"{key} = {value}")

# Range
for i in range(5):       # 0, 1, 2, 3, 4
    print(i)

for i in range(1, 10, 2):  # 1, 3, 5, 7, 9
    print(i)

# While
retries = 0
max_retries = 3
while retries < max_retries:
    print(f"Attempt {retries + 1}")
    retries += 1
```

### List Comprehensions

```python
# Filtrer et transformer
servers = ["web01", "web02", "db01", "db02"]

# Seulement les web servers
web_servers = [s for s in servers if s.startswith("web")]

# Transformer
fqdns = [f"{s}.example.com" for s in servers]

# Dict comprehension
ports = {"http": 80, "https": 443, "ssh": 22}
open_ports = {k: v for k, v in ports.items() if v < 1024}
```

---

## Fonctions

### Définition et Arguments

```python
def check_server(hostname, port=22, timeout=5):
    """Vérifie si un serveur répond sur un port."""
    print(f"Checking {hostname}:{port} (timeout={timeout}s)")
    return True

# Appels
check_server("web01")                    # Port 22, timeout 5
check_server("web01", 443)               # Port 443, timeout 5
check_server("web01", port=80, timeout=10)  # Nommés

# Arguments variables
def log_servers(*servers):
    for server in servers:
        print(f"Server: {server}")

log_servers("web01", "web02", "db01")

# Kwargs
def create_config(**options):
    for key, value in options.items():
        print(f"{key} = {value}")

create_config(host="localhost", port=5432, ssl=True)
```

### Fonctions Lambda

```python
# Fonction anonyme
square = lambda x: x ** 2

# Tri personnalisé
servers = [
    {"name": "web01", "load": 75},
    {"name": "web02", "load": 45},
    {"name": "db01", "load": 90}
]
sorted_servers = sorted(servers, key=lambda s: s["load"])
```

---

## Gestion des Erreurs

```python
import socket

def check_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        if result == 0:
            return True
        return False
    except socket.error as e:
        print(f"Socket error: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        return False
    finally:
        sock.close()

# Lever une exception
def validate_port(port):
    if not 1 <= port <= 65535:
        raise ValueError(f"Invalid port: {port}")
    return port
```

---

## Classes (OOP)

```python
class Server:
    """Représente un serveur."""

    def __init__(self, hostname, ip, port=22):
        self.hostname = hostname
        self.ip = ip
        self.port = port
        self.status = "unknown"

    def check(self):
        """Vérifie si le serveur est accessible."""
        # Logique de vérification
        self.status = "up"
        return self.status == "up"

    def __str__(self):
        return f"{self.hostname} ({self.ip}:{self.port}) - {self.status}"

    def __repr__(self):
        return f"Server('{self.hostname}', '{self.ip}', {self.port})"


# Utilisation
srv = Server("web01", "10.0.0.10", 443)
srv.check()
print(srv)  # web01 (10.0.0.10:443) - up

# Héritage
class WebServer(Server):
    def __init__(self, hostname, ip, port=443):
        super().__init__(hostname, ip, port)
        self.server_type = "nginx"

    def reload(self):
        print(f"Reloading {self.server_type} on {self.hostname}")
```

---

## Modules et Imports

```python
# Import standard
import os
import sys
import json

# Import spécifique
from pathlib import Path
from datetime import datetime, timedelta

# Import avec alias
import subprocess as sp

# Structure projet typique
# my_project/
# ├── main.py
# ├── config.py
# └── utils/
#     ├── __init__.py
#     ├── network.py
#     └── files.py

# Dans main.py
from utils.network import check_port
from utils.files import read_config
import config
```

---

## Gestion de l'Environnement

### Virtual Environments

```bash
# Créer un venv
python3 -m venv venv

# Activer
source venv/bin/activate      # Linux/Mac
.\venv\Scripts\activate       # Windows

# Installer des packages
pip install requests boto3

# Sauvegarder les dépendances
pip freeze > requirements.txt

# Installer depuis requirements
pip install -r requirements.txt

# Désactiver
deactivate
```

### Variables d'Environnement

```python
import os

# Lire une variable
db_host = os.environ.get("DB_HOST", "localhost")
db_port = int(os.environ.get("DB_PORT", "5432"))

# Variable obligatoire
api_key = os.environ["API_KEY"]  # Lève KeyError si absente

# Mieux : avec valeur par défaut et validation
def get_env(key, default=None, required=False):
    value = os.environ.get(key, default)
    if required and value is None:
        raise ValueError(f"Environment variable {key} is required")
    return value

api_key = get_env("API_KEY", required=True)
debug = get_env("DEBUG", "false").lower() == "true"
```

---

## Script Type Ops

```python
#!/usr/bin/env python3
"""
Script de vérification de l'état des serveurs.
Usage: python check_servers.py
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor


def check_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Vérifie si un port est ouvert."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except socket.error:
        return False


def check_server(server: dict) -> dict:
    """Vérifie un serveur et retourne son statut."""
    hostname = server["hostname"]
    port = server.get("port", 22)

    is_up = check_port(hostname, port)

    return {
        "hostname": hostname,
        "port": port,
        "status": "UP" if is_up else "DOWN"
    }


def main():
    parser = argparse.ArgumentParser(description="Check server status")
    parser.add_argument("-f", "--file", help="Servers file (JSON)")
    parser.add_argument("-t", "--threads", type=int, default=10)
    args = parser.parse_args()

    # Liste des serveurs
    servers = [
        {"hostname": "google.com", "port": 443},
        {"hostname": "github.com", "port": 443},
        {"hostname": "localhost", "port": 22},
    ]

    # Vérification parallèle
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = list(executor.map(check_server, servers))

    # Affichage
    for result in results:
        status = "✓" if result["status"] == "UP" else "✗"
        print(f"{status} {result['hostname']}:{result['port']} - {result['status']}")

    # Exit code
    failed = [r for r in results if r["status"] == "DOWN"]
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
```

---

## Bonnes Pratiques

### Type Hints (Python 3.5+)

```python
from typing import List, Dict, Optional

def get_servers(env: str) -> List[Dict[str, str]]:
    """Retourne la liste des serveurs pour un environnement."""
    pass

def find_server(hostname: str) -> Optional[Dict]:
    """Trouve un serveur par son nom, None si non trouvé."""
    pass
```

### Docstrings

```python
def check_health(host: str, port: int = 80, path: str = "/health") -> bool:
    """
    Vérifie l'endpoint de santé d'un service.

    Args:
        host: Hostname ou IP du serveur
        port: Port HTTP (default: 80)
        path: Chemin de l'endpoint (default: /health)

    Returns:
        True si le service répond 200, False sinon

    Raises:
        ConnectionError: Si le serveur est injoignable
    """
    pass
```

### Logging

```python
import logging

# Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Utilisation
logger.debug("Debug message")
logger.info("Server started")
logger.warning("High memory usage")
logger.error("Connection failed")
logger.critical("Database down!")
```

---

## Voir Aussi

- [Fichiers & Données](files-data.md) - JSON, YAML, CSV
- [API & Réseau](api-network.md) - Requests, Paramiko
- [Cloud & AWS](cloud-aws.md) - Boto3
