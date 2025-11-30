---
tags:
  - python
  - json
  - yaml
  - files
---

# Fichiers & Données

Manipulation de fichiers, JSON, YAML et CSV en Python.

---

## Fichiers Texte

### Lecture

```python
# Lecture complète
with open("config.txt", "r") as f:
    content = f.read()

# Lecture ligne par ligne
with open("servers.txt", "r") as f:
    for line in f:
        hostname = line.strip()
        print(hostname)

# Lire toutes les lignes dans une liste
with open("servers.txt", "r") as f:
    servers = [line.strip() for line in f if line.strip()]
```

### Écriture

```python
# Écriture (écrase)
with open("output.txt", "w") as f:
    f.write("Hello World\n")

# Append
with open("log.txt", "a") as f:
    f.write(f"{datetime.now()}: Event occurred\n")

# Écrire plusieurs lignes
lines = ["server1", "server2", "server3"]
with open("servers.txt", "w") as f:
    f.writelines(line + "\n" for line in lines)
```

---

## Pathlib (Moderne)

```python
from pathlib import Path

# Chemins
config_dir = Path("/etc/myapp")
config_file = config_dir / "config.yaml"

# Vérifications
config_file.exists()
config_file.is_file()
config_dir.is_dir()

# Lecture/Écriture
content = config_file.read_text()
config_file.write_text("key: value\n")

# Lister les fichiers
for f in Path(".").glob("*.py"):
    print(f.name)

# Récursif
for f in Path(".").rglob("*.yaml"):
    print(f)

# Créer un répertoire
Path("logs").mkdir(parents=True, exist_ok=True)

# Informations fichier
print(config_file.stem)      # nom sans extension
print(config_file.suffix)    # extension
print(config_file.parent)    # répertoire parent
```

---

## JSON

### Lecture

```python
import json

# Depuis un fichier
with open("config.json", "r") as f:
    config = json.load(f)

# Depuis une string
json_str = '{"hostname": "web01", "port": 443}'
data = json.loads(json_str)

# Accès aux données
print(config["database"]["host"])
print(config.get("optional_key", "default_value"))
```

### Écriture

```python
import json

config = {
    "hostname": "web01",
    "ports": [80, 443],
    "settings": {
        "ssl": True,
        "timeout": 30
    }
}

# Vers un fichier (formaté)
with open("config.json", "w") as f:
    json.dump(config, f, indent=2)

# Vers une string
json_str = json.dumps(config, indent=2)
print(json_str)

# Compact (pour API)
json_compact = json.dumps(config, separators=(',', ':'))
```

### Exemple Complet

```python
import json
from pathlib import Path
from datetime import datetime


def load_inventory(filepath: str) -> dict:
    """Charge l'inventaire depuis un fichier JSON."""
    path = Path(filepath)
    if not path.exists():
        return {"servers": [], "updated": None}

    with open(path, "r") as f:
        return json.load(f)


def save_inventory(filepath: str, inventory: dict):
    """Sauvegarde l'inventaire."""
    inventory["updated"] = datetime.now().isoformat()
    with open(filepath, "w") as f:
        json.dump(inventory, f, indent=2)


def add_server(inventory: dict, hostname: str, ip: str):
    """Ajoute un serveur à l'inventaire."""
    server = {"hostname": hostname, "ip": ip, "added": datetime.now().isoformat()}
    inventory["servers"].append(server)


# Utilisation
inventory = load_inventory("inventory.json")
add_server(inventory, "web03", "10.0.0.13")
save_inventory("inventory.json", inventory)
```

---

## YAML

### Installation

```bash
pip install pyyaml
```

### Lecture

```python
import yaml

# Depuis un fichier
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

# Depuis une string
yaml_str = """
database:
  host: localhost
  port: 5432
servers:
  - web01
  - web02
"""
data = yaml.safe_load(yaml_str)

# Plusieurs documents
with open("multi.yaml", "r") as f:
    docs = list(yaml.safe_load_all(f))
```

### Écriture

```python
import yaml

config = {
    "database": {
        "host": "localhost",
        "port": 5432
    },
    "servers": ["web01", "web02"]
}

# Vers un fichier
with open("config.yaml", "w") as f:
    yaml.dump(config, f, default_flow_style=False)

# Vers une string
yaml_str = yaml.dump(config, default_flow_style=False)
```

### Ansible Inventory Parser

```python
import yaml
from pathlib import Path


def parse_ansible_inventory(filepath: str) -> dict:
    """Parse un inventaire Ansible YAML."""
    with open(filepath, "r") as f:
        inventory = yaml.safe_load(f)

    servers = []
    for group_name, group_data in inventory.items():
        if group_name == "all":
            continue
        if "hosts" in group_data:
            for hostname, host_vars in group_data["hosts"].items():
                servers.append({
                    "hostname": hostname,
                    "group": group_name,
                    "vars": host_vars or {}
                })

    return servers


# inventory.yaml:
# webservers:
#   hosts:
#     web01:
#       ansible_host: 10.0.0.10
#     web02:
#       ansible_host: 10.0.0.11
# databases:
#   hosts:
#     db01:
#       ansible_host: 10.0.0.20

servers = parse_ansible_inventory("inventory.yaml")
for srv in servers:
    print(f"{srv['hostname']} ({srv['group']}): {srv['vars'].get('ansible_host')}")
```

---

## CSV

### Lecture

```python
import csv

# Lecture simple
with open("servers.csv", "r") as f:
    reader = csv.reader(f)
    header = next(reader)  # Skip header
    for row in reader:
        hostname, ip, port = row
        print(f"{hostname}: {ip}:{port}")

# Avec DictReader (recommandé)
with open("servers.csv", "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(f"{row['hostname']}: {row['ip']}")
```

### Écriture

```python
import csv

servers = [
    {"hostname": "web01", "ip": "10.0.0.10", "port": "443"},
    {"hostname": "web02", "ip": "10.0.0.11", "port": "443"},
]

# Avec DictWriter
with open("servers.csv", "w", newline="") as f:
    fieldnames = ["hostname", "ip", "port"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(servers)
```

---

## INI / Config Files

```python
import configparser

# Lecture
config = configparser.ConfigParser()
config.read("config.ini")

db_host = config["database"]["host"]
db_port = config.getint("database", "port")
debug = config.getboolean("app", "debug", fallback=False)

# Écriture
config = configparser.ConfigParser()
config["database"] = {
    "host": "localhost",
    "port": "5432"
}
config["app"] = {
    "debug": "true"
}
with open("config.ini", "w") as f:
    config.write(f)
```

---

## Variables d'Environnement (.env)

```bash
pip install python-dotenv
```

```python
from dotenv import load_dotenv
import os

# Charger .env
load_dotenv()

# Utiliser les variables
db_host = os.getenv("DB_HOST", "localhost")
db_password = os.getenv("DB_PASSWORD")
```

```ini
# .env
DB_HOST=localhost
DB_PORT=5432
DB_PASSWORD=secret
```

---

## Templates (Jinja2)

```bash
pip install jinja2
```

```python
from jinja2 import Template, Environment, FileSystemLoader

# Template inline
template = Template("""
server {
    listen {{ port }};
    server_name {{ hostname }};

    {% for location in locations %}
    location {{ location.path }} {
        proxy_pass {{ location.backend }};
    }
    {% endfor %}
}
""")

config = template.render(
    port=443,
    hostname="example.com",
    locations=[
        {"path": "/", "backend": "http://app:8080"},
        {"path": "/api", "backend": "http://api:3000"}
    ]
)
print(config)

# Depuis fichiers
env = Environment(loader=FileSystemLoader("templates"))
template = env.get_template("nginx.conf.j2")
config = template.render(servers=servers)
```

---

## Manipulation de Données

### Filtrage et Transformation

```python
servers = [
    {"name": "web01", "env": "prod", "cpu": 85},
    {"name": "web02", "env": "prod", "cpu": 45},
    {"name": "dev01", "env": "dev", "cpu": 20},
]

# Filtrer
prod_servers = [s for s in servers if s["env"] == "prod"]
high_cpu = [s for s in servers if s["cpu"] > 80]

# Transformer
names = [s["name"] for s in servers]
server_map = {s["name"]: s for s in servers}

# Trier
sorted_by_cpu = sorted(servers, key=lambda s: s["cpu"], reverse=True)

# Grouper
from itertools import groupby
sorted_servers = sorted(servers, key=lambda s: s["env"])
grouped = {k: list(v) for k, v in groupby(sorted_servers, key=lambda s: s["env"])}
```

### Validation

```python
def validate_server(server: dict) -> list:
    """Valide la configuration d'un serveur."""
    errors = []

    if "hostname" not in server:
        errors.append("hostname is required")

    if "ip" in server:
        import ipaddress
        try:
            ipaddress.ip_address(server["ip"])
        except ValueError:
            errors.append(f"invalid IP: {server['ip']}")

    if "port" in server:
        if not 1 <= server["port"] <= 65535:
            errors.append(f"invalid port: {server['port']}")

    return errors


# Utilisation
server = {"hostname": "web01", "ip": "not-an-ip", "port": 99999}
errors = validate_server(server)
if errors:
    print(f"Validation failed: {errors}")
```

---

## Voir Aussi

- [Fondamentaux](fundamentals.md) - Bases Python
- [API & Réseau](api-network.md) - HTTP, SSH
