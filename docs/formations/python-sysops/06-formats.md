---
tags:
  - formation
  - python
  - json
  - yaml
  - csv
---

# Module 06 - Formats de Données

Manipuler JSON, YAML, CSV et autres formats de configuration.

---

## Objectifs du Module

- Parser et générer du JSON
- Travailler avec des fichiers YAML
- Lire et écrire des CSV
- Manipuler des fichiers INI

---

## 1. JSON

### Lecture/Écriture

```python
import json

# Depuis une string
data = json.loads('{"host": "localhost", "port": 8080}')

# Vers une string
json_string = json.dumps(data)
json_pretty = json.dumps(data, indent=2)

# Depuis un fichier
with open("config.json") as f:
    config = json.load(f)

# Vers un fichier
with open("output.json", "w") as f:
    json.dump(data, f, indent=2)
```

### Options de Formatage

```python
data = {
    "servers": ["web01", "web02"],
    "config": {"timeout": 30, "retries": 3}
}

# Formatage lisible
json.dumps(data, indent=2)

# Tri des clés
json.dumps(data, indent=2, sort_keys=True)

# Séparateurs compacts
json.dumps(data, separators=(',', ':'))  # Sans espaces

# Encodage non-ASCII
json.dumps({"nom": "Café"}, ensure_ascii=False)
```

### Gestion des Types Python

```python
from datetime import datetime
from pathlib import Path

# Problème : types non-sérialisables
data = {
    "timestamp": datetime.now(),  # Non sérialisable
    "path": Path("/var/log")      # Non sérialisable
}

# Solution : encoder personnalisé
class CustomEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, Path):
            return str(obj)
        return super().default(obj)

json.dumps(data, cls=CustomEncoder)
# {"timestamp": "2024-01-15T10:30:00", "path": "/var/log"}
```

---

## 2. YAML

### Installation

```bash
pip install pyyaml
```

### Lecture/Écriture

```python
import yaml

# Depuis une string
config = yaml.safe_load("""
server:
  host: localhost
  port: 8080
  ssl: true
""")

# Vers une string
yaml_string = yaml.dump(config, default_flow_style=False)

# Depuis un fichier
with open("config.yaml") as f:
    config = yaml.safe_load(f)

# Vers un fichier
with open("output.yaml", "w") as f:
    yaml.dump(config, f, default_flow_style=False)
```

### Multi-documents YAML

```python
# Fichier avec plusieurs documents
yaml_content = """
---
name: web01
role: web
---
name: db01
role: database
"""

# Lire tous les documents
docs = list(yaml.safe_load_all(yaml_content))
# [{'name': 'web01', 'role': 'web'}, {'name': 'db01', 'role': 'database'}]

# Depuis un fichier
with open("servers.yaml") as f:
    servers = list(yaml.safe_load_all(f))
```

### Options de Formatage

```python
data = {"servers": ["web01", "web02"], "config": {"timeout": 30}}

# Format bloc (par défaut pour safe_dump)
yaml.dump(data, default_flow_style=False)
# servers:
# - web01
# - web02
# config:
#   timeout: 30

# Format inline
yaml.dump(data, default_flow_style=True)
# {config: {timeout: 30}, servers: [web01, web02]}

# Préserver l'ordre
yaml.dump(data, default_flow_style=False, sort_keys=False)
```

!!! warning "Sécurité YAML"
    Toujours utiliser `yaml.safe_load()` au lieu de `yaml.load()`.
    `yaml.load()` peut exécuter du code arbitraire !

---

## 3. CSV

### Lecture

```python
import csv

# Lecture simple
with open("servers.csv") as f:
    reader = csv.reader(f)
    for row in reader:
        print(row)  # Liste

# Avec headers (DictReader)
with open("servers.csv") as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(row)  # Dict avec les headers comme clés

# Fichier servers.csv:
# hostname,ip,port
# web01,10.0.0.1,80
# db01,10.0.0.10,5432
```

### Écriture

```python
import csv

# Écriture simple
servers = [
    ["web01", "10.0.0.1", 80],
    ["db01", "10.0.0.10", 5432]
]

with open("servers.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["hostname", "ip", "port"])  # Header
    writer.writerows(servers)

# Avec DictWriter
servers = [
    {"hostname": "web01", "ip": "10.0.0.1", "port": 80},
    {"hostname": "db01", "ip": "10.0.0.10", "port": 5432}
]

with open("servers.csv", "w", newline="") as f:
    fieldnames = ["hostname", "ip", "port"]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(servers)
```

### Options CSV

```python
# Délimiteur personnalisé
with open("data.tsv") as f:
    reader = csv.reader(f, delimiter="\t")

# Caractère de quote
with open("data.csv") as f:
    reader = csv.reader(f, quotechar="'")

# Dialectes
csv.register_dialect('pipes', delimiter='|', quoting=csv.QUOTE_MINIMAL)
with open("data.csv") as f:
    reader = csv.reader(f, dialect='pipes')
```

---

## 4. INI / ConfigParser

```python
from configparser import ConfigParser

# Lecture
config = ConfigParser()
config.read("/etc/myapp.ini")

# Accès aux valeurs
host = config.get("database", "host")
port = config.getint("database", "port")
debug = config.getboolean("general", "debug")

# Valeur par défaut
timeout = config.getint("network", "timeout", fallback=30)

# Sections
config.sections()  # ['general', 'database', 'network']
config.items("database")  # [('host', 'localhost'), ('port', '5432')]

# Écriture
config = ConfigParser()
config["general"] = {"debug": "true", "log_level": "INFO"}
config["database"] = {"host": "localhost", "port": "5432"}

with open("myapp.ini", "w") as f:
    config.write(f)
```

Fichier INI exemple :
```ini
[general]
debug = true
log_level = INFO

[database]
host = localhost
port = 5432
user = admin
```

---

## 5. XML (Optionnel)

```python
import xml.etree.ElementTree as ET

# Parser du XML
tree = ET.parse("config.xml")
root = tree.getroot()

# Naviguer
for server in root.findall("server"):
    name = server.get("name")  # Attribut
    ip = server.find("ip").text  # Élément enfant
    print(f"{name}: {ip}")

# Créer du XML
root = ET.Element("servers")
server = ET.SubElement(root, "server", name="web01")
ET.SubElement(server, "ip").text = "10.0.0.1"
ET.SubElement(server, "port").text = "80"

tree = ET.ElementTree(root)
tree.write("output.xml", encoding="unicode", xml_declaration=True)
```

---

## 6. Cas d'Usage SysOps

### Chargeur de Configuration Multi-format

```python
from pathlib import Path
import json
import yaml

def load_config(path):
    """Charge une config JSON ou YAML."""
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Config not found: {path}")

    content = path.read_text()

    if path.suffix in [".yaml", ".yml"]:
        return yaml.safe_load(content)
    elif path.suffix == ".json":
        return json.loads(content)
    else:
        raise ValueError(f"Unsupported format: {path.suffix}")

# Usage
config = load_config("/etc/myapp/config.yaml")
```

### Merge de Configurations

```python
def merge_configs(*configs):
    """Fusionne plusieurs configurations (le dernier gagne)."""
    result = {}
    for config in configs:
        deep_merge(result, config)
    return result

def deep_merge(base, override):
    """Fusion profonde de dictionnaires."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            deep_merge(base[key], value)
        else:
            base[key] = value

# Usage : defaults < config < environment
defaults = {"timeout": 30, "retries": 3}
config = load_config("config.yaml")
env_config = {"timeout": int(os.getenv("TIMEOUT", 30))}

final_config = merge_configs(defaults, config, env_config)
```

### Export d'Inventaire

```python
import csv
import json

def export_inventory(servers, format="csv", output_path="inventory"):
    """Exporte l'inventaire dans différents formats."""

    if format == "csv":
        with open(f"{output_path}.csv", "w", newline="") as f:
            if servers:
                writer = csv.DictWriter(f, fieldnames=servers[0].keys())
                writer.writeheader()
                writer.writerows(servers)

    elif format == "json":
        with open(f"{output_path}.json", "w") as f:
            json.dump(servers, f, indent=2)

    elif format == "yaml":
        with open(f"{output_path}.yaml", "w") as f:
            yaml.dump(servers, f, default_flow_style=False)

# Usage
servers = [
    {"hostname": "web01", "ip": "10.0.0.1", "role": "web"},
    {"hostname": "db01", "ip": "10.0.0.10", "role": "database"},
]

export_inventory(servers, format="yaml")
```

---

## Exercices Pratiques

### Exercice 1 : Convertisseur de Formats

```python
# Créer un script qui convertit entre JSON, YAML et CSV
# python convert.py input.json output.yaml
# python convert.py servers.csv servers.json
```

### Exercice 2 : Validateur de Configuration

```python
# Créer une fonction validate_config(config, schema) qui :
# - Vérifie les champs requis
# - Valide les types
# - Retourne les erreurs trouvées

schema = {
    "host": {"type": str, "required": True},
    "port": {"type": int, "required": True, "min": 1, "max": 65535},
    "ssl": {"type": bool, "required": False, "default": False}
}
```

### Exercice 3 : Ansible Inventory Generator

```python
# Créer une fonction qui génère un inventaire Ansible YAML
# à partir d'une liste de serveurs avec leurs groupes

servers = [
    {"name": "web01", "ip": "10.0.0.1", "groups": ["web", "prod"]},
    {"name": "web02", "ip": "10.0.0.2", "groups": ["web", "prod"]},
    {"name": "db01", "ip": "10.0.0.10", "groups": ["database", "prod"]},
]

# Sortie attendue :
# all:
#   children:
#     web:
#       hosts:
#         web01:
#           ansible_host: 10.0.0.1
#         web02:
#           ansible_host: 10.0.0.2
#     database:
#       hosts:
#         db01:
#           ansible_host: 10.0.0.10
```

---

## Points Clés à Retenir

!!! success "Formats de Données"
    - **JSON** : Standard pour APIs, pas de commentaires
    - **YAML** : Lisible, commentaires, multi-documents
    - **CSV** : Données tabulaires, interop Excel
    - **INI** : Config simple, sections

!!! tip "Choix du Format"
    | Besoin | Format |
    |--------|--------|
    | API REST | JSON |
    | Config lisible | YAML |
    | Données tabulaires | CSV |
    | Config simple | INI |
    | Interop legacy | XML |

---

## Voir Aussi

- [Module 07 - Sous-processus](07-subprocess.md)
- [Python Fichiers & Données](../../python/files-data.md)
