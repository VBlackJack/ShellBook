---
tags:
  - formation
  - python
  - cheatsheet
  - libraries
---

# Cheatsheet Bibliothèques SysOps

Aide-mémoire des bibliothèques Python essentielles pour SysOps.

---

## requests - HTTP Client

```python
import requests

# GET
r = requests.get("https://api.example.com/users")
r.status_code          # 200
r.json()               # Parse JSON
r.text                 # Contenu brut
r.headers              # Headers de réponse

# GET avec paramètres
r = requests.get(url, params={"page": 1, "limit": 10})

# POST
r = requests.post(url, json={"name": "test"})
r = requests.post(url, data={"field": "value"})

# Headers et Auth
r = requests.get(url,
    headers={"Authorization": "Bearer token"},
    auth=("user", "pass"),
    timeout=30
)

# Session (réutilise connexion)
session = requests.Session()
session.headers.update({"Authorization": "Bearer token"})
session.get(url)
```

---

## paramiko - SSH

```python
import paramiko

# Connexion basique
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect("hostname", username="user", password="pass")

# Avec clé
ssh.connect("hostname", username="user", key_filename="/path/to/key")

# Exécuter une commande
stdin, stdout, stderr = ssh.exec_command("uptime")
output = stdout.read().decode()
exit_code = stdout.channel.recv_exit_status()

# SFTP
sftp = ssh.open_sftp()
sftp.get("/remote/file", "/local/file")
sftp.put("/local/file", "/remote/file")
sftp.close()

ssh.close()
```

---

## boto3 - AWS SDK

```python
import boto3

# Client EC2
ec2 = boto3.client("ec2")
instances = ec2.describe_instances()

# Resource EC2 (haut niveau)
ec2 = boto3.resource("ec2")
for instance in ec2.instances.all():
    print(instance.id, instance.state)

# S3
s3 = boto3.client("s3")
s3.upload_file("/local/file", "bucket", "key")
s3.download_file("bucket", "key", "/local/file")

# Secrets Manager
secrets = boto3.client("secretsmanager")
secret = secrets.get_secret_value(SecretId="my-secret")

# SSM Parameter Store
ssm = boto3.client("ssm")
param = ssm.get_parameter(Name="/myapp/config", WithDecryption=True)
```

---

## subprocess - Commandes Système

```python
import subprocess

# Exécution simple
result = subprocess.run(["ls", "-la"], capture_output=True, text=True)
result.stdout
result.stderr
result.returncode

# Avec shell
result = subprocess.run("ls -la | grep .py", shell=True, capture_output=True, text=True)

# Vérifier le code retour
result = subprocess.run(["grep", "error", "/var/log/messages"], check=True)

# Timeout
result = subprocess.run(["long_command"], timeout=30)

# Pipe
p1 = subprocess.Popen(["cat", "file.txt"], stdout=subprocess.PIPE)
p2 = subprocess.Popen(["grep", "error"], stdin=p1.stdout, stdout=subprocess.PIPE)
output = p2.communicate()[0]
```

---

## pyyaml - YAML

```python
import yaml

# Lecture
with open("config.yaml") as f:
    config = yaml.safe_load(f)

# Multi-documents
with open("docs.yaml") as f:
    docs = list(yaml.safe_load_all(f))

# Écriture
with open("output.yaml", "w") as f:
    yaml.dump(data, f, default_flow_style=False)
```

---

## click - CLI Framework

```python
import click

@click.command()
@click.option("--name", "-n", required=True, help="Server name")
@click.option("--port", "-p", default=22, type=int, help="SSH port")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.argument("action", type=click.Choice(["start", "stop", "status"]))
def cli(name, port, verbose, action):
    """Manage servers."""
    click.echo(f"Action: {action} on {name}:{port}")

if __name__ == "__main__":
    cli()

# Usage: python cli.py --name web01 -v start
```

---

## rich - Terminal Formatting

```python
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()

# Couleurs et styles
console.print("[bold red]Error![/bold red] Something went wrong")
console.print("[green]Success[/green]")

# Tableau
table = Table(title="Servers")
table.add_column("Name", style="cyan")
table.add_column("Status", style="green")
table.add_row("web01", "running")
table.add_row("db01", "stopped")
console.print(table)

# Progress bar
for item in track(items, description="Processing..."):
    process(item)
```

---

## logging - Journalisation

```python
import logging

# Configuration basique
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)
logger.info("Starting application")
logger.warning("Resource low")
logger.error("Connection failed")

# Vers fichier
handler = logging.FileHandler("/var/log/myapp.log")
handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
logger.addHandler(handler)
```

---

## pytest - Tests

```python
import pytest

def test_addition():
    assert 1 + 1 == 2

def test_exception():
    with pytest.raises(ValueError):
        int("not a number")

@pytest.fixture
def sample_data():
    return {"host": "localhost", "port": 8080}

def test_with_fixture(sample_data):
    assert sample_data["port"] == 8080

@pytest.mark.parametrize("input,expected", [
    (1, 2),
    (2, 4),
    (3, 6),
])
def test_double(input, expected):
    assert input * 2 == expected
```

---

## Jinja2 - Templates

```python
from jinja2 import Template, Environment, FileSystemLoader

# Template simple
template = Template("Hello {{ name }}!")
output = template.render(name="World")

# Depuis fichier
env = Environment(loader=FileSystemLoader("templates"))
template = env.get_template("config.j2")
output = template.render(servers=servers, port=8080)

# Template config.j2
"""
{% for server in servers %}
server {{ server.name }} {
    address {{ server.ip }};
    port {{ port }};
}
{% endfor %}
"""
```

---

## Installation Rapide

```bash
# Essentiels SysOps
pip install requests paramiko pyyaml click rich

# AWS
pip install boto3

# Dev & Test
pip install pytest black flake8

# Templates
pip install jinja2
```

---

## Voir Aussi

- [Cheatsheet Python](cheatsheet-python.md)
- [Programme de la formation](index.md)
- [Python API & Réseau](../../python/api-network.md)
- [Python Cloud & AWS](../../python/cloud-aws.md)
