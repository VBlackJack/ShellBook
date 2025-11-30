---
tags:
  - python
  - api
  - requests
  - ssh
  - paramiko
---

# API & Réseau

Intégration avec des APIs REST, SSH et opérations réseau en Python.

---

## Requests (HTTP)

### Installation

```bash
pip install requests
```

### Requêtes de Base

```python
import requests

# GET
response = requests.get("https://api.github.com/users/octocat")
print(response.status_code)  # 200
print(response.json())       # Dict

# GET avec paramètres
response = requests.get(
    "https://api.example.com/servers",
    params={"env": "prod", "status": "active"}
)

# Headers
response = requests.get(
    "https://api.example.com/data",
    headers={
        "Authorization": "Bearer token123",
        "Accept": "application/json"
    }
)

# Timeout (toujours définir!)
response = requests.get("https://api.example.com", timeout=10)
```

### POST, PUT, DELETE

```python
import requests

# POST JSON
response = requests.post(
    "https://api.example.com/servers",
    json={
        "hostname": "web03",
        "ip": "10.0.0.13"
    },
    headers={"Authorization": "Bearer token123"}
)

# POST form data
response = requests.post(
    "https://api.example.com/login",
    data={"username": "admin", "password": "secret"}
)

# PUT
response = requests.put(
    "https://api.example.com/servers/web03",
    json={"status": "maintenance"}
)

# DELETE
response = requests.delete("https://api.example.com/servers/web03")
```

### Gestion des Erreurs

```python
import requests
from requests.exceptions import RequestException, Timeout, HTTPError

def call_api(url: str, timeout: int = 10) -> dict:
    """Appelle une API avec gestion d'erreurs."""
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()  # Lève HTTPError si 4xx/5xx
        return response.json()

    except Timeout:
        print(f"Timeout calling {url}")
        return None
    except HTTPError as e:
        print(f"HTTP Error: {e.response.status_code}")
        return None
    except RequestException as e:
        print(f"Request failed: {e}")
        return None
```

### Session (Réutiliser les Connexions)

```python
import requests

# Session pour plusieurs requêtes
session = requests.Session()
session.headers.update({
    "Authorization": "Bearer token123",
    "Accept": "application/json"
})

# Les headers sont réutilisés
response1 = session.get("https://api.example.com/servers")
response2 = session.get("https://api.example.com/metrics")

# Fermer proprement
session.close()

# Ou avec context manager
with requests.Session() as session:
    session.headers["Authorization"] = "Bearer token123"
    response = session.get("https://api.example.com/data")
```

---

## Exemple : Client API REST

```python
import requests
from typing import Optional, List, Dict


class APIClient:
    """Client pour une API REST."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[Dict]:
        """Effectue une requête."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            response = self.session.request(method, url, timeout=30, **kwargs)
            response.raise_for_status()
            return response.json() if response.text else None
        except requests.exceptions.RequestException as e:
            print(f"API Error: {e}")
            return None

    def get_servers(self) -> List[Dict]:
        """Liste tous les serveurs."""
        return self._request("GET", "/servers") or []

    def get_server(self, server_id: str) -> Optional[Dict]:
        """Récupère un serveur par ID."""
        return self._request("GET", f"/servers/{server_id}")

    def create_server(self, data: Dict) -> Optional[Dict]:
        """Crée un nouveau serveur."""
        return self._request("POST", "/servers", json=data)

    def update_server(self, server_id: str, data: Dict) -> Optional[Dict]:
        """Met à jour un serveur."""
        return self._request("PUT", f"/servers/{server_id}", json=data)

    def delete_server(self, server_id: str) -> bool:
        """Supprime un serveur."""
        result = self._request("DELETE", f"/servers/{server_id}")
        return result is not None


# Utilisation
client = APIClient("https://api.example.com", "my-api-key")

# CRUD
servers = client.get_servers()
new_server = client.create_server({"hostname": "web03", "ip": "10.0.0.13"})
client.update_server("web03", {"status": "active"})
client.delete_server("old-server")
```

---

## Paramiko (SSH)

### Installation

```bash
pip install paramiko
```

### Connexion et Commandes

```python
import paramiko

# Connexion par mot de passe
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

client.connect(
    hostname="10.0.0.10",
    username="admin",
    password="password",
    port=22
)

# Exécuter une commande
stdin, stdout, stderr = client.exec_command("uptime")
output = stdout.read().decode()
errors = stderr.read().decode()
print(output)

client.close()
```

### Connexion par Clé SSH

```python
import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Avec clé privée
client.connect(
    hostname="10.0.0.10",
    username="admin",
    key_filename="/home/user/.ssh/id_rsa",
    # ou pkey=paramiko.RSAKey.from_private_key_file("/path/to/key")
)

stdin, stdout, stderr = client.exec_command("hostname")
print(stdout.read().decode().strip())

client.close()
```

### Classe SSH Réutilisable

```python
import paramiko
from typing import Tuple, Optional


class SSHClient:
    """Client SSH réutilisable."""

    def __init__(self, hostname: str, username: str,
                 password: str = None, key_file: str = None, port: int = 22):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.client = None

    def connect(self):
        """Établit la connexion SSH."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.hostname,
            "username": self.username,
            "port": self.port,
        }

        if self.key_file:
            connect_kwargs["key_filename"] = self.key_file
        elif self.password:
            connect_kwargs["password"] = self.password

        self.client.connect(**connect_kwargs)

    def run(self, command: str, timeout: int = 30) -> Tuple[str, str, int]:
        """Exécute une commande et retourne (stdout, stderr, exit_code)."""
        if not self.client:
            self.connect()

        stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()

        return (
            stdout.read().decode().strip(),
            stderr.read().decode().strip(),
            exit_code
        )

    def close(self):
        """Ferme la connexion."""
        if self.client:
            self.client.close()

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Utilisation
with SSHClient("10.0.0.10", "admin", key_file="~/.ssh/id_rsa") as ssh:
    stdout, stderr, code = ssh.run("uptime")
    print(f"Uptime: {stdout}")

    stdout, stderr, code = ssh.run("df -h /")
    print(f"Disk: {stdout}")
```

### SFTP (Transfert de Fichiers)

```python
import paramiko

# Connexion
transport = paramiko.Transport(("10.0.0.10", 22))
transport.connect(username="admin", password="password")
sftp = paramiko.SFTPClient.from_transport(transport)

# Upload
sftp.put("/local/file.txt", "/remote/file.txt")

# Download
sftp.get("/remote/file.txt", "/local/file.txt")

# Lister un répertoire
for entry in sftp.listdir("/var/log"):
    print(entry)

# Fermer
sftp.close()
transport.close()
```

---

## Sockets (Bas Niveau)

### Vérification de Port

```python
import socket
from typing import List, Tuple


def check_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Vérifie si un port est ouvert."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            return result == 0
    except socket.error:
        return False


def scan_ports(host: str, ports: List[int]) -> List[Tuple[int, bool]]:
    """Scanne plusieurs ports."""
    results = []
    for port in ports:
        is_open = check_port(host, port)
        results.append((port, is_open))
    return results


# Utilisation
common_ports = [22, 80, 443, 3306, 5432, 6379]
results = scan_ports("10.0.0.10", common_ports)

for port, is_open in results:
    status = "OPEN" if is_open else "CLOSED"
    print(f"Port {port}: {status}")
```

### Résolution DNS

```python
import socket

# Résoudre un hostname
ip = socket.gethostbyname("google.com")
print(ip)

# Reverse DNS
hostname = socket.gethostbyaddr("8.8.8.8")
print(hostname)

# Toutes les IPs
ips = socket.getaddrinfo("google.com", 443)
for ip in ips:
    print(ip[4][0])
```

---

## Webhooks

### Envoyer un Webhook

```python
import requests
import json
from datetime import datetime


def send_slack_webhook(webhook_url: str, message: str, channel: str = None):
    """Envoie un message à Slack."""
    payload = {
        "text": message,
        "username": "Python Bot",
        "icon_emoji": ":robot_face:"
    }
    if channel:
        payload["channel"] = channel

    response = requests.post(webhook_url, json=payload, timeout=10)
    return response.status_code == 200


def send_teams_webhook(webhook_url: str, title: str, message: str):
    """Envoie une carte à Microsoft Teams."""
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title,
        "themeColor": "0076D7",
        "title": title,
        "sections": [{
            "activityTitle": message,
            "facts": [
                {"name": "Timestamp", "value": datetime.now().isoformat()}
            ]
        }]
    }

    response = requests.post(webhook_url, json=payload, timeout=10)
    return response.status_code == 200


# Utilisation
send_slack_webhook(
    "https://hooks.slack.com/services/XXX/YYY/ZZZ",
    ":warning: Server web01 is down!"
)
```

---

## Polling & Retry

```python
import time
import requests
from typing import Callable


def retry(func: Callable, max_attempts: int = 3, delay: float = 1.0):
    """Réessaie une fonction en cas d'échec."""
    last_exception = None

    for attempt in range(1, max_attempts + 1):
        try:
            return func()
        except Exception as e:
            last_exception = e
            print(f"Attempt {attempt} failed: {e}")
            if attempt < max_attempts:
                time.sleep(delay * attempt)  # Backoff exponentiel

    raise last_exception


def wait_for_service(url: str, timeout: int = 300, interval: int = 5) -> bool:
    """Attend qu'un service soit disponible."""
    start_time = time.time()

    while time.time() - start_time < timeout:
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                return True
        except requests.exceptions.RequestException:
            pass

        print(f"Waiting for {url}...")
        time.sleep(interval)

    return False


# Utilisation
if wait_for_service("http://localhost:8080/health", timeout=120):
    print("Service is ready!")
else:
    print("Service failed to start")
```

---

## Voir Aussi

- [Fondamentaux](fundamentals.md) - Bases Python
- [Cloud & AWS](cloud-aws.md) - Boto3
- [Tests](testing.md) - Pytest
