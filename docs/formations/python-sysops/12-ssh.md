---
tags:
  - formation
  - python
  - ssh
  - paramiko
  - automatisation
  - remote
---

# Module 12 - SSH & Automatisation Distante

Automatiser l'administration de serveurs distants via SSH.

---

## Objectifs du Module

- Utiliser Paramiko pour les connexions SSH
- Exécuter des commandes à distance
- Transférer des fichiers (SFTP)
- Gérer plusieurs serveurs

---

## 1. Installation

```bash
pip install paramiko
pip install fabric  # Optionnel, pour le haut niveau
```

---

## 2. Connexion SSH avec Paramiko

### Connexion Basique

```python
import paramiko

# Créer le client SSH
client = paramiko.SSHClient()

# Accepter automatiquement les clés inconnues (attention en production!)
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    # Connexion par mot de passe
    client.connect(
        hostname="192.168.1.100",
        port=22,
        username="admin",
        password="secret",
        timeout=10
    )

    # Exécuter une commande
    stdin, stdout, stderr = client.exec_command("uptime")

    # Lire les résultats
    output = stdout.read().decode()
    error = stderr.read().decode()
    exit_code = stdout.channel.recv_exit_status()

    print(f"Output: {output}")
    print(f"Exit code: {exit_code}")

finally:
    client.close()
```

### Connexion par Clé SSH

```python
import paramiko
from pathlib import Path

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Clé privée sans passphrase
private_key = paramiko.RSAKey.from_private_key_file(
    str(Path.home() / ".ssh" / "id_rsa")
)

# Clé avec passphrase
private_key = paramiko.RSAKey.from_private_key_file(
    str(Path.home() / ".ssh" / "id_rsa"),
    password="key_passphrase"
)

# Connexion
client.connect(
    hostname="192.168.1.100",
    username="admin",
    pkey=private_key
)

# Ou directement avec key_filename
client.connect(
    hostname="192.168.1.100",
    username="admin",
    key_filename=str(Path.home() / ".ssh" / "id_rsa")
)
```

### Connexion via Agent SSH

```python
import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Utiliser l'agent SSH (ssh-agent)
client.connect(
    hostname="192.168.1.100",
    username="admin",
    allow_agent=True,
    look_for_keys=True  # Cherche aussi dans ~/.ssh/
)
```

---

## 3. Exécution de Commandes

### Commandes Simples

```python
import paramiko

def run_command(client, command, timeout=30):
    """Exécute une commande et retourne le résultat."""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)

    output = stdout.read().decode("utf-8")
    error = stderr.read().decode("utf-8")
    exit_code = stdout.channel.recv_exit_status()

    return {
        "stdout": output,
        "stderr": error,
        "exit_code": exit_code,
        "success": exit_code == 0
    }

# Utilisation
result = run_command(client, "df -h")
if result["success"]:
    print(result["stdout"])
else:
    print(f"Erreur: {result['stderr']}")
```

### Commandes avec Sudo

```python
def run_sudo_command(client, command, sudo_password):
    """Exécute une commande avec sudo."""
    sudo_command = f"echo {sudo_password} | sudo -S {command}"

    stdin, stdout, stderr = client.exec_command(sudo_command)

    output = stdout.read().decode()
    error = stderr.read().decode()

    # Filtrer le prompt sudo de stderr
    error_lines = [l for l in error.split('\n')
                   if not l.startswith('[sudo]')]

    return {
        "stdout": output,
        "stderr": '\n'.join(error_lines),
        "exit_code": stdout.channel.recv_exit_status()
    }

# Utilisation
result = run_sudo_command(client, "systemctl restart nginx", "sudo_password")
```

### Shell Interactif

```python
import paramiko
import time

def interactive_shell(client, commands):
    """Exécute plusieurs commandes dans un shell interactif."""
    channel = client.invoke_shell()
    time.sleep(0.5)  # Attendre le prompt

    output = ""

    for cmd in commands:
        channel.send(cmd + "\n")
        time.sleep(0.5)

        while channel.recv_ready():
            output += channel.recv(4096).decode()

    channel.close()
    return output

# Utilisation
commands = [
    "cd /var/log",
    "ls -la",
    "tail -5 syslog"
]
output = interactive_shell(client, commands)
```

---

## 4. Transfert de Fichiers (SFTP)

### Opérations SFTP de Base

```python
import paramiko
from pathlib import Path

# Ouvrir une session SFTP
sftp = client.open_sftp()

try:
    # Upload un fichier
    sftp.put("/local/path/file.txt", "/remote/path/file.txt")

    # Download un fichier
    sftp.get("/remote/path/file.txt", "/local/path/file.txt")

    # Avec callback de progression
    def progress(transferred, total):
        percent = (transferred / total) * 100
        print(f"\rProgress: {percent:.1f}%", end="")

    sftp.put("large_file.tar.gz", "/remote/large_file.tar.gz",
             callback=progress)

finally:
    sftp.close()
```

### Opérations sur les Fichiers/Répertoires

```python
# Lister un répertoire
files = sftp.listdir("/var/log")
for f in files:
    print(f)

# Avec attributs
for attr in sftp.listdir_attr("/var/log"):
    print(f"{attr.filename} - {attr.st_size} bytes - {attr.st_mtime}")

# Créer un répertoire
sftp.mkdir("/remote/new_dir")

# Supprimer un fichier
sftp.remove("/remote/file.txt")

# Supprimer un répertoire
sftp.rmdir("/remote/empty_dir")

# Renommer
sftp.rename("/remote/old.txt", "/remote/new.txt")

# Changer les permissions
sftp.chmod("/remote/script.sh", 0o755)

# Changer le propriétaire
sftp.chown("/remote/file.txt", uid=1000, gid=1000)

# Obtenir les attributs
stat = sftp.stat("/remote/file.txt")
print(f"Size: {stat.st_size}")
print(f"Modified: {stat.st_mtime}")
```

### Upload/Download Récursif

```python
import os
from pathlib import Path

def sftp_upload_dir(sftp, local_dir, remote_dir):
    """Upload récursif d'un répertoire."""
    local_path = Path(local_dir)

    # Créer le répertoire distant s'il n'existe pas
    try:
        sftp.stat(remote_dir)
    except FileNotFoundError:
        sftp.mkdir(remote_dir)

    for item in local_path.iterdir():
        remote_path = f"{remote_dir}/{item.name}"

        if item.is_dir():
            sftp_upload_dir(sftp, str(item), remote_path)
        else:
            print(f"Uploading: {item} -> {remote_path}")
            sftp.put(str(item), remote_path)

def sftp_download_dir(sftp, remote_dir, local_dir):
    """Download récursif d'un répertoire."""
    local_path = Path(local_dir)
    local_path.mkdir(parents=True, exist_ok=True)

    for attr in sftp.listdir_attr(remote_dir):
        remote_path = f"{remote_dir}/{attr.filename}"
        local_file = local_path / attr.filename

        if stat.S_ISDIR(attr.st_mode):
            sftp_download_dir(sftp, remote_path, str(local_file))
        else:
            print(f"Downloading: {remote_path} -> {local_file}")
            sftp.get(remote_path, str(local_file))

# Utilisation
sftp_upload_dir(sftp, "./deploy", "/var/www/app")
sftp_download_dir(sftp, "/var/log/app", "./logs")
```

---

## 5. Client SSH Réutilisable

```python
import paramiko
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from pathlib import Path
import logging

@dataclass
class CommandResult:
    stdout: str
    stderr: str
    exit_code: int
    success: bool

class SSHClient:
    """Client SSH réutilisable avec gestion d'erreurs."""

    def __init__(
        self,
        hostname: str,
        username: str,
        password: Optional[str] = None,
        key_file: Optional[str] = None,
        port: int = 22,
        timeout: int = 30
    ):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.key_file = key_file
        self.port = port
        self.timeout = timeout
        self.client = None
        self.sftp = None
        self.logger = logging.getLogger(__name__)

    def connect(self):
        """Établit la connexion SSH."""
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.hostname,
            "port": self.port,
            "username": self.username,
            "timeout": self.timeout
        }

        if self.key_file:
            connect_kwargs["key_filename"] = self.key_file
        elif self.password:
            connect_kwargs["password"] = self.password
        else:
            connect_kwargs["allow_agent"] = True
            connect_kwargs["look_for_keys"] = True

        self.logger.info(f"Connecting to {self.hostname}...")
        self.client.connect(**connect_kwargs)
        self.logger.info(f"Connected to {self.hostname}")

    def disconnect(self):
        """Ferme la connexion."""
        if self.sftp:
            self.sftp.close()
            self.sftp = None
        if self.client:
            self.client.close()
            self.client = None
        self.logger.info(f"Disconnected from {self.hostname}")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    def run(self, command: str, timeout: int = None) -> CommandResult:
        """Exécute une commande."""
        if not self.client:
            raise RuntimeError("Not connected")

        self.logger.debug(f"Running: {command}")

        stdin, stdout, stderr = self.client.exec_command(
            command,
            timeout=timeout or self.timeout
        )

        out = stdout.read().decode("utf-8")
        err = stderr.read().decode("utf-8")
        code = stdout.channel.recv_exit_status()

        result = CommandResult(
            stdout=out,
            stderr=err,
            exit_code=code,
            success=code == 0
        )

        if not result.success:
            self.logger.warning(f"Command failed: {command} (code={code})")

        return result

    def sudo(self, command: str, password: str = None) -> CommandResult:
        """Exécute une commande avec sudo."""
        pwd = password or self.password
        if not pwd:
            raise ValueError("Password required for sudo")

        sudo_cmd = f"echo {pwd} | sudo -S {command}"
        return self.run(sudo_cmd)

    def get_sftp(self):
        """Retourne une session SFTP."""
        if not self.sftp:
            self.sftp = self.client.open_sftp()
        return self.sftp

    def upload(self, local_path: str, remote_path: str):
        """Upload un fichier."""
        sftp = self.get_sftp()
        self.logger.info(f"Uploading {local_path} -> {remote_path}")
        sftp.put(local_path, remote_path)

    def download(self, remote_path: str, local_path: str):
        """Download un fichier."""
        sftp = self.get_sftp()
        self.logger.info(f"Downloading {remote_path} -> {local_path}")
        sftp.get(remote_path, local_path)

    def read_file(self, remote_path: str) -> str:
        """Lit le contenu d'un fichier distant."""
        sftp = self.get_sftp()
        with sftp.open(remote_path, "r") as f:
            return f.read().decode("utf-8")

    def write_file(self, remote_path: str, content: str):
        """Écrit du contenu dans un fichier distant."""
        sftp = self.get_sftp()
        with sftp.open(remote_path, "w") as f:
            f.write(content)

# Utilisation
with SSHClient("192.168.1.100", "admin", password="secret") as ssh:
    # Exécuter des commandes
    result = ssh.run("uptime")
    print(result.stdout)

    # Avec sudo
    result = ssh.sudo("systemctl status nginx")

    # Transfert de fichiers
    ssh.upload("config.yml", "/etc/myapp/config.yml")
```

---

## 6. Gestion Multi-Serveurs

### Exécution Parallèle

```python
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class ServerConfig:
    hostname: str
    username: str
    password: str = None
    key_file: str = None

@dataclass
class ServerResult:
    hostname: str
    success: bool
    output: str
    error: str = None

def run_on_server(server: ServerConfig, command: str) -> ServerResult:
    """Exécute une commande sur un serveur."""
    try:
        with SSHClient(
            server.hostname,
            server.username,
            password=server.password,
            key_file=server.key_file
        ) as ssh:
            result = ssh.run(command)
            return ServerResult(
                hostname=server.hostname,
                success=result.success,
                output=result.stdout,
                error=result.stderr if not result.success else None
            )
    except Exception as e:
        return ServerResult(
            hostname=server.hostname,
            success=False,
            output="",
            error=str(e)
        )

def run_parallel(servers: List[ServerConfig], command: str, max_workers: int = 10) -> List[ServerResult]:
    """Exécute une commande sur plusieurs serveurs en parallèle."""
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(run_on_server, server, command): server
            for server in servers
        }

        for future in as_completed(futures):
            result = future.result()
            results.append(result)
            status = "✓" if result.success else "✗"
            print(f"{status} {result.hostname}")

    return results

# Utilisation
servers = [
    ServerConfig("web01.example.com", "admin", key_file="~/.ssh/id_rsa"),
    ServerConfig("web02.example.com", "admin", key_file="~/.ssh/id_rsa"),
    ServerConfig("db01.example.com", "admin", key_file="~/.ssh/id_rsa"),
]

results = run_parallel(servers, "uptime")

for r in results:
    print(f"\n{r.hostname}:")
    if r.success:
        print(r.output)
    else:
        print(f"Error: {r.error}")
```

### Gestionnaire de Serveurs

```python
import yaml
from pathlib import Path

class ServerManager:
    """Gestionnaire de flotte de serveurs."""

    def __init__(self, inventory_file: str = "inventory.yml"):
        self.servers = self._load_inventory(inventory_file)

    def _load_inventory(self, path: str) -> Dict[str, List[ServerConfig]]:
        """Charge l'inventaire depuis un fichier YAML."""
        with open(path) as f:
            data = yaml.safe_load(f)

        inventory = {}
        for group, hosts in data.get("groups", {}).items():
            inventory[group] = [
                ServerConfig(
                    hostname=h["host"],
                    username=h.get("user", "admin"),
                    key_file=h.get("key_file")
                )
                for h in hosts
            ]

        return inventory

    def get_group(self, group: str) -> List[ServerConfig]:
        """Retourne les serveurs d'un groupe."""
        return self.servers.get(group, [])

    def run_on_group(self, group: str, command: str) -> List[ServerResult]:
        """Exécute une commande sur un groupe de serveurs."""
        servers = self.get_group(group)
        return run_parallel(servers, command)

    def deploy_file(self, group: str, local_path: str, remote_path: str):
        """Déploie un fichier sur un groupe de serveurs."""
        def deploy(server):
            try:
                with SSHClient(server.hostname, server.username,
                              key_file=server.key_file) as ssh:
                    ssh.upload(local_path, remote_path)
                    return ServerResult(server.hostname, True, "Deployed")
            except Exception as e:
                return ServerResult(server.hostname, False, "", str(e))

        servers = self.get_group(group)
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(deploy, servers))

        return results

# Fichier inventory.yml:
# groups:
#   webservers:
#     - host: web01.example.com
#       user: deploy
#       key_file: ~/.ssh/deploy_key
#     - host: web02.example.com
#       user: deploy
#   databases:
#     - host: db01.example.com
#       user: admin

# Utilisation
manager = ServerManager("inventory.yml")
results = manager.run_on_group("webservers", "systemctl status nginx")
manager.deploy_file("webservers", "app.conf", "/etc/nginx/sites-enabled/app.conf")
```

---

## 7. Tunneling SSH

### Port Forwarding Local

```python
import paramiko
from sshtunnel import SSHTunnelForwarder

# Avec sshtunnel (pip install sshtunnel)
with SSHTunnelForwarder(
    ("jumpbox.example.com", 22),
    ssh_username="admin",
    ssh_pkey="~/.ssh/id_rsa",
    remote_bind_address=("db.internal", 3306),
    local_bind_address=("127.0.0.1", 3307)
) as tunnel:
    print(f"Tunnel ouvert: localhost:{tunnel.local_bind_port} -> db.internal:3306")
    # Utiliser la connexion tunnelisée
    # mysql -h 127.0.0.1 -P 3307 -u user -p

# Tunnel vers plusieurs ports
with SSHTunnelForwarder(
    ("jumpbox.example.com", 22),
    ssh_username="admin",
    ssh_pkey="~/.ssh/id_rsa",
    remote_bind_addresses=[
        ("db.internal", 3306),
        ("redis.internal", 6379)
    ]
) as tunnel:
    print(f"MySQL: localhost:{tunnel.local_bind_ports[0]}")
    print(f"Redis: localhost:{tunnel.local_bind_ports[1]}")
```

### Jump Host (Bastion)

```python
import paramiko

def connect_via_jump(jump_host, target_host, username, key_file):
    """Connexion via un jump host."""
    # Connexion au jump host
    jump_client = paramiko.SSHClient()
    jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    jump_client.connect(
        jump_host,
        username=username,
        key_filename=key_file
    )

    # Créer un canal vers le serveur cible
    jump_transport = jump_client.get_transport()
    dest_addr = (target_host, 22)
    local_addr = ("127.0.0.1", 0)

    channel = jump_transport.open_channel(
        "direct-tcpip",
        dest_addr,
        local_addr
    )

    # Connexion au serveur cible via le canal
    target_client = paramiko.SSHClient()
    target_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    target_client.connect(
        target_host,
        username=username,
        key_filename=key_file,
        sock=channel
    )

    return target_client, jump_client

# Utilisation
target, jump = connect_via_jump(
    "bastion.example.com",
    "internal-server.local",
    "admin",
    "~/.ssh/id_rsa"
)

stdin, stdout, stderr = target.exec_command("hostname")
print(stdout.read().decode())

target.close()
jump.close()
```

---

## Exercices Pratiques

### Exercice 1 : Health Check Distribué

```python
# Créer un script qui :
# - Se connecte à plusieurs serveurs en parallèle
# - Collecte CPU, mémoire, espace disque
# - Génère un rapport HTML
```

### Exercice 2 : Déploiement Automatisé

```python
# Créer un script de déploiement qui :
# - Upload les fichiers d'application
# - Exécute les migrations
# - Redémarre les services
# - Vérifie la santé de l'application
```

### Exercice 3 : Backup Centralisé

```python
# Créer un script qui :
# - Se connecte à plusieurs serveurs
# - Crée des backups (tar.gz)
# - Les télécharge vers un serveur central
# - Nettoie les anciens backups
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Utiliser les clés SSH plutôt que les mots de passe
    - Toujours fermer les connexions proprement
    - Gérer les timeouts
    - Logger les opérations
    - Utiliser l'agent SSH quand possible

!!! warning "Sécurité"
    - Ne jamais utiliser `AutoAddPolicy` en production
    - Vérifier les empreintes des clés host
    - Ne pas stocker les mots de passe en clair
    - Utiliser des clés SSH avec passphrase

---

## Voir Aussi

- [Module 11 - APIs REST](11-api-rest.md)
- [Module 13 - Outils CLI](13-cli.md)
- [Cheatsheet Bibliothèques](cheatsheet-libs.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 11 - APIs REST & HTTP](11-api-rest.md) | [Module 13 - Création d'Outils CLI →](13-cli.md) |

[Retour au Programme](index.md){ .md-button }
