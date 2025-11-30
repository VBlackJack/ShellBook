---
tags:
  - formation
  - python
  - subprocess
  - système
---

# Module 07 - Sous-processus & Commandes Système

Exécuter des commandes système et interagir avec le shell.

---

## Objectifs du Module

- Exécuter des commandes avec subprocess
- Capturer et traiter les sorties
- Gérer les erreurs et timeouts
- Utiliser os et shutil pour les opérations système

---

## 1. subprocess.run() - Méthode Moderne

### Exécution Simple

```python
import subprocess

# Commande simple
result = subprocess.run(["ls", "-la"])
print(f"Return code: {result.returncode}")

# Avec capture de sortie
result = subprocess.run(
    ["ls", "-la", "/var/log"],
    capture_output=True,
    text=True  # Decode en string (sinon bytes)
)

print(result.stdout)
print(result.stderr)
print(result.returncode)
```

### Options Importantes

```python
import subprocess

# capture_output=True équivaut à :
result = subprocess.run(
    ["command"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Fusionner stderr dans stdout
result = subprocess.run(
    ["command"],
    capture_output=True,
    text=True,
    stderr=subprocess.STDOUT
)

# Timeout (en secondes)
try:
    result = subprocess.run(
        ["sleep", "10"],
        timeout=5
    )
except subprocess.TimeoutExpired:
    print("Command timed out!")

# Vérifier le code retour (exception si != 0)
try:
    result = subprocess.run(
        ["grep", "pattern", "/nonexistent"],
        check=True,
        capture_output=True,
        text=True
    )
except subprocess.CalledProcessError as e:
    print(f"Command failed with code {e.returncode}")
    print(f"stderr: {e.stderr}")
```

### Exécution avec Shell

```python
# Sans shell (plus sûr, recommandé)
result = subprocess.run(["ls", "-la"], capture_output=True, text=True)

# Avec shell (nécessaire pour pipes, wildcards, etc.)
result = subprocess.run(
    "ls -la | grep .py | wc -l",
    shell=True,
    capture_output=True,
    text=True
)

# ⚠️ DANGER : Injection de commandes avec shell=True
user_input = "file.txt; rm -rf /"  # Malicieux!
# NE JAMAIS FAIRE :
subprocess.run(f"cat {user_input}", shell=True)

# Sécurisé : utiliser shlex.quote ou liste d'arguments
import shlex
subprocess.run(f"cat {shlex.quote(user_input)}", shell=True)
# Ou mieux : sans shell
subprocess.run(["cat", user_input])
```

### Répertoire de Travail et Environnement

```python
import subprocess
import os

# Changer le répertoire de travail
result = subprocess.run(
    ["ls"],
    cwd="/var/log",
    capture_output=True,
    text=True
)

# Variables d'environnement personnalisées
my_env = os.environ.copy()
my_env["MY_VAR"] = "value"
my_env["PATH"] = f"/custom/bin:{my_env['PATH']}"

result = subprocess.run(
    ["my_script.sh"],
    env=my_env,
    capture_output=True,
    text=True
)

# Ou ajouter uniquement quelques variables
result = subprocess.run(
    ["printenv", "MY_VAR"],
    env={**os.environ, "MY_VAR": "value"},
    capture_output=True,
    text=True
)
```

---

## 2. Entrée Standard (stdin)

```python
import subprocess

# Passer des données en entrée
result = subprocess.run(
    ["grep", "error"],
    input="line1\nerror line\nline3\n",
    capture_output=True,
    text=True
)
print(result.stdout)  # "error line\n"

# Depuis une variable
log_content = open("/var/log/messages").read()
result = subprocess.run(
    ["grep", "-c", "ERROR"],
    input=log_content,
    capture_output=True,
    text=True
)

# Depuis un fichier
with open("/var/log/messages") as f:
    result = subprocess.run(
        ["grep", "ERROR"],
        stdin=f,
        capture_output=True,
        text=True
    )
```

---

## 3. Popen - Contrôle Avancé

### Exécution Asynchrone

```python
import subprocess
import time

# Lancer un processus en arrière-plan
process = subprocess.Popen(
    ["long_running_command"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Vérifier si terminé
while process.poll() is None:
    print("Still running...")
    time.sleep(1)

# Récupérer la sortie
stdout, stderr = process.communicate()
print(f"Exit code: {process.returncode}")
```

### Lecture en Temps Réel

```python
import subprocess

# Lire la sortie ligne par ligne
process = subprocess.Popen(
    ["tail", "-f", "/var/log/messages"],
    stdout=subprocess.PIPE,
    text=True
)

try:
    for line in process.stdout:
        print(f"LOG: {line.strip()}")
        if "CRITICAL" in line:
            break
finally:
    process.terminate()
    process.wait()
```

### Pipes entre Processus

```python
import subprocess

# ps aux | grep python | wc -l
ps = subprocess.Popen(
    ["ps", "aux"],
    stdout=subprocess.PIPE
)

grep = subprocess.Popen(
    ["grep", "python"],
    stdin=ps.stdout,
    stdout=subprocess.PIPE
)

wc = subprocess.Popen(
    ["wc", "-l"],
    stdin=grep.stdout,
    stdout=subprocess.PIPE,
    text=True
)

ps.stdout.close()
grep.stdout.close()

output = wc.communicate()[0]
print(f"Python processes: {output.strip()}")
```

---

## 4. Module os - Opérations Système

### Variables d'Environnement

```python
import os

# Lire
home = os.getenv("HOME")
user = os.environ.get("USER", "unknown")
path = os.environ["PATH"]

# Modifier (pour le processus courant)
os.environ["MY_APP_DEBUG"] = "true"

# Supprimer
del os.environ["MY_APP_DEBUG"]

# Lister toutes les variables
for key, value in os.environ.items():
    print(f"{key}={value}")
```

### Informations Système

```python
import os

# Répertoires
os.getcwd()              # Répertoire courant
os.chdir("/tmp")         # Changer de répertoire

# Utilisateur
os.getuid()              # User ID
os.getgid()              # Group ID
os.getlogin()            # Nom de login

# Système
os.uname()               # Info système (Linux)
os.cpu_count()           # Nombre de CPUs
os.getpid()              # PID du processus
os.getppid()             # PID du parent
```

### Opérations sur Fichiers/Répertoires

```python
import os

# Test d'existence
os.path.exists("/var/log")
os.path.isfile("/etc/passwd")
os.path.isdir("/var/log")
os.path.islink("/usr/bin/python")

# Création
os.mkdir("/tmp/mydir")
os.makedirs("/tmp/a/b/c", exist_ok=True)

# Suppression
os.remove("/tmp/file.txt")          # Fichier
os.rmdir("/tmp/empty_dir")          # Dossier vide

# Renommage
os.rename("/tmp/old.txt", "/tmp/new.txt")

# Listing
os.listdir("/var/log")              # Liste des fichiers

# Parcours récursif
for root, dirs, files in os.walk("/var/log"):
    for file in files:
        filepath = os.path.join(root, file)
        print(filepath)
```

---

## 5. Module shutil - Opérations de Haut Niveau

```python
import shutil

# Copie de fichiers
shutil.copy("/src/file.txt", "/dst/file.txt")       # Copie fichier
shutil.copy2("/src/file.txt", "/dst/")              # Préserve métadonnées

# Copie de répertoires
shutil.copytree("/src/dir", "/dst/dir")
shutil.copytree("/src", "/dst", dirs_exist_ok=True)  # Python 3.8+

# Déplacement
shutil.move("/src/file.txt", "/dst/file.txt")

# Suppression récursive
shutil.rmtree("/tmp/mydir")
shutil.rmtree("/tmp/mydir", ignore_errors=True)

# Archive
shutil.make_archive("/tmp/backup", "zip", "/data")
shutil.make_archive("/tmp/backup", "gztar", "/data")
shutil.unpack_archive("/tmp/backup.zip", "/restore")

# Espace disque
total, used, free = shutil.disk_usage("/")
print(f"Total: {total // (1024**3)} GB")
print(f"Free: {free // (1024**3)} GB")

# Trouver un exécutable
shutil.which("python3")  # /usr/bin/python3
```

---

## 6. Cas d'Usage SysOps

### Wrapper de Commandes

```python
import subprocess
from dataclasses import dataclass
from typing import Optional

@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str
    success: bool

def run_command(
    cmd: list,
    timeout: int = 60,
    cwd: Optional[str] = None
) -> CommandResult:
    """Exécute une commande et retourne un résultat structuré."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        return CommandResult(
            command=" ".join(cmd),
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            success=result.returncode == 0
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=" ".join(cmd),
            returncode=-1,
            stdout="",
            stderr="Command timed out",
            success=False
        )

# Usage
result = run_command(["systemctl", "status", "nginx"])
if result.success:
    print("Nginx is running")
else:
    print(f"Error: {result.stderr}")
```

### Service Manager

```python
import subprocess

class ServiceManager:
    """Gestionnaire de services systemd."""

    def __init__(self, service_name: str):
        self.service = service_name

    def _run_systemctl(self, action: str) -> tuple:
        result = subprocess.run(
            ["systemctl", action, self.service],
            capture_output=True,
            text=True
        )
        return result.returncode == 0, result.stderr

    def start(self) -> bool:
        success, _ = self._run_systemctl("start")
        return success

    def stop(self) -> bool:
        success, _ = self._run_systemctl("stop")
        return success

    def restart(self) -> bool:
        success, _ = self._run_systemctl("restart")
        return success

    def status(self) -> dict:
        result = subprocess.run(
            ["systemctl", "is-active", self.service],
            capture_output=True,
            text=True
        )
        is_active = result.stdout.strip() == "active"

        result = subprocess.run(
            ["systemctl", "is-enabled", self.service],
            capture_output=True,
            text=True
        )
        is_enabled = result.stdout.strip() == "enabled"

        return {
            "name": self.service,
            "active": is_active,
            "enabled": is_enabled
        }

# Usage
nginx = ServiceManager("nginx")
print(nginx.status())
nginx.restart()
```

---

## Exercices Pratiques

### Exercice 1 : Health Checker

```python
# Créer un script qui :
# - Vérifie si des services sont actifs (systemctl)
# - Vérifie l'espace disque (df)
# - Vérifie la charge système (uptime)
# - Retourne un rapport JSON
```

### Exercice 2 : Backup Script

```python
# Créer un script de backup qui :
# - Utilise tar pour créer une archive
# - Gère les erreurs et timeouts
# - Affiche la progression
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Toujours utiliser `subprocess.run()` plutôt que `os.system()`
    - Éviter `shell=True` quand possible
    - Toujours capturer stderr
    - Utiliser des timeouts
    - Vérifier les codes de retour

!!! warning "Sécurité"
    ```python
    # DANGEREUX - Injection possible
    subprocess.run(f"cat {user_input}", shell=True)

    # SÛR - Liste d'arguments
    subprocess.run(["cat", user_input])
    ```

---

## Voir Aussi

- [Module 08 - Expressions Régulières](08-regex.md)
- [Module 12 - SSH & Automatisation](12-ssh.md)
