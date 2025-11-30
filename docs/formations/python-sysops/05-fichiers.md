---
tags:
  - formation
  - python
  - fichiers
  - pathlib
---

# Module 05 - Fichiers & I/O

Manipuler des fichiers et répertoires avec Python.

---

## Objectifs du Module

- Lire et écrire des fichiers texte et binaires
- Utiliser pathlib pour la manipulation de chemins
- Maîtriser les context managers
- Gérer les permissions et métadonnées

---

## 1. Lecture de Fichiers

### Méthode Traditionnelle

```python
# Lecture complète
file = open("/var/log/messages", "r")
content = file.read()
file.close()

# Avec context manager (recommandé)
with open("/var/log/messages", "r") as file:
    content = file.read()
# Fichier automatiquement fermé

# Lecture ligne par ligne
with open("/var/log/messages", "r") as file:
    for line in file:
        print(line.strip())

# Lecture en liste de lignes
with open("/var/log/messages", "r") as file:
    lines = file.readlines()

# Lecture avec limite
with open("/var/log/messages", "r") as file:
    first_100_chars = file.read(100)
    next_line = file.readline()
```

### Modes d'Ouverture

| Mode | Description |
|------|-------------|
| `r` | Lecture (défaut) |
| `w` | Écriture (écrase) |
| `a` | Ajout (append) |
| `x` | Création exclusive |
| `b` | Mode binaire |
| `t` | Mode texte (défaut) |
| `+` | Lecture et écriture |

```python
# Exemples
open("file.txt", "r")    # Lecture texte
open("file.txt", "w")    # Écriture texte (écrase)
open("file.txt", "a")    # Ajout texte
open("file.bin", "rb")   # Lecture binaire
open("file.bin", "wb")   # Écriture binaire
open("file.txt", "r+")   # Lecture et écriture
```

### Encodage

```python
# Spécifier l'encodage
with open("file.txt", "r", encoding="utf-8") as f:
    content = f.read()

# Gérer les erreurs d'encodage
with open("file.txt", "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

# errors="replace" remplace les caractères invalides par ?
# errors="strict" lève une exception (défaut)
```

---

## 2. Écriture de Fichiers

### Écriture Texte

```python
# Écriture simple
with open("output.txt", "w") as f:
    f.write("Hello World\n")

# Écriture de plusieurs lignes
lines = ["line 1", "line 2", "line 3"]
with open("output.txt", "w") as f:
    for line in lines:
        f.write(line + "\n")

# writelines (pas de newline automatique)
with open("output.txt", "w") as f:
    f.writelines([line + "\n" for line in lines])

# print() vers fichier
with open("output.txt", "w") as f:
    print("Hello", "World", sep=", ", file=f)
```

### Ajout (Append)

```python
# Ajouter à un fichier existant
with open("log.txt", "a") as f:
    f.write(f"[{datetime.now()}] New entry\n")
```

### Fichiers Binaires

```python
# Lecture binaire
with open("image.png", "rb") as f:
    data = f.read()

# Écriture binaire
with open("copy.png", "wb") as f:
    f.write(data)
```

---

## 3. pathlib - Chemins Modernes

### Création de Chemins

```python
from pathlib import Path

# Chemins
home = Path.home()              # /home/user
cwd = Path.cwd()                # Répertoire courant
config = Path("/etc/nginx")
relative = Path("logs/app.log")

# Construction de chemins
log_file = config / "nginx.conf"  # /etc/nginx/nginx.conf
backup = Path("/backup") / "2024" / "01"

# Depuis une string
path = Path("/var/log/messages")
```

### Propriétés de Chemin

```python
path = Path("/var/log/nginx/access.log")

path.name           # 'access.log'
path.stem           # 'access'
path.suffix         # '.log'
path.suffixes       # ['.log']
path.parent         # Path('/var/log/nginx')
path.parents        # Tous les parents
path.parts          # ('/', 'var', 'log', 'nginx', 'access.log')
path.anchor         # '/'

# Chemin absolu
Path("logs").resolve()  # /home/user/project/logs
path.is_absolute()      # True

# Modification
path.with_name("error.log")    # /var/log/nginx/error.log
path.with_suffix(".bak")       # /var/log/nginx/access.bak
```

### Test d'Existence et Type

```python
path = Path("/var/log")

path.exists()       # True
path.is_file()      # False
path.is_dir()       # True
path.is_symlink()   # False
path.is_absolute()  # True
```

### Lecture/Écriture avec pathlib

```python
config_path = Path("/etc/myapp/config.txt")

# Lecture
content = config_path.read_text()
content = config_path.read_text(encoding="utf-8")
data = config_path.read_bytes()

# Écriture
config_path.write_text("key=value\n")
config_path.write_bytes(b"binary data")
```

### Navigation et Listing

```python
logs = Path("/var/log")

# Liste des fichiers/dossiers
list(logs.iterdir())

# Glob patterns
list(logs.glob("*.log"))           # Fichiers .log directs
list(logs.glob("**/*.log"))        # Récursif
list(logs.rglob("*.log"))          # Équivalent récursif

# Filtrer
log_files = [f for f in logs.iterdir() if f.is_file() and f.suffix == ".log"]
```

### Opérations sur Fichiers

```python
from pathlib import Path

src = Path("source.txt")
dst = Path("dest.txt")

# Création
Path("logs").mkdir(exist_ok=True)
Path("a/b/c").mkdir(parents=True, exist_ok=True)

# Suppression
Path("temp.txt").unlink(missing_ok=True)  # Supprime fichier
Path("empty_dir").rmdir()                  # Supprime dossier vide

# Renommage
src.rename(dst)

# Copie (nécessite shutil)
import shutil
shutil.copy(src, dst)
shutil.copytree(Path("src_dir"), Path("dst_dir"))
```

---

## 4. Métadonnées et Permissions

### Informations sur les Fichiers

```python
from pathlib import Path
import os
import stat

path = Path("/etc/passwd")

# Statistiques
stats = path.stat()
stats.st_size           # Taille en bytes
stats.st_mtime          # Modification time (timestamp)
stats.st_atime          # Access time
stats.st_ctime          # Change time (metadata)
stats.st_mode           # Permissions
stats.st_uid            # User ID
stats.st_gid            # Group ID

# Conversion du timestamp
from datetime import datetime
mtime = datetime.fromtimestamp(stats.st_mtime)
print(f"Modified: {mtime}")
```

### Permissions

```python
import os
import stat
from pathlib import Path

path = Path("script.sh")

# Lire les permissions
mode = path.stat().st_mode
is_readable = bool(mode & stat.S_IRUSR)
is_writable = bool(mode & stat.S_IWUSR)
is_executable = bool(mode & stat.S_IXUSR)

# Modifier les permissions
path.chmod(0o755)  # rwxr-xr-x
path.chmod(0o644)  # rw-r--r--

# Avec os
os.chmod("script.sh", stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
```

### Propriétaire

```python
import os
import pwd
import grp
from pathlib import Path

path = Path("/etc/passwd")
stats = path.stat()

# Obtenir le nom à partir de l'UID/GID
owner = pwd.getpwuid(stats.st_uid).pw_name
group = grp.getgrgid(stats.st_gid).gr_name

# Modifier le propriétaire (nécessite root)
os.chown("/path/to/file", uid, gid)
```

---

## 5. Fichiers Temporaires

```python
import tempfile
from pathlib import Path

# Fichier temporaire auto-supprimé
with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=True) as f:
    f.write("temporary content")
    f.flush()
    # Utiliser f.name pour le chemin
    print(f"Temp file: {f.name}")
# Fichier supprimé à la sortie du with

# Répertoire temporaire
with tempfile.TemporaryDirectory() as tmpdir:
    tmp_path = Path(tmpdir)
    (tmp_path / "file.txt").write_text("content")
    # Tout est supprimé à la sortie

# Créer sans auto-suppression
fd, path = tempfile.mkstemp(suffix=".log")
os.close(fd)
# N'oubliez pas de supprimer manuellement

# Obtenir le répertoire temp
tempfile.gettempdir()  # /tmp ou équivalent
```

---

## 6. Cas d'Usage SysOps

### Lecture de Logs

```python
from pathlib import Path
from collections import Counter

def analyze_nginx_log(log_path):
    """Analyse un log nginx."""
    status_codes = Counter()
    ips = Counter()

    with open(log_path) as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 9:
                ip = parts[0]
                status = parts[8]
                ips[ip] += 1
                status_codes[status] += 1

    return {
        "top_ips": ips.most_common(10),
        "status_codes": dict(status_codes)
    }
```

### Backup de Configuration

```python
from pathlib import Path
from datetime import datetime
import shutil

def backup_config(config_path, backup_dir="/backup/configs"):
    """Crée une sauvegarde horodatée d'un fichier de config."""
    config_path = Path(config_path)
    backup_dir = Path(backup_dir)

    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {config_path}")

    backup_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"{config_path.stem}_{timestamp}{config_path.suffix}"
    backup_path = backup_dir / backup_name

    shutil.copy2(config_path, backup_path)
    return backup_path

# Usage
backup_path = backup_config("/etc/nginx/nginx.conf")
print(f"Backup created: {backup_path}")
```

### Rotation de Logs

```python
from pathlib import Path

def rotate_logs(log_dir, pattern="*.log", keep=5):
    """Garde les N derniers fichiers de log."""
    log_dir = Path(log_dir)
    logs = sorted(log_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)

    for old_log in logs[keep:]:
        old_log.unlink()
        print(f"Deleted: {old_log}")
```

---

## Exercices Pratiques

### Exercice 1 : Lecteur de Config

```python
# Créer une fonction read_config(path) qui :
# - Lit un fichier clé=valeur
# - Ignore les lignes vides et commentaires (#)
# - Retourne un dictionnaire

# Fichier config.ini :
# host=localhost
# port=8080
# # Ceci est un commentaire
# debug=true
```

### Exercice 2 : Recherche de Fichiers

```python
# Créer une fonction find_large_files(directory, min_size_mb) qui :
# - Parcourt récursivement un répertoire
# - Retourne les fichiers plus grands que min_size_mb
# - Inclut le chemin, la taille et la date de modification
```

### Exercice 3 : Générateur de Rapport

```python
# Créer une fonction disk_report(directory) qui :
# - Liste tous les fichiers récursivement
# - Calcule la taille totale par extension
# - Génère un rapport dans un fichier
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Toujours utiliser `with` pour les fichiers
    - Préférer `pathlib` à `os.path`
    - Spécifier l'encodage explicitement
    - Gérer les fichiers absents avec `exist_ok`

!!! warning "Pièges Courants"
    - Oublier de fermer les fichiers
    - Chemins relatifs vs absolus
    - Encodage incorrect (UTF-8 vs Latin-1)
    - Permissions insuffisantes

---

## Voir Aussi

- [Module 06 - Formats de Données](06-formats.md)
- [Python Fichiers & Données](../../python/files-data.md)
