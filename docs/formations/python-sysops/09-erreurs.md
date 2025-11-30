---
tags:
  - formation
  - python
  - exceptions
  - logging
  - debugging
---

# Module 09 - Gestion des Erreurs & Logging

Gérer les erreurs proprement et implémenter une journalisation efficace.

---

## Objectifs du Module

- Comprendre le système d'exceptions Python
- Créer des exceptions personnalisées
- Implémenter un logging structuré
- Debugger efficacement

---

## 1. Exceptions Python

### Try/Except Basique

```python
# Gestion simple
try:
    result = 10 / 0
except ZeroDivisionError:
    print("Division par zéro!")

# Capturer plusieurs exceptions
try:
    value = int("abc")
except (ValueError, TypeError) as e:
    print(f"Erreur de conversion: {e}")

# Capturer toutes les exceptions (à éviter en général)
try:
    risky_operation()
except Exception as e:
    print(f"Erreur inattendue: {e}")
```

### Structure Complète

```python
try:
    file = open("/etc/passwd")
    content = file.read()
    data = process(content)
except FileNotFoundError:
    print("Fichier non trouvé")
except PermissionError:
    print("Permission refusée")
except Exception as e:
    print(f"Erreur: {e}")
else:
    # Exécuté si aucune exception
    print("Lecture réussie")
finally:
    # Toujours exécuté
    file.close()
```

### Lever des Exceptions

```python
def validate_port(port):
    """Valide un numéro de port."""
    if not isinstance(port, int):
        raise TypeError(f"Port doit être un entier, pas {type(port).__name__}")
    if not 1 <= port <= 65535:
        raise ValueError(f"Port {port} hors limites (1-65535)")
    return port

# Re-lever une exception
try:
    connect_to_server()
except ConnectionError:
    log_error("Connexion échouée")
    raise  # Re-lève l'exception originale

# Chaîner les exceptions
try:
    parse_config()
except ValueError as e:
    raise ConfigurationError("Config invalide") from e
```

### Hiérarchie des Exceptions

```python
# Exceptions courantes en SysOps
BaseException
├── SystemExit          # sys.exit()
├── KeyboardInterrupt   # Ctrl+C
└── Exception
    ├── StopIteration
    ├── OSError
    │   ├── FileNotFoundError
    │   ├── PermissionError
    │   ├── FileExistsError
    │   ├── IsADirectoryError
    │   ├── NotADirectoryError
    │   ├── ConnectionError
    │   │   ├── ConnectionRefusedError
    │   │   ├── ConnectionResetError
    │   │   └── ConnectionAbortedError
    │   └── TimeoutError
    ├── ValueError
    ├── TypeError
    ├── KeyError
    ├── IndexError
    ├── AttributeError
    └── RuntimeError
```

---

## 2. Exceptions Personnalisées

### Créer ses Exceptions

```python
class ServerError(Exception):
    """Exception de base pour les erreurs serveur."""
    pass

class ConnectionFailed(ServerError):
    """Impossible de se connecter au serveur."""
    def __init__(self, host, port, reason=None):
        self.host = host
        self.port = port
        self.reason = reason
        message = f"Connexion à {host}:{port} échouée"
        if reason:
            message += f": {reason}"
        super().__init__(message)

class AuthenticationError(ServerError):
    """Authentification échouée."""
    pass

class ConfigurationError(ServerError):
    """Erreur de configuration."""
    pass

# Utilisation
def connect(host, port):
    try:
        # tentative de connexion
        socket.connect((host, port))
    except socket.error as e:
        raise ConnectionFailed(host, port, str(e))

try:
    connect("192.168.1.100", 22)
except ConnectionFailed as e:
    print(f"Échec: {e}")
    print(f"Host: {e.host}, Port: {e.port}")
```

### Exceptions avec Contexte

```python
class CommandError(Exception):
    """Erreur d'exécution de commande."""
    def __init__(self, command, returncode, stdout="", stderr=""):
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        message = f"Commande '{command}' a échoué (code {returncode})"
        super().__init__(message)

def run_command(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise CommandError(
            command=" ".join(cmd),
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr
        )
    return result.stdout
```

---

## 3. Module logging

### Configuration de Base

```python
import logging

# Configuration simple
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger(__name__)

# Niveaux de log
logger.debug("Information de debug")      # 10
logger.info("Information générale")       # 20
logger.warning("Attention")               # 30
logger.error("Erreur")                    # 40
logger.critical("Erreur critique")        # 50
```

### Configuration Avancée

```python
import logging
import logging.handlers
import sys

def setup_logging(log_file="/var/log/myapp.log", level=logging.INFO):
    """Configure le système de logging."""

    # Créer le logger racine
    logger = logging.getLogger()
    logger.setLevel(level)

    # Formatter commun
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - "
        "[%(filename)s:%(lineno)d] - %(message)s"
    )

    # Handler console (stderr)
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # Handler fichier avec rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5,
        encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # Handler syslog (Linux)
    syslog_handler = logging.handlers.SysLogHandler(
        address="/dev/log",
        facility=logging.handlers.SysLogHandler.LOG_LOCAL0
    )
    syslog_handler.setLevel(logging.ERROR)
    logger.addHandler(syslog_handler)

    return logger

# Utilisation
logger = setup_logging()
logger.info("Application démarrée")
```

### Logging Structuré (JSON)

```python
import logging
import json
from datetime import datetime

class JSONFormatter(logging.Formatter):
    """Formatter pour logs en JSON."""

    def format(self, record):
        log_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }

        # Ajouter les extras
        if hasattr(record, "extra_data"):
            log_data.update(record.extra_data)

        # Ajouter l'exception si présente
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)

# Configuration
handler = logging.FileHandler("/var/log/myapp.json")
handler.setFormatter(JSONFormatter())

logger = logging.getLogger("myapp")
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Utilisation avec contexte
def log_with_context(logger, level, message, **context):
    """Log avec données contextuelles."""
    record = logger.makeRecord(
        logger.name, level, "", 0, message, (), None
    )
    record.extra_data = context
    logger.handle(record)

log_with_context(
    logger, logging.INFO,
    "Connexion établie",
    host="192.168.1.100",
    user="admin",
    duration_ms=150
)
```

### Logging par Module

```python
# main.py
import logging
from server import Server
from database import Database

logging.basicConfig(level=logging.DEBUG)

# Configurer les niveaux par module
logging.getLogger("server").setLevel(logging.INFO)
logging.getLogger("database").setLevel(logging.WARNING)

# server.py
import logging
logger = logging.getLogger(__name__)  # "server"

class Server:
    def start(self):
        logger.info("Serveur démarré")
        logger.debug("Configuration chargée")  # Ne s'affiche pas

# database.py
import logging
logger = logging.getLogger(__name__)  # "database"

class Database:
    def connect(self):
        logger.debug("Tentative connexion")   # Ne s'affiche pas
        logger.warning("Pool connexions bas")  # S'affiche
```

---

## 4. Context Managers pour les Erreurs

### Suppression Temporaire d'Erreurs

```python
from contextlib import suppress, contextmanager
import os

# Ignorer une exception spécifique
with suppress(FileNotFoundError):
    os.remove("/tmp/maybe_exists.txt")

# Équivalent de :
try:
    os.remove("/tmp/maybe_exists.txt")
except FileNotFoundError:
    pass
```

### Context Manager avec Logging

```python
import logging
from contextlib import contextmanager
import time

@contextmanager
def log_execution(operation_name, logger=None):
    """Log le début, la fin et les erreurs d'une opération."""
    if logger is None:
        logger = logging.getLogger(__name__)

    start = time.time()
    logger.info(f"Début: {operation_name}")

    try:
        yield
    except Exception as e:
        elapsed = time.time() - start
        logger.error(
            f"Échec: {operation_name} après {elapsed:.2f}s - {e}"
        )
        raise
    else:
        elapsed = time.time() - start
        logger.info(f"Fin: {operation_name} en {elapsed:.2f}s")

# Utilisation
with log_execution("Backup base de données"):
    backup_database()
```

### Retry avec Backoff

```python
import time
import logging
from functools import wraps

def retry(max_attempts=3, delay=1, backoff=2, exceptions=(Exception,)):
    """Décorateur pour réessayer une fonction en cas d'erreur."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(func.__module__)
            attempt = 0
            current_delay = delay

            while attempt < max_attempts:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    attempt += 1
                    if attempt == max_attempts:
                        logger.error(
                            f"{func.__name__} échoué après {max_attempts} tentatives"
                        )
                        raise

                    logger.warning(
                        f"{func.__name__} échoué (tentative {attempt}), "
                        f"retry dans {current_delay}s: {e}"
                    )
                    time.sleep(current_delay)
                    current_delay *= backoff

        return wrapper
    return decorator

# Utilisation
@retry(max_attempts=3, delay=1, backoff=2, exceptions=(ConnectionError,))
def connect_to_server(host, port):
    """Se connecte au serveur avec retry automatique."""
    # Code de connexion
    pass
```

---

## 5. Debugging

### Assertions

```python
def process_servers(servers):
    """Traite une liste de serveurs."""
    # Vérification de précondition
    assert servers, "La liste de serveurs ne peut pas être vide"
    assert all(isinstance(s, dict) for s in servers), "Format serveur invalide"

    for server in servers:
        assert "host" in server, f"Serveur sans host: {server}"
        process(server)

# Désactiver les assertions en production
# python -O script.py
```

### Module pdb

```python
import pdb

def complex_function():
    data = load_data()

    # Point d'arrêt
    pdb.set_trace()  # Python < 3.7
    breakpoint()      # Python 3.7+

    result = process(data)
    return result

# Commandes pdb
# n (next)      - Ligne suivante
# s (step)      - Entrer dans la fonction
# c (continue)  - Continuer jusqu'au prochain breakpoint
# p var         - Afficher la valeur de var
# pp var        - Pretty print var
# l (list)      - Afficher le code autour
# w (where)     - Afficher la stack trace
# q (quit)      - Quitter le debugger
```

### Traceback Détaillé

```python
import traceback
import sys

def log_exception():
    """Log l'exception courante avec le traceback complet."""
    exc_type, exc_value, exc_tb = sys.exc_info()

    # Traceback formaté
    tb_lines = traceback.format_exception(exc_type, exc_value, exc_tb)
    tb_text = "".join(tb_lines)

    logging.error(f"Exception:\n{tb_text}")

try:
    dangerous_operation()
except Exception:
    log_exception()
    raise

# Obtenir le traceback comme string
try:
    something()
except Exception:
    error_msg = traceback.format_exc()
    print(error_msg)
```

### Warnings

```python
import warnings

# Émettre un warning
warnings.warn("Cette fonction est dépréciée", DeprecationWarning)

# Contrôler l'affichage
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("error", category=UserWarning)  # Transforme en exception

# Context manager
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    deprecated_function()
```

---

## 6. Patterns SysOps

### Health Check avec Gestion d'Erreurs

```python
import logging
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum

class HealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"

@dataclass
class CheckResult:
    name: str
    status: HealthStatus
    message: str
    error: Optional[str] = None

def check_service(name: str, check_func) -> CheckResult:
    """Exécute un check de santé avec gestion d'erreurs."""
    logger = logging.getLogger("health")

    try:
        result = check_func()
        if result:
            return CheckResult(name, HealthStatus.HEALTHY, "OK")
        else:
            return CheckResult(name, HealthStatus.DEGRADED, "Check failed")
    except Exception as e:
        logger.exception(f"Health check {name} failed")
        return CheckResult(
            name,
            HealthStatus.UNHEALTHY,
            "Exception",
            error=str(e)
        )

def run_health_checks(checks: dict) -> List[CheckResult]:
    """Exécute tous les checks de santé."""
    results = []
    for name, check_func in checks.items():
        result = check_service(name, check_func)
        results.append(result)

    # Déterminer le status global
    if any(r.status == HealthStatus.UNHEALTHY for r in results):
        overall = HealthStatus.UNHEALTHY
    elif any(r.status == HealthStatus.DEGRADED for r in results):
        overall = HealthStatus.DEGRADED
    else:
        overall = HealthStatus.HEALTHY

    return results, overall

# Utilisation
checks = {
    "database": check_database,
    "redis": check_redis,
    "disk_space": check_disk_space,
}

results, status = run_health_checks(checks)
```

### Script avec Gestion Complète

```python
#!/usr/bin/env python3
"""Script de maintenance avec gestion d'erreurs complète."""

import logging
import sys
import argparse
from pathlib import Path

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler("/var/log/maintenance.log")
    ]
)
logger = logging.getLogger(__name__)

class MaintenanceError(Exception):
    """Erreur lors de la maintenance."""
    pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    args = parser.parse_args()

    exit_code = 0

    try:
        logger.info(f"Démarrage maintenance: {args.target}")
        perform_maintenance(args.target)
        logger.info("Maintenance terminée avec succès")

    except KeyboardInterrupt:
        logger.warning("Maintenance interrompue par l'utilisateur")
        exit_code = 130

    except MaintenanceError as e:
        logger.error(f"Erreur de maintenance: {e}")
        exit_code = 1

    except Exception as e:
        logger.exception("Erreur inattendue")
        exit_code = 2

    finally:
        cleanup()
        logger.info(f"Script terminé (code: {exit_code})")

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
```

---

## Exercices Pratiques

### Exercice 1 : Logger Configurable

```python
# Créer une fonction setup_app_logging() qui :
# - Accepte un niveau de log et un fichier de sortie
# - Configure la rotation automatique
# - Ajoute un handler console pour WARNING+
# - Retourne le logger configuré
```

### Exercice 2 : Retry Decorator

```python
# Améliorer le décorateur @retry pour :
# - Supporter un callback on_retry
# - Logger les tentatives
# - Supporter un timeout global
```

### Exercice 3 : Exception Hierarchy

```python
# Créer une hiérarchie d'exceptions pour un outil de déploiement :
# - DeploymentError (base)
# - ConfigurationError
# - ConnectionError
# - ValidationError
# - RollbackError
# Chaque exception doit avoir des attributs contextuels
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Capturer les exceptions les plus spécifiques
    - Toujours logger les exceptions avec le contexte
    - Utiliser des exceptions personnalisées pour la logique métier
    - Configurer le logging dès le démarrage de l'application

!!! warning "Pièges Courants"
    ```python
    # MAUVAIS - Capture trop large
    try:
        something()
    except:  # Capture même KeyboardInterrupt!
        pass

    # BON - Exception spécifique
    try:
        something()
    except ValueError as e:
        logger.error(f"Valeur invalide: {e}")
    ```

---

## Voir Aussi

- [Module 10 - Programmation Réseau](10-reseau.md)
- [Module 15 - Tests & Qualité](15-tests.md)
