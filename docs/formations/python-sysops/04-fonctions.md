---
tags:
  - formation
  - python
  - fonctions
  - decorateurs
---

# Module 04 - Fonctions

Créer des fonctions modulaires et réutilisables.

---

## Objectifs du Module

- Définir et appeler des fonctions
- Maîtriser les arguments et valeurs de retour
- Comprendre les scopes et closures
- Utiliser les décorateurs

---

## 1. Définition de Fonctions

### Syntaxe de Base

```python
def greet(name):
    """Affiche un message de bienvenue."""
    print(f"Hello, {name}!")

# Appel
greet("SysOps")  # Hello, SysOps!
```

### Valeurs de Retour

```python
def add(a, b):
    """Additionne deux nombres."""
    return a + b

result = add(3, 5)  # 8

# Retour multiple (tuple)
def get_server_info(hostname):
    """Retourne les infos d'un serveur."""
    ip = "192.168.1.10"
    port = 22
    return ip, port  # Tuple implicite

ip, port = get_server_info("web01")

# Retour anticipé
def is_valid_port(port):
    """Vérifie si un port est valide."""
    if not isinstance(port, int):
        return False
    return 1 <= port <= 65535
```

### Docstrings

```python
def connect_server(hostname, port=22, timeout=30):
    """
    Établit une connexion SSH vers un serveur.

    Args:
        hostname: Le nom d'hôte ou l'adresse IP du serveur.
        port: Le port SSH (défaut: 22).
        timeout: Timeout de connexion en secondes (défaut: 30).

    Returns:
        SSHConnection: Objet de connexion SSH.

    Raises:
        ConnectionError: Si la connexion échoue.
        TimeoutError: Si le timeout est dépassé.

    Example:
        >>> conn = connect_server("web01", port=2222)
        >>> conn.execute("uptime")
    """
    pass

# Accéder à la docstring
print(connect_server.__doc__)
help(connect_server)
```

---

## 2. Arguments

### Arguments Positionnels et Nommés

```python
def create_user(username, password, admin=False, shell="/bin/bash"):
    """Crée un utilisateur système."""
    print(f"Creating {username}, admin={admin}, shell={shell}")

# Positionnels
create_user("john", "secret123")

# Nommés (keyword arguments)
create_user("john", "secret123", admin=True)
create_user("john", "secret123", shell="/bin/zsh", admin=True)

# Mélange (positionnels d'abord)
create_user("john", "secret123", True, "/bin/zsh")
```

### Valeurs par Défaut

```python
def connect(host, port=22, timeout=30, retries=3):
    """Connexion avec valeurs par défaut."""
    pass

# ⚠️ PIÈGE : Objets mutables par défaut
def add_server(name, servers=[]):  # MAUVAIS!
    servers.append(name)
    return servers

# Correct
def add_server(name, servers=None):
    if servers is None:
        servers = []
    servers.append(name)
    return servers
```

### *args et **kwargs

```python
# *args : arguments positionnels variables
def log_message(level, *messages):
    """Log plusieurs messages."""
    for msg in messages:
        print(f"[{level}] {msg}")

log_message("INFO", "Starting server", "Loading config", "Ready")

# **kwargs : arguments nommés variables
def create_config(**options):
    """Crée une configuration à partir d'options."""
    config = {"version": "1.0"}
    config.update(options)
    return config

config = create_config(host="localhost", port=8080, debug=True)
# {'version': '1.0', 'host': 'localhost', 'port': 8080, 'debug': True}

# Combinaison complète
def api_call(method, url, *path_params, headers=None, **query_params):
    """Appel API flexible."""
    print(f"{method} {url}")
    print(f"Path: {path_params}")
    print(f"Headers: {headers}")
    print(f"Query: {query_params}")

api_call("GET", "/users", "123", "posts", headers={"Auth": "token"}, limit=10)
```

### Unpacking d'Arguments

```python
def deploy(server, app, version):
    print(f"Deploying {app} v{version} to {server}")

# Unpacking de liste/tuple
params = ["web01", "myapp", "1.2.3"]
deploy(*params)  # Équivalent à deploy("web01", "myapp", "1.2.3")

# Unpacking de dictionnaire
config = {"server": "web01", "app": "myapp", "version": "1.2.3"}
deploy(**config)  # Équivalent à deploy(server="web01", app="myapp", version="1.2.3")
```

---

## 3. Scope et Closures

### Portée des Variables

```python
# Variable globale
config_file = "/etc/myapp.conf"

def load_config():
    # Variable locale
    local_var = "local"

    # Lecture de global OK
    print(config_file)

    # Modification de global nécessite 'global'
    global config_file
    config_file = "/etc/newapp.conf"

# Règle LEGB : Local → Enclosing → Global → Built-in
```

### Closures

```python
def create_logger(prefix):
    """Factory qui crée des fonctions de log."""
    def log(message):
        print(f"[{prefix}] {message}")
    return log

# Créer des loggers spécialisés
info_log = create_logger("INFO")
error_log = create_logger("ERROR")

info_log("Server started")   # [INFO] Server started
error_log("Connection lost") # [ERROR] Connection lost

# Closure avec état
def create_counter(start=0):
    """Crée un compteur."""
    count = start

    def increment():
        nonlocal count
        count += 1
        return count

    return increment

counter = create_counter(10)
print(counter())  # 11
print(counter())  # 12
```

---

## 4. Fonctions Lambda

### Syntaxe

```python
# Lambda : fonction anonyme sur une ligne
square = lambda x: x ** 2
square(5)  # 25

add = lambda a, b: a + b
add(3, 4)  # 7

# Équivalent à
def square(x):
    return x ** 2
```

### Cas d'Usage

```python
servers = [
    {"name": "web01", "priority": 3},
    {"name": "db01", "priority": 1},
    {"name": "cache01", "priority": 2},
]

# Tri avec key
servers.sort(key=lambda s: s["priority"])

# sorted() avec lambda
sorted_servers = sorted(servers, key=lambda s: s["name"])

# filter() avec lambda
high_priority = list(filter(lambda s: s["priority"] <= 2, servers))

# map() avec lambda
names = list(map(lambda s: s["name"].upper(), servers))

# Note : les compréhensions sont souvent plus lisibles
names = [s["name"].upper() for s in servers]
high_priority = [s for s in servers if s["priority"] <= 2]
```

---

## 5. Décorateurs

### Concept

```python
# Un décorateur est une fonction qui modifie une autre fonction

def my_decorator(func):
    def wrapper(*args, **kwargs):
        print("Before function call")
        result = func(*args, **kwargs)
        print("After function call")
        return result
    return wrapper

@my_decorator
def say_hello(name):
    print(f"Hello, {name}!")

say_hello("World")
# Before function call
# Hello, World!
# After function call
```

### Décorateurs Pratiques

```python
import time
import functools

# Timer
def timer(func):
    """Mesure le temps d'exécution."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = time.time()
        result = func(*args, **kwargs)
        elapsed = time.time() - start
        print(f"{func.__name__} took {elapsed:.4f}s")
        return result
    return wrapper

@timer
def slow_function():
    time.sleep(1)
    return "Done"

# Logger
def log_calls(func):
    """Log les appels de fonction."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__} with {args}, {kwargs}")
        result = func(*args, **kwargs)
        print(f"{func.__name__} returned {result}")
        return result
    return wrapper

@log_calls
def add(a, b):
    return a + b

# Retry
def retry(max_attempts=3, delay=1):
    """Réessaie une fonction en cas d'échec."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if attempt < max_attempts - 1:
                        print(f"Attempt {attempt + 1} failed: {e}")
                        time.sleep(delay)
                    else:
                        raise
        return wrapper
    return decorator

@retry(max_attempts=3, delay=2)
def fetch_data(url):
    # Peut échouer...
    pass
```

### Décorateurs avec Paramètres

```python
def require_auth(role="user"):
    """Vérifie l'authentification et le rôle."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                raise PermissionError("Not authenticated")
            if user.role != role and role != "user":
                raise PermissionError(f"Requires role: {role}")
            return func(*args, **kwargs)
        return wrapper
    return decorator

@require_auth(role="admin")
def delete_server(server_id):
    pass
```

---

## 6. Fonctions Built-in Utiles

```python
# map() - Appliquer une fonction à chaque élément
ports = [80, 443, 8080]
port_strings = list(map(str, ports))  # ['80', '443', '8080']

# filter() - Filtrer les éléments
numbers = [1, 2, 3, 4, 5, 6]
evens = list(filter(lambda x: x % 2 == 0, numbers))  # [2, 4, 6]

# zip() - Combiner des itérables
hosts = ["web01", "web02"]
ips = ["10.0.0.1", "10.0.0.2"]
pairs = list(zip(hosts, ips))  # [('web01', '10.0.0.1'), ('web02', '10.0.0.2')]
mapping = dict(zip(hosts, ips))  # {'web01': '10.0.0.1', 'web02': '10.0.0.2'}

# enumerate() - Index + valeur
for i, host in enumerate(hosts, start=1):
    print(f"{i}. {host}")

# any() / all()
statuses = [True, True, False]
any(statuses)  # True (au moins un True)
all(statuses)  # False (pas tous True)

# sorted() avec key
servers = ["web10", "web2", "web1"]
sorted(servers)  # ['web1', 'web10', 'web2']
sorted(servers, key=lambda s: int(s[3:]))  # ['web1', 'web2', 'web10']
```

---

## Exercices Pratiques

### Exercice 1 : Fonctions de Base

```python
# 1. Créer une fonction ping_server(host, count=4) qui simule un ping
# 2. Créer une fonction format_bytes(size) qui convertit en KB/MB/GB
# 3. Créer une fonction parse_log_line(line) qui retourne un dict

# format_bytes(1024) -> "1.00 KB"
# format_bytes(1048576) -> "1.00 MB"
```

### Exercice 2 : Décorateur

```python
# Créer un décorateur @cache qui mémorise les résultats

@cache
def expensive_dns_lookup(hostname):
    """Résolution DNS coûteuse."""
    time.sleep(2)  # Simule latence
    return f"192.168.1.{hash(hostname) % 255}"

# Premier appel : 2s
result1 = expensive_dns_lookup("web01")
# Deuxième appel : instantané (cache)
result2 = expensive_dns_lookup("web01")
```

### Exercice 3 : Factory de Validateurs

```python
# Créer une factory de validateurs

def create_validator(min_val=None, max_val=None, allowed=None):
    """Crée une fonction de validation."""
    # À implémenter
    pass

validate_port = create_validator(min_val=1, max_val=65535)
validate_env = create_validator(allowed=["dev", "staging", "prod"])

validate_port(8080)    # True
validate_port(70000)   # False
validate_env("prod")   # True
validate_env("test")   # False
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Documenter avec des docstrings
    - Éviter les effets de bord
    - Utiliser `functools.wraps` pour les décorateurs
    - Préférer les compréhensions aux map/filter

!!! warning "Pièges Courants"
    - Arguments mutables par défaut
    - Oublier `return` (retourne `None`)
    - Modifier des variables globales
    - Lambda trop complexes

---

## Voir Aussi

- [Module 05 - Fichiers & I/O](05-fichiers.md)
- [Python Fondamentaux](../../python/fundamentals.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 03 - Structures de Données](03-structures.md) | [Module 05 - Fichiers & I/O →](05-fichiers.md) |

[Retour au Programme](index.md){ .md-button }
