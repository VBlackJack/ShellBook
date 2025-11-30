---
tags:
  - formation
  - python
  - structures
  - collections
---

# Module 03 - Structures de Données

Maîtriser les collections Python essentielles pour le SysOps.

---

## Objectifs du Module

- Utiliser les listes, tuples, sets et dictionnaires
- Maîtriser les compréhensions
- Choisir la structure adaptée à chaque cas d'usage

---

## 1. Listes

### Création et Accès

```python
# Création
servers = ["web01", "web02", "db01"]
empty_list = []
mixed = [1, "hello", 3.14, True]

# Accès par index
servers[0]          # 'web01'
servers[-1]         # 'db01'
servers[1:3]        # ['web02', 'db01']

# Modification
servers[0] = "web-01"
servers[1:2] = ["web-02", "web-03"]  # Remplacement
```

### Méthodes de Liste

```python
servers = ["web01", "web02"]

# Ajout
servers.append("db01")           # Ajoute à la fin
servers.insert(0, "lb01")        # Insère à l'index 0
servers.extend(["cache01", "cache02"])  # Ajoute plusieurs éléments

# Suppression
servers.remove("web01")          # Supprime par valeur
del servers[0]                   # Supprime par index
last = servers.pop()             # Supprime et retourne le dernier
first = servers.pop(0)           # Supprime et retourne l'index 0
servers.clear()                  # Vide la liste

# Recherche
"web01" in servers               # True/False
servers.index("web01")           # Index de l'élément
servers.count("web01")           # Nombre d'occurrences

# Tri
numbers = [3, 1, 4, 1, 5]
numbers.sort()                   # Tri en place
numbers.sort(reverse=True)       # Tri décroissant
servers.sort(key=str.lower)      # Tri avec clé

sorted_list = sorted(numbers)    # Nouveau liste triée

# Autres
numbers.reverse()                # Inverse en place
copy = servers.copy()            # Copie superficielle
len(servers)                     # Longueur
```

### Opérations sur Listes

```python
list1 = [1, 2, 3]
list2 = [4, 5, 6]

# Concaténation
combined = list1 + list2         # [1, 2, 3, 4, 5, 6]

# Répétition
repeated = list1 * 3             # [1, 2, 3, 1, 2, 3, 1, 2, 3]

# Agrégations
numbers = [10, 20, 30, 40, 50]
sum(numbers)                     # 150
min(numbers)                     # 10
max(numbers)                     # 50
len(numbers)                     # 5
```

---

## 2. Tuples

### Caractéristiques

```python
# Tuples : immutables (non modifiables)
coordinates = (10, 20)
single = (42,)                   # Note la virgule !
from_list = tuple([1, 2, 3])

# Accès (comme les listes)
coordinates[0]                   # 10
coordinates[-1]                  # 20

# Impossible de modifier
coordinates[0] = 5               # TypeError!
```

### Utilisation des Tuples

```python
# Unpacking
x, y = coordinates
host, port = ("localhost", 8080)

# Swap
a, b = b, a

# Retour multiple de fonction
def get_server_info():
    return ("web01", "192.168.1.10", 80)

hostname, ip, port = get_server_info()

# Named tuples (meilleure lisibilité)
from collections import namedtuple

Server = namedtuple('Server', ['hostname', 'ip', 'port'])
server = Server("web01", "192.168.1.10", 80)

server.hostname         # 'web01'
server.ip               # '192.168.1.10'
server[2]               # 80
```

---

## 3. Dictionnaires

### Création et Accès

```python
# Création
server = {
    "hostname": "web01",
    "ip": "192.168.1.10",
    "port": 80,
    "active": True
}

empty_dict = {}
from_tuples = dict([("a", 1), ("b", 2)])
from_keys = dict.fromkeys(["host", "port"], None)

# Accès
server["hostname"]              # 'web01'
server.get("hostname")          # 'web01'
server.get("missing", "default")  # 'default' si clé absente
server["missing"]               # KeyError!

# Modification
server["hostname"] = "web-01"
server["environment"] = "prod"  # Nouvelle clé

# Suppression
del server["active"]
value = server.pop("port")      # Supprime et retourne
server.clear()                  # Vide le dict
```

### Méthodes de Dictionnaire

```python
config = {
    "host": "localhost",
    "port": 8080,
    "debug": True
}

# Clés, valeurs, items
config.keys()           # dict_keys(['host', 'port', 'debug'])
config.values()         # dict_values(['localhost', 8080, True])
config.items()          # dict_items([('host', 'localhost'), ...])

# Test d'appartenance
"host" in config        # True (teste les clés)
"localhost" in config.values()  # True

# Mise à jour
config.update({"port": 9090, "timeout": 30})

# Valeur par défaut avec setdefault
config.setdefault("retries", 3)  # Ajoute si absent

# Copie
config_copy = config.copy()
```

### Dictionnaires Imbriqués

```python
infrastructure = {
    "web": {
        "servers": ["web01", "web02"],
        "port": 80
    },
    "database": {
        "servers": ["db01"],
        "port": 5432,
        "credentials": {
            "user": "admin",
            "password": "secret"
        }
    }
}

# Accès imbriqué
infrastructure["database"]["port"]          # 5432
infrastructure["database"]["credentials"]["user"]  # 'admin'

# Accès sécurisé
infrastructure.get("cache", {}).get("port", 6379)  # 6379
```

---

## 4. Sets

### Caractéristiques

```python
# Sets : éléments uniques, non ordonnés
active_servers = {"web01", "web02", "db01"}
empty_set = set()                # Pas {} qui crée un dict!
from_list = set([1, 2, 2, 3, 3])  # {1, 2, 3}

# Ajout/Suppression
active_servers.add("cache01")
active_servers.discard("web01")  # Pas d'erreur si absent
active_servers.remove("web02")   # KeyError si absent
```

### Opérations Ensemblistes

```python
prod_servers = {"web01", "web02", "db01"}
dev_servers = {"web01", "dev01", "dev02"}

# Union
all_servers = prod_servers | dev_servers
all_servers = prod_servers.union(dev_servers)
# {'web01', 'web02', 'db01', 'dev01', 'dev02'}

# Intersection
common = prod_servers & dev_servers
common = prod_servers.intersection(dev_servers)
# {'web01'}

# Différence
prod_only = prod_servers - dev_servers
prod_only = prod_servers.difference(dev_servers)
# {'web02', 'db01'}

# Différence symétrique
exclusive = prod_servers ^ dev_servers
# {'web02', 'db01', 'dev01', 'dev02'}

# Sous-ensemble
{"web01"}.issubset(prod_servers)      # True
prod_servers.issuperset({"web01"})    # True
```

### Cas d'Usage Sets

```python
# Dédupliquer une liste
ips = ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.3"]
unique_ips = list(set(ips))

# Vérifier l'appartenance (plus rapide que liste)
allowed_ports = {22, 80, 443, 8080}
if port in allowed_ports:
    print("Port autorisé")

# Trouver les éléments communs
users_a = {"alice", "bob", "charlie"}
users_b = {"bob", "david", "eve"}
common_users = users_a & users_b  # {'bob'}
```

---

## 5. Compréhensions

### List Comprehensions

```python
# Syntaxe : [expression for item in iterable if condition]

# Simple
squares = [x**2 for x in range(10)]
# [0, 1, 4, 9, 16, 25, 36, 49, 64, 81]

# Avec condition
evens = [x for x in range(20) if x % 2 == 0]
# [0, 2, 4, 6, 8, 10, 12, 14, 16, 18]

# Avec transformation
servers = ["WEB01", "WEB02", "DB01"]
lower_servers = [s.lower() for s in servers]
# ['web01', 'web02', 'db01']

# Filtrer et transformer
web_servers = [s.lower() for s in servers if s.startswith("WEB")]
# ['web01', 'web02']

# Imbriqué (équivalent à boucles imbriquées)
matrix = [[1, 2], [3, 4], [5, 6]]
flat = [num for row in matrix for num in row]
# [1, 2, 3, 4, 5, 6]
```

### Dict Comprehensions

```python
# Syntaxe : {key: value for item in iterable if condition}

# Simple
squares_dict = {x: x**2 for x in range(5)}
# {0: 0, 1: 1, 2: 4, 3: 9, 4: 16}

# Inverser clé/valeur
original = {"a": 1, "b": 2, "c": 3}
inverted = {v: k for k, v in original.items()}
# {1: 'a', 2: 'b', 3: 'c'}

# Filtrer un dictionnaire
config = {"host": "localhost", "port": 8080, "debug": True, "verbose": False}
string_config = {k: v for k, v in config.items() if isinstance(v, str)}
# {'host': 'localhost'}

# Depuis deux listes
keys = ["host", "port", "timeout"]
values = ["localhost", 8080, 30]
config = {k: v for k, v in zip(keys, values)}
# {'host': 'localhost', 'port': 8080, 'timeout': 30}
```

### Set Comprehensions

```python
# Syntaxe : {expression for item in iterable if condition}

# Extraire les extensions uniques
files = ["app.py", "config.yaml", "main.py", "data.json", "test.py"]
extensions = {f.split(".")[-1] for f in files}
# {'py', 'yaml', 'json'}
```

### Generator Expressions

```python
# Syntaxe : (expression for item in iterable if condition)
# Plus économe en mémoire (lazy evaluation)

# Generator (parenthèses)
gen = (x**2 for x in range(1000000))

# Utilisation
next(gen)           # 0
next(gen)           # 1
sum(gen)            # Somme des carrés restants

# Avec fonctions
sum(x**2 for x in range(100))
any(s.startswith("web") for s in servers)
all(port > 0 for port in ports)
```

---

## 6. Choix de la Structure

### Tableau Comparatif

| Structure | Ordonné | Modifiable | Doublons | Cas d'usage |
|-----------|---------|------------|----------|-------------|
| `list` | Oui | Oui | Oui | Collection générale |
| `tuple` | Oui | Non | Oui | Données fixes, clés dict |
| `dict` | Oui* | Oui | Clés non | Mapping clé-valeur |
| `set` | Non | Oui | Non | Unicité, appartenance |

*Depuis Python 3.7+

### Quand Utiliser Quoi ?

```python
# LISTE : Collection ordonnée modifiable
servers = ["web01", "web02", "db01"]
log_entries = []
log_entries.append(entry)

# TUPLE : Données fixes, retours multiples
coordinates = (10, 20)
rgb = (255, 128, 0)
def get_bounds(): return (0, 100)

# DICTIONNAIRE : Association clé-valeur
config = {"host": "localhost", "port": 8080}
server_status = {"web01": "up", "db01": "down"}

# SET : Unicité et opérations ensemblistes
allowed_users = {"admin", "operator"}
active_sessions = set()
if user in allowed_users:
    active_sessions.add(session_id)
```

---

## Exercices Pratiques

### Exercice 1 : Gestion de Serveurs

```python
servers = [
    {"name": "web01", "ip": "10.0.0.1", "env": "prod", "role": "web"},
    {"name": "web02", "ip": "10.0.0.2", "env": "prod", "role": "web"},
    {"name": "db01", "ip": "10.0.0.10", "env": "prod", "role": "db"},
    {"name": "dev01", "ip": "10.0.1.1", "env": "dev", "role": "web"},
]

# 1. Extraire la liste des noms de serveurs
# 2. Créer un dict {nom: ip}
# 3. Filtrer les serveurs de prod
# 4. Grouper par rôle (dict de listes)
# 5. Extraire les environnements uniques (set)
```

### Exercice 2 : Analyse de Logs

```python
log_entries = [
    {"timestamp": "2024-01-15 10:00:00", "level": "INFO", "source": "nginx"},
    {"timestamp": "2024-01-15 10:00:01", "level": "ERROR", "source": "app"},
    {"timestamp": "2024-01-15 10:00:02", "level": "INFO", "source": "app"},
    {"timestamp": "2024-01-15 10:00:03", "level": "WARN", "source": "nginx"},
    {"timestamp": "2024-01-15 10:00:04", "level": "ERROR", "source": "db"},
]

# 1. Compter les entrées par niveau
# 2. Extraire les sources uniques
# 3. Filtrer les erreurs
# 4. Créer un résumé {source: [niveaux]}
```

### Exercice 3 : Compréhensions

```python
# Utiliser des compréhensions pour :

# 1. Générer les IPs 192.168.1.1 à 192.168.1.254
# 2. Créer un dict {port: service} pour les ports courants
ports_services = [(22, "ssh"), (80, "http"), (443, "https"), (3306, "mysql")]
# 3. Extraire les fichiers .py d'une liste de fichiers
# 4. Convertir une liste de tuples (host, port) en "host:port"
```

---

## Points Clés à Retenir

!!! success "Structures Python"
    - **Liste** : ordonnée, modifiable, `[]`
    - **Tuple** : ordonnée, immutable, `()`
    - **Dict** : clé-valeur, `{}`
    - **Set** : unique, non ordonné, `set()`

!!! tip "Compréhensions"
    ```python
    # Plus pythonique que les boucles
    # Liste
    [x*2 for x in range(10) if x % 2 == 0]

    # Dict
    {k: v*2 for k, v in data.items()}

    # Set
    {x.lower() for x in names}
    ```

---

## Voir Aussi

- [Module 04 - Fonctions](04-fonctions.md)
- [Python Fondamentaux](../../python/fundamentals.md)
