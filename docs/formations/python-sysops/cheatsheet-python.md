---
tags:
  - formation
  - python
  - cheatsheet
---

# Cheatsheet Python

Aide-mémoire syntaxe et patterns Python.

---

## Types de Base

```python
# Nombres
x = 42              # int
x = 3.14            # float
x = 1_000_000       # Séparateur lisibilité

# Chaînes
s = "hello"
s = 'hello'
s = """multiline"""
s = f"Hello {name}"  # f-string

# Booléens
b = True
b = False

# None
x = None
```

---

## Structures de Données

```python
# Liste (mutable, ordonné)
l = [1, 2, 3]
l.append(4)
l[0]                # Premier élément
l[-1]               # Dernier élément
l[1:3]              # Slice

# Tuple (immutable, ordonné)
t = (1, 2, 3)
x, y, z = t         # Unpacking

# Dictionnaire
d = {"key": "value"}
d["key"]            # Accès
d.get("key", "default")
d.keys()
d.values()
d.items()

# Set (unique, non ordonné)
s = {1, 2, 3}
s.add(4)
s1 | s2             # Union
s1 & s2             # Intersection
```

---

## Compréhensions

```python
# Liste
[x*2 for x in range(10)]
[x for x in items if x > 0]

# Dict
{k: v*2 for k, v in d.items()}

# Set
{x.lower() for x in names}

# Generator
(x*2 for x in range(10))
```

---

## Contrôle de Flux

```python
# Conditions
if x > 0:
    pass
elif x < 0:
    pass
else:
    pass

# Ternaire
value = "yes" if condition else "no"

# Boucle for
for item in items:
    pass

for i, item in enumerate(items):
    pass

for key, value in dict.items():
    pass

# Boucle while
while condition:
    pass
```

---

## Fonctions

```python
# Définition
def func(arg1, arg2="default"):
    """Docstring."""
    return result

# Args variables
def func(*args, **kwargs):
    pass

# Lambda
f = lambda x: x * 2

# Décorateur
@decorator
def func():
    pass
```

---

## Classes

```python
class Server:
    """Un serveur."""

    def __init__(self, hostname, ip):
        self.hostname = hostname
        self.ip = ip

    def __str__(self):
        return f"{self.hostname} ({self.ip})"

    def ping(self):
        return True

# Héritage
class WebServer(Server):
    def __init__(self, hostname, ip, port=80):
        super().__init__(hostname, ip)
        self.port = port
```

---

## Fichiers

```python
# Lecture
with open("file.txt") as f:
    content = f.read()
    lines = f.readlines()

# Écriture
with open("file.txt", "w") as f:
    f.write("content")

# pathlib
from pathlib import Path
p = Path("/var/log")
p.exists()
p.is_file()
p.read_text()
p.write_text("content")
list(p.glob("*.log"))
```

---

## Exceptions

```python
try:
    result = risky_operation()
except ValueError as e:
    print(f"Error: {e}")
except (TypeError, KeyError):
    pass
except Exception as e:
    raise
else:
    print("Success")
finally:
    cleanup()

# Lever une exception
raise ValueError("Invalid input")
```

---

## Modules Utiles

```python
import os
import sys
import json
import yaml
import re
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from collections import Counter, defaultdict

# os
os.getenv("HOME")
os.getcwd()
os.listdir(".")

# sys
sys.argv          # Arguments CLI
sys.exit(1)       # Quitter

# datetime
now = datetime.now()
now.strftime("%Y-%m-%d %H:%M:%S")
datetime.fromisoformat("2024-01-15")

# subprocess
result = subprocess.run(["ls", "-la"], capture_output=True, text=True)
result.stdout
result.returncode
```

---

## Patterns Courants

```python
# Valeur par défaut
value = x or "default"

# Swap
a, b = b, a

# Aplatir une liste
flat = [item for sublist in nested for item in sublist]

# Grouper par clé
from collections import defaultdict
groups = defaultdict(list)
for item in items:
    groups[item["key"]].append(item)

# Compteur
from collections import Counter
counts = Counter(items)
counts.most_common(10)

# Context manager
from contextlib import contextmanager

@contextmanager
def timer():
    start = time.time()
    yield
    print(f"Elapsed: {time.time() - start}")
```

---

## Voir Aussi

- [Cheatsheet Libs SysOps](cheatsheet-libs.md)
- [Programme de la formation](index.md)
