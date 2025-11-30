---
tags:
  - formation
  - python
  - syntaxe
  - bases
---

# Module 02 - Syntaxe de Base

Maîtriser les fondamentaux de la syntaxe Python.

---

## Objectifs du Module

- Comprendre les types de données primitifs
- Utiliser les opérateurs
- Maîtriser les structures de contrôle
- Appliquer les conventions de nommage Python

---

## 1. Variables et Types

### Typage Dynamique

```python
# Python est typé dynamiquement
x = 42          # int
x = "hello"     # maintenant str
x = 3.14        # maintenant float

# Vérifier le type
type(x)         # <class 'float'>
isinstance(x, float)  # True
```

### Types Primitifs

```python
# Entiers (int) - pas de limite de taille
count = 100
big_number = 10_000_000_000  # Séparateurs pour lisibilité
binary = 0b1010              # 10 en binaire
hexa = 0xFF                  # 255 en hexadécimal

# Flottants (float)
pi = 3.14159
scientific = 1.5e-10

# Booléens (bool)
is_active = True
is_disabled = False

# None (absence de valeur)
result = None

# Chaînes de caractères (str)
name = "John"
name = 'John'           # Simple ou double quotes
multiline = """
Texte sur
plusieurs lignes
"""
```

### Conversions de Types

```python
# str -> int
port = int("8080")

# int -> str
port_str = str(8080)

# str -> float
ratio = float("0.75")

# int -> bool
bool(0)      # False
bool(1)      # True
bool(-1)     # True

# str -> bool
bool("")     # False
bool("any")  # True
```

---

## 2. Chaînes de Caractères

### Opérations de Base

```python
hostname = "web-server-01"

# Longueur
len(hostname)           # 13

# Accès par index
hostname[0]             # 'w'
hostname[-1]            # '1'

# Slicing
hostname[0:3]           # 'web'
hostname[:3]            # 'web'
hostname[4:]            # 'server-01'
hostname[::2]           # 'wbsre-1'
hostname[::-1]          # '10-revres-bew' (reverse)

# Concaténation
"web" + "-" + "01"      # 'web-01'
"-".join(["web", "server", "01"])  # 'web-server-01'

# Répétition
"=" * 50                # '=================================================='
```

### Méthodes Utiles

```python
text = "  Hello World  "

# Casse
text.upper()            # '  HELLO WORLD  '
text.lower()            # '  hello world  '
text.title()            # '  Hello World  '
text.capitalize()       # '  hello world  '

# Nettoyage
text.strip()            # 'Hello World'
text.lstrip()           # 'Hello World  '
text.rstrip()           # '  Hello World'

# Recherche
text.find("World")      # 8
text.count("l")         # 3
text.startswith("  H")  # True
text.endswith("  ")     # True
"World" in text         # True

# Remplacement
text.replace("World", "Python")  # '  Hello Python  '

# Découpage
"web-server-01".split("-")       # ['web', 'server', '01']
"line1\nline2".splitlines()      # ['line1', 'line2']
```

### F-strings (Formatage Moderne)

```python
hostname = "web01"
port = 8080
status = "running"

# F-string (Python 3.6+)
message = f"Server {hostname} on port {port} is {status}"

# Expressions dans f-strings
f"Port: {port}, Double: {port * 2}"

# Formatage
pi = 3.14159265
f"Pi = {pi:.2f}"                    # 'Pi = 3.14'
f"Hex: {255:x}"                     # 'Hex: ff'
f"Binary: {10:b}"                   # 'Binary: 1010'
f"Padding: {42:05d}"                # 'Padding: 00042'
f"Align: {hostname:>15}"            # 'Align:           web01'

# Debug (Python 3.8+)
f"{hostname=}"                      # "hostname='web01'"
```

---

## 3. Opérateurs

### Opérateurs Arithmétiques

```python
a, b = 17, 5

a + b       # 22 (addition)
a - b       # 12 (soustraction)
a * b       # 85 (multiplication)
a / b       # 3.4 (division)
a // b      # 3 (division entière)
a % b       # 2 (modulo)
a ** b      # 1419857 (puissance)

# Opérateurs d'assignation
x = 10
x += 5      # x = x + 5 = 15
x -= 3      # x = x - 3 = 12
x *= 2      # x = x * 2 = 24
x //= 5     # x = x // 5 = 4
```

### Opérateurs de Comparaison

```python
a, b = 10, 20

a == b      # False (égalité)
a != b      # True (différence)
a < b       # True
a > b       # False
a <= b      # True
a >= b      # False

# Comparaison d'identité
x = [1, 2]
y = [1, 2]
z = x

x == y      # True (même valeur)
x is y      # False (objets différents)
x is z      # True (même objet)

# Comparaison chaînée
5 < x < 15  # True si x entre 5 et 15
```

### Opérateurs Logiques

```python
# and, or, not
True and False      # False
True or False       # True
not True            # False

# Court-circuit
x = 0
x != 0 and 10/x     # False (10/x jamais évalué)
x == 0 or 10/x      # True (10/x jamais évalué)

# Valeurs "falsy"
bool(0)             # False
bool("")            # False
bool([])            # False
bool(None)          # False
bool({})            # False

# Opérateur ternaire
status = "up" if is_running else "down"
```

---

## 4. Structures de Contrôle

### Conditions if/elif/else

```python
status_code = 404

if status_code == 200:
    print("OK")
elif status_code == 404:
    print("Not Found")
elif status_code >= 500:
    print("Server Error")
else:
    print("Unknown")

# Conditions multiples
if status_code >= 200 and status_code < 300:
    print("Success")

# Pattern matching (Python 3.10+)
match status_code:
    case 200:
        print("OK")
    case 404:
        print("Not Found")
    case code if code >= 500:
        print(f"Server Error: {code}")
    case _:
        print("Unknown")
```

### Boucle for

```python
# Itérer sur une liste
servers = ["web01", "web02", "db01"]
for server in servers:
    print(f"Checking {server}")

# range() pour les compteurs
for i in range(5):          # 0, 1, 2, 3, 4
    print(i)

for i in range(1, 6):       # 1, 2, 3, 4, 5
    print(i)

for i in range(0, 10, 2):   # 0, 2, 4, 6, 8
    print(i)

# enumerate() pour index + valeur
for index, server in enumerate(servers):
    print(f"{index}: {server}")

# enumerate avec start
for num, server in enumerate(servers, start=1):
    print(f"{num}. {server}")

# Itérer sur un dictionnaire
config = {"host": "localhost", "port": 8080}
for key in config:
    print(key)

for key, value in config.items():
    print(f"{key} = {value}")
```

### Boucle while

```python
# While simple
count = 0
while count < 5:
    print(count)
    count += 1

# While avec condition de sortie
attempts = 0
max_attempts = 3

while attempts < max_attempts:
    success = try_connection()
    if success:
        break
    attempts += 1
else:
    # Exécuté si pas de break
    print("Failed after max attempts")

# Boucle infinie contrôlée
while True:
    command = input("Enter command: ")
    if command == "quit":
        break
    process(command)
```

### Contrôle de Boucle

```python
# break - sortir de la boucle
for i in range(10):
    if i == 5:
        break
    print(i)  # 0, 1, 2, 3, 4

# continue - passer à l'itération suivante
for i in range(10):
    if i % 2 == 0:
        continue
    print(i)  # 1, 3, 5, 7, 9

# pass - ne rien faire (placeholder)
for i in range(10):
    if i == 5:
        pass  # TODO: handle this case
    print(i)
```

---

## 5. Conventions Python (PEP 8)

### Nommage

```python
# Variables et fonctions : snake_case
server_name = "web01"
def get_server_status():
    pass

# Constantes : UPPER_CASE
MAX_CONNECTIONS = 100
DEFAULT_TIMEOUT = 30

# Classes : PascalCase
class ServerManager:
    pass

# Variables "privées" : _underscore
_internal_cache = {}

# Variables à ignorer : _
for _ in range(5):
    print("Hello")
```

### Indentation et Espacement

```python
# Indentation : 4 espaces (pas de tabs)
if condition:
    do_something()

# Espaces autour des opérateurs
x = 1 + 2           # Bien
x=1+2               # Mal

# Pas d'espaces dans les appels de fonction
func(arg1, arg2)    # Bien
func( arg1, arg2 )  # Mal

# Lignes vides
# 2 lignes entre les fonctions/classes de niveau module
# 1 ligne entre les méthodes d'une classe

# Longueur de ligne : 79-120 caractères max
```

### Imports

```python
# Ordre des imports :
# 1. Standard library
# 2. Third-party
# 3. Local

import os
import sys
from pathlib import Path

import requests
import yaml

from myproject import utils
from myproject.config import settings

# Un import par ligne (sauf from)
import os
import sys
# Pas : import os, sys

# Éviter les wildcard imports
from os import *        # Mal
from os import path     # Bien
```

---

## Exercices Pratiques

### Exercice 1 : Variables et Types

```python
# Créer des variables pour représenter un serveur :
# - hostname (str)
# - ip_address (str)
# - port (int)
# - is_active (bool)
# - cpu_usage (float)
# - tags (None pour l'instant)

# Afficher le type de chaque variable
# Convertir le port en string
```

### Exercice 2 : Manipulation de Chaînes

```python
log_line = "2024-01-15 10:30:45 ERROR [nginx] Connection refused to 192.168.1.100:8080"

# 1. Extraire la date (10 premiers caractères)
# 2. Extraire l'heure
# 3. Extraire le niveau de log (ERROR)
# 4. Vérifier si c'est une erreur (contient "ERROR")
# 5. Remplacer l'IP par "XXX.XXX.XXX.XXX"
# 6. Compter le nombre de ":"
```

### Exercice 3 : Conditions et Boucles

```python
# Script de validation de configuration
servers = [
    {"name": "web01", "port": 80, "status": "running"},
    {"name": "web02", "port": 8080, "status": "stopped"},
    {"name": "db01", "port": 5432, "status": "running"},
    {"name": "cache01", "port": 6379, "status": "error"},
]

# Pour chaque serveur :
# - Afficher le nom et le statut
# - Si port < 1024, afficher "Port privilégié"
# - Compter les serveurs par statut
# - Lister les serveurs en erreur
```

---

## Points Clés à Retenir

!!! success "Syntaxe Python"
    - Indentation significative (4 espaces)
    - Typage dynamique mais fort
    - F-strings pour le formatage
    - PEP 8 pour les conventions

!!! tip "Idiomes Python"
    ```python
    # Swap sans variable temporaire
    a, b = b, a

    # Unpacking
    first, *rest = [1, 2, 3, 4]  # first=1, rest=[2,3,4]

    # Valeur par défaut
    name = user_input or "default"

    # Chaîne vide/liste vide
    if not my_list:  # Plus pythonique que len(my_list) == 0
        print("Empty")
    ```

---

## Voir Aussi

- [Module 03 - Structures de Données](03-structures.md)
- [Module 04 - Fonctions](04-fonctions.md)
