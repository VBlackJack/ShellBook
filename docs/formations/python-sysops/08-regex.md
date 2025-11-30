---
tags:
  - formation
  - python
  - regex
  - parsing
---

# Module 08 - Expressions Régulières

Parser et valider des données avec les expressions régulières.

---

## Objectifs du Module

- Comprendre la syntaxe des regex
- Utiliser le module re de Python
- Parser des logs et fichiers de configuration
- Valider des entrées utilisateur

---

## 1. Syntaxe des Regex

### Caractères Spéciaux

| Pattern | Description | Exemple |
|---------|-------------|---------|
| `.` | N'importe quel caractère | `a.c` → abc, a1c |
| `^` | Début de ligne | `^Error` |
| `$` | Fin de ligne | `\.log$` |
| `*` | 0 ou plusieurs | `ab*c` → ac, abc, abbc |
| `+` | 1 ou plusieurs | `ab+c` → abc, abbc |
| `?` | 0 ou 1 | `colou?r` → color, colour |
| `\` | Échappement | `\.` → point littéral |
| `|` | OU logique | `cat|dog` |
| `()` | Groupe de capture | `(ab)+` |
| `[]` | Classe de caractères | `[aeiou]` |

### Classes de Caractères

| Pattern | Description | Équivalent |
|---------|-------------|------------|
| `\d` | Chiffre | `[0-9]` |
| `\D` | Non-chiffre | `[^0-9]` |
| `\w` | Alphanumérique | `[a-zA-Z0-9_]` |
| `\W` | Non-alphanumérique | `[^a-zA-Z0-9_]` |
| `\s` | Espace blanc | `[ \t\n\r\f\v]` |
| `\S` | Non-espace | `[^ \t\n\r\f\v]` |

### Quantificateurs

| Pattern | Description |
|---------|-------------|
| `{n}` | Exactement n fois |
| `{n,}` | Au moins n fois |
| `{n,m}` | Entre n et m fois |
| `*?` | 0+ (non-greedy) |
| `+?` | 1+ (non-greedy) |
| `??` | 0 ou 1 (non-greedy) |

### Classes de Caractères Personnalisées

```python
# Plages
[a-z]           # Minuscules
[A-Z]           # Majuscules
[0-9]           # Chiffres
[a-zA-Z0-9]     # Alphanumériques

# Négation
[^0-9]          # Tout sauf chiffres
[^aeiou]        # Tout sauf voyelles

# Caractères spéciaux dans []
[.\-+]          # Point, tiret, plus littéraux
[\[\]]          # Crochets littéraux
```

---

## 2. Module re de Python

### Fonctions de Base

```python
import re

text = "Error 404: Page not found at 10:30:45"

# search() - Première correspondance
match = re.search(r'\d+', text)
if match:
    print(match.group())    # '404'
    print(match.start())    # 6
    print(match.end())      # 9
    print(match.span())     # (6, 9)

# match() - Correspondance au début
match = re.match(r'Error', text)
if match:
    print(match.group())    # 'Error'

# fullmatch() - Correspondance complète
match = re.fullmatch(r'Error.*', text)

# findall() - Toutes les correspondances
numbers = re.findall(r'\d+', text)
print(numbers)              # ['404', '10', '30', '45']

# finditer() - Itérateur de matches
for match in re.finditer(r'\d+', text):
    print(f"{match.group()} at {match.span()}")
```

### Substitution

```python
import re

text = "Hello World"

# sub() - Remplacer
result = re.sub(r'World', 'Python', text)
# 'Hello Python'

# Remplacer tous les chiffres
text = "Error 404 at line 123"
result = re.sub(r'\d+', 'XXX', text)
# 'Error XXX at line XXX'

# Limiter les remplacements
result = re.sub(r'\d+', 'XXX', text, count=1)
# 'Error XXX at line 123'

# Fonction de remplacement
def double_number(match):
    return str(int(match.group()) * 2)

result = re.sub(r'\d+', double_number, "Price: 100")
# 'Price: 200'

# subn() - Retourne aussi le nombre de remplacements
result, count = re.subn(r'\d+', 'X', text)
```

### Split

```python
import re

# Découper sur un pattern
text = "apple,banana;orange:grape"
parts = re.split(r'[,;:]', text)
# ['apple', 'banana', 'orange', 'grape']

# Garder les délimiteurs
parts = re.split(r'([,;:])', text)
# ['apple', ',', 'banana', ';', 'orange', ':', 'grape']

# Limiter les splits
parts = re.split(r'[,;:]', text, maxsplit=2)
# ['apple', 'banana', 'orange:grape']
```

---

## 3. Groupes de Capture

### Groupes Numérotés

```python
import re

log_line = "2024-01-15 10:30:45 ERROR Connection failed"

# Capturer date et heure
pattern = r'(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})'
match = re.search(pattern, log_line)

if match:
    print(match.group(0))   # Match complet
    print(match.group(1))   # '2024-01-15'
    print(match.group(2))   # '10:30:45'
    print(match.groups())   # ('2024-01-15', '10:30:45')
```

### Groupes Nommés

```python
import re

log_line = "2024-01-15 10:30:45 ERROR Connection failed"

# Groupes nommés avec (?P<name>...)
pattern = r'(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<level>\w+)'
match = re.search(pattern, log_line)

if match:
    print(match.group('date'))    # '2024-01-15'
    print(match.group('time'))    # '10:30:45'
    print(match.group('level'))   # 'ERROR'
    print(match.groupdict())
    # {'date': '2024-01-15', 'time': '10:30:45', 'level': 'ERROR'}
```

### Références Arrière

```python
import re

# Trouver les mots répétés
text = "the the quick brown fox fox"
pattern = r'\b(\w+)\s+\1\b'
matches = re.findall(pattern, text)
# ['the', 'fox']

# Avec groupe nommé
pattern = r'\b(?P<word>\w+)\s+(?P=word)\b'
```

---

## 4. Compilation et Flags

### Compiler une Regex

```python
import re

# Compiler pour réutilisation (plus performant)
ip_pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

logs = [
    "Connection from 192.168.1.100",
    "Connection from 10.0.0.1",
    "No IP here"
]

for log in logs:
    match = ip_pattern.search(log)
    if match:
        print(f"Found IP: {match.group()}")
```

### Flags

```python
import re

# re.IGNORECASE (re.I) - Insensible à la casse
re.search(r'error', 'ERROR', re.IGNORECASE)

# re.MULTILINE (re.M) - ^ et $ matchent début/fin de ligne
text = "line1\nline2\nline3"
re.findall(r'^line\d', text, re.MULTILINE)  # ['line1', 'line2', 'line3']

# re.DOTALL (re.S) - . matche aussi \n
text = "first\nsecond"
re.search(r'first.second', text, re.DOTALL)

# re.VERBOSE (re.X) - Regex sur plusieurs lignes avec commentaires
pattern = re.compile(r'''
    ^                   # Début de ligne
    (\d{4}-\d{2}-\d{2}) # Date YYYY-MM-DD
    \s+                 # Espaces
    (\d{2}:\d{2}:\d{2}) # Heure HH:MM:SS
    \s+                 # Espaces
    (\w+)               # Niveau de log
    ''', re.VERBOSE)

# Combiner les flags
re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
```

---

## 5. Cas d'Usage SysOps

### Parser des Logs

```python
import re
from collections import Counter
from datetime import datetime

def parse_nginx_log(line):
    """Parse une ligne de log Nginx."""
    pattern = r'''
        ^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+    # IP client
        -\s+-\s+                            # Identité (souvent -)
        \[(?P<datetime>[^\]]+)\]\s+         # Date/heure
        "(?P<method>\w+)\s+                 # Méthode HTTP
        (?P<path>[^\s]+)\s+                 # Chemin
        HTTP/[\d.]+"\s+                     # Version HTTP
        (?P<status>\d+)\s+                  # Code status
        (?P<size>\d+)                       # Taille réponse
    '''
    match = re.search(pattern, line, re.VERBOSE)
    if match:
        return match.groupdict()
    return None

# Parser un fichier de logs
def analyze_logs(log_file):
    status_counts = Counter()
    ip_counts = Counter()

    with open(log_file) as f:
        for line in f:
            parsed = parse_nginx_log(line)
            if parsed:
                status_counts[parsed['status']] += 1
                ip_counts[parsed['ip']] += 1

    return {
        'status_codes': dict(status_counts.most_common(10)),
        'top_ips': dict(ip_counts.most_common(10))
    }
```

### Valider des Entrées

```python
import re

def validate_hostname(hostname):
    """Valide un nom d'hôte."""
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
    return bool(re.match(pattern, hostname))

def validate_ip(ip):
    """Valide une adresse IPv4."""
    pattern = r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$'
    match = re.match(pattern, ip)
    if match:
        return all(0 <= int(octet) <= 255 for octet in match.groups())
    return False

def validate_email(email):
    """Valide une adresse email (basique)."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_port(port_str):
    """Valide un numéro de port."""
    pattern = r'^\d{1,5}$'
    if re.match(pattern, port_str):
        port = int(port_str)
        return 1 <= port <= 65535
    return False

# Tests
print(validate_hostname("web-server-01"))  # True
print(validate_ip("192.168.1.100"))        # True
print(validate_email("admin@example.com")) # True
```

### Extraire des Informations

```python
import re

def extract_urls(text):
    """Extrait les URLs d'un texte."""
    pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    return re.findall(pattern, text)

def extract_ips(text):
    """Extrait les adresses IP d'un texte."""
    pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    return re.findall(pattern, text)

def extract_emails(text):
    """Extrait les emails d'un texte."""
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(pattern, text)

def extract_mac_addresses(text):
    """Extrait les adresses MAC."""
    pattern = r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})'
    return [m[0] + m[1] for m in re.findall(f'({pattern})', text)]
```

### Transformer du Texte

```python
import re

def mask_sensitive_data(text):
    """Masque les données sensibles dans un texte."""
    # Masquer les IPs
    text = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'X.X.X.X', text)

    # Masquer les emails
    text = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                  '***@***.***', text)

    # Masquer les mots de passe dans les URLs
    text = re.sub(r'(password=)[^&\s]+', r'\1****', text)

    return text

def normalize_whitespace(text):
    """Normalise les espaces."""
    # Remplacer multiples espaces par un seul
    text = re.sub(r' +', ' ', text)
    # Supprimer espaces en début/fin de ligne
    text = re.sub(r'^ +| +$', '', text, flags=re.MULTILINE)
    return text
```

---

## 6. Patterns Courants SysOps

```python
import re

# Date ISO
DATE_ISO = r'\d{4}-\d{2}-\d{2}'

# Heure
TIME_24H = r'\d{2}:\d{2}:\d{2}'

# Timestamp syslog
SYSLOG_TS = r'[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'

# IP v4
IPV4 = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

# IP v6 (simplifié)
IPV6 = r'[0-9a-fA-F:]+:[0-9a-fA-F:]+'

# CIDR
CIDR = r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b'

# MAC Address
MAC = r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}'

# UUID
UUID = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

# Chemin Unix
UNIX_PATH = r'/[a-zA-Z0-9._/-]+'

# Chemin Windows
WIN_PATH = r'[A-Z]:\\[a-zA-Z0-9._\\-]+'

# Niveau de log
LOG_LEVEL = r'\b(DEBUG|INFO|WARNING|ERROR|CRITICAL)\b'
```

---

## Exercices Pratiques

### Exercice 1 : Parser Syslog

```python
# Parser une ligne syslog :
# "Jan 15 10:30:45 web01 nginx[1234]: GET /api/users 200"
# Extraire : date, hostname, service, pid, message
```

### Exercice 2 : Validateur de Config

```python
# Créer des validateurs pour :
# - FQDN (hostname.domain.tld)
# - Plage de ports (8080-8090)
# - Variable d'environnement (VAR_NAME=value)
```

### Exercice 3 : Log Anonymizer

```python
# Créer une fonction qui anonymise :
# - IPs → IP_MASKED
# - Emails → EMAIL_MASKED
# - Numéros de téléphone → PHONE_MASKED
```

---

## Points Clés à Retenir

!!! success "Bonnes Pratiques"
    - Utiliser des raw strings `r'pattern'`
    - Compiler les regex réutilisées
    - Préférer les groupes nommés
    - Tester avec des outils comme regex101.com

!!! warning "Pièges Courants"
    ```python
    # Greedy vs Non-Greedy
    re.search(r'<.*>', '<tag>content</tag>')   # '<tag>content</tag>'
    re.search(r'<.*?>', '<tag>content</tag>')  # '<tag>'

    # Échapper les caractères spéciaux
    re.search(r'\.txt$', 'file.txt')           # Correct
    re.search(r'.txt$', 'file.txt')            # Matche aussi 'filetxt'
    ```

---

## Voir Aussi

- [Module 09 - Gestion des Erreurs](09-erreurs.md)
- [Linux Text Processing](../../linux/text-processing.md)
