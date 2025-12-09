---
tags:
  - awk
  - jq
  - json
  - logs
  - parsing
---

# Advanced Data Processing: Awk, Sed & JQ

Transformer le terminal en moteur ETL. Traiter des logs, du JSON et des données structurées sans Python.

---

## Awk comme Langage de Programmation

### Structure Complète : BEGIN / Pattern / END

**Awk n'est pas qu'un `print $1`** - c'est un langage de programmation à part entière.

```awk
BEGIN {
    # Exécuté AVANT de lire les données
    # Initialisation de variables
}

/pattern/ {
    # Exécuté pour chaque ligne matchant le pattern
    # Actions de traitement
}

{
    # Exécuté pour TOUTES les lignes
}

END {
    # Exécuté APRÈS avoir lu toutes les données
    # Affichage des résultats
}
```

**Exemple : Compter les types de fichiers dans un dossier**

```bash
ls -lh | awk '
BEGIN {
    print "=== Analyse des fichiers ==="
    total_size = 0
    file_count = 0
}

NR > 1 {  # Ignorer la première ligne (total)
    # $5 = taille, $9 = nom de fichier
    total_size += $5
    file_count++

    # Extraire l'extension
    n = split($9, parts, ".")
    ext = (n > 1) ? parts[n] : "no_extension"

    # Compter par extension
    extensions[ext]++
}

END {
    print "\n=== Résultats ==="
    print "Total fichiers:", file_count
    print "Taille totale:", total_size

    print "\n=== Par extension ==="
    for (ext in extensions) {
        printf "%-15s : %d fichiers\n", ext, extensions[ext]
    }
}'
```

### Tableaux Associatifs : L'Arme Fatale

**Concept :** Hash map intégré dans Awk. **Pas besoin de `sort | uniq -c`** !

```bash
# Données exemple : access.log
# 192.168.1.10 - - [10/Oct/2024:13:55:36] "GET /api/users" 200 1024
# 192.168.1.11 - - [10/Oct/2024:13:55:37] "GET /api/posts" 200 2048
# 192.168.1.10 - - [10/Oct/2024:13:55:38] "POST /api/login" 200 512
```

**Exemple 1 : Compter les requêtes par IP**

```bash
awk '{
    # $1 = IP address
    ip_count[$1]++
}

END {
    # Afficher le résultat
    for (ip in ip_count) {
        printf "%s : %d requêtes\n", ip, ip_count[ip]
    }
}' access.log

# Output:
# 192.168.1.10 : 2 requêtes
# 192.168.1.11 : 1 requêtes
```

**Exemple 2 : Compter par Status Code**

```bash
awk '{
    # $9 = status code
    status[$9]++
}

END {
    for (code in status) {
        printf "HTTP %s : %d\n", code, status[code]
    }
}' access.log
```

### Calculs : Sommes, Moyennes, Ratios

**Exemple : Calculer la taille moyenne des réponses par endpoint**

```bash
awk '{
    # $7 = endpoint, $10 = bytes
    endpoint = $7
    bytes = $10

    # Accumuler
    total_bytes[endpoint] += bytes
    count[endpoint]++
}

END {
    print "Endpoint                   | Total (KB) | Avg (KB)"
    print "--------------------------------------------------------"

    for (ep in total_bytes) {
        total_kb = total_bytes[ep] / 1024
        avg_kb = total_kb / count[ep]
        printf "%-25s | %10.2f | %8.2f\n", ep, total_kb, avg_kb
    }
}' access.log
```

### Exemple Concret : Top 5 IPs par Volume de Données

**Scénario :** Identifier les IPs qui consomment le plus de bande passante.

**Données :** `access.log`

```text
192.168.1.10 - - [10/Oct/2024:13:55:36] "GET /api/users" 200 1024
192.168.1.11 - - [10/Oct/2024:13:55:37] "GET /api/posts" 200 2048
192.168.1.10 - - [10/Oct/2024:13:55:38] "POST /api/login" 200 512
192.168.1.12 - - [10/Oct/2024:13:55:39] "GET /static/image.jpg" 200 51200
192.168.1.11 - - [10/Oct/2024:13:55:40] "GET /api/comments" 200 4096
192.168.1.10 - - [10/Oct/2024:13:55:41] "GET /api/profile" 200 2048
```

**Solution Awk :**

```bash
awk '
BEGIN {
    print "=== Analyse des IPs par volume de données ==="
}

{
    # $1 = IP, $10 = bytes
    ip = $1
    bytes = $10

    # Accumuler les bytes par IP
    ip_bytes[ip] += bytes
    ip_requests[ip]++
}

END {
    # Trier par volume (méthode manuelle avec Awk)
    # 1. Stocker dans un array avec clé inversée
    for (ip in ip_bytes) {
        # Créer une clé unique : bytes + IP
        key = sprintf("%015d_%s", ip_bytes[ip], ip)
        sorted[key] = ip
    }

    # 2. Utiliser asort (GNU Awk) pour trier
    n = asort(sorted)

    # 3. Afficher le Top 5 (en ordre décroissant)
    print "\n=== Top 5 IPs par volume ==="
    printf "%-15s | %-12s | %-10s | %-10s\n", "IP", "Requests", "Bytes", "MB"
    print "-----------------------------------------------------------"

    count = 0
    for (i = n; i >= 1 && count < 5; i--) {
        ip = sorted[i]
        # Extraire l'IP (après le underscore)
        split(ip, parts, "_")
        real_ip = parts[2]

        requests = ip_requests[real_ip]
        bytes = ip_bytes[real_ip]
        mb = bytes / (1024 * 1024)

        printf "%-15s | %12d | %10d | %10.2f\n", real_ip, requests, bytes, mb
        count++
    }
}
' access.log
```

**Alternative avec `sort` externe (plus simple) :**

```bash
awk '{
    ip_bytes[$1] += $10
    ip_requests[$1]++
}

END {
    for (ip in ip_bytes) {
        printf "%s\t%d\t%d\n", ip, ip_requests[ip], ip_bytes[ip]
    }
}' access.log | sort -k3 -nr | head -5 | awk '
BEGIN {
    printf "%-15s | %-12s | %-10s | %-10s\n", "IP", "Requests", "Bytes", "MB"
    print "-----------------------------------------------------------"
}
{
    printf "%-15s | %12d | %10d | %10.2f\n", $1, $2, $3, $3/(1024*1024)
}'
```

### Fonctions Avancées

```bash
# Fonctions mathématiques
awk 'BEGIN {
    print sqrt(16)        # 4
    print int(3.7)        # 3
    print rand()          # 0.xxx (random)
    print sin(3.14159)    # 0.xxx
}'

# Fonctions de chaînes
awk 'BEGIN {
    str = "Hello World"
    print length(str)              # 11
    print substr(str, 1, 5)        # Hello
    print tolower(str)             # hello world
    print toupper(str)             # HELLO WORLD
    print index(str, "World")      # 7

    # Split
    n = split(str, arr, " ")
    print arr[1], arr[2]           # Hello World

    # gsub (global substitute)
    gsub("World", "Universe", str)
    print str                      # Hello Universe
}'
```

!!! tip "Performance : Awk vs Python"
    **Awk est 10x plus rapide que Python pour du parsing simple.**

    Benchmark sur un fichier de 1 GB :
    - **Awk** : 8 secondes
    - **Python** : 85 secondes
    - **Grep** : 3 secondes (mais fonctionnalités limitées)

    **Utilisez Awk pour :**
    - Parsing de logs volumineux (> 100 MB)
    - Statistiques simples (count, sum, avg)
    - Pipelines shell rapides

    **Utilisez Python pour :**
    - Logique complexe (APIs, DB)
    - Structures de données avancées
    - Débogage (plus lisible)

---

## JQ : Le Awk du JSON

### Installation

```bash
# Debian/Ubuntu
sudo apt install jq

# RHEL/CentOS
sudo yum install jq

# macOS
brew install jq

# Vérifier
jq --version
```

### Navigation : Sélectionner des Données

**Données exemple :** `pods.json` (output de `kubectl get pods -o json`)

```json
{
  "items": [
    {
      "metadata": {
        "name": "nginx-deployment-abc123",
        "namespace": "production",
        "labels": {
          "app": "nginx",
          "version": "v1.0"
        }
      },
      "status": {
        "phase": "Running",
        "podIP": "10.244.1.5"
      }
    },
    {
      "metadata": {
        "name": "redis-deployment-def456",
        "namespace": "production",
        "labels": {
          "app": "redis",
          "version": "v6.2"
        }
      },
      "status": {
        "phase": "Pending",
        "podIP": null
      }
    }
  ]
}
```

**Extraire les noms de pods :**

```bash
jq '.items[].metadata.name' pods.json

# Output:
# "nginx-deployment-abc123"
# "redis-deployment-def456"
```

**Extraire pods + status :**

```bash
jq '.items[] | {name: .metadata.name, status: .status.phase}' pods.json

# Output:
# {
#   "name": "nginx-deployment-abc123",
#   "status": "Running"
# }
# {
#   "name": "redis-deployment-def456",
#   "status": "Pending"
# }
```

**Extraire uniquement les pods Running :**

```bash
jq '.items[] | select(.status.phase == "Running") | .metadata.name' pods.json

# Output:
# "nginx-deployment-abc123"
```

### Construction : Créer de Nouveaux Objets JSON

**Scénario :** Créer un fichier d'inventaire simplifié depuis kubectl.

```bash
kubectl get pods -o json | jq '.items[] | {
    name: .metadata.name,
    namespace: .metadata.namespace,
    ip: .status.podIP,
    app: .metadata.labels.app,
    status: .status.phase
}'

# Output:
# {
#   "name": "nginx-deployment-abc123",
#   "namespace": "production",
#   "ip": "10.244.1.5",
#   "app": "nginx",
#   "status": "Running"
# }
```

**Créer un CSV depuis JSON :**

```bash
kubectl get pods -o json | jq -r '.items[] |
    [.metadata.name, .metadata.namespace, .status.podIP, .status.phase] |
    @csv'

# Output:
# "nginx-deployment-abc123","production","10.244.1.5","Running"
# "redis-deployment-def456","production",null,"Pending"
```

**Créer un TSV (Tab-Separated Values) :**

```bash
kubectl get pods -o json | jq -r '.items[] |
    [.metadata.name, .status.podIP, .status.phase] |
    @tsv'

# Output:
# nginx-deployment-abc123	10.244.1.5	Running
# redis-deployment-def456	null	Pending
```

### Filtres et Sélections

**Opérateurs disponibles :**

| Opérateur | Description | Exemple |
|-----------|-------------|---------|
| `select()` | Filtrer | `select(.status == "Running")` |
| `map()` | Transformer array | `map(.name)` |
| `has()` | Vérifier clé existe | `select(has("podIP"))` |
| `length` | Longueur | `.items | length` |
| `sort_by()` | Trier | `sort_by(.metadata.name)` |
| `group_by()` | Grouper | `group_by(.status.phase)` |
| `unique` | Dédupliquer | `.items | map(.status.phase) | unique` |

**Exemples :**

```bash
# Compter les pods par phase
kubectl get pods -o json | jq '
    .items |
    group_by(.status.phase) |
    map({phase: .[0].status.phase, count: length})'

# Output:
# [
#   {"phase": "Pending", "count": 1},
#   {"phase": "Running", "count": 1}
# ]

# Lister les pods sans IP
kubectl get pods -o json | jq '
    .items[] |
    select(.status.podIP == null) |
    .metadata.name'

# Trier les pods par nom
kubectl get pods -o json | jq '
    .items |
    sort_by(.metadata.name) |
    .[].metadata.name'
```

### Exemple Concret : Parser des Logs JSON Structurés

**Données :** `app.log` (logs d'application en JSON)

```json
{"timestamp":"2024-10-10T13:55:36Z","level":"INFO","message":"User login successful","user_id":1234,"ip":"192.168.1.10"}
{"timestamp":"2024-10-10T13:55:37Z","level":"ERROR","message":"Database connection failed","error":"timeout"}
{"timestamp":"2024-10-10T13:55:38Z","level":"INFO","message":"User logout","user_id":1234}
{"timestamp":"2024-10-10T13:55:39Z","level":"WARN","message":"High memory usage","memory_percent":85}
{"timestamp":"2024-10-10T13:55:40Z","level":"ERROR","message":"API request failed","endpoint":"/api/users","status":500}
```

**Extraire uniquement les erreurs :**

```bash
jq 'select(.level == "ERROR")' app.log

# Output:
# {"timestamp":"2024-10-10T13:55:37Z","level":"ERROR","message":"Database connection failed","error":"timeout"}
# {"timestamp":"2024-10-10T13:55:40Z","level":"ERROR","message":"API request failed","endpoint":"/api/users","status":500}
```

**Compter les logs par niveau :**

```bash
jq -s 'group_by(.level) | map({level: .[0].level, count: length})' app.log

# Output:
# [
#   {"level":"ERROR","count":2},
#   {"level":"INFO","count":2},
#   {"level":"WARN","count":1}
# ]
```

**Créer un rapport d'erreurs :**

```bash
jq -r 'select(.level == "ERROR") |
    [.timestamp, .message, .error // .status] |
    @tsv' app.log

# Output:
# 2024-10-10T13:55:37Z	Database connection failed	timeout
# 2024-10-10T13:55:40Z	API request failed	500
```

### Combiner JQ avec d'autres outils

```bash
# JQ + Curl : Query une API et extraire
curl -s https://api.github.com/repos/ansible/ansible | jq '.stargazers_count'

# JQ + Kubectl : Lister les containers par pod
kubectl get pods -o json | jq -r '
    .items[] |
    "\(.metadata.name): \(.spec.containers[].name)"'

# JQ + AWS CLI : Lister les instances EC2
aws ec2 describe-instances | jq '.Reservations[].Instances[] |
    {id: .InstanceId, type: .InstanceType, ip: .PrivateIpAddress}'

# JQ + Docker : Lister les conteneurs avec leur statut
docker inspect $(docker ps -q) | jq -r '.[] |
    [.Name, .State.Status, .NetworkSettings.IPAddress] |
    @tsv'
```

---

## Sed Avancé : Groupes de Capture & Multiligne

### Groupes de Capture : Réorganiser des Données

**Syntaxe :** `\(pattern\)` pour capturer, `\1`, `\2` pour réutiliser.

**Exemple 1 : Transformer "Nom, Prénom" en "Prénom Nom"**

```bash
echo "Dupont, Jean" | sed 's/\(.*\), \(.*\)/\2 \1/'
# Output: Jean Dupont

echo "Martin, Sophie" | sed 's/\(.*\), \(.*\)/\2 \1/'
# Output: Sophie Martin
```

**Exemple 2 : Extraire domaine d'une URL**

```bash
echo "https://www.example.com/path/to/page" | sed 's|https://\([^/]*\)/.*|\1|'
# Output: www.example.com

echo "https://api.github.com/users/octocat" | sed 's|https://\([^/]*\)/.*|\1|'
# Output: api.github.com
```

**Exemple 3 : Reformater des dates (YYYY-MM-DD → DD/MM/YYYY)**

```bash
echo "2024-10-15" | sed 's/\([0-9]\{4\}\)-\([0-9]\{2\}\)-\([0-9]\{2\}\)/\3\/\2\/\1/'
# Output: 15/10/2024

echo "2024-01-01" | sed 's/\([0-9]\{4\}\)-\([0-9]\{2\}\)-\([0-9]\{2\}\)/\3\/\2\/\1/'
# Output: 01/01/2024
```

### Plages d'Adresses : Agir entre Deux Patterns

**Syntaxe :** `/pattern1/,/pattern2/ { action }`

**Exemple 1 : Extraire un certificat PEM**

```bash
# Fichier : cert.pem
# -----BEGIN CERTIFICATE-----
# MIIBkTCB+wIJAKH...
# -----END CERTIFICATE-----

sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' cert.pem

# Output:
# -----BEGIN CERTIFICATE-----
# MIIBkTCB+wIJAKH...
# -----END CERTIFICATE-----
```

**Exemple 2 : Extraire une section de configuration**

```bash
# Fichier : nginx.conf
# server {
#     listen 80;
#     server_name example.com;
#     location / { ... }
# }

sed -n '/server {/,/^}/p' nginx.conf

# Output: toute la section server
```

**Exemple 3 : Supprimer un bloc**

```bash
# Supprimer tous les commentaires multi-lignes /* ... */
sed '/\/\*/,/\*\//d' code.c
```

### Multiligne : Manipuler Plusieurs Lignes

**Commandes multiligne :**

| Commande | Description |
|----------|-------------|
| `N` | Ajouter la ligne suivante au pattern space |
| `D` | Supprimer la première ligne du pattern space |
| `P` | Afficher la première ligne du pattern space |

**Exemple : Joindre des lignes qui se terminent par `\`**

```bash
# Fichier : script.sh
# echo "This is a long \
# command that spans \
# multiple lines"

sed ':a; /\\$/{ N; s/\\\n//; ba }' script.sh

# Output:
# echo "This is a long command that spans multiple lines"
```

**Exemple : Remplacer des sauts de ligne par des espaces**

```bash
# Transformer un fichier multi-lignes en une seule ligne
sed ':a; N; $!ba; s/\n/ /g' file.txt
```

---

## Cas d'Usage "Real World"

### Scénario 1 : Générer des INSERT SQL depuis CSV

**Données :** `users.csv`

```csv
id,name,email,role
1,Alice,alice@example.com,admin
2,Bob,bob@example.com,user
3,Charlie,charlie@example.com,moderator
```

**Solution avec Awk :**

```bash
awk -F, '
BEGIN {
    print "-- Generated SQL INSERT statements"
}

NR > 1 {  # Ignorer le header
    # Échapper les apostrophes
    gsub(/"/, "\"\"", $2)
    gsub(/"/, "\"\"", $3)

    printf "INSERT INTO users (id, name, email, role) VALUES (%d, '\''%s'\'', '\''%s'\'', '\''%s'\'');\n",
        $1, $2, $3, $4
}
' users.csv

# Output:
# -- Generated SQL INSERT statements
# INSERT INTO users (id, name, email, role) VALUES (1, 'Alice', 'alice@example.com', 'admin');
# INSERT INTO users (id, name, email, role) VALUES (2, 'Bob', 'bob@example.com', 'user');
# INSERT INTO users (id, name, email, role) VALUES (3, 'Charlie', 'charlie@example.com', 'moderator');
```

### Scénario 2 : Identifier les Processus Zombies

**Commande :**

```bash
ps aux | awk '
BEGIN {
    print "=== Analyse des processus ==="
}

# Ignorer le header
NR > 1 {
    # $8 = STAT (process state)
    # Z = zombie
    if ($8 ~ /Z/) {
        zombies++
        zombie_pids = zombie_pids " " $2
    }

    # %MEM > 5%
    if ($4 > 5) {
        mem_hogs++
        printf "High memory: PID %s (%s) - %s%% - %s\n", $2, $11, $4, $1
    }
}

END {
    print "\n=== Résultats ==="
    if (zombies > 0) {
        print "⚠️  Zombies détectés:", zombies
        print "PIDs:", zombie_pids
    } else {
        print "✅ Pas de processus zombie"
    }

    if (mem_hogs > 0) {
        print "⚠️  Processus consommant > 5% RAM:", mem_hogs
    }
}'
```

**Top 10 des consommateurs de RAM :**

```bash
ps aux | awk 'NR > 1 {print $4, $2, $11}' | sort -nr | head -10 | awk '
BEGIN {
    printf "%-8s %-8s %s\n", "MEM%", "PID", "COMMAND"
    print "----------------------------------------"
}
{
    printf "%-8s %-8s %s\n", $1, $2, $3
}'
```

### Scénario 3 : Convertir INI/Conf en JSON

**Données :** `config.ini`

```ini
[database]
host=localhost
port=5432
user=admin

[cache]
host=redis.local
port=6379
ttl=3600
```

**Solution avec Awk :**

```bash
awk '
BEGIN {
    print "{"
    section = ""
}

# Ligne de section [xxx]
/^\[.*\]/ {
    # Fermer la section précédente
    if (section != "") {
        print "  },"
    }

    # Ouvrir nouvelle section
    section = $0
    gsub(/[\[\]]/, "", section)
    printf "  \"%s\": {\n", section
    first_in_section = 1
    next
}

# Ligne clé=valeur
/^[a-zA-Z]/ {
    if (!first_in_section) {
        print ","
    }
    first_in_section = 0

    split($0, kv, "=")
    key = kv[1]
    value = kv[2]

    # Détecter si c'est un nombre
    if (value ~ /^[0-9]+$/) {
        printf "    \"%s\": %s", key, value
    } else {
        printf "    \"%s\": \"%s\"", key, value
    }
}

END {
    print "\n  }"
    print "}"
}
' config.ini

# Output:
# {
#   "database": {
#     "host": "localhost",
#     "port": 5432,
#     "user": "admin"
#   },
#   "cache": {
#     "host": "redis.local",
#     "port": 6379,
#     "ttl": 3600
#   }
# }
```

---

## Référence Rapide

### Awk : Opérateurs Essentiels

| Opérateur | Description | Exemple |
|-----------|-------------|---------|
| `$1, $2, $n` | Champs (colonnes) | `print $1` |
| `$0` | Ligne complète | `print $0` |
| `NR` | Numéro de ligne | `NR > 1` |
| `NF` | Nombre de champs | `print NF` |
| `FS` | Field Separator | `BEGIN {FS=","}` |
| `RS` | Record Separator | `BEGIN {RS="\n\n"}` |
| `~` | Match regex | `$1 ~ /pattern/` |
| `!~` | Not match regex | `$1 !~ /pattern/` |
| `==, !=, <, >` | Comparaison | `$2 > 100` |
| `&&, \|\|, !` | Logique | `$1 > 5 && $2 < 10` |
| `++, --` | Incrémentation | `count++` |
| `+=, -=, *=, /=` | Affectation | `total += $3` |

### JQ : Opérateurs Essentiels

| Opérateur | Description | Exemple |
|-----------|-------------|---------|
| `.` | Identité (tout) | `.` |
| `.key` | Accès clé | `.metadata.name` |
| `.[]` | Itérer array | `.items[]` |
| `.[n]` | Index array | `.items[0]` |
| `\|` | Pipe | `.items[] \| .name` |
| `select()` | Filtrer | `select(.status == "Running")` |
| `map()` | Transformer | `map(.name)` |
| `{key: .value}` | Construire objet | `{name: .metadata.name}` |
| `[.a, .b]` | Construire array | `[.name, .age]` |
| `@csv` | Format CSV | `[.name, .age] \| @csv` |
| `@tsv` | Format TSV | `[.name, .age] \| @tsv` |
| `@json` | Format JSON | `.data \| @json` |
| `length` | Longueur | `.items \| length` |
| `sort_by()` | Trier | `sort_by(.name)` |
| `group_by()` | Grouper | `group_by(.status)` |
| `has()` | Vérifier clé | `select(has("ip"))` |
| `// value` | Valeur par défaut | `.ip // "N/A"` |

### Sed : Commandes Essentielles

| Commande | Description | Exemple |
|----------|-------------|---------|
| `s/old/new/` | Substitution | `sed 's/foo/bar/'` |
| `s/old/new/g` | Substitution globale | `sed 's/foo/bar/g'` |
| `d` | Supprimer ligne | `sed '/pattern/d'` |
| `p` | Afficher ligne | `sed -n '/pattern/p'` |
| `a\text` | Ajouter après | `sed '/pattern/a\new line'` |
| `i\text` | Insérer avant | `sed '/pattern/i\new line'` |
| `c\text` | Remplacer ligne | `sed '/pattern/c\new content'` |
| `/pattern/,/pattern/` | Plage | `sed '/BEGIN/,/END/d'` |
| `\1, \2` | Groupes de capture | `sed 's/\(.*\),\(.*\)/\2 \1/'` |

---

## Ressources Complémentaires

- **GNU Awk Manual** : https://www.gnu.org/software/gawk/manual/
- **JQ Manual** : https://stedolan.github.io/jq/manual/
- **JQ Play (Online)** : https://jqplay.org/
- **Sed Manual** : https://www.gnu.org/software/sed/manual/
- **Advanced Bash-Scripting Guide** : https://tldp.org/LDP/abs/html/

---

!!! example "Parcours Recommandé"
    **Avant ce guide :**
    → [Text Processing](text-processing.md) - Bases de sed/awk/grep
    → [Bash Wizardry](bash-wizardry.md) - Pipelines et redirection

    **Après ce guide :**
    → [Scripting Standards](scripting-standards.md) - Écrire des scripts propres
    → [Logs Management](logs-management.md) - Analyser les logs système

    **Pratiquez :**
    → Parsez vos logs Nginx/Apache avec Awk
    → Explorez les APIs avec curl + JQ
    → Automatisez vos rapports ops avec des scripts Awk/JQ
