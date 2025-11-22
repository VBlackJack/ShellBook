---
tags:
  - sed
  - awk
  - regex
  - logs
---

# Sed, Awk & Text Processing

Manipulation de texte en ligne de commande : les outils indispensables du SysOps.

---

## Sed (Stream Editor) - Le Chirurgien

### Concept

Sed lit le texte ligne par ligne, applique des transformations, et affiche le résultat. Idéal pour les modifications chirurgicales.

```
Input → sed 'instruction' → Output
```

### Cas d'Usage #1 : Remplacement dans un Fichier

```bash
# Syntaxe de base
sed 's/old/new/' file.txt         # Première occurrence par ligne
sed 's/old/new/g' file.txt        # Toutes les occurrences (global)

# Modifier le fichier directement (-i = in-place)
sed -i 's/old/new/g' config.conf

# Backup avant modification (-i.bak)
sed -i.bak 's/old/new/g' config.conf
# Crée config.conf.bak avec l'original
```

!!! warning "Option -i : Danger"
    `-i` modifie le fichier **sans confirmation**. Toujours tester sans `-i` d'abord, ou utiliser `-i.bak` pour créer une sauvegarde.

```bash
# Exemples pratiques
sed -i 's/Listen 80/Listen 8080/g' /etc/apache2/ports.conf
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i "s/DB_HOST=.*/DB_HOST=$NEW_HOST/g" .env
```

### Cas d'Usage #2 : Afficher des Lignes Spécifiques

```bash
# Ligne 5 uniquement
sed -n '5p' file.txt

# Lignes 5 à 10
sed -n '5,10p' file.txt

# Depuis la ligne 100 jusqu'à la fin
sed -n '100,$p' file.txt

# Première ligne (head -1)
sed -n '1p' file.txt

# Dernière ligne (tail -1)
sed -n '$p' file.txt
```

### Cas d'Usage #3 : Supprimer des Lignes

```bash
# Supprimer les lignes commentées (#)
sed '/^#/d' config.conf

# Supprimer les lignes vides
sed '/^$/d' file.txt

# Supprimer commentaires ET lignes vides
sed '/^#/d; /^$/d' config.conf

# Version plus robuste (espaces avant #, lignes avec espaces)
sed '/^\s*#/d; /^\s*$/d' config.conf

# Supprimer une ligne spécifique (ligne 3)
sed '3d' file.txt

# Supprimer les lignes contenant "DEBUG"
sed '/DEBUG/d' app.log
```

### Récapitulatif Sed

| Commande | Action |
|----------|--------|
| `s/old/new/` | Remplacer (1ère occurrence) |
| `s/old/new/g` | Remplacer (toutes) |
| `-i` | Modifier en place |
| `-n 'Np'` | Afficher ligne N |
| `/pattern/d` | Supprimer lignes matchant |
| `^` | Début de ligne |
| `$` | Fin de ligne |

---

## Awk - Le Statisticien

### Concept

Awk traite le texte **colonne par colonne**. Chaque ligne est découpée en champs (`$1`, `$2`, ...). Parfait pour les rapports et calculs.

```
$0 = ligne entière
$1 = première colonne
$2 = deuxième colonne
$NF = dernière colonne
NR = numéro de ligne
```

### Cas d'Usage #1 : Filtrer les Colonnes

```bash
# Afficher colonnes 1 et 9 de ls -l
ls -l | awk '{print $1, $9}'

# Permissions et nom de fichier
ls -l | awk '{print $1, $NF}'

# Utilisateurs connectés
who | awk '{print $1}'

# IP et URL d'un access.log Apache
awk '{print $1, $7}' /var/log/apache2/access.log

# Avec séparateur personnalisé (: pour /etc/passwd)
awk -F: '{print $1, $7}' /etc/passwd
# Output: root /bin/bash
```

### Cas d'Usage #2 : Filtrer par Condition

```bash
# Processus utilisant > 100MB de RAM
ps aux | awk '$6 > 100000 {print $11, $6/1024 "MB"}'

# Fichiers > 1GB
ls -l | awk '$5 > 1073741824 {print $9, $5/1073741824 "GB"}'

# Lignes où colonne 3 > 50
awk '$3 > 50' data.txt

# Requêtes HTTP avec code 500
awk '$9 == 500' /var/log/apache2/access.log

# Utilisateurs avec UID > 1000
awk -F: '$3 > 1000 {print $1}' /etc/passwd
```

### Cas d'Usage #3 : Calculs et Sommes

```bash
# Taille totale des fichiers
ls -l | awk '{sum += $5} END {print sum/1024/1024 "MB"}'

# Nombre de requêtes par code HTTP
awk '{count[$9]++} END {for (code in count) print code, count[code]}' access.log

# Moyenne d'une colonne
awk '{sum += $1; count++} END {print sum/count}' numbers.txt

# Taille totale des logs
find /var/log -name "*.log" -exec ls -l {} \; | awk '{sum += $5} END {print sum/1024/1024 "MB"}'

# Compter les occurrences
awk '{count[$1]++} END {for (ip in count) print count[ip], ip}' access.log | sort -rn | head
```

### Récapitulatif Awk

| Syntaxe | Description |
|---------|-------------|
| `$1, $2, $N` | Colonnes |
| `$NF` | Dernière colonne |
| `$0` | Ligne entière |
| `NR` | Numéro de ligne |
| `-F:` | Séparateur (ici `:`) |
| `condition {action}` | Si condition, faire action |
| `END {action}` | Action après toutes les lignes |

---

## Cut, Sort & Uniq - Les Outils Rapides

### Cut : Extraire des Colonnes

```bash
# Par délimiteur (-d) et champ (-f)
cut -d: -f1 /etc/passwd              # Usernames
cut -d: -f1,7 /etc/passwd            # Username et shell
cut -d',' -f2 data.csv               # 2ème colonne CSV

# Par position de caractères
cut -c1-10 file.txt                  # Caractères 1 à 10
cut -c-5 file.txt                    # 5 premiers caractères
```

### Sort : Trier

```bash
# Tri alphabétique
sort file.txt

# Tri numérique
sort -n numbers.txt

# Tri inverse
sort -r file.txt

# Tri par colonne (colonne 2, numérique)
sort -t: -k3 -n /etc/passwd          # Par UID

# Tri par taille (human-readable)
ls -lh | sort -k5 -h

# Supprimer les doublons en triant
sort -u file.txt
```

### Uniq : Dédupliquer

```bash
# Supprimer les doublons consécutifs (DOIT être trié avant)
sort file.txt | uniq

# Compter les occurrences
sort file.txt | uniq -c

# Afficher uniquement les doublons
sort file.txt | uniq -d

# Afficher uniquement les lignes uniques
sort file.txt | uniq -u
```

### Quick Wins : Combinaisons Puissantes

#### IPs Uniques dans un Access Log

```bash
# Top 10 des IPs
awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -10

# Output:
#   1523 192.168.1.100
#    892 10.0.0.50
#    ...
```

#### Utilisateurs Connectés Uniques

```bash
who | awk '{print $1}' | sort -u
```

#### Extensions de Fichiers les Plus Communes

```bash
find . -type f | sed 's/.*\.//' | sort | uniq -c | sort -rn | head
```

#### URLs les Plus Demandées

```bash
awk '{print $7}' /var/log/apache2/access.log | sort | uniq -c | sort -rn | head -20
```

#### Erreurs 5xx par Heure

```bash
awk '$9 ~ /^5/ {print $4}' access.log | cut -d: -f2 | sort | uniq -c
```

#### Taille des Répertoires (Top 10)

```bash
du -sh */ 2>/dev/null | sort -rh | head -10
```

---

## Référence Rapide

```bash
# === SED ===
sed 's/old/new/g' file           # Remplacer
sed -i 's/old/new/g' file        # In-place
sed -n '5,10p' file              # Lignes 5-10
sed '/^#/d; /^$/d' file          # Suppr commentaires/vides

# === AWK ===
awk '{print $1, $3}' file        # Colonnes 1 et 3
awk -F: '{print $1}' /etc/passwd # Séparateur :
awk '$3 > 100' file              # Condition
awk '{sum+=$1} END {print sum}'  # Somme

# === CUT ===
cut -d: -f1 file                 # Colonne 1, délim :
cut -c1-10 file                  # Caractères 1-10

# === SORT ===
sort -n file                     # Tri numérique
sort -k2 -t: file                # Par colonne 2

# === UNIQ ===
sort file | uniq -c              # Compter occurrences

# === COMBO CLASSIQUE ===
awk '{print $1}' log | sort | uniq -c | sort -rn | head
```
