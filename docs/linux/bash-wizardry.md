---
tags:
  - bash
  - shell
  - scripting
---

# Caractères Spéciaux Bash & Redirections

Maîtriser les symboles magiques qui rendent Bash puissant.

---

## Les Signes Dollar

### Codes de Sortie (`$?`)

Chaque commande retourne un code de sortie. Vérifiez-le immédiatement après l'exécution.

```bash
ls /existing/path
echo $?    # 0 = Succès

ls /nonexistent/path
echo $?    # 2 = Erreur (Fichier inexistant)
```

| Code | Signification |
|------|---------|
| `0` | Succès |
| `1` | Erreur générale |
| `2` | Mauvaise utilisation de commande shell |
| `126` | Permission refusée |
| `127` | Commande non trouvée |
| `130` | Interrompu (Ctrl+C) |

```bash
# Utilisation dans les scripts
if [ $? -eq 0 ]; then
    echo "Commande réussie"
else
    echo "Commande échouée"
fi

# Ou plus court
command && echo "Succès" || echo "Échec"
```

### Arguments de Script

```bash
#!/bin/bash
# Sauvegarder sous : myscript.sh

echo "Nom du script: $0"
echo "Premier arg:   $1"
echo "Second arg:    $2"
echo "Tous les args: $@"
echo "Nombre args:   $#"
```

```bash
./myscript.sh hello world

# Output:
# Nom du script: ./myscript.sh
# Premier arg:   hello
# Second arg:    world
# Tous les args: hello world
# Nombre args:   2
```

| Variable | Description |
|----------|-------------|
| `$0` | Nom du script |
| `$1` - `$9` | Arguments positionnels |
| `${10}` | 10e+ argument (accolades requises) |
| `$@` | Tous les arguments (comme chaînes séparées) |
| `$*` | Tous les arguments (comme chaîne unique) |
| `$#` | Nombre d'arguments |
| `$$` | PID du processus actuel |
| `$!` | PID du dernier processus en arrière-plan |

---

## Redirections (La Plomberie)

### Redirection de Sortie

```bash
# Écraser le fichier (crée si inexistant)
echo "Hello" > file.txt

# Ajouter au fichier
echo "World" >> file.txt

# Rediriger STDERR (2)
command 2> errors.log

# Rediriger STDOUT et STDERR vers le même fichier
command > output.log 2>&1
command &> output.log    # Raccourci (Bash 4+)

# Ignorer la sortie
command > /dev/null 2>&1
command &> /dev/null     # Raccourci
```

### Redirection d'Entrée

```bash
# Lire depuis un fichier
grep "pattern" < file.txt

# Identique à (mais techniquement différent)
grep "pattern" file.txt
```

### Pipes (`|`)

La sortie de la commande A devient l'entrée de la commande B.

```bash
# Enchaîner les commandes
cat /var/log/syslog | grep "error" | wc -l

# Modèles courants
ps aux | grep nginx
history | tail -20
df -h | grep /dev/sda
cat file.txt | sort | uniq
```

### Heredoc (`<< EOF`)

Entrée multi-ligne. **Critique pour générer des fichiers de configuration dans les scripts.**

```bash
# Heredoc basique
cat << EOF
Ceci est la ligne 1
Ceci est la ligne 2
Variable: $HOME
EOF

# Écrire dans un fichier
cat << EOF > /etc/myapp/config.conf
server=localhost
port=8080
user=$USER
EOF

# Empêcher l'expansion des variables (quoter EOF)
cat << 'EOF' > script.sh
echo $HOME    # $HOME littéral, non expansé
EOF
```

!!! tip "Heredoc dans les Scripts"
    Parfait pour :

    - Générer des fichiers de configuration
    - Requêtes SQL multi-lignes
    - Créer des scripts dans des scripts
    - Commandes SSH distantes

    ```bash
    ssh user@server << 'EOF'
    cd /var/www
    git pull
    systemctl restart app
    EOF
    ```

---

## Opérateurs de Contrôle

### AND (`&&`)

Exécuter la seconde commande **UNIQUEMENT si la première réussit** (code de sortie 0).

```bash
# Déployer uniquement si les tests passent
./run_tests.sh && ./deploy.sh

# Créer un répertoire et y entrer
mkdir myproject && cd myproject

# Mise à jour et upgrade
apt update && apt upgrade -y
```

### OR (`||`)

Exécuter la seconde commande **UNIQUEMENT si la première échoue** (code de sortie != 0).

```bash
# Comportement de secours
ping -c 1 server1 || ping -c 1 server2

# Modèle de valeur par défaut
grep "config" file.txt || echo "Non trouvé"

# Sortir en cas d'échec
cd /important/dir || exit 1
```

### Combiner AND/OR

```bash
# Message de succès ou erreur
command && echo "Terminé !" || echo "Échec !"

# S'assurer que le répertoire existe
[ -d "$DIR" ] || mkdir -p "$DIR"

# Essayer primaire, sinon secondaire
wget "$URL1" && echo "Téléchargé depuis primaire" || wget "$URL2"
```

### Arrière-plan (`&`)

Exécuter la commande en arrière-plan, ne pas bloquer le terminal.

```bash
# Exécuter en arrière-plan
./long_task.sh &

# Obtenir son PID
echo $!

# Exécuter plusieurs en parallèle
./task1.sh &
./task2.sh &
./task3.sh &
wait    # Attendre tous les jobs en arrière-plan

# Détacher (continue après fermeture du terminal)
./server.sh &
disown
```

---

## Référence Rapide

| Symbole | Nom | Usage |
|--------|------|---------|
| `$?` | Code de sortie | Résultat de la commande précédente |
| `$1-$9` | Args | Paramètres du script |
| `$@` | Tous les args | Liste d'arguments |
| `$#` | Nombre args | Nombre d'arguments |
| `$$` | PID | ID du processus actuel |
| `>` | Rediriger | Écraser le fichier |
| `>>` | Ajouter | Ajouter au fichier |
| `2>` | STDERR | Rediriger les erreurs |
| `&>` | Les deux | STDOUT + STDERR |
| `<` | Entrée | Lire depuis fichier |
| `<<` | Heredoc | Entrée multi-ligne |
| `\|` | Pipe | Enchaîner les commandes |
| `&&` | AND | Si succès, alors |
| `\|\|` | OR | Si échec, alors |
| `&` | Arrière-plan | Ne pas bloquer |

---

## Exemples Pratiques

```bash
#!/bin/bash
# Script de sauvegarde avec gestion d'erreur appropriée

BACKUP_DIR="/backup"
SOURCE="/var/www"
DATE=$(date +%Y%m%d)

# S'assurer que le répertoire de sauvegarde existe
[ -d "$BACKUP_DIR" ] || mkdir -p "$BACKUP_DIR"

# Créer la sauvegarde, logger les erreurs
tar -czf "$BACKUP_DIR/www_$DATE.tar.gz" "$SOURCE" 2>> /var/log/backup.log \
    && echo "Sauvegarde réussie" \
    || { echo "Sauvegarde échouée"; exit 1; }

# Nettoyer les anciennes sauvegardes (garder les 7 dernières)
find "$BACKUP_DIR" -name "*.tar.gz" -mtime +7 -delete
```
