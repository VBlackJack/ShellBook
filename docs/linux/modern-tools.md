---
tags:
  - iproute2
  - net-tools
  - modern-tools
  - network
  - migration
---

# Remplacements Modernes (Legacy vs Nouveau)

Arrêtez d'utiliser les `net-tools` obsolètes. Passez à `iproute2` et aux alternatives modernes.

---

## Commandes Réseau : net-tools → iproute2

!!! danger "Avertissement de Dépréciation"
    `net-tools` (ifconfig, netstat, route) est déprécié et non maintenu depuis 2001.
    Utilisez `iproute2` pour les noyaux modernes et les nouvelles fonctionnalités.

| Legacy (net-tools) | Moderne (iproute2) | Usage |
|--------------------|-------------------|---------|
| `ifconfig` | `ip addr` / `ip a` | Afficher les adresses IP |
| `ifconfig eth0 up` | `ip link set eth0 up` | Activer l'interface |
| `netstat -tulpn` | `ss -tulpn` | Afficher les ports en écoute |
| `netstat -an` | `ss -an` | Toutes les connexions |
| `route -n` | `ip route` / `ip r` | Afficher la table de routage |
| `route add` | `ip route add` | Ajouter une route |
| `arp -a` | `ip neigh` | Table ARP |
| `hostname -I` | `ip -br addr` | Résumé IP concis |

### Exemples Rapides

```bash
# Afficher toutes les IPs (format concis)
ip -br addr

# Afficher uniquement IPv4
ip -4 addr

# Afficher TCP/UDP en écoute avec noms de processus
ss -tulpn

# Afficher les connexions établies
ss -t state established
```

---

## Monitoring Processus : top → htop/btop

| Outil | Installation | Fonctionnalités |
|------|---------|----------|
| `top` | Intégré | Basique, pas de souris |
| `htop` | `dnf install htop` | Couleurs, souris, vue arbre, kill processus |
| `btop` | `dnf install btop` | UI moderne, graphiques, thèmes |

```bash
# Installer les alternatives modernes
sudo dnf install htop btop    # RHEL/Rocky/Fedora
sudo apt install htop btop    # Debian/Ubuntu
```

!!! tip "Raccourcis htop"
    - `F5` → Vue arbre
    - `F6` → Trier par colonne
    - `F9` → Tuer le processus
    - `t` → Basculer arbre
    - `H` → Masquer les threads utilisateur

---

## Recherche de Fichiers : find → fd

`fd` est une alternative rapide et conviviale à `find`.

| Tâche | find | fd |
|------|------|-----|
| Chercher par nom | `find . -name "*.log"` | `fd ".log$"` |
| Insensible à la casse | `find . -iname "*.LOG"` | `fd -i ".log$"` |
| Trouver répertoires | `find . -type d -name config` | `fd -t d config` |
| Exclure répertoire | `find . -path ./node_modules -prune -o -name "*.js"` | `fd -E node_modules ".js$"` |

```bash
# Installer fd
sudo dnf install fd-find      # RHEL/Rocky/Fedora
sudo apt install fd-find      # Debian/Ubuntu (binaire: fdfind)

# Créer un alias si nécessaire (Debian/Ubuntu)
alias fd='fdfind'
```

---

## Recherche de Texte : grep → ripgrep

`ripgrep` (`rg`) est significativement plus rapide que `grep` pour les grandes bases de code.

```bash
# Installer
sudo dnf install ripgrep      # RHEL/Rocky/Fedora
sudo apt install ripgrep      # Debian/Ubuntu

# Utilisation
rg "pattern"                  # Récursif par défaut
rg -i "error"                 # Insensible à la casse
rg -t py "import"             # Seulement fichiers Python
rg --hidden "secret"          # Inclure fichiers cachés
rg -C 3 "error"               # 3 lignes de contexte
rg -l "TODO"                  # Seulement les noms de fichiers
rg -c "error"                 # Compter les occurrences
```

| Tâche | grep | ripgrep |
|-------|------|---------|
| Recherche récursive | `grep -r "pattern" .` | `rg "pattern"` |
| Ignorer la casse | `grep -ri "pattern"` | `rg -i "pattern"` |
| Fichiers avec match | `grep -rl "pattern"` | `rg -l "pattern"` |
| Exclure répertoire | `grep -r --exclude-dir=node_modules` | `rg "pattern"` (auto) |
| Contexte | `grep -C 3 "pattern"` | `rg -C 3 "pattern"` |

---

## Affichage de Fichiers : cat → bat

`bat` est un clone de `cat` avec coloration syntaxique et numéros de ligne.

```bash
# Installer
sudo dnf install bat          # RHEL/Rocky/Fedora
sudo apt install bat          # Debian/Ubuntu (binaire: batcat)

# Créer un alias si nécessaire (Debian/Ubuntu)
alias bat='batcat'
```

```bash
# Utilisation
bat config.yaml               # Coloration syntaxique auto
bat -n script.sh              # Numéros de ligne uniquement
bat -A file.txt               # Afficher caractères invisibles
bat --diff file1 file2        # Mode diff
bat -l json data.txt          # Forcer le langage
bat --style=plain file.txt    # Sans décorations
```

| Tâche | cat | bat |
|-------|-----|-----|
| Afficher fichier | `cat file` | `bat file` |
| Avec numéros | `cat -n file` | `bat file` (par défaut) |
| Sans numéros | `cat file` | `bat -p file` |
| Plusieurs fichiers | `cat f1 f2` | `bat f1 f2` |

!!! tip "Configuration ~/.config/bat/config"
    ```bash
    --theme="Dracula"
    --style="numbers,changes,header"
    --map-syntax "*.conf:INI"
    ```

---

## Listing de Fichiers : ls → eza/lsd

`eza` (anciennement `exa`) et `lsd` sont des remplacements modernes de `ls` avec icônes et couleurs.

```bash
# Installer eza
sudo dnf install eza          # Fedora
cargo install eza             # Via Rust

# Installer lsd
sudo dnf install lsd          # Fedora
sudo apt install lsd          # Debian/Ubuntu
```

```bash
# eza
eza                           # Liste simple
eza -l                        # Liste longue
eza -la                       # Avec fichiers cachés
eza -lah                      # Avec tailles humaines
eza --tree -L 2               # Vue arbre (2 niveaux)
eza --git                     # Statut Git
eza --icons                   # Avec icônes (nécessite Nerd Font)

# lsd
lsd                           # Liste avec icônes
lsd -la                       # Liste complète
lsd --tree                    # Vue arbre
```

| Tâche | ls | eza | lsd |
|-------|-----|-----|-----|
| Liste | `ls` | `eza` | `lsd` |
| Liste longue | `ls -l` | `eza -l` | `lsd -l` |
| Avec cachés | `ls -la` | `eza -la` | `lsd -la` |
| Arbre | `tree` | `eza --tree` | `lsd --tree` |
| Par date | `ls -lt` | `eza -l --sort=modified` | `lsd -lt` |

---

## JSON : jq

`jq` est indispensable pour manipuler du JSON en ligne de commande.

```bash
# Installer
sudo dnf install jq           # RHEL/Rocky/Fedora
sudo apt install jq           # Debian/Ubuntu
```

```bash
# Formater du JSON
echo '{"name":"test"}' | jq .

# Extraire un champ
cat data.json | jq '.name'
cat data.json | jq '.users[0].email'

# Filtrer
cat servers.json | jq '.[] | select(.status == "running")'

# Transformer
cat data.json | jq '{hostname: .name, ip: .address}'

# Depuis une API
curl -s https://api.github.com/users/octocat | jq '.login, .name'
```

---

## Diff : diff → delta

`delta` offre une sortie diff avec coloration syntaxique.

```bash
# Installer
sudo dnf install git-delta    # Fedora
# Ou télécharger depuis https://github.com/dandavison/delta
```

```bash
# Configuration Git (~/.gitconfig)
[core]
    pager = delta

[interactive]
    diffFilter = delta --color-only

[delta]
    navigate = true
    side-by-side = true
    line-numbers = true
```

---

## Disk Usage : du → dust/duf

### dust (du + rust)

```bash
# Installer
cargo install du-dust
# Ou télécharger depuis https://github.com/bootandy/dust
```

```bash
# Utilisation
dust                          # Arbre visuel des tailles
dust -d 2                     # Profondeur 2
dust -r                       # Ordre inverse
dust /var/log                 # Répertoire spécifique
```

### duf (disk usage/free)

```bash
# Installer
sudo dnf install duf          # Fedora
sudo apt install duf          # Debian/Ubuntu
```

```bash
# Utilisation
duf                           # Vue tableau des disques
duf /home                     # Répertoire spécifique
duf --only local              # Seulement disques locaux
```

---

## Résumé : Tableau Complet

| Catégorie | Legacy | Moderne | Installation |
|-----------|--------|---------|--------------|
| **Réseau** | `ifconfig` | `ip` | Intégré |
| **Ports** | `netstat` | `ss` | Intégré |
| **Processus** | `top` | `htop` / `btop` | `dnf install htop btop` |
| **Recherche fichiers** | `find` | `fd` | `dnf install fd-find` |
| **Recherche texte** | `grep` | `rg` (ripgrep) | `dnf install ripgrep` |
| **Affichage** | `cat` | `bat` | `dnf install bat` |
| **Listing** | `ls` | `eza` / `lsd` | `dnf install eza lsd` |
| **JSON** | - | `jq` | `dnf install jq` |
| **Diff** | `diff` | `delta` | `dnf install git-delta` |
| **Disk usage** | `du` | `dust` / `duf` | `dnf install duf` |

---

## Script d'Installation Complète

```bash
#!/bin/bash
# install-modern-tools.sh

echo "Installing modern CLI tools..."

# Détecter le gestionnaire de paquets
if command -v dnf &> /dev/null; then
    PKG="dnf"
elif command -v apt &> /dev/null; then
    PKG="apt"
else
    echo "Unsupported package manager"
    exit 1
fi

# Installation
sudo $PKG install -y \
    htop \
    btop \
    ripgrep \
    fd-find \
    bat \
    jq \
    duf

# Alias pour Debian/Ubuntu
if [ "$PKG" = "apt" ]; then
    echo "alias fd='fdfind'" >> ~/.bashrc
    echo "alias bat='batcat'" >> ~/.bashrc
fi

echo "Done! Restart your shell or run: source ~/.bashrc"
```

---

## Alias Recommandés

```bash
# ~/.bashrc ou ~/.bash_aliases

# Remplacements modernes
alias cat='bat --paging=never'
alias ls='eza --icons'
alias ll='eza -la --icons'
alias lt='eza -la --icons --sort=modified'
alias tree='eza --tree --icons'
alias grep='rg'
alias find='fd'
alias top='btop'
alias du='dust'
alias df='duf'

# Garder les originaux accessibles
alias ocat='/usr/bin/cat'
alias ols='/usr/bin/ls'
alias ogrep='/usr/bin/grep'
alias ofind='/usr/bin/find'
```
