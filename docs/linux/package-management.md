# APT & Package Management

`#apt` `#dpkg` `#repository` `#updates`

Gestion des paquets sur Debian, Ubuntu et dérivés.

---

## Le Cycle de Vie APT

### Les 3 Étapes

```
┌──────────────────────────────────────────────────────────────┐
│                    CYCLE DE MISE À JOUR                       │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  1. UPDATE        2. UPGRADE           3. FULL-UPGRADE        │
│  ─────────────    ─────────────        ─────────────          │
│  Rafraîchir       Mettre à jour        Mise à jour            │
│  le cache         les paquets          intelligente           │
│  (métadonnées)    (conservateur)       (+ dépendances)        │
│                                                               │
│  apt update   →   apt upgrade      →   apt full-upgrade       │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

| Commande | Action | Risque |
|----------|--------|--------|
| `apt update` | Télécharge la liste des paquets disponibles | Aucun |
| `apt upgrade` | Met à jour les paquets, **ne supprime rien** | Faible |
| `apt full-upgrade` | Met à jour + peut supprimer des paquets obsolètes | Moyen |
| `apt dist-upgrade` | Alias de full-upgrade (ancien nom) | Moyen |

```bash
# Workflow standard
sudo apt update && sudo apt upgrade -y

# Mise à jour complète (nouveau kernel, etc.)
sudo apt update && sudo apt full-upgrade -y
```

---

### apt vs apt-get

| `apt` | `apt-get` |
|-------|-----------|
| Interface moderne | Interface classique |
| Barre de progression | Output brut |
| Couleurs | Pas de couleurs |
| Recommandé pour l'interactif | Recommandé pour les scripts |

```bash
# Interactif (humain)
apt search nginx
apt install nginx

# Scripts (non-interactif, stable)
apt-get update
apt-get install -y nginx
```

!!! tip "Dans les scripts, utilisez apt-get"
    L'interface de `apt` peut changer entre versions.
    `apt-get` est garanti stable pour l'automatisation.

---

## Commandes de Survie

### Rechercher des Paquets

```bash
# Rechercher par nom ou description
apt search nginx
apt search "web server"

# Informations détaillées sur un paquet
apt show nginx

# Version disponible vs installée
apt policy nginx

# Lister les fichiers d'un paquet (avant install)
apt-file list nginx

# Installer apt-file si nécessaire
sudo apt install apt-file
sudo apt-file update
```

### Installer / Supprimer

```bash
# Installer
sudo apt install nginx
sudo apt install nginx php-fpm mariadb-server   # Plusieurs paquets

# Installer sans confirmation
sudo apt install -y nginx

# Installer une version spécifique
sudo apt install nginx=1.18.0-0ubuntu1

# Réinstaller (réparer)
sudo apt install --reinstall nginx

# Supprimer (garde la config)
sudo apt remove nginx

# Supprimer complètement (config incluse)
sudo apt purge nginx

# Supprimer + dépendances orphelines
sudo apt purge nginx && sudo apt autoremove -y
```

### Nettoyer

```bash
# Supprimer les paquets orphelins (plus nécessaires)
sudo apt autoremove -y

# Vider le cache des .deb téléchargés
sudo apt clean

# Vider uniquement les anciennes versions
sudo apt autoclean

# Espace utilisé par le cache
du -sh /var/cache/apt/archives/
```

### Lister les Paquets

```bash
# Tous les paquets installés
apt list --installed

# Paquets avec mise à jour disponible
apt list --upgradable

# Filtrer par pattern
apt list --installed | grep nginx

# Compter les paquets installés
apt list --installed 2>/dev/null | wc -l
```

### Trouver un Paquet par Fichier

```bash
# Quel paquet a installé ce fichier ?
dpkg -S /bin/ls
# Output: coreutils: /bin/ls

dpkg -S /usr/bin/curl
# Output: curl: /usr/bin/curl

# Chercher dans tous les paquets (même non installés)
apt-file search /bin/netstat
# Output: net-tools: /bin/netstat
```

### Informations sur un Paquet Installé

```bash
# Status d'un paquet
dpkg -s nginx

# Fichiers installés par un paquet
dpkg -L nginx

# Liste des paquets installés (dpkg)
dpkg -l
dpkg -l | grep nginx
```

---

## Gestion des Sources (Repositories)

### Fichiers de Configuration

| Fichier/Dossier | Usage |
|-----------------|-------|
| `/etc/apt/sources.list` | Sources principales (distro) |
| `/etc/apt/sources.list.d/` | Sources additionnelles (un fichier par repo) |
| `/etc/apt/keyrings/` | Clés GPG des repos (méthode moderne) |

### Format d'une Ligne

```
deb [options] URL distribution composants
```

**Exemple :**

```bash
# Format standard
deb http://deb.debian.org/debian bookworm main contrib non-free

# Avec architecture spécifique
deb [arch=amd64] http://deb.debian.org/debian bookworm main

# Avec clé GPG (méthode moderne)
deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian bookworm stable
```

| Élément | Description |
|---------|-------------|
| `deb` | Paquets binaires (`deb-src` = sources) |
| `[arch=amd64]` | Architecture (optionnel) |
| `[signed-by=...]` | Chemin vers la clé GPG |
| URL | Adresse du dépôt |
| Distribution | `bookworm`, `jammy`, `stable`, etc. |
| Composants | `main`, `contrib`, `non-free`, `universe` |

---

### Ajouter un Dépôt Tiers (Méthode Moderne)

!!! tip "Méthode Propre vs add-apt-repository"
    `add-apt-repository` est pratique mais opaque.
    La méthode manuelle est plus transparente et recommandée en production.

**Exemple : Ajouter le dépôt Docker**

```bash
# 1. Installer les prérequis
sudo apt install -y ca-certificates curl gnupg

# 2. Créer le dossier pour les clés
sudo install -m 0755 -d /etc/apt/keyrings

# 3. Télécharger et convertir la clé GPG
curl -fsSL https://download.docker.com/linux/debian/gpg | \
    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# 4. Ajuster les permissions
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# 5. Ajouter le dépôt (fichier séparé)
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
    https://download.docker.com/linux/debian $(lsb_release -cs) stable" | \
    sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# 6. Mettre à jour et installer
sudo apt update
sudo apt install docker-ce
```

**Structure résultante :**

```
/etc/apt/
├── sources.list                 # Sources distro
├── sources.list.d/
│   └── docker.list              # Source Docker
└── keyrings/
    └── docker.gpg               # Clé GPG Docker
```

---

### Supprimer un Dépôt

```bash
# Supprimer le fichier de source
sudo rm /etc/apt/sources.list.d/docker.list

# Supprimer la clé GPG
sudo rm /etc/apt/keyrings/docker.gpg

# Rafraîchir
sudo apt update
```

---

### Dépôts Ubuntu vs Debian

**Ubuntu :**

```bash
# /etc/apt/sources.list
deb http://archive.ubuntu.com/ubuntu jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu jammy-security main restricted universe multiverse
```

| Composant | Contenu |
|-----------|---------|
| `main` | Logiciels libres supportés par Canonical |
| `restricted` | Drivers propriétaires |
| `universe` | Logiciels libres maintenus par la communauté |
| `multiverse` | Logiciels non-libres |

**Debian :**

```bash
# /etc/apt/sources.list
deb http://deb.debian.org/debian bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian bookworm-updates main contrib non-free
deb http://security.debian.org/debian-security bookworm-security main contrib non-free
```

| Composant | Contenu |
|-----------|---------|
| `main` | Logiciels 100% libres (DFSG) |
| `contrib` | Libres mais dépendent de non-libres |
| `non-free` | Logiciels non-libres |
| `non-free-firmware` | Firmwares propriétaires (Debian 12+) |

---

## Logs & Historique

### Fichiers de Logs

| Fichier | Contenu |
|---------|---------|
| `/var/log/apt/history.log` | Historique APT (lisible) |
| `/var/log/apt/term.log` | Output terminal des opérations |
| `/var/log/dpkg.log` | Log bas niveau dpkg |

### Consulter l'Historique

```bash
# Dernières opérations APT
cat /var/log/apt/history.log | tail -50

# Chercher une date spécifique
grep "2024-01-15" /var/log/apt/history.log

# Voir les upgrades récents
grep "Upgrade:" /var/log/apt/history.log | tail -10

# Historique dpkg (plus détaillé)
grep " install " /var/log/dpkg.log | tail -20
grep " upgrade " /var/log/dpkg.log | tail -20
grep " remove " /var/log/dpkg.log | tail -20
```

### Exemple de Log APT

```
Start-Date: 2024-01-15  10:30:00
Commandline: apt upgrade -y
Requested-By: admin (1000)
Upgrade: nginx:amd64 (1.18.0-0ubuntu1, 1.18.0-0ubuntu2)
End-Date: 2024-01-15  10:31:15
```

!!! warning "Après une mise à jour qui casse le système"
    ```bash
    # 1. Identifier le paquet problématique
    cat /var/log/apt/history.log | tail -100

    # 2. Downgrade si nécessaire
    sudo apt install nginx=1.18.0-0ubuntu1

    # 3. Bloquer la version (hold)
    sudo apt-mark hold nginx

    # 4. Débloquer plus tard
    sudo apt-mark unhold nginx
    ```

---

## Gestion des Versions

### Bloquer/Débloquer un Paquet

```bash
# Empêcher la mise à jour (hold)
sudo apt-mark hold nginx
sudo apt-mark hold linux-image-generic

# Lister les paquets bloqués
apt-mark showhold

# Débloquer
sudo apt-mark unhold nginx
```

### Installer une Version Spécifique

```bash
# Lister les versions disponibles
apt policy nginx
apt-cache madison nginx

# Installer une version précise
sudo apt install nginx=1.18.0-0ubuntu1

# Depuis un dépôt spécifique (priorité)
sudo apt install -t bookworm-backports nginx
```

---

## Quick Reference

```bash
# Mise à jour
sudo apt update                    # Rafraîchir cache
sudo apt upgrade -y                # Mettre à jour
sudo apt full-upgrade -y           # Mise à jour complète

# Recherche
apt search nginx                   # Chercher
apt show nginx                     # Détails
apt policy nginx                   # Versions

# Installation
sudo apt install nginx             # Installer
sudo apt remove nginx              # Supprimer
sudo apt purge nginx               # Supprimer + config

# Nettoyage
sudo apt autoremove -y             # Orphelins
sudo apt clean                     # Cache

# Infos
apt list --installed               # Paquets installés
dpkg -S /path/to/file              # Quel paquet ?
dpkg -L package                    # Fichiers d'un paquet

# Versions
sudo apt-mark hold package         # Bloquer
sudo apt-mark unhold package       # Débloquer

# Logs
cat /var/log/apt/history.log       # Historique
cat /var/log/dpkg.log              # Détails
```
