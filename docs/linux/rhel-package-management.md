---
tags:
  - dnf
  - rpm
  - modules
  - appstream
  - rollback
---

# DNF, RPM & Modules

## DNF : Le Gestionnaire de Paquets RHEL 8+

**DNF** (Dandified YUM) remplace YUM depuis RHEL 8. Il apporte les **modules AppStream**, un meilleur résolveur de dépendances et l'**historique transactionnel** avec rollback.

### Cycle de Vie DNF

```bash
# Mise à jour de la base de données des dépôts
dnf check-update

# Lister les mises à jour disponibles
dnf list updates

# Mettre à jour TOUT le système
dnf upgrade -y
# ou : dnf update -y (alias)

# Mettre à jour un paquet spécifique
dnf upgrade nginx -y

# Mettre à jour seulement les paquets de sécurité
dnf upgrade --security -y
```

### Installation & Suppression

```bash
# Installer un paquet
dnf install nginx -y

# Installer plusieurs paquets
dnf install vim git curl wget -y

# Installer un groupe de paquets
dnf groupinstall "Development Tools" -y

# Réinstaller un paquet (si corrompu)
dnf reinstall nginx -y

# Supprimer un paquet
dnf remove nginx -y

# Supprimer + dépendances orphelines
dnf autoremove -y
```

### Recherche de Paquets

```bash
# Chercher un paquet par nom
dnf search nginx

# Chercher avec des métadonnées étendues
dnf search all "web server"

# Lister tous les paquets disponibles
dnf list available

# Lister les paquets installés
dnf list installed

# Voir les infos d'un paquet
dnf info nginx

# Trouver quel paquet fournit un fichier
dnf provides /usr/sbin/nginx
# nginx-1:1.20.1-1.el9.x86_64 : High performance web server

dnf provides */semanage
# policycoreutils-python-utils-3.3-6.el9.noarch
```

### Gestion des Dépôts

```bash
# Lister les dépôts activés
dnf repolist

# Lister TOUS les dépôts (y compris désactivés)
dnf repolist --all

# Activer un dépôt
dnf config-manager --set-enabled epel

# Désactiver un dépôt
dnf config-manager --set-disabled epel

# Ajouter un dépôt tiers
dnf config-manager --add-repo https://example.com/repo.repo

# Installer depuis un dépôt spécifique
dnf install --enablerepo=epel htop
```

### Nettoyage

```bash
# Nettoyer le cache
dnf clean all

# Supprimer les paquets orphelins
dnf autoremove -y

# Lister les paquets orphelins (leaf packages)
dnf list extras

# Supprimer les vieux kernels (garder les 3 derniers)
dnf remove --oldinstallonly --setopt installonly_limit=3 kernel
```

## AppStream & Modules : La Killer Feature

**AppStream** permet d'avoir **plusieurs versions d'un logiciel** (ex: Python 3.9, 3.11, 3.12) installables en parallèle via des **modules**.

### Concepts Clés

- **Module** : Un ensemble de paquets (ex: `nodejs`)
- **Stream** : Une version majeure (ex: `18`, `20`)
- **Profile** : Un jeu de paquets pré-sélectionnés (ex: `default`, `development`)

```bash
# Lister tous les modules disponibles
dnf module list

# Chercher un module spécifique
dnf module list nodejs
# Name    Stream  Profiles              Summary
# nodejs  18      default, development  JavaScript runtime
# nodejs  20 [d]  default, development  JavaScript runtime (default)
```

### Installer un Module

```bash
# Installer le stream par défaut
dnf module install nodejs -y

# Vérifier la version installée
node --version
# v20.x.x

# Installer un stream spécifique
dnf module install nodejs:18 -y

# Installer avec un profile spécifique
dnf module install nodejs:18/development -y
```

### Changer de Stream (Reset)

```bash
# Situation : NodeJS 18 installé, besoin de passer à NodeJS 20

# 1. Voir le stream actuel
dnf module list nodejs
# nodejs  18 [e]  default [i]  # [e] = enabled, [i] = installed

# 2. Désactiver le stream actuel
dnf module reset nodejs -y

# 3. Activer le nouveau stream
dnf module enable nodejs:20 -y

# 4. Mettre à jour (ou installer si absent)
dnf distro-sync -y

# Vérifier
node --version
# v20.x.x
```

### Exemple Pratique : Python 3.9 → 3.11

```bash
# Voir les streams Python disponibles
dnf module list python3
# python39  3.9  common [d]
# python311 3.11 common

# Installer Python 3.11
dnf module install python311 -y

# Vérifier
python3.11 --version
# Python 3.11.x

# Créer un venv avec Python 3.11
python3.11 -m venv /opt/myapp/venv
```

### Désactiver un Module

```bash
# Supprimer les paquets du module
dnf module remove nodejs -y

# Réinitialiser (permet de changer de stream)
dnf module reset nodejs -y

# Désactiver complètement (empêche l'install)
dnf module disable nodejs -y
```

## Historique & Rollback : La Vraie Killer Feature

DNF enregistre **chaque transaction** et permet de revenir en arrière en cas de problème.

### Consulter l'Historique

```bash
# Lister les dernières transactions
dnf history
# ID  | Command line             | Date and time    | Action(s) | Altered
# ----|--------------------------|------------------|-----------|--------
# 15  | install nginx            | 2025-01-15 10:30 | Install   | 3
# 14  | upgrade                  | 2025-01-14 09:00 | Upgrade   | 45
# 13  | remove httpd             | 2025-01-13 14:20 | Removed   | 1

# Voir les détails d'une transaction
dnf history info 15
# Transaction ID : 15
# Begin time     : Wed 15 Jan 2025 10:30:00 AM CET
# Command line   : install nginx
# Packages Altered:
#   Install nginx-1:1.20.1-1.el9.x86_64
#   Install nginx-filesystem-1:1.20.1-1.el9.noarch
#   Dep-Install openssl-1:3.0.1-1.el9.x86_64

# Lister les paquets modifiés dans une transaction
dnf history list nginx
```

### Rollback : Annuler une Transaction

```bash
# Annuler la dernière transaction
dnf history undo last -y

# Annuler une transaction spécifique
dnf history undo 15 -y

# Refaire une transaction (redo)
dnf history redo 15 -y

# Revenir à un état précis (rollback)
dnf history rollback 10 -y
# ⚠️ Annule TOUTES les transactions depuis la 10 jusqu'à maintenant
```

!!! warning "Rollback de Kernel"
    Le rollback de kernel est **dangereux**. Préférez redémarrer avec un vieux kernel via GRUB :

    ```bash
    # Lister les kernels installés
    rpm -qa kernel
    # kernel-5.14.0-70.el9.x86_64
    # kernel-5.14.0-80.el9.x86_64

    # Définir le kernel par défaut (via GRUB)
    grubby --set-default /boot/vmlinuz-5.14.0-70.el9.x86_64

    # Ou au reboot, choisir manuellement dans GRUB
    ```

### Exemple : Sauver une Mise à Jour Cassée

```bash
# Scénario : dnf upgrade a cassé un service
dnf upgrade -y
systemctl status myapp
# Failed to start myapp.service

# Consulter l'historique
dnf history
# ID  | Command line  | Action(s) | Altered
# 42  | upgrade       | Upgrade   | 67 packages

# Annuler la mise à jour
dnf history undo 42 -y

# Vérifier
systemctl status myapp
# Active (running)

# Investiguer quel paquet a causé le problème
dnf history info 42 | grep myapp-dependency
```

## RPM : Gestion Bas Niveau

**RPM** est le format de paquet bas niveau (comme `.deb` sur Debian). DNF gère RPM, mais RPM peut être utilisé directement pour des tâches avancées.

### Queries RPM

```bash
# Lister tous les paquets installés
rpm -qa
# nginx-1.20.1-1.el9.x86_64
# vim-enhanced-8.2.2637-16.el9.x86_64

# Chercher un paquet spécifique
rpm -qa | grep nginx

# Voir les infos d'un paquet
rpm -qi nginx

# Lister les fichiers d'un paquet
rpm -ql nginx
# /usr/sbin/nginx
# /etc/nginx/nginx.conf
# /usr/share/nginx/html/index.html

# Trouver quel paquet fournit un fichier
rpm -qf /usr/sbin/nginx
# nginx-1.20.1-1.el9.x86_64

# Lister les fichiers de configuration d'un paquet
rpm -qc nginx
# /etc/nginx/nginx.conf
# /etc/nginx/mime.types

# Lister les scripts pré/post-installation
rpm -q --scripts nginx
```

### Vérifier l'Intégrité des Paquets

```bash
# Vérifier TOUS les paquets (lent)
rpm -Va
# S.5....T.  c /etc/passwd  # Modifié (normal)
# .M.......    /usr/bin/vim  # Permissions modifiées

# Vérifier un paquet spécifique
rpm -V nginx
# (Pas de sortie = OK)

# Légende :
# S : Size differs
# M : Mode differs (permissions)
# 5 : MD5 checksum differs
# D : Device differs
# L : Symlink differs
# U : User ownership differs
# G : Group ownership differs
# T : Modification time differs
```

### Installer/Supprimer un RPM Local

```bash
# Installer un .rpm téléchargé (avec dépendances)
dnf install ./paquet.rpm

# Ou avec rpm brut (SANS dépendances - déconseillé)
rpm -ivh paquet.rpm
# i : install, v : verbose, h : hash progress

# Mettre à jour
rpm -Uvh paquet-nouveau.rpm
# U : upgrade

# Supprimer
rpm -e paquet
```

### Extraire un RPM sans Installer

```bash
# Créer un répertoire de travail
mkdir /tmp/rpm-extract
cd /tmp/rpm-extract

# Extraire
rpm2cpio /path/to/paquet.rpm | cpio -idmv

# Les fichiers sont extraits dans ./
ls
# usr/
# etc/
```

## Createrepo : Dépôt Local

Utile pour les environnements **déconnectés** (air-gapped) ou pour distribuer des paquets custom.

### Créer un Dépôt Local

```bash
# Installer createrepo
dnf install createrepo_c -y

# Créer un répertoire pour le dépôt
mkdir -p /var/www/html/myrepo

# Copier les RPM
cp *.rpm /var/www/html/myrepo/

# Générer les métadonnées
createrepo /var/www/html/myrepo
# Spawning worker 0 with 5 pkgs
# Workers Finished
# Saving Primary metadata
# Saving file lists metadata
# Saving other metadata

# Servir via HTTP (Apache ou Python)
cd /var/www/html/myrepo
python3 -m http.server 8080
```

### Configurer un Client pour Utiliser le Dépôt

```bash
# Créer un fichier .repo
cat > /etc/yum.repos.d/myrepo.repo <<EOF
[myrepo]
name=My Local Repository
baseurl=http://192.168.1.100:8080
enabled=1
gpgcheck=0
EOF

# Vérifier
dnf repolist
# myrepo  My Local Repository  5

# Installer depuis le dépôt
dnf install mon-paquet-custom -y
```

### Mettre à Jour le Dépôt

```bash
# Ajouter de nouveaux RPM
cp nouveau.rpm /var/www/html/myrepo/

# Mettre à jour les métadonnées
createrepo --update /var/www/html/myrepo

# Les clients verront les nouveaux paquets
dnf clean all
dnf repolist
```

## Dépannage

### Réparer une Base RPM Corrompue

```bash
# Reconstruire la base RPM
rpm --rebuilddb

# Vérifier
rpm -qa | wc -l
# (Doit retourner un nombre)
```

### Résoudre les Conflits de Dépendances

```bash
# Simuler une installation (dry-run)
dnf install paquet --assumeno

# Forcer l'installation (dangereux)
rpm -ivh --nodeps paquet.rpm  # ⚠️ Casse les dépendances

# Downgrade d'un paquet
dnf downgrade nginx -y
```

### Vérifier la Signature GPG

```bash
# Importer une clé GPG
rpm --import https://repo.example.com/RPM-GPG-KEY

# Vérifier la signature d'un RPM
rpm --checksig paquet.rpm
# paquet.rpm: rsa sha1 (md5) pgp md5 OK

# Installer avec vérification stricte
dnf install paquet.rpm --setopt=gpgcheck=1
```

## Checklist Production

```bash
# 1. Mises à jour de sécurité automatiques
systemctl is-active dnf-automatic.timer  # active

# 2. Pas de paquets cassés
rpm -Va | grep "^missing"  # Vide

# 3. Dépôts configurés correctement
dnf repolist
# baseos, appstream, epel

# 4. Historique DNF propre (pas de rollback récent suspect)
dnf history | head -n 5

# 5. Vieux kernels nettoyés (garder 2-3 max)
rpm -qa kernel | wc -l  # <= 3

# 6. Espace disque suffisant (/var/cache/dnf)
df -h /var
# Use% <= 80%
```

## Aide-Mémoire DNF

| Tâche | Commande |
|-------|----------|
| Chercher un paquet | `dnf search nginx` |
| Installer | `dnf install nginx -y` |
| Supprimer | `dnf remove nginx -y` |
| Mettre à jour tout | `dnf upgrade -y` |
| Mettre à jour un paquet | `dnf upgrade nginx -y` |
| Lister les updates | `dnf check-update` |
| Historique | `dnf history` |
| Annuler dernière transaction | `dnf history undo last -y` |
| Lister les modules | `dnf module list` |
| Installer un module | `dnf module install nodejs:20 -y` |
| Reset un module | `dnf module reset nodejs -y` |
| Quel paquet fournit ce fichier ? | `dnf provides /usr/sbin/nginx` |
| Nettoyer le cache | `dnf clean all` |
| Supprimer les orphelins | `dnf autoremove -y` |

## Liens Utiles

- [DNF Documentation RHEL](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/managing_software_with_the_dnf_tool/)
- [AppStream Modules Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/installing_managing_and_removing_user-space_components/using-appstream_using-appstream)
- [RPM Packaging Guide](https://rpm-packaging-guide.github.io/)
- [Createrepo Documentation](https://github.com/rpm-software-management/createrepo_c)
