---
tags:
  - tutos
  - storage
  - backup
  - borg
  - rocky
---

# Borg Backup sur Rocky Linux 9

Configuration de **BorgBackup** pour des sauvegardes déduplicantes et chiffrées.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| BorgBackup | 1.2+ |

**Durée estimée :** 35 minutes

---

## Avantages de Borg

| Caractéristique | Description |
|-----------------|-------------|
| **Déduplication** | Économie d'espace (bloc par bloc) |
| **Compression** | LZ4, ZSTD, LZMA |
| **Chiffrement** | AES-256 côté client |
| **Intégrité** | Vérification HMAC-SHA256 |
| **Efficace** | Sauvegardes incrémentales rapides |

---

## Architecture

```
┌─────────────────┐          SSH          ┌─────────────────┐
│  Client Borg    │─────────────────────►│  Serveur Borg   │
│  (source)       │                       │  (repository)   │
│                 │                       │                 │
│  /etc           │                       │  /backup/repo   │
│  /home          │                       │  (dédupliqué)   │
│  /var/www       │                       │                 │
└─────────────────┘                       └─────────────────┘
```

---

## 1. Installation

### Sur le client (machine à sauvegarder)

```bash
dnf install -y epel-release
dnf install -y borgbackup
```

### Sur le serveur (stockage des backups)

```bash
dnf install -y epel-release
dnf install -y borgbackup

# Créer un utilisateur dédié
useradd -m -s /bin/bash borg
passwd borg

# Répertoire de stockage
mkdir -p /backup/repos
chown borg:borg /backup/repos
```

---

## 2. Authentification SSH

### Générer une clé SSH (client)

```bash
ssh-keygen -t ed25519 -f ~/.ssh/borg_key -N ""

# Copier sur le serveur
ssh-copy-id -i ~/.ssh/borg_key.pub borg@backup-server
```

### Restreindre la clé (serveur)

```bash
# Sur le serveur, éditer /home/borg/.ssh/authorized_keys
vim /home/borg/.ssh/authorized_keys
```

```
command="borg serve --restrict-to-path /backup/repos",restrict ssh-ed25519 AAAAC3... user@client
```

---

## 3. Initialiser un repository

### Repository local

```bash
borg init --encryption=repokey /backup/local-repo

# Exporter la clé (IMPORTANT - à sauvegarder ailleurs)
borg key export /backup/local-repo /root/borg-key-backup.txt
```

### Repository distant

```bash
export BORG_RSH="ssh -i ~/.ssh/borg_key"
export BORG_REPO="borg@backup-server:/backup/repos/client1"

borg init --encryption=repokey-blake2 $BORG_REPO

# Sauvegarder la clé
borg key export $BORG_REPO /root/borg-key-backup.txt
```

### Options de chiffrement

| Mode | Description |
|------|-------------|
| `none` | Pas de chiffrement |
| `repokey` | Clé dans le repo (AES) |
| `repokey-blake2` | Plus rapide (recommandé) |
| `keyfile` | Clé locale uniquement |

---

## 4. Créer des sauvegardes

### Sauvegarde basique

```bash
export BORG_REPO="borg@backup-server:/backup/repos/client1"
export BORG_PASSPHRASE="motdepasse-securise"

borg create --stats --progress \
    ::backup-{now:%Y-%m-%d_%H-%M} \
    /etc \
    /home \
    /var/www
```

### Avec compression et exclusions

```bash
borg create \
    --stats \
    --progress \
    --compression zstd,5 \
    --exclude '*.log' \
    --exclude '*.tmp' \
    --exclude '/home/*/.cache' \
    --exclude '/var/cache' \
    ::backup-{now:%Y-%m-%d_%H-%M} \
    /etc \
    /home \
    /var/www \
    /var/lib/mysql
```

### Exclusions recommandées

```bash
cat > /etc/borg/exclude.txt << 'EOF'
# Cache
*/.cache
*/cache
*.tmp
*.temp

# Logs
*.log
/var/log

# Compilations
*/__pycache__
*/node_modules
*/.npm
*/.gradle

# Systèmes de fichiers virtuels
/proc
/sys
/dev
/run
/tmp

# Sockets
*.sock
*.socket
EOF

borg create --exclude-from /etc/borg/exclude.txt ...
```

---

## 5. Script de sauvegarde automatisé

```bash
cat > /usr/local/bin/borg-backup.sh << 'EOF'
#!/bin/bash

# Configuration
export BORG_RSH="ssh -i /root/.ssh/borg_key"
export BORG_REPO="borg@backup-server:/backup/repos/$(hostname)"
export BORG_PASSPHRASE="$(cat /root/.borg-passphrase)"

# Logging
LOG="/var/log/borg-backup.log"
exec > >(tee -a $LOG) 2>&1
echo "========== $(date) =========="

# Vérifier la connexion
borg info :: > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERREUR: Impossible de se connecter au repository"
    exit 1
fi

# Créer la sauvegarde
echo "Démarrage de la sauvegarde..."
borg create \
    --stats \
    --compression zstd,5 \
    --exclude-from /etc/borg/exclude.txt \
    ::{hostname}-{now:%Y-%m-%d_%H-%M} \
    /etc \
    /home \
    /var/www \
    /var/lib/mysql

BACKUP_EXIT=$?

# Purger les anciennes sauvegardes
echo "Nettoyage des anciennes sauvegardes..."
borg prune \
    --keep-daily=7 \
    --keep-weekly=4 \
    --keep-monthly=6 \
    --stats

PRUNE_EXIT=$?

# Vérifier l'intégrité (hebdomadaire)
if [ "$(date +%u)" = "7" ]; then
    echo "Vérification d'intégrité..."
    borg check ::
fi

# Status final
if [ $BACKUP_EXIT -eq 0 ] && [ $PRUNE_EXIT -eq 0 ]; then
    echo "Sauvegarde terminée avec succès"
    exit 0
else
    echo "ERREUR: Sauvegarde échouée"
    exit 1
fi
EOF

chmod 700 /usr/local/bin/borg-backup.sh

# Sauvegarder la passphrase
echo "motdepasse-securise" > /root/.borg-passphrase
chmod 600 /root/.borg-passphrase
```

---

## 6. Planification (cron/systemd)

### Avec cron

```bash
crontab -e
```

```cron
# Sauvegarde quotidienne à 2h
0 2 * * * /usr/local/bin/borg-backup.sh
```

### Avec systemd timer

```bash
cat > /etc/systemd/system/borg-backup.service << 'EOF'
[Unit]
Description=Borg Backup
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/borg-backup.sh
Nice=19
IOSchedulingClass=idle
EOF

cat > /etc/systemd/system/borg-backup.timer << 'EOF'
[Unit]
Description=Run Borg Backup daily

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now borg-backup.timer
```

---

## 7. Lister et restaurer

### Lister les archives

```bash
borg list ::

# Détails d'une archive
borg info ::backup-2024-12-15_02-00

# Contenu d'une archive
borg list ::backup-2024-12-15_02-00
```

### Restaurer des fichiers

```bash
# Restaurer tout
cd /
borg extract ::backup-2024-12-15_02-00

# Restaurer un répertoire spécifique
borg extract ::backup-2024-12-15_02-00 home/user/documents

# Restaurer avec dry-run
borg extract --dry-run --list ::backup-2024-12-15_02-00

# Restaurer vers un autre emplacement
cd /tmp/restore
borg extract ::backup-2024-12-15_02-00
```

### Monter une archive

```bash
mkdir /mnt/borg
borg mount ::backup-2024-12-15_02-00 /mnt/borg

# Explorer
ls /mnt/borg/

# Démonter
borg umount /mnt/borg
```

---

## 8. Politique de rétention

```bash
borg prune \
    --keep-hourly=24 \    # 24 heures
    --keep-daily=7 \      # 7 jours
    --keep-weekly=4 \     # 4 semaines
    --keep-monthly=12 \   # 12 mois
    --keep-yearly=2 \     # 2 ans
    --stats \
    --list
```

---

## 9. Maintenance

### Vérifier l'intégrité

```bash
# Vérification rapide
borg check ::

# Vérification complète
borg check --verify-data ::
```

### Compacter le repository

```bash
# Borg 1.2+
borg compact ::
```

### Informations du repository

```bash
borg info ::

# Statistiques d'utilisation
borg info :: --json | jq '.cache.stats'
```

---

## 10. Sauvegarde de bases de données

### MariaDB/MySQL

```bash
# Dans le script avant borg create
mysqldump --all-databases --single-transaction > /var/backups/mysql-dump.sql

# Puis inclure /var/backups dans la sauvegarde Borg
```

### PostgreSQL

```bash
sudo -u postgres pg_dumpall > /var/backups/postgres-dump.sql
```

---

## Commandes utiles

```bash
# Info repository
borg info ::

# Liste archives
borg list ::

# Supprimer une archive
borg delete ::backup-2024-01-01

# Recréer l'index
borg check --repair ::

# Exporter la clé
borg key export :: /safe/location/key.txt

# Changer la passphrase
borg key change-passphrase ::
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Lock existant | `borg break-lock ::` |
| Erreur cache | `borg delete --cache-only ::` |
| Permission denied | Vérifier SSH et clés |
| Repository corrompu | `borg check --repair ::` |

```bash
# Debug
BORG_LOGGING_CONF=/dev/stderr borg list ::

# Verbose
borg create -v --stats ...
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
