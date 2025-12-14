---
tags:
  - tutos
  - storage
  - backup
  - borg
  - debian
---

# Borg Backup sur Debian 12

Configuration de **BorgBackup** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| BorgBackup | 1.2+ |

**Durée estimée :** 30 minutes

---

## 1. Installation

```bash
apt update
apt install -y borgbackup

# Version
borg --version
```

---

## 2. Configuration serveur (stockage)

```bash
# Utilisateur dédié
useradd -m -s /bin/bash borg
passwd borg

# Stockage
mkdir -p /backup/repos
chown borg:borg /backup/repos
```

---

## 3. Authentification SSH

```bash
# Client : générer clé
ssh-keygen -t ed25519 -f ~/.ssh/borg_key -N ""
ssh-copy-id -i ~/.ssh/borg_key.pub borg@backup-server
```

```bash
# Serveur : restreindre dans authorized_keys
command="borg serve --restrict-to-path /backup/repos",restrict ssh-ed25519 AAAAC3... user@client
```

---

## 4. Initialiser repository

```bash
export BORG_RSH="ssh -i ~/.ssh/borg_key"
export BORG_REPO="borg@backup-server:/backup/repos/client1"

borg init --encryption=repokey-blake2 $BORG_REPO

# IMPORTANT : exporter la clé
borg key export $BORG_REPO ~/borg-key-backup.txt
```

---

## 5. Créer des sauvegardes

```bash
export BORG_PASSPHRASE="motdepasse"

borg create \
    --stats \
    --progress \
    --compression zstd,5 \
    --exclude '*/.cache' \
    --exclude '*.log' \
    ::backup-{now:%Y-%m-%d_%H-%M} \
    /etc \
    /home \
    /var/www
```

---

## 6. Script automatisé

```bash
cat > /usr/local/bin/borg-backup.sh << 'EOF'
#!/bin/bash
export BORG_RSH="ssh -i /root/.ssh/borg_key"
export BORG_REPO="borg@backup-server:/backup/repos/$(hostname)"
export BORG_PASSPHRASE="$(cat /root/.borg-passphrase)"

LOG="/var/log/borg-backup.log"
exec > >(tee -a $LOG) 2>&1
echo "========== $(date) =========="

# Sauvegarde
borg create \
    --stats \
    --compression zstd,5 \
    --exclude-from /etc/borg/exclude.txt \
    ::{hostname}-{now:%Y-%m-%d_%H-%M} \
    /etc /home /var/www /var/lib/mysql

# Purge
borg prune \
    --keep-daily=7 \
    --keep-weekly=4 \
    --keep-monthly=6

echo "Terminé"
EOF

chmod 700 /usr/local/bin/borg-backup.sh
```

---

## 7. Exclusions

```bash
mkdir -p /etc/borg
cat > /etc/borg/exclude.txt << 'EOF'
*/.cache
*/cache
*.tmp
*.log
/var/log
/proc
/sys
/dev
/run
/tmp
*/node_modules
*/__pycache__
EOF
```

---

## 8. Systemd Timer

```bash
cat > /etc/systemd/system/borg-backup.service << 'EOF'
[Unit]
Description=Borg Backup

[Service]
Type=oneshot
ExecStart=/usr/local/bin/borg-backup.sh
Nice=19
EOF

cat > /etc/systemd/system/borg-backup.timer << 'EOF'
[Unit]
Description=Borg Backup Timer

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now borg-backup.timer
```

---

## 9. Restauration

```bash
# Lister
borg list ::

# Monter pour explorer
mkdir /mnt/borg
borg mount ::backup-2024-12-15_02-00 /mnt/borg
ls /mnt/borg/
borg umount /mnt/borg

# Restaurer
cd /
borg extract ::backup-2024-12-15_02-00 home/user/documents
```

---

## 10. Rétention

```bash
borg prune \
    --keep-daily=7 \
    --keep-weekly=4 \
    --keep-monthly=12 \
    --keep-yearly=2
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | epel-release + borgbackup | borgbackup |
| Version | 1.2.x | 1.2.x |
| Timer | systemd | systemd |

---

## Commandes

```bash
borg info ::                  # Info repo
borg list ::                  # Lister archives
borg check ::                 # Vérifier intégrité
borg compact ::               # Compacter
borg break-lock ::            # Débloquer
borg key export :: key.txt    # Exporter clé
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
