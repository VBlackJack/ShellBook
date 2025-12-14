---
tags:
  - tutos
  - storage
  - restic
  - backup
  - deduplication
  - debian
---

# Restic sur Debian 12

Installation de **Restic** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Restic | Latest |

**Durée estimée :** 15 minutes

---

## 1. Installation

```bash
apt update
apt install -y restic
```

Ou dernière version :

```bash
wget https://github.com/restic/restic/releases/latest/download/restic_0.16.2_linux_amd64.bz2
bunzip2 restic_0.16.2_linux_amd64.bz2
mv restic_0.16.2_linux_amd64 /usr/local/bin/restic
chmod +x /usr/local/bin/restic
```

---

## 2. Initialiser le repository

### Local

```bash
export RESTIC_REPOSITORY=/backup/restic
export RESTIC_PASSWORD="secret_password"

restic init
```

### S3

```bash
export AWS_ACCESS_KEY_ID="access_key"
export AWS_SECRET_ACCESS_KEY="secret_key"
export RESTIC_REPOSITORY="s3:http://minio:9000/backup"
export RESTIC_PASSWORD="secret_password"

restic init
```

---

## 3. Configuration

```bash
mkdir -p /etc/restic
echo "secret_password" > /root/.restic-password
chmod 600 /root/.restic-password

cat > /etc/restic/env << 'EOF'
export RESTIC_REPOSITORY=/backup/restic
export RESTIC_PASSWORD_FILE=/root/.restic-password
EOF
```

---

## 4. Backup

```bash
source /etc/restic/env

restic backup /home /etc /var/www \
  --exclude="*.tmp" \
  --exclude=".cache"
```

---

## 5. Restauration

```bash
# Dernier snapshot
restic restore latest --target /restore/

# Snapshot spécifique
restic restore abc123 --target /restore/

# Fichiers spécifiques
restic restore latest --target /restore/ --include "/home/user"
```

---

## 6. Lister les snapshots

```bash
restic snapshots
restic snapshots --host $(hostname)
```

---

## 7. Retention

```bash
restic forget \
  --keep-last 7 \
  --keep-daily 7 \
  --keep-weekly 4 \
  --keep-monthly 12 \
  --prune
```

---

## 8. Script automatisé

```bash
cat > /opt/restic-backup.sh << 'EOF'
#!/bin/bash
source /etc/restic/env

restic backup /home /etc --tag daily
restic forget --keep-last 7 --keep-daily 7 --prune
restic check
EOF

chmod +x /opt/restic-backup.sh
```

---

## 9. Systemd timer

```bash
cat > /etc/systemd/system/restic-backup.service << 'EOF'
[Unit]
Description=Restic Backup

[Service]
Type=oneshot
ExecStart=/opt/restic-backup.sh
EOF

cat > /etc/systemd/system/restic-backup.timer << 'EOF'
[Unit]
Description=Daily Restic Backup

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now restic-backup.timer
```

---

## 10. Mount FUSE

```bash
apt install -y fuse
mkdir /mnt/restic
restic mount /mnt/restic &

ls /mnt/restic/snapshots/
fusermount -u /mnt/restic
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | epel-release + dnf | apt |
| FUSE | dnf install fuse | apt install fuse |
| Config | Identique | Identique |

---

## Commandes

```bash
# Stats
restic stats

# Vérifier
restic check

# Diff
restic diff snap1 snap2

# Unlock
restic unlock

# Debug
restic -v backup /home
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
