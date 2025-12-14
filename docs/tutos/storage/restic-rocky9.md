---
tags:
  - tutos
  - storage
  - restic
  - backup
  - deduplication
  - rocky
---

# Restic sur Rocky Linux 9

Installation de **Restic** - outil de backup rapide et sécurisé.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Restic | Latest |

**Durée estimée :** 20 minutes

---

## Avantages Restic

| Caractéristique | Description |
|-----------------|-------------|
| **Chiffrement** | AES-256 |
| **Déduplication** | Au niveau bloc |
| **Multi-backend** | Local, S3, SFTP, REST... |
| **Rapide** | Backup incrémental |
| **Vérifiable** | Intégrité des données |

---

## 1. Installation

### Via package

```bash
dnf install -y epel-release
dnf install -y restic
```

### Via binaire

```bash
wget https://github.com/restic/restic/releases/latest/download/restic_0.16.2_linux_amd64.bz2
bunzip2 restic_0.16.2_linux_amd64.bz2
mv restic_0.16.2_linux_amd64 /usr/local/bin/restic
chmod +x /usr/local/bin/restic
```

### Mise à jour automatique

```bash
restic self-update
```

---

## 2. Initialiser un repository

### Repository local

```bash
export RESTIC_REPOSITORY=/backup/restic
export RESTIC_PASSWORD="super_secret_password"

restic init
```

### Repository S3 (MinIO/AWS)

```bash
export AWS_ACCESS_KEY_ID="minioadmin"
export AWS_SECRET_ACCESS_KEY="minioadmin123"
export RESTIC_REPOSITORY="s3:http://minio.example.com:9000/backup"
export RESTIC_PASSWORD="super_secret_password"

restic init
```

### Repository SFTP

```bash
export RESTIC_REPOSITORY="sftp:user@backup-server:/backup/restic"
export RESTIC_PASSWORD="super_secret_password"

restic init
```

---

## 3. Fichier de configuration

### Créer un fichier password

```bash
echo "super_secret_password" > /root/.restic-password
chmod 600 /root/.restic-password
```

### Variables d'environnement

```bash
cat > /etc/restic/env << 'EOF'
export RESTIC_REPOSITORY=/backup/restic
export RESTIC_PASSWORD_FILE=/root/.restic-password
EOF

chmod 600 /etc/restic/env
```

---

## 4. Backup

### Backup simple

```bash
source /etc/restic/env
restic backup /home /etc /var/www
```

### Avec exclusions

```bash
restic backup /home \
  --exclude="*.tmp" \
  --exclude=".cache" \
  --exclude="node_modules"
```

### Fichier d'exclusions

```bash
cat > /etc/restic/excludes << 'EOF'
*.tmp
*.log
.cache
node_modules
__pycache__
*.pyc
EOF

restic backup /home --exclude-file=/etc/restic/excludes
```

### Tags

```bash
restic backup /home --tag daily --tag server1
```

---

## 5. Lister les snapshots

```bash
source /etc/restic/env

# Tous les snapshots
restic snapshots

# Par host
restic snapshots --host server1

# Par tag
restic snapshots --tag daily

# Format JSON
restic snapshots --json
```

---

## 6. Restauration

### Restaurer complètement

```bash
restic restore latest --target /restore/
```

### Restaurer un snapshot spécifique

```bash
restic restore abc123 --target /restore/
```

### Restaurer des fichiers spécifiques

```bash
restic restore latest --target /restore/ --include "/home/user/documents"
```

### Dump d'un fichier

```bash
restic dump latest /etc/passwd > /tmp/passwd.restored
```

---

## 7. Mount (accès FUSE)

```bash
dnf install -y fuse

mkdir -p /mnt/restic
restic mount /mnt/restic &

# Naviguer dans les snapshots
ls /mnt/restic/snapshots/

# Démonter
fusermount -u /mnt/restic
```

---

## 8. Retention et pruning

### Supprimer les anciens snapshots

```bash
restic forget \
  --keep-last 7 \
  --keep-daily 7 \
  --keep-weekly 4 \
  --keep-monthly 12 \
  --keep-yearly 3 \
  --prune
```

### Dry-run

```bash
restic forget --keep-last 7 --dry-run
```

---

## 9. Vérification

### Vérifier l'intégrité

```bash
# Structure du repo
restic check

# Données complètes (long)
restic check --read-data

# Échantillon de données
restic check --read-data-subset=5%
```

---

## 10. Script de backup automatisé

```bash
cat > /opt/restic-backup.sh << 'EOF'
#!/bin/bash
set -e

source /etc/restic/env

# Backup
restic backup /home /etc /var/www \
  --exclude-file=/etc/restic/excludes \
  --tag automated \
  --tag $(hostname)

# Retention
restic forget \
  --keep-last 7 \
  --keep-daily 7 \
  --keep-weekly 4 \
  --keep-monthly 6 \
  --prune

# Vérification
restic check

echo "Backup completed: $(date)"
EOF

chmod +x /opt/restic-backup.sh
```

---

## 11. Systemd timer

### Service

```bash
cat > /etc/systemd/system/restic-backup.service << 'EOF'
[Unit]
Description=Restic Backup

[Service]
Type=oneshot
ExecStart=/opt/restic-backup.sh
Environment="HOME=/root"
EOF
```

### Timer

```bash
cat > /etc/systemd/system/restic-backup.timer << 'EOF'
[Unit]
Description=Restic Backup Timer

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now restic-backup.timer
```

---

## 12. Backup vers différents backends

### REST Server

```bash
# Installer restic-rest-server
docker run -d --name rest-server \
  -p 8000:8000 \
  -v /backup:/data \
  restic/rest-server

# Utiliser
export RESTIC_REPOSITORY="rest:http://user:pass@backup-server:8000/"
```

### Backblaze B2

```bash
export B2_ACCOUNT_ID="accountId"
export B2_ACCOUNT_KEY="accountKey"
export RESTIC_REPOSITORY="b2:bucket-name:/restic"
```

### Azure Blob

```bash
export AZURE_ACCOUNT_NAME="account"
export AZURE_ACCOUNT_KEY="key"
export RESTIC_REPOSITORY="azure:container:/"
```

---

## 13. Backup de bases de données

### MySQL/MariaDB

```bash
#!/bin/bash
source /etc/restic/env

# Dump MySQL
mysqldump --all-databases | restic backup --stdin --stdin-filename mysql-all.sql

# Ou vers fichier puis backup
mysqldump --all-databases > /backup/mysql-$(date +%Y%m%d).sql
restic backup /backup/mysql-*.sql
rm /backup/mysql-*.sql
```

### PostgreSQL

```bash
pg_dumpall | restic backup --stdin --stdin-filename postgres-all.sql
```

---

## 14. Monitoring

### Prometheus metrics

```bash
# Après chaque backup
restic stats --json > /var/lib/prometheus/restic.prom
```

### Script avec notifications

```bash
#!/bin/bash
source /etc/restic/env

if restic backup /home /etc --tag daily; then
    curl -X POST -d "Backup OK" https://hooks.slack.com/services/XXX
else
    curl -X POST -d "Backup FAILED!" https://hooks.slack.com/services/XXX
    exit 1
fi
```

---

## Commandes utiles

```bash
# Stats
restic stats

# Stats par snapshot
restic stats latest

# Diff entre snapshots
restic diff abc123 def456

# Copier vers autre repo
restic copy --repo2 /backup2/restic

# Clé de chiffrement
restic key list
restic key add
restic key remove KEY_ID
```

---

## Dépannage

```bash
# Verbose
restic -v backup /home

# Debug
restic --verbose=3 backup /home

# Unlock (si bloqué)
restic unlock

# Réparer index
restic rebuild-index

# Cache
restic cache --cleanup
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
