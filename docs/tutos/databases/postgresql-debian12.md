---
tags:
  - tutos
  - postgresql
  - database
  - debian
---

# PostgreSQL sur Debian 12

Installation et configuration de **PostgreSQL** standalone.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| PostgreSQL | 15 |

**Durée estimée :** 20 minutes

---

## 1. Installation

```bash
apt update
apt install -y postgresql postgresql-contrib

# Vérifier
psql --version
systemctl status postgresql
```

---

## 2. Configuration du Firewall

```bash
ufw allow 5432/tcp
```

---

## 3. Configuration

```bash
# postgresql.conf
cat >> /etc/postgresql/15/main/postgresql.conf << 'EOF'

# Connexions
listen_addresses = '*'
max_connections = 200

# Mémoire
shared_buffers = 256MB
effective_cache_size = 768MB
work_mem = 16MB

# Logging
log_min_duration_statement = 1000
EOF

# pg_hba.conf
echo "host all all 192.168.1.0/24 scram-sha-256" >> /etc/postgresql/15/main/pg_hba.conf

systemctl restart postgresql
```

---

## 4. Créer une base

```bash
sudo -u postgres psql << 'EOF'
CREATE USER appuser WITH PASSWORD 'SecurePass123!';
CREATE DATABASE appdb OWNER appuser;
GRANT ALL PRIVILEGES ON DATABASE appdb TO appuser;
\l
EOF
```

---

## 5. Backup

```bash
# Dump
sudo -u postgres pg_dump appdb > /backup/appdb.sql

# Compressé
sudo -u postgres pg_dump -Fc appdb > /backup/appdb.dump

# Cron
echo "0 2 * * * postgres pg_dumpall | gzip > /backup/pg-\$(date +\%Y\%m\%d).sql.gz" > /etc/cron.d/pg-backup
```

---

## Différences Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Config dir | `/var/lib/pgsql/15/data/` | `/etc/postgresql/15/main/` |
| Data dir | `/var/lib/pgsql/15/data/` | `/var/lib/postgresql/15/main/` |
| Service | `postgresql-15` | `postgresql` |
| Binaires | `/usr/pgsql-15/bin/` | `/usr/lib/postgresql/15/bin/` |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
