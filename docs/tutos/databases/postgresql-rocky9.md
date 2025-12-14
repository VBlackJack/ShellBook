---
tags:
  - tutos
  - postgresql
  - database
  - rocky-linux
---

# PostgreSQL sur Rocky Linux 9

Installation et configuration de **PostgreSQL** standalone.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| PostgreSQL | 15 |

**Durée estimée :** 25 minutes

---

## 1. Installation

```bash
# Installer le repo PostgreSQL officiel
dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm

# Désactiver le module PostgreSQL par défaut
dnf -qy module disable postgresql

# Installer PostgreSQL 15
dnf install -y postgresql15-server postgresql15-contrib

# Initialiser la base
/usr/pgsql-15/bin/postgresql-15-setup initdb
```

---

## 2. Configuration du Firewall

```bash
firewall-cmd --permanent --add-service=postgresql
firewall-cmd --reload
```

---

## 3. Configuration

### postgresql.conf

```bash
cat >> /var/lib/pgsql/15/data/postgresql.conf << 'EOF'

# Connexions
listen_addresses = '*'
port = 5432
max_connections = 200

# Mémoire (adapter selon RAM)
shared_buffers = 256MB
effective_cache_size = 768MB
work_mem = 16MB
maintenance_work_mem = 128MB

# WAL
wal_level = replica
max_wal_size = 1GB
min_wal_size = 80MB

# Logging
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d.log'
log_min_duration_statement = 1000

# Locale
lc_messages = 'en_US.UTF-8'
EOF
```

### pg_hba.conf (authentification)

```bash
cat >> /var/lib/pgsql/15/data/pg_hba.conf << 'EOF'

# Connexions réseau local
host    all             all             192.168.1.0/24          scram-sha-256
EOF
```

---

## 4. Démarrer le service

```bash
systemctl enable --now postgresql-15
systemctl status postgresql-15
```

---

## 5. Créer une base et un utilisateur

```bash
# Se connecter en tant que postgres
sudo -u postgres psql << 'EOF'
-- Créer un utilisateur
CREATE USER appuser WITH PASSWORD 'SecurePass123!';

-- Créer une base
CREATE DATABASE appdb OWNER appuser;

-- Permissions
GRANT ALL PRIVILEGES ON DATABASE appdb TO appuser;

-- Vérifier
\l
\du
EOF
```

---

## 6. Connexion

```bash
# Local
psql -U appuser -d appdb

# Distant
psql -h 192.168.1.10 -U appuser -d appdb

# Test rapide
psql -U postgres -c "SELECT version();"
```

---

## 7. Backup et restore

### pg_dump

```bash
# Dump d'une base
pg_dump -U postgres appdb > /backup/appdb.sql

# Dump compressé
pg_dump -U postgres -Fc appdb > /backup/appdb.dump

# Toutes les bases
pg_dumpall -U postgres > /backup/all_databases.sql
```

### Restore

```bash
# Restaurer SQL
psql -U postgres appdb < /backup/appdb.sql

# Restaurer format custom
pg_restore -U postgres -d appdb /backup/appdb.dump

# Créer + restaurer
createdb -U postgres appdb_new
pg_restore -U postgres -d appdb_new /backup/appdb.dump
```

---

## 8. Commandes psql

```bash
# Lister les bases
\l

# Lister les tables
\dt

# Décrire une table
\d tablename

# Lister les utilisateurs
\du

# Changer de base
\c database_name

# Exécuter un fichier SQL
\i /path/to/file.sql

# Quitter
\q
```

---

## 9. Maintenance

```bash
# Vacuum (nettoyage)
sudo -u postgres vacuumdb --all --analyze

# Reindex
sudo -u postgres reindexdb --all

# Statistiques
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity;"

# Taille des bases
sudo -u postgres psql -c "SELECT pg_database.datname, pg_size_pretty(pg_database_size(pg_database.datname)) FROM pg_database;"
```

---

## 10. SELinux

```bash
# Si port personnalisé
semanage port -a -t postgresql_port_t -p tcp 5433

# Contexte
restorecon -Rv /var/lib/pgsql
```

---

## Dépannage

```bash
# Logs
tail -f /var/lib/pgsql/15/data/log/postgresql-*.log

# Connexions actives
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity WHERE state = 'active';"

# Tuer une connexion
sudo -u postgres psql -c "SELECT pg_terminate_backend(pid);"

# Réinitialiser mot de passe postgres
# Dans pg_hba.conf: local all postgres trust
# systemctl restart postgresql-15
# psql -U postgres -c "ALTER USER postgres PASSWORD 'newpass';"
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
