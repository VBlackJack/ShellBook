---
tags:
  - postgresql
  - database
  - sql
  - backup
  - tuning
---

# PostgreSQL

Guide complet d'administration PostgreSQL : installation, configuration, tuning et sauvegarde.

---

## Installation

=== "RHEL/Rocky 9"

    ```bash
    # Installer le dépôt officiel PostgreSQL
    sudo dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm

    # Désactiver le module PostgreSQL par défaut
    sudo dnf -qy module disable postgresql

    # Installer PostgreSQL 16
    sudo dnf install -y postgresql16-server postgresql16-contrib

    # Initialiser le cluster
    sudo /usr/pgsql-16/bin/postgresql-16-setup initdb

    # Démarrer et activer
    sudo systemctl enable --now postgresql-16
    ```

=== "Debian/Ubuntu"

    ```bash
    # Ajouter le dépôt officiel
    sudo sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
    wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -

    # Installer PostgreSQL 16
    sudo apt update
    sudo apt install -y postgresql-16 postgresql-contrib-16

    # Le service démarre automatiquement
    sudo systemctl status postgresql
    ```

=== "Docker"

    ```bash
    # Lancement rapide
    docker run -d \
      --name postgres \
      -e POSTGRES_PASSWORD=secretpassword \
      -e POSTGRES_USER=admin \
      -e POSTGRES_DB=myapp \
      -v pgdata:/var/lib/postgresql/data \
      -p 5432:5432 \
      postgres:16-alpine

    # Connexion
    docker exec -it postgres psql -U admin -d myapp
    ```

---

## Configuration de Base

### Fichiers de Configuration

| Fichier | Emplacement RHEL | Emplacement Debian |
|---------|------------------|-------------------|
| `postgresql.conf` | `/var/lib/pgsql/16/data/` | `/etc/postgresql/16/main/` |
| `pg_hba.conf` | `/var/lib/pgsql/16/data/` | `/etc/postgresql/16/main/` |
| `pg_ident.conf` | `/var/lib/pgsql/16/data/` | `/etc/postgresql/16/main/` |

### Accès Réseau (pg_hba.conf)

```bash
# Voir la configuration actuelle
sudo -u postgres psql -c "SELECT * FROM pg_hba_file_rules;"
```

```ini
# /var/lib/pgsql/16/data/pg_hba.conf

# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Connexions locales
local   all             postgres                                peer
local   all             all                                     scram-sha-256

# IPv4 local
host    all             all             127.0.0.1/32            scram-sha-256

# Réseau interne (adapter selon votre réseau)
host    all             all             10.0.0.0/8              scram-sha-256
host    all             all             192.168.0.0/16          scram-sha-256

# Réplication (pour les replicas)
host    replication     replicator      10.0.0.0/8              scram-sha-256
```

!!! warning "Méthodes d'Authentification"
    | Méthode | Usage | Sécurité |
    |---------|-------|----------|
    | `peer` | Unix socket, même user OS | Élevée |
    | `scram-sha-256` | Mot de passe hashé | Élevée |
    | `md5` | Mot de passe MD5 | Moyenne (legacy) |
    | `trust` | Sans mot de passe | **Dangereuse** |

### Écoute Réseau (postgresql.conf)

```ini
# Écouter sur toutes les interfaces (par défaut: localhost)
listen_addresses = '*'

# Port (par défaut: 5432)
port = 5432

# Connexions max
max_connections = 200
```

```bash
# Appliquer les changements
sudo systemctl reload postgresql-16
```

---

## Tuning Performance

### Calcul des Paramètres selon la RAM

```bash
# Script de calcul automatique
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')

cat << EOF
# PostgreSQL Tuning pour ${RAM_GB}GB RAM

# Mémoire partagée (25% RAM)
shared_buffers = $((RAM_GB * 256))MB

# Mémoire par opération de tri/hash (4% RAM / max_connections)
work_mem = $((RAM_GB * 1024 * 4 / 100 / 200))MB

# Mémoire pour maintenance (VACUUM, CREATE INDEX)
maintenance_work_mem = $((RAM_GB * 1024 * 5 / 100))MB

# Cache effectif (50-75% RAM)
effective_cache_size = $((RAM_GB * 1024 * 75 / 100))MB
EOF
```

### Configuration Recommandée par Profil

=== "Serveur Dédié (32GB RAM)"

    ```ini
    # Mémoire
    shared_buffers = 8GB
    work_mem = 64MB
    maintenance_work_mem = 2GB
    effective_cache_size = 24GB

    # WAL
    wal_buffers = 64MB
    min_wal_size = 1GB
    max_wal_size = 4GB

    # Checkpoints
    checkpoint_completion_target = 0.9
    checkpoint_timeout = 10min

    # Parallélisme
    max_parallel_workers_per_gather = 4
    max_parallel_workers = 8
    max_worker_processes = 8

    # Planificateur
    random_page_cost = 1.1          # SSD
    effective_io_concurrency = 200   # SSD
    ```

=== "VM Moyenne (8GB RAM)"

    ```ini
    # Mémoire
    shared_buffers = 2GB
    work_mem = 16MB
    maintenance_work_mem = 512MB
    effective_cache_size = 6GB

    # WAL
    wal_buffers = 16MB
    min_wal_size = 512MB
    max_wal_size = 2GB

    # Checkpoints
    checkpoint_completion_target = 0.9

    # Parallélisme
    max_parallel_workers_per_gather = 2
    max_parallel_workers = 4
    ```

=== "Petit Serveur (2GB RAM)"

    ```ini
    # Mémoire
    shared_buffers = 512MB
    work_mem = 4MB
    maintenance_work_mem = 128MB
    effective_cache_size = 1536MB

    # WAL
    wal_buffers = 8MB
    min_wal_size = 256MB
    max_wal_size = 1GB
    ```

### Vérification de la Configuration

```sql
-- Voir la configuration actuelle
SHOW shared_buffers;
SHOW work_mem;
SHOW effective_cache_size;

-- Voir toutes les configurations non-default
SELECT name, setting, unit, source
FROM pg_settings
WHERE source != 'default'
ORDER BY name;

-- Statistiques du buffer cache
SELECT
    c.relname,
    pg_size_pretty(count(*) * 8192) as buffered,
    round(100.0 * count(*) / (SELECT setting FROM pg_settings WHERE name='shared_buffers')::integer, 1) as buffer_percent
FROM pg_class c
INNER JOIN pg_buffercache b ON b.relfilenode = c.relfilenode
GROUP BY c.relname
ORDER BY count(*) DESC
LIMIT 10;
```

---

## Gestion des Utilisateurs

### Création de Rôles

```sql
-- Créer un utilisateur applicatif
CREATE USER myapp_user WITH PASSWORD 'strong_password_here';

-- Créer une base de données
CREATE DATABASE myapp_db OWNER myapp_user;

-- Accorder les privilèges
GRANT ALL PRIVILEGES ON DATABASE myapp_db TO myapp_user;

-- Connexion à la base puis :
\c myapp_db
GRANT ALL ON SCHEMA public TO myapp_user;
GRANT ALL ON ALL TABLES IN SCHEMA public TO myapp_user;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO myapp_user;

-- Privilèges par défaut pour les futures tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO myapp_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO myapp_user;
```

### Utilisateur Read-Only

```sql
-- Créer un utilisateur lecture seule
CREATE USER readonly_user WITH PASSWORD 'readonly_password';

-- Accorder l'accès en lecture
GRANT CONNECT ON DATABASE myapp_db TO readonly_user;
\c myapp_db
GRANT USAGE ON SCHEMA public TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO readonly_user;
```

### Audit des Utilisateurs

```sql
-- Lister tous les rôles
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication
FROM pg_roles
WHERE rolname NOT LIKE 'pg_%'
ORDER BY rolname;

-- Voir les privilèges sur une base
SELECT grantee, privilege_type
FROM information_schema.role_table_grants
WHERE table_catalog = 'myapp_db'
GROUP BY grantee, privilege_type;
```

---

## Sauvegarde et Restauration

### pg_dump / pg_dumpall

```bash
# Sauvegarder une base (format custom, compressé)
pg_dump -h localhost -U postgres -Fc myapp_db > myapp_db_$(date +%Y%m%d).dump

# Sauvegarder en SQL plain text
pg_dump -h localhost -U postgres myapp_db > myapp_db_$(date +%Y%m%d).sql

# Sauvegarder uniquement le schéma
pg_dump -h localhost -U postgres --schema-only myapp_db > schema.sql

# Sauvegarder uniquement les données
pg_dump -h localhost -U postgres --data-only myapp_db > data.sql

# Sauvegarder toutes les bases + rôles
pg_dumpall -h localhost -U postgres > full_backup_$(date +%Y%m%d).sql

# Restaurer depuis un dump custom
pg_restore -h localhost -U postgres -d myapp_db myapp_db_20241130.dump

# Restaurer depuis SQL
psql -h localhost -U postgres -d myapp_db < myapp_db_20241130.sql
```

### Script de Backup Automatisé

```bash
#!/bin/bash
# /opt/scripts/pg_backup.sh

BACKUP_DIR="/var/backups/postgresql"
RETENTION_DAYS=7
DATE=$(date +%Y%m%d_%H%M%S)
DATABASES=$(psql -U postgres -t -c "SELECT datname FROM pg_database WHERE datistemplate = false AND datname != 'postgres';")

mkdir -p "$BACKUP_DIR"

for DB in $DATABASES; do
    DB=$(echo $DB | xargs)  # Trim whitespace
    BACKUP_FILE="$BACKUP_DIR/${DB}_${DATE}.dump"

    echo "Backing up $DB..."
    pg_dump -U postgres -Fc "$DB" > "$BACKUP_FILE"

    if [ $? -eq 0 ]; then
        gzip "$BACKUP_FILE"
        echo "  ✓ $DB backed up successfully"
    else
        echo "  ✗ $DB backup failed"
    fi
done

# Nettoyage des vieux backups
find "$BACKUP_DIR" -name "*.dump.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed. Remaining files:"
ls -lh "$BACKUP_DIR"
```

```bash
# Crontab
0 2 * * * /opt/scripts/pg_backup.sh >> /var/log/pg_backup.log 2>&1
```

### PITR (Point-In-Time Recovery)

```ini
# postgresql.conf - Activer l'archivage WAL
wal_level = replica
archive_mode = on
archive_command = 'cp %p /var/lib/pgsql/wal_archive/%f'

# Ou avec compression
archive_command = 'gzip < %p > /var/lib/pgsql/wal_archive/%f.gz'
```

```bash
# Créer un base backup
pg_basebackup -h localhost -U postgres -D /var/backups/pg_basebackup -Ft -z -P

# Pour restaurer à un point précis :
# 1. Arrêter PostgreSQL
# 2. Restaurer le base backup
# 3. Créer recovery.signal
# 4. Configurer recovery_target_time dans postgresql.conf
# 5. Démarrer PostgreSQL
```

---

## Monitoring et Diagnostic

### Requêtes Actives

```sql
-- Voir les requêtes en cours
SELECT
    pid,
    now() - pg_stat_activity.query_start AS duration,
    query,
    state,
    wait_event_type,
    wait_event
FROM pg_stat_activity
WHERE state != 'idle'
  AND query NOT LIKE '%pg_stat_activity%'
ORDER BY duration DESC;

-- Tuer une requête
SELECT pg_cancel_backend(pid);      -- Graceful
SELECT pg_terminate_backend(pid);   -- Force
```

### Verrous (Locks)

```sql
-- Voir les verrous bloquants
SELECT
    blocked_locks.pid AS blocked_pid,
    blocked_activity.usename AS blocked_user,
    blocking_locks.pid AS blocking_pid,
    blocking_activity.usename AS blocking_user,
    blocked_activity.query AS blocked_statement,
    blocking_activity.query AS blocking_statement
FROM pg_catalog.pg_locks blocked_locks
JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
JOIN pg_catalog.pg_locks blocking_locks
    ON blocking_locks.locktype = blocked_locks.locktype
    AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database
    AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
    AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
    AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
    AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
    AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
    AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
    AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
    AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
    AND blocking_locks.pid != blocked_locks.pid
JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
WHERE NOT blocked_locks.granted;
```

### Statistiques des Tables

```sql
-- Taille des tables
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname || '.' || tablename)) AS total_size,
    pg_size_pretty(pg_relation_size(schemaname || '.' || tablename)) AS table_size,
    pg_size_pretty(pg_indexes_size(schemaname || '.' || tablename)) AS index_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname || '.' || tablename) DESC
LIMIT 20;

-- Tables nécessitant un VACUUM
SELECT
    schemaname,
    relname,
    n_dead_tup,
    n_live_tup,
    round(n_dead_tup * 100.0 / nullif(n_live_tup + n_dead_tup, 0), 2) AS dead_ratio,
    last_vacuum,
    last_autovacuum
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC;
```

### Index Inutilisés

```sql
-- Index jamais utilisés (candidats à la suppression)
SELECT
    schemaname,
    tablename,
    indexname,
    pg_size_pretty(pg_relation_size(indexrelid)) AS index_size,
    idx_scan AS scans
FROM pg_stat_user_indexes
WHERE idx_scan = 0
  AND indexrelid NOT IN (SELECT conindid FROM pg_constraint)
ORDER BY pg_relation_size(indexrelid) DESC;
```

---

## Maintenance

### VACUUM et ANALYZE

```sql
-- VACUUM simple (libère l'espace pour réutilisation)
VACUUM mytable;

-- VACUUM FULL (récupère l'espace disque - LOCK exclusif)
VACUUM FULL mytable;

-- ANALYZE (met à jour les statistiques)
ANALYZE mytable;

-- Les deux ensemble
VACUUM ANALYZE mytable;

-- Sur toute la base
VACUUM ANALYZE;
```

### REINDEX

```sql
-- Reconstruire un index
REINDEX INDEX myindex;

-- Reconstruire tous les index d'une table
REINDEX TABLE mytable;

-- Reconstruire tous les index de la base
REINDEX DATABASE mydb;

-- Version concurrente (sans lock, PostgreSQL 12+)
REINDEX TABLE CONCURRENTLY mytable;
```

### Vérification d'Intégrité

```bash
# Vérifier l'intégrité avec pg_amcheck (PostgreSQL 14+)
pg_amcheck -d mydb --heapallindexed

# Vérifier les checksums
pg_checksums --check -D /var/lib/pgsql/16/data
```

---

## Extensions Utiles

```sql
-- Lister les extensions disponibles
SELECT * FROM pg_available_extensions WHERE installed_version IS NOT NULL;

-- Extensions recommandées
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;  -- Analyse des requêtes
CREATE EXTENSION IF NOT EXISTS pgcrypto;            -- Fonctions crypto
CREATE EXTENSION IF NOT EXISTS uuid-ossp;           -- Génération UUID
CREATE EXTENSION IF NOT EXISTS pg_trgm;             -- Recherche floue
CREATE EXTENSION IF NOT EXISTS btree_gist;          -- Index GiST
CREATE EXTENSION IF NOT EXISTS postgis;             -- Données géographiques
```

### pg_stat_statements

```sql
-- Activer dans postgresql.conf
-- shared_preload_libraries = 'pg_stat_statements'

-- Top 10 requêtes les plus lentes
SELECT
    round(total_exec_time::numeric, 2) AS total_time_ms,
    calls,
    round(mean_exec_time::numeric, 2) AS mean_time_ms,
    query
FROM pg_stat_statements
ORDER BY total_exec_time DESC
LIMIT 10;

-- Reset des statistiques
SELECT pg_stat_statements_reset();
```

---

## Voir Aussi

- [Haute Disponibilité](high-availability.md) - Patroni, réplication
- [MariaDB/MySQL](mariadb.md) - Alternative MySQL
- [Redis](redis.md) - Cache et sessions
- [Concepts BDD](../concepts/databases.md) - Types de bases de données
