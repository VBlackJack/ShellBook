---
tags:
  - postgresql
  - cheatsheet
  - sql
---

# PostgreSQL Survival Guide

Commandes essentielles pour survivre en production PostgreSQL.

---

## Connexion

```bash
# Connexion locale (user postgres)
sudo -u postgres psql

# Connexion avec paramètres
psql -h localhost -p 5432 -U myuser -d mydb

# Connexion via URI
psql "postgresql://user:password@host:5432/dbname"

# Exécuter une commande
psql -c "SELECT version();"

# Exécuter un fichier SQL
psql -f script.sql
```

---

## Commandes psql

| Commande | Description |
|----------|-------------|
| `\l` | Lister les bases |
| `\c dbname` | Se connecter à une base |
| `\dt` | Lister les tables |
| `\dt+` | Tables avec tailles |
| `\d table` | Décrire une table |
| `\di` | Lister les index |
| `\du` | Lister les users/rôles |
| `\dn` | Lister les schemas |
| `\df` | Lister les fonctions |
| `\x` | Affichage étendu (toggle) |
| `\timing` | Afficher durée requêtes |
| `\e` | Éditer dans $EDITOR |
| `\i file.sql` | Exécuter un fichier |
| `\o file` | Sortie vers fichier |
| `\q` | Quitter |

---

## Utilisateurs & Permissions

```sql
-- Créer un utilisateur
CREATE USER myuser WITH PASSWORD 'password';

-- Créer une base
CREATE DATABASE mydb OWNER myuser;

-- Accorder tous les droits
GRANT ALL PRIVILEGES ON DATABASE mydb TO myuser;

-- Droits sur le schema
\c mydb
GRANT ALL ON SCHEMA public TO myuser;
GRANT ALL ON ALL TABLES IN SCHEMA public TO myuser;

-- User read-only
CREATE USER readonly WITH PASSWORD 'password';
GRANT CONNECT ON DATABASE mydb TO readonly;
GRANT USAGE ON SCHEMA public TO readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;

-- Changer le mot de passe
ALTER USER myuser WITH PASSWORD 'newpassword';

-- Supprimer un utilisateur
DROP USER myuser;
```

---

## Requêtes Utiles

### Taille des Bases

```sql
SELECT datname, pg_size_pretty(pg_database_size(datname)) as size
FROM pg_database ORDER BY pg_database_size(datname) DESC;
```

### Taille des Tables

```sql
SELECT tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total,
       pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table,
       pg_size_pretty(pg_indexes_size(schemaname||'.'||tablename)) as index
FROM pg_tables WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

### Connexions Actives

```sql
SELECT pid, usename, application_name, client_addr, state, query
FROM pg_stat_activity WHERE state != 'idle';
```

### Requêtes Longues

```sql
SELECT pid, now() - query_start as duration, state, query
FROM pg_stat_activity
WHERE state != 'idle' AND query_start < now() - interval '5 minutes'
ORDER BY duration DESC;
```

### Tuer une Requête

```sql
-- Graceful
SELECT pg_cancel_backend(pid);

-- Force
SELECT pg_terminate_backend(pid);
```

### Verrous (Locks)

```sql
SELECT pid, relation::regclass, mode, granted
FROM pg_locks WHERE NOT granted;
```

### Tables Bloat (à VACUUM)

```sql
SELECT schemaname, relname, n_dead_tup, n_live_tup,
       round(n_dead_tup * 100.0 / nullif(n_live_tup + n_dead_tup, 0), 2) as dead_pct
FROM pg_stat_user_tables
WHERE n_dead_tup > 1000
ORDER BY n_dead_tup DESC;
```

### Index Inutilisés

```sql
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
WHERE idx_scan = 0 ORDER BY pg_relation_size(indexrelid) DESC;
```

---

## Backup & Restore

```bash
# Dump une base (format custom)
pg_dump -Fc mydb > mydb.dump

# Dump en SQL
pg_dump mydb > mydb.sql

# Dump toutes les bases
pg_dumpall > all_databases.sql

# Restore format custom
pg_restore -d mydb mydb.dump

# Restore SQL
psql mydb < mydb.sql

# Dump schema only
pg_dump --schema-only mydb > schema.sql

# Dump data only
pg_dump --data-only mydb > data.sql
```

---

## Maintenance

```sql
-- VACUUM (récupérer espace)
VACUUM mytable;
VACUUM ANALYZE mytable;
VACUUM FULL mytable;  -- LOCK exclusif!

-- REINDEX
REINDEX TABLE mytable;
REINDEX INDEX myindex;
REINDEX TABLE CONCURRENTLY mytable;  -- Sans lock (PG12+)

-- ANALYZE (stats)
ANALYZE mytable;

-- Voir l'état autovacuum
SELECT schemaname, relname, last_vacuum, last_autovacuum, last_analyze
FROM pg_stat_user_tables;
```

---

## Configuration Rapide

```sql
-- Voir un paramètre
SHOW shared_buffers;
SHOW max_connections;
SHOW work_mem;

-- Voir tous les paramètres modifiés
SELECT name, setting, source FROM pg_settings WHERE source != 'default';

-- Modifier (session)
SET work_mem = '256MB';

-- Recharger la config
SELECT pg_reload_conf();
```

---

## Réplication

```sql
-- Statut réplication (sur primary)
SELECT client_addr, state, sent_lsn, write_lsn, replay_lsn,
       pg_wal_lsn_diff(sent_lsn, replay_lsn) as lag_bytes
FROM pg_stat_replication;

-- Statut (sur replica)
SELECT status, received_lsn, latest_end_lsn FROM pg_stat_wal_receiver;

-- Promouvoir un replica
SELECT pg_promote();
```

---

## Troubleshooting Express

| Problème | Commande |
|----------|----------|
| Base inaccessible | `SELECT pg_is_in_recovery();` |
| Connexions max | `SHOW max_connections; SELECT count(*) FROM pg_stat_activity;` |
| Requête bloquée | `SELECT * FROM pg_locks WHERE NOT granted;` |
| Disque plein | `SELECT pg_size_pretty(pg_database_size(current_database()));` |
| Replica lag | `SELECT pg_wal_lsn_diff(sent_lsn, replay_lsn) FROM pg_stat_replication;` |

---

## Voir Aussi

- [PostgreSQL Guide Complet](postgresql.md)
- [Haute Disponibilité](high-availability.md)
