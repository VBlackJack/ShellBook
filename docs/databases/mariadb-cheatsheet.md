---
tags:
  - mariadb
  - mysql
  - cheatsheet
  - sql
---

# MariaDB/MySQL Survival Guide

Commandes essentielles pour survivre en production MariaDB/MySQL.

---

## Connexion

```bash
# Connexion locale
mysql -u root -p

# Connexion avec paramètres
mysql -h localhost -P 3306 -u myuser -p mydb

# Exécuter une commande
mysql -e "SELECT version();"

# Exécuter un fichier SQL
mysql mydb < script.sql

# Mode safe (pas de WHERE = pas d'UPDATE/DELETE)
mysql --safe-updates
```

---

## Commandes MySQL CLI

| Commande | Description |
|----------|-------------|
| `SHOW DATABASES;` | Lister les bases |
| `USE dbname;` | Sélectionner une base |
| `SHOW TABLES;` | Lister les tables |
| `DESCRIBE table;` | Structure d'une table |
| `SHOW CREATE TABLE t;` | DDL d'une table |
| `SHOW INDEX FROM t;` | Index d'une table |
| `SHOW PROCESSLIST;` | Requêtes en cours |
| `SHOW VARIABLES;` | Variables serveur |
| `SHOW STATUS;` | Statut serveur |
| `\G` | Affichage vertical |
| `\c` | Annuler la requête |
| `\q` ou `exit` | Quitter |

---

## Utilisateurs & Permissions

```sql
-- Créer un utilisateur
CREATE USER 'myuser'@'localhost' IDENTIFIED BY 'password';
CREATE USER 'myuser'@'%' IDENTIFIED BY 'password';  -- Accès distant

-- Accorder tous les droits sur une base
GRANT ALL PRIVILEGES ON mydb.* TO 'myuser'@'localhost';

-- Droits limités
GRANT SELECT, INSERT, UPDATE, DELETE ON mydb.* TO 'myuser'@'localhost';

-- User read-only
CREATE USER 'readonly'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT ON mydb.* TO 'readonly'@'localhost';

-- Appliquer les changements
FLUSH PRIVILEGES;

-- Voir les privilèges
SHOW GRANTS FOR 'myuser'@'localhost';

-- Changer le mot de passe
ALTER USER 'myuser'@'localhost' IDENTIFIED BY 'newpassword';

-- Supprimer un utilisateur
DROP USER 'myuser'@'localhost';
```

---

## Requêtes Utiles

### Taille des Bases

```sql
SELECT table_schema AS 'Database',
       ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
FROM information_schema.tables
GROUP BY table_schema
ORDER BY SUM(data_length + index_length) DESC;
```

### Taille des Tables

```sql
SELECT table_name,
       ROUND(data_length / 1024 / 1024, 2) AS 'Data (MB)',
       ROUND(index_length / 1024 / 1024, 2) AS 'Index (MB)',
       ROUND((data_length + index_length) / 1024 / 1024, 2) AS 'Total (MB)',
       table_rows AS 'Rows'
FROM information_schema.tables
WHERE table_schema = 'mydb'
ORDER BY (data_length + index_length) DESC;
```

### Connexions Actives

```sql
SHOW PROCESSLIST;

-- Version détaillée
SELECT id, user, host, db, command, time, state, info
FROM information_schema.processlist
WHERE command != 'Sleep';
```

### Requêtes Longues

```sql
SELECT id, user, host, db, time, state, info
FROM information_schema.processlist
WHERE time > 60 AND command != 'Sleep'
ORDER BY time DESC;
```

### Tuer une Requête

```sql
KILL <process_id>;
KILL QUERY <process_id>;  -- Tue la requête mais garde la connexion
```

### Verrous InnoDB

```sql
-- Transactions en attente
SELECT * FROM information_schema.innodb_lock_waits;

-- Transactions actives
SELECT * FROM information_schema.innodb_trx;

-- Détails des locks
SHOW ENGINE INNODB STATUS\G
```

### Variables Importantes

```sql
-- Connexions
SHOW VARIABLES LIKE 'max_connections';
SHOW STATUS LIKE 'Threads_connected';

-- Buffer pool InnoDB
SHOW VARIABLES LIKE 'innodb_buffer_pool_size';
SHOW STATUS LIKE 'Innodb_buffer_pool%';

-- Slow queries
SHOW VARIABLES LIKE 'slow_query%';
SHOW VARIABLES LIKE 'long_query_time';
```

---

## Backup & Restore

```bash
# Dump une base
mysqldump -u root -p mydb > mydb.sql

# Dump avec compression
mysqldump -u root -p mydb | gzip > mydb.sql.gz

# Dump toutes les bases
mysqldump -u root -p --all-databases > all_databases.sql

# Options recommandées production
mysqldump -u root -p --single-transaction --routines --triggers mydb > mydb.sql

# Restore
mysql -u root -p mydb < mydb.sql

# Restore depuis gzip
gunzip < mydb.sql.gz | mysql -u root -p mydb

# Dump structure only
mysqldump -u root -p --no-data mydb > schema.sql

# Dump data only
mysqldump -u root -p --no-create-info mydb > data.sql
```

---

## Maintenance

```sql
-- Vérifier une table
CHECK TABLE mytable;

-- Réparer une table
REPAIR TABLE mytable;

-- Optimiser (récupérer espace)
OPTIMIZE TABLE mytable;

-- Analyser (stats)
ANALYZE TABLE mytable;
```

```bash
# Vérifier toutes les tables
mysqlcheck -u root -p --all-databases

# Optimiser toutes les tables
mysqlcheck -u root -p --all-databases --optimize

# Réparer toutes les tables
mysqlcheck -u root -p --all-databases --repair
```

---

## Réplication

### Statut Master

```sql
SHOW MASTER STATUS;
SHOW BINARY LOGS;
```

### Statut Slave

```sql
SHOW SLAVE STATUS\G

-- Points clés à vérifier :
-- Slave_IO_Running: Yes
-- Slave_SQL_Running: Yes
-- Seconds_Behind_Master: 0
```

### Gestion Slave

```sql
-- Arrêter la réplication
STOP SLAVE;

-- Démarrer la réplication
START SLAVE;

-- Reset la réplication
RESET SLAVE ALL;

-- Sauter une erreur
SET GLOBAL sql_slave_skip_counter = 1;
START SLAVE;
```

### Binlogs

```sql
-- Lister les binlogs
SHOW BINARY LOGS;

-- Purger les anciens
PURGE BINARY LOGS BEFORE '2024-11-01 00:00:00';
PURGE BINARY LOGS TO 'mysql-bin.000010';

-- Voir le contenu
SHOW BINLOG EVENTS IN 'mysql-bin.000001' LIMIT 10;
```

---

## Configuration Rapide

```sql
-- Voir un paramètre
SHOW VARIABLES LIKE 'max_connections';

-- Modifier (session)
SET max_connections = 500;

-- Modifier (global, jusqu'au restart)
SET GLOBAL max_connections = 500;

-- Voir les paramètres non-default
SHOW VARIABLES WHERE Variable_name IN ('innodb_buffer_pool_size','max_connections');
```

---

## Troubleshooting Express

| Problème | Commande |
|----------|----------|
| Connexions max | `SHOW STATUS LIKE 'Threads_connected'; SHOW VARIABLES LIKE 'max_connections';` |
| Requête bloquée | `SHOW PROCESSLIST; KILL <id>;` |
| Table corrompue | `CHECK TABLE t; REPAIR TABLE t;` |
| Réplication cassée | `SHOW SLAVE STATUS\G` |
| Disque plein binlogs | `PURGE BINARY LOGS BEFORE NOW() - INTERVAL 3 DAY;` |
| Lock wait timeout | `SHOW ENGINE INNODB STATUS\G` |
| Buffer pool hit | `SHOW STATUS LIKE 'Innodb_buffer_pool_read%';` |

### Calcul Buffer Pool Hit Ratio

```sql
SELECT
  (1 - (
    (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME = 'Innodb_buffer_pool_reads') /
    (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS WHERE VARIABLE_NAME = 'Innodb_buffer_pool_read_requests')
  )) * 100 AS hit_ratio;
-- Devrait être > 99%
```

---

## Voir Aussi

- [MariaDB Guide Complet](mariadb.md)
- [Haute Disponibilité](high-availability.md)
