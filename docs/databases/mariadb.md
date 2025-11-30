---
tags:
  - mariadb
  - mysql
  - database
  - sql
  - replication
---

# MariaDB / MySQL

Guide d'administration MariaDB et MySQL : installation, configuration, réplication et maintenance.

---

## Installation

=== "RHEL/Rocky 9"

    ```bash
    # MariaDB (par défaut dans les repos)
    sudo dnf install -y mariadb-server mariadb

    # Ou MySQL Community
    sudo dnf install -y https://dev.mysql.com/get/mysql84-community-release-el9-1.noarch.rpm
    sudo dnf install -y mysql-community-server

    # Démarrer et activer
    sudo systemctl enable --now mariadb   # ou mysqld pour MySQL
    ```

=== "Debian/Ubuntu"

    ```bash
    # MariaDB
    sudo apt install -y mariadb-server mariadb-client

    # Ou MySQL
    sudo apt install -y mysql-server mysql-client

    # Le service démarre automatiquement
    sudo systemctl status mariadb
    ```

=== "Docker"

    ```bash
    # MariaDB
    docker run -d \
      --name mariadb \
      -e MARIADB_ROOT_PASSWORD=rootpassword \
      -e MARIADB_DATABASE=myapp \
      -e MARIADB_USER=myapp_user \
      -e MARIADB_PASSWORD=userpassword \
      -v mariadb_data:/var/lib/mysql \
      -p 3306:3306 \
      mariadb:11

    # MySQL
    docker run -d \
      --name mysql \
      -e MYSQL_ROOT_PASSWORD=rootpassword \
      -e MYSQL_DATABASE=myapp \
      -e MYSQL_USER=myapp_user \
      -e MYSQL_PASSWORD=userpassword \
      -v mysql_data:/var/lib/mysql \
      -p 3306:3306 \
      mysql:8
    ```

### Sécurisation Initiale

```bash
# OBLIGATOIRE après installation
sudo mysql_secure_installation
```

!!! danger "mysql_secure_installation"
    Ce script interactif :

    - Définit/renforce le mot de passe root
    - Supprime les utilisateurs anonymes
    - Désactive l'accès root distant
    - Supprime la base de test
    - Recharge les privilèges

---

## Configuration

### Fichiers de Configuration

| Distribution | Fichier Principal | Dossier Include |
|--------------|-------------------|-----------------|
| RHEL/Rocky | `/etc/my.cnf` | `/etc/my.cnf.d/` |
| Debian/Ubuntu | `/etc/mysql/mariadb.conf.d/` | `/etc/mysql/conf.d/` |

### Configuration Recommandée

```ini
# /etc/my.cnf.d/server.cnf (RHEL) ou /etc/mysql/mariadb.conf.d/50-server.cnf (Debian)

[mysqld]
# === Réseau ===
bind-address = 0.0.0.0
port = 3306

# === Charset ===
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

# === Moteur de stockage ===
default-storage-engine = InnoDB

# === InnoDB (adapter selon RAM) ===
# Pour 8GB RAM :
innodb_buffer_pool_size = 4G          # 50-70% RAM
innodb_buffer_pool_instances = 4      # 1 par GB de buffer pool
innodb_log_file_size = 512M
innodb_log_buffer_size = 64M
innodb_flush_log_at_trx_commit = 1    # ACID complet
innodb_flush_method = O_DIRECT

# === Connexions ===
max_connections = 200
max_connect_errors = 100000
wait_timeout = 600
interactive_timeout = 600

# === Query Cache (désactivé en MySQL 8, optionnel MariaDB) ===
query_cache_type = 0
query_cache_size = 0

# === Logs ===
log_error = /var/log/mariadb/error.log
slow_query_log = 1
slow_query_log_file = /var/log/mariadb/slow.log
long_query_time = 2

# === Sécurité ===
local_infile = 0
symbolic-links = 0

[client]
default-character-set = utf8mb4
```

### Calcul InnoDB Buffer Pool

```bash
# Règle : 50-70% de la RAM disponible
RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
BUFFER_POOL=$((RAM_GB * 60 / 100))
echo "innodb_buffer_pool_size = ${BUFFER_POOL}G"
```

---

## Gestion des Utilisateurs

### Création d'Utilisateurs

```sql
-- Connexion en root
mysql -u root -p

-- Créer un utilisateur avec accès local uniquement
CREATE USER 'myapp_user'@'localhost' IDENTIFIED BY 'strong_password';

-- Créer un utilisateur avec accès depuis un réseau
CREATE USER 'myapp_user'@'10.0.0.%' IDENTIFIED BY 'strong_password';

-- Créer un utilisateur avec accès depuis n'importe où (déconseillé)
CREATE USER 'myapp_user'@'%' IDENTIFIED BY 'strong_password';

-- Accorder tous les privilèges sur une base
GRANT ALL PRIVILEGES ON myapp_db.* TO 'myapp_user'@'localhost';

-- Privilèges limités
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp_db.* TO 'readonly_user'@'localhost';

-- Appliquer les changements
FLUSH PRIVILEGES;
```

### Utilisateur de Réplication

```sql
-- Pour la réplication master-slave
CREATE USER 'replicator'@'10.0.0.%' IDENTIFIED BY 'replication_password';
GRANT REPLICATION SLAVE ON *.* TO 'replicator'@'10.0.0.%';
FLUSH PRIVILEGES;
```

### Audit des Utilisateurs

```sql
-- Lister tous les utilisateurs
SELECT User, Host, authentication_string FROM mysql.user;

-- Voir les privilèges d'un utilisateur
SHOW GRANTS FOR 'myapp_user'@'localhost';

-- Voir les connexions actives
SHOW PROCESSLIST;

-- Version détaillée
SELECT * FROM information_schema.processlist;
```

---

## Sauvegarde et Restauration

### mysqldump

```bash
# Sauvegarder une base
mysqldump -u root -p myapp_db > myapp_db_$(date +%Y%m%d).sql

# Avec compression
mysqldump -u root -p myapp_db | gzip > myapp_db_$(date +%Y%m%d).sql.gz

# Sauvegarder toutes les bases
mysqldump -u root -p --all-databases > full_backup_$(date +%Y%m%d).sql

# Options recommandées pour la production
mysqldump -u root -p \
  --single-transaction \
  --routines \
  --triggers \
  --events \
  --quick \
  myapp_db > myapp_db_$(date +%Y%m%d).sql

# Restaurer
mysql -u root -p myapp_db < myapp_db_20241130.sql

# Restaurer depuis gzip
gunzip < myapp_db_20241130.sql.gz | mysql -u root -p myapp_db
```

### mariabackup / xtrabackup

```bash
# Installation
sudo dnf install -y mariadb-backup   # MariaDB
sudo dnf install -y percona-xtrabackup  # MySQL

# Backup complet
mariabackup --backup --target-dir=/var/backups/mariadb/full \
  --user=root --password=rootpassword

# Préparer le backup pour la restauration
mariabackup --prepare --target-dir=/var/backups/mariadb/full

# Restaurer (après arrêt du service)
sudo systemctl stop mariadb
sudo rm -rf /var/lib/mysql/*
mariabackup --copy-back --target-dir=/var/backups/mariadb/full
sudo chown -R mysql:mysql /var/lib/mysql
sudo systemctl start mariadb
```

### Script de Backup Automatisé

```bash
#!/bin/bash
# /opt/scripts/mysql_backup.sh

BACKUP_DIR="/var/backups/mysql"
RETENTION_DAYS=7
DATE=$(date +%Y%m%d_%H%M%S)
MYSQL_USER="backup_user"
MYSQL_PASS="backup_password"

mkdir -p "$BACKUP_DIR"

# Liste des bases (exclure les bases système)
DATABASES=$(mysql -u$MYSQL_USER -p$MYSQL_PASS -e "SHOW DATABASES;" | grep -Ev "(Database|information_schema|performance_schema|mysql|sys)")

for DB in $DATABASES; do
    echo "Backing up $DB..."
    mysqldump -u$MYSQL_USER -p$MYSQL_PASS \
        --single-transaction \
        --routines \
        --triggers \
        "$DB" | gzip > "$BACKUP_DIR/${DB}_${DATE}.sql.gz"

    if [ $? -eq 0 ]; then
        echo "  ✓ $DB backed up successfully"
    else
        echo "  ✗ $DB backup failed"
    fi
done

# Nettoyage
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed."
```

---

## Réplication Master-Slave

### Configuration du Master

```ini
# /etc/my.cnf.d/server.cnf sur le MASTER

[mysqld]
server-id = 1
log_bin = /var/log/mariadb/mysql-bin
binlog_format = ROW
binlog_do_db = myapp_db          # Optionnel : filtrer les bases
expire_logs_days = 7
sync_binlog = 1
```

```sql
-- Sur le Master
CREATE USER 'replicator'@'10.0.0.%' IDENTIFIED BY 'replication_password';
GRANT REPLICATION SLAVE ON *.* TO 'replicator'@'10.0.0.%';
FLUSH PRIVILEGES;

-- Noter la position du binlog
SHOW MASTER STATUS;
-- +------------------+----------+
-- | File             | Position |
-- +------------------+----------+
-- | mysql-bin.000001 |      154 |
-- +------------------+----------+
```

### Configuration du Slave

```ini
# /etc/my.cnf.d/server.cnf sur le SLAVE

[mysqld]
server-id = 2
relay_log = /var/log/mariadb/relay-bin
read_only = 1
```

```sql
-- Sur le Slave
CHANGE MASTER TO
    MASTER_HOST='10.0.0.1',
    MASTER_USER='replicator',
    MASTER_PASSWORD='replication_password',
    MASTER_LOG_FILE='mysql-bin.000001',
    MASTER_LOG_POS=154;

-- Démarrer la réplication
START SLAVE;

-- Vérifier le statut
SHOW SLAVE STATUS\G
-- Vérifier que :
-- Slave_IO_Running: Yes
-- Slave_SQL_Running: Yes
-- Seconds_Behind_Master: 0
```

### Monitoring de la Réplication

```sql
-- Sur le Slave
SHOW SLAVE STATUS\G

-- Points à vérifier :
-- - Slave_IO_Running = Yes
-- - Slave_SQL_Running = Yes
-- - Seconds_Behind_Master = 0 (ou proche)
-- - Last_Error = (vide)
```

---

## Monitoring et Diagnostic

### État du Serveur

```sql
-- Statut global
SHOW GLOBAL STATUS;

-- Variables de configuration
SHOW GLOBAL VARIABLES;

-- Connexions actives
SHOW PROCESSLIST;
SHOW FULL PROCESSLIST;

-- Tuer une requête
KILL <process_id>;
```

### Métriques Importantes

```sql
-- Connexions
SHOW GLOBAL STATUS LIKE 'Threads_%';
SHOW GLOBAL STATUS LIKE 'Max_used_connections';
SHOW GLOBAL VARIABLES LIKE 'max_connections';

-- InnoDB Buffer Pool
SHOW GLOBAL STATUS LIKE 'Innodb_buffer_pool%';

-- Taux de hit du buffer pool (devrait être > 99%)
SELECT
    (1 - (Innodb_buffer_pool_reads / Innodb_buffer_pool_read_requests)) * 100
    AS buffer_pool_hit_ratio
FROM (
    SELECT
        (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS
         WHERE VARIABLE_NAME = 'Innodb_buffer_pool_reads') AS Innodb_buffer_pool_reads,
        (SELECT VARIABLE_VALUE FROM information_schema.GLOBAL_STATUS
         WHERE VARIABLE_NAME = 'Innodb_buffer_pool_read_requests') AS Innodb_buffer_pool_read_requests
) stats;

-- Requêtes lentes
SHOW GLOBAL STATUS LIKE 'Slow_queries';
```

### Taille des Tables

```sql
-- Taille de toutes les tables d'une base
SELECT
    table_name,
    ROUND(data_length / 1024 / 1024, 2) AS data_mb,
    ROUND(index_length / 1024 / 1024, 2) AS index_mb,
    ROUND((data_length + index_length) / 1024 / 1024, 2) AS total_mb,
    table_rows
FROM information_schema.tables
WHERE table_schema = 'myapp_db'
ORDER BY (data_length + index_length) DESC;

-- Taille totale par base
SELECT
    table_schema AS database_name,
    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS size_mb
FROM information_schema.tables
GROUP BY table_schema
ORDER BY size_mb DESC;
```

---

## Maintenance

### OPTIMIZE TABLE

```sql
-- Récupérer l'espace après beaucoup de DELETE/UPDATE
OPTIMIZE TABLE mytable;

-- Pour les tables InnoDB, équivalent à :
ALTER TABLE mytable ENGINE=InnoDB;
```

### CHECK et REPAIR

```sql
-- Vérifier l'intégrité (MyISAM principalement)
CHECK TABLE mytable;

-- Réparer une table corrompue
REPAIR TABLE mytable;

-- Pour InnoDB, utiliser mysqlcheck
```

```bash
# Vérifier toutes les tables
mysqlcheck -u root -p --all-databases

# Optimiser toutes les tables
mysqlcheck -u root -p --all-databases --optimize

# Réparer toutes les tables
mysqlcheck -u root -p --all-databases --repair
```

### Logs Binaires

```sql
-- Voir les logs binaires
SHOW BINARY LOGS;

-- Purger les anciens logs
PURGE BINARY LOGS BEFORE '2024-11-01 00:00:00';
PURGE BINARY LOGS TO 'mysql-bin.000010';

-- Configuration automatique
SET GLOBAL expire_logs_days = 7;  -- MySQL < 8
SET GLOBAL binlog_expire_logs_seconds = 604800;  -- MySQL 8+
```

---

## Différences MariaDB vs MySQL

| Fonctionnalité | MariaDB | MySQL |
|----------------|---------|-------|
| Licence | GPL v2 | GPL + Commercial |
| Moteurs supplémentaires | Aria, ColumnStore, Spider | X Plugin, HeatWave |
| JSON | Alias de LONGTEXT | Type natif |
| Window Functions | Depuis 10.2 | Depuis 8.0 |
| Réplication | Galera natif | Group Replication |
| Compatibilité | Fork de MySQL 5.5 | Oracle |

!!! info "Choix Pratique"
    - **MariaDB** : Drop-in replacement, communauté open source, Galera cluster
    - **MySQL** : Support Oracle, fonctionnalités enterprise (InnoDB Cluster, HeatWave)

---

## Voir Aussi

- [PostgreSQL](postgresql.md) - Alternative PostgreSQL
- [Haute Disponibilité](high-availability.md) - Galera Cluster
- [Redis](redis.md) - Cache et sessions
