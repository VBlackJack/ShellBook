---
tags:
  - sql
  - mariadb
  - postgresql
  - backup
  - security
---

# Database Administration (MariaDB/PostgreSQL)

Administration des bases de données relationnelles sous Linux.

!!! tip "Section Dédiée"
    Pour des guides complets, consultez la **[Section Bases de Données](../databases/index.md)** :

    - [PostgreSQL](../databases/postgresql.md) - Installation, tuning, backup, monitoring
    - [MariaDB/MySQL](../databases/mariadb.md) - Configuration, réplication, maintenance
    - [Redis](../databases/redis.md) - Cache, sessions, pub/sub
    - [Haute Disponibilité](../databases/high-availability.md) - Patroni, Galera

---

## MariaDB/MySQL : Les Bases Ops

### Installation et Sécurisation

=== "RHEL/Rocky"

    ```bash
    # Installation
    sudo dnf install mariadb-server

    # Démarrer et activer
    sudo systemctl enable --now mariadb

    # IMPÉRATIF : Sécurisation initiale
    sudo mysql_secure_installation
    ```

=== "Debian/Ubuntu"

    ```bash
    # Installation
    sudo apt install mariadb-server    # MariaDB
    sudo apt install mysql-server      # MySQL

    # Démarrer et activer
    sudo systemctl enable --now mariadb

    # IMPÉRATIF : Sécurisation initiale
    sudo mysql_secure_installation
    ```

!!! danger "mysql_secure_installation est OBLIGATOIRE"
    Ce script interactif :

    - Définit un mot de passe root (si auth par mot de passe)
    - Supprime les utilisateurs anonymes
    - Désactive la connexion root distante
    - Supprime la base de test
    - Recharge les privilèges

### Connexion Root (Changement Récent)

Sur les installations modernes (Debian 9+, Ubuntu 18.04+), root utilise l'authentification par **socket Unix** :

```bash
# Connexion root (pas besoin de mot de passe, mais sudo requis)
sudo mysql

# Ou
sudo mariadb

# L'ancienne méthode (mot de passe) peut ne pas fonctionner :
mysql -u root -p    # Peut échouer !
```

| Méthode | Commande | Sécurité |
|---------|----------|----------|
| Socket Unix (défaut) | `sudo mysql` | Plus sécurisé (nécessite accès sudo) |
| Mot de passe | `mysql -u root -p` | Risque de fuite du mot de passe |

### SQL Survival Kit

#### Gestion des Bases

```sql
-- Lister les bases
SHOW DATABASES;

-- Créer une base
CREATE DATABASE appdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Sélectionner une base
USE appdb;

-- Supprimer une base
DROP DATABASE appdb;
```

#### Gestion des Utilisateurs

```sql
-- Lister les utilisateurs
SELECT User, Host FROM mysql.user;

-- Créer un utilisateur (accès local uniquement)
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'SecureP@ss123';

-- Créer un utilisateur (accès distant)
CREATE USER 'appuser'@'%' IDENTIFIED BY 'SecureP@ss123';
--                    ^^
--                    % = Depuis n'importe quelle IP

-- Créer un utilisateur (IP spécifique)
CREATE USER 'appuser'@'192.168.1.%' IDENTIFIED BY 'SecureP@ss123';
```

| Host | Signification |
|------|---------------|
| `localhost` | Connexions locales uniquement |
| `%` | Toutes les IPs (dangereux si exposé) |
| `192.168.1.%` | Sous-réseau spécifique |
| `10.0.0.5` | IP unique |

#### Gestion des Privilèges

```sql
-- Donner tous les privilèges sur une base
GRANT ALL PRIVILEGES ON appdb.* TO 'appuser'@'localhost';

-- Privilèges limités (lecture seule)
GRANT SELECT ON appdb.* TO 'readonly'@'localhost';

-- Privilèges CRUD classiques
GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'appuser'@'localhost';

-- Appliquer les changements
FLUSH PRIVILEGES;

-- Voir les privilèges d'un utilisateur
SHOW GRANTS FOR 'appuser'@'localhost';

-- Révoquer des privilèges
REVOKE ALL PRIVILEGES ON appdb.* FROM 'appuser'@'localhost';

-- Supprimer un utilisateur
DROP USER 'appuser'@'localhost';
```

#### Script Complet

```sql
-- Création complète : base + utilisateur + privilèges
CREATE DATABASE appdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'SecureP@ss123';
GRANT ALL PRIVILEGES ON appdb.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;
```

---

## PostgreSQL : La Robustesse

### Installation

```bash
# Installation
sudo apt install postgresql postgresql-contrib

# Démarrer et activer
sudo systemctl enable --now postgresql

# Vérifier
sudo systemctl status postgresql
```

### Connexion et Authentification

PostgreSQL utilise un système de **rôles** et le fichier `pg_hba.conf` pour l'authentification.

```bash
# Se connecter en tant que postgres (superuser)
sudo -u postgres psql

# Depuis un utilisateur autorisé
psql -U appuser -d appdb -h localhost
```

### Commandes Méta (psql)

| Commande | Description |
|----------|-------------|
| `\l` | Lister les bases de données |
| `\du` | Lister les rôles/utilisateurs |
| `\c dbname` | Se connecter à une base |
| `\dt` | Lister les tables |
| `\d table` | Décrire une table |
| `\q` | Quitter psql |
| `\?` | Aide des commandes méta |
| `\h` | Aide SQL |

```bash
postgres=# \l
                              List of databases
   Name    |  Owner   | Encoding |   Collate   |    Ctype    |
-----------+----------+----------+-------------+-------------+
 postgres  | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |
 appdb     | postgres | UTF8     | en_US.UTF-8 | en_US.UTF-8 |

postgres=# \du
                             List of roles
 Role name |                         Attributes
-----------+------------------------------------------------------------
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS
 appuser   |
```

### Gestion des Rôles et Bases

```sql
-- Créer un rôle (utilisateur)
CREATE ROLE appuser WITH LOGIN PASSWORD 'SecureP@ss123';

-- Créer une base
CREATE DATABASE appdb OWNER appuser;

-- Donner des privilèges
GRANT ALL PRIVILEGES ON DATABASE appdb TO appuser;

-- Privilèges sur les tables (après connexion à la base)
\c appdb
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO appuser;

-- Supprimer
DROP DATABASE appdb;
DROP ROLE appuser;
```

### Configuration pg_hba.conf

```bash
# Fichier d'authentification
sudo nano /var/lib/postgresql/14/main/pg_hba.conf
# ou
sudo nano /etc/postgresql/14/main/pg_hba.conf
```

```
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             postgres                                peer
local   all             all                                     peer
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             192.168.1.0/24          scram-sha-256
```

| Method | Description |
|--------|-------------|
| `peer` | Auth via utilisateur système (local) |
| `scram-sha-256` | Mot de passe chiffré (recommandé) |
| `md5` | Mot de passe MD5 (legacy) |
| `trust` | Pas d'authentification (dangereux !) |

```bash
# Après modification, recharger
sudo systemctl reload postgresql
```

---

## Backup & Restore

### MySQL / MariaDB

#### Backup

```bash
# Base unique
mysqldump -u root -p appdb > backup_appdb.sql

# Avec sudo (auth socket)
sudo mysqldump appdb > backup_appdb.sql

# Toutes les bases
sudo mysqldump --all-databases > backup_all.sql

# Avec compression
sudo mysqldump appdb | gzip > backup_appdb.sql.gz

# Structure uniquement (pas de données)
sudo mysqldump --no-data appdb > schema.sql

# Données uniquement
sudo mysqldump --no-create-info appdb > data.sql
```

#### Restore

```bash
# Restore simple
mysql -u root -p appdb < backup_appdb.sql

# Avec sudo
sudo mysql appdb < backup_appdb.sql

# Depuis fichier compressé
gunzip < backup_appdb.sql.gz | sudo mysql appdb

# Créer la base si elle n'existe pas
sudo mysql -e "CREATE DATABASE IF NOT EXISTS appdb"
sudo mysql appdb < backup_appdb.sql
```

### PostgreSQL

#### Backup

```bash
# Base unique (format SQL)
sudo -u postgres pg_dump appdb > backup_appdb.sql

# Format custom (compressé, recommandé)
sudo -u postgres pg_dump -Fc appdb > backup_appdb.dump

# Toutes les bases
sudo -u postgres pg_dumpall > backup_all.sql

# Table spécifique
sudo -u postgres pg_dump -t users appdb > backup_users.sql

# Avec compression
sudo -u postgres pg_dump appdb | gzip > backup_appdb.sql.gz
```

#### Restore

```bash
# Format SQL
sudo -u postgres psql appdb < backup_appdb.sql

# Format custom (avec pg_restore)
sudo -u postgres pg_restore -d appdb backup_appdb.dump

# Créer la base si nécessaire
sudo -u postgres createdb appdb
sudo -u postgres psql appdb < backup_appdb.sql

# Depuis fichier compressé
gunzip < backup_appdb.sql.gz | sudo -u postgres psql appdb
```

### Sécurisation des Credentials

!!! danger "SecNumCloud : Jamais de mots de passe en clair dans les scripts"
    Utiliser les fichiers de credentials avec permissions restrictives.

#### MySQL : ~/.my.cnf

```bash
# Créer le fichier
cat > ~/.my.cnf << 'EOF'
[client]
user=backup_user
password=SecureBackupP@ss

[mysqldump]
user=backup_user
password=SecureBackupP@ss
EOF

# Permissions restrictives (OBLIGATOIRE)
chmod 600 ~/.my.cnf

# Utilisation (pas besoin de -u -p)
mysqldump appdb > backup.sql
```

#### PostgreSQL : ~/.pgpass

```bash
# Format : hostname:port:database:username:password
cat > ~/.pgpass << 'EOF'
localhost:5432:appdb:backup_user:SecureBackupP@ss
localhost:5432:*:backup_user:SecureBackupP@ss
EOF

# Permissions restrictives (OBLIGATOIRE)
chmod 600 ~/.pgpass

# Utilisation
pg_dump -U backup_user -h localhost appdb > backup.sql
```

### Script de Backup Automatisé

```bash
#!/bin/bash
set -euo pipefail

DATE=$(date +%Y%m%d_%H%M)
BACKUP_DIR="/backup/databases"
RETENTION_DAYS=30

# MySQL
mysqldump --all-databases | gzip > "$BACKUP_DIR/mysql_$DATE.sql.gz"

# PostgreSQL
sudo -u postgres pg_dumpall | gzip > "$BACKUP_DIR/postgres_$DATE.sql.gz"

# Nettoyage des anciens backups
find "$BACKUP_DIR" -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $DATE"
```

---

## Référence Rapide

```bash
# === MYSQL/MARIADB ===
sudo mysql                                 # Connexion root
mysql_secure_installation                  # Sécurisation initiale

# SQL
CREATE DATABASE appdb;
CREATE USER 'user'@'localhost' IDENTIFIED BY 'pass';
GRANT ALL PRIVILEGES ON appdb.* TO 'user'@'localhost';
FLUSH PRIVILEGES;

# Backup/Restore
sudo mysqldump appdb > backup.sql
sudo mysql appdb < backup.sql

# === POSTGRESQL ===
sudo -u postgres psql                      # Connexion
\l  \du  \c dbname  \dt  \q               # Commandes méta

# SQL
CREATE ROLE appuser WITH LOGIN PASSWORD 'pass';
CREATE DATABASE appdb OWNER appuser;

# Backup/Restore
sudo -u postgres pg_dump appdb > backup.sql
sudo -u postgres psql appdb < backup.sql

# === CREDENTIALS SÉCURISÉS ===
chmod 600 ~/.my.cnf                        # MySQL
chmod 600 ~/.pgpass                        # PostgreSQL
```
