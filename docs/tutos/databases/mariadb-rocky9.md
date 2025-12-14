---
tags:
  - tutos
  - mariadb
  - mysql
  - database
  - rocky-linux
---

# MariaDB sur Rocky Linux 9

Installation et configuration de **MariaDB** standalone.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| MariaDB | 10.11 LTS |

**Durée estimée :** 25 minutes

---

## 1. Installation

```bash
# MariaDB 10.5 est dans les repos par défaut
# Pour 10.11 LTS, ajouter le repo officiel

cat > /etc/yum.repos.d/mariadb.repo << 'EOF'
[mariadb]
name = MariaDB
baseurl = https://mirror.mariadb.org/yum/10.11/rhel/$releasever/$basearch
gpgkey = https://mirror.mariadb.org/yum/RPM-GPG-KEY-MariaDB
gpgcheck = 1
EOF

# Installer
dnf install -y MariaDB-server MariaDB-client

# Ou version par défaut
# dnf install -y mariadb-server
```

---

## 2. Configuration du Firewall

```bash
firewall-cmd --permanent --add-service=mysql
firewall-cmd --reload
```

---

## 3. Configuration initiale

### Fichier /etc/my.cnf.d/server.cnf

```bash
cat > /etc/my.cnf.d/server.cnf << 'EOF'
[mysqld]
# Réseau
bind-address = 0.0.0.0
port = 3306

# InnoDB (adapter selon la RAM disponible)
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
innodb_flush_log_at_trx_commit = 1
innodb_file_per_table = 1

# Connexions
max_connections = 200
max_allowed_packet = 64M

# Cache
query_cache_type = 1
query_cache_size = 64M
table_open_cache = 400

# Logs
log_error = /var/log/mariadb/mariadb.log
slow_query_log = 1
slow_query_log_file = /var/log/mariadb/slow.log
long_query_time = 2

# Charset
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci
EOF

# Créer le répertoire de logs
mkdir -p /var/log/mariadb
chown mysql:mysql /var/log/mariadb
```

---

## 4. Démarrer le service

```bash
systemctl enable --now mariadb
systemctl status mariadb
```

---

## 5. Sécurisation

```bash
mariadb-secure-installation
```

| Question | Réponse |
|----------|---------|
| Enter current password for root | Entrée (vide) |
| Switch to unix_socket authentication | n |
| Change the root password | Y + mot de passe fort |
| Remove anonymous users | Y |
| Disallow root login remotely | Y |
| Remove test database | Y |
| Reload privilege tables | Y |

---

## 6. Créer une base et un utilisateur

```bash
mariadb -u root -p << 'EOF'
-- Créer une base
CREATE DATABASE appdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Créer un utilisateur local
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'SecurePass123!';
GRANT ALL PRIVILEGES ON appdb.* TO 'appuser'@'localhost';

-- Créer un utilisateur distant
CREATE USER 'appuser'@'192.168.1.%' IDENTIFIED BY 'SecurePass123!';
GRANT ALL PRIVILEGES ON appdb.* TO 'appuser'@'192.168.1.%';

-- Appliquer
FLUSH PRIVILEGES;

-- Vérifier
SHOW DATABASES;
SELECT user, host FROM mysql.user;
EOF
```

---

## 7. Backup et restore

### Backup

```bash
# Dump complet
mariadb-dump -u root -p --all-databases > /backup/full-$(date +%Y%m%d).sql

# Dump d'une base
mariadb-dump -u root -p appdb > /backup/appdb-$(date +%Y%m%d).sql

# Dump compressé
mariadb-dump -u root -p appdb | gzip > /backup/appdb-$(date +%Y%m%d).sql.gz

# Avec mariabackup (InnoDB hot backup)
mariabackup --backup --target-dir=/backup/full --user=root --password=xxx
```

### Restore

```bash
# Restaurer un dump
mariadb -u root -p appdb < /backup/appdb.sql

# Restaurer compressé
gunzip < /backup/appdb.sql.gz | mariadb -u root -p appdb

# Avec mariabackup
mariabackup --prepare --target-dir=/backup/full
mariabackup --copy-back --target-dir=/backup/full
chown -R mysql:mysql /var/lib/mysql
```

---

## 8. Commandes utiles

```bash
# Connexion
mariadb -u root -p

# Voir les processus
SHOW PROCESSLIST;

# Voir les variables
SHOW VARIABLES LIKE 'innodb%';

# Statut du serveur
SHOW STATUS;

# Taille des bases
SELECT table_schema,
       ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS "Size (MB)"
FROM information_schema.tables
GROUP BY table_schema;

# Kill une requête
KILL <process_id>;
```

---

## 9. Monitoring

```bash
# Statut en temps réel
mysqladmin -u root -p status

# Variables étendues
mysqladmin -u root -p extended-status

# Processlist
mysqladmin -u root -p processlist
```

---

## 10. SELinux

```bash
# Autoriser les connexions réseau
setsebool -P mysql_connect_any 1

# Si port personnalisé
semanage port -a -t mysqld_port_t -p tcp 3307
```

---

## Dépannage

```bash
# Logs
tail -f /var/log/mariadb/mariadb.log

# Vérifier la connexion
mariadb -u root -p -e "SELECT 1"

# Réinitialiser le mot de passe root
systemctl stop mariadb
mysqld_safe --skip-grant-tables &
mariadb -u root
# ALTER USER 'root'@'localhost' IDENTIFIED BY 'newpassword';
# FLUSH PRIVILEGES;
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
