---
tags:
  - tutos
  - mariadb
  - mysql
  - database
  - debian
---

# MariaDB sur Debian 12

Installation et configuration de **MariaDB** standalone.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| MariaDB | 10.11 |

**Durée estimée :** 20 minutes

---

## 1. Installation

```bash
apt update
apt install -y mariadb-server mariadb-client

# Vérifier
mariadb --version
```

---

## 2. Configuration du Firewall

```bash
ufw allow 3306/tcp
ufw status
```

---

## 3. Configuration

```bash
cat > /etc/mysql/mariadb.conf.d/99-custom.cnf << 'EOF'
[mysqld]
bind-address = 0.0.0.0
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
max_connections = 200
character-set-server = utf8mb4
collation-server = utf8mb4_unicode_ci

# Logs
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2
EOF

systemctl restart mariadb
```

---

## 4. Sécurisation

```bash
mariadb-secure-installation
```

---

## 5. Créer une base

```bash
mariadb -u root -p << 'EOF'
CREATE DATABASE appdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'appuser'@'localhost' IDENTIFIED BY 'SecurePass123!';
GRANT ALL PRIVILEGES ON appdb.* TO 'appuser'@'localhost';
FLUSH PRIVILEGES;
EOF
```

---

## 6. Backup

```bash
# Dump
mariadb-dump -u root -p appdb > /backup/appdb.sql

# Cron quotidien
echo "0 2 * * * root mariadb-dump -u root -p'xxx' --all-databases | gzip > /backup/mariadb-\$(date +\%Y\%m\%d).sql.gz" > /etc/cron.d/mariadb-backup
```

---

## Différences Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Config dir | `/etc/my.cnf.d/` | `/etc/mysql/mariadb.conf.d/` |
| Service | `mariadb` | `mariadb` |
| Data dir | `/var/lib/mysql` | `/var/lib/mysql` |
| Socket | `/var/lib/mysql/mysql.sock` | `/run/mysqld/mysqld.sock` |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
