---
tags:
  - tutos
  - monitoring
  - zabbix
  - alerting
  - debian
---

# Zabbix sur Debian 12

Installation de **Zabbix** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Zabbix | 6.4+ |
| MariaDB | 10.11+ |

**Durée estimée :** 40 minutes

---

## 1. Prérequis

```bash
apt update
apt install -y mariadb-server apache2 php php-mysql php-gd php-bcmath php-mbstring php-xml php-ldap

systemctl enable --now mariadb
mysql_secure_installation
```

---

## 2. Repository Zabbix

```bash
wget https://repo.zabbix.com/zabbix/6.4/debian/pool/main/z/zabbix-release/zabbix-release_6.4-1+debian12_all.deb
dpkg -i zabbix-release_6.4-1+debian12_all.deb
apt update
```

---

## 3. Installation

```bash
apt install -y zabbix-server-mysql zabbix-frontend-php zabbix-apache-conf zabbix-sql-scripts zabbix-agent
```

---

## 4. Base de données

```bash
mysql -u root -p
```

```sql
CREATE DATABASE zabbix CHARACTER SET utf8mb4 COLLATE utf8mb4_bin;
CREATE USER 'zabbix'@'localhost' IDENTIFIED BY 'zabbix_password';
GRANT ALL PRIVILEGES ON zabbix.* TO 'zabbix'@'localhost';
SET GLOBAL log_bin_trust_function_creators = 1;
FLUSH PRIVILEGES;
EXIT;
```

```bash
zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql --default-character-set=utf8mb4 -uzabbix -p zabbix

mysql -u root -p -e "SET GLOBAL log_bin_trust_function_creators = 0;"
```

---

## 5. Configuration

```bash
vim /etc/zabbix/zabbix_server.conf
```

```ini
DBHost=localhost
DBName=zabbix
DBUser=zabbix
DBPassword=zabbix_password
CacheSize=128M
```

---

## 6. PHP Timezone

```bash
vim /etc/zabbix/apache.conf
```

```ini
php_value date.timezone Europe/Paris
```

---

## 7. Démarrer

```bash
systemctl enable --now zabbix-server zabbix-agent apache2
systemctl restart zabbix-server zabbix-agent apache2
```

---

## 8. Firewall

```bash
ufw allow 80/tcp
ufw allow 10050/tcp
ufw allow 10051/tcp
ufw reload
```

---

## 9. Frontend

1. Ouvrir `http://IP/zabbix`
2. Login : `Admin` / `zabbix`

---

## 10. Agent sur les hôtes

```bash
wget https://repo.zabbix.com/zabbix/6.4/debian/pool/main/z/zabbix-release/zabbix-release_6.4-1+debian12_all.deb
dpkg -i zabbix-release_6.4-1+debian12_all.deb
apt update
apt install -y zabbix-agent
```

```bash
vim /etc/zabbix/zabbix_agentd.conf
```

```ini
Server=192.168.1.10
ServerActive=192.168.1.10
Hostname=client-hostname
```

```bash
systemctl enable --now zabbix-agent
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | zabbix-release-6.4-1.el9 | zabbix-release_6.4-1+debian12 |
| Web | httpd | apache2 |
| SELinux | Oui | Non |

---

## Commandes

```bash
zabbix_get -s IP -k agent.ping       # Test agent
zabbix_server -R config_cache_reload  # Reload config
tail -f /var/log/zabbix/zabbix_server.log
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
