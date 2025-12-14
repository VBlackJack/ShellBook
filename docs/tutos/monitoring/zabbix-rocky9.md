---
tags:
  - tutos
  - monitoring
  - zabbix
  - alerting
  - rocky
---

# Zabbix sur Rocky Linux 9

Installation de **Zabbix** pour le monitoring enterprise.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Zabbix | 6.4+ |
| MariaDB | 10.5+ |
| Apache/Nginx | Latest |

**Durée estimée :** 45 minutes

---

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Zabbix Agent   │────►│  Zabbix Server  │◄────│  Zabbix Proxy   │
│  (hosts)        │     │  (central)      │     │  (remote sites) │
└─────────────────┘     └────────┬────────┘     └─────────────────┘
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
             ┌──────────┐ ┌──────────┐ ┌──────────┐
             │ MariaDB  │ │ Frontend │ │ Alerting │
             └──────────┘ └──────────┘ └──────────┘
```

---

## 1. Prérequis

### Base de données

```bash
dnf install -y mariadb-server
systemctl enable --now mariadb
mysql_secure_installation
```

### Apache et PHP

```bash
dnf install -y httpd php php-mysqlnd php-gd php-bcmath php-mbstring php-xml php-ldap
```

---

## 2. Installation Zabbix

### Ajouter le repository

```bash
rpm -Uvh https://repo.zabbix.com/zabbix/6.4/rhel/9/x86_64/zabbix-release-6.4-1.el9.noarch.rpm
dnf clean all
```

### Installer les composants

```bash
dnf install -y zabbix-server-mysql zabbix-web-mysql zabbix-apache-conf zabbix-sql-scripts zabbix-selinux-policy zabbix-agent
```

---

## 3. Configuration base de données

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

### Importer le schéma

```bash
zcat /usr/share/zabbix-sql-scripts/mysql/server.sql.gz | mysql --default-character-set=utf8mb4 -uzabbix -p zabbix
```

### Désactiver log_bin_trust_function_creators

```bash
mysql -u root -p -e "SET GLOBAL log_bin_trust_function_creators = 0;"
```

---

## 4. Configuration Zabbix Server

```bash
vim /etc/zabbix/zabbix_server.conf
```

```ini
DBHost=localhost
DBName=zabbix
DBUser=zabbix
DBPassword=zabbix_password

# Performance
StartPollers=10
StartPollersUnreachable=5
StartTrappers=5
StartPingers=5
StartDiscoverers=3

# Cache
CacheSize=128M
HistoryCacheSize=64M
TrendCacheSize=32M
ValueCacheSize=64M

# Alerting
AlertScriptsPath=/usr/lib/zabbix/alertscripts
ExternalScripts=/usr/lib/zabbix/externalscripts
```

---

## 5. Configuration PHP

```bash
vim /etc/php-fpm.d/zabbix.conf
```

```ini
php_value[date.timezone] = Europe/Paris
php_value[max_execution_time] = 300
php_value[memory_limit] = 128M
php_value[post_max_size] = 16M
php_value[upload_max_filesize] = 2M
php_value[max_input_time] = 300
php_value[max_input_vars] = 10000
```

---

## 6. SELinux

```bash
setsebool -P httpd_can_connect_zabbix on
setsebool -P httpd_can_network_connect_db on
setsebool -P zabbix_can_network on
```

---

## 7. Démarrer les services

```bash
systemctl enable --now zabbix-server zabbix-agent httpd php-fpm
systemctl restart zabbix-server zabbix-agent httpd php-fpm
```

---

## 8. Firewall

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-port=10051/tcp  # Server
firewall-cmd --permanent --add-port=10050/tcp  # Agent
firewall-cmd --reload
```

---

## 9. Configuration Frontend

1. Ouvrir `http://IP/zabbix`
2. Suivre l'assistant d'installation
3. Credentials par défaut : `Admin` / `zabbix`

---

## 10. Zabbix Agent (sur les hôtes)

### Installation

```bash
rpm -Uvh https://repo.zabbix.com/zabbix/6.4/rhel/9/x86_64/zabbix-release-6.4-1.el9.noarch.rpm
dnf install -y zabbix-agent
```

### Configuration

```bash
vim /etc/zabbix/zabbix_agentd.conf
```

```ini
Server=192.168.1.10
ServerActive=192.168.1.10
Hostname=client-hostname
EnableRemoteCommands=1
LogFileSize=10
```

### Démarrer

```bash
systemctl enable --now zabbix-agent
firewall-cmd --permanent --add-port=10050/tcp
firewall-cmd --reload
```

---

## 11. Zabbix Agent 2 (moderne)

```bash
dnf install -y zabbix-agent2 zabbix-agent2-plugin-*
```

```bash
vim /etc/zabbix/zabbix_agent2.conf
```

```ini
Server=192.168.1.10
ServerActive=192.168.1.10
Hostname=client-hostname
```

```bash
systemctl enable --now zabbix-agent2
```

---

## 12. Templates et découverte

### Ajouter un hôte

1. Configuration → Hosts → Create host
2. Hostname, Groups, Interface (Agent)
3. Templates : Linux by Zabbix agent

### Auto-découverte

1. Configuration → Discovery
2. IP range, checks (Zabbix agent, SNMP, etc.)

### Auto-registration

```ini
# Sur l'agent
HostMetadata=Linux
```

---

## 13. Alerting

### Email

1. Administration → Media types → Email
2. SMTP server, port, credentials
3. Users → Media → Add email

### Webhook (Slack/Teams)

1. Administration → Media types → Slack/MS Teams
2. Configurer le webhook URL

---

## 14. Monitoring avancé

### SNMP

```bash
dnf install -y net-snmp net-snmp-utils
```

### JMX (Java)

```bash
dnf install -y zabbix-java-gateway
systemctl enable --now zabbix-java-gateway
```

```ini
# zabbix_server.conf
JavaGateway=127.0.0.1
JavaGatewayPort=10052
StartJavaPollers=5
```

---

## 15. Proxy (sites distants)

```bash
dnf install -y zabbix-proxy-mysql
```

```ini
# zabbix_proxy.conf
Server=zabbix-server-ip
Hostname=proxy-name
DBName=zabbix_proxy
ProxyMode=0  # Active
```

---

## Maintenance

```bash
# Housekeeping
# Dans zabbix_server.conf
HousekeepingFrequency=1
MaxHousekeeperDelete=5000

# Purge historique (SQL)
DELETE FROM history WHERE clock < UNIX_TIMESTAMP(NOW() - INTERVAL 30 DAY);
DELETE FROM trends WHERE clock < UNIX_TIMESTAMP(NOW() - INTERVAL 365 DAY);
```

---

## Commandes utiles

```bash
# Status serveur
zabbix_server -R config_cache_reload
zabbix_server -R housekeeper_execute

# Test agent
zabbix_get -s 192.168.1.20 -k system.hostname
zabbix_get -s 192.168.1.20 -k agent.ping

# Logs
tail -f /var/log/zabbix/zabbix_server.log
tail -f /var/log/zabbix/zabbix_agentd.log
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Agent unreachable | Vérifier firewall, port 10050 |
| Permission denied | SELinux, vérifier booleans |
| DB connection | Vérifier credentials |
| Frontend lent | Augmenter cache PHP |

```bash
# Debug
zabbix_server -c /etc/zabbix/zabbix_server.conf -f
journalctl -u zabbix-server -f
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
