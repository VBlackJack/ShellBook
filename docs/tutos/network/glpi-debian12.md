---
tags:
  - tutos
  - network
  - glpi
  - itsm
  - inventory
  - helpdesk
  - debian
---

# GLPI sur Debian 12

Installation de **GLPI** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| GLPI | 10.x |
| PHP | 8.2 |
| MariaDB | 10.11 |

**Durée estimée :** 30 minutes

---

## 1. Prérequis

### MariaDB

```bash
apt update
apt install -y mariadb-server
systemctl enable --now mariadb
mysql_secure_installation
```

### PHP et Apache

```bash
apt install -y apache2 libapache2-mod-php php php-mysql php-gd php-curl \
    php-intl php-ldap php-apcu php-xmlrpc php-zip php-bz2 php-mbstring \
    php-xml php-imap
```

---

## 2. Configuration PHP

```bash
vim /etc/php/8.2/apache2/php.ini
```

```ini
memory_limit = 256M
max_execution_time = 600
session.cookie_httponly = On
upload_max_filesize = 20M
post_max_size = 20M
date.timezone = Europe/Paris
```

```bash
systemctl restart apache2
```

---

## 3. Base de données

```bash
mysql -u root -p
```

```sql
CREATE DATABASE glpi CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'glpi'@'localhost' IDENTIFIED BY 'glpi_password';
GRANT ALL PRIVILEGES ON glpi.* TO 'glpi'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

---

## 4. Télécharger GLPI

```bash
cd /var/www
wget https://github.com/glpi-project/glpi/releases/download/10.0.11/glpi-10.0.11.tgz
tar -xzf glpi-10.0.11.tgz
rm glpi-10.0.11.tgz

chown -R www-data:www-data /var/www/glpi
chmod -R 755 /var/www/glpi
```

---

## 5. Configuration Apache

```bash
cat > /etc/apache2/sites-available/glpi.conf << 'EOF'
<VirtualHost *:80>
    ServerName glpi.example.com
    DocumentRoot /var/www/glpi/public

    <Directory /var/www/glpi/public>
        Require all granted
        RewriteEngine On
        RewriteCond %{REQUEST_FILENAME} !-f
        RewriteRule ^(.*)$ index.php [QSA,L]
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/glpi_error.log
    CustomLog ${APACHE_LOG_DIR}/glpi_access.log combined
</VirtualHost>
EOF

a2ensite glpi.conf
a2enmod rewrite
systemctl restart apache2
```

---

## 6. Firewall

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw reload
```

---

## 7. Installation Web

1. Ouvrir `http://glpi.example.com`
2. Suivre l'assistant
3. Connexion BDD : localhost / glpi / glpi_password
4. Terminer

---

## 8. Post-installation

```bash
# Supprimer install
rm -rf /var/www/glpi/install

# Déplacer fichiers sensibles
mkdir -p /etc/glpi /var/lib/glpi /var/log/glpi
mv /var/www/glpi/config/* /etc/glpi/
mv /var/www/glpi/files/* /var/lib/glpi/
chown -R www-data:www-data /etc/glpi /var/lib/glpi /var/log/glpi
```

Créer `/var/www/glpi/inc/downstream.php` :

```php
<?php
define('GLPI_CONFIG_DIR', '/etc/glpi');
define('GLPI_VAR_DIR', '/var/lib/glpi');
define('GLPI_LOG_DIR', '/var/log/glpi');
```

---

## 9. HTTPS

```bash
apt install -y certbot python3-certbot-apache
certbot --apache -d glpi.example.com
```

---

## 10. Tâches CRON

```bash
echo "* * * * * www-data /usr/bin/php /var/www/glpi/front/cron.php &>/dev/null" > /etc/cron.d/glpi
```

---

## 11. Agent inventaire

```bash
# Sur les clients Debian
apt install -y fusioninventory-agent
```

Configuration : `/etc/fusioninventory/agent.cfg`

```ini
server = http://glpi.example.com/plugins/fusioninventory/
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| PHP package | remi repo | apt |
| Web user | apache | www-data |
| SELinux | Oui | Non |

---

## Commandes

```bash
# Console
php /var/www/glpi/bin/console

# Clear cache
php /var/www/glpi/bin/console cache:clear

# Maintenance
php /var/www/glpi/bin/console glpi:maintenance:enable

# Logs
tail -f /var/log/glpi/*.log
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
