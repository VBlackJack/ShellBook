---
tags:
  - tutos
  - network
  - glpi
  - itsm
  - inventory
  - helpdesk
  - rocky
---

# GLPI sur Rocky Linux 9

Installation de **GLPI** - gestion de parc informatique et helpdesk.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| GLPI | 10.x |
| PHP | 8.1+ |
| MariaDB | 10.5+ |

**Durée estimée :** 35 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **Inventaire** | Parc informatique |
| **Helpdesk** | Tickets, incidents |
| **CMDB** | Configuration items |
| **Contrats** | Gestion fournisseurs |
| **Plugins** | +700 plugins |

---

## 1. Prérequis

### MariaDB

```bash
dnf install -y mariadb-server
systemctl enable --now mariadb
mysql_secure_installation
```

### PHP et extensions

```bash
dnf install -y epel-release
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm
dnf module enable php:remi-8.2 -y

dnf install -y php php-fpm php-mysqlnd php-gd php-curl php-intl \
    php-ldap php-apcu php-xmlrpc php-zip php-bz2 php-mbstring \
    php-opcache php-sodium php-xml
```

### Apache

```bash
dnf install -y httpd
systemctl enable --now httpd
```

---

## 2. Configuration PHP

```bash
vim /etc/php.ini
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
systemctl restart php-fpm
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

chown -R apache:apache /var/www/glpi
chmod -R 755 /var/www/glpi
```

---

## 5. Configuration Apache

```bash
cat > /etc/httpd/conf.d/glpi.conf << 'EOF'
<VirtualHost *:80>
    ServerName glpi.example.com
    DocumentRoot /var/www/glpi/public

    <Directory /var/www/glpi/public>
        Require all granted
        RewriteEngine On
        RewriteCond %{REQUEST_FILENAME} !-f
        RewriteRule ^(.*)$ index.php [QSA,L]
    </Directory>

    <Directory /var/www/glpi>
        Options -Indexes
    </Directory>

    # Bloquer accès direct aux fichiers sensibles
    <FilesMatch "^(config|files|plugins|install)">
        Require all denied
    </FilesMatch>

    ErrorLog /var/log/httpd/glpi_error.log
    CustomLog /var/log/httpd/glpi_access.log combined
</VirtualHost>
EOF

systemctl restart httpd
```

---

## 6. SELinux

```bash
setsebool -P httpd_can_network_connect on
setsebool -P httpd_can_sendmail on
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/glpi/files(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/glpi/config(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/glpi/marketplace(/.*)?"
restorecon -Rv /var/www/glpi
```

---

## 7. Firewall

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

---

## 8. Installation Web

1. Ouvrir `http://glpi.example.com`
2. Choisir la langue
3. Accepter la licence
4. Installation
5. Connexion BDD :
   - Server: localhost
   - User: glpi
   - Password: glpi_password
6. Sélectionner la base `glpi`
7. Terminer l'installation

---

## 9. Post-installation

### Supprimer le fichier install

```bash
rm -rf /var/www/glpi/install
```

### Changer les mots de passe par défaut

Comptes par défaut :
- glpi/glpi (super-admin)
- tech/tech
- normal/normal
- post-only/postonly

### Déplacer les fichiers sensibles

```bash
mkdir -p /etc/glpi /var/lib/glpi /var/log/glpi

mv /var/www/glpi/config/* /etc/glpi/
mv /var/www/glpi/files/* /var/lib/glpi/

chown -R apache:apache /etc/glpi /var/lib/glpi /var/log/glpi
chmod 750 /etc/glpi /var/lib/glpi /var/log/glpi
```

Créer `/var/www/glpi/inc/downstream.php` :

```php
<?php
define('GLPI_CONFIG_DIR', '/etc/glpi');
define('GLPI_VAR_DIR', '/var/lib/glpi');
define('GLPI_LOG_DIR', '/var/log/glpi');
```

---

## 10. HTTPS avec Let's Encrypt

```bash
dnf install -y certbot python3-certbot-apache
certbot --apache -d glpi.example.com
```

---

## 11. Agent Fusion Inventory

### Installer l'agent sur les clients

#### Linux

```bash
# Debian/Ubuntu
apt install -y fusioninventory-agent

# Rocky/RHEL
dnf install -y fusioninventory-agent
```

Configuration `/etc/fusioninventory/agent.cfg` :

```ini
server = http://glpi.example.com/plugins/fusioninventory/
```

#### Windows

Télécharger l'agent depuis le [GitHub FusionInventory](https://github.com/fusioninventory/fusioninventory-agent/releases).

---

## 12. Plugin GLPIInventory

1. Configuration → Plugins → Marketplace
2. Rechercher "GLPIInventory"
3. Installer et activer

### Configurer l'inventaire

Administration → Inventaire → Configuration

---

## 13. Tâches planifiées (CRON)

```bash
cat > /etc/cron.d/glpi << 'EOF'
* * * * * apache /usr/bin/php /var/www/glpi/front/cron.php &>/dev/null
EOF
```

Ou via CLI :

```bash
php /var/www/glpi/bin/console glpi:system:cron
```

---

## 14. LDAP/Active Directory

1. Configuration → Authentification → Annuaires LDAP
2. Ajouter un annuaire

```
Nom: Active Directory
Serveur: ldap://dc.example.com
BaseDN: DC=example,DC=com
Login: CN=svc-glpi,OU=Service,DC=example,DC=com
Password: ****
Filtre: (&(objectClass=user)(objectCategory=person))
Login field: sAMAccountName
```

---

## 15. Email notifications

1. Configuration → Notifications → Configuration des suivis par courriels
2. Configurer SMTP :

```
Mode: SMTP+SSL
Serveur: smtp.example.com
Port: 465
Login: glpi@example.com
```

---

## 16. Backup

### Script de backup

```bash
cat > /opt/glpi-backup.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d)
BACKUP_DIR="/backup/glpi"

mkdir -p $BACKUP_DIR

# Database
mysqldump -u glpi -p'glpi_password' glpi > $BACKUP_DIR/glpi-db-$DATE.sql

# Files
tar -czf $BACKUP_DIR/glpi-files-$DATE.tar.gz /var/lib/glpi /etc/glpi

# Retention
find $BACKUP_DIR -mtime +7 -delete
EOF

chmod +x /opt/glpi-backup.sh
echo "0 2 * * * root /opt/glpi-backup.sh" >> /etc/crontab
```

---

## Commandes utiles

```bash
# Console GLPI
php /var/www/glpi/bin/console

# Maintenance mode
php /var/www/glpi/bin/console glpi:maintenance:enable

# Clear cache
php /var/www/glpi/bin/console cache:clear

# Database check
php /var/www/glpi/bin/console glpi:database:check_schema_integrity

# Migration
php /var/www/glpi/bin/console db:update
```

---

## Dépannage

```bash
# Logs
tail -f /var/log/glpi/*.log
tail -f /var/log/httpd/glpi_error.log

# Permissions
chown -R apache:apache /var/www/glpi
chmod -R 755 /var/www/glpi

# PHP info
php -m | grep -i mysql

# SELinux
ausearch -c 'httpd' --raw | audit2why
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
