---
tags:
  - tutos
  - network
  - nextcloud
  - cloud
  - storage
  - rocky
---

# Nextcloud sur Rocky Linux 9

Installation de **Nextcloud** pour le cloud privé.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Nextcloud | 28+ |
| PHP | 8.2 |
| MariaDB | 10.5+ |

**Durée estimée :** 45 minutes

---

## Architecture

```
┌─────────────┐     HTTPS      ┌─────────────┐
│   Clients   │───────────────►│   Nginx     │
│  Web/Mobile │                │   :443      │
│  Desktop    │                └──────┬──────┘
└─────────────┘                       │
                               ┌──────▼──────┐
                               │  PHP-FPM    │
                               │  Nextcloud  │
                               └──────┬──────┘
                        ┌──────────────┼──────────────┐
                        ▼              ▼              ▼
                 ┌──────────┐  ┌──────────┐  ┌──────────┐
                 │ MariaDB  │  │  Redis   │  │   Data   │
                 └──────────┘  └──────────┘  └──────────┘
```

---

## 1. Prérequis

### MariaDB

```bash
dnf install -y mariadb-server
systemctl enable --now mariadb
mysql_secure_installation

mysql -u root -p
```

```sql
CREATE DATABASE nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'nextcloud'@'localhost' IDENTIFIED BY 'nextcloud_password';
GRANT ALL PRIVILEGES ON nextcloud.* TO 'nextcloud'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Redis

```bash
dnf install -y redis
systemctl enable --now redis
```

---

## 2. PHP 8.2

```bash
dnf install -y epel-release
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm
dnf module reset php
dnf module enable php:remi-8.2

dnf install -y php php-fpm php-gd php-mbstring php-intl php-pecl-apcu \
    php-mysqlnd php-pecl-redis5 php-opcache php-imagick php-zip php-process \
    php-bcmath php-gmp php-pecl-imagick php-xml php-curl
```

### Configuration PHP

```bash
vim /etc/php.ini
```

```ini
memory_limit = 512M
upload_max_filesize = 16G
post_max_size = 16G
max_execution_time = 3600
max_input_time = 3600
date.timezone = Europe/Paris

# OPcache
opcache.enable=1
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=10000
opcache.memory_consumption=128
opcache.save_comments=1
opcache.revalidate_freq=1
```

### PHP-FPM

```bash
vim /etc/php-fpm.d/www.conf
```

```ini
user = nginx
group = nginx
listen = /run/php-fpm/www.sock
listen.owner = nginx
listen.group = nginx

pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35

env[HOSTNAME] = $HOSTNAME
env[PATH] = /usr/local/bin:/usr/bin:/bin
env[TMP] = /tmp
env[TMPDIR] = /tmp
env[TEMP] = /tmp
```

```bash
systemctl enable --now php-fpm
```

---

## 3. Nginx

```bash
dnf install -y nginx
```

### Configuration

```bash
cat > /etc/nginx/conf.d/nextcloud.conf << 'EOF'
upstream php-handler {
    server unix:/run/php-fpm/www.sock;
}

server {
    listen 80;
    server_name cloud.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name cloud.example.com;

    ssl_certificate /etc/letsencrypt/live/cloud.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/cloud.example.com/privkey.pem;

    root /var/www/nextcloud;
    index index.php index.html;

    client_max_body_size 16G;
    client_body_timeout 3600s;
    fastcgi_buffers 64 4K;

    # Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Download-Options "noopen" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Permitted-Cross-Domain-Policies "none" always;
    add_header X-Robots-Tag "noindex, nofollow" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # CalDAV/CardDAV
    location = /.well-known/carddav {
        return 301 $scheme://$host/remote.php/dav;
    }
    location = /.well-known/caldav {
        return 301 $scheme://$host/remote.php/dav;
    }
    location = /.well-known/webfinger {
        return 301 $scheme://$host/index.php/.well-known/webfinger;
    }

    location / {
        rewrite ^ /index.php;
    }

    location ~ ^\/(?:build|tests|config|lib|3rdparty|templates|data)\/ {
        deny all;
    }

    location ~ ^\/(?:\.|autotest|occ|issue|indie|db_|console) {
        deny all;
    }

    location ~ ^\/(?:index|remote|public|cron|core\/ajax\/update|status|ocs\/v[12]|updater\/.+|oc[ms]-provider\/.+|.+\/richdocumentscode\/proxy)\.php(?:$|\/) {
        fastcgi_split_path_info ^(.+?\.php)(\/.*|)$;
        set $path_info $fastcgi_path_info;
        try_files $fastcgi_script_name =404;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $path_info;
        fastcgi_param HTTPS on;
        fastcgi_param modHeadersAvailable true;
        fastcgi_param front_controller_active true;
        fastcgi_pass php-handler;
        fastcgi_intercept_errors on;
        fastcgi_request_buffering off;
        fastcgi_read_timeout 3600;
    }

    location ~ ^\/(?:updater|oc[ms]-provider)(?:$|\/) {
        try_files $uri/ =404;
        index index.php;
    }

    location ~ \.(?:css|js|woff2?|svg|gif|map)$ {
        try_files $uri /index.php$request_uri;
        add_header Cache-Control "public, max-age=15778463";
        access_log off;
    }

    location ~ \.(?:png|html|ttf|ico|jpg|jpeg|bcmap|mp4|webm)$ {
        try_files $uri /index.php$request_uri;
        access_log off;
    }
}
EOF

systemctl enable --now nginx
```

---

## 4. Installation Nextcloud

```bash
cd /var/www
wget https://download.nextcloud.com/server/releases/latest.tar.bz2
tar -xjf latest.tar.bz2
chown -R nginx:nginx nextcloud

# Répertoire data externe (recommandé)
mkdir -p /data/nextcloud
chown nginx:nginx /data/nextcloud
```

---

## 5. SELinux

```bash
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/data(/.*)?'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/config(/.*)?'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/apps(/.*)?'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/.htaccess'
semanage fcontext -a -t httpd_sys_rw_content_t '/var/www/nextcloud/.user.ini'
semanage fcontext -a -t httpd_sys_rw_content_t '/data/nextcloud(/.*)?'
restorecon -Rv /var/www/nextcloud
restorecon -Rv /data/nextcloud

setsebool -P httpd_can_network_connect on
setsebool -P httpd_can_network_connect_db on
setsebool -P httpd_use_nfs on
```

---

## 6. Installation via CLI

```bash
cd /var/www/nextcloud
sudo -u nginx php occ maintenance:install \
    --database "mysql" \
    --database-name "nextcloud" \
    --database-user "nextcloud" \
    --database-pass "nextcloud_password" \
    --admin-user "admin" \
    --admin-pass "admin_password" \
    --data-dir "/data/nextcloud"
```

### Configuration post-installation

```bash
sudo -u nginx php occ config:system:set trusted_domains 0 --value=cloud.example.com
sudo -u nginx php occ config:system:set overwrite.cli.url --value=https://cloud.example.com

# Redis
sudo -u nginx php occ config:system:set redis host --value=localhost
sudo -u nginx php occ config:system:set redis port --value=6379 --type=integer
sudo -u nginx php occ config:system:set memcache.local --value='\OC\Memcache\APCu'
sudo -u nginx php occ config:system:set memcache.distributed --value='\OC\Memcache\Redis'
sudo -u nginx php occ config:system:set memcache.locking --value='\OC\Memcache\Redis'

# Phone region
sudo -u nginx php occ config:system:set default_phone_region --value=FR
```

---

## 7. Cron

```bash
crontab -u nginx -e
```

```cron
*/5 * * * * php -f /var/www/nextcloud/cron.php
```

```bash
sudo -u nginx php occ background:cron
```

---

## 8. Firewall

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

---

## 9. Optimisations

### Preview generator

```bash
sudo -u nginx php occ app:install previewgenerator
sudo -u nginx php occ preview:generate-all
```

### Maintenance

```bash
# Mode maintenance
sudo -u nginx php occ maintenance:mode --on
sudo -u nginx php occ maintenance:mode --off

# Scan fichiers
sudo -u nginx php occ files:scan --all

# Nettoyage
sudo -u nginx php occ files:cleanup
sudo -u nginx php occ trashbin:cleanup --all-users
```

---

## 10. Backup

```bash
#!/bin/bash
# /usr/local/bin/nextcloud-backup.sh

BACKUP_DIR="/backup/nextcloud"
DATE=$(date +%Y%m%d)

sudo -u nginx php /var/www/nextcloud/occ maintenance:mode --on

mysqldump -u nextcloud -p nextcloud > $BACKUP_DIR/nextcloud-db-$DATE.sql
tar -czf $BACKUP_DIR/nextcloud-data-$DATE.tar.gz /data/nextcloud
tar -czf $BACKUP_DIR/nextcloud-config-$DATE.tar.gz /var/www/nextcloud/config

sudo -u nginx php /var/www/nextcloud/occ maintenance:mode --off
```

---

## Commandes OCC

```bash
sudo -u nginx php occ list                    # Lister commandes
sudo -u nginx php occ status                  # Status
sudo -u nginx php occ app:list                # Apps installées
sudo -u nginx php occ user:list               # Utilisateurs
sudo -u nginx php occ user:add username       # Ajouter utilisateur
sudo -u nginx php occ user:resetpassword user # Reset password
sudo -u nginx php occ upgrade                 # Mise à jour
```

---

## Dépannage

```bash
# Logs
tail -f /data/nextcloud/nextcloud.log

# Status
sudo -u nginx php occ status

# Réparer
sudo -u nginx php occ maintenance:repair

# Permissions
chown -R nginx:nginx /var/www/nextcloud /data/nextcloud
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
