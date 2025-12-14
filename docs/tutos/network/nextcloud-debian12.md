---
tags:
  - tutos
  - network
  - nextcloud
  - cloud
  - storage
  - debian
---

# Nextcloud sur Debian 12

Installation de **Nextcloud** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Nextcloud | 28+ |
| PHP | 8.2 |
| MariaDB | 10.11+ |

**Durée estimée :** 40 minutes

---

## 1. Base de données

```bash
apt update
apt install -y mariadb-server
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

---

## 2. Redis

```bash
apt install -y redis-server
systemctl enable --now redis-server
```

---

## 3. PHP 8.2

```bash
apt install -y php php-fpm php-gd php-mbstring php-intl php-apcu \
    php-mysql php-redis php-opcache php-imagick php-zip php-bcmath \
    php-gmp php-xml php-curl php-bz2
```

### Configuration

```bash
vim /etc/php/8.2/fpm/php.ini
```

```ini
memory_limit = 512M
upload_max_filesize = 16G
post_max_size = 16G
max_execution_time = 3600
date.timezone = Europe/Paris
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=10000
opcache.memory_consumption=128
```

```bash
vim /etc/php/8.2/fpm/pool.d/www.conf
```

```ini
user = www-data
group = www-data
env[PATH] = /usr/local/bin:/usr/bin:/bin
```

```bash
systemctl restart php8.2-fpm
```

---

## 4. Nginx

```bash
apt install -y nginx
```

```bash
cat > /etc/nginx/sites-available/nextcloud << 'EOF'
upstream php-handler {
    server unix:/run/php/php8.2-fpm.sock;
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
    index index.php;
    client_max_body_size 16G;

    location / {
        rewrite ^ /index.php;
    }

    location ~ ^\/(?:index|remote|public|cron|core\/ajax\/update|status|ocs\/v[12]|updater\/.+|ocs-provider\/.+)\.php(?:$|\/) {
        fastcgi_split_path_info ^(.+?\.php)(\/.*|)$;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        fastcgi_param HTTPS on;
        fastcgi_pass php-handler;
        fastcgi_read_timeout 3600;
    }

    location ~ \.(?:css|js|woff2?|svg|gif)$ {
        try_files $uri /index.php$request_uri;
        add_header Cache-Control "public, max-age=15778463";
    }
}
EOF

ln -s /etc/nginx/sites-available/nextcloud /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default
systemctl restart nginx
```

---

## 5. Nextcloud

```bash
cd /var/www
wget https://download.nextcloud.com/server/releases/latest.tar.bz2
tar -xjf latest.tar.bz2
chown -R www-data:www-data nextcloud

mkdir -p /data/nextcloud
chown www-data:www-data /data/nextcloud
```

---

## 6. Installation CLI

```bash
cd /var/www/nextcloud
sudo -u www-data php occ maintenance:install \
    --database "mysql" \
    --database-name "nextcloud" \
    --database-user "nextcloud" \
    --database-pass "nextcloud_password" \
    --admin-user "admin" \
    --admin-pass "admin_password" \
    --data-dir "/data/nextcloud"
```

### Post-configuration

```bash
sudo -u www-data php occ config:system:set trusted_domains 0 --value=cloud.example.com
sudo -u www-data php occ config:system:set memcache.local --value='\OC\Memcache\APCu'
sudo -u www-data php occ config:system:set memcache.distributed --value='\OC\Memcache\Redis'
sudo -u www-data php occ config:system:set memcache.locking --value='\OC\Memcache\Redis'
sudo -u www-data php occ config:system:set redis host --value=localhost
sudo -u www-data php occ config:system:set redis port --value=6379 --type=integer
sudo -u www-data php occ config:system:set default_phone_region --value=FR
```

---

## 7. Cron

```bash
crontab -u www-data -e
```

```cron
*/5 * * * * php -f /var/www/nextcloud/cron.php
```

```bash
sudo -u www-data php occ background:cron
```

---

## 8. Firewall

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw reload
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| User web | nginx | www-data |
| PHP socket | /run/php-fpm/www.sock | /run/php/php8.2-fpm.sock |
| PHP repo | Remi | Natif |
| SELinux | Oui | Non |

---

## Commandes

```bash
sudo -u www-data php occ status
sudo -u www-data php occ maintenance:mode --on
sudo -u www-data php occ maintenance:mode --off
sudo -u www-data php occ files:scan --all
sudo -u www-data php occ upgrade
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
