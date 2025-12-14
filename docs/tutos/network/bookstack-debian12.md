---
tags:
  - tutos
  - network
  - bookstack
  - wiki
  - documentation
  - debian
---

# BookStack sur Debian 12

Installation de **BookStack** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| BookStack | 23+ |
| PHP | 8.2 |
| MariaDB | 10.11 |

**Durée estimée :** 20 minutes

---

## 1. Prérequis

```bash
apt update
apt install -y mariadb-server apache2 git composer
apt install -y php php-mysql php-gd php-xml php-mbstring php-curl \
    php-ldap php-tokenizer php-zip php-fileinfo libapache2-mod-php

systemctl enable --now mariadb apache2
mysql_secure_installation
```

---

## 2. Base de données

```bash
mysql -u root -p
```

```sql
CREATE DATABASE bookstack CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'bookstack'@'localhost' IDENTIFIED BY 'bookstack_password';
GRANT ALL PRIVILEGES ON bookstack.* TO 'bookstack'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

---

## 3. Télécharger BookStack

```bash
cd /var/www
git clone https://github.com/BookStackApp/BookStack.git --branch release --single-branch bookstack

cd bookstack
composer install --no-dev
```

---

## 4. Configuration

```bash
cp .env.example .env
php artisan key:generate

vim .env
```

```ini
APP_URL=http://bookstack.example.com
DB_HOST=localhost
DB_DATABASE=bookstack
DB_USERNAME=bookstack
DB_PASSWORD=bookstack_password
```

---

## 5. Migration

```bash
php artisan migrate --force
```

---

## 6. Permissions

```bash
chown -R www-data:www-data /var/www/bookstack
chmod -R 755 /var/www/bookstack
chmod -R 775 /var/www/bookstack/storage
chmod -R 775 /var/www/bookstack/bootstrap/cache
chmod -R 775 /var/www/bookstack/public/uploads
```

---

## 7. Apache

```bash
cat > /etc/apache2/sites-available/bookstack.conf << 'EOF'
<VirtualHost *:80>
    ServerName bookstack.example.com
    DocumentRoot /var/www/bookstack/public

    <Directory /var/www/bookstack/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/bookstack_error.log
    CustomLog ${APACHE_LOG_DIR}/bookstack_access.log combined
</VirtualHost>
EOF

a2ensite bookstack.conf
a2enmod rewrite
systemctl restart apache2
```

---

## 8. Firewall

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw reload
```

---

## 9. Accès

- URL: `http://bookstack.example.com`
- Email: `admin@admin.com`
- Password: `password`

**Changer le mot de passe !**

---

## 10. HTTPS

```bash
apt install -y certbot python3-certbot-apache
certbot --apache -d bookstack.example.com
```

---

## 11. Docker

```yaml
# docker-compose.yml
version: '3.8'

services:
  bookstack:
    image: lscr.io/linuxserver/bookstack:latest
    environment:
      - APP_URL=http://bookstack.example.com
      - DB_HOST=db
      - DB_USER=bookstack
      - DB_PASS=bookstack_password
      - DB_DATABASE=bookstack
    volumes:
      - bookstack_data:/config
    ports:
      - "80:80"
    depends_on:
      - db

  db:
    image: mariadb:10
    environment:
      - MYSQL_ROOT_PASSWORD=root_password
      - MYSQL_DATABASE=bookstack
      - MYSQL_USER=bookstack
      - MYSQL_PASSWORD=bookstack_password
    volumes:
      - db_data:/var/lib/mysql

volumes:
  bookstack_data:
  db_data:
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| PHP | remi repo | apt |
| Web user | apache | www-data |
| SELinux | Oui | Non |

---

## Commandes

```bash
cd /var/www/bookstack

# Cache
php artisan cache:clear
php artisan view:clear

# Permissions
php artisan bookstack:regenerate-permissions

# Logs
tail -f storage/logs/laravel.log
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
