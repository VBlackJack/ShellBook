---
tags:
  - tutos
  - network
  - bookstack
  - wiki
  - documentation
  - rocky
---

# BookStack sur Rocky Linux 9

Installation de **BookStack** - plateforme wiki et documentation.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| BookStack | 23+ |
| PHP | 8.2 |
| MariaDB | 10.5+ |

**Durée estimée :** 25 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **Organisation** | Shelves, Books, Chapters, Pages |
| **WYSIWYG** | Éditeur visuel |
| **Markdown** | Support complet |
| **Search** | Recherche full-text |
| **Permissions** | RBAC granulaire |
| **API** | REST API complète |

---

## 1. Prérequis

### MariaDB

```bash
dnf install -y mariadb-server
systemctl enable --now mariadb
mysql_secure_installation
```

### PHP

```bash
dnf install -y epel-release
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm
dnf module enable php:remi-8.2 -y

dnf install -y php php-fpm php-mysqlnd php-gd php-xml php-mbstring \
    php-curl php-ldap php-tokenizer php-zip php-fileinfo
```

### Apache et outils

```bash
dnf install -y httpd git composer
systemctl enable --now httpd
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

# Générer la clé
php artisan key:generate
```

Éditer `.env` :

```bash
vim .env
```

```ini
APP_URL=http://bookstack.example.com

DB_HOST=localhost
DB_DATABASE=bookstack
DB_USERNAME=bookstack
DB_PASSWORD=bookstack_password

# Mail
MAIL_DRIVER=smtp
MAIL_HOST=smtp.example.com
MAIL_PORT=587
MAIL_USERNAME=bookstack@example.com
MAIL_PASSWORD=mail_password
MAIL_ENCRYPTION=tls
MAIL_FROM=bookstack@example.com
```

---

## 5. Migration base de données

```bash
php artisan migrate --force
```

---

## 6. Permissions

```bash
chown -R apache:apache /var/www/bookstack
chmod -R 755 /var/www/bookstack
chmod -R 775 /var/www/bookstack/storage
chmod -R 775 /var/www/bookstack/bootstrap/cache
chmod -R 775 /var/www/bookstack/public/uploads
```

---

## 7. Configuration Apache

```bash
cat > /etc/httpd/conf.d/bookstack.conf << 'EOF'
<VirtualHost *:80>
    ServerName bookstack.example.com
    DocumentRoot /var/www/bookstack/public

    <Directory /var/www/bookstack/public>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog /var/log/httpd/bookstack_error.log
    CustomLog /var/log/httpd/bookstack_access.log combined
</VirtualHost>
EOF

systemctl restart httpd
```

---

## 8. SELinux

```bash
setsebool -P httpd_can_network_connect on
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/bookstack/storage(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/bookstack/bootstrap/cache(/.*)?"
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/bookstack/public/uploads(/.*)?"
restorecon -Rv /var/www/bookstack
```

---

## 9. Firewall

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

---

## 10. Premier accès

1. Ouvrir `http://bookstack.example.com`
2. Login par défaut :
   - Email: `admin@admin.com`
   - Password: `password`
3. **Changer le mot de passe immédiatement !**

---

## 11. HTTPS

```bash
dnf install -y certbot python3-certbot-apache
certbot --apache -d bookstack.example.com
```

---

## 12. LDAP / Active Directory

Éditer `.env` :

```ini
AUTH_METHOD=ldap

LDAP_SERVER=ldap://dc.example.com:389
LDAP_BASE_DN=DC=example,DC=com
LDAP_DN=CN=svc-bookstack,OU=Service,DC=example,DC=com
LDAP_PASS=password

LDAP_USER_FILTER=(&(objectClass=user)(sAMAccountName=${user}))
LDAP_VERSION=3
LDAP_ID_ATTRIBUTE=objectGUID
LDAP_EMAIL_ATTRIBUTE=mail
LDAP_DISPLAY_NAME_ATTRIBUTE=displayName
LDAP_FOLLOW_REFERRALS=false
```

---

## 13. SSO avec SAML

```ini
AUTH_METHOD=saml2

SAML2_NAME=SSO
SAML2_EMAIL_ATTRIBUTE=email
SAML2_DISPLAY_NAME_ATTRIBUTES=firstname|lastname
SAML2_EXTERNAL_ID_ATTRIBUTE=uid
SAML2_IDP_ENTITYID=https://idp.example.com/saml
SAML2_IDP_SSO=https://idp.example.com/saml/sso
SAML2_IDP_x509=base64_certificate
```

---

## 14. API

### Générer un token

Settings → API Tokens → Create Token

### Exemples

```bash
# Lister les livres
curl -H "Authorization: Token TOKEN_ID:TOKEN_SECRET" \
    http://bookstack.example.com/api/books

# Créer une page
curl -X POST \
    -H "Authorization: Token TOKEN_ID:TOKEN_SECRET" \
    -H "Content-Type: application/json" \
    -d '{"book_id":1,"name":"New Page","html":"<p>Content</p>"}' \
    http://bookstack.example.com/api/pages
```

---

## 15. Docker alternative

```bash
mkdir -p /opt/bookstack
cd /opt/bookstack

cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  bookstack:
    image: lscr.io/linuxserver/bookstack:latest
    container_name: bookstack
    environment:
      - PUID=1000
      - PGID=1000
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
    restart: unless-stopped

  db:
    image: mariadb:10
    container_name: bookstack_db
    environment:
      - MYSQL_ROOT_PASSWORD=root_password
      - MYSQL_DATABASE=bookstack
      - MYSQL_USER=bookstack
      - MYSQL_PASSWORD=bookstack_password
    volumes:
      - db_data:/var/lib/mysql
    restart: unless-stopped

volumes:
  bookstack_data:
  db_data:
EOF

docker compose up -d
```

---

## 16. Backup

```bash
cat > /opt/bookstack-backup.sh << 'EOF'
#!/bin/bash
DATE=$(date +%Y%m%d)
BACKUP_DIR="/backup/bookstack"

mkdir -p $BACKUP_DIR

# Database
mysqldump -u bookstack -p'bookstack_password' bookstack > $BACKUP_DIR/bookstack-db-$DATE.sql

# Files
tar -czf $BACKUP_DIR/bookstack-files-$DATE.tar.gz \
    /var/www/bookstack/.env \
    /var/www/bookstack/storage \
    /var/www/bookstack/public/uploads

find $BACKUP_DIR -mtime +7 -delete
EOF

chmod +x /opt/bookstack-backup.sh
```

---

## Commandes Artisan

```bash
cd /var/www/bookstack

# Clear cache
php artisan cache:clear
php artisan view:clear
php artisan config:clear

# Régénérer les permissions
php artisan bookstack:regenerate-permissions

# Mettre à jour les index de recherche
php artisan bookstack:regenerate-search
```

---

## Dépannage

```bash
# Logs
tail -f /var/www/bookstack/storage/logs/laravel.log

# Permissions
chown -R apache:apache /var/www/bookstack/storage
chmod -R 775 /var/www/bookstack/storage

# Test DB
php artisan migrate:status
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
