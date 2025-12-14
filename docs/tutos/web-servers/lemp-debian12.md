---
tags:
  - tutos
  - lemp
  - nginx
  - mariadb
  - php
  - debian
---

# LEMP Stack sur Debian 12

Installation de **Nginx + MariaDB + PHP 8.2** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Nginx | 1.22+ |
| MariaDB | 10.11 |
| PHP | 8.2 |

**Durée estimée :** 25 minutes

---

## Prérequis

- Debian 12 minimal installé
- Accès root ou sudo
- Connexion Internet

---

## 1. Mise à jour du système

```bash
# Mise à jour
apt update && apt upgrade -y

# Outils de base
apt install -y vim curl wget gnupg2
```

---

## 2. Installation de Nginx

```bash
# Installer Nginx
apt install -y nginx

# Activer et démarrer
systemctl enable --now nginx

# Vérifier
systemctl status nginx
nginx -v
```

### Firewall (si UFW actif)

```bash
ufw allow 'Nginx Full'
ufw reload
```

---

## 3. Installation de MariaDB

```bash
# Installer MariaDB
apt install -y mariadb-server mariadb-client

# Activer et démarrer
systemctl enable --now mariadb

# Sécurisation
mariadb-secure-installation
```

Réponses recommandées :

| Question | Réponse |
|----------|---------|
| Switch to unix_socket authentication | n |
| Change root password | Y |
| Remove anonymous users | Y |
| Disallow root login remotely | Y |
| Remove test database | Y |
| Reload privilege tables | Y |

---

## 4. Installation de PHP 8.2

```bash
# PHP 8.2 est inclus dans Debian 12
apt install -y php-fpm php-mysql php-gd php-xml php-mbstring php-curl php-zip php-intl php-opcache

# Vérifier la version
php -v

# Vérifier PHP-FPM
systemctl status php8.2-fpm
```

### Configurer PHP-FPM pour Nginx

```bash
vim /etc/php/8.2/fpm/pool.d/www.conf
```

Vérifier :

```ini
user = www-data
group = www-data
listen = /run/php/php8.2-fpm.sock
listen.owner = www-data
listen.group = www-data
```

```bash
systemctl restart php8.2-fpm
```

---

## 5. Configuration de Nginx pour PHP

### Virtual Host par défaut

```bash
vim /etc/nginx/sites-available/default
```

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.php index.html index.htm;

    server_name _;

    location / {
        try_files $uri $uri/ =404;
    }

    # PHP via FPM
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }

    # Bloquer .htaccess
    location ~ /\.ht {
        deny all;
    }
}
```

### Vérifier et recharger

```bash
nginx -t
systemctl reload nginx
```

---

## 6. Test de l'installation

### Page de test PHP

```bash
cat > /var/www/html/info.php << 'EOF'
<?php
phpinfo();
EOF

chown www-data:www-data /var/www/html/info.php
```

### Tester

```bash
curl http://localhost/info.php | head -20
```

!!! warning "Sécurité"
    Supprimer après test : `rm /var/www/html/info.php`

---

## 7. Test de connexion PHP-MariaDB

```bash
cat > /var/www/html/test-db.php << 'EOF'
<?php
$host = 'localhost';
$user = 'root';
$pass = 'VOTRE_MOT_DE_PASSE';

try {
    $pdo = new PDO("mysql:host=$host", $user, $pass);
    echo "Connexion MariaDB réussie!\n";
    echo "Version: " . $pdo->query('SELECT VERSION()')->fetchColumn() . "\n";
} catch (PDOException $e) {
    echo "Erreur: " . $e->getMessage() . "\n";
}
EOF
```

```bash
php /var/www/html/test-db.php
rm /var/www/html/test-db.php
```

---

## 8. Virtual Host personnalisé

### Créer un site

```bash
mkdir -p /var/www/monsite.local/public
chown -R www-data:www-data /var/www/monsite.local
echo '<?php echo "Bienvenue sur monsite.local!"; ?>' > /var/www/monsite.local/public/index.php
```

### Configuration Nginx

```bash
vim /etc/nginx/sites-available/monsite.local
```

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name monsite.local www.monsite.local;
    root /var/www/monsite.local/public;
    index index.php index.html;

    access_log /var/log/nginx/monsite.local.access.log;
    error_log /var/log/nginx/monsite.local.error.log;

    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.2-fpm.sock;
    }

    location ~ /\. {
        deny all;
    }
}
```

### Activer le site

```bash
ln -s /etc/nginx/sites-available/monsite.local /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

---

## 9. Optimisation PHP-FPM

```bash
vim /etc/php/8.2/fpm/pool.d/www.conf
```

```ini
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
pm.max_requests = 500
```

### OPcache

```bash
vim /etc/php/8.2/fpm/conf.d/10-opcache.ini
```

```ini
opcache.enable=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=16
opcache.max_accelerated_files=10000
opcache.revalidate_freq=2
```

```bash
systemctl restart php8.2-fpm
```

---

## 10. Optimisation Nginx

```bash
vim /etc/nginx/nginx.conf
```

```nginx
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;

    # Limite taille upload
    client_max_body_size 64m;

    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
```

```bash
nginx -t && systemctl reload nginx
```

---

## Comparatif Rocky 9 vs Debian 12

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| PHP | Via Remi repo | Natif 8.2 |
| Nginx config | `/etc/nginx/conf.d/` | `/etc/nginx/sites-*` |
| PHP-FPM socket | `/run/php-fpm/www.sock` | `/run/php/php8.2-fpm.sock` |
| User web | nginx | www-data |
| SELinux | Oui | Non (AppArmor) |
| Firewall | firewalld | UFW |

---

## Vérification finale

```bash
systemctl is-active nginx php8.2-fpm mariadb
ss -tlnp | grep -E ':(80|443|3306)'
nginx -v && php -v && mariadb --version
```

---

## Dépannage

```bash
# Logs Nginx
tail -f /var/log/nginx/error.log

# Logs PHP-FPM
tail -f /var/log/php8.2-fpm.log

# Test configuration
nginx -t
php-fpm8.2 -t
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
