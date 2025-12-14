---
tags:
  - tutos
  - lemp
  - nginx
  - mariadb
  - php
  - rocky
---

# LEMP Stack sur Rocky Linux 9

Installation de **Nginx + MariaDB + PHP 8.2** sur Rocky Linux 9.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Nginx | 1.20+ |
| MariaDB | 10.11 |
| PHP | 8.2 (Remi) |

**Durée estimée :** 30 minutes

---

## Prérequis

- Rocky Linux 9 minimal installé
- Accès root ou sudo
- Connexion Internet

---

## 1. Mise à jour du système

```bash
# Mise à jour
dnf update -y

# Outils de base
dnf install -y vim curl wget tar
```

---

## 2. Installation de Nginx

```bash
# Installer Nginx
dnf install -y nginx

# Activer et démarrer
systemctl enable --now nginx

# Vérifier
systemctl status nginx
nginx -v
```

### Firewall

```bash
# Ouvrir HTTP/HTTPS
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

---

## 3. Installation de MariaDB

```bash
# Installer MariaDB 10.11
dnf install -y mariadb-server mariadb

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

### Activer le dépôt Remi

```bash
# Installer EPEL et Remi
dnf install -y epel-release
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm

# Activer PHP 8.2
dnf module reset php -y
dnf module enable php:remi-8.2 -y
```

### Installer PHP-FPM

```bash
# Packages PHP essentiels
dnf install -y php php-fpm php-mysqlnd php-opcache php-gd php-xml php-mbstring php-json php-curl php-zip php-intl

# Vérifier la version
php -v
```

### Configurer PHP-FPM pour Nginx

```bash
# Éditer la configuration
vim /etc/php-fpm.d/www.conf
```

Modifier :

```ini
; Changer l'utilisateur
user = nginx
group = nginx

; Utiliser socket Unix (plus performant)
listen = /run/php-fpm/www.sock
listen.owner = nginx
listen.group = nginx
listen.mode = 0660
```

```bash
# Activer et démarrer PHP-FPM
systemctl enable --now php-fpm

# Vérifier
systemctl status php-fpm
```

---

## 5. Configuration de Nginx pour PHP

### Configuration globale

```bash
vim /etc/nginx/nginx.conf
```

Vérifier dans le bloc `http` :

```nginx
http {
    # ...
    include /etc/nginx/conf.d/*.conf;
}
```

### Virtual Host par défaut

```bash
vim /etc/nginx/conf.d/default.conf
```

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name _;
    root /var/www/html;
    index index.php index.html index.htm;

    # Logs
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;

    # Fichiers statiques
    location / {
        try_files $uri $uri/ =404;
    }

    # PHP via FPM
    location ~ \.php$ {
        fastcgi_pass unix:/run/php-fpm/www.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Sécurité - bloquer .htaccess
    location ~ /\.ht {
        deny all;
    }

    # Sécurité - bloquer fichiers cachés
    location ~ /\. {
        deny all;
    }
}
```

### Vérifier et recharger

```bash
# Tester la configuration
nginx -t

# Recharger
systemctl reload nginx
```

---

## 6. Test de l'installation

### Permissions du dossier web

```bash
# Créer le dossier si nécessaire
mkdir -p /var/www/html

# Permissions
chown -R nginx:nginx /var/www/html
chmod -R 755 /var/www/html
```

### Page de test PHP

```bash
cat > /var/www/html/info.php << 'EOF'
<?php
phpinfo();
EOF

chown nginx:nginx /var/www/html/info.php
```

### Tester

```bash
# Test local
curl http://localhost/info.php | head -20

# Ou navigateur : http://IP_SERVEUR/info.php
```

!!! warning "Sécurité"
    Supprimer `info.php` après les tests : `rm /var/www/html/info.php`

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
# Structure
mkdir -p /var/www/monsite.local/public
chown -R nginx:nginx /var/www/monsite.local

# Page d'accueil
echo '<?php echo "Bienvenue sur monsite.local!"; ?>' > /var/www/monsite.local/public/index.php
```

### Configuration Nginx

```bash
vim /etc/nginx/conf.d/monsite.local.conf
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
        fastcgi_pass unix:/run/php-fpm/www.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\. {
        deny all;
    }
}
```

```bash
nginx -t && systemctl reload nginx
```

---

## 9. SELinux

```bash
# Autoriser Nginx à se connecter au réseau (pour PHP-FPM, bases de données)
setsebool -P httpd_can_network_connect 1
setsebool -P httpd_can_network_connect_db 1

# Contexte pour les fichiers web
semanage fcontext -a -t httpd_sys_content_t "/var/www(/.*)?"
restorecon -Rv /var/www
```

---

## 10. Optimisation PHP-FPM

```bash
vim /etc/php-fpm.d/www.conf
```

```ini
; Pool de processus
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
pm.max_requests = 500
```

```bash
systemctl restart php-fpm
```

---

## 11. Optimisation Nginx

```bash
vim /etc/nginx/nginx.conf
```

```nginx
worker_processes auto;
worker_rlimit_nofile 65535;

events {
    worker_connections 4096;
    multi_accept on;
    use epoll;
}

http {
    # Buffers
    client_body_buffer_size 16k;
    client_max_body_size 64m;

    # Timeouts
    client_body_timeout 60;
    client_header_timeout 60;
    keepalive_timeout 65;
    send_timeout 60;

    # Gzip
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css text/xml application/json application/javascript application/rss+xml application/atom+xml image/svg+xml;

    # Cache fichiers statiques
    open_file_cache max=10000 inactive=20s;
    open_file_cache_valid 30s;
    open_file_cache_min_uses 2;

    include /etc/nginx/conf.d/*.conf;
}
```

```bash
nginx -t && systemctl reload nginx
```

---

## Vérification finale

```bash
# Services actifs
systemctl is-active nginx php-fpm mariadb

# Ports en écoute
ss -tlnp | grep -E ':(80|443|3306)'

# Versions
nginx -v
php -v
mariadb --version
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| 502 Bad Gateway | Vérifier PHP-FPM : `systemctl status php-fpm` |
| Permission denied | Vérifier utilisateur PHP-FPM et permissions |
| SELinux bloque | `setsebool -P httpd_can_network_connect 1` |
| Socket non trouvé | Vérifier `listen` dans `/etc/php-fpm.d/www.conf` |

```bash
# Logs Nginx
tail -f /var/log/nginx/error.log

# Logs PHP-FPM
tail -f /var/log/php-fpm/www-error.log
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
