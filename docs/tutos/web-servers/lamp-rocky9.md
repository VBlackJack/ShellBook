---
tags:
  - tutos
  - lamp
  - apache
  - php
  - mariadb
  - rocky-linux
---

# LAMP sur Rocky Linux 9

Stack **L**inux **A**pache **M**ariaDB **P**HP complète et sécurisée.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Apache | 2.4 |
| MariaDB | 10.11 |
| PHP | 8.2 |

**Durée estimée :** 30 minutes

**Prérequis :**

- Rocky Linux 9 installé (minimal ou server)
- Accès root ou sudo
- Connexion internet

---

## 1. Mise à jour du système

```bash
# Mise à jour complète
dnf update -y

# Installer les outils de base
dnf install -y vim wget curl tar
```

---

## 2. Installation d'Apache

### Installation

```bash
# Installer Apache
dnf install -y httpd

# Activer et démarrer le service
systemctl enable --now httpd

# Vérifier le statut
systemctl status httpd
```

### Configuration Firewall

```bash
# Ouvrir les ports HTTP et HTTPS
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload

# Vérifier
firewall-cmd --list-all
```

### Test

```bash
# Créer une page de test
echo "<h1>Apache fonctionne</h1>" > /var/www/html/index.html

# Tester localement
curl http://localhost
```

---

## 3. Installation de MariaDB

### Installation

```bash
# Installer MariaDB server et client
dnf install -y mariadb-server mariadb

# Activer et démarrer le service
systemctl enable --now mariadb

# Vérifier le statut
systemctl status mariadb
```

### Sécurisation

```bash
# Lancer l'assistant de sécurisation
mariadb-secure-installation
```

Répondre aux questions :

| Question | Réponse recommandée |
|----------|---------------------|
| Enter current password for root | Appuyer sur Entrée (vide) |
| Switch to unix_socket authentication | `n` |
| Change the root password | `Y` puis définir un mot de passe fort |
| Remove anonymous users | `Y` |
| Disallow root login remotely | `Y` |
| Remove test database | `Y` |
| Reload privilege tables | `Y` |

### Test de connexion

```bash
# Se connecter à MariaDB
mariadb -u root -p

# Dans le shell MariaDB
SHOW DATABASES;
EXIT;
```

---

## 4. Installation de PHP 8.2

### Activer le dépôt Remi

```bash
# Installer EPEL (prérequis)
dnf install -y epel-release

# Installer le dépôt Remi
dnf install -y https://rpms.remirepo.net/enterprise/remi-release-9.rpm

# Activer le module PHP 8.2
dnf module reset php -y
dnf module enable php:remi-8.2 -y
```

### Installation de PHP et modules

```bash
# Installer PHP et les modules courants
dnf install -y php php-cli php-common php-mysqlnd php-zip php-gd \
    php-mbstring php-curl php-xml php-json php-opcache php-intl
```

### Configuration

```bash
# Vérifier la version
php -v

# Afficher les modules installés
php -m
```

### Redémarrer Apache

```bash
# Apache doit être redémarré pour charger PHP
systemctl restart httpd
```

### Test PHP

```bash
# Créer une page phpinfo
cat > /var/www/html/info.php << 'EOF'
<?php
phpinfo();
EOF

# Tester
curl -s http://localhost/info.php | grep "PHP Version"
```

!!! warning "Supprimer info.php en production"
    ```bash
    rm -f /var/www/html/info.php
    ```

---

## 5. Test de la connexion PHP → MariaDB

### Créer une base de test

```bash
mariadb -u root -p << 'EOF'
CREATE DATABASE testdb;
CREATE USER 'testuser'@'localhost' IDENTIFIED BY 'TestPassword123!';
GRANT ALL PRIVILEGES ON testdb.* TO 'testuser'@'localhost';
FLUSH PRIVILEGES;
EOF
```

### Script de test PHP

```bash
cat > /var/www/html/dbtest.php << 'EOF'
<?php
$host = 'localhost';
$db   = 'testdb';
$user = 'testuser';
$pass = 'TestPassword123!';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$db", $user, $pass);
    echo "Connexion réussie à MariaDB!";
} catch (PDOException $e) {
    echo "Erreur : " . $e->getMessage();
}
EOF

# Tester
curl http://localhost/dbtest.php
```

**Résultat attendu :** `Connexion réussie à MariaDB!`

### Nettoyage

```bash
# Supprimer les fichiers de test
rm -f /var/www/html/info.php /var/www/html/dbtest.php

# Supprimer la base de test (optionnel)
mariadb -u root -p -e "DROP DATABASE testdb; DROP USER 'testuser'@'localhost';"
```

---

## 6. Configuration recommandée

### Apache - Cacher la version

```bash
cat >> /etc/httpd/conf/httpd.conf << 'EOF'

# Sécurité - Cacher les informations serveur
ServerTokens Prod
ServerSignature Off
EOF

systemctl restart httpd
```

### PHP - Paramètres de production

```bash
# Éditer php.ini
cat > /etc/php.d/99-production.ini << 'EOF'
; Sécurité
expose_php = Off
display_errors = Off
log_errors = On

; Performance
memory_limit = 256M
max_execution_time = 60
upload_max_filesize = 64M
post_max_size = 64M

; OPcache
opcache.enable = 1
opcache.memory_consumption = 128
opcache.max_accelerated_files = 10000
EOF

systemctl restart httpd
```

### MariaDB - Paramètres de base

```bash
cat > /etc/my.cnf.d/server-tuning.cnf << 'EOF'
[mysqld]
# InnoDB
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 2

# Connexions
max_connections = 100

# Cache
query_cache_type = 1
query_cache_size = 32M
EOF

systemctl restart mariadb
```

---

## 7. Virtual Host (optionnel)

### Créer un virtual host

```bash
# Créer le répertoire du site
mkdir -p /var/www/monsite.local/public_html
chown -R apache:apache /var/www/monsite.local

# Créer la configuration
cat > /etc/httpd/conf.d/monsite.local.conf << 'EOF'
<VirtualHost *:80>
    ServerName monsite.local
    ServerAlias www.monsite.local
    DocumentRoot /var/www/monsite.local/public_html

    <Directory /var/www/monsite.local/public_html>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog /var/log/httpd/monsite.local-error.log
    CustomLog /var/log/httpd/monsite.local-access.log combined
</VirtualHost>
EOF

# Tester la configuration
apachectl configtest

# Appliquer
systemctl reload httpd
```

---

## 8. Récapitulatif des services

```bash
# Vérifier tous les services
systemctl status httpd mariadb --no-pager

# Voir les ports en écoute
ss -tlnp | grep -E ':(80|443|3306)'
```

**Résultat attendu :**

| Port | Service | Description |
|------|---------|-------------|
| 80 | httpd | Apache HTTP |
| 443 | httpd | Apache HTTPS (après config SSL) |
| 3306 | mariadbd | MariaDB (local uniquement) |

---

## Dépannage

### Apache ne démarre pas

```bash
# Vérifier les logs
journalctl -u httpd -n 50

# Tester la configuration
apachectl configtest
```

### MariaDB refuse les connexions

```bash
# Vérifier les logs
journalctl -u mariadb -n 50

# Vérifier que le socket existe
ls -la /var/lib/mysql/mysql.sock
```

### PHP non exécuté (affiche le code source)

```bash
# Vérifier que le module PHP est chargé
httpd -M | grep php

# Si absent, réinstaller
dnf reinstall php
systemctl restart httpd
```

---

## Pour aller plus loin

- [Certificat SSL avec Let's Encrypt](../security/letsencrypt-certbot.md)
- [Backup MariaDB automatisé](../databases/mariadb-backup.md)
- [Monitoring avec Netdata](../monitoring/netdata-install.md)

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale - Rocky 9 + PHP 8.2 |
