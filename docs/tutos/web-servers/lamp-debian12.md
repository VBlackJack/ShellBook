---
tags:
  - tutos
  - lamp
  - apache
  - php
  - mariadb
  - debian
---

# LAMP sur Debian 12

Stack **L**inux **A**pache **M**ariaDB **P**HP complète et sécurisée.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Apache | 2.4 |
| MariaDB | 10.11 |
| PHP | 8.2 |

**Durée estimée :** 25 minutes

**Prérequis :**

- Debian 12 installé (minimal ou server)
- Accès root ou sudo
- Connexion internet

---

## 1. Mise à jour du système

```bash
# Mise à jour complète
apt update && apt upgrade -y

# Installer les outils de base
apt install -y vim wget curl gnupg2 ca-certificates lsb-release apt-transport-https
```

---

## 2. Installation d'Apache

### Installation

```bash
# Installer Apache
apt install -y apache2

# Vérifier le statut
systemctl status apache2
```

!!! info "Démarrage automatique"
    Apache est automatiquement activé et démarré sur Debian après installation.

### Configuration Firewall (UFW)

```bash
# Installer UFW si nécessaire
apt install -y ufw

# Activer UFW
ufw enable

# Autoriser SSH (important !)
ufw allow ssh

# Autoriser HTTP et HTTPS
ufw allow 'WWW Full'

# Vérifier
ufw status
```

### Test

```bash
# Créer une page de test
echo "<h1>Apache fonctionne sur Debian 12</h1>" > /var/www/html/index.html

# Tester localement
curl http://localhost
```

---

## 3. Installation de MariaDB

### Installation

```bash
# Installer MariaDB server et client
apt install -y mariadb-server mariadb-client

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

### Installation

PHP 8.2 est disponible directement dans les dépôts Debian 12.

```bash
# Installer PHP et les modules courants
apt install -y php php-cli php-common php-mysql php-zip php-gd \
    php-mbstring php-curl php-xml php-intl php-opcache libapache2-mod-php
```

### Vérification

```bash
# Vérifier la version
php -v

# Afficher les modules installés
php -m
```

### Redémarrer Apache

```bash
# Apache doit être redémarré pour charger PHP
systemctl restart apache2
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
# Éditer la configuration de sécurité
cat >> /etc/apache2/conf-available/security.conf << 'EOF'

# Sécurité - Cacher les informations serveur
ServerTokens Prod
ServerSignature Off
EOF

# Activer et recharger
a2enconf security
systemctl reload apache2
```

### Apache - Activer mod_rewrite

```bash
# Activer le module rewrite (utile pour WordPress, Laravel, etc.)
a2enmod rewrite
systemctl restart apache2
```

### PHP - Paramètres de production

```bash
# Créer un fichier de configuration personnalisé
cat > /etc/php/8.2/apache2/conf.d/99-production.ini << 'EOF'
; Sécurité
expose_php = Off
display_errors = Off
log_errors = On
error_log = /var/log/php/error.log

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

# Créer le répertoire de logs PHP
mkdir -p /var/log/php
chown www-data:www-data /var/log/php

systemctl restart apache2
```

### MariaDB - Paramètres de base

```bash
cat > /etc/mysql/mariadb.conf.d/99-server-tuning.cnf << 'EOF'
[mysqld]
# InnoDB
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 2

# Connexions
max_connections = 100

# Performance
skip-name-resolve
EOF

systemctl restart mariadb
```

---

## 7. Virtual Host (optionnel)

### Créer un virtual host

```bash
# Créer le répertoire du site
mkdir -p /var/www/monsite.local/public_html
chown -R www-data:www-data /var/www/monsite.local

# Créer la configuration
cat > /etc/apache2/sites-available/monsite.local.conf << 'EOF'
<VirtualHost *:80>
    ServerName monsite.local
    ServerAlias www.monsite.local
    DocumentRoot /var/www/monsite.local/public_html

    <Directory /var/www/monsite.local/public_html>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/monsite.local-error.log
    CustomLog ${APACHE_LOG_DIR}/monsite.local-access.log combined
</VirtualHost>
EOF

# Activer le site
a2ensite monsite.local.conf

# Tester la configuration
apachectl configtest

# Appliquer
systemctl reload apache2
```

---

## 8. Récapitulatif des services

```bash
# Vérifier tous les services
systemctl status apache2 mariadb --no-pager

# Voir les ports en écoute
ss -tlnp | grep -E ':(80|443|3306)'
```

**Résultat attendu :**

| Port | Service | Description |
|------|---------|-------------|
| 80 | apache2 | Apache HTTP |
| 443 | apache2 | Apache HTTPS (après config SSL) |
| 3306 | mariadbd | MariaDB (local uniquement) |

---

## Différences Rocky 9 vs Debian 12

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Gestionnaire paquets | `dnf` | `apt` |
| Firewall par défaut | firewalld | aucun (ufw recommandé) |
| PHP | via Remi repo | natif 8.2 |
| Service Apache | `httpd` | `apache2` |
| Config Apache | `/etc/httpd/` | `/etc/apache2/` |
| Utilisateur web | `apache` | `www-data` |
| SELinux | Activé | Non présent |

---

## Dépannage

### Apache ne démarre pas

```bash
# Vérifier les logs
journalctl -u apache2 -n 50

# Tester la configuration
apachectl configtest

# Vérifier les erreurs de syntaxe
apache2ctl -t
```

### MariaDB refuse les connexions

```bash
# Vérifier les logs
journalctl -u mariadb -n 50

# Vérifier que le socket existe
ls -la /run/mysqld/mysqld.sock
```

### PHP non exécuté (affiche le code source)

```bash
# Vérifier que le module PHP est chargé
apachectl -M | grep php

# Si absent, réinstaller
apt install --reinstall libapache2-mod-php
a2enmod php8.2
systemctl restart apache2
```

---

## Pour aller plus loin

- [Certificat SSL avec Let's Encrypt](../security/letsencrypt-certbot.md)
- [Backup MariaDB automatisé](../databases/mariadb-backup.md)
- [LEMP Debian 12](lemp-debian12.md)

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale - Debian 12 + PHP 8.2 |
