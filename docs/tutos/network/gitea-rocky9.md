---
tags:
  - tutos
  - network
  - gitea
  - git
  - devops
  - rocky
---

# Gitea sur Rocky Linux 9

Installation de **Gitea**, serveur Git léger auto-hébergé.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Gitea | 1.21+ |
| MariaDB | 10.5+ |

**Durée estimée :** 30 minutes

---

## Gitea vs alternatives

| Critère | Gitea | GitLab | Gogs |
|---------|-------|--------|------|
| RAM | ~100MB | ~4GB | ~100MB |
| Fonctionnalités | Moyen | Complet | Basique |
| CI/CD | Actions | Intégré | Non |
| Maintenance | Active | Active | Faible |

---

## 1. Prérequis

### Base de données (MariaDB)

```bash
dnf install -y mariadb-server
systemctl enable --now mariadb

mysql_secure_installation

mysql -u root -p
```

```sql
CREATE DATABASE gitea CHARACTER SET 'utf8mb4' COLLATE 'utf8mb4_unicode_ci';
CREATE USER 'gitea'@'localhost' IDENTIFIED BY 'gitea_password';
GRANT ALL PRIVILEGES ON gitea.* TO 'gitea'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Git

```bash
dnf install -y git
git --version
```

---

## 2. Utilisateur Gitea

```bash
useradd -r -m -d /home/gitea -s /bin/bash gitea
```

---

## 3. Installation

### Télécharger le binaire

```bash
# Vérifier la dernière version sur https://dl.gitea.io/gitea/
GITEA_VERSION="1.21.3"

wget -O /usr/local/bin/gitea https://dl.gitea.io/gitea/${GITEA_VERSION}/gitea-${GITEA_VERSION}-linux-amd64

chmod +x /usr/local/bin/gitea

gitea --version
```

### Créer les répertoires

```bash
mkdir -p /var/lib/gitea/{custom,data,log}
mkdir -p /etc/gitea

chown -R gitea:gitea /var/lib/gitea
chown -R root:gitea /etc/gitea
chmod 750 /etc/gitea
```

---

## 4. Service systemd

```bash
cat > /etc/systemd/system/gitea.service << 'EOF'
[Unit]
Description=Gitea (Git with a cup of tea)
After=syslog.target
After=network.target
After=mariadb.service

[Service]
Type=simple
User=gitea
Group=gitea
WorkingDirectory=/var/lib/gitea
ExecStart=/usr/local/bin/gitea web --config /etc/gitea/app.ini
Restart=always
Environment=USER=gitea HOME=/home/gitea GITEA_WORK_DIR=/var/lib/gitea

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable gitea
```

---

## 5. Configuration

### Première configuration (via web)

```bash
systemctl start gitea
# Ouvrir http://IP:3000
```

### Configuration manuelle

```bash
vim /etc/gitea/app.ini
```

```ini
APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = gitea

[server]
HTTP_PORT = 3000
ROOT_URL = https://git.example.com/
DOMAIN = git.example.com
SSH_DOMAIN = git.example.com
SSH_PORT = 22
START_SSH_SERVER = false
OFFLINE_MODE = false

[database]
DB_TYPE = mysql
HOST = 127.0.0.1:3306
NAME = gitea
USER = gitea
PASSWD = gitea_password
CHARSET = utf8mb4

[repository]
ROOT = /var/lib/gitea/repositories

[security]
SECRET_KEY = GENERATE_ONE
INTERNAL_TOKEN = GENERATE_ONE
INSTALL_LOCK = true

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
ENABLE_NOTIFY_MAIL = false

[mailer]
ENABLED = false

[log]
MODE = file
LEVEL = info
ROOT_PATH = /var/lib/gitea/log
```

### Générer les tokens

```bash
gitea generate secret SECRET_KEY
gitea generate secret INTERNAL_TOKEN
```

---

## 6. Reverse Proxy Nginx

```bash
dnf install -y nginx

cat > /etc/nginx/conf.d/gitea.conf << 'EOF'
server {
    listen 80;
    server_name git.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name git.example.com;

    ssl_certificate /etc/letsencrypt/live/git.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/git.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        client_max_body_size 100M;
    }
}
EOF

systemctl enable --now nginx
```

---

## 7. Firewall

```bash
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

---

## 8. SSH Passthrough

### Option A : Port différent

```ini
# Dans app.ini
[server]
SSH_PORT = 2222
START_SSH_SERVER = true
SSH_LISTEN_PORT = 2222
```

### Option B : SSH Wrapper (recommandé)

```bash
# Créer le wrapper
cat > /usr/local/bin/gitea-shell << 'EOF'
#!/bin/sh
/usr/local/bin/gitea serv key-$1
EOF

chmod +x /usr/local/bin/gitea-shell

# Modifier /etc/passwd pour l'utilisateur gitea
# gitea:x:...:...:/home/gitea:/usr/local/bin/gitea-shell
```

---

## 9. Gitea Actions (CI/CD)

### Activer Actions

```ini
[actions]
ENABLED = true
```

### Runner

```bash
# Télécharger act_runner
wget https://dl.gitea.com/act_runner/0.2.6/act_runner-0.2.6-linux-amd64
chmod +x act_runner-*
mv act_runner-* /usr/local/bin/act_runner

# Enregistrer
act_runner register --instance https://git.example.com --token TOKEN

# Service
act_runner daemon
```

---

## 10. Backup

```bash
#!/bin/bash
# /usr/local/bin/gitea-backup.sh

BACKUP_DIR="/backup/gitea"
DATE=$(date +%Y%m%d)

mkdir -p $BACKUP_DIR

# Dump database
mysqldump -u gitea -pgitea_password gitea > $BACKUP_DIR/gitea-db-$DATE.sql

# Backup data
tar -czf $BACKUP_DIR/gitea-data-$DATE.tar.gz /var/lib/gitea /etc/gitea

# Garder 7 jours
find $BACKUP_DIR -mtime +7 -delete
```

---

## 11. Mise à jour

```bash
# Arrêter
systemctl stop gitea

# Backup
gitea dump -c /etc/gitea/app.ini

# Télécharger nouvelle version
wget -O /usr/local/bin/gitea https://dl.gitea.io/gitea/VERSION/gitea-VERSION-linux-amd64
chmod +x /usr/local/bin/gitea

# Redémarrer
systemctl start gitea
```

---

## Commandes utiles

```bash
# Admin
gitea admin user create --admin --username admin --password pass --email admin@example.com

# Régénérer hooks
gitea admin regenerate hooks

# Dump
gitea dump -c /etc/gitea/app.ini

# Doctor
gitea doctor check
```

---

## Dépannage

```bash
# Logs
journalctl -u gitea -f
tail -f /var/lib/gitea/log/gitea.log

# Permissions
chown -R gitea:gitea /var/lib/gitea
chmod 750 /etc/gitea
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
