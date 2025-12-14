---
tags:
  - tutos
  - network
  - gitea
  - git
  - devops
  - debian
---

# Gitea sur Debian 12

Installation de **Gitea** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Gitea | 1.21+ |
| MariaDB | 10.11+ |

**Durée estimée :** 25 minutes

---

## 1. Base de données

```bash
apt update
apt install -y mariadb-server git

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

---

## 2. Utilisateur

```bash
useradd -r -m -d /home/gitea -s /bin/bash gitea
```

---

## 3. Installation

```bash
GITEA_VERSION="1.21.3"
wget -O /usr/local/bin/gitea https://dl.gitea.io/gitea/${GITEA_VERSION}/gitea-${GITEA_VERSION}-linux-amd64
chmod +x /usr/local/bin/gitea

mkdir -p /var/lib/gitea/{custom,data,log}
mkdir -p /etc/gitea
chown -R gitea:gitea /var/lib/gitea
chown root:gitea /etc/gitea
chmod 750 /etc/gitea
```

---

## 4. Service systemd

```bash
cat > /etc/systemd/system/gitea.service << 'EOF'
[Unit]
Description=Gitea
After=network.target mariadb.service

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
systemctl enable --now gitea
```

---

## 5. Configuration initiale

Ouvrir `http://IP:3000` et compléter l'installation web.

---

## 6. Reverse Proxy Nginx

```bash
apt install -y nginx

cat > /etc/nginx/sites-available/gitea << 'EOF'
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
        client_max_body_size 100M;
    }
}
EOF

ln -s /etc/nginx/sites-available/gitea /etc/nginx/sites-enabled/
systemctl reload nginx
```

---

## 7. Firewall

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw reload
```

---

## 8. Gitea Actions

```ini
# /etc/gitea/app.ini
[actions]
ENABLED = true
```

```bash
wget https://dl.gitea.com/act_runner/0.2.6/act_runner-0.2.6-linux-amd64 -O /usr/local/bin/act_runner
chmod +x /usr/local/bin/act_runner
act_runner register --instance https://git.example.com --token TOKEN
```

---

## 9. Backup

```bash
mysqldump -u gitea -p gitea > gitea-db.sql
tar -czf gitea-data.tar.gz /var/lib/gitea /etc/gitea
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| MariaDB | 10.5 | 10.11 |
| Package | dnf | apt |
| Firewall | firewalld | ufw |

---

## Commandes

```bash
gitea admin user create --admin --username admin --password pass --email admin@example.com
gitea admin regenerate hooks
gitea dump -c /etc/gitea/app.ini
gitea doctor check
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
