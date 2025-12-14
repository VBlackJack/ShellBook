---
tags:
  - tutos
  - network
  - keycloak
  - sso
  - iam
  - debian
---

# Keycloak sur Debian 12

Installation de **Keycloak** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Keycloak | 23+ |
| PostgreSQL | 15+ |

**Durée estimée :** 35 minutes

---

## 1. Prérequis

### Java 17

```bash
apt update
apt install -y openjdk-17-jdk
java -version
```

### PostgreSQL

```bash
apt install -y postgresql postgresql-contrib
systemctl enable --now postgresql
```

```bash
sudo -u postgres psql
```

```sql
CREATE DATABASE keycloak;
CREATE USER keycloak WITH PASSWORD 'keycloak_password';
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
\c keycloak
GRANT ALL ON SCHEMA public TO keycloak;
\q
```

---

## 2. Installation

```bash
cd /opt
wget https://github.com/keycloak/keycloak/releases/download/23.0.3/keycloak-23.0.3.tar.gz
tar -xzf keycloak-23.0.3.tar.gz
mv keycloak-23.0.3 keycloak

useradd -r -s /sbin/nologin keycloak
chown -R keycloak:keycloak /opt/keycloak
```

---

## 3. Configuration

```bash
vim /opt/keycloak/conf/keycloak.conf
```

```properties
db=postgres
db-url=jdbc:postgresql://localhost:5432/keycloak
db-username=keycloak
db-password=keycloak_password

http-enabled=true
http-port=8080
hostname=keycloak.example.com
proxy=edge
```

---

## 4. Build et service

```bash
/opt/keycloak/bin/kc.sh build
```

```bash
cat > /etc/systemd/system/keycloak.service << 'EOF'
[Unit]
Description=Keycloak
After=network.target postgresql.service

[Service]
Type=simple
User=keycloak
Group=keycloak
Environment="KEYCLOAK_ADMIN=admin"
Environment="KEYCLOAK_ADMIN_PASSWORD=admin_password"
ExecStart=/opt/keycloak/bin/kc.sh start --optimized
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now keycloak
```

---

## 5. Reverse Proxy Nginx

```bash
apt install -y nginx
```

```nginx
# /etc/nginx/sites-available/keycloak
server {
    listen 80;
    server_name keycloak.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name keycloak.example.com;

    ssl_certificate /etc/letsencrypt/live/keycloak.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/keycloak.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
ln -s /etc/nginx/sites-available/keycloak /etc/nginx/sites-enabled/
systemctl reload nginx
```

---

## 6. Firewall

```bash
ufw allow 80/tcp
ufw allow 443/tcp
ufw reload
```

---

## 7. Accès

1. Ouvrir `https://keycloak.example.com`
2. Login : `admin` / `admin_password`

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Java | java-17-openjdk | openjdk-17-jdk |
| PostgreSQL | postgresql-server | postgresql |
| Nginx config | /etc/nginx/conf.d/ | /etc/nginx/sites-available/ |

---

## Commandes

```bash
# Status
systemctl status keycloak

# Logs
journalctl -u keycloak -f

# CLI admin
/opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 \
    --realm master \
    --user admin
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
