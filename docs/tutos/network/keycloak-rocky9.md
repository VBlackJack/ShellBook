---
tags:
  - tutos
  - network
  - keycloak
  - sso
  - iam
  - rocky
---

# Keycloak sur Rocky Linux 9

Installation de **Keycloak** pour l'identity management et SSO.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Keycloak | 23+ |
| PostgreSQL | 15+ |

**Durée estimée :** 40 minutes

---

## Fonctionnalités

| Protocole | Description |
|-----------|-------------|
| **OpenID Connect** | SSO moderne |
| **OAuth 2.0** | Autorisation |
| **SAML 2.0** | SSO enterprise |
| **LDAP/AD** | Fédération d'identité |

---

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   Application   │────►│    Keycloak     │
│   (Client)      │◄────│    (IdP)        │
└─────────────────┘     └────────┬────────┘
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
             ┌──────────┐ ┌──────────┐ ┌──────────┐
             │PostgreSQL│ │   LDAP   │ │   AD     │
             └──────────┘ └──────────┘ └──────────┘
```

---

## 1. Prérequis

### Java 17

```bash
dnf install -y java-17-openjdk java-17-openjdk-devel
java -version
```

### PostgreSQL

```bash
dnf install -y postgresql-server postgresql
postgresql-setup --initdb
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

## 2. Installation Keycloak

```bash
cd /opt
wget https://github.com/keycloak/keycloak/releases/download/23.0.3/keycloak-23.0.3.tar.gz
tar -xzf keycloak-23.0.3.tar.gz
mv keycloak-23.0.3 keycloak

# Utilisateur dédié
useradd -r -s /sbin/nologin keycloak
chown -R keycloak:keycloak /opt/keycloak
```

---

## 3. Configuration

```bash
vim /opt/keycloak/conf/keycloak.conf
```

```properties
# Database
db=postgres
db-url=jdbc:postgresql://localhost:5432/keycloak
db-username=keycloak
db-password=keycloak_password

# HTTP
http-enabled=true
http-port=8080
hostname=keycloak.example.com

# Proxy (si derrière reverse proxy)
proxy=edge

# Production mode
# http-enabled=false
# https-port=8443
# https-certificate-file=/path/to/cert.pem
# https-certificate-key-file=/path/to/key.pem
```

---

## 4. Build et démarrage

### Mode développement

```bash
/opt/keycloak/bin/kc.sh start-dev
```

### Mode production

```bash
# Build
/opt/keycloak/bin/kc.sh build

# Créer l'admin
export KEYCLOAK_ADMIN=admin
export KEYCLOAK_ADMIN_PASSWORD=admin_password

# Démarrer
/opt/keycloak/bin/kc.sh start --optimized
```

---

## 5. Service systemd

```bash
cat > /etc/systemd/system/keycloak.service << 'EOF'
[Unit]
Description=Keycloak Server
After=network.target postgresql.service

[Service]
Type=simple
User=keycloak
Group=keycloak
Environment="KEYCLOAK_ADMIN=admin"
Environment="KEYCLOAK_ADMIN_PASSWORD=admin_password"
ExecStart=/opt/keycloak/bin/kc.sh start --optimized
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now keycloak
```

---

## 6. Reverse Proxy Nginx

```bash
dnf install -y nginx
```

```nginx
# /etc/nginx/conf.d/keycloak.conf
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
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
}
```

```bash
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

## 8. Configuration initiale

### Accéder à la console

1. Ouvrir `https://keycloak.example.com`
2. Login : `admin` / `admin_password`

### Créer un Realm

1. Master → Create Realm
2. Nom : `mycompany`

### Créer un Client (application)

1. Clients → Create client
2. Client ID : `myapp`
3. Client Protocol : `openid-connect`
4. Access Type : `confidential`
5. Valid Redirect URIs : `https://myapp.example.com/*`

### Récupérer le secret

1. Clients → myapp → Credentials
2. Copier le Secret

---

## 9. Fédération LDAP

1. User Federation → Add provider → LDAP
2. Configuration :

```
Vendor: Other
Connection URL: ldap://ldap.example.com:389
Users DN: ou=users,dc=example,dc=com
Bind DN: cn=admin,dc=example,dc=com
Bind Credential: password
```

3. Synchronize all users

---

## 10. Fédération Active Directory

1. User Federation → Add provider → LDAP
2. Vendor : Active Directory
3. Configuration :

```
Connection URL: ldap://ad.example.com:389
Users DN: CN=Users,DC=ad,DC=example,DC=com
Bind DN: CN=svc_keycloak,CN=Users,DC=ad,DC=example,DC=com
```

---

## 11. SAML Configuration

### Identity Provider (externe)

1. Identity Providers → Add provider → SAML v2.0
2. Import metadata ou configurer manuellement

### Service Provider (Keycloak)

1. Clients → Create client
2. Protocol : SAML
3. Configurer les URLs et certificats

---

## 12. Authentification 2FA

1. Authentication → Required actions
2. Activer "Configure OTP"
3. Authentication → Flows → Browser
4. Ajouter "OTP Form"

---

## 13. Thèmes personnalisés

```bash
mkdir -p /opt/keycloak/themes/mytheme/login
cp -r /opt/keycloak/lib/lib/main/org.keycloak.keycloak-themes-*.jar /tmp/
cd /tmp && unzip keycloak-themes-*.jar

# Personnaliser les fichiers dans /opt/keycloak/themes/mytheme/
```

---

## Commandes CLI (kcadm)

```bash
# Authentification
/opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 \
    --realm master \
    --user admin

# Créer un realm
/opt/keycloak/bin/kcadm.sh create realms -s realm=test -s enabled=true

# Créer un utilisateur
/opt/keycloak/bin/kcadm.sh create users -r myrealm \
    -s username=newuser \
    -s enabled=true

# Définir le mot de passe
/opt/keycloak/bin/kcadm.sh set-password -r myrealm \
    --username newuser \
    --new-password password
```

---

## Dépannage

```bash
# Logs
journalctl -u keycloak -f
tail -f /opt/keycloak/data/log/keycloak.log

# Test
curl -k https://keycloak.example.com/realms/master/.well-known/openid-configuration

# Debug
/opt/keycloak/bin/kc.sh start-dev --log-level=DEBUG
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
