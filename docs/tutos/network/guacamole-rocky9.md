---
tags:
  - tutos
  - network
  - guacamole
  - remote-desktop
  - vnc
  - rdp
  - ssh
  - rocky
---

# Apache Guacamole sur Rocky Linux 9

Installation de **Apache Guacamole** - passerelle de bureau à distance HTML5.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Guacamole | 1.5+ |
| Tomcat | 9 |
| MariaDB | 10.5+ |

**Durée estimée :** 40 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **SSH** | Connexion terminal |
| **RDP** | Windows Remote Desktop |
| **VNC** | Virtual Network Computing |
| **Telnet** | Legacy support |
| **SFTP** | Transfert de fichiers |
| **Recording** | Enregistrement sessions |

---

## 1. Dépendances

```bash
dnf install -y epel-release
dnf groupinstall -y "Development Tools"

dnf install -y cairo-devel libjpeg-turbo-devel libpng-devel \
    libtool uuid-devel freerdp-devel pango-devel libssh2-devel \
    libtelnet-devel libvncserver-devel libwebsockets-devel \
    pulseaudio-libs-devel openssl-devel libvorbis-devel libwebp-devel \
    ffmpeg-devel
```

---

## 2. Compiler guacamole-server

```bash
cd /tmp
wget https://apache.org/dyn/closer.lua/guacamole/1.5.4/source/guacamole-server-1.5.4.tar.gz?action=download -O guacamole-server-1.5.4.tar.gz
tar -xzf guacamole-server-1.5.4.tar.gz
cd guacamole-server-1.5.4

./configure --with-init-dir=/etc/init.d
make
make install
ldconfig
```

### Service systemd

```bash
cat > /etc/systemd/system/guacd.service << 'EOF'
[Unit]
Description=Guacamole Server
Documentation=man:guacd(8)
After=network.target

[Service]
User=daemon
ExecStart=/usr/local/sbin/guacd -f
Restart=on-abnormal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now guacd
```

---

## 3. Tomcat

```bash
dnf install -y tomcat
systemctl enable --now tomcat
```

---

## 4. Application Web Guacamole

```bash
mkdir -p /etc/guacamole/{extensions,lib}

cd /tmp
wget https://apache.org/dyn/closer.lua/guacamole/1.5.4/binary/guacamole-1.5.4.war?action=download -O guacamole-1.5.4.war
mv guacamole-1.5.4.war /var/lib/tomcat/webapps/guacamole.war

# Symlinks
ln -s /etc/guacamole /usr/share/tomcat/.guacamole
```

---

## 5. MariaDB

```bash
dnf install -y mariadb-server
systemctl enable --now mariadb
mysql_secure_installation
```

### Créer la base

```bash
mysql -u root -p
```

```sql
CREATE DATABASE guacamole_db;
CREATE USER 'guacamole_user'@'localhost' IDENTIFIED BY 'guacamole_password';
GRANT ALL PRIVILEGES ON guacamole_db.* TO 'guacamole_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Extension JDBC

```bash
cd /tmp
wget https://apache.org/dyn/closer.lua/guacamole/1.5.4/binary/guacamole-auth-jdbc-1.5.4.tar.gz?action=download -O guacamole-auth-jdbc-1.5.4.tar.gz
tar -xzf guacamole-auth-jdbc-1.5.4.tar.gz

cp guacamole-auth-jdbc-1.5.4/mysql/guacamole-auth-jdbc-mysql-1.5.4.jar /etc/guacamole/extensions/

# MySQL connector
wget https://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-j-8.2.0.tar.gz
tar -xzf mysql-connector-j-8.2.0.tar.gz
cp mysql-connector-j-8.2.0/mysql-connector-j-8.2.0.jar /etc/guacamole/lib/
```

### Schéma de base

```bash
cat guacamole-auth-jdbc-1.5.4/mysql/schema/*.sql | mysql -u root -p guacamole_db
```

---

## 6. Configuration Guacamole

```bash
cat > /etc/guacamole/guacamole.properties << 'EOF'
# Guacd
guacd-hostname: localhost
guacd-port: 4822

# MySQL
mysql-hostname: localhost
mysql-port: 3306
mysql-database: guacamole_db
mysql-username: guacamole_user
mysql-password: guacamole_password
mysql-auto-create-accounts: true
EOF

cat > /etc/guacamole/guacd.conf << 'EOF'
[daemon]
pid_file = /var/run/guacd.pid
log_level = info

[server]
bind_host = 127.0.0.1
bind_port = 4822
EOF
```

---

## 7. Redémarrer les services

```bash
systemctl restart guacd
systemctl restart tomcat
```

---

## 8. Firewall

```bash
firewall-cmd --permanent --add-port=8080/tcp
firewall-cmd --reload
```

---

## 9. Premier accès

- URL: `http://IP:8080/guacamole`
- Login: `guacadmin`
- Password: `guacadmin`

**Changer le mot de passe immédiatement !**

---

## 10. Ajouter une connexion SSH

1. Settings → Connections → New Connection
2. Name: Server SSH
3. Protocol: SSH
4. Parameters:
   - Hostname: 192.168.1.50
   - Port: 22
   - Username: admin
   - Password: ****
5. Save

---

## 11. Ajouter une connexion RDP

1. New Connection
2. Protocol: RDP
3. Parameters:
   - Hostname: 192.168.1.100
   - Port: 3389
   - Username: Administrator
   - Password: ****
   - Security mode: Any
   - Ignore server certificate: Yes
4. Save

---

## 12. Ajouter une connexion VNC

1. New Connection
2. Protocol: VNC
3. Parameters:
   - Hostname: 192.168.1.60
   - Port: 5900
   - Password: ****
4. Save

---

## 13. LDAP Authentication

### Extension LDAP

```bash
cd /tmp
wget https://apache.org/dyn/closer.lua/guacamole/1.5.4/binary/guacamole-auth-ldap-1.5.4.tar.gz?action=download -O guacamole-auth-ldap-1.5.4.tar.gz
tar -xzf guacamole-auth-ldap-1.5.4.tar.gz
cp guacamole-auth-ldap-1.5.4/guacamole-auth-ldap-1.5.4.jar /etc/guacamole/extensions/
```

### Configuration

Ajouter à `/etc/guacamole/guacamole.properties` :

```ini
# LDAP
ldap-hostname: dc.example.com
ldap-port: 389
ldap-user-base-dn: OU=Users,DC=example,DC=com
ldap-username-attribute: sAMAccountName
ldap-search-bind-dn: CN=svc-guac,OU=Service,DC=example,DC=com
ldap-search-bind-password: password
ldap-user-search-filter: (&(objectClass=user)(memberOf=CN=GuacamoleUsers,OU=Groups,DC=example,DC=com))
```

```bash
systemctl restart tomcat
```

---

## 14. TOTP (2FA)

### Extension TOTP

```bash
cd /tmp
wget https://apache.org/dyn/closer.lua/guacamole/1.5.4/binary/guacamole-auth-totp-1.5.4.tar.gz?action=download -O guacamole-auth-totp-1.5.4.tar.gz
tar -xzf guacamole-auth-totp-1.5.4.tar.gz
cp guacamole-auth-totp-1.5.4/guacamole-auth-totp-1.5.4.jar /etc/guacamole/extensions/
```

Ajouter à la config :

```ini
totp-issuer: MyCompany Guacamole
totp-digits: 6
totp-period: 30
```

```bash
systemctl restart tomcat
```

---

## 15. Session Recording

Ajouter à `/etc/guacamole/guacamole.properties` :

```ini
recording-path: /var/guacamole/recordings
recording-include-keys: true
create-recording-path: true
```

```bash
mkdir -p /var/guacamole/recordings
chown tomcat:tomcat /var/guacamole/recordings
```

Dans la connexion, activer "Record session".

---

## 16. Reverse Proxy Nginx

```bash
dnf install -y nginx

cat > /etc/nginx/conf.d/guacamole.conf << 'EOF'
server {
    listen 80;
    server_name guac.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name guac.example.com;

    ssl_certificate /etc/letsencrypt/live/guac.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/guac.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080/guacamole/;
        proxy_buffering off;
        proxy_http_version 1.1;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $http_connection;
        proxy_cookie_path /guacamole/ /;
    }
}
EOF

systemctl enable --now nginx
```

---

## 17. Docker alternative

```bash
mkdir -p /opt/guacamole
cd /opt/guacamole

cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  guacd:
    image: guacamole/guacd
    container_name: guacd
    restart: always

  guacamole:
    image: guacamole/guacamole
    container_name: guacamole
    restart: always
    ports:
      - "8080:8080"
    environment:
      GUACD_HOSTNAME: guacd
      MYSQL_HOSTNAME: db
      MYSQL_DATABASE: guacamole_db
      MYSQL_USER: guacamole_user
      MYSQL_PASSWORD: guacamole_password
    depends_on:
      - guacd
      - db

  db:
    image: mysql:8
    container_name: guacamole_db
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: root_password
      MYSQL_DATABASE: guacamole_db
      MYSQL_USER: guacamole_user
      MYSQL_PASSWORD: guacamole_password
    volumes:
      - db_data:/var/lib/mysql
      - ./initdb:/docker-entrypoint-initdb.d

volumes:
  db_data:
EOF

# Initialiser le schéma
mkdir initdb
docker run --rm guacamole/guacamole /opt/guacamole/bin/initdb.sh --mysql > initdb/01-schema.sql

docker compose up -d
```

---

## Commandes utiles

```bash
# Status
systemctl status guacd
systemctl status tomcat

# Logs
journalctl -u guacd -f
tail -f /var/log/tomcat/catalina.out

# Test guacd
nc -zv localhost 4822
```

---

## Dépannage

```bash
# Guacd debug
guacd -f -L debug

# Permissions
chown -R tomcat:tomcat /etc/guacamole

# Vérifier extensions
ls -la /etc/guacamole/extensions/
ls -la /etc/guacamole/lib/

# Logs Tomcat
tail -f /var/log/tomcat/localhost.*.log
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
