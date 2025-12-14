---
tags:
  - tutos
  - network
  - guacamole
  - remote-desktop
  - vnc
  - rdp
  - ssh
  - debian
---

# Apache Guacamole sur Debian 12

Installation de **Apache Guacamole** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Guacamole | 1.5+ |
| Tomcat | 10 |
| MariaDB | 10.11 |

**Durée estimée :** 35 minutes

---

## 1. Dépendances

```bash
apt update
apt install -y build-essential libcairo2-dev libjpeg62-turbo-dev libpng-dev \
    libtool-bin uuid-dev libfreerdp-dev libpango1.0-dev libssh2-1-dev \
    libtelnet-dev libvncserver-dev libwebsockets-dev libpulse-dev \
    libssl-dev libvorbis-dev libwebp-dev freerdp2-dev
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
apt install -y tomcat10
systemctl enable --now tomcat10
```

---

## 4. Application Web

```bash
mkdir -p /etc/guacamole/{extensions,lib}

cd /tmp
wget https://apache.org/dyn/closer.lua/guacamole/1.5.4/binary/guacamole-1.5.4.war?action=download -O guacamole-1.5.4.war
mv guacamole-1.5.4.war /var/lib/tomcat10/webapps/guacamole.war

ln -s /etc/guacamole /usr/share/tomcat10/.guacamole
```

---

## 5. MariaDB

```bash
apt install -y mariadb-server
systemctl enable --now mariadb
mysql_secure_installation
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

# Schéma
cat guacamole-auth-jdbc-1.5.4/mysql/schema/*.sql | mysql -u root -p guacamole_db
```

---

## 6. Configuration

```bash
cat > /etc/guacamole/guacamole.properties << 'EOF'
guacd-hostname: localhost
guacd-port: 4822

mysql-hostname: localhost
mysql-port: 3306
mysql-database: guacamole_db
mysql-username: guacamole_user
mysql-password: guacamole_password
EOF

cat > /etc/guacamole/guacd.conf << 'EOF'
[daemon]
pid_file = /var/run/guacd.pid

[server]
bind_host = 127.0.0.1
bind_port = 4822
EOF
```

---

## 7. Redémarrer

```bash
systemctl restart guacd
systemctl restart tomcat10
```

---

## 8. Firewall

```bash
ufw allow 8080/tcp
ufw reload
```

---

## 9. Accès

- URL: `http://IP:8080/guacamole`
- Login: `guacadmin` / `guacadmin`

---

## 10. Docker

```yaml
# docker-compose.yml
version: '3.8'

services:
  guacd:
    image: guacamole/guacd
    restart: always

  guacamole:
    image: guacamole/guacamole
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
```

```bash
mkdir initdb
docker run --rm guacamole/guacamole /opt/guacamole/bin/initdb.sh --mysql > initdb/01-schema.sql
docker compose up -d
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Tomcat | tomcat (9) | tomcat10 |
| libjpeg | libjpeg-turbo-devel | libjpeg62-turbo-dev |
| Firewall | firewalld | ufw |

---

## Commandes

```bash
# Status
systemctl status guacd tomcat10

# Logs
journalctl -u guacd -f
tail -f /var/log/tomcat10/catalina.out

# Test
nc -zv localhost 4822
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
