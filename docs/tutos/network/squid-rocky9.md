---
tags:
  - tutos
  - network
  - proxy
  - squid
  - rocky
---

# Squid Proxy sur Rocky Linux 9

Configuration de **Squid** comme proxy cache et filtrage web.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Squid | 5.5+ |

**Durée estimée :** 30 minutes

---

## Cas d'utilisation

| Usage | Description |
|-------|-------------|
| **Cache** | Accélération navigation |
| **Filtrage** | Blocage sites/domaines |
| **Contrôle** | Logs et statistiques |
| **Authentification** | Accès par utilisateur |

---

## Architecture

```
┌─────────────┐     HTTP/HTTPS      ┌─────────────┐      ┌─────────────┐
│   Clients   │────────────────────►│    Squid    │─────►│  Internet   │
│  LAN        │                     │    Proxy    │      │             │
│             │◄────────────────────│   :3128     │◄─────│             │
└─────────────┘     Réponse cache   └─────────────┘      └─────────────┘
```

---

## 1. Installation

```bash
dnf install -y squid

# Version
squid -v
```

---

## 2. Configuration de base

```bash
cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
vim /etc/squid/squid.conf
```

```conf
# Port d'écoute
http_port 3128

# Nom du proxy
visible_hostname proxy.example.com

# ACL réseau local
acl localnet src 192.168.1.0/24
acl localnet src 10.0.0.0/8

# Ports autorisés
acl SSL_ports port 443
acl Safe_ports port 80          # http
acl Safe_ports port 21          # ftp
acl Safe_ports port 443         # https
acl Safe_ports port 70          # gopher
acl Safe_ports port 210         # wais
acl Safe_ports port 1025-65535  # unregistered ports
acl Safe_ports port 280         # http-mgmt
acl Safe_ports port 488         # gss-http
acl Safe_ports port 591         # filemaker
acl Safe_ports port 777         # multiling http

acl CONNECT method CONNECT

# Règles d'accès
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow localnet
http_access allow localhost
http_access deny all

# Cache
cache_mem 256 MB
maximum_object_size_in_memory 512 KB
cache_dir ufs /var/spool/squid 10000 16 256
maximum_object_size 50 MB
cache_swap_low 90
cache_swap_high 95

# Logs
access_log /var/log/squid/access.log squid
cache_log /var/log/squid/cache.log
cache_store_log /var/log/squid/store.log

# DNS
dns_nameservers 8.8.8.8 8.8.4.4

# Timeouts
connect_timeout 30 seconds
read_timeout 3 minutes
request_timeout 3 minutes

# Email admin
cache_mgr admin@example.com

# Anonymiser
forwarded_for off
via off
```

---

## 3. Initialiser et démarrer

```bash
# Créer les répertoires de cache
squid -z

# Vérifier la configuration
squid -k parse

# Démarrer
systemctl enable --now squid
systemctl status squid
```

---

## 4. Firewall et SELinux

```bash
# Firewall
firewall-cmd --permanent --add-port=3128/tcp
firewall-cmd --reload

# SELinux
setsebool -P squid_connect_any 1
```

---

## 5. Filtrage de sites

### Bloquer des domaines

```bash
cat > /etc/squid/blocked_domains.txt << 'EOF'
.facebook.com
.twitter.com
.instagram.com
.tiktok.com
EOF
```

```conf
# Dans squid.conf
acl blocked_domains dstdomain "/etc/squid/blocked_domains.txt"
http_access deny blocked_domains
```

### Bloquer des mots-clés URL

```bash
cat > /etc/squid/blocked_urls.txt << 'EOF'
porn
gambling
torrent
EOF
```

```conf
acl blocked_urls url_regex -i "/etc/squid/blocked_urls.txt"
http_access deny blocked_urls
```

### Bloquer des extensions

```conf
acl blocked_ext urlpath_regex -i \.(exe|mp3|mp4|avi|mkv)$
http_access deny blocked_ext
```

---

## 6. Authentification

### Basic (htpasswd)

```bash
dnf install -y httpd-tools
htpasswd -c /etc/squid/passwd user1
htpasswd /etc/squid/passwd user2
```

```conf
# Dans squid.conf
auth_param basic program /usr/lib64/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm Proxy Authentication
auth_param basic credentialsttl 2 hours

acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
```

### LDAP

```conf
auth_param basic program /usr/lib64/squid/basic_ldap_auth -v 3 \
    -b "dc=example,dc=com" \
    -D "cn=proxy,dc=example,dc=com" \
    -w "password" \
    -f "(&(uid=%s)(objectClass=person))" \
    -h ldap.example.com

auth_param basic realm LDAP Authentication
```

---

## 7. Proxy transparent

```conf
# Dans squid.conf
http_port 3128 intercept

# Désactiver pour HTTPS (nécessite SSL bump)
```

### Redirection iptables

```bash
# Sur le routeur/firewall
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 3128
```

---

## 8. HTTPS Interception (SSL Bump)

### Générer certificat CA

```bash
mkdir -p /etc/squid/ssl
cd /etc/squid/ssl

# CA
openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \
    -extensions v3_ca \
    -keyout squid-ca.key \
    -out squid-ca.crt \
    -subj "/CN=Squid Proxy CA/O=Example/C=FR"

# Convertir en DER pour clients
openssl x509 -in squid-ca.crt -outform DER -out squid-ca.der

# Initialiser la base de certificats
/usr/lib64/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 20MB

chown -R squid:squid /etc/squid/ssl /var/lib/squid/ssl_db
```

### Configuration SSL Bump

```conf
http_port 3128 ssl-bump \
    cert=/etc/squid/ssl/squid-ca.crt \
    key=/etc/squid/ssl/squid-ca.key \
    generate-host-certificates=on \
    dynamic_cert_mem_cache_size=4MB

sslcrtd_program /usr/lib64/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 20MB

acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all
```

---

## 9. Restrictions horaires

```conf
# Heures de bureau
acl business_hours time MTWHF 08:00-18:00

# Bloquer les réseaux sociaux pendant le travail
acl social dstdomain .facebook.com .twitter.com
http_access deny social business_hours
http_access allow social
```

---

## 10. Monitoring et logs

### Analyser les logs

```bash
# Logs en temps réel
tail -f /var/log/squid/access.log

# Top sites
awk '{print $7}' /var/log/squid/access.log | sort | uniq -c | sort -rn | head -20

# Par utilisateur
awk '{print $3}' /var/log/squid/access.log | sort | uniq -c | sort -rn
```

### SARG (rapports)

```bash
dnf install -y sarg
sarg -l /var/log/squid/access.log
```

### Cache Manager

```bash
# Via navigateur
# http://proxy:3128/squid-internal-mgr/

squidclient mgr:info
squidclient mgr:utilization
squidclient mgr:client_list
```

---

## Commandes de gestion

```bash
# Vérifier config
squid -k parse

# Recharger config
squid -k reconfigure

# Rotation des logs
squid -k rotate

# Arrêt propre
squid -k shutdown

# Status du cache
squidclient mgr:info
```

---

## Dépannage

```bash
# Logs
tail -f /var/log/squid/cache.log
tail -f /var/log/squid/access.log

# Debug
squid -d 2 -N

# Test ACL
squid -k parse 2>&1 | grep -i error
```

| Problème | Solution |
|----------|----------|
| Permission denied | Vérifier SELinux, droits |
| Cannot resolve | Vérifier dns_nameservers |
| Access denied | Vérifier ACL |
| HTTPS non intercepté | Installer certificat CA |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
