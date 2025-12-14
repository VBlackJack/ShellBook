---
tags:
  - tutos
  - network
  - proxy
  - squid
  - debian
---

# Squid Proxy sur Debian 12

Configuration de **Squid** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Squid | 5.7+ |

**Durée estimée :** 25 minutes

---

## 1. Installation

```bash
apt update
apt install -y squid

squid -v
```

---

## 2. Configuration

```bash
cp /etc/squid/squid.conf /etc/squid/squid.conf.bak
vim /etc/squid/squid.conf
```

```conf
# Port
http_port 3128

# Hostname
visible_hostname proxy.example.com

# ACL réseau
acl localnet src 192.168.1.0/24
acl localnet src 10.0.0.0/8

# Ports
acl SSL_ports port 443
acl Safe_ports port 80 21 443 70 210 1025-65535 280 488 591 777
acl CONNECT method CONNECT

# Accès
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access allow localhost manager
http_access deny manager
http_access allow localnet
http_access allow localhost
http_access deny all

# Cache
cache_mem 256 MB
cache_dir ufs /var/spool/squid 10000 16 256
maximum_object_size 50 MB

# Logs
access_log /var/log/squid/access.log squid

# Anonymiser
forwarded_for off
via off
```

---

## 3. Démarrer

```bash
squid -z
squid -k parse
systemctl enable --now squid
```

---

## 4. Firewall

```bash
ufw allow 3128/tcp
ufw reload
```

---

## 5. Filtrage

```bash
# Domaines bloqués
cat > /etc/squid/blocked_domains.txt << 'EOF'
.facebook.com
.twitter.com
EOF
```

```conf
acl blocked_domains dstdomain "/etc/squid/blocked_domains.txt"
http_access deny blocked_domains
```

---

## 6. Authentification

```bash
apt install -y apache2-utils
htpasswd -c /etc/squid/passwd user1
```

```conf
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwd
auth_param basic realm Proxy Authentication

acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
```

---

## 7. SSL Bump

```bash
mkdir -p /etc/squid/ssl
cd /etc/squid/ssl

openssl req -new -newkey rsa:2048 -sha256 -days 3650 -nodes -x509 \
    -keyout squid-ca.key -out squid-ca.crt \
    -subj "/CN=Squid Proxy CA"

/usr/lib/squid/security_file_certgen -c -s /var/lib/squid/ssl_db -M 20MB
chown -R proxy:proxy /etc/squid/ssl /var/lib/squid/ssl_db
```

```conf
http_port 3128 ssl-bump \
    cert=/etc/squid/ssl/squid-ca.crt \
    key=/etc/squid/ssl/squid-ca.key \
    generate-host-certificates=on

sslcrtd_program /usr/lib/squid/security_file_certgen -s /var/lib/squid/ssl_db -M 20MB

acl step1 at_step SslBump1
ssl_bump peek step1
ssl_bump bump all
```

---

## 8. Analyse des logs

```bash
# Top sites
awk '{print $7}' /var/log/squid/access.log | sort | uniq -c | sort -rn | head

# Temps réel
tail -f /var/log/squid/access.log
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | squid | squid |
| Config | /etc/squid/squid.conf | /etc/squid/squid.conf |
| User | squid | proxy |
| Auth helper | /usr/lib64/squid/ | /usr/lib/squid/ |

---

## Commandes

```bash
squid -k parse        # Vérifier config
squid -k reconfigure  # Recharger
squid -k rotate       # Rotation logs
squid -k shutdown     # Arrêt propre
squidclient mgr:info  # Status
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
