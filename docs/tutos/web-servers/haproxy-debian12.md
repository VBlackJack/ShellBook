---
tags:
  - tutos
  - haproxy
  - load-balancer
  - high-availability
  - debian
---

# HAProxy sur Debian 12

Installation et configuration de **HAProxy** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| HAProxy | 2.6+ |

**Durée estimée :** 30 minutes

---

## 1. Installation

```bash
apt update
apt install -y haproxy

# Activer
systemctl enable haproxy

# Version
haproxy -v
```

---

## 2. Configuration de base

```bash
cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak
vim /etc/haproxy/haproxy.cfg
```

```haproxy
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

    # SSL
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    log global
    mode http
    option httplog
    option dontlognull
    option forwardfor
    option http-server-close
    timeout connect 5000
    timeout client 50000
    timeout server 50000
    errorfile 400 /etc/haproxy/errors/400.http
    errorfile 403 /etc/haproxy/errors/403.http
    errorfile 408 /etc/haproxy/errors/408.http
    errorfile 500 /etc/haproxy/errors/500.http
    errorfile 502 /etc/haproxy/errors/502.http
    errorfile 503 /etc/haproxy/errors/503.http
    errorfile 504 /etc/haproxy/errors/504.http

# Page de stats
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 10s
    stats auth admin:SecurePassword123

# Frontend HTTP
frontend http_front
    bind *:80
    default_backend http_back

# Backend
backend http_back
    balance roundrobin
    option httpchk GET /
    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
```

---

## 3. Démarrage

```bash
# Vérifier la config
haproxy -c -f /etc/haproxy/haproxy.cfg

# Démarrer
systemctl start haproxy
systemctl status haproxy

# Firewall UFW
ufw allow 80/tcp
ufw allow 8404/tcp
```

---

## 4. Load Balancing avancé

### Algorithmes

```haproxy
backend http_back
    # Round Robin
    balance roundrobin

    # Least Connections
    # balance leastconn

    # Source Hash (sticky par IP)
    # balance source

    # Avec poids
    server web1 192.168.1.10:80 check weight 3
    server web2 192.168.1.11:80 check weight 1
    server web3 192.168.1.12:80 check backup
```

### Health checks HTTP

```haproxy
backend http_back
    option httpchk GET /health HTTP/1.1\r\nHost:\ localhost
    http-check expect status 200

    server web1 192.168.1.10:80 check inter 5s fall 3 rise 2
    server web2 192.168.1.11:80 check inter 5s fall 3 rise 2
```

---

## 5. Routage par domaine/chemin

```haproxy
frontend http_front
    bind *:80

    # ACLs
    acl is_api hdr(host) -i api.example.com
    acl is_app hdr(host) -i app.example.com
    acl path_api path_beg /api
    acl path_static path_beg /static /assets

    # Routage
    use_backend api_back if is_api
    use_backend api_back if path_api
    use_backend app_back if is_app
    use_backend static_back if path_static
    default_backend web_back

backend api_back
    balance leastconn
    server api1 192.168.1.20:3000 check
    server api2 192.168.1.21:3000 check

backend app_back
    server app1 192.168.1.30:8080 check

backend static_back
    server static1 192.168.1.40:80 check

backend web_back
    server web1 192.168.1.10:80 check
```

---

## 6. SSL/TLS Termination

```haproxy
frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/example.com.pem
    bind *:80

    # Redirection HTTPS
    http-request redirect scheme https unless { ssl_fc }
    http-request set-header X-Forwarded-Proto https if { ssl_fc }

    default_backend http_back
```

### Créer le PEM

```bash
mkdir -p /etc/haproxy/certs

# Combiner cert + key
cat /etc/letsencrypt/live/example.com/fullchain.pem \
    /etc/letsencrypt/live/example.com/privkey.pem \
    > /etc/haproxy/certs/example.com.pem

chmod 600 /etc/haproxy/certs/example.com.pem
chown haproxy:haproxy /etc/haproxy/certs/example.com.pem
```

### Multi-certificats

```haproxy
frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/
    # HAProxy charge tous les .pem du dossier et utilise SNI
```

---

## 7. Sticky Sessions

```haproxy
backend app_back
    balance roundrobin
    cookie SERVERID insert indirect nocache

    server web1 192.168.1.10:80 check cookie s1
    server web2 192.168.1.11:80 check cookie s2
```

### Sticky par IP

```haproxy
backend app_back
    stick-table type ip size 100k expire 30m
    stick on src

    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
```

---

## 8. Rate Limiting

```haproxy
frontend http_front
    bind *:80

    # Compteur par IP
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src

    # Limite : 100 req/10s
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }

    default_backend http_back
```

### Protection connexions

```haproxy
frontend http_front
    bind *:80

    stick-table type ip size 100k expire 30s store conn_cur
    http-request track-sc0 src

    # Max 20 connexions simultanées par IP
    http-request deny deny_status 429 if { sc_conn_cur(0) gt 20 }
```

---

## 9. WebSocket

```haproxy
frontend http_front
    bind *:80

    acl is_websocket hdr(Upgrade) -i websocket
    use_backend ws_back if is_websocket
    default_backend http_back

backend ws_back
    balance source
    option http-server-close
    timeout tunnel 1h

    server ws1 192.168.1.50:3001 check
```

---

## 10. Headers de sécurité

```haproxy
frontend http_front
    bind *:80

    # Sécurité
    http-response set-header X-Frame-Options "SAMEORIGIN"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"

    # Supprimer infos serveur
    http-response del-header Server
    http-response del-header X-Powered-By

    default_backend http_back
```

---

## 11. Logging

Les logs vont déjà dans syslog. Pour un fichier dédié :

```bash
vim /etc/rsyslog.d/49-haproxy.conf
```

```
$AddUnixListenSocket /var/lib/haproxy/dev/log

local0.* /var/log/haproxy/haproxy.log
local1.* /var/log/haproxy/haproxy-info.log
```

```bash
mkdir -p /var/log/haproxy /var/lib/haproxy/dev
systemctl restart rsyslog haproxy
```

---

## 12. Socket admin

```bash
# Activer dans global
# stats socket /run/haproxy/admin.sock mode 660 level admin

# Commandes utiles
echo "show info" | socat stdio /run/haproxy/admin.sock
echo "show stat" | socat stdio /run/haproxy/admin.sock
echo "show servers state" | socat stdio /run/haproxy/admin.sock

# Disable/enable serveur
echo "disable server http_back/web1" | socat stdio /run/haproxy/admin.sock
echo "enable server http_back/web1" | socat stdio /run/haproxy/admin.sock

# Poids dynamique
echo "set server http_back/web1 weight 50%" | socat stdio /run/haproxy/admin.sock
```

---

## 13. Configuration production

```haproxy
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    user haproxy
    group haproxy
    daemon
    maxconn 4096
    ssl-default-bind-options ssl-min-ver TLSv1.2

defaults
    log global
    mode http
    option httplog
    option dontlognull
    option forwardfor
    option http-server-close
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    timeout http-keep-alive 10s
    timeout check 5s

listen stats
    bind 127.0.0.1:8404
    stats enable
    stats uri /stats
    stats auth admin:SecurePass!

frontend www
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/ alpn h2,http/1.1

    http-request redirect scheme https unless { ssl_fc }
    http-response set-header Strict-Transport-Security "max-age=31536000"

    acl is_api path_beg /api
    use_backend api if is_api
    default_backend web

backend web
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    cookie SRV insert indirect nocache
    server web1 192.168.1.10:80 check cookie w1
    server web2 192.168.1.11:80 check cookie w2

backend api
    balance leastconn
    option httpchk GET /api/health
    server api1 192.168.1.20:3000 check
    server api2 192.168.1.21:3000 check
```

---

## Comparatif Rocky 9 vs Debian 12

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Socket path | /var/lib/haproxy/stats | /run/haproxy/admin.sock |
| SELinux | Oui | Non |
| Errors path | À créer | /etc/haproxy/errors/ |
| Firewall | firewalld | ufw/iptables |

---

## Vérification

```bash
haproxy -c -f /etc/haproxy/haproxy.cfg
systemctl status haproxy
curl -I http://localhost
curl http://localhost:8404/stats
```

---

## Dépannage

```bash
# Logs
tail -f /var/log/haproxy.log
journalctl -u haproxy -f

# Stats socket
echo "show stat" | socat stdio /run/haproxy/admin.sock | cut -d',' -f1,2,18

# Connexions
ss -tlnp | grep haproxy
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
