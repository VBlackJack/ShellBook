---
tags:
  - tutos
  - haproxy
  - load-balancer
  - high-availability
  - rocky
---

# HAProxy sur Rocky Linux 9

Installation et configuration de **HAProxy** comme load balancer et reverse proxy.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| HAProxy | 2.4+ |

**Durée estimée :** 30 minutes

---

## Concepts

```
                     ┌─────────────┐
                     │   HAProxy   │
    Clients ────────►│ :80 / :443  │
                     └──────┬──────┘
                            │
           ┌────────────────┼────────────────┐
           ▼                ▼                ▼
      ┌─────────┐      ┌─────────┐      ┌─────────┐
      │ Backend │      │ Backend │      │ Backend │
      │   :80   │      │   :80   │      │   :80   │
      └─────────┘      └─────────┘      └─────────┘
```

### Terminologie

| Terme | Description |
|-------|-------------|
| **Frontend** | Point d'entrée (écoute les clients) |
| **Backend** | Pool de serveurs |
| **ACL** | Règle de routage conditionnelle |
| **Health check** | Vérification de l'état des serveurs |

---

## 1. Installation

```bash
dnf install -y haproxy

# Activer au démarrage
systemctl enable haproxy

# Version
haproxy -v
```

---

## 2. Configuration de base

```bash
# Backup
cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak

vim /etc/haproxy/haproxy.cfg
```

```haproxy
#---------------------------------------------------------------------
# Global settings
#---------------------------------------------------------------------
global
    log         /dev/log local0
    log         /dev/log local1 notice
    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon

    # SSL/TLS
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

#---------------------------------------------------------------------
# Defaults
#---------------------------------------------------------------------
defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option                  http-server-close
    option                  forwardfor except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 3000

#---------------------------------------------------------------------
# Stats page
#---------------------------------------------------------------------
listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 10s
    stats admin if LOCALHOST
    stats auth admin:CHANGE_ME

#---------------------------------------------------------------------
# Frontend HTTP
#---------------------------------------------------------------------
frontend http_front
    bind *:80
    default_backend http_back

#---------------------------------------------------------------------
# Backend HTTP
#---------------------------------------------------------------------
backend http_back
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200

    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
    server web3 192.168.1.12:80 check backup
```

---

## 3. Démarrage et test

```bash
# Vérifier la configuration
haproxy -c -f /etc/haproxy/haproxy.cfg

# Démarrer
systemctl start haproxy
systemctl status haproxy

# Firewall
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-port=8404/tcp
firewall-cmd --reload
```

Accéder aux stats : `http://IP:8404/stats`

---

## 4. Algorithmes de load balancing

```haproxy
backend http_back
    # Round Robin (défaut) - distribution égale
    balance roundrobin

    # Least Connections - serveur le moins chargé
    # balance leastconn

    # Source IP Hash - même client → même serveur
    # balance source

    # URI Hash - même URL → même serveur
    # balance uri

    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
```

### Poids des serveurs

```haproxy
backend http_back
    balance roundrobin
    server web1 192.168.1.10:80 check weight 3  # 3x plus de trafic
    server web2 192.168.1.11:80 check weight 1
```

---

## 5. Health checks

```haproxy
backend http_back
    option httpchk GET /health
    http-check expect status 200

    # Check toutes les 5s, 2 échecs = down, 3 succès = up
    server web1 192.168.1.10:80 check inter 5s fall 2 rise 3
    server web2 192.168.1.11:80 check inter 5s fall 2 rise 3
```

### Check TCP simple

```haproxy
backend tcp_back
    mode tcp
    option tcp-check
    server db1 192.168.1.20:3306 check
```

---

## 6. Routage par ACL

### Routage par domaine

```haproxy
frontend http_front
    bind *:80

    # ACLs basées sur le Host header
    acl is_api hdr(host) -i api.example.com
    acl is_app hdr(host) -i app.example.com
    acl is_admin hdr(host) -i admin.example.com

    # Routage
    use_backend api_back if is_api
    use_backend app_back if is_app
    use_backend admin_back if is_admin
    default_backend default_back

backend api_back
    server api1 192.168.1.20:3000 check
    server api2 192.168.1.21:3000 check

backend app_back
    server app1 192.168.1.30:8080 check

backend admin_back
    server admin1 192.168.1.40:8000 check

backend default_back
    server default 192.168.1.10:80 check
```

### Routage par chemin

```haproxy
frontend http_front
    bind *:80

    acl is_api path_beg /api
    acl is_static path_beg /static /assets /images
    acl is_websocket hdr(Upgrade) -i websocket

    use_backend api_back if is_api
    use_backend static_back if is_static
    use_backend ws_back if is_websocket
    default_backend app_back
```

---

## 7. SSL/TLS Termination

```haproxy
frontend https_front
    bind *:443 ssl crt /etc/haproxy/certs/example.com.pem
    bind *:80

    # Redirection HTTP → HTTPS
    http-request redirect scheme https unless { ssl_fc }

    # Header pour le backend
    http-request set-header X-Forwarded-Proto https if { ssl_fc }

    default_backend http_back
```

### Créer le fichier PEM

```bash
# Combiner certificat et clé
cat /etc/letsencrypt/live/example.com/fullchain.pem \
    /etc/letsencrypt/live/example.com/privkey.pem \
    > /etc/haproxy/certs/example.com.pem

chmod 600 /etc/haproxy/certs/example.com.pem
```

---

## 8. SSL Passthrough

Pour laisser le backend gérer SSL :

```haproxy
frontend https_front
    bind *:443
    mode tcp
    option tcplog

    tcp-request inspect-delay 5s
    tcp-request content accept if { req_ssl_hello_type 1 }

    use_backend https_back

backend https_back
    mode tcp
    server web1 192.168.1.10:443 check
```

---

## 9. Sticky Sessions

```haproxy
backend app_back
    balance roundrobin
    cookie SERVERID insert indirect nocache

    server web1 192.168.1.10:80 check cookie web1
    server web2 192.168.1.11:80 check cookie web2
```

### Avec table de session

```haproxy
backend app_back
    balance roundrobin
    stick-table type ip size 200k expire 30m
    stick on src

    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
```

---

## 10. Rate Limiting

```haproxy
frontend http_front
    bind *:80

    # Table pour compter les requêtes par IP
    stick-table type ip size 100k expire 30s store http_req_rate(10s)
    http-request track-sc0 src

    # Bloquer si > 100 requêtes en 10s
    http-request deny deny_status 429 if { sc_http_req_rate(0) gt 100 }

    default_backend http_back
```

---

## 11. Headers de sécurité

```haproxy
frontend http_front
    bind *:80

    # Headers de sécurité
    http-response set-header X-Frame-Options "SAMEORIGIN"
    http-response set-header X-Content-Type-Options "nosniff"
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header Referrer-Policy "strict-origin-when-cross-origin"

    # Supprimer headers serveur
    http-response del-header Server
    http-response del-header X-Powered-By

    default_backend http_back
```

---

## 12. Logging

```bash
# Configurer rsyslog pour HAProxy
vim /etc/rsyslog.d/haproxy.conf
```

```
# HAProxy logs
local0.* /var/log/haproxy/haproxy.log
local1.* /var/log/haproxy/haproxy-info.log
```

```bash
mkdir -p /var/log/haproxy
systemctl restart rsyslog
```

### Format de log personnalisé

```haproxy
frontend http_front
    bind *:80
    log-format "%ci:%cp [%tr] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r"
```

---

## 13. SELinux

```bash
# Autoriser HAProxy à se connecter au réseau
setsebool -P haproxy_connect_any 1

# Si port non-standard
semanage port -a -t http_port_t -p tcp 8404
```

---

## 14. Reload sans downtime

```bash
# Reload graceful
systemctl reload haproxy

# Via socket (plus rapide)
echo "show info" | socat stdio /var/lib/haproxy/stats

# Désactiver un serveur temporairement
echo "disable server http_back/web1" | socat stdio /var/lib/haproxy/stats
echo "enable server http_back/web1" | socat stdio /var/lib/haproxy/stats
```

Activer le socket admin :

```haproxy
global
    stats socket /var/lib/haproxy/stats mode 660 level admin
```

---

## Configuration complète exemple

```haproxy
global
    log /dev/log local0
    log /dev/log local1 notice
    chroot /var/lib/haproxy
    stats socket /var/lib/haproxy/stats mode 660 level admin
    maxconn 4000
    user haproxy
    group haproxy
    daemon
    ssl-default-bind-options ssl-min-ver TLSv1.2

defaults
    mode http
    log global
    option httplog
    option dontlognull
    option forwardfor
    option http-server-close
    timeout connect 5s
    timeout client 50s
    timeout server 50s

listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats auth admin:SecurePassword123!

frontend http_front
    bind *:80
    bind *:443 ssl crt /etc/haproxy/certs/
    http-request redirect scheme https unless { ssl_fc }

    acl is_api path_beg /api
    use_backend api_back if is_api
    default_backend web_back

backend web_back
    balance roundrobin
    option httpchk GET /health
    cookie SERVERID insert indirect nocache
    server web1 192.168.1.10:80 check cookie web1
    server web2 192.168.1.11:80 check cookie web2

backend api_back
    balance leastconn
    option httpchk GET /api/health
    server api1 192.168.1.20:3000 check
    server api2 192.168.1.21:3000 check
```

---

## Vérification

```bash
# Configuration
haproxy -c -f /etc/haproxy/haproxy.cfg

# Status
systemctl status haproxy

# Stats CLI
echo "show stat" | socat stdio /var/lib/haproxy/stats

# Logs
tail -f /var/log/haproxy/haproxy.log
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Backend DOWN | Vérifier health check, firewall |
| 503 Service Unavailable | Tous les backends down |
| Connection refused | Vérifier SELinux, firewall |
| SSL errors | Vérifier format PEM (cert+key) |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
