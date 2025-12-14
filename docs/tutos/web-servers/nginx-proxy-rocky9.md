---
tags:
  - tutos
  - nginx
  - reverse-proxy
  - load-balancer
  - rocky
---

# Reverse Proxy Nginx sur Rocky Linux 9

Configuration de **Nginx comme Reverse Proxy** pour router le trafic vers des applications backend.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Nginx | 1.20+ |

**Durée estimée :** 25 minutes

---

## Concepts

### Qu'est-ce qu'un Reverse Proxy ?

```
Client → [Nginx Reverse Proxy] → Backend(s)
                ↓
         - SSL/TLS termination
         - Load balancing
         - Cache
         - Compression
         - Sécurité
```

### Cas d'usage

- Exposer des applications internes (Node.js, Python, Java)
- Centraliser les certificats SSL
- Load balancing entre plusieurs serveurs
- Cache et compression
- Protection des backends

---

## 1. Installation

```bash
dnf install -y nginx
systemctl enable --now nginx

firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

---

## 2. Reverse Proxy simple

### Configuration de base

```bash
vim /etc/nginx/conf.d/app.example.com.conf
```

```nginx
server {
    listen 80;
    server_name app.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;

        # Headers essentiels
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
nginx -t && systemctl reload nginx
```

---

## 3. Configuration avancée

### Headers complets

```nginx
server {
    listen 80;
    server_name app.example.com;

    # Logs dédiés
    access_log /var/log/nginx/app.example.com.access.log;
    error_log /var/log/nginx/app.example.com.error.log;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;

        # Headers proxy
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Port $server_port;

        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffers
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}
```

---

## 4. Proxy vers différents chemins

```nginx
server {
    listen 80;
    server_name example.com;

    # API vers Node.js
    location /api/ {
        proxy_pass http://127.0.0.1:3000/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Admin vers Python/Django
    location /admin/ {
        proxy_pass http://127.0.0.1:8000/admin/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # Fichiers statiques servis par Nginx
    location /static/ {
        alias /var/www/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Frontend par défaut
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## 5. Load Balancing

### Upstream avec plusieurs backends

```nginx
upstream app_backend {
    # Round-robin (défaut)
    server 192.168.1.10:3000;
    server 192.168.1.11:3000;
    server 192.168.1.12:3000;
}

server {
    listen 80;
    server_name app.example.com;

    location / {
        proxy_pass http://app_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Méthodes de load balancing

```nginx
upstream app_backend {
    # Least connections - envoie au serveur le moins chargé
    least_conn;

    server 192.168.1.10:3000;
    server 192.168.1.11:3000;
}

upstream app_backend_weighted {
    # Weighted - poids différents
    server 192.168.1.10:3000 weight=3;  # 3x plus de trafic
    server 192.168.1.11:3000 weight=1;
}

upstream app_backend_ip {
    # IP Hash - même client → même backend (sessions)
    ip_hash;

    server 192.168.1.10:3000;
    server 192.168.1.11:3000;
}
```

### Health checks et failover

```nginx
upstream app_backend {
    server 192.168.1.10:3000 max_fails=3 fail_timeout=30s;
    server 192.168.1.11:3000 max_fails=3 fail_timeout=30s;
    server 192.168.1.12:3000 backup;  # Utilisé si les autres sont down
}
```

---

## 6. Proxy WebSocket

```nginx
upstream websocket_backend {
    server 127.0.0.1:3001;
}

server {
    listen 80;
    server_name ws.example.com;

    location / {
        proxy_pass http://websocket_backend;
        proxy_http_version 1.1;

        # Headers WebSocket
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;

        # Timeout long pour WebSocket
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

---

## 7. Cache Proxy

```nginx
# Définir zone de cache (dans http{})
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=1g inactive=60m use_temp_path=off;

server {
    listen 80;
    server_name cached.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;

        # Activer le cache
        proxy_cache my_cache;
        proxy_cache_valid 200 302 10m;
        proxy_cache_valid 404 1m;
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;

        # Headers de debug
        add_header X-Cache-Status $upstream_cache_status;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Bypass cache pour certains chemins
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_cache off;
        proxy_set_header Host $host;
    }
}
```

```bash
# Créer le dossier cache
mkdir -p /var/cache/nginx
chown nginx:nginx /var/cache/nginx
```

---

## 8. Sécurité

### Rate limiting

```nginx
# Définir zone de limite (dans http{})
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;

server {
    listen 80;
    server_name api.example.com;

    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;

        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Headers de sécurité

```nginx
server {
    listen 80;
    server_name secure.example.com;

    # Headers de sécurité
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # Cacher la version du backend
        proxy_hide_header X-Powered-By;
    }
}
```

### Restriction par IP

```nginx
location /admin/ {
    allow 192.168.1.0/24;
    allow 10.0.0.0/8;
    deny all;

    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
}
```

---

## 9. SELinux

```bash
# Autoriser Nginx à se connecter au réseau
setsebool -P httpd_can_network_connect 1

# Si proxy vers un port non-standard
semanage port -a -t http_port_t -p tcp 3000
```

---

## 10. Fichier de configuration réutilisable

### Snippet proxy

```bash
vim /etc/nginx/conf.d/proxy_params.conf
```

```nginx
# Inclure dans les locations avec: include /etc/nginx/conf.d/proxy_params.conf;
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_connect_timeout 60s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;
```

### Utilisation

```nginx
server {
    listen 80;
    server_name app.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        include /etc/nginx/conf.d/proxy_params.conf;
    }
}
```

---

## Vérification

```bash
# Tester configuration
nginx -t

# Recharger
systemctl reload nginx

# Tester le proxy
curl -I http://app.example.com

# Voir les headers
curl -v http://app.example.com 2>&1 | grep -E '^[<>]'
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| 502 Bad Gateway | Backend non démarré ou mauvaise IP/port |
| 504 Gateway Timeout | Backend trop lent, augmenter timeouts |
| SELinux bloque | `setsebool -P httpd_can_network_connect 1` |
| Headers manquants | Vérifier `proxy_set_header` |

```bash
# Logs
tail -f /var/log/nginx/error.log

# Debug headers
curl -v http://app.example.com

# Vérifier backend
curl http://127.0.0.1:3000
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
