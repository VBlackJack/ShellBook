---
tags:
  - tutos
  - nginx
  - reverse-proxy
  - load-balancer
  - debian
---

# Reverse Proxy Nginx sur Debian 12

Configuration de **Nginx comme Reverse Proxy** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Nginx | 1.22+ |

**Durée estimée :** 25 minutes

---

## 1. Installation

```bash
apt update
apt install -y nginx

systemctl enable --now nginx

# Firewall si UFW actif
ufw allow 'Nginx Full'
```

---

## 2. Reverse Proxy simple

```bash
vim /etc/nginx/sites-available/app.example.com
```

```nginx
server {
    listen 80;
    server_name app.example.com;

    access_log /var/log/nginx/app.example.com.access.log;
    error_log /var/log/nginx/app.example.com.error.log;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

```bash
ln -s /etc/nginx/sites-available/app.example.com /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

---

## 3. Proxy vers différents chemins

```bash
vim /etc/nginx/sites-available/multi-backend
```

```nginx
server {
    listen 80;
    server_name example.com;

    # API Node.js sur /api
    location /api/ {
        proxy_pass http://127.0.0.1:3000/;
        include /etc/nginx/proxy_params;
    }

    # Backend Python sur /admin
    location /admin/ {
        proxy_pass http://127.0.0.1:8000/admin/;
        include /etc/nginx/proxy_params;
    }

    # Fichiers statiques
    location /static/ {
        alias /var/www/static/;
        expires 30d;
    }

    # Frontend par défaut
    location / {
        proxy_pass http://127.0.0.1:8080;
        include /etc/nginx/proxy_params;
    }
}
```

---

## 4. Load Balancing

### Configuration upstream

```nginx
upstream app_cluster {
    # Méthode: round-robin (défaut), least_conn, ip_hash
    least_conn;

    server 192.168.1.10:3000 weight=3;
    server 192.168.1.11:3000 weight=2;
    server 192.168.1.12:3000 backup;

    # Health check
    keepalive 32;
}

server {
    listen 80;
    server_name app.example.com;

    location / {
        proxy_pass http://app_cluster;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        include /etc/nginx/proxy_params;
    }
}
```

---

## 5. Proxy WebSocket

```nginx
upstream websocket {
    server 127.0.0.1:3001;
}

server {
    listen 80;
    server_name ws.example.com;

    location / {
        proxy_pass http://websocket;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 3600s;
    }

    location /socket.io/ {
        proxy_pass http://websocket;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

---

## 6. Cache Proxy

### Configuration globale

```bash
vim /etc/nginx/nginx.conf
```

Ajouter dans le bloc `http {}` :

```nginx
http {
    # Zone de cache
    proxy_cache_path /var/cache/nginx/proxy
        levels=1:2
        keys_zone=proxy_cache:10m
        max_size=1g
        inactive=60m
        use_temp_path=off;

    # ...
}
```

### Utilisation dans un site

```nginx
server {
    listen 80;
    server_name cached.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;

        proxy_cache proxy_cache;
        proxy_cache_valid 200 10m;
        proxy_cache_valid 404 1m;
        proxy_cache_use_stale error timeout updating;

        add_header X-Cache-Status $upstream_cache_status;

        include /etc/nginx/proxy_params;
    }

    # API sans cache
    location /api/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_cache off;
        include /etc/nginx/proxy_params;
    }
}
```

```bash
mkdir -p /var/cache/nginx/proxy
chown www-data:www-data /var/cache/nginx/proxy
```

---

## 7. Sécurité

### Rate limiting

```bash
vim /etc/nginx/nginx.conf
```

Dans `http {}` :

```nginx
limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
```

Utilisation :

```nginx
server {
    listen 80;
    server_name api.example.com;

    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        limit_conn conn_limit 10;

        proxy_pass http://127.0.0.1:3000;
        include /etc/nginx/proxy_params;
    }
}
```

### Headers de sécurité

```nginx
server {
    listen 80;
    server_name secure.example.com;

    # Sécurité
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_hide_header X-Powered-By;
        include /etc/nginx/proxy_params;
    }
}
```

---

## 8. Fichier proxy_params

Debian inclut déjà `/etc/nginx/proxy_params`. Contenu typique :

```bash
cat /etc/nginx/proxy_params
```

```nginx
proxy_set_header Host $http_host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

### Personnaliser

```bash
vim /etc/nginx/conf.d/proxy_custom.conf
```

```nginx
# Timeouts
proxy_connect_timeout 60s;
proxy_send_timeout 60s;
proxy_read_timeout 60s;

# Buffers
proxy_buffering on;
proxy_buffer_size 4k;
proxy_buffers 8 4k;
```

---

## 9. Configuration complète type

```bash
vim /etc/nginx/sites-available/production-app
```

```nginx
upstream backend {
    least_conn;
    server 127.0.0.1:3000;
    server 127.0.0.1:3001;
    keepalive 32;
}

server {
    listen 80;
    server_name app.example.com;

    access_log /var/log/nginx/app.access.log combined;
    error_log /var/log/nginx/app.error.log warn;

    # Limite taille upload
    client_max_body_size 50m;

    # Sécurité
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "OK\n";
        add_header Content-Type text/plain;
    }

    # Fichiers statiques
    location /static/ {
        alias /var/www/app/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # API
    location /api/ {
        limit_req zone=api_limit burst=20 nodelay;
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        include /etc/nginx/proxy_params;
    }

    # WebSocket
    location /ws/ {
        proxy_pass http://backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        include /etc/nginx/proxy_params;
        proxy_read_timeout 3600s;
    }

    # Frontend
    location / {
        proxy_pass http://backend;
        include /etc/nginx/proxy_params;
    }
}
```

---

## Comparatif Rocky 9 vs Debian 12

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Config sites | `/etc/nginx/conf.d/` | `/etc/nginx/sites-*` |
| proxy_params | À créer | Inclus |
| SELinux | Oui (setsebool) | Non |
| User | nginx | www-data |

---

## Vérification

```bash
nginx -t
systemctl reload nginx

# Test proxy
curl -I http://app.example.com

# Headers
curl -v http://app.example.com 2>&1 | grep -E '^[<>]'

# Cache status
curl -I http://cached.example.com | grep X-Cache
```

---

## Dépannage

```bash
# Logs
tail -f /var/log/nginx/error.log

# Vérifier backend
curl http://127.0.0.1:3000

# Connections actives
ss -tlnp | grep nginx
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
