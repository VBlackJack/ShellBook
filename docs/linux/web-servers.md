---
tags:
  - nginx
  - reverse-proxy
  - https
  - certbot
---

# Nginx & Web Hosting

Configuration de serveurs web et reverse proxy sous Linux.

---

## Architecture de Configuration (Debian/Ubuntu)

### Structure des Fichiers

```
/etc/nginx/
├── nginx.conf              # Configuration globale
├── sites-available/        # Stockage des vhosts (inactifs)
│   ├── default
│   └── monsite.conf
├── sites-enabled/          # Vhosts actifs (symlinks)
│   └── monsite.conf → ../sites-available/monsite.conf
├── conf.d/                 # Configs additionnelles
├── snippets/               # Fragments réutilisables
└── mime.types              # Types MIME
```

| Dossier | Rôle |
|---------|------|
| `nginx.conf` | Configuration globale (workers, logs, includes) |
| `sites-available/` | Tous les vhosts disponibles |
| `sites-enabled/` | Vhosts **actifs** (symlinks vers available) |
| `conf.d/` | Configs auto-incluses (*.conf) |
| `snippets/` | Fragments réutilisables (SSL, headers) |

### Activer / Désactiver un Site

```bash
# Activer un site (créer le symlink)
sudo ln -s /etc/nginx/sites-available/monsite.conf /etc/nginx/sites-enabled/

# Désactiver un site (supprimer le symlink)
sudo rm /etc/nginx/sites-enabled/monsite.conf

# Note : Le fichier original reste dans sites-available
```

### Commandes Essentielles

```bash
# Tester la configuration (TOUJOURS avant reload)
sudo nginx -t

# Output OK:
# nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
# nginx: configuration file /etc/nginx/nginx.conf test is successful

# Recharger sans interruption
sudo systemctl reload nginx

# Redémarrer (coupe les connexions)
sudo systemctl restart nginx

# Status
sudo systemctl status nginx

# Voir la config effective
sudo nginx -T
```

!!! tip "Workflow de modification"
    1. Éditer le fichier dans `sites-available/`
    2. `nginx -t` pour tester
    3. `systemctl reload nginx` si OK

---

## Le Virtual Host (Server Block) Parfait

### Reverse Proxy Robuste

```nginx
# /etc/nginx/sites-available/myapp.conf

# Redirection HTTP → HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name myapp.example.com;

    # Redirection permanente vers HTTPS
    return 301 https://$server_name$request_uri;
}

# Configuration HTTPS principale
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name myapp.example.com;

    # === SSL (géré par Certbot) ===
    ssl_certificate /etc/letsencrypt/live/myapp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/myapp.example.com/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # === Sécurité ===
    server_tokens off;                    # Cache version Nginx

    # Headers de sécurité
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # === Logs ===
    access_log /var/log/nginx/myapp.access.log;
    error_log /var/log/nginx/myapp.error.log;

    # === Reverse Proxy ===
    location / {
        proxy_pass http://localhost:3000;

        # Headers essentiels pour le backend
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (si nécessaire)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # === Fichiers statiques (optionnel) ===
    location /static/ {
        alias /var/www/myapp/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
```

### Headers Proxy Expliqués

| Header | Description |
|--------|-------------|
| `Host` | Domaine original de la requête |
| `X-Real-IP` | IP réelle du client |
| `X-Forwarded-For` | Chaîne des proxies traversés |
| `X-Forwarded-Proto` | Protocole original (http/https) |

### Snippet Réutilisable

```nginx
# /etc/nginx/snippets/proxy-headers.conf
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;

# Utilisation dans un vhost :
location / {
    proxy_pass http://localhost:3000;
    include snippets/proxy-headers.conf;
}
```

---

## Apache (Le Vétéran)

### Comparatif Nginx vs Apache

| Aspect | Nginx | Apache |
|--------|-------|--------|
| **Architecture** | Event-driven (async) | Process/Thread-based |
| **Performances** | Excellent pour statique/proxy | Bon pour dynamique |
| **Mémoire** | Faible consommation | Plus gourmand |
| **Configuration** | Fichiers centralisés | .htaccess (distribué) |
| **Modules** | Compilés à l'avance | Chargement dynamique |
| **Cas d'usage** | Reverse proxy, CDN, statique | PHP-FPM, .htaccess, legacy |

### Architecture Commune

```
┌─────────────────────────────────────────────────────────────┐
│                         Client                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Nginx (Reverse Proxy)                     │
│              - SSL Termination                               │
│              - Load Balancing                                │
│              - Caching statique                              │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
         ┌────────┐      ┌────────┐      ┌────────┐
         │ App 1  │      │ App 2  │      │ Apache │
         │ :3000  │      │ :3001  │      │ + PHP  │
         └────────┘      └────────┘      └────────┘
```

### Commandes Apache

```bash
# Configuration Debian/Ubuntu
/etc/apache2/
├── apache2.conf
├── sites-available/
└── sites-enabled/

# Activer/désactiver un site
sudo a2ensite monsite.conf
sudo a2dissite monsite.conf

# Activer/désactiver un module
sudo a2enmod rewrite
sudo a2enmod proxy_http

# Tester et recharger
sudo apachectl configtest
sudo systemctl reload apache2
```

---

## HTTPS & Certbot

### Installation

=== "RHEL/Rocky"

    ```bash
    sudo dnf install epel-release -y
    sudo dnf install certbot python3-certbot-nginx

    # Pour Apache
    sudo dnf install certbot python3-certbot-apache
    ```

=== "Debian/Ubuntu"

    ```bash
    sudo apt install certbot python3-certbot-nginx

    # Pour Apache
    sudo apt install certbot python3-certbot-apache
    ```

### Obtenir un Certificat

```bash
# Mode automatique (modifie la config Nginx)
sudo certbot --nginx -d myapp.example.com

# Multi-domaines
sudo certbot --nginx -d example.com -d www.example.com

# Mode manuel (ne modifie rien)
sudo certbot certonly --nginx -d myapp.example.com

# Wildcard (nécessite DNS challenge)
sudo certbot certonly --manual --preferred-challenges dns \
    -d "*.example.com" -d "example.com"
```

### Renouvellement Automatique

```bash
# Tester le renouvellement
sudo certbot renew --dry-run

# Vérifier le timer systemd
systemctl list-timers | grep certbot

# Ou le cron
cat /etc/cron.d/certbot

# Forcer le renouvellement
sudo certbot renew --force-renewal
```

### Vérifier les Certificats

```bash
# Liste des certificats
sudo certbot certificates

# Output:
# Certificate Name: myapp.example.com
#   Domains: myapp.example.com
#   Expiry Date: 2024-04-15
#   Certificate Path: /etc/letsencrypt/live/myapp.example.com/fullchain.pem
#   Private Key Path: /etc/letsencrypt/live/myapp.example.com/privkey.pem
```

### Structure Let's Encrypt

```
/etc/letsencrypt/
├── live/
│   └── myapp.example.com/
│       ├── cert.pem        # Certificat seul
│       ├── chain.pem       # Chaîne intermédiaire
│       ├── fullchain.pem   # Cert + Chain (à utiliser)
│       └── privkey.pem     # Clé privée
├── renewal/
│   └── myapp.example.com.conf
└── archive/                # Historique des certificats
```

---

## Référence Rapide

```bash
# === NGINX ===
sudo nginx -t                              # Tester config
sudo systemctl reload nginx                # Recharger

# Activer un site
sudo ln -s /etc/nginx/sites-available/site.conf /etc/nginx/sites-enabled/

# === APACHE ===
sudo a2ensite site.conf                    # Activer
sudo a2dissite site.conf                   # Désactiver
sudo apachectl configtest                  # Tester
sudo systemctl reload apache2              # Recharger

# === CERTBOT ===
sudo certbot --nginx -d domain.com         # Certificat auto
sudo certbot renew --dry-run               # Test renouvellement
sudo certbot certificates                  # Liste certificats
```
