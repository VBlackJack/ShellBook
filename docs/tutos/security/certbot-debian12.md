---
tags:
  - tutos
  - ssl
  - tls
  - letsencrypt
  - certbot
  - debian
---

# Let's Encrypt avec Certbot sur Debian 12

Certificats SSL/TLS gratuits avec **Certbot** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Certbot | 2.x |
| Let's Encrypt | Production |

**Durée estimée :** 15 minutes

---

## Prérequis

- Nom de domaine avec enregistrement A pointant vers le serveur
- Ports 80 et 443 ouverts
- Serveur web installé (Apache ou Nginx)

---

## 1. Installation de Certbot

### Pour Nginx

```bash
apt update
apt install -y certbot python3-certbot-nginx
```

### Pour Apache

```bash
apt update
apt install -y certbot python3-certbot-apache
```

### Vérification

```bash
certbot --version
```

---

## 2. Obtenir un certificat

### Avec Nginx

```bash
# Automatique
certbot --nginx -d example.com -d www.example.com

# Non-interactif
certbot --nginx -d example.com \
    --non-interactive \
    --agree-tos \
    --email admin@example.com \
    --redirect
```

### Avec Apache

```bash
certbot --apache -d example.com -d www.example.com
```

### Mode standalone

```bash
systemctl stop nginx
certbot certonly --standalone -d example.com
systemctl start nginx
```

### Mode webroot

```bash
certbot certonly --webroot -w /var/www/html -d example.com
```

---

## 3. Emplacement des certificats

```bash
ls -la /etc/letsencrypt/live/example.com/

# Fichiers :
# - privkey.pem   : Clé privée
# - fullchain.pem : Certificat complet (à utiliser)
# - cert.pem      : Certificat seul
# - chain.pem     : Chaîne intermédiaire
```

---

## 4. Configuration manuelle Nginx

```bash
vim /etc/nginx/sites-available/example.com
```

```nginx
# Redirection HTTP → HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name example.com www.example.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name example.com www.example.com;

    # Certificats
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # SSL moderne
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # OCSP
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;

    root /var/www/html;
    index index.html index.php;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

```bash
ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

---

## 5. Configuration manuelle Apache

```bash
# Activer le module SSL
a2enmod ssl
a2enmod headers
```

```bash
vim /etc/apache2/sites-available/example.com-ssl.conf
```

```apache
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    Redirect permanent / https://example.com/
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem

    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder off

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

```bash
a2ensite example.com-ssl
apache2ctl configtest && systemctl reload apache2
```

---

## 6. Renouvellement automatique

### Timer systemd

```bash
# Vérifier le timer
systemctl status certbot.timer
systemctl list-timers | grep certbot

# Activer si nécessaire
systemctl enable --now certbot.timer
```

### Test

```bash
certbot renew --dry-run
```

### Hook de rechargement

```bash
vim /etc/letsencrypt/renewal-hooks/deploy/reload-webserver.sh
```

```bash
#!/bin/bash
# Recharger Nginx ou Apache après renouvellement
if systemctl is-active nginx >/dev/null 2>&1; then
    systemctl reload nginx
elif systemctl is-active apache2 >/dev/null 2>&1; then
    systemctl reload apache2
fi
```

```bash
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-webserver.sh
```

---

## 7. Certificat wildcard

```bash
# Validation DNS manuelle
certbot certonly --manual --preferred-challenges dns \
    -d "*.example.com" -d example.com
```

### Avec Cloudflare

```bash
apt install -y python3-certbot-dns-cloudflare

vim /etc/letsencrypt/cloudflare.ini
```

```ini
dns_cloudflare_api_token = YOUR_API_TOKEN
```

```bash
chmod 600 /etc/letsencrypt/cloudflare.ini

certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    -d "*.example.com" -d example.com
```

---

## 8. Gestion des certificats

```bash
# Lister
certbot certificates

# Révoquer
certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem

# Supprimer
certbot delete --cert-name example.com

# Ajouter domaines
certbot certonly --nginx -d example.com -d new.example.com --expand

# Forcer renouvellement
certbot renew --force-renewal --cert-name example.com
```

---

## 9. Firewall UFW

```bash
ufw allow 'Nginx Full'
# ou
ufw allow 443/tcp
ufw reload
```

---

## Comparatif Rocky 9 vs Debian 12

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Installation | dnf + epel-release | apt |
| Timer | certbot-renew.timer | certbot.timer |
| Apache module | httpd | apache2 |
| SSL activation | Automatique | a2enmod ssl |

---

## Vérification

```bash
# Test SSL
curl -I https://example.com

# Infos certificat
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -dates -subject

# Test complet en ligne
# https://www.ssllabs.com/ssltest/
```

---

## Dépannage

```bash
# Logs
cat /var/log/letsencrypt/letsencrypt.log

# Debug
certbot certonly --nginx -d example.com -v

# Vérifier ports
ss -tlnp | grep -E ':(80|443)'
```

| Problème | Solution |
|----------|----------|
| Challenge failed | Vérifier DNS, port 80 ouvert |
| Rate limit | Utiliser `--staging` pour tests |
| Permission denied | Vérifier permissions `/etc/letsencrypt/` |

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
