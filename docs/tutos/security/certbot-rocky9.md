---
tags:
  - tutos
  - ssl
  - tls
  - letsencrypt
  - certbot
  - rocky
---

# Let's Encrypt avec Certbot sur Rocky Linux 9

Obtention et renouvellement automatique de certificats SSL/TLS gratuits avec **Certbot**.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Certbot | 2.x |
| Let's Encrypt | Production |

**Durée estimée :** 15 minutes

---

## Prérequis

- Nom de domaine pointant vers le serveur (enregistrement A)
- Ports 80 et 443 ouverts
- Serveur web installé (Apache ou Nginx)

---

## 1. Installation de Certbot

### Pour Nginx

```bash
dnf install -y epel-release
dnf install -y certbot python3-certbot-nginx
```

### Pour Apache

```bash
dnf install -y epel-release
dnf install -y certbot python3-certbot-apache
```

### Vérification

```bash
certbot --version
```

---

## 2. Obtenir un certificat

### Avec Nginx

```bash
# Automatique (modifie la config Nginx)
certbot --nginx -d example.com -d www.example.com

# Interactif
certbot --nginx
```

### Avec Apache

```bash
certbot --apache -d example.com -d www.example.com
```

### Mode standalone (sans serveur web)

```bash
# Arrêter le serveur web d'abord
systemctl stop nginx

# Obtenir le certificat
certbot certonly --standalone -d example.com -d www.example.com

# Redémarrer
systemctl start nginx
```

### Mode webroot (serveur web actif)

```bash
# Sans modifier la config du serveur web
certbot certonly --webroot -w /var/www/html -d example.com -d www.example.com
```

---

## 3. Options courantes

```bash
# Non-interactif (scripts)
certbot --nginx -d example.com \
    --non-interactive \
    --agree-tos \
    --email admin@example.com \
    --redirect  # Force HTTPS

# Staging (test, pas de rate limit)
certbot --nginx -d example.com --staging

# Dry-run (test sans rien modifier)
certbot --nginx -d example.com --dry-run
```

---

## 4. Où sont les certificats ?

```bash
# Répertoire des certificats
ls -la /etc/letsencrypt/live/example.com/

# Fichiers
# - privkey.pem   : Clé privée
# - cert.pem      : Certificat
# - chain.pem     : Chaîne intermédiaire
# - fullchain.pem : Certificat + chaîne (à utiliser)
```

---

## 5. Configuration manuelle Nginx

Si vous n'utilisez pas le plugin `--nginx` :

```bash
vim /etc/nginx/conf.d/example.com.conf
```

```nginx
server {
    listen 80;
    server_name example.com www.example.com;

    # Redirection HTTP → HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name example.com www.example.com;

    # Certificats Let's Encrypt
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Configuration SSL moderne
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # OCSP Stapling
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
nginx -t && systemctl reload nginx
```

---

## 6. Configuration manuelle Apache

```bash
vim /etc/httpd/conf.d/example.com-ssl.conf
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

    # Configuration SSL moderne
    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
    SSLHonorCipherOrder off

    # HSTS
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
```

```bash
httpd -t && systemctl reload httpd
```

---

## 7. Renouvellement automatique

### Vérifier le timer systemd

```bash
# Certbot installe un timer automatique
systemctl status certbot-renew.timer
systemctl list-timers | grep certbot
```

### Test de renouvellement

```bash
# Dry-run (ne renouvelle pas vraiment)
certbot renew --dry-run
```

### Hook post-renouvellement

```bash
vim /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

```bash
#!/bin/bash
systemctl reload nginx
```

```bash
chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
```

---

## 8. Certificat wildcard

Les certificats wildcard nécessitent une validation DNS.

```bash
# Wildcard avec validation DNS manuelle
certbot certonly --manual --preferred-challenges dns \
    -d "*.example.com" -d example.com

# Suivre les instructions pour créer l'enregistrement TXT
```

### Avec plugin DNS (exemple Cloudflare)

```bash
# Installer le plugin
dnf install -y python3-certbot-dns-cloudflare

# Créer le fichier credentials
vim /etc/letsencrypt/cloudflare.ini
```

```ini
dns_cloudflare_api_token = YOUR_API_TOKEN
```

```bash
chmod 600 /etc/letsencrypt/cloudflare.ini

# Obtenir le wildcard
certbot certonly --dns-cloudflare \
    --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    -d "*.example.com" -d example.com
```

---

## 9. Gestion des certificats

```bash
# Lister les certificats
certbot certificates

# Révoquer un certificat
certbot revoke --cert-path /etc/letsencrypt/live/example.com/cert.pem

# Supprimer un certificat
certbot delete --cert-name example.com

# Étendre un certificat (ajouter des domaines)
certbot certonly --nginx -d example.com -d www.example.com -d new.example.com --expand
```

---

## 10. SELinux

```bash
# Autoriser Nginx/Apache à lire les certificats
restorecon -Rv /etc/letsencrypt
```

---

## 11. Firewall

```bash
# HTTPS doit être ouvert
firewall-cmd --permanent --add-service=https
firewall-cmd --reload
```

---

## Vérification

```bash
# Tester la connexion SSL
curl -I https://example.com

# Vérifier le certificat
openssl s_client -connect example.com:443 -servername example.com < /dev/null 2>/dev/null | openssl x509 -noout -dates

# Test en ligne
# https://www.ssllabs.com/ssltest/
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Rate limit atteint | Utiliser `--staging` pour les tests |
| Validation échoue | Vérifier DNS, port 80 ouvert |
| Certificat expiré | `certbot renew --force-renewal` |
| Nginx ne démarre pas | Vérifier chemins des certificats |

```bash
# Logs Certbot
cat /var/log/letsencrypt/letsencrypt.log

# Vérifier ports
ss -tlnp | grep -E ':(80|443)'

# Debug validation
certbot certonly --nginx -d example.com -v
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
