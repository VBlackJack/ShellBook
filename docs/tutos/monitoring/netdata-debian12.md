---
tags:
  - tutos
  - monitoring
  - netdata
  - metrics
  - realtime
  - debian
---

# Netdata sur Debian 12

Installation de **Netdata** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Netdata | Latest |

**Durée estimée :** 10 minutes

---

## 1. Installation

### Script officiel

```bash
wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh
bash /tmp/netdata-kickstart.sh --stable-channel --disable-telemetry
```

### Via apt

```bash
apt update
apt install -y netdata
systemctl enable --now netdata
```

---

## 2. Firewall

```bash
ufw allow 19999/tcp
ufw reload
```

---

## 3. Accès

- URL: `http://IP:19999`

---

## 4. Configuration

```bash
vim /etc/netdata/netdata.conf
```

```ini
[global]
    hostname = server1
    history = 3996

[web]
    bind to = 0.0.0.0
```

```bash
systemctl restart netdata
```

---

## 5. Authentification Nginx

```bash
apt install -y nginx apache2-utils
htpasswd -c /etc/nginx/.htpasswd admin

cat > /etc/nginx/sites-available/netdata << 'EOF'
server {
    listen 80;
    server_name netdata.example.com;

    location / {
        proxy_pass http://127.0.0.1:19999;
        auth_basic "Netdata";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
EOF

ln -s /etc/nginx/sites-available/netdata /etc/nginx/sites-enabled/
systemctl reload nginx
```

---

## 6. Collectors

### Nginx

```yaml
# /etc/netdata/go.d/nginx.conf
jobs:
  - name: local_nginx
    url: http://127.0.0.1/nginx_status
```

### MySQL

```yaml
# /etc/netdata/go.d/mysql.conf
jobs:
  - name: local
    dsn: netdata:netdata@tcp(127.0.0.1:3306)/
```

---

## 7. Alerting

```bash
# /etc/netdata/health_alarm_notify.conf
SEND_EMAIL="YES"
DEFAULT_RECIPIENT_EMAIL="admin@example.com"
```

---

## 8. Docker monitoring

```bash
usermod -aG docker netdata
systemctl restart netdata
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Package | dnf | apt |
| Firewall | firewalld | ufw |
| Config | Identique | Identique |

---

## Commandes

```bash
# Status
systemctl status netdata

# Logs
journalctl -u netdata -f

# Restart
systemctl restart netdata

# Info API
curl localhost:19999/api/v1/info
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
