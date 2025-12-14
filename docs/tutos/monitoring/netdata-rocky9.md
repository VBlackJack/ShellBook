---
tags:
  - tutos
  - monitoring
  - netdata
  - metrics
  - realtime
  - rocky
---

# Netdata sur Rocky Linux 9

Installation de **Netdata** - monitoring temps réel avec dashboard.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Netdata | Latest |

**Durée estimée :** 10 minutes

---

## Fonctionnalités

| Fonction | Description |
|----------|-------------|
| **Real-time** | Métriques par seconde |
| **Auto-discovery** | Détection auto services |
| **Zero config** | Fonctionne immédiatement |
| **Low footprint** | Léger en ressources |
| **Alerting** | Alertes intégrées |

---

## 1. Installation

### Script officiel

```bash
wget -O /tmp/netdata-kickstart.sh https://get.netdata.cloud/kickstart.sh
bash /tmp/netdata-kickstart.sh --stable-channel --disable-telemetry
```

### Via repository

```bash
cat > /etc/yum.repos.d/netdata.repo << 'EOF'
[netdata_stable]
name=Netdata Stable
baseurl=https://packagecloud.io/netdata/netdata-stable/el/9/$basearch
gpgcheck=1
gpgkey=https://packagecloud.io/netdata/netdata-stable/gpgkey
enabled=1
EOF

dnf install -y netdata
systemctl enable --now netdata
```

---

## 2. Firewall

```bash
firewall-cmd --permanent --add-port=19999/tcp
firewall-cmd --reload
```

---

## 3. Accès

- URL: `http://IP:19999`
- Pas d'authentification par défaut

---

## 4. Configuration

### Fichier principal

```bash
vim /etc/netdata/netdata.conf
```

```ini
[global]
    hostname = server1
    history = 3996  # 1 heure à 1 seconde
    update every = 1

[web]
    bind to = 0.0.0.0
    default port = 19999

[plugins]
    proc = yes
    diskspace = yes
    cgroups = yes
```

### Appliquer

```bash
systemctl restart netdata
```

---

## 5. Authentification basique

### Avec Nginx

```bash
dnf install -y nginx httpd-tools
htpasswd -c /etc/nginx/.htpasswd admin

cat > /etc/nginx/conf.d/netdata.conf << 'EOF'
server {
    listen 80;
    server_name netdata.example.com;

    location / {
        proxy_pass http://127.0.0.1:19999;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        auth_basic "Netdata";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
EOF

systemctl enable --now nginx
```

---

## 6. Collectors / Plugins

### Plugins actifs

```bash
ls /usr/libexec/netdata/plugins.d/
```

### Configurer un collector

```bash
cd /etc/netdata
./edit-config go.d/nginx.conf
```

```yaml
jobs:
  - name: local_nginx
    url: http://127.0.0.1/nginx_status
```

### Activer le stub_status Nginx

```nginx
location /nginx_status {
    stub_status on;
    allow 127.0.0.1;
    deny all;
}
```

---

## 7. Monitoring Docker

### Activer le plugin cgroups

```bash
./edit-config netdata.conf
```

```ini
[plugins]
    cgroups = yes
```

### Socket Docker

```bash
usermod -aG docker netdata
systemctl restart netdata
```

---

## 8. Monitoring MySQL/MariaDB

```bash
./edit-config go.d/mysql.conf
```

```yaml
jobs:
  - name: local
    dsn: netdata:netdata@tcp(127.0.0.1:3306)/
```

Créer l'utilisateur MySQL :

```sql
CREATE USER 'netdata'@'localhost' IDENTIFIED BY 'netdata';
GRANT USAGE, REPLICATION CLIENT, PROCESS ON *.* TO 'netdata'@'localhost';
FLUSH PRIVILEGES;
```

---

## 9. Alerting

### Configuration alertes

```bash
./edit-config health.d/cpu.conf
```

```yaml
alarm: cpu_usage
    on: system.cpu
lookup: average -1m percentage of user,system
 every: 10s
  warn: $this > 80
  crit: $this > 95
  info: CPU usage is high
```

### Notifications

```bash
./edit-config health_alarm_notify.conf
```

```bash
# Email
SEND_EMAIL="YES"
DEFAULT_RECIPIENT_EMAIL="admin@example.com"

# Slack
SEND_SLACK="YES"
SLACK_WEBHOOK_URL="https://hooks.slack.com/services/XXX"
DEFAULT_RECIPIENT_SLACK="#alerts"

# Discord
SEND_DISCORD="YES"
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/XXX"
```

### Tester

```bash
/usr/libexec/netdata/plugins.d/alarm-notify.sh test
```

---

## 10. Streaming (Parent/Child)

### Sur le parent

```bash
./edit-config stream.conf
```

```ini
[API_KEY]
    enabled = yes
    allow from = *
```

### Sur le child

```bash
./edit-config stream.conf
```

```ini
[stream]
    enabled = yes
    destination = parent.example.com:19999
    api key = API_KEY
```

---

## 11. Netdata Cloud

### Connecter à Netdata Cloud

```bash
netdata-claim.sh -token=YOUR_TOKEN -rooms=YOUR_ROOM -url=https://app.netdata.cloud
```

---

## 12. Retention des données

### Modifier la retention

```bash
./edit-config netdata.conf
```

```ini
[db]
    mode = dbengine
    dbengine multihost disk space MB = 1024
    dbengine page cache size MB = 32
```

---

## 13. Export vers Prometheus

```bash
./edit-config exporting.conf
```

```ini
[prometheus:remote_write]
    enabled = yes
    destination = localhost:9090
    remote write URL path = /api/v1/write
```

---

## Commandes utiles

```bash
# Status
systemctl status netdata

# Logs
journalctl -u netdata -f
cat /var/log/netdata/error.log

# Vérifier config
netdata -W conf

# Redémarrer
systemctl restart netdata

# Info
netdatacli info
```

---

## Dépannage

```bash
# Vérifier les collectors
curl -s localhost:19999/api/v1/info | jq .collectors

# Debug
netdata -D  # Foreground avec debug

# Plugins health
/usr/libexec/netdata/plugins.d/python.d.plugin debug 1

# Permissions
ls -la /var/run/docker.sock
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
