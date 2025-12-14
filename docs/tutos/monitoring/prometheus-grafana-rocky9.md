---
tags:
  - tutos
  - monitoring
  - prometheus
  - grafana
  - rocky
---

# Prometheus + Grafana sur Rocky Linux 9

Installation et configuration de **Prometheus** et **Grafana** pour le monitoring d'infrastructure.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Prometheus | 2.x |
| Grafana | 10.x |
| Node Exporter | 1.x |

**Durée estimée :** 45 minutes

---

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   Grafana       │────►│   Prometheus    │
│   :3000         │     │   :9090         │
└─────────────────┘     └────────┬────────┘
                                 │ scrape
                    ┌────────────┼────────────┐
                    ▼            ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌──────────┐
              │  Node    │ │  Node    │ │  Other   │
              │ Exporter │ │ Exporter │ │ Exporter │
              │  :9100   │ │  :9100   │ │  :xxxx   │
              └──────────┘ └──────────┘ └──────────┘
```

---

## 1. Installation de Prometheus

### Créer l'utilisateur

```bash
useradd --no-create-home --shell /bin/false prometheus
```

### Télécharger Prometheus

```bash
cd /tmp
PROM_VERSION="2.48.0"
wget https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-amd64.tar.gz

tar xzf prometheus-${PROM_VERSION}.linux-amd64.tar.gz
cd prometheus-${PROM_VERSION}.linux-amd64
```

### Installer les binaires

```bash
# Binaires
cp prometheus promtool /usr/local/bin/
chown prometheus:prometheus /usr/local/bin/prometheus /usr/local/bin/promtool

# Répertoires
mkdir -p /etc/prometheus /var/lib/prometheus
cp -r consoles console_libraries /etc/prometheus/
chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus
```

### Configuration

```bash
vim /etc/prometheus/prometheus.yml
```

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets: []

rule_files: []

scrape_configs:
  # Prometheus lui-même
  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]

  # Node Exporter local
  - job_name: "node"
    static_configs:
      - targets: ["localhost:9100"]

  # Autres serveurs (ajouter ici)
  # - job_name: "web-servers"
  #   static_configs:
  #     - targets: ["192.168.1.10:9100", "192.168.1.11:9100"]
```

```bash
chown prometheus:prometheus /etc/prometheus/prometheus.yml
```

### Service systemd

```bash
vim /etc/systemd/system/prometheus.service
```

```ini
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target

[Service]
User=prometheus
Group=prometheus
Type=simple
ExecStart=/usr/local/bin/prometheus \
    --config.file=/etc/prometheus/prometheus.yml \
    --storage.tsdb.path=/var/lib/prometheus/ \
    --web.console.templates=/etc/prometheus/consoles \
    --web.console.libraries=/etc/prometheus/console_libraries \
    --storage.tsdb.retention.time=30d \
    --web.enable-lifecycle

ExecReload=/bin/kill -HUP $MAINPID
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now prometheus
systemctl status prometheus
```

### Firewall

```bash
firewall-cmd --permanent --add-port=9090/tcp
firewall-cmd --reload
```

---

## 2. Installation de Node Exporter

### Télécharger

```bash
cd /tmp
NODE_VERSION="1.7.0"
wget https://github.com/prometheus/node_exporter/releases/download/v${NODE_VERSION}/node_exporter-${NODE_VERSION}.linux-amd64.tar.gz

tar xzf node_exporter-${NODE_VERSION}.linux-amd64.tar.gz
cp node_exporter-${NODE_VERSION}.linux-amd64/node_exporter /usr/local/bin/
```

### Utilisateur et service

```bash
useradd --no-create-home --shell /bin/false node_exporter

vim /etc/systemd/system/node_exporter.service
```

```ini
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

[Service]
User=node_exporter
Group=node_exporter
Type=simple
ExecStart=/usr/local/bin/node_exporter \
    --collector.systemd \
    --collector.processes

Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now node_exporter
systemctl status node_exporter

firewall-cmd --permanent --add-port=9100/tcp
firewall-cmd --reload
```

### Vérifier

```bash
curl http://localhost:9100/metrics | head -20
```

---

## 3. Installation de Grafana

### Ajouter le dépôt

```bash
cat > /etc/yum.repos.d/grafana.repo << 'EOF'
[grafana]
name=grafana
baseurl=https://rpm.grafana.com
repo_gpgcheck=1
enabled=1
gpgcheck=1
gpgkey=https://rpm.grafana.com/gpg.key
sslverify=1
sslcacert=/etc/pki/tls/certs/ca-bundle.crt
EOF
```

### Installer

```bash
dnf install -y grafana

systemctl enable --now grafana-server
systemctl status grafana-server

firewall-cmd --permanent --add-port=3000/tcp
firewall-cmd --reload
```

### Accès initial

- URL : `http://IP:3000`
- Login : `admin`
- Password : `admin` (à changer)

---

## 4. Configurer Grafana

### Ajouter Prometheus comme source

1. Aller dans **Configuration** → **Data Sources**
2. Cliquer **Add data source**
3. Sélectionner **Prometheus**
4. URL : `http://localhost:9090`
5. Cliquer **Save & Test**

### Importer des dashboards

1. Aller dans **Dashboards** → **Import**
2. Entrer l'ID du dashboard :
   - **1860** : Node Exporter Full
   - **11074** : Node Exporter for Prometheus
   - **3662** : Prometheus 2.0 Overview
3. Sélectionner la source Prometheus
4. Cliquer **Import**

---

## 5. Alertes Prometheus

### Créer des règles d'alerte

```bash
vim /etc/prometheus/alert.rules.yml
```

```yaml
groups:
  - name: node_alerts
    rules:
      # CPU élevé
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on {{ $labels.instance }}"
          description: "CPU usage is above 80% for more than 5 minutes."

      # Mémoire faible
      - alert: LowMemory
        expr: (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low memory on {{ $labels.instance }}"
          description: "Available memory is below 10%."

      # Disque plein
      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes) * 100 < 15
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space on {{ $labels.instance }}"
          description: "Disk space is below 15% on {{ $labels.mountpoint }}."

      # Instance down
      - alert: InstanceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Instance {{ $labels.instance }} down"
          description: "{{ $labels.instance }} has been down for more than 1 minute."
```

### Activer les règles

```bash
vim /etc/prometheus/prometheus.yml
```

```yaml
rule_files:
  - "alert.rules.yml"
```

```bash
chown prometheus:prometheus /etc/prometheus/alert.rules.yml
promtool check rules /etc/prometheus/alert.rules.yml
systemctl reload prometheus
```

---

## 6. Alertmanager (optionnel)

### Installer

```bash
cd /tmp
AM_VERSION="0.26.0"
wget https://github.com/prometheus/alertmanager/releases/download/v${AM_VERSION}/alertmanager-${AM_VERSION}.linux-amd64.tar.gz

tar xzf alertmanager-${AM_VERSION}.linux-amd64.tar.gz
cp alertmanager-${AM_VERSION}.linux-amd64/alertmanager /usr/local/bin/
cp alertmanager-${AM_VERSION}.linux-amd64/amtool /usr/local/bin/

useradd --no-create-home --shell /bin/false alertmanager
mkdir -p /etc/alertmanager /var/lib/alertmanager
chown alertmanager:alertmanager /etc/alertmanager /var/lib/alertmanager
```

### Configuration

```bash
vim /etc/alertmanager/alertmanager.yml
```

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'email-notifications'

receivers:
  - name: 'email-notifications'
    email_configs:
      - to: 'admin@example.com'
        from: 'alertmanager@example.com'
        smarthost: 'smtp.example.com:587'
        auth_username: 'alertmanager@example.com'
        auth_password: 'password'
```

### Service

```bash
vim /etc/systemd/system/alertmanager.service
```

```ini
[Unit]
Description=Alertmanager
Wants=network-online.target
After=network-online.target

[Service]
User=alertmanager
Group=alertmanager
Type=simple
ExecStart=/usr/local/bin/alertmanager \
    --config.file=/etc/alertmanager/alertmanager.yml \
    --storage.path=/var/lib/alertmanager/

Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now alertmanager

firewall-cmd --permanent --add-port=9093/tcp
firewall-cmd --reload
```

### Connecter à Prometheus

```yaml
# Dans prometheus.yml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ["localhost:9093"]
```

---

## 7. Monitoring d'autres services

### MySQL/MariaDB Exporter

```bash
# Installer
wget https://github.com/prometheus/mysqld_exporter/releases/download/v0.15.0/mysqld_exporter-0.15.0.linux-amd64.tar.gz
tar xzf mysqld_exporter-0.15.0.linux-amd64.tar.gz
cp mysqld_exporter-0.15.0.linux-amd64/mysqld_exporter /usr/local/bin/

# Créer utilisateur MySQL
mysql -u root -p << 'EOF'
CREATE USER 'exporter'@'localhost' IDENTIFIED BY 'password';
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configuration
cat > /etc/.mysqld_exporter.cnf << 'EOF'
[client]
user=exporter
password=password
EOF
chmod 600 /etc/.mysqld_exporter.cnf
```

### Nginx Exporter

```bash
# Dans nginx.conf, activer stub_status
location /nginx_status {
    stub_status on;
    allow 127.0.0.1;
    deny all;
}

# Installer nginx-prometheus-exporter
wget https://github.com/nginxinc/nginx-prometheus-exporter/releases/download/v0.11.0/nginx-prometheus-exporter_0.11.0_linux_amd64.tar.gz
```

---

## 8. SELinux

```bash
# Autoriser les connexions réseau
setsebool -P nis_enabled 1

# Ou créer une politique personnalisée si nécessaire
```

---

## 9. Sécurisation

### Authentification Prometheus (Nginx reverse proxy)

```nginx
server {
    listen 9090;
    server_name prometheus.example.com;

    auth_basic "Prometheus";
    auth_basic_user_file /etc/nginx/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:9091;
    }
}
```

### HTTPS pour Grafana

```bash
vim /etc/grafana/grafana.ini
```

```ini
[server]
protocol = https
cert_file = /etc/grafana/ssl/grafana.crt
cert_key = /etc/grafana/ssl/grafana.key
```

---

## Vérification

```bash
# Services
systemctl status prometheus node_exporter grafana-server

# Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[].health'

# Métriques
curl http://localhost:9100/metrics | grep node_cpu

# Grafana
curl -I http://localhost:3000
```

---

## Requêtes PromQL utiles

```promql
# CPU usage %
100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Mémoire utilisée %
(1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100

# Espace disque utilisé %
(1 - (node_filesystem_avail_bytes / node_filesystem_size_bytes)) * 100

# Trafic réseau (bytes/s)
rate(node_network_receive_bytes_total[5m])
rate(node_network_transmit_bytes_total[5m])

# Load average
node_load1
node_load5
node_load15
```

---

## Dépannage

| Problème | Solution |
|----------|----------|
| Target down | Vérifier firewall, exporter actif |
| Pas de données | Vérifier scrape_interval, target |
| Grafana erreur datasource | Vérifier URL Prometheus |

```bash
# Logs
journalctl -u prometheus -f
journalctl -u grafana-server -f

# Vérifier config
promtool check config /etc/prometheus/prometheus.yml
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
