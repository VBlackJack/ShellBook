---
tags:
  - tutos
  - monitoring
  - prometheus
  - grafana
  - debian
---

# Prometheus + Grafana sur Debian 12

Installation de **Prometheus** et **Grafana** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Prometheus | 2.x |
| Grafana | 10.x |
| Node Exporter | 1.x |

**Durée estimée :** 40 minutes

---

## 1. Installation de Prometheus

### Méthode APT (recommandée)

```bash
apt update
apt install -y prometheus prometheus-node-exporter

# Vérifier
systemctl status prometheus
systemctl status prometheus-node-exporter
```

### Ou installation manuelle

```bash
useradd --no-create-home --shell /bin/false prometheus

cd /tmp
PROM_VERSION="2.48.0"
wget https://github.com/prometheus/prometheus/releases/download/v${PROM_VERSION}/prometheus-${PROM_VERSION}.linux-amd64.tar.gz
tar xzf prometheus-${PROM_VERSION}.linux-amd64.tar.gz

cp prometheus-${PROM_VERSION}.linux-amd64/prometheus /usr/local/bin/
cp prometheus-${PROM_VERSION}.linux-amd64/promtool /usr/local/bin/
mkdir -p /etc/prometheus /var/lib/prometheus
chown -R prometheus:prometheus /etc/prometheus /var/lib/prometheus
```

---

## 2. Configuration Prometheus

```bash
vim /etc/prometheus/prometheus.yml
```

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files: []

scrape_configs:
  - job_name: "prometheus"
    static_configs:
      - targets: ["localhost:9090"]

  - job_name: "node"
    static_configs:
      - targets: ["localhost:9100"]

  # Ajouter d'autres serveurs
  # - job_name: "servers"
  #   static_configs:
  #     - targets: ["192.168.1.10:9100", "192.168.1.11:9100"]
```

```bash
systemctl restart prometheus
```

### Firewall

```bash
ufw allow 9090/tcp
ufw allow 9100/tcp
ufw reload
```

---

## 3. Installation de Grafana

### Ajouter le dépôt

```bash
apt install -y apt-transport-https software-properties-common wget

mkdir -p /etc/apt/keyrings/
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | tee /etc/apt/keyrings/grafana.gpg > /dev/null

echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" | tee /etc/apt/sources.list.d/grafana.list
```

### Installer

```bash
apt update
apt install -y grafana

systemctl enable --now grafana-server
systemctl status grafana-server

ufw allow 3000/tcp
```

### Accès

- URL : `http://IP:3000`
- Login : `admin` / `admin`

---

## 4. Configurer Grafana

### Ajouter la source Prometheus

1. **Configuration** → **Data Sources** → **Add**
2. Sélectionner **Prometheus**
3. URL : `http://localhost:9090`
4. **Save & Test**

### Importer dashboards

1. **Dashboards** → **Import**
2. Entrer l'ID :
   - `1860` : Node Exporter Full
   - `11074` : Node Exporter
3. Sélectionner la source Prometheus

---

## 5. Node Exporter sur serveurs distants

### Installation rapide

```bash
apt install -y prometheus-node-exporter
systemctl enable --now prometheus-node-exporter
ufw allow 9100/tcp
```

### Ajouter à Prometheus

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: "remote-nodes"
    static_configs:
      - targets:
          - "192.168.1.10:9100"
          - "192.168.1.11:9100"
          - "192.168.1.12:9100"
        labels:
          env: "production"
```

```bash
systemctl reload prometheus
```

---

## 6. Règles d'alerte

```bash
vim /etc/prometheus/alert.rules.yml
```

```yaml
groups:
  - name: system_alerts
    rules:
      - alert: InstanceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Instance {{ $labels.instance }} down"

      - alert: HighCPU
        expr: 100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU on {{ $labels.instance }}"

      - alert: LowDiskSpace
        expr: (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes) * 100 < 15
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk on {{ $labels.instance }}:{{ $labels.mountpoint }}"

      - alert: LowMemory
        expr: (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Low memory on {{ $labels.instance }}"
```

```yaml
# /etc/prometheus/prometheus.yml
rule_files:
  - "alert.rules.yml"
```

```bash
promtool check rules /etc/prometheus/alert.rules.yml
systemctl reload prometheus
```

---

## 7. Alertmanager

```bash
apt install -y prometheus-alertmanager

vim /etc/prometheus/alertmanager.yml
```

```yaml
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 3h
  receiver: 'email'

receivers:
  - name: 'email'
    email_configs:
      - to: 'admin@example.com'
        from: 'alerts@example.com'
        smarthost: 'smtp.example.com:587'
        auth_username: 'alerts@example.com'
        auth_password: 'password'
```

```yaml
# /etc/prometheus/prometheus.yml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ["localhost:9093"]
```

```bash
systemctl restart prometheus-alertmanager prometheus
```

---

## 8. Exporters additionnels

### MySQL/MariaDB

```bash
apt install -y prometheus-mysqld-exporter

# Créer utilisateur MySQL
mysql -u root -p << 'EOF'
CREATE USER 'exporter'@'localhost' IDENTIFIED BY 'password';
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configuration
cat > /etc/default/prometheus-mysqld-exporter << 'EOF'
DATA_SOURCE_NAME='exporter:password@(localhost:3306)/'
EOF

systemctl restart prometheus-mysqld-exporter
```

### PostgreSQL

```bash
apt install -y prometheus-postgres-exporter

# Créer utilisateur PostgreSQL
sudo -u postgres psql << 'EOF'
CREATE USER exporter WITH PASSWORD 'password';
GRANT pg_monitor TO exporter;
EOF

# Configuration
cat > /etc/default/prometheus-postgres-exporter << 'EOF'
DATA_SOURCE_NAME='postgresql://exporter:password@localhost:5432/postgres?sslmode=disable'
EOF

systemctl restart prometheus-postgres-exporter
```

### Nginx

```bash
# Dans nginx, activer stub_status
location /nginx_status {
    stub_status on;
    allow 127.0.0.1;
    deny all;
}

# Installer l'exporter
apt install -y prometheus-nginx-exporter
```

---

## 9. Grafana dashboards recommandés

| ID | Nom | Usage |
|----|-----|-------|
| 1860 | Node Exporter Full | Système complet |
| 11074 | Node Exporter | Vue simplifiée |
| 7362 | MySQL Overview | MariaDB/MySQL |
| 9628 | PostgreSQL | PostgreSQL |
| 12708 | Nginx | Nginx |
| 3662 | Prometheus 2.0 | Prometheus |

---

## 10. Sécurisation

### Reverse proxy Nginx pour Grafana

```nginx
server {
    listen 443 ssl;
    server_name grafana.example.com;

    ssl_certificate /etc/letsencrypt/live/grafana.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/grafana.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Authentification Prometheus

```bash
apt install -y apache2-utils
htpasswd -c /etc/prometheus/.htpasswd admin
```

```nginx
server {
    listen 9090;
    auth_basic "Prometheus";
    auth_basic_user_file /etc/prometheus/.htpasswd;

    location / {
        proxy_pass http://127.0.0.1:9091;
    }
}
```

---

## Vérification

```bash
# Services
systemctl status prometheus prometheus-node-exporter grafana-server

# Targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[] | {instance: .labels.instance, health: .health}'

# Métriques
curl -s http://localhost:9100/metrics | grep node_load

# Grafana
curl -I http://localhost:3000
```

---

## PromQL essentielles

```promql
# CPU %
100 - (avg by(instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Mémoire utilisée %
(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100

# Disque utilisé %
(1 - node_filesystem_avail_bytes{fstype!~"tmpfs"} / node_filesystem_size_bytes) * 100

# Réseau (bytes/s)
rate(node_network_receive_bytes_total[5m])
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Installation | Manuelle | APT disponible |
| Packages | prometheus (manuel) | prometheus, exporters |
| Firewall | firewalld | ufw |
| Alertmanager | Manuel | prometheus-alertmanager |

---

## Dépannage

```bash
# Logs
journalctl -u prometheus -f
journalctl -u grafana-server -f

# Vérifier config
promtool check config /etc/prometheus/prometheus.yml

# Targets down
curl http://localhost:9090/api/v1/targets
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
