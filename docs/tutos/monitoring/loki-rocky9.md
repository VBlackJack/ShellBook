---
tags:
  - tutos
  - monitoring
  - loki
  - grafana
  - logs
  - rocky
---

# Grafana Loki sur Rocky Linux 9

Installation de **Grafana Loki** pour l'agrégation de logs.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| Loki | 2.9+ |
| Promtail | 2.9+ |
| Grafana | 10+ |

**Durée estimée :** 35 minutes

---

## Avantages Loki

| Caractéristique | Description |
|-----------------|-------------|
| **Léger** | N'indexe que les labels |
| **Scalable** | Architecture distribuée |
| **Compatible** | S'intègre avec Grafana |
| **LogQL** | Langage de requête puissant |

---

## Architecture

```
Applications → Promtail → Loki → Grafana
                 ↓
              Labels + Logs
```

---

## 1. Installation Loki

### Télécharger le binaire

```bash
cd /tmp
LOKI_VERSION="2.9.3"
wget https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/loki-linux-amd64.zip
unzip loki-linux-amd64.zip
mv loki-linux-amd64 /usr/local/bin/loki
chmod +x /usr/local/bin/loki
```

### Utilisateur et répertoires

```bash
useradd -r -s /sbin/nologin loki
mkdir -p /etc/loki /var/lib/loki
chown -R loki:loki /var/lib/loki
```

---

## 2. Configuration Loki

```bash
cat > /etc/loki/loki-config.yml << 'EOF'
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  instance_addr: 127.0.0.1
  path_prefix: /var/lib/loki
  storage:
    filesystem:
      chunks_directory: /var/lib/loki/chunks
      rules_directory: /var/lib/loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h

ruler:
  alertmanager_url: http://localhost:9093

limits_config:
  reject_old_samples: true
  reject_old_samples_max_age: 168h
  ingestion_rate_mb: 4
  ingestion_burst_size_mb: 6

analytics:
  reporting_enabled: false
EOF

chown loki:loki /etc/loki/loki-config.yml
```

---

## 3. Service systemd Loki

```bash
cat > /etc/systemd/system/loki.service << 'EOF'
[Unit]
Description=Loki log aggregation system
After=network-online.target
Wants=network-online.target

[Service]
User=loki
Group=loki
Type=simple
ExecStart=/usr/local/bin/loki -config.file=/etc/loki/loki-config.yml
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now loki
```

---

## 4. Installation Promtail

### Télécharger le binaire

```bash
cd /tmp
wget https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/promtail-linux-amd64.zip
unzip promtail-linux-amd64.zip
mv promtail-linux-amd64 /usr/local/bin/promtail
chmod +x /usr/local/bin/promtail
```

### Utilisateur et répertoires

```bash
useradd -r -s /sbin/nologin promtail
mkdir -p /etc/promtail
usermod -aG adm promtail  # Accès aux logs
```

---

## 5. Configuration Promtail

```bash
cat > /etc/promtail/promtail-config.yml << 'EOF'
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  # System logs
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          host: ${HOSTNAME}
          __path__: /var/log/*.log

  # Journal systemd
  - job_name: journal
    journal:
      json: false
      max_age: 12h
      path: /var/log/journal
      labels:
        job: systemd-journal
        host: ${HOSTNAME}
    relabel_configs:
      - source_labels: ['__journal__systemd_unit']
        target_label: 'unit'

  # Secure log
  - job_name: secure
    static_configs:
      - targets:
          - localhost
        labels:
          job: secure
          host: ${HOSTNAME}
          __path__: /var/log/secure

  # Messages
  - job_name: messages
    static_configs:
      - targets:
          - localhost
        labels:
          job: messages
          host: ${HOSTNAME}
          __path__: /var/log/messages

  # Nginx (si installé)
  - job_name: nginx
    static_configs:
      - targets:
          - localhost
        labels:
          job: nginx
          host: ${HOSTNAME}
          __path__: /var/log/nginx/*.log
    pipeline_stages:
      - regex:
          expression: '^(?P<remote_addr>[\w\.]+) - (?P<remote_user>[^ ]*) \[(?P<time_local>[^\]]*)\] "(?P<method>\w+) (?P<request>[^ ]*) (?P<protocol>[^"]*)" (?P<status>\d+) (?P<body_bytes_sent>\d+)'
      - labels:
          method:
          status:
EOF

chown promtail:promtail /etc/promtail/promtail-config.yml
```

---

## 6. Service systemd Promtail

```bash
cat > /etc/systemd/system/promtail.service << 'EOF'
[Unit]
Description=Promtail log agent
After=network-online.target loki.service
Wants=network-online.target

[Service]
User=promtail
Group=promtail
Type=simple
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/promtail-config.yml
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now promtail
```

---

## 7. Firewall

```bash
firewall-cmd --permanent --add-port=3100/tcp   # Loki API
firewall-cmd --permanent --add-port=9080/tcp   # Promtail
firewall-cmd --reload
```

---

## 8. Installation Grafana

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

dnf install -y grafana
systemctl enable --now grafana-server

firewall-cmd --permanent --add-port=3000/tcp
firewall-cmd --reload
```

---

## 9. Configurer Loki dans Grafana

1. Ouvrir `http://IP:3000` (admin/admin)
2. Configuration → Data Sources → Add data source
3. Sélectionner "Loki"
4. URL: `http://localhost:3100`
5. Save & Test

---

## 10. LogQL - Requêtes de base

### Sélecteurs

```logql
# Par job
{job="varlogs"}

# Par host
{host="server1"}

# Combinés
{job="nginx", host="webserver"}
```

### Filtres

```logql
# Contient
{job="secure"} |= "Failed"

# Ne contient pas
{job="messages"} != "debug"

# Regex
{job="nginx"} |~ "error|warn"

# Négation regex
{job="varlogs"} !~ "healthcheck"
```

### Parsers

```logql
# Parser JSON
{job="app"} | json

# Parser logfmt
{job="system"} | logfmt

# Parser regex
{job="nginx"} | regexp `(?P<ip>\d+\.\d+\.\d+\.\d+)`
```

---

## 11. LogQL - Métriques

```logql
# Taux d'erreurs par seconde
rate({job="nginx"} |= "error" [5m])

# Comptage sur période
count_over_time({job="secure"} |= "Failed" [1h])

# Top 10 IPs
topk(10, sum by (ip) (count_over_time({job="nginx"} | regexp `(?P<ip>\d+\.\d+\.\d+\.\d+)` [1h])))
```

---

## 12. Alerting avec Ruler

### Configurer les règles

```bash
mkdir -p /var/lib/loki/rules/fake

cat > /var/lib/loki/rules/fake/alerts.yml << 'EOF'
groups:
  - name: security
    rules:
      - alert: HighFailedLogins
        expr: |
          sum(rate({job="secure"} |= "Failed password" [5m])) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High rate of failed SSH logins"
          description: "More than 5 failed logins per second over 5 minutes"

      - alert: RootLogin
        expr: |
          count_over_time({job="secure"} |= "session opened for user root" [1m]) > 0
        labels:
          severity: info
        annotations:
          summary: "Root user logged in"
EOF

chown -R loki:loki /var/lib/loki/rules
systemctl restart loki
```

---

## 13. Retention et nettoyage

### Configuration retention

```yaml
# Dans loki-config.yml
compactor:
  working_directory: /var/lib/loki/compactor
  shared_store: filesystem
  compaction_interval: 10m
  retention_enabled: true
  retention_delete_delay: 2h
  retention_delete_worker_count: 150

limits_config:
  retention_period: 720h  # 30 jours
```

---

## 14. Multi-tenant

```yaml
# loki-config.yml
auth_enabled: true

# Dans Promtail - ajouter tenant
clients:
  - url: http://localhost:3100/loki/api/v1/push
    tenant_id: team-a
```

---

## 15. Dashboards Grafana

### Dashboard Logs Explorer

1. Create → Dashboard → Add Panel
2. Data source: Loki
3. Query: `{job="varlogs"}`
4. Visualization: Logs

### Dashboard Stats

```logql
# Panel: Error rate
sum(rate({job=~".+"} |= "error" [5m])) by (job)

# Panel: Log volume
sum(bytes_over_time({job=~".+"} [1h])) by (job)
```

---

## Commandes utiles

```bash
# Vérifier Loki
curl http://localhost:3100/ready
curl http://localhost:3100/metrics

# Vérifier Promtail
curl http://localhost:9080/ready
curl http://localhost:9080/targets

# Query API
curl -G -s "http://localhost:3100/loki/api/v1/query" \
  --data-urlencode 'query={job="varlogs"}' | jq

# Labels disponibles
curl http://localhost:3100/loki/api/v1/labels

# Valeurs d'un label
curl http://localhost:3100/loki/api/v1/label/job/values
```

---

## Dépannage

```bash
# Logs Loki
journalctl -u loki -f

# Logs Promtail
journalctl -u promtail -f

# Vérifier config
/usr/local/bin/loki -config.file=/etc/loki/loki-config.yml -verify-config

# Status targets Promtail
curl http://localhost:9080/targets
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
