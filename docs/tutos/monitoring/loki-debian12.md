---
tags:
  - tutos
  - monitoring
  - loki
  - grafana
  - logs
  - debian
---

# Grafana Loki sur Debian 12

Installation de **Grafana Loki** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| Loki | 2.9+ |
| Promtail | 2.9+ |
| Grafana | 10+ |

**Durée estimée :** 30 minutes

---

## 1. Installation Loki

```bash
cd /tmp
LOKI_VERSION="2.9.3"
wget https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/loki-linux-amd64.zip
apt install -y unzip
unzip loki-linux-amd64.zip
mv loki-linux-amd64 /usr/local/bin/loki
chmod +x /usr/local/bin/loki

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

limits_config:
  reject_old_samples: true
  reject_old_samples_max_age: 168h

analytics:
  reporting_enabled: false
EOF

chown loki:loki /etc/loki/loki-config.yml
```

---

## 3. Service Loki

```bash
cat > /etc/systemd/system/loki.service << 'EOF'
[Unit]
Description=Loki log aggregation system
After=network-online.target

[Service]
User=loki
Group=loki
Type=simple
ExecStart=/usr/local/bin/loki -config.file=/etc/loki/loki-config.yml
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now loki
```

---

## 4. Installation Promtail

```bash
cd /tmp
wget https://github.com/grafana/loki/releases/download/v${LOKI_VERSION}/promtail-linux-amd64.zip
unzip promtail-linux-amd64.zip
mv promtail-linux-amd64 /usr/local/bin/promtail
chmod +x /usr/local/bin/promtail

useradd -r -s /sbin/nologin promtail
mkdir -p /etc/promtail
usermod -aG adm promtail
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
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          host: ${HOSTNAME}
          __path__: /var/log/*.log

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

  - job_name: auth
    static_configs:
      - targets:
          - localhost
        labels:
          job: auth
          host: ${HOSTNAME}
          __path__: /var/log/auth.log

  - job_name: syslog
    static_configs:
      - targets:
          - localhost
        labels:
          job: syslog
          host: ${HOSTNAME}
          __path__: /var/log/syslog
EOF

chown promtail:promtail /etc/promtail/promtail-config.yml
```

---

## 6. Service Promtail

```bash
cat > /etc/systemd/system/promtail.service << 'EOF'
[Unit]
Description=Promtail log agent
After=network-online.target loki.service

[Service]
User=promtail
Group=promtail
Type=simple
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/promtail-config.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now promtail
```

---

## 7. Installation Grafana

```bash
apt install -y apt-transport-https software-properties-common
wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor > /etc/apt/keyrings/grafana.gpg
echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
apt update
apt install -y grafana
systemctl enable --now grafana-server
```

---

## 8. Firewall

```bash
ufw allow 3100/tcp  # Loki
ufw allow 9080/tcp  # Promtail
ufw allow 3000/tcp  # Grafana
ufw reload
```

---

## 9. Configurer Grafana

1. Ouvrir `http://IP:3000` (admin/admin)
2. Data Sources → Add → Loki
3. URL: `http://localhost:3100`
4. Save & Test

---

## 10. LogQL exemples

```logql
# Logs système
{job="syslog"}

# Erreurs auth
{job="auth"} |= "Failed"

# Par unité systemd
{job="systemd-journal", unit="nginx.service"}

# Taux d'erreurs
rate({job="auth"} |= "authentication failure" [5m])
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Logs auth | /var/log/secure | /var/log/auth.log |
| Logs système | /var/log/messages | /var/log/syslog |
| Firewall | firewalld | ufw |

---

## Commandes

```bash
# Status
curl http://localhost:3100/ready
curl http://localhost:9080/targets

# Logs
journalctl -u loki -f
journalctl -u promtail -f

# Query
curl -G "http://localhost:3100/loki/api/v1/query" \
  --data-urlencode 'query={job="syslog"}'
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
