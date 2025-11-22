# Prometheus, Loki & Grafana

`#monitoring` `#prometheus` `#loki` `#grafana` `#metrics`

Stack d'observabilité moderne pour le monitoring d'infrastructure et d'applications.

---

## Les 3 Piliers de l'Observabilité

### Vue d'Ensemble

```mermaid
flowchart LR
    APP[Application] --> METRICS[Métriques<br/>Prometheus]
    APP --> LOGS[Logs<br/>Loki]
    APP --> TRACES[Traces<br/>Tempo/Jaeger]

    METRICS --> GRAFANA[Grafana<br/>Dashboards]
    LOGS --> GRAFANA
    TRACES --> GRAFANA

    GRAFANA --> ALERTS[Alerting<br/>Alertmanager]
```

### Comparatif

| Pilier | Technologie | Question | Format | Exemple |
|--------|-------------|----------|--------|---------|
| **Métriques** | Prometheus | **Quoi ?** | Séries temporelles (chiffres) | `cpu_usage{host="web1"} 90` |
| **Logs** | Loki / ELK | **Pourquoi ?** | Texte structuré ou non | `ERROR: Connection timeout at line 42` |
| **Traces** | Tempo / Jaeger | **Où ?** | Spans avec timing | `GET /api/users → 250ms (DB: 200ms)` |

### Quand utiliser quoi ?

```
Scénario : "Le site est lent !"

1. MÉTRIQUES (Prometheus)
   → Latence P95 des requêtes HTTP : 2.5s (normal = 200ms)
   → CPU du pod "api" : 95%

2. LOGS (Loki)
   → Recherche "error" dans les logs de "api"
   → Trouve : "Database connection pool exhausted"

3. TRACES (Tempo)
   → Requête /api/checkout prend 2.3s
   → Décomposition : DB query = 2.1s, API call = 0.2s
   → Le problème est la query SQL lente
```

---

## Prometheus : Le Collecteur de Métriques

### Architecture Pull

Contrairement à d'autres systèmes (Graphite, InfluxDB), Prometheus **va chercher** les métriques (pull).

```
┌─────────────┐         HTTP GET /metrics         ┌──────────────┐
│ Prometheus  │ ─────────────────────────────────► │ Application  │
│   Server    │ ◄───────────────────────────────── │ (/metrics)   │
└─────────────┘     200 OK + metrics format       └──────────────┘
      │
      │ Scrape toutes les 15s (configurable)
      │
      ▼
┌─────────────┐
│  Time Series│
│   Database  │
└─────────────┘
```

**Avantages :**

- Prometheus contrôle la fréquence de collecte
- Pas de dépendance réseau depuis les apps
- Détection automatique des cibles down

### Configuration de Base

```yaml
# prometheus.yml
global:
  scrape_interval: 15s       # Collecter toutes les 15s
  evaluation_interval: 15s   # Évaluer les règles toutes les 15s

scrape_configs:
  # Job 1 : Prometheus lui-même
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  # Job 2 : Node Exporter (métriques système)
  - job_name: 'node'
    static_configs:
      - targets: ['node1:9100', 'node2:9100']

  # Job 3 : Application custom
  - job_name: 'myapp'
    static_configs:
      - targets: ['app1:8080', 'app2:8080']
```

### Les Exporters (Adaptateurs)

Prometheus ne sait scraper que le **format Prometheus** (texte simple). Les exporters convertissent les métriques système/applicatives.

| Exporter | Usage | Port | Métriques clés |
|----------|-------|------|----------------|
| **node_exporter** | Hardware Linux | 9100 | `node_cpu_seconds_total`, `node_memory_*`, `node_disk_*` |
| **cadvisor** | Conteneurs Docker | 8080 | `container_cpu_usage_seconds_total`, `container_memory_usage_bytes` |
| **mysqld_exporter** | MySQL/MariaDB | 9104 | `mysql_global_status_connections`, `mysql_global_status_queries` |
| **blackbox_exporter** | Probing HTTP/TCP/ICMP | 9115 | `probe_success`, `probe_duration_seconds` |
| **postgres_exporter** | PostgreSQL | 9187 | `pg_stat_database_*`, `pg_locks_count` |

```bash
# Installation node_exporter (systemd)
wget https://github.com/prometheus/node_exporter/releases/download/v1.7.0/node_exporter-1.7.0.linux-amd64.tar.gz
tar xvf node_exporter-1.7.0.linux-amd64.tar.gz
sudo mv node_exporter-1.7.0.linux-amd64/node_exporter /usr/local/bin/

# Créer le service
sudo tee /etc/systemd/system/node_exporter.service > /dev/null <<EOF
[Unit]
Description=Node Exporter

[Service]
ExecStart=/usr/local/bin/node_exporter

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now node_exporter

# Vérifier
curl http://localhost:9100/metrics
```

### PromQL : Le Langage de Requête

```promql
# Métrique instantanée
node_cpu_seconds_total

# Filtrer par label
node_cpu_seconds_total{mode="idle"}

# Taux sur 5 minutes (pour les counters)
rate(http_requests_total[5m])

# Agrégation par instance
sum by (instance) (rate(http_requests_total[5m]))

# Top 5 des pods par CPU
topk(5, sum by (pod) (rate(container_cpu_usage_seconds_total[5m])))

# Mémoire disponible en %
100 * (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)

# Disque plein à >80%
(node_filesystem_avail_bytes / node_filesystem_size_bytes) < 0.2

# Prédiction : disque plein dans 4h
predict_linear(node_filesystem_free_bytes[1h], 4*3600) < 0
```

### Types de Métriques

| Type | Description | Exemple | Utilisation |
|------|-------------|---------|-------------|
| **Counter** | Toujours croissant | `http_requests_total` | Utiliser `rate()` ou `increase()` |
| **Gauge** | Peut monter/descendre | `node_memory_free_bytes` | Utiliser tel quel |
| **Histogram** | Distribution de valeurs | `http_request_duration_seconds` | Utiliser `_bucket`, `_sum`, `_count` |
| **Summary** | Quantiles précalculés | `rpc_duration_seconds` | Utiliser `{quantile="0.95"}` |

---

## Loki : Prometheus pour les Logs

### Concept Clé : Pas d'Indexation Full-Text

```
┌─────────────────────────────────────────────┐
│          ELK Stack (Elasticsearch)          │
│  - Indexe TOUT le texte                     │
│  - Heavy : 10 GB de logs = 30 GB d'index    │
│  - Coûteux en CPU/RAM/disque                │
└─────────────────────────────────────────────┘

          VS

┌─────────────────────────────────────────────┐
│               Grafana Loki                   │
│  - Indexe UNIQUEMENT les labels             │
│  - Light : 10 GB de logs = 10.5 GB stockés  │
│  - Grep distribué sur les logs bruts        │
└─────────────────────────────────────────────┘
```

**Philosophie :** Loki ne cherche pas à indexer tout le texte comme Elasticsearch. Il stocke les logs bruts et utilise des **labels** (comme Prometheus) pour les filtrer.

### Architecture

```
┌──────────────┐
│ Application  │
│   (stdout)   │
└──────┬───────┘
       │
       ▼
┌──────────────┐     HTTP Push      ┌──────────────┐
│   Promtail   │ ──────────────────► │     Loki     │
│ (Log Shipper)│                     │   (Server)   │
└──────────────┘                     └──────┬───────┘
                                            │
                                            ▼
                                     ┌──────────────┐
                                     │   Grafana    │
                                     │  (Frontend)  │
                                     └──────────────┘
```

- **Promtail** : Agent installé sur chaque serveur/pod, lit les logs et les envoie à Loki
- **Loki** : Serveur central qui stocke et indexe les logs
- **Grafana** : Interface de visualisation

### Installation Stack Loki (Docker Compose)

```yaml
# docker-compose.yml
version: "3.8"

services:
  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    volumes:
      - ./loki-config.yaml:/etc/loki/local-config.yaml
      - loki-data:/loki
    command: -config.file=/etc/loki/local-config.yaml

  promtail:
    image: grafana/promtail:2.9.0
    volumes:
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - ./promtail-config.yaml:/etc/promtail/config.yml
    command: -config.file=/etc/promtail/config.yml

  grafana:
    image: grafana/grafana:10.2.0
    ports:
      - "3000:3000"
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
    volumes:
      - grafana-data:/var/lib/grafana

volumes:
  loki-data:
  grafana-data:
```

```yaml
# promtail-config.yaml
server:
  http_listen_port: 9080

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  # Logs système
  - job_name: system
    static_configs:
      - targets:
          - localhost
        labels:
          job: varlogs
          __path__: /var/log/*.log

  # Logs Docker
  - job_name: containers
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
        refresh_interval: 5s
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        target_label: 'container'
```

### LogQL : Le Langage de Requête

```logql
# Recherche simple
{job="varlogs"}

# Filtrer par container
{container="nginx"}

# Recherche de texte (insensible à la casse)
{container="nginx"} |= "error"
{container="nginx"} |~ "(?i)error"

# Exclure
{container="nginx"} != "200 OK"

# Multiple conditions
{job="varlogs", level="error"} |= "database"

# Regex
{container="api"} |~ "HTTP [45][0-9]{2}"

# Parser JSON
{container="api"} | json | level="error"

# Métriques depuis logs (count over time)
count_over_time({container="nginx"} |= "error" [5m])

# Taux d'erreurs
rate({container="nginx"} |= "error" [5m])

# Top 5 des IPs avec le plus de 404
topk(5,
  sum by (ip) (
    count_over_time({container="nginx"} |= "404" | regexp `(?P<ip>\d+\.\d+\.\d+\.\d+)` [5m])
  )
)
```

---

## Grafana : La Vitrine

### Concept de Data Source

Grafana ne stocke **aucune donnée**. Il se connecte à des sources externes.

```
┌──────────────────────────────────────────┐
│              Grafana                     │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │      Data Sources                  │ │
│  │  - Prometheus (metrics)            │ │
│  │  - Loki (logs)                     │ │
│  │  - Tempo (traces)                  │ │
│  │  - PostgreSQL, MySQL, InfluxDB...  │ │
│  └────────────────────────────────────┘ │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │        Dashboards                  │ │
│  │  - Infrastructure                  │ │
│  │  - Application Performance         │ │
│  │  - Business Metrics                │ │
│  └────────────────────────────────────┘ │
└──────────────────────────────────────────┘
```

### Ajouter une Data Source (UI)

```
1. Grafana → Configuration → Data Sources
2. Add data source
3. Choisir "Prometheus"
4. URL : http://prometheus:9090
5. Save & Test
```

### Ajouter une Data Source (Code)

```yaml
# datasources.yaml (volume monté dans /etc/grafana/provisioning/datasources/)
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true

  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100

  - name: Tempo
    type: tempo
    access: proxy
    url: http://tempo:3200
```

### Dashboards Communautaires

Grafana possède un **store de dashboards** prêts à l'emploi : [grafana.com/grafana/dashboards](https://grafana.com/grafana/dashboards)

| Dashboard | ID | Usage |
|-----------|----|----- |
| **Node Exporter Full** | 1860 | Monitoring serveur Linux complet |
| **Docker Container & Host** | 10619 | Monitoring Docker |
| **Kubernetes Cluster Monitoring** | 7249 | K8s overview |
| **NGINX Ingress Controller** | 9614 | Ingress K8s |
| **PostgreSQL Database** | 9628 | Monitoring PostgreSQL |

```bash
# Importer un dashboard via UI
Grafana → Dashboards → Import → Enter ID : 1860 → Load

# Ou via API
curl -X POST http://admin:admin@localhost:3000/api/dashboards/import \
  -H "Content-Type: application/json" \
  -d '{
    "dashboard": {
      "id": null,
      "uid": null,
      "title": "Node Exporter Full"
    },
    "overwrite": true,
    "inputs": [{
      "name": "DS_PROMETHEUS",
      "type": "datasource",
      "pluginId": "prometheus",
      "value": "Prometheus"
    }]
  }'
```

### Panels : Les Briques des Dashboards

| Type de Panel | Usage | Exemple |
|---------------|-------|---------|
| **Time series** | Courbes de métriques | CPU over time |
| **Gauge** | Valeur instantanée avec seuils | Disk usage 75% |
| **Stat** | Valeur unique grande | Total requests: 1.2M |
| **Bar chart** | Comparaisons | Requests by endpoint |
| **Table** | Données tabulaires | Top 10 slowest queries |
| **Logs** | Affichage de logs Loki | Stream logs from pods |
| **Heatmap** | Distribution de latences | P50, P95, P99 histogram |

### Variables : Dashboards Dynamiques

```
Variable "instance" :
Query : label_values(node_cpu_seconds_total, instance)

Utilisation dans query :
rate(node_cpu_seconds_total{instance="$instance"}[5m])
```

Permet de créer un **dropdown** dans le dashboard pour sélectionner l'instance à monitorer.

### Alerting : Grafana Alerting (v9+)

```yaml
# Exemple d'alerte : CPU > 80% pendant 5 minutes
- alert: HighCPU
  expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High CPU on {{ $labels.instance }}"
    description: "CPU usage is {{ $value }}%"
```

Grafana peut envoyer les alertes vers :

- Email
- Slack
- PagerDuty
- Webhook
- Microsoft Teams
- Discord

---

## Stack Complète : Docker Compose Exemple

```yaml
# docker-compose.yml - Stack complète Prometheus + Loki + Grafana
version: "3.8"

services:
  # === MÉTRIQUES ===
  prometheus:
    image: prom/prometheus:v2.48.0
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'

  node-exporter:
    image: prom/node-exporter:v1.7.0
    ports:
      - "9100:9100"
    command:
      - '--path.rootfs=/host'
    volumes:
      - '/:/host:ro,rslave'

  cadvisor:
    image: gcr.io/cadvisor/cadvisor:v0.47.0
    ports:
      - "8080:8080"
    volumes:
      - /:/rootfs:ro
      - /var/run:/var/run:ro
      - /sys:/sys:ro
      - /var/lib/docker/:/var/lib/docker:ro

  # === LOGS ===
  loki:
    image: grafana/loki:2.9.0
    ports:
      - "3100:3100"
    volumes:
      - loki-data:/loki
    command: -config.file=/etc/loki/local-config.yaml

  promtail:
    image: grafana/promtail:2.9.0
    volumes:
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - ./promtail-config.yaml:/etc/promtail/config.yml
    command: -config.file=/etc/promtail/config.yml

  # === VISUALISATION ===
  grafana:
    image: grafana/grafana:10.2.0
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/provisioning:/etc/grafana/provisioning

volumes:
  prometheus-data:
  loki-data:
  grafana-data:
```

```bash
# Démarrer la stack
docker-compose up -d

# Accès
# Grafana : http://localhost:3000 (admin/admin)
# Prometheus : http://localhost:9090
# Loki : http://localhost:3100
```

---

## Référence Rapide

```bash
# === PROMETHEUS ===
# Vérifier targets
curl http://localhost:9090/api/v1/targets

# Exécuter une query PromQL via API
curl -G http://localhost:9090/api/v1/query \
  --data-urlencode 'query=up'

# Recharger la config sans restart
curl -X POST http://localhost:9090/-/reload

# === LOKI ===
# Pousser des logs manuellement
curl -X POST http://localhost:3100/loki/api/v1/push \
  -H "Content-Type: application/json" \
  -d '{
    "streams": [{
      "stream": {"job": "test"},
      "values": [["'"$(date +%s)000000000"'", "test log message"]]
    }]
  }'

# Query LogQL via API
curl -G http://localhost:3100/loki/api/v1/query \
  --data-urlencode 'query={job="varlogs"}'

# === GRAFANA ===
# Créer une API key
curl -X POST http://admin:admin@localhost:3000/api/auth/keys \
  -H "Content-Type: application/json" \
  -d '{"name":"mykey", "role":"Admin"}'

# Lister les dashboards
curl http://admin:admin@localhost:3000/api/search

# === EXPORTERS ===
# Node Exporter
curl http://localhost:9100/metrics | grep node_cpu

# cAdvisor
curl http://localhost:8080/metrics | grep container_cpu
```

---

## Dépannage

### Prometheus : Targets Down

```bash
# Vérifier la connectivité
curl http://target-host:9100/metrics

# Vérifier les logs Prometheus
docker logs prometheus

# Causes communes :
# - Firewall bloque le port
# - Exporter non démarré
# - Mauvaise URL dans prometheus.yml
```

### Loki : No Logs Received

```bash
# Vérifier Promtail
docker logs promtail

# Tester l'envoi manuel
curl -X POST http://localhost:3100/loki/api/v1/push \
  -H "Content-Type: application/json" \
  -d '{
    "streams": [{
      "stream": {"job": "test"},
      "values": [["'"$(date +%s)000000000"'", "test"]]
    }]
  }'

# Vérifier les labels dans Grafana Explore
# → Loki data source → Label browser
```

### Grafana : No Data

```bash
# Vérifier la data source
Grafana → Configuration → Data Sources → Test

# Vérifier la query dans Explore
Grafana → Explore → Choisir Prometheus → Metrics browser

# Vérifier les logs Grafana
docker logs grafana
```
