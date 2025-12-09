---
tags:
  - formation
  - observability
  - prometheus
  - grafana
  - tp
---

# TP Final : Stack d'Observabilité Complète

## Objectifs

- Déployer une stack de monitoring production-ready
- Monitorer une application multi-tiers
- Créer des SLOs et SLIs
- Simuler et résoudre des incidents

**Durée :** 2 heures

---

## Scénario

Vous êtes SRE chez **TechShop**, une plateforme e-commerce. Vous devez mettre en place une stack d'observabilité complète pour monitorer :

- Frontend (Nginx)
- API Backend (Python/Flask)
- Base de données (PostgreSQL)
- Cache (Redis)

---

## Architecture

![TechShop Observability Architecture](../../assets/diagrams/observability-techshop-architecture.jpeg)

```
ARCHITECTURE TECHSHOP
═════════════════════

                    ┌─────────────────────────────────────────┐
                    │              MONITORING                  │
                    │                                          │
                    │  ┌──────────┐  ┌──────────┐  ┌────────┐│
                    │  │Prometheus│  │ Grafana  │  │Alertmgr││
                    │  │  :9090   │  │  :3000   │  │  :9093 ││
                    │  └────┬─────┘  └──────────┘  └────────┘│
                    │       │                                  │
                    └───────┼──────────────────────────────────┘
                            │ scrape
        ┌───────────────────┼───────────────────────┐
        │                   │                       │
        ▼                   ▼                       ▼
┌───────────────┐   ┌───────────────┐       ┌───────────────┐
│    Nginx      │   │   API Flask   │       │  Node Exporter│
│   Frontend    │   │   Backend     │       │   (chaque)    │
│    :80        │   │    :5000      │       │    :9100      │
│  + Exporter   │   │  + /metrics   │       │               │
│    :9113      │   │               │       │               │
└───────┬───────┘   └───────┬───────┘       └───────────────┘
        │                   │
        │           ┌───────┴───────┐
        │           │               │
        │           ▼               ▼
        │   ┌───────────────┐ ┌───────────────┐
        │   │  PostgreSQL   │ │    Redis      │
        │   │    :5432      │ │    :6379      │
        │   │  + Exporter   │ │  + Exporter   │
        │   │    :9187      │ │    :9121      │
        │   └───────────────┘ └───────────────┘
        │
        ▼
┌───────────────┐
│   Blackbox    │
│   Exporter    │
│    :9115      │
└───────────────┘
```

---

## Partie 1 : Déploiement (30 min)

### 1.1 Structure du Projet

```bash
mkdir -p techshop-monitoring/{prometheus,alertmanager,grafana,app}
cd techshop-monitoring
```

### 1.2 Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  # ============ APPLICATION ============
  nginx:
    image: nginx:alpine
    container_name: nginx
    ports:
      - "80:80"
    volumes:
      - ./app/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - api

  api:
    build: ./app
    container_name: api
    ports:
      - "5000:5000"
    environment:
      - DATABASE_URL=postgresql://techshop:password@postgres:5432/techshop
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:15-alpine
    container_name: postgres
    environment:
      - POSTGRES_USER=techshop
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=techshop
    volumes:
      - postgres_data:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    container_name: redis

  # ============ EXPORTERS ============
  node-exporter:
    image: prom/node-exporter:latest
    container_name: node-exporter
    ports:
      - "9100:9100"
    volumes:
      - /proc:/host/proc:ro
      - /sys:/host/sys:ro
      - /:/rootfs:ro
    command:
      - '--path.procfs=/host/proc'
      - '--path.sysfs=/host/sys'
      - '--collector.filesystem.mount-points-exclude=^/(sys|proc|dev|host|etc)($$|/)'

  nginx-exporter:
    image: nginx/nginx-prometheus-exporter:latest
    container_name: nginx-exporter
    ports:
      - "9113:9113"
    command:
      - '-nginx.scrape-uri=http://nginx:80/stub_status'
    depends_on:
      - nginx

  postgres-exporter:
    image: prometheuscommunity/postgres-exporter:latest
    container_name: postgres-exporter
    ports:
      - "9187:9187"
    environment:
      - DATA_SOURCE_NAME=postgresql://techshop:password@postgres:5432/techshop?sslmode=disable

  redis-exporter:
    image: oliver006/redis_exporter:latest
    container_name: redis-exporter
    ports:
      - "9121:9121"
    environment:
      - REDIS_ADDR=redis://redis:6379

  blackbox-exporter:
    image: prom/blackbox-exporter:latest
    container_name: blackbox-exporter
    ports:
      - "9115:9115"
    volumes:
      - ./prometheus/blackbox.yml:/etc/blackbox_exporter/config.yml

  # ============ MONITORING STACK ============
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
      - ./prometheus/rules:/etc/prometheus/rules
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--storage.tsdb.retention.time=7d'
      - '--web.enable-lifecycle'

  alertmanager:
    image: prom/alertmanager:latest
    container_name: alertmanager
    ports:
      - "9093:9093"
    volumes:
      - ./alertmanager/alertmanager.yml:/etc/alertmanager/alertmanager.yml

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
      - grafana_data:/var/lib/grafana
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin123

volumes:
  postgres_data:
  prometheus_data:
  grafana_data:
```

### 1.3 Application Flask avec Métriques

```python
# app/app.py
from flask import Flask, jsonify, request
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST
import time
import random
import redis
import psycopg2
import os

app = Flask(__name__)

# Métriques Prometheus
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency',
    ['method', 'endpoint'],
    buckets=[0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0]
)

ACTIVE_REQUESTS = Gauge(
    'http_requests_active',
    'Active HTTP requests'
)

ORDERS_TOTAL = Counter(
    'orders_total',
    'Total orders processed',
    ['status']
)

CART_VALUE = Histogram(
    'cart_value_euros',
    'Shopping cart value',
    buckets=[10, 25, 50, 100, 200, 500, 1000]
)

# Connexions
redis_client = redis.from_url(os.environ.get('REDIS_URL', 'redis://localhost:6379'))

def get_db():
    return psycopg2.connect(os.environ.get('DATABASE_URL', 'postgresql://techshop:password@localhost:5432/techshop'))

# Middleware pour les métriques
@app.before_request
def before_request():
    request.start_time = time.time()
    ACTIVE_REQUESTS.inc()

@app.after_request
def after_request(response):
    latency = time.time() - request.start_time
    REQUEST_COUNT.labels(request.method, request.path, response.status_code).inc()
    REQUEST_LATENCY.labels(request.method, request.path).observe(latency)
    ACTIVE_REQUESTS.dec()
    return response

# Endpoints
@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

@app.route('/api/products')
def get_products():
    # Simuler une latence variable
    time.sleep(random.uniform(0.01, 0.1))
    return jsonify({'products': [
        {'id': 1, 'name': 'Laptop', 'price': 999},
        {'id': 2, 'name': 'Phone', 'price': 699},
        {'id': 3, 'name': 'Tablet', 'price': 499}
    ]})

@app.route('/api/cart', methods=['POST'])
def add_to_cart():
    time.sleep(random.uniform(0.02, 0.15))
    value = random.uniform(10, 500)
    CART_VALUE.observe(value)
    return jsonify({'status': 'added', 'cart_value': value})

@app.route('/api/order', methods=['POST'])
def create_order():
    time.sleep(random.uniform(0.05, 0.3))
    # Simuler des erreurs occasionnelles
    if random.random() < 0.05:
        ORDERS_TOTAL.labels('failed').inc()
        return jsonify({'error': 'Payment failed'}), 500
    ORDERS_TOTAL.labels('success').inc()
    return jsonify({'order_id': random.randint(1000, 9999)})

@app.route('/api/slow')
def slow_endpoint():
    # Endpoint intentionnellement lent pour les tests
    time.sleep(random.uniform(1, 3))
    return jsonify({'status': 'slow response'})

@app.route('/metrics')
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

```dockerfile
# app/Dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install flask prometheus_client redis psycopg2-binary

COPY app.py .

CMD ["python", "app.py"]
```

### 1.4 Configuration Prometheus

```yaml
# prometheus/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s
  external_labels:
    environment: production
    service: techshop

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['alertmanager:9093']

rule_files:
  - '/etc/prometheus/rules/*.yml'

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']

  - job_name: 'api'
    static_configs:
      - targets: ['api:5000']

  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-exporter:9113']

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

  - job_name: 'blackbox-http'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
          - http://nginx:80/health
          - http://api:5000/health
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

---

## Partie 2 : Règles d'Alerte (20 min)

### 2.1 Alertes Infrastructure

```yaml
# prometheus/rules/infrastructure.yml
groups:
  - name: infrastructure
    rules:
      - alert: InstanceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Instance {{ $labels.instance }} is down"
          description: "{{ $labels.job }} instance {{ $labels.instance }} has been down for more than 1 minute"

      - alert: HighCPU
        expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on {{ $labels.instance }}"
          description: "CPU usage is {{ $value | printf \"%.1f\" }}%"

      - alert: HighMemory
        expr: (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on {{ $labels.instance }}"

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay"} / node_filesystem_size_bytes) * 100 < 15
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space on {{ $labels.instance }}"
          description: "Disk {{ $labels.mountpoint }} has {{ $value | printf \"%.1f\" }}% available"
```

### 2.2 Alertes Application

```yaml
# prometheus/rules/application.yml
groups:
  - name: application
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate(http_requests_total{status=~"5.."}[5m])) by (endpoint)
          /
          sum(rate(http_requests_total[5m])) by (endpoint)
          * 100 > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate on {{ $labels.endpoint }}"
          description: "Error rate is {{ $value | printf \"%.2f\" }}%"

      - alert: HighLatencyP95
        expr: |
          histogram_quantile(0.95,
            sum(rate(http_request_duration_seconds_bucket[5m])) by (le, endpoint)
          ) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High P95 latency on {{ $labels.endpoint }}"
          description: "P95 latency is {{ $value | printf \"%.2f\" }}s"

      - alert: OrderFailureRate
        expr: |
          sum(rate(orders_total{status="failed"}[5m]))
          /
          sum(rate(orders_total[5m]))
          * 100 > 2
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High order failure rate"
          description: "{{ $value | printf \"%.1f\" }}% of orders are failing"

      - alert: HighActiveRequests
        expr: http_requests_active > 50
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Too many active requests"
```

### 2.3 Alertes SLO

```yaml
# prometheus/rules/slo.yml
groups:
  - name: slo
    rules:
      # Recording rules pour SLIs
      - record: sli:availability:ratio_rate5m
        expr: |
          sum(rate(http_requests_total{status!~"5.."}[5m]))
          /
          sum(rate(http_requests_total[5m]))

      - record: sli:latency:ratio_rate5m
        expr: |
          sum(rate(http_request_duration_seconds_bucket{le="0.3"}[5m]))
          /
          sum(rate(http_request_duration_seconds_count[5m]))

      # Alertes SLO
      - alert: SLOAvailabilityBreach
        expr: sli:availability:ratio_rate5m < 0.995
        for: 5m
        labels:
          severity: critical
          slo: availability
        annotations:
          summary: "SLO Availability breach"
          description: "Availability is {{ $value | printf \"%.3f\" }} (target: 99.5%)"

      - alert: SLOLatencyBreach
        expr: sli:latency:ratio_rate5m < 0.95
        for: 5m
        labels:
          severity: warning
          slo: latency
        annotations:
          summary: "SLO Latency breach"
          description: "Only {{ $value | printf \"%.1f\" }}% of requests under 300ms (target: 95%)"
```

---

## Partie 3 : Dashboard Grafana (30 min)

### 3.1 Provisioning Datasource

```yaml
# grafana/provisioning/datasources/datasources.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
```

### 3.2 Dashboard TechShop

Créez un dashboard avec les panels suivants :

![Grafana Dashboard Layout TechShop](../../assets/diagrams/grafana-dashboard-layout-techshop.jpeg)

```
LAYOUT DASHBOARD TECHSHOP
═════════════════════════

Row: Overview
┌──────────┬──────────┬──────────┬──────────┐
│ Uptime   │Requests/s│Error Rate│ P95 Lat  │
│  STAT    │  STAT    │  STAT    │  STAT    │
└──────────┴──────────┴──────────┴──────────┘

Row: Traffic
┌─────────────────────────────────────────────┐
│        Requests per Second (Time Series)    │
│           by endpoint                       │
└─────────────────────────────────────────────┘

Row: Performance
┌─────────────────────┬───────────────────────┐
│ Latency Distribution│ Error Rate by Endpoint│
│     HEATMAP         │     TIME SERIES       │
└─────────────────────┴───────────────────────┘

Row: Business Metrics
┌─────────────────────┬───────────────────────┐
│  Orders/min         │  Cart Value Histogram │
│   TIME SERIES       │     HISTOGRAM         │
└─────────────────────┴───────────────────────┘

Row: Infrastructure
┌──────────┬──────────┬──────────┬──────────┐
│ CPU %    │ Memory % │ Redis Ops│ PG Conn  │
│  GAUGE   │  GAUGE   │  STAT    │  STAT    │
└──────────┴──────────┴──────────┴──────────┘
```

### 3.3 Queries Importantes

```promql
# Requests per second
sum(rate(http_requests_total[5m])) by (endpoint)

# Error rate %
sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) * 100

# P95 Latency
histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))

# Orders per minute
sum(rate(orders_total[1m])) * 60

# Redis operations
rate(redis_commands_total[5m])

# PostgreSQL connections
pg_stat_activity_count{state="active"}
```

---

## Partie 4 : Simulation d'Incidents (30 min)

### 4.1 Test de Charge

```bash
# Installer hey (load testing tool)
# https://github.com/rakyll/hey

# Charge normale
hey -n 1000 -c 10 http://localhost/api/products

# Charge élevée
hey -n 10000 -c 100 http://localhost/api/products

# Test endpoint lent
hey -n 100 -c 20 http://localhost/api/slow
```

### 4.2 Simulation de Pannes

```bash
# Arrêter l'API (déclenche InstanceDown)
docker stop api

# Observer les alertes dans Alertmanager
curl http://localhost:9093/api/v2/alerts | jq .

# Redémarrer
docker start api

# Simuler une surcharge PostgreSQL
docker exec -it postgres psql -U techshop -c "SELECT pg_sleep(10);" &
docker exec -it postgres psql -U techshop -c "SELECT pg_sleep(10);" &
docker exec -it postgres psql -U techshop -c "SELECT pg_sleep(10);" &
```

### 4.3 Checklist de Validation

- [ ] Toutes les targets sont UP dans Prometheus
- [ ] Les métriques de l'API apparaissent
- [ ] Les alertes sont configurées (Status > Rules)
- [ ] Grafana affiche les dashboards
- [ ] Les alertes se déclenchent lors des tests
- [ ] Les notifications arrivent (si configurées)

---

## Partie 5 : SLOs et SLIs

### 5.1 Définition des SLOs

| SLI | SLO | Mesure |
|-----|-----|--------|
| Availability | 99.5% | Requêtes non-5xx / Total |
| Latency P95 | < 300ms | 95% des requêtes sous 300ms |
| Error Rate | < 1% | Erreurs 5xx / Total |

### 5.2 Dashboard SLO

```promql
# Error Budget remaining (%)
100 * (
  1 - (
    (1 - sli:availability:ratio_rate5m) / (1 - 0.995)
  )
)

# Burn rate (1 = normal, >1 = burning fast)
(1 - sli:availability:ratio_rate5m) / (1 - 0.995)

# Time until budget exhaustion (hours)
# Si burn rate constant
(1 - 0.995) * 30 * 24 / (1 - sli:availability:ratio_rate5m)
```

---

## Évaluation

### Critères

| Critère | Points |
|---------|--------|
| Stack déployée et fonctionnelle | 20 |
| Métriques collectées correctement | 20 |
| Règles d'alerte pertinentes | 20 |
| Dashboard complet et lisible | 20 |
| SLOs définis et monitorés | 10 |
| Documentation/Annotations | 10 |

**Total : 100 points**
**Seuil de réussite : 70 points**

---

## Livrables

1. **docker-compose.yml** fonctionnel
2. **prometheus.yml** avec tous les jobs
3. **Règles d'alerte** (3 fichiers minimum)
4. **Dashboard JSON** exporté
5. **Document SLO** avec justifications

---

## Bonus

- Ajouter Loki pour les logs
- Intégrer des traces avec Tempo
- Créer un runbook automatisé
- Configurer des webhooks personnalisés

---

**Précédent :** [Module 5 - Alerting](05-module.md)

**Retour au programme :** [Index](index.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 5 : Alerting et Notifications](05-module.md) | [Programme →](index.md) |

[Retour au Programme](index.md){ .md-button }
