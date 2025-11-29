---
tags:
  - formation
  - observability
  - prometheus
  - exporters
  - instrumentation
---

# Module 3 : Exporters et Instrumentation

## Objectifs du Module

- Déployer et configurer les exporters essentiels
- Instrumenter des applications dans différents langages
- Utiliser le Pushgateway pour les jobs batch
- Créer des exporters personnalisés

**Durée :** 3 heures

---

## 1. Vue d'Ensemble des Exporters

### 1.1 Écosystème

```
ÉCOSYSTÈME DES EXPORTERS
════════════════════════

INFRASTRUCTURE                    BASES DE DONNÉES
─────────────────                 ────────────────
┌─────────────────┐               ┌─────────────────┐
│ Node Exporter   │               │ MySQL Exporter  │
│ (Linux/Windows) │               │ PostgreSQL Exp. │
│ cAdvisor        │               │ MongoDB Exp.    │
│ SNMP Exporter   │               │ Redis Exporter  │
└─────────────────┘               └─────────────────┘

APPLICATIONS                      MESSAGING
────────────                      ─────────
┌─────────────────┐               ┌─────────────────┐
│ Blackbox Exp.   │               │ Kafka Exporter  │
│ JMX Exporter    │               │ RabbitMQ Exp.   │
│ Nginx Exporter  │               │ NATS Exporter   │
│ Apache Exporter │               └─────────────────┘
└─────────────────┘

CLOUD                             CUSTOM
─────                             ──────
┌─────────────────┐               ┌─────────────────┐
│ AWS CloudWatch  │               │ Pushgateway     │
│ Azure Monitor   │               │ Script Exporter │
│ GCP Stackdriver │               │ Custom Exporter │
└─────────────────┘               └─────────────────┘
```

### 1.2 Ports Standards

| Exporter | Port | Endpoint |
|----------|------|----------|
| Node Exporter | 9100 | /metrics |
| Blackbox | 9115 | /probe |
| MySQL | 9104 | /metrics |
| PostgreSQL | 9187 | /metrics |
| Redis | 9121 | /metrics |
| Nginx | 9113 | /metrics |
| Pushgateway | 9091 | /metrics |

---

## 2. Node Exporter

### 2.1 Installation

```bash
# Docker
docker run -d \
  --name node-exporter \
  --net="host" \
  --pid="host" \
  -v "/:/host:ro,rslave" \
  prom/node-exporter:latest \
  --path.rootfs=/host

# Binaire
VERSION="1.6.1"
wget https://github.com/prometheus/node_exporter/releases/download/v${VERSION}/node_exporter-${VERSION}.linux-amd64.tar.gz
tar xvfz node_exporter-${VERSION}.linux-amd64.tar.gz
sudo cp node_exporter-${VERSION}.linux-amd64/node_exporter /usr/local/bin/
```

### 2.2 Service Systemd

```ini
# /etc/systemd/system/node_exporter.service
[Unit]
Description=Node Exporter
Documentation=https://prometheus.io/docs/guides/node-exporter/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=node_exporter
Group=node_exporter
ExecStart=/usr/local/bin/node_exporter \
    --collector.systemd \
    --collector.processes \
    --web.listen-address=:9100 \
    --web.telemetry-path=/metrics

Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 2.3 Collectors Disponibles

```bash
# Lister les collectors activés
node_exporter --help | grep collector

# Collectors par défaut activés
# cpu, diskstats, filesystem, loadavg, meminfo, netdev, etc.

# Collectors désactivés par défaut (à activer si besoin)
--collector.systemd          # Services systemd
--collector.processes        # Processus
--collector.tcpstat          # Statistiques TCP
--collector.wifi             # WiFi
--collector.ntp              # NTP offset

# Désactiver un collector
--no-collector.wifi

# Exemple complet
/usr/local/bin/node_exporter \
  --collector.systemd \
  --collector.processes \
  --no-collector.wifi \
  --no-collector.infiniband
```

### 2.4 Métriques Clés

```promql
# CPU
node_cpu_seconds_total{mode="idle"}
100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Mémoire
node_memory_MemTotal_bytes
node_memory_MemAvailable_bytes
node_memory_MemFree_bytes
node_memory_Cached_bytes
node_memory_Buffers_bytes

# Disque
node_filesystem_size_bytes
node_filesystem_avail_bytes
node_disk_read_bytes_total
node_disk_written_bytes_total

# Réseau
node_network_receive_bytes_total
node_network_transmit_bytes_total

# Système
node_load1, node_load5, node_load15
node_boot_time_seconds
node_uname_info
```

---

## 3. Blackbox Exporter

### 3.1 Concept

```
BLACKBOX EXPORTER - PROBES EXTERNES
═══════════════════════════════════

                ┌─────────────────┐
                │   Prometheus    │
                │                 │
                │ /probe?target=  │
                │   example.com   │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │    Blackbox     │
                │    Exporter     │
                │                 │
                │  HTTP │ TCP     │
                │  ICMP │ DNS     │
                │  GRPC           │
                └────────┬────────┘
                         │
           ┌─────────────┼─────────────┐
           ▼             ▼             ▼
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │ Website  │  │   API    │  │   DNS    │
    │          │  │          │  │  Server  │
    └──────────┘  └──────────┘  └──────────┘
```

### 3.2 Configuration

```yaml
# blackbox.yml
modules:
  http_2xx:
    prober: http
    timeout: 5s
    http:
      valid_http_versions: ["HTTP/1.1", "HTTP/2.0"]
      valid_status_codes: []  # Accepte 2xx par défaut
      method: GET
      follow_redirects: true
      fail_if_ssl: false
      fail_if_not_ssl: false

  http_post_2xx:
    prober: http
    timeout: 5s
    http:
      method: POST
      headers:
        Content-Type: application/json
      body: '{"test": "data"}'

  https_2xx:
    prober: http
    timeout: 5s
    http:
      valid_status_codes: [200, 201, 204]
      fail_if_not_ssl: true
      tls_config:
        insecure_skip_verify: false

  tcp_connect:
    prober: tcp
    timeout: 5s

  tcp_connect_tls:
    prober: tcp
    timeout: 5s
    tcp:
      tls: true

  icmp:
    prober: icmp
    timeout: 5s
    icmp:
      preferred_ip_protocol: ip4

  dns_lookup:
    prober: dns
    timeout: 5s
    dns:
      query_name: example.com
      query_type: A
      valid_rcodes:
        - NOERROR
```

### 3.3 Configuration Prometheus

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'blackbox-http'
    metrics_path: /probe
    params:
      module: [http_2xx]
    static_configs:
      - targets:
          - https://example.com
          - https://api.example.com/health
          - https://www.google.com
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115

  - job_name: 'blackbox-tcp'
    metrics_path: /probe
    params:
      module: [tcp_connect]
    static_configs:
      - targets:
          - db.example.com:5432
          - redis.example.com:6379
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115

  - job_name: 'blackbox-icmp'
    metrics_path: /probe
    params:
      module: [icmp]
    static_configs:
      - targets:
          - 8.8.8.8
          - 1.1.1.1
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: blackbox-exporter:9115
```

### 3.4 Métriques Blackbox

```promql
# Disponibilité
probe_success

# Durée totale de la probe
probe_duration_seconds

# Expiration certificat SSL
probe_ssl_earliest_cert_expiry - time()
# En jours
(probe_ssl_earliest_cert_expiry - time()) / 86400

# Code HTTP
probe_http_status_code

# Version HTTP
probe_http_version

# DNS lookup time
probe_dns_lookup_time_seconds

# Phases HTTP détaillées
probe_http_duration_seconds{phase="connect"}
probe_http_duration_seconds{phase="processing"}
probe_http_duration_seconds{phase="tls"}
probe_http_duration_seconds{phase="transfer"}
```

---

## 4. Instrumentation d'Applications

### 4.1 Python (prometheus_client)

```python
# app.py
from prometheus_client import Counter, Histogram, Gauge, start_http_server
import time
import random

# Définir les métriques
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP Requests',
    ['method', 'endpoint', 'status']
)

REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP Request Duration',
    ['method', 'endpoint'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

ACTIVE_REQUESTS = Gauge(
    'http_requests_active',
    'Active HTTP Requests'
)

# Décorateur pour mesurer les requêtes
def track_request(method, endpoint):
    def decorator(func):
        def wrapper(*args, **kwargs):
            ACTIVE_REQUESTS.inc()
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                REQUEST_COUNT.labels(method, endpoint, '200').inc()
                return result
            except Exception as e:
                REQUEST_COUNT.labels(method, endpoint, '500').inc()
                raise
            finally:
                REQUEST_LATENCY.labels(method, endpoint).observe(time.time() - start_time)
                ACTIVE_REQUESTS.dec()
        return wrapper
    return decorator

# Exemple d'utilisation
@track_request('GET', '/api/users')
def get_users():
    time.sleep(random.uniform(0.01, 0.5))
    return [{"id": 1, "name": "John"}]

if __name__ == '__main__':
    # Démarrer le serveur de métriques sur port 8000
    start_http_server(8000)

    # Simuler des requêtes
    while True:
        get_users()
        time.sleep(random.uniform(0.1, 1))
```

### 4.2 Go (promhttp)

```go
// main.go
package main

import (
    "math/rand"
    "net/http"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    requestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "http_requests_total",
            Help: "Total number of HTTP requests",
        },
        []string{"method", "endpoint", "status"},
    )

    requestDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "http_request_duration_seconds",
            Help:    "HTTP request duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"method", "endpoint"},
    )

    activeRequests = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "http_requests_active",
            Help: "Number of active HTTP requests",
        },
    )
)

func instrumentHandler(method, endpoint string, handler http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        activeRequests.Inc()
        defer activeRequests.Dec()

        start := time.Now()

        // Wrapper pour capturer le status code
        wrapper := &responseWrapper{ResponseWriter: w, status: 200}
        handler(wrapper, r)

        duration := time.Since(start).Seconds()
        requestDuration.WithLabelValues(method, endpoint).Observe(duration)
        requestsTotal.WithLabelValues(method, endpoint, http.StatusText(wrapper.status)).Inc()
    }
}

type responseWrapper struct {
    http.ResponseWriter
    status int
}

func (w *responseWrapper) WriteHeader(status int) {
    w.status = status
    w.ResponseWriter.WriteHeader(status)
}

func main() {
    http.Handle("/metrics", promhttp.Handler())
    http.HandleFunc("/api/users", instrumentHandler("GET", "/api/users", func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(time.Duration(rand.Intn(500)) * time.Millisecond)
        w.Write([]byte(`{"users": []}`))
    }))

    http.ListenAndServe(":8080", nil)
}
```

### 4.3 Java (Micrometer)

```java
// Application.java
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import io.micrometer.prometheus.PrometheusConfig;
import io.micrometer.prometheus.PrometheusMeterRegistry;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public class Application {
    private static PrometheusMeterRegistry registry;
    private static Counter requestCounter;
    private static Timer requestTimer;

    public static void main(String[] args) throws Exception {
        // Initialiser le registry
        registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);

        // Créer les métriques
        requestCounter = Counter.builder("http_requests_total")
            .tag("method", "GET")
            .tag("endpoint", "/api/users")
            .register(registry);

        requestTimer = Timer.builder("http_request_duration_seconds")
            .tag("method", "GET")
            .tag("endpoint", "/api/users")
            .publishPercentiles(0.5, 0.95, 0.99)
            .register(registry);

        // Endpoint metrics
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/metrics", exchange -> {
            String response = registry.scrape();
            exchange.sendResponseHeaders(200, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        });

        // API endpoint
        server.createContext("/api/users", exchange -> {
            Timer.Sample sample = Timer.start(registry);
            try {
                Thread.sleep((long) (Math.random() * 500));
                requestCounter.increment();
                String response = "{\"users\": []}";
                exchange.sendResponseHeaders(200, response.length());
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(response.getBytes());
                }
            } finally {
                sample.stop(requestTimer);
            }
        });

        server.start();
    }
}
```

### 4.4 Spring Boot (Actuator)

```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: health,info,prometheus
  endpoint:
    prometheus:
      enabled: true
  metrics:
    tags:
      application: ${spring.application.name}
    export:
      prometheus:
        enabled: true
```

```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-registry-prometheus</artifactId>
</dependency>
```

---

## 5. Pushgateway

### 5.1 Cas d'Usage

```
PUSHGATEWAY - JOBS BATCH ET ÉPHÉMÈRES
═════════════════════════════════════

Problème: Prometheus pull, mais certains jobs...
─────────────────────────────────────────────────
  • Sont trop courts (durée < scrape_interval)
  • N'ont pas de endpoint HTTP persistant
  • Sont des jobs batch/cron

Solution: Pushgateway comme intermédiaire
─────────────────────────────────────────

┌─────────────┐    push     ┌─────────────┐    pull    ┌─────────────┐
│  Job Batch  │ ─────────▶  │ Pushgateway │ ◀───────── │ Prometheus  │
│  (court)    │             │  (persist)  │            │             │
└─────────────┘             └─────────────┘            └─────────────┘

⚠️ ATTENTION: Pushgateway ne remplace pas le modèle pull
              À utiliser uniquement pour les cas spécifiques
```

### 5.2 Installation et Configuration

```yaml
# docker-compose.yml
pushgateway:
  image: prom/pushgateway:latest
  container_name: pushgateway
  ports:
    - "9091:9091"
  command:
    - '--persistence.file=/data/metrics'
    - '--persistence.interval=5m'
  volumes:
    - pushgateway_data:/data
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'pushgateway'
    honor_labels: true  # Important: garder les labels du push
    static_configs:
      - targets: ['pushgateway:9091']
```

### 5.3 Push des Métriques

```bash
# Push simple avec curl
echo "backup_last_success_timestamp $(date +%s)" | \
  curl --data-binary @- http://pushgateway:9091/metrics/job/backup

# Push avec labels
cat <<EOF | curl --data-binary @- http://pushgateway:9091/metrics/job/backup/instance/server1
backup_last_success_timestamp $(date +%s)
backup_duration_seconds 542
backup_size_bytes 1073741824
EOF

# Push depuis Python
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

registry = CollectorRegistry()
g = Gauge('job_last_success_timestamp', 'Last successful job', registry=registry)
g.set_to_current_time()

push_to_gateway('pushgateway:9091', job='backup', registry=registry)

# Supprimer des métriques
curl -X DELETE http://pushgateway:9091/metrics/job/backup/instance/server1
```

### 5.4 Script Batch avec Push

```bash
#!/bin/bash
# backup-with-metrics.sh

PUSHGATEWAY="pushgateway:9091"
JOB="backup"
INSTANCE=$(hostname)

START_TIME=$(date +%s)

# Exécuter le backup
if /usr/local/bin/backup.sh; then
    STATUS=1
else
    STATUS=0
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
SIZE=$(du -sb /backup/latest | cut -f1)

# Push les métriques
cat <<EOF | curl --data-binary @- "http://${PUSHGATEWAY}/metrics/job/${JOB}/instance/${INSTANCE}"
# HELP backup_success Whether the backup succeeded
# TYPE backup_success gauge
backup_success ${STATUS}
# HELP backup_duration_seconds Duration of the backup
# TYPE backup_duration_seconds gauge
backup_duration_seconds ${DURATION}
# HELP backup_size_bytes Size of the backup
# TYPE backup_size_bytes gauge
backup_size_bytes ${SIZE}
# HELP backup_last_run_timestamp Timestamp of the last backup
# TYPE backup_last_run_timestamp gauge
backup_last_run_timestamp ${END_TIME}
EOF
```

---

## 6. Autres Exporters Courants

### 6.1 MySQL Exporter

```bash
# Installation
docker run -d \
  --name mysql-exporter \
  -p 9104:9104 \
  -e DATA_SOURCE_NAME="exporter:password@(mysql:3306)/" \
  prom/mysqld-exporter
```

```sql
-- Créer l'utilisateur MySQL pour l'exporter
CREATE USER 'exporter'@'%' IDENTIFIED BY 'password';
GRANT PROCESS, REPLICATION CLIENT, SELECT ON *.* TO 'exporter'@'%';
FLUSH PRIVILEGES;
```

### 6.2 PostgreSQL Exporter

```bash
docker run -d \
  --name postgres-exporter \
  -p 9187:9187 \
  -e DATA_SOURCE_NAME="postgresql://postgres:password@postgres:5432/postgres?sslmode=disable" \
  prometheuscommunity/postgres-exporter
```

### 6.3 Redis Exporter

```bash
docker run -d \
  --name redis-exporter \
  -p 9121:9121 \
  oliver006/redis_exporter \
  --redis.addr redis://redis:6379
```

---

## 7. Exercice Pratique

### Tâches

1. Déployer Node Exporter avec collectors personnalisés
2. Configurer Blackbox pour monitorer 3 endpoints
3. Instrumenter une application Python
4. Configurer Pushgateway pour un job batch

### Docker Compose Complet

```yaml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  node-exporter:
    image: prom/node-exporter:latest
    ports:
      - "9100:9100"

  blackbox-exporter:
    image: prom/blackbox-exporter:latest
    ports:
      - "9115:9115"
    volumes:
      - ./blackbox.yml:/etc/blackbox_exporter/config.yml

  pushgateway:
    image: prom/pushgateway:latest
    ports:
      - "9091:9091"

  python-app:
    build: ./python-app
    ports:
      - "8000:8000"
```

---

## Quiz

1. **Quel exporter pour monitorer les systèmes Linux ?**
   - [ ] A. Blackbox Exporter
   - [ ] B. Node Exporter
   - [ ] C. SNMP Exporter

2. **Quand utiliser le Pushgateway ?**
   - [ ] A. Pour toutes les applications
   - [ ] B. Pour les jobs batch courts
   - [ ] C. Pour les bases de données

3. **Quelle métrique Blackbox pour vérifier la validité SSL ?**
   - [ ] A. probe_success
   - [ ] B. probe_ssl_earliest_cert_expiry
   - [ ] C. probe_http_status_code

**Réponses :** 1-B, 2-B, 3-B

---

**Précédent :** [Module 2 - Prometheus Configuration](02-module.md)

**Suivant :** [Module 4 - Grafana Dashboards](04-module.md)
