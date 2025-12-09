---
tags:
  - devops
  - loki
  - logging
  - observability
  - grafana
---

# Loki - Logging Stack

Agrégation et requêtes de logs avec Grafana Loki : architecture, déploiement et LogQL.

## Concepts

![Loki Architecture Full Stack](../assets/diagrams/loki-architecture-full-stack.jpeg)

```
ARCHITECTURE LOKI
══════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────────┐
│                     Applications                        │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
│  │  App 1  │  │  App 2  │  │  App 3  │  │  Syslog │    │
│  └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘    │
└───────┼────────────┼────────────┼────────────┼─────────┘
        │            │            │            │
        ▼            ▼            ▼            ▼
┌─────────────────────────────────────────────────────────┐
│                   Agents de Collecte                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Promtail │  │ Fluent   │  │ Vector   │              │
│  │          │  │ Bit      │  │          │              │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘              │
└───────┼─────────────┼─────────────┼────────────────────┘
        │             │             │
        └─────────────┼─────────────┘
                      ▼
┌─────────────────────────────────────────────────────────┐
│                      Loki                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐     │
│  │ Distributor │─►│   Ingester  │─►│    Store    │     │
│  │             │  │             │  │  (S3/GCS/   │     │
│  │             │  │             │  │   Minio)    │     │
│  └─────────────┘  └─────────────┘  └─────────────┘     │
│                          │                              │
│                          ▼                              │
│                   ┌─────────────┐                       │
│                   │   Querier   │                       │
│                   └─────────────┘                       │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   Grafana   │
                    │  (Explore)  │
                    └─────────────┘

Loki vs ELK :
• Loki n'indexe PAS le contenu des logs (seulement les labels)
• Beaucoup moins de ressources (CPU, RAM, stockage)
• Requêtes basées sur les labels + filtrage texte
• Même philosophie que Prometheus (labels, scraping)
```

### Composants

![Loki Components Detailed](../assets/diagrams/loki-components-detailed.jpeg)

```
COMPOSANTS LOKI
══════════════════════════════════════════════════════════

Promtail (Agent) :
  • Collecte les logs locaux
  • Ajoute des labels (job, host, path...)
  • Push vers Loki

Loki (Serveur) :
  • Distributor : reçoit les logs, valide, distribue
  • Ingester : écrit les chunks en mémoire puis stockage
  • Querier : exécute les requêtes LogQL
  • Compactor : optimise le stockage

Grafana :
  • Interface de requête (Explore)
  • Dashboards de logs
  • Alerting sur les logs
```

---

## Installation

### Docker Compose (Dev/Test)

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
      - ./promtail-config.yaml:/etc/promtail/config.yaml
      - /var/log:/var/log:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
    command: -config.file=/etc/promtail/config.yaml

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana

volumes:
  loki-data:
  grafana-data:
```

### Configuration Loki

```yaml
# loki-config.yaml
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  instance_addr: 127.0.0.1
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
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
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

ruler:
  alertmanager_url: http://alertmanager:9093

limits_config:
  reject_old_samples: true
  reject_old_samples_max_age: 168h  # 7 days
  ingestion_rate_mb: 16
  ingestion_burst_size_mb: 32
  max_streams_per_user: 10000
  max_entries_limit_per_query: 5000

chunk_store_config:
  max_look_back_period: 168h  # 7 days

table_manager:
  retention_deletes_enabled: true
  retention_period: 168h  # 7 days
```

### Configuration Promtail

```yaml
# promtail-config.yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

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
          host: ${HOSTNAME}
          __path__: /var/log/*.log

  # Logs syslog
  - job_name: syslog
    static_configs:
      - targets:
          - localhost
        labels:
          job: syslog
          host: ${HOSTNAME}
          __path__: /var/log/syslog

  # Logs Docker containers
  - job_name: docker
    static_configs:
      - targets:
          - localhost
        labels:
          job: docker
          __path__: /var/lib/docker/containers/*/*-json.log
    pipeline_stages:
      - json:
          expressions:
            log: log
            stream: stream
            time: time
      - output:
          source: log

  # Logs d'une application spécifique
  - job_name: myapp
    static_configs:
      - targets:
          - localhost
        labels:
          job: myapp
          env: production
          __path__: /var/log/myapp/*.log
    pipeline_stages:
      - regex:
          expression: '^(?P<timestamp>\S+) (?P<level>\S+) (?P<message>.*)$'
      - labels:
          level:
      - timestamp:
          source: timestamp
          format: RFC3339
```

---

## Déploiement Kubernetes

### Helm Chart

```bash
# Ajouter le repo Grafana
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

# Installer Loki Stack (Loki + Promtail + Grafana)
helm install loki grafana/loki-stack \
  --namespace monitoring \
  --create-namespace \
  --set grafana.enabled=true \
  --set prometheus.enabled=false \
  --set loki.persistence.enabled=true \
  --set loki.persistence.size=50Gi

# Ou Loki seul (mode simple)
helm install loki grafana/loki \
  --namespace monitoring \
  --create-namespace

# Promtail séparé
helm install promtail grafana/promtail \
  --namespace monitoring \
  --set config.lokiAddress=http://loki:3100/loki/api/v1/push
```

### Configuration Helm Avancée

```yaml
# values-loki.yaml
loki:
  auth_enabled: false

  storage:
    type: s3
    s3:
      endpoint: minio.storage:9000
      bucketnames: loki-chunks
      access_key_id: ${MINIO_ACCESS_KEY}
      secret_access_key: ${MINIO_SECRET_KEY}
      s3forcepathstyle: true
      insecure: true

  limits_config:
    retention_period: 720h  # 30 days
    max_streams_per_user: 50000
    max_entries_limit_per_query: 10000

  compactor:
    working_directory: /data/loki/compactor
    shared_store: s3
    retention_enabled: true

persistence:
  enabled: true
  size: 10Gi

resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 2Gi
```

```yaml
# values-promtail.yaml
config:
  lokiAddress: http://loki:3100/loki/api/v1/push

  snippets:
    # Labels additionnels depuis les pods K8s
    pipelineStages:
      - cri: {}
      - labeldrop:
          - filename
      - match:
          selector: '{namespace="production"}'
          stages:
            - json:
                expressions:
                  level: level
                  msg: msg
            - labels:
                level:

  # Scrape tous les pods
  scrapeConfigs: |
    - job_name: kubernetes-pods
      kubernetes_sd_configs:
        - role: pod
      relabel_configs:
        - source_labels: [__meta_kubernetes_pod_label_app]
          target_label: app
        - source_labels: [__meta_kubernetes_namespace]
          target_label: namespace
        - source_labels: [__meta_kubernetes_pod_name]
          target_label: pod
```

---

## LogQL - Langage de Requête

### Syntaxe de Base

```logql
# Sélectionner par labels (obligatoire)
{job="nginx"}
{namespace="production", app="api"}
{host=~"web-.*"}  # Regex

# Filtrer le contenu
{job="nginx"} |= "error"           # Contient "error"
{job="nginx"} != "healthcheck"     # Ne contient pas
{job="nginx"} |~ "error|warning"   # Regex match
{job="nginx"} !~ "debug|trace"     # Regex not match

# Combiner les filtres
{job="nginx"} |= "error" != "404" |~ "timeout|refused"

# Pipeline de parsing
{job="nginx"} | json                           # Parse JSON
{job="nginx"} | logfmt                         # Parse logfmt (key=value)
{job="nginx"} | regexp `(?P<ip>\d+\.\d+\.\d+\.\d+)`  # Regex avec capture
{job="nginx"} | pattern `<ip> - - [<_>] "<method> <uri>"`  # Pattern

# Extraire et filtrer sur les champs parsés
{job="nginx"} | json | level="error"
{job="nginx"} | json | status >= 500
{job="nginx"} | json | duration > 1s
```

### Fonctions d'Agrégation (Metrics from Logs)

```logql
# Compter les lignes
count_over_time({job="nginx"} |= "error" [5m])

# Taux par seconde
rate({job="nginx"} |= "error" [5m])

# Bytes par seconde
bytes_rate({job="nginx"} [5m])

# Agrégation par label
sum(rate({job="nginx"} |= "error" [5m])) by (host)
sum(count_over_time({namespace="production"} |= "error" [1h])) by (app)

# Top 10 des apps avec le plus d'erreurs
topk(10, sum(count_over_time({namespace="production"} |= "error" [1h])) by (app))

# Quantiles (sur valeurs extraites)
{job="nginx"} | json | quantile_over_time(0.95, unwrap duration [5m])

# Moyenne de latence
{job="nginx"} | json | avg_over_time(unwrap response_time [5m]) by (endpoint)
```

### Exemples Pratiques

```logql
# Erreurs 5xx Nginx
{job="nginx"} | json | status >= 500

# Requêtes lentes (> 2s)
{job="api"} | json | response_time > 2

# Erreurs par pod dans les 15 dernières minutes
sum(count_over_time({namespace="production"} |= "ERROR" [15m])) by (pod)

# Logs d'un déploiement spécifique
{namespace="production", app="frontend"} |= "error" | json | line_format "{{.level}} {{.message}}"

# Exceptions Java
{job="java-app"} |~ "Exception|Error" | pattern `<_> <level> <_> - <message>` | level="ERROR"

# Requêtes HTTP groupées par status code
sum by (status) (count_over_time({job="nginx"} | json [1h]))

# Logs avec contexte (5 lignes avant/après) - dans Grafana Explore
{job="myapp"} |= "OutOfMemoryError"
```

---

## Pipeline Stages Promtail

### Parsing Avancé

```yaml
# promtail-config.yaml
scrape_configs:
  - job_name: application
    static_configs:
      - targets: [localhost]
        labels:
          job: myapp
          __path__: /var/log/myapp/*.log
    pipeline_stages:
      # 1. Parser le JSON
      - json:
          expressions:
            timestamp: time
            level: level
            message: msg
            trace_id: trace_id
            user_id: user.id

      # 2. Ajouter des labels depuis les champs parsés
      - labels:
          level:
          trace_id:

      # 3. Modifier le timestamp
      - timestamp:
          source: timestamp
          format: RFC3339Nano

      # 4. Reformater la ligne de log
      - output:
          source: message

      # 5. Filtrer (drop) certains logs
      - match:
          selector: '{job="myapp"}'
          stages:
            - drop:
                expression: "healthcheck"

      # 6. Métriques depuis les logs
      - metrics:
          log_lines_total:
            type: Counter
            description: "Total log lines"
            source: level
            config:
              action: inc
          errors_total:
            type: Counter
            description: "Total errors"
            source: level
            config:
              match_all: true
              action: inc
              match: "error"
```

### Multi-tenant

```yaml
# Promtail avec tenant
clients:
  - url: http://loki:3100/loki/api/v1/push
    tenant_id: team-a

# Ou dynamique depuis un label
pipeline_stages:
  - tenant:
      source: team
```

---

## Alerting

### Ruler (Loki)

```yaml
# alerts.yaml (dans Loki)
groups:
  - name: application-errors
    interval: 1m
    rules:
      - alert: HighErrorRate
        expr: |
          sum(rate({namespace="production"} |= "error" [5m])) by (app) > 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate for {{ $labels.app }}"
          description: "{{ $labels.app }} has more than 10 errors/sec for 5 minutes"

      - alert: NoLogsReceived
        expr: |
          absent_over_time({job="critical-app"}[15m])
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "No logs from critical-app"
          description: "No logs received from critical-app for 15 minutes"
```

### Grafana Alerting

```yaml
# Dans Grafana UI ou provisioning
# Data source: Loki
# Query: sum(count_over_time({job="nginx"} |= "error" [5m]))
# Condition: IS ABOVE 100
# Evaluate every: 1m
# For: 5m
```

---

## Intégration

### Avec Prometheus

```yaml
# Loki comme datasource dans Grafana
# Prometheus pour les métriques, Loki pour les logs

# Corrélation via labels communs
# Prometheus: up{job="nginx", instance="web-1"}
# Loki: {job="nginx", host="web-1"}

# Dans Grafana: Exemplars et liens vers les logs
```

### Avec Tempo (Traces)

```yaml
# Correlation traces <-> logs via trace_id
# Promtail extrait le trace_id
pipeline_stages:
  - json:
      expressions:
        trace_id: traceId
  - labels:
      trace_id:

# Grafana: Derived fields dans Loki datasource
# Regex: traceID=(\w+)
# URL: http://tempo:3200/api/traces/${__value.raw}
```

---

## Bonnes Pratiques

```yaml
Checklist Loki:
  Labels:
    - [ ] Peu de labels (< 15 par stream)
    - [ ] Labels à faible cardinalité
    - [ ] Pas de valeurs dynamiques (user_id, request_id)
    - [ ] Labels utiles pour le filtrage

  Performance:
    - [ ] Filtrer par labels AVANT le texte
    - [ ] Limiter la plage de temps des requêtes
    - [ ] Utiliser le cache de requêtes
    - [ ] Activer la rétention automatique

  Opérations:
    - [ ] Monitoring de Loki lui-même
    - [ ] Alertes sur ingestion rate
    - [ ] Backup du stockage
    - [ ] Plan de rétention défini

  Sécurité:
    - [ ] Multi-tenant si multi-équipes
    - [ ] Auth sur l'API Loki
    - [ ] Pas de données sensibles dans les logs
```

### Labels : À Faire / À Éviter

```
✅ BONS LABELS (faible cardinalité):
  job: nginx
  env: production
  namespace: frontend
  level: error
  region: eu-west-1

❌ MAUVAIS LABELS (haute cardinalité):
  user_id: 12345           # Millions de valeurs
  request_id: abc-123      # Unique par requête
  timestamp: 1234567890    # Change tout le temps
  message: "..."           # Contenu du log
```

---

**Voir aussi :**

- [Observability Stack](observability-stack.md) - Prometheus & Grafana
- [Observability Advanced](observability-advanced.md) - Monitoring avancé
- [Kubernetes Survival](kubernetes-survival.md) - Logs K8s
