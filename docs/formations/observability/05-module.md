---
tags:
  - formation
  - observability
  - alertmanager
  - alerting
  - notifications
---

# Module 5 : Alerting et Notifications

## Objectifs du Module

- Configurer Alertmanager
- Créer des règles d'alerte Prometheus
- Implémenter le routage et le silencing
- Intégrer les canaux de notification
- Appliquer les bonnes pratiques d'alerting

**Durée :** 2 heures

---

## 1. Architecture de l'Alerting

### 1.1 Vue d'Ensemble

```
FLUX D'ALERTING PROMETHEUS
══════════════════════════

┌─────────────────────────────────────────────────────────────┐
│                        PROMETHEUS                            │
│                                                              │
│  ┌────────────────┐      ┌────────────────┐                │
│  │  Règles        │      │  Évaluation    │                │
│  │  d'Alerte      │ ───▶ │  périodique    │                │
│  │  (YAML)        │      │  (15s/1m)      │                │
│  └────────────────┘      └────────┬───────┘                │
│                                   │                         │
│                          ┌────────▼───────┐                │
│                          │  Alerte        │                │
│                          │  pending/firing│                │
│                          └────────┬───────┘                │
└───────────────────────────────────┼─────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────┐
│                      ALERTMANAGER                            │
│                                                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐            │
│  │ Grouping   │─▶│  Routing   │─▶│ Silencing  │            │
│  │            │  │            │  │ Inhibition │            │
│  └────────────┘  └────────────┘  └─────┬──────┘            │
│                                        │                    │
│                              ┌─────────▼─────────┐         │
│                              │   Notifications   │         │
│                              └───────────────────┘         │
└─────────────────────────────────────────────────────────────┘
                                    │
           ┌────────────────────────┼────────────────────────┐
           ▼                        ▼                        ▼
    ┌─────────────┐          ┌─────────────┐          ┌─────────────┐
    │    Slack    │          │   Email     │          │  PagerDuty  │
    └─────────────┘          └─────────────┘          └─────────────┘
```

### 1.2 États des Alertes

```
CYCLE DE VIE D'UNE ALERTE
═════════════════════════

                    Condition fausse
    ┌──────────────────────────────────────────┐
    │                                          │
    ▼                                          │
┌─────────┐    Condition vraie    ┌─────────┐  │   Durée 'for' atteinte   ┌─────────┐
│ INACTIVE│ ────────────────────▶ │ PENDING │──┼─────────────────────────▶│ FIRING  │
└─────────┘                       └─────────┘  │                          └─────────┘
                                      │        │                               │
                                      │        │                               │
                                      └────────┘                               │
                                  Condition fausse                             │
                                                                              │
                                                   Condition fausse            │
                                  ┌────────────────────────────────────────────┘
                                  │
                                  ▼
                              ┌─────────┐
                              │RESOLVED │
                              └─────────┘
```

---

## 2. Règles d'Alerte Prometheus

### 2.1 Syntaxe de Base

```yaml
# /etc/prometheus/rules/alerts.yml
groups:
  - name: infrastructure
    interval: 30s  # Évaluation toutes les 30s (optionnel)
    rules:
      # Alerte simple
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
          team: infrastructure
        annotations:
          summary: "High CPU usage on {{ $labels.instance }}"
          description: "CPU usage is {{ $value | printf \"%.1f\" }}% on {{ $labels.instance }}"

      # Alerte avec plusieurs seuils
      - alert: HighMemoryUsage
        expr: (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Memory usage above 85% on {{ $labels.instance }}"
          description: "Memory usage: {{ $value | printf \"%.1f\" }}%"

      - alert: CriticalMemoryUsage
        expr: (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 95
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Critical memory usage on {{ $labels.instance }}"
          description: "Memory usage: {{ $value | printf \"%.1f\" }}%"
```

### 2.2 Alertes d'Infrastructure

```yaml
groups:
  - name: node-exporter
    rules:
      # Instance down
      - alert: InstanceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Instance {{ $labels.instance }} down"
          description: "{{ $labels.job }} instance {{ $labels.instance }} has been down for more than 1 minute"

      # Disque
      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 15
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space on {{ $labels.instance }}"
          description: "Disk {{ $labels.mountpoint }} has {{ $value | printf \"%.1f\" }}% available"

      - alert: DiskSpaceCritical
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 5
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Critical disk space on {{ $labels.instance }}"
          description: "Disk {{ $labels.mountpoint }} has only {{ $value | printf \"%.1f\" }}% available"

      # Load
      - alert: HighSystemLoad
        expr: node_load15 > count(node_cpu_seconds_total{mode="idle"}) by (instance)
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "High system load on {{ $labels.instance }}"
          description: "15-minute load average is {{ $value }}"

      # Swap
      - alert: HighSwapUsage
        expr: (1 - node_memory_SwapFree_bytes / node_memory_SwapTotal_bytes) * 100 > 50
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High swap usage on {{ $labels.instance }}"

      # Network errors
      - alert: NetworkErrors
        expr: rate(node_network_receive_errs_total[5m]) > 0 or rate(node_network_transmit_errs_total[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Network errors on {{ $labels.instance }}"
```

### 2.3 Alertes Applicatives

```yaml
groups:
  - name: application
    rules:
      # Taux d'erreur HTTP
      - alert: HighHTTPErrorRate
        expr: |
          sum(rate(http_requests_total{status=~"5.."}[5m])) by (service)
          /
          sum(rate(http_requests_total[5m])) by (service)
          * 100 > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High HTTP error rate for {{ $labels.service }}"
          description: "Error rate is {{ $value | printf \"%.1f\" }}%"

      # Latence P95
      - alert: HighLatencyP95
        expr: |
          histogram_quantile(0.95,
            sum(rate(http_request_duration_seconds_bucket[5m])) by (le, service)
          ) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High P95 latency for {{ $labels.service }}"
          description: "P95 latency is {{ $value | printf \"%.2f\" }}s"

      # Saturation (queue depth)
      - alert: HighQueueDepth
        expr: avg_over_time(queue_depth[5m]) > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High queue depth"
```

### 2.4 Alertes Blackbox

```yaml
groups:
  - name: blackbox
    rules:
      - alert: EndpointDown
        expr: probe_success == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Endpoint {{ $labels.instance }} is down"
          description: "Probe failed for {{ $labels.instance }}"

      - alert: SSLCertExpiringSoon
        expr: (probe_ssl_earliest_cert_expiry - time()) / 86400 < 30
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "SSL certificate expiring soon"
          description: "Certificate for {{ $labels.instance }} expires in {{ $value | printf \"%.0f\" }} days"

      - alert: SSLCertExpiryCritical
        expr: (probe_ssl_earliest_cert_expiry - time()) / 86400 < 7
        for: 1h
        labels:
          severity: critical
        annotations:
          summary: "SSL certificate expiring very soon!"
          description: "Certificate for {{ $labels.instance }} expires in {{ $value | printf \"%.0f\" }} days"

      - alert: SlowResponse
        expr: probe_duration_seconds > 3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Slow response from {{ $labels.instance }}"
          description: "Response time is {{ $value | printf \"%.2f\" }}s"
```

---

## 3. Configuration Alertmanager

### 3.1 Structure de Base

```yaml
# alertmanager.yml
global:
  # Configuration globale
  resolve_timeout: 5m
  smtp_smarthost: 'smtp.example.com:587'
  smtp_from: 'alertmanager@example.com'
  smtp_auth_username: 'alertmanager'
  smtp_auth_password: 'password'

  # Slack global
  slack_api_url: 'https://hooks.slack.com/services/XXX/YYY/ZZZ'

# Templates personnalisés
templates:
  - '/etc/alertmanager/templates/*.tmpl'

# Arbre de routage
route:
  # Route par défaut
  receiver: 'default-receiver'
  group_by: ['alertname', 'severity']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h

  # Routes enfants
  routes:
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
      continue: true

    - match:
        team: infrastructure
      receiver: 'slack-infra'

    - match_re:
        service: (api|web)
      receiver: 'slack-backend'

# Inhibitions
inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']

# Receivers
receivers:
  - name: 'default-receiver'
    email_configs:
      - to: 'alerts@example.com'

  - name: 'slack-infra'
    slack_configs:
      - channel: '#alerts-infra'
        send_resolved: true

  - name: 'pagerduty-critical'
    pagerduty_configs:
      - service_key: 'your-pagerduty-key'
```

### 3.2 Routage Avancé

```yaml
route:
  receiver: 'default'
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 12h

  routes:
    # Alertes critiques -> PagerDuty + Slack
    - match:
        severity: critical
      receiver: 'pagerduty-critical'
      routes:
        - match:
            env: production
          receiver: 'pagerduty-prod'
          continue: true
        - receiver: 'slack-critical'

    # Par équipe
    - match:
        team: platform
      receiver: 'slack-platform'
      routes:
        - match:
            severity: critical
          receiver: 'pagerduty-platform'

    - match:
        team: backend
      receiver: 'slack-backend'

    # Par environnement
    - match:
        env: staging
      receiver: 'slack-staging'
      group_wait: 1m
      repeat_interval: 1h

    # Heures de bureau uniquement
    - match:
        severity: warning
      receiver: 'email-team'
      active_time_intervals:
        - business-hours

# Time intervals
time_intervals:
  - name: business-hours
    time_intervals:
      - weekdays: ['monday:friday']
        times:
          - start_time: '09:00'
            end_time: '18:00'
```

### 3.3 Receivers Détaillés

```yaml
receivers:
  # Email
  - name: 'email-team'
    email_configs:
      - to: 'team@example.com'
        send_resolved: true
        html: '{{ template "email.html" . }}'
        headers:
          Subject: '[{{ .Status | toUpper }}] {{ .GroupLabels.alertname }}'

  # Slack
  - name: 'slack-alerts'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/XXX/YYY/ZZZ'
        channel: '#alerts'
        send_resolved: true
        username: 'Alertmanager'
        icon_emoji: ':warning:'
        title: '{{ if eq .Status "firing" }}:fire:{{ else }}:white_check_mark:{{ end }} {{ .GroupLabels.alertname }}'
        text: |-
          {{ range .Alerts }}
          *Alert:* {{ .Annotations.summary }}
          *Severity:* {{ .Labels.severity }}
          *Instance:* {{ .Labels.instance }}
          *Description:* {{ .Annotations.description }}
          {{ end }}
        actions:
          - type: button
            text: 'Runbook'
            url: '{{ (index .Alerts 0).Annotations.runbook_url }}'
          - type: button
            text: 'Dashboard'
            url: 'https://grafana.example.com/d/xxx'

  # PagerDuty
  - name: 'pagerduty-critical'
    pagerduty_configs:
      - routing_key: 'your-routing-key'
        severity: '{{ .CommonLabels.severity }}'
        description: '{{ .CommonAnnotations.summary }}'
        details:
          firing: '{{ template "pagerduty.default.instances" .Alerts.Firing }}'
          resolved: '{{ template "pagerduty.default.instances" .Alerts.Resolved }}'

  # Microsoft Teams
  - name: 'teams-alerts'
    webhook_configs:
      - url: 'https://outlook.office.com/webhook/xxx'
        send_resolved: true

  # Opsgenie
  - name: 'opsgenie-critical'
    opsgenie_configs:
      - api_key: 'your-api-key'
        message: '{{ .CommonAnnotations.summary }}'
        priority: '{{ if eq .CommonLabels.severity "critical" }}P1{{ else }}P3{{ end }}'

  # Webhook générique
  - name: 'webhook-custom'
    webhook_configs:
      - url: 'https://api.example.com/alerts'
        send_resolved: true
        http_config:
          bearer_token: 'your-token'
```

---

## 4. Silencing et Inhibition

### 4.1 Silences via API

```bash
# Créer un silence via amtool
amtool silence add alertname="HighCPUUsage" instance="server1:9100" \
  --comment="Maintenance planned" \
  --author="admin" \
  --duration="2h"

# Créer un silence via API
curl -X POST http://alertmanager:9093/api/v2/silences \
  -H "Content-Type: application/json" \
  -d '{
    "matchers": [
      {"name": "alertname", "value": "HighCPUUsage", "isRegex": false},
      {"name": "instance", "value": "server1.*", "isRegex": true}
    ],
    "startsAt": "2024-01-15T10:00:00Z",
    "endsAt": "2024-01-15T12:00:00Z",
    "createdBy": "admin",
    "comment": "Planned maintenance"
  }'

# Lister les silences
amtool silence query
curl http://alertmanager:9093/api/v2/silences

# Supprimer un silence
amtool silence expire <silence-id>
curl -X DELETE http://alertmanager:9093/api/v2/silence/<silence-id>
```

### 4.2 Inhibition Rules

```yaml
# alertmanager.yml
inhibit_rules:
  # Critical inhibe Warning pour la même alerte
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']

  # InstanceDown inhibe toutes les autres alertes de cette instance
  - source_match:
      alertname: 'InstanceDown'
    target_match_re:
      alertname: '.+'
    equal: ['instance']

  # Cluster down inhibe les alertes de nodes
  - source_match:
      alertname: 'ClusterDown'
    target_match_re:
      alertname: 'Node.*'
    equal: ['cluster']

  # Maintenance mode
  - source_match:
      alertname: 'MaintenanceMode'
    target_match_re:
      severity: '(warning|critical)'
    equal: ['instance']
```

---

## 5. Bonnes Pratiques

### 5.1 Design des Alertes

```
BONNES PRATIQUES ALERTING
═════════════════════════

1. ACTIONABLE
─────────────────────────────────────────────
✓ Chaque alerte doit avoir une action claire
✓ Inclure un runbook_url dans les annotations
✗ Éviter les alertes "pour information"

2. SYMPTÔMES vs CAUSES
─────────────────────────────────────────────
✓ Alerter sur les symptômes (latence, erreurs)
✗ Éviter d'alerter sur les causes (CPU, RAM)
   sauf si vraiment critique

3. SEUILS APPROPRIÉS
─────────────────────────────────────────────
✓ Basés sur les SLOs/SLAs
✓ Utiliser le 'for' pour éviter le flapping
✗ Éviter les seuils arbitraires

4. FATIGUE D'ALERTE
─────────────────────────────────────────────
✓ Réduire le bruit au maximum
✓ Grouper les alertes similaires
✓ Utiliser les inhibitions
✗ Ne pas ignorer les alertes récurrentes

5. DOCUMENTATION
─────────────────────────────────────────────
✓ Annotations claires (summary, description)
✓ Runbooks à jour
✓ Labels cohérents (severity, team, service)
```

### 5.2 Template d'Alerte

```yaml
- alert: ServiceHighErrorRate
  # Expression claire et commentée
  expr: |
    # Taux d'erreur 5xx sur 5 minutes
    sum(rate(http_requests_total{status=~"5.."}[5m])) by (service)
    /
    sum(rate(http_requests_total[5m])) by (service)
    * 100 > 1  # Seuil: 1% d'erreurs
  # Durée avant firing (évite flapping)
  for: 5m
  # Labels pour routage et filtrage
  labels:
    severity: warning
    team: backend
    slo: availability
  # Annotations pour contexte humain
  annotations:
    summary: "High error rate for {{ $labels.service }}"
    description: |
      Error rate is {{ $value | printf "%.2f" }}% for service {{ $labels.service }}.
      This exceeds the 1% threshold for 5 minutes.
    runbook_url: "https://wiki.example.com/runbooks/high-error-rate"
    dashboard_url: "https://grafana.example.com/d/service-overview?var-service={{ $labels.service }}"
```

### 5.3 SLO-Based Alerting

```yaml
groups:
  - name: slo-alerts
    rules:
      # Error budget burn rate
      - alert: ErrorBudgetBurn
        expr: |
          # Burn rate sur 1h
          (
            sum(rate(http_requests_total{status=~"5.."}[1h])) by (service)
            /
            sum(rate(http_requests_total[1h])) by (service)
          ) > (1 - 0.999) * 14.4  # 14.4x = consume budget en 5 jours
        for: 5m
        labels:
          severity: warning
          type: error-budget
        annotations:
          summary: "Error budget burning fast for {{ $labels.service }}"

      # Multi-window, multi-burn-rate
      - alert: SLOViolation
        expr: |
          # Fast burn (1h window, 14.4x burn rate)
          (
            sum(rate(http_requests_total{status=~"5.."}[1h])) by (service)
            /
            sum(rate(http_requests_total[1h])) by (service)
            > 14.4 * (1 - 0.999)
          )
          and
          # Slow burn (6h window, 6x burn rate)
          (
            sum(rate(http_requests_total{status=~"5.."}[6h])) by (service)
            /
            sum(rate(http_requests_total[6h])) by (service)
            > 6 * (1 - 0.999)
          )
        for: 5m
        labels:
          severity: critical
```

---

## 6. Exercice Pratique

### Tâches

1. Créer 5 règles d'alerte (CPU, RAM, Disk, HTTP errors, Uptime)
2. Configurer Alertmanager avec Slack
3. Créer des routes par severity
4. Tester le silencing

### Configuration Complète

```yaml
# prometheus/rules/alerts.yml
groups:
  - name: infrastructure
    rules:
      - alert: HighCPU
        expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "CPU > 80% on {{ $labels.instance }}"

      - alert: HighMemory
        expr: (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Memory > 85% on {{ $labels.instance }}"

      - alert: DiskFull
        expr: (node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 < 10
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Disk < 10% on {{ $labels.instance }}"

  - name: application
    rules:
      - alert: HighErrorRate
        expr: sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: warning

      - alert: ServiceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
```

```yaml
# alertmanager/alertmanager.yml
global:
  resolve_timeout: 5m

route:
  receiver: 'slack-default'
  group_by: ['alertname']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
  routes:
    - match:
        severity: critical
      receiver: 'slack-critical'

receivers:
  - name: 'slack-default'
    slack_configs:
      - channel: '#alerts'
        send_resolved: true

  - name: 'slack-critical'
    slack_configs:
      - channel: '#alerts-critical'
        send_resolved: true
```

---

## Quiz

1. **Que signifie l'état "pending" d'une alerte ?**
   - [ ] A. L'alerte est résolue
   - [ ] B. La condition est vraie mais la durée 'for' n'est pas atteinte
   - [ ] C. L'alerte attend une approbation

2. **Que fait une inhibition ?**
   - [ ] A. Supprime définitivement une alerte
   - [ ] B. Empêche certaines alertes si une autre est active
   - [ ] C. Augmente la priorité d'une alerte

3. **Quel paramètre pour éviter les alertes répétitives ?**
   - [ ] A. group_wait
   - [ ] B. repeat_interval
   - [ ] C. resolve_timeout

**Réponses :** 1-B, 2-B, 3-B

---

**Précédent :** [Module 4 - Grafana Dashboards](04-module.md)

**Suivant :** [TP Final - Stack Complète](06-tp-final.md)
