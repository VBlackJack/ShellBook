---
tags:
  - formation
  - observability
  - grafana
  - dashboards
  - visualization
---

# Module 4 : Grafana - Dashboards Avancés

## Objectifs du Module

- Installer et configurer Grafana
- Créer des dashboards professionnels
- Utiliser les variables et templates
- Maîtriser les panels avancés
- Implémenter le provisioning as code

**Durée :** 3 heures

---

## 1. Installation et Configuration

### 1.1 Docker

```yaml
# docker-compose.yml
grafana:
  image: grafana/grafana:10.2.0
  container_name: grafana
  ports:
    - "3000:3000"
  volumes:
    - grafana_data:/var/lib/grafana
    - ./grafana/provisioning:/etc/grafana/provisioning
  environment:
    - GF_SECURITY_ADMIN_USER=admin
    - GF_SECURITY_ADMIN_PASSWORD=admin123
    - GF_USERS_ALLOW_SIGN_UP=false
    - GF_SERVER_ROOT_URL=http://localhost:3000
  restart: unless-stopped

volumes:
  grafana_data:
```

### 1.2 Configuration Avancée

```ini
# grafana.ini ou variables d'environnement

#################################### Server ####################################
[server]
protocol = http
http_port = 3000
domain = grafana.example.com
root_url = %(protocol)s://%(domain)s/

#################################### Security ##################################
[security]
admin_user = admin
admin_password = secure_password
secret_key = SW2YcwTIb9zpOOhoPsMm

# Désactiver la création de compte
[users]
allow_sign_up = false
auto_assign_org = true
auto_assign_org_role = Viewer

#################################### Auth ######################################
[auth]
disable_login_form = false

# LDAP
[auth.ldap]
enabled = true
config_file = /etc/grafana/ldap.toml

# OAuth (exemple avec Keycloak)
[auth.generic_oauth]
enabled = true
name = Keycloak
client_id = grafana
client_secret = your_secret
scopes = openid profile email
auth_url = https://keycloak.example.com/auth/realms/master/protocol/openid-connect/auth
token_url = https://keycloak.example.com/auth/realms/master/protocol/openid-connect/token
api_url = https://keycloak.example.com/auth/realms/master/protocol/openid-connect/userinfo

#################################### Database ##################################
[database]
type = postgres
host = postgres:5432
name = grafana
user = grafana
password = grafana_password
```

### 1.3 Datasources

```text
DATASOURCES SUPPORTÉES
══════════════════════

TIME SERIES                 LOGS                    TRACES
───────────                 ────                    ──────
• Prometheus                • Loki                  • Tempo
• InfluxDB                  • Elasticsearch         • Jaeger
• Graphite                  • CloudWatch Logs       • Zipkin
• TimescaleDB
• VictoriaMetrics

SQL                         CLOUD                   AUTRES
───                         ─────                   ──────
• MySQL                     • CloudWatch            • JSON API
• PostgreSQL                • Azure Monitor         • CSV
• MSSQL                     • Google Cloud          • TestData
• ClickHouse               • Datadog
```

---

## 2. Création de Dashboards

### 2.1 Structure d'un Dashboard

![Anatomie d'un Dashboard Grafana](../../assets/diagrams/grafana-dashboard-anatomy.jpeg)

### 2.2 Types de Panels

```text
PANELS GRAFANA
══════════════

VISUALISATIONS
─────────────────────────────────────────────
Time series    │ Graphiques temporels classiques
Stat           │ Valeur unique avec seuils
Gauge          │ Jauge avec min/max
Bar gauge      │ Barres horizontales/verticales
Table          │ Données tabulaires
Heatmap        │ Distribution 2D
Histogram      │ Distribution des valeurs
Pie chart      │ Camembert
State timeline │ États au fil du temps
Status history │ Historique des statuts
Geomap         │ Carte géographique
Canvas         │ Visualisation personnalisée
Text           │ Markdown/HTML

WIDGETS
─────────────────────────────────────────────
Alert list     │ Liste des alertes actives
Annotation list│ Liste des annotations
Dashboard list │ Navigation entre dashboards
News           │ Flux RSS
Logs           │ Visualisation de logs (Loki)
Traces         │ Visualisation de traces (Tempo)
```

### 2.3 Panel Time Series

```json
{
  "type": "timeseries",
  "title": "CPU Usage",
  "datasource": {
    "type": "prometheus",
    "uid": "prometheus"
  },
  "targets": [
    {
      "expr": "100 - (avg by(instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
      "legendFormat": "{{instance}}"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "unit": "percent",
      "min": 0,
      "max": 100,
      "thresholds": {
        "mode": "absolute",
        "steps": [
          { "value": null, "color": "green" },
          { "value": 70, "color": "yellow" },
          { "value": 90, "color": "red" }
        ]
      },
      "custom": {
        "lineWidth": 2,
        "fillOpacity": 10,
        "gradientMode": "scheme",
        "showPoints": "never"
      }
    }
  },
  "options": {
    "legend": {
      "displayMode": "table",
      "placement": "bottom",
      "calcs": ["mean", "max", "last"]
    },
    "tooltip": {
      "mode": "multi",
      "sort": "desc"
    }
  }
}
```

### 2.4 Panel Stat

```json
{
  "type": "stat",
  "title": "Uptime",
  "targets": [
    {
      "expr": "(time() - node_boot_time_seconds) / 86400",
      "legendFormat": "Days"
    }
  ],
  "fieldConfig": {
    "defaults": {
      "unit": "d",
      "decimals": 1,
      "thresholds": {
        "mode": "absolute",
        "steps": [
          { "value": null, "color": "red" },
          { "value": 1, "color": "yellow" },
          { "value": 7, "color": "green" }
        ]
      }
    }
  },
  "options": {
    "reduceOptions": {
      "calcs": ["lastNotNull"]
    },
    "colorMode": "background",
    "graphMode": "none",
    "textMode": "value_and_name"
  }
}
```

### 2.5 Panel Table

```json
{
  "type": "table",
  "title": "Server Status",
  "targets": [
    {
      "expr": "up{job=\"node\"}",
      "format": "table",
      "instant": true
    },
    {
      "expr": "100 - (avg by(instance) (rate(node_cpu_seconds_total{mode=\"idle\"}[5m])) * 100)",
      "format": "table",
      "instant": true
    },
    {
      "expr": "100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)",
      "format": "table",
      "instant": true
    }
  ],
  "transformations": [
    {
      "id": "merge"
    },
    {
      "id": "organize",
      "options": {
        "excludeByName": {
          "Time": true,
          "job": true
        },
        "renameByName": {
          "instance": "Server",
          "Value #A": "Status",
          "Value #B": "CPU %",
          "Value #C": "Memory %"
        }
      }
    }
  ],
  "fieldConfig": {
    "overrides": [
      {
        "matcher": { "id": "byName", "options": "Status" },
        "properties": [
          {
            "id": "mappings",
            "value": [
              { "type": "value", "options": { "1": { "text": "UP", "color": "green" } } },
              { "type": "value", "options": { "0": { "text": "DOWN", "color": "red" } } }
            ]
          }
        ]
      }
    ]
  }
}
```

---

## 3. Variables et Templates

### 3.1 Types de Variables

```text
TYPES DE VARIABLES
══════════════════

Query          │ Valeurs depuis une datasource
Custom         │ Liste statique de valeurs
Text box       │ Saisie libre
Constant       │ Valeur fixe (masquée)
Datasource     │ Sélection de datasource
Interval       │ Intervalles de temps
Ad hoc filters │ Filtres dynamiques
```

### 3.2 Variable Query (Prometheus)

```yaml
# Variable: instance
# Type: Query
# Query: label_values(node_cpu_seconds_total, instance)
# Regex: /(.+):.+/  # Extraire hostname sans port
# Multi-value: true
# Include All: true

# Variable: job
# Query: label_values(up, job)

# Variable: mountpoint
# Query: label_values(node_filesystem_size_bytes{instance=~"$instance"}, mountpoint)
# Dépend de la variable instance

# Variable: cpu_mode
# Type: Custom
# Values: user,system,iowait,idle
```

### 3.3 Utilisation dans les Queries

```promql
# Utiliser une variable simple
up{instance="$instance"}

# Utiliser une variable multi-valeur
up{instance=~"$instance"}

# Combiner plusieurs variables
node_cpu_seconds_total{instance=~"$instance", mode="$cpu_mode"}

# Variable avec regex
up{job=~"$job"}

# Variable intervalle
rate(http_requests_total[$__interval])

# Variables auto
rate(http_requests_total[$__rate_interval])
```

### 3.4 Exemple Complet

```json
{
  "templating": {
    "list": [
      {
        "name": "datasource",
        "type": "datasource",
        "query": "prometheus"
      },
      {
        "name": "env",
        "type": "query",
        "datasource": "$datasource",
        "query": "label_values(up, environment)",
        "current": { "selected": true, "text": "production", "value": "production" },
        "refresh": 1
      },
      {
        "name": "instance",
        "type": "query",
        "datasource": "$datasource",
        "query": "label_values(up{environment=\"$env\"}, instance)",
        "multi": true,
        "includeAll": true,
        "allValue": ".*",
        "refresh": 2
      },
      {
        "name": "interval",
        "type": "interval",
        "query": "1m,5m,10m,30m,1h",
        "current": { "text": "5m", "value": "5m" }
      }
    ]
  }
}
```

---

## 4. Transformations

### 4.1 Transformations Courantes

```text
TRANSFORMATIONS GRAFANA
═══════════════════════

DONNÉES
─────────────────────────────────────────────
Merge            │ Fusionner plusieurs queries
Join by field    │ Joindre par un champ commun
Concatenate      │ Concaténer les frames
Group by         │ Grouper et agréger

COLONNES
─────────────────────────────────────────────
Organize fields  │ Renommer, réordonner, masquer
Filter by name   │ Filtrer les colonnes
Filter by value  │ Filtrer les lignes
Add field        │ Ajouter un champ calculé

CALCULS
─────────────────────────────────────────────
Reduce           │ Calculer une seule valeur (avg, sum, etc.)
Calculate field  │ Opérations entre champs
Binary operation │ Opérations binaires
```

### 4.2 Exemples de Transformations

```json
{
  "transformations": [
    // Fusionner les résultats de plusieurs queries
    {
      "id": "merge"
    },
    // Réorganiser les colonnes
    {
      "id": "organize",
      "options": {
        "excludeByName": {
          "Time": true,
          "__name__": true
        },
        "indexByName": {
          "instance": 0,
          "cpu": 1,
          "memory": 2
        },
        "renameByName": {
          "instance": "Server",
          "Value #A": "CPU Usage",
          "Value #B": "Memory Usage"
        }
      }
    },
    // Filtrer les valeurs
    {
      "id": "filterByValue",
      "options": {
        "filters": [
          {
            "fieldName": "CPU Usage",
            "config": {
              "id": "greaterOrEqual",
              "options": { "value": 50 }
            }
          }
        ],
        "type": "include",
        "match": "any"
      }
    },
    // Ajouter un champ calculé
    {
      "id": "calculateField",
      "options": {
        "mode": "binary",
        "binary": {
          "left": "CPU Usage",
          "operator": "+",
          "right": "Memory Usage"
        },
        "alias": "Total Usage"
      }
    }
  ]
}
```

---

## 5. Provisioning as Code

### 5.1 Structure

```text
grafana/provisioning/
├── dashboards/
│   ├── default.yml           # Configuration provider
│   └── dashboards/
│       ├── node-exporter.json
│       └── application.json
├── datasources/
│   └── datasources.yml
├── alerting/
│   └── alerting.yml
└── notifiers/
    └── notifiers.yml
```

### 5.2 Datasources

```yaml
# provisioning/datasources/datasources.yml
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
    editable: false
    jsonData:
      httpMethod: POST
      manageAlerts: true
      prometheusType: Prometheus
      prometheusVersion: "2.47.0"

  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    editable: false
    jsonData:
      derivedFields:
        - datasourceUid: tempo
          matcherRegex: "traceID=(\\w+)"
          name: TraceID
          url: "$${__value.raw}"

  - name: Tempo
    type: tempo
    access: proxy
    url: http://tempo:3200
    uid: tempo
    editable: false
```

### 5.3 Dashboard Provider

```yaml
# provisioning/dashboards/default.yml
apiVersion: 1

providers:
  - name: 'default'
    orgId: 1
    folder: 'Provisioned'
    folderUid: 'provisioned'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards/dashboards
```

### 5.4 Dashboard JSON

```json
{
  "uid": "node-exporter",
  "title": "Node Exporter",
  "tags": ["prometheus", "node-exporter"],
  "timezone": "browser",
  "schemaVersion": 38,
  "version": 1,
  "refresh": "30s",
  "time": {
    "from": "now-1h",
    "to": "now"
  },
  "templating": {
    "list": [
      {
        "name": "instance",
        "type": "query",
        "datasource": { "type": "prometheus", "uid": "prometheus" },
        "query": "label_values(node_uname_info, instance)",
        "refresh": 2,
        "multi": true,
        "includeAll": true
      }
    ]
  },
  "panels": [
    {
      "id": 1,
      "type": "stat",
      "title": "CPU Usage",
      "gridPos": { "x": 0, "y": 0, "w": 6, "h": 4 },
      "targets": [
        {
          "expr": "100 - (avg by(instance) (rate(node_cpu_seconds_total{mode=\"idle\", instance=~\"$instance\"}[5m])) * 100)",
          "legendFormat": "{{instance}}"
        }
      ],
      "fieldConfig": {
        "defaults": {
          "unit": "percent",
          "thresholds": {
            "steps": [
              { "value": null, "color": "green" },
              { "value": 70, "color": "yellow" },
              { "value": 90, "color": "red" }
            ]
          }
        }
      }
    }
  ]
}
```

### 5.5 Alerting Rules

```yaml
# provisioning/alerting/alerting.yml
apiVersion: 1

groups:
  - orgId: 1
    name: Infrastructure
    folder: Alerts
    interval: 1m
    rules:
      - uid: high-cpu
        title: High CPU Usage
        condition: C
        data:
          - refId: A
            relativeTimeRange:
              from: 300
              to: 0
            datasourceUid: prometheus
            model:
              expr: 100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)
          - refId: B
            relativeTimeRange:
              from: 0
              to: 0
            datasourceUid: __expr__
            model:
              type: reduce
              expression: A
              reducer: mean
          - refId: C
            datasourceUid: __expr__
            model:
              type: threshold
              expression: B
              conditions:
                - evaluator:
                    type: gt
                    params: [80]
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: High CPU usage on {{ $labels.instance }}
          description: CPU usage is above 80% for 5 minutes
```

---

## 6. Dashboards Recommandés

### 6.1 Dashboards Communautaires

```bash
# Importer depuis grafana.com par ID

# Node Exporter Full - ID: 1860
# → Dashboard complet pour Node Exporter

# Docker and System Monitoring - ID: 893
# → Monitoring Docker + système

# Kubernetes Cluster - ID: 6417
# → Vue cluster Kubernetes

# Nginx - ID: 9614
# → Monitoring Nginx

# PostgreSQL - ID: 9628
# → Monitoring PostgreSQL

# Redis - ID: 11835
# → Monitoring Redis
```

### 6.2 Best Practices

```text
BONNES PRATIQUES DASHBOARDS
═══════════════════════════

ORGANISATION
─────────────────────────────────────────────
✓ Un dashboard = un focus (service/infra)
✓ Utiliser les folders pour organiser
✓ Nommer clairement avec tags
✓ Documenter avec des Text panels

DESIGN
─────────────────────────────────────────────
✓ Panels importants en haut
✓ Utiliser les Row pour regrouper
✓ Couleurs cohérentes (vert=OK, rouge=KO)
✓ Éviter la surcharge d'informations

PERFORMANCE
─────────────────────────────────────────────
✓ Limiter le nombre de panels (<20)
✓ Utiliser des variables pour filtrer
✓ Préférer instant queries pour les stats
✓ Éviter les regex complexes
```

---

## 7. Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Créer un dashboard Grafana professionnel avec variables, transformations et provisioning

    **Contexte** : Votre équipe a besoin d'un dashboard unifié pour monitorer tous les serveurs de l'infrastructure. Le dashboard doit être réutilisable pour n'importe quel serveur grâce aux variables, et doit être versionné via le provisioning as code.

    **Tâches à réaliser** :

    1. Créer un dashboard "Infrastructure Overview" avec 6 panels différents
    2. Ajouter une variable `instance` pour filtrer par serveur
    3. Ajouter une variable `interval` pour ajuster la fenêtre temporelle
    4. Utiliser des transformations sur au moins un panel
    5. Configurer des seuils colorés (vert/jaune/rouge) sur les panels
    6. Exporter le dashboard en JSON
    7. Configurer le provisioning pour charger automatiquement le dashboard au démarrage

    **Critères de validation** :

    - [ ] Panel Stat affiche l'uptime du serveur
    - [ ] Panel Gauge affiche le CPU avec seuils colorés
    - [ ] Panel Time Series affiche l'évolution de la mémoire
    - [ ] Panel Table affiche l'utilisation disque par partition
    - [ ] Panel Bar Gauge affiche le trafic réseau
    - [ ] Panel Graph affiche la charge système (load average)
    - [ ] Les variables fonctionnent et filtrent correctement
    - [ ] Le dashboard est provisionné automatiquement

??? quote "Solution"
    **1. Structure du provisioning**

    ```bash
    grafana/
    ├── provisioning/
    │   ├── datasources/
    │   │   └── datasources.yml
    │   └── dashboards/
    │       ├── default.yml
    │       └── dashboards/
    │           └── infrastructure.json
    ```

    **2. Configuration datasource**

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

    **3. Configuration dashboard provider**

    ```yaml
    # grafana/provisioning/dashboards/default.yml
    apiVersion: 1

    providers:
      - name: 'default'
        orgId: 1
        folder: 'Infrastructure'
        type: file
        disableDeletion: false
        updateIntervalSeconds: 30
        allowUiUpdates: true
        options:
          path: /etc/grafana/provisioning/dashboards/dashboards
    ```

    **4. Panels à créer dans l'interface Grafana**

    **Panel 1 - Stat : Uptime**

    ```json
    {
      "type": "stat",
      "title": "Uptime",
      "targets": [{
        "expr": "(time() - node_boot_time_seconds{instance=~\"$instance\"}) / 86400"
      }],
      "fieldConfig": {
        "defaults": {
          "unit": "d",
          "decimals": 1,
          "thresholds": {
            "steps": [
              {"value": null, "color": "red"},
              {"value": 1, "color": "yellow"},
              {"value": 7, "color": "green"}
            ]
          }
        }
      }
    }
    ```

    **Panel 2 - Gauge : CPU Usage**

    ```promql
    100 - (avg by(instance) (rate(node_cpu_seconds_total{mode="idle",instance=~"$instance"}[$interval])) * 100)
    ```

    Configuration :
    - Unit: percent (0-100)
    - Thresholds: 70 (yellow), 90 (red)
    - Display mode: Gradient

    **Panel 3 - Time Series : Memory**

    ```promql
    100 * (1 - node_memory_MemAvailable_bytes{instance=~"$instance"} / node_memory_MemTotal_bytes{instance=~"$instance"})
    ```

    Configuration :
    - Unit: percent
    - Legend: {{instance}}
    - Fill opacity: 10

    **Panel 4 - Table : Disk Usage**

    Queries multiples :
    ```promql
    # Query A - Filesystem
    node_filesystem_size_bytes{instance=~"$instance",fstype!~"tmpfs|overlay"}

    # Query B - Used
    node_filesystem_size_bytes{instance=~"$instance",fstype!~"tmpfs|overlay"} - node_filesystem_avail_bytes{instance=~"$instance",fstype!~"tmpfs|overlay"}

    # Query C - Available
    node_filesystem_avail_bytes{instance=~"$instance",fstype!~"tmpfs|overlay"}
    ```

    Transformations :
    - Merge
    - Organize fields (renommer les colonnes)
    - Add field from calculation (calcul du pourcentage)

    **Panel 5 - Bar Gauge : Network Traffic**

    ```promql
    rate(node_network_receive_bytes_total{instance=~"$instance",device!~"lo|veth.*"}[$interval]) / 1024 / 1024
    ```

    Configuration :
    - Unit: MBps
    - Orientation: Horizontal
    - Display mode: Gradient

    **Panel 6 - Graph : Load Average**

    ```promql
    node_load1{instance=~"$instance"}
    node_load5{instance=~"$instance"}
    node_load15{instance=~"$instance"}
    ```

    Configuration :
    - Legend: Load 1m, 5m, 15m
    - Threshold line au nombre de CPUs

    **5. Variables à configurer**

    **Variable : datasource**
    - Type: Datasource
    - Query: prometheus

    **Variable : instance**
    - Type: Query
    - Query: `label_values(node_cpu_seconds_total, instance)`
    - Multi-value: true
    - Include All: true
    - Refresh: On Dashboard Load

    **Variable : interval**
    - Type: Interval
    - Values: 1m,5m,10m,30m,1h
    - Auto: false

    **6. Export et sauvegarde**

    Une fois le dashboard créé dans l'UI :

    1. Cliquer sur l'icône Share (⬆)
    2. Onglet "Export"
    3. "Save to file"
    4. Sauvegarder dans `grafana/provisioning/dashboards/dashboards/infrastructure.json`

    **7. Docker Compose avec provisioning**

    ```yaml
    grafana:
      image: grafana/grafana:latest
      ports:
        - "3000:3000"
      volumes:
        - ./grafana/provisioning:/etc/grafana/provisioning
        - grafana_data:/var/lib/grafana
      environment:
        - GF_SECURITY_ADMIN_PASSWORD=admin123
        - GF_USERS_ALLOW_SIGN_UP=false
    ```

    **Validation complète :**

    ```bash
    # Démarrer la stack
    docker-compose up -d

    # Attendre que Grafana démarre
    sleep 10

    # Vérifier que le datasource est provisionné
    curl -u admin:admin123 http://localhost:3000/api/datasources | jq .

    # Vérifier que le dashboard est provisionné
    curl -u admin:admin123 http://localhost:3000/api/search | jq .

    # Accéder à Grafana
    open http://localhost:3000
    ```

    **Points importants :**

    - Utilisez toujours `instance=~"$instance"` pour filtrer par la variable
    - Utilisez `$interval` dans les fonctions rate() pour la flexibilité
    - Configurez `"editable": true` dans le JSON pour permettre les modifications
    - Testez le dashboard avec différentes sélections de variables

---

## Quiz

1. **Quel panel pour afficher une valeur unique ?**
   - [ ] A. Time series
   - [ ] B. Stat
   - [ ] C. Table

2. **Comment utiliser une variable multi-valeur dans une query ?**
   - [ ] A. {instance="$instance"}
   - [ ] B. {instance=~"$instance"}
   - [ ] C. {instance IN $instance}

3. **Où placer les dashboards pour le provisioning ?**
   - [ ] A. /var/lib/grafana/dashboards
   - [ ] B. /etc/grafana/provisioning/dashboards
   - [ ] C. /usr/share/grafana/dashboards

**Réponses :** 1-B, 2-B, 3-B

---

**Précédent :** [Module 3 - Exporters](03-module.md)

**Suivant :** [Module 5 - Alerting](05-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 3 : Exporters et Instrumentation](03-module.md) | [Module 5 : Alerting et Notifications →](05-module.md) |

[Retour au Programme](index.md){ .md-button }
