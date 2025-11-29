---
tags:
  - formation
  - kubernetes
  - helm
  - packaging
  - charts
---

# Module 9 : Helm et Packaging

## Objectifs du Module

- Comprendre les concepts Helm
- Créer et personnaliser des Charts
- Maîtriser les templates et values
- Gérer les releases et repositories

**Durée :** 3 heures

---

## 1. Introduction à Helm

### 1.1 Concepts

```
HELM - PACKAGE MANAGER KUBERNETES
═════════════════════════════════

Chart       │ Package Helm (collection de fichiers YAML)
Release     │ Instance d'un Chart installé
Repository  │ Collection de Charts
Values      │ Configuration personnalisée

┌─────────────────────────────────────────────────────────────┐
│                        CHART                                 │
│                                                              │
│   mychart/                                                   │
│   ├── Chart.yaml          # Métadonnées du chart            │
│   ├── values.yaml         # Valeurs par défaut              │
│   ├── charts/             # Charts dépendants               │
│   ├── templates/          # Templates Kubernetes            │
│   │   ├── deployment.yaml                                   │
│   │   ├── service.yaml                                      │
│   │   ├── _helpers.tpl    # Fonctions réutilisables        │
│   │   └── NOTES.txt       # Notes post-installation        │
│   └── README.md                                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Installation

```bash
# Installation Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Vérifier
helm version

# Ajouter des repositories
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add stable https://charts.helm.sh/stable
helm repo update

# Rechercher des charts
helm search repo nginx
helm search hub wordpress
```

---

## 2. Utilisation de Base

### 2.1 Installer un Chart

```bash
# Installer depuis un repo
helm install my-nginx bitnami/nginx

# Avec namespace
helm install my-nginx bitnami/nginx -n webserver --create-namespace

# Avec fichier de values
helm install my-nginx bitnami/nginx -f my-values.yaml

# Avec values en ligne
helm install my-nginx bitnami/nginx \
  --set replicaCount=3 \
  --set service.type=NodePort

# Voir les values par défaut
helm show values bitnami/nginx

# Dry-run (prévisualisation)
helm install my-nginx bitnami/nginx --dry-run
```

### 2.2 Gérer les Releases

```bash
# Lister les releases
helm list
helm list -A  # Tous les namespaces

# Status d'une release
helm status my-nginx

# Historique
helm history my-nginx

# Upgrade
helm upgrade my-nginx bitnami/nginx --set replicaCount=5

# Rollback
helm rollback my-nginx 1

# Désinstaller
helm uninstall my-nginx
```

---

## 3. Créer un Chart

### 3.1 Structure

```bash
# Créer un nouveau chart
helm create myapp

# Structure générée
myapp/
├── Chart.yaml
├── values.yaml
├── charts/
├── templates/
│   ├── deployment.yaml
│   ├── service.yaml
│   ├── serviceaccount.yaml
│   ├── ingress.yaml
│   ├── hpa.yaml
│   ├── _helpers.tpl
│   ├── NOTES.txt
│   └── tests/
│       └── test-connection.yaml
└── .helmignore
```

### 3.2 Chart.yaml

```yaml
# Chart.yaml
apiVersion: v2
name: myapp
description: A Helm chart for MyApp
type: application
version: 1.0.0
appVersion: "2.0.0"
keywords:
  - myapp
  - web
home: https://github.com/myorg/myapp
sources:
  - https://github.com/myorg/myapp
maintainers:
  - name: John Doe
    email: john@example.com
dependencies:
  - name: postgresql
    version: "12.x.x"
    repository: "https://charts.bitnami.com/bitnami"
    condition: postgresql.enabled
```

### 3.3 values.yaml

```yaml
# values.yaml
replicaCount: 3

image:
  repository: myapp
  pullPolicy: IfNotPresent
  tag: ""  # Defaults to appVersion

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: myapp.local
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: myapp-tls
      hosts:
        - myapp.local

resources:
  limits:
    cpu: 500m
    memory: 256Mi
  requests:
    cpu: 100m
    memory: 128Mi

postgresql:
  enabled: true
  auth:
    database: myapp
```

---

## 4. Templates Helm

### 4.1 Syntaxe de Base

```yaml
# templates/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "myapp.fullname" . }}
  labels:
    {{- include "myapp.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      {{- include "myapp.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "myapp.selectorLabels" . | nindent 8 }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - name: http
              containerPort: 80
          {{- with .Values.resources }}
          resources:
            {{- toYaml . | nindent 12 }}
          {{- end }}
```

### 4.2 Helpers (_helpers.tpl)

```yaml
# templates/_helpers.tpl
{{/*
Expand the name of the chart.
*/}}
{{- define "myapp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "myapp.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "myapp.labels" -}}
helm.sh/chart: {{ include "myapp.chart" . }}
{{ include "myapp.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "myapp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "myapp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}
```

### 4.3 Conditionnels et Boucles

```yaml
# Conditionnel
{{- if .Values.ingress.enabled }}
apiVersion: networking.k8s.io/v1
kind: Ingress
...
{{- end }}

# Boucle
{{- range .Values.ingress.hosts }}
  - host: {{ .host | quote }}
    http:
      paths:
        {{- range .paths }}
        - path: {{ .path }}
          pathType: {{ .pathType }}
        {{- end }}
{{- end }}

# With (scope)
{{- with .Values.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 8 }}
{{- end }}
```

---

## 5. Helm Hooks

```yaml
# Hook pre-install
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "myapp.fullname" . }}-db-migrate
  annotations:
    "helm.sh/hook": pre-install,pre-upgrade
    "helm.sh/hook-weight": "-5"
    "helm.sh/hook-delete-policy": hook-succeeded
spec:
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: migrate
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          command: ["./migrate.sh"]
```

---

## 6. Exercice Pratique

### Tâches

1. Créer un chart pour une application web
2. Personnaliser avec des values
3. Ajouter un Ingress conditionnel
4. Packager et déployer

### Commandes Utiles

```bash
# Lint
helm lint ./myapp

# Template (voir le YAML généré)
helm template myapp ./myapp -f values-prod.yaml

# Package
helm package ./myapp

# Install local
helm install myapp ./myapp -f values-prod.yaml
```

---

## Quiz

1. **Où sont stockées les valeurs par défaut d'un chart ?**
   - [ ] A. Chart.yaml
   - [ ] B. values.yaml
   - [ ] C. templates/

2. **Quelle commande prévisualise le YAML généré ?**
   - [ ] A. helm show
   - [ ] B. helm template
   - [ ] C. helm install --dry-run

**Réponses :** 1-B, 2-B (ou C pour dry-run)

---

**Précédent :** [Module 8 - Observabilité](08-module.md)

**Suivant :** [Module 10 - GitOps](10-module.md)
