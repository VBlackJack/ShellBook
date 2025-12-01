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

## 6. Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Créer un Chart Helm complet pour une application web avec base de données, configurable pour plusieurs environnements

    **Contexte** : Vous devez créer un Chart Helm pour déployer "BlogApp", une application de blog composée d'un frontend (React), d'un backend API (Node.js), et d'une base PostgreSQL. Le Chart doit supporter les environnements dev, staging et production avec des configurations différentes.

    **Tâches à réaliser** :

    1. Créer la structure du Chart avec `helm create`
    2. Configurer le Deployment du backend avec probes et resources
    3. Ajouter PostgreSQL comme dépendance
    4. Créer un Ingress conditionnel pour chaque environnement
    5. Créer des fichiers values pour dev, staging et production
    6. Ajouter un Hook pre-install pour la migration de base de données
    7. Packager et déployer le Chart

    **Critères de validation** :

    - [ ] `helm lint` passe sans erreur
    - [ ] `helm template` génère les manifests corrects
    - [ ] Les trois environnements ont des configurations différentes
    - [ ] L'Ingress s'active uniquement en production
    - [ ] Le Hook de migration s'exécute avant le déploiement

??? quote "Solution"
    **Étape 1 : Créer la Structure**

    ```bash
    # Créer le chart de base
    helm create blogapp

    cd blogapp

    # Nettoyer les fichiers par défaut
    rm -rf templates/tests
    rm templates/serviceaccount.yaml templates/hpa.yaml

    # Structure finale
    tree
    # blogapp/
    # ├── Chart.yaml
    # ├── values.yaml
    # ├── values-dev.yaml
    # ├── values-staging.yaml
    # ├── values-prod.yaml
    # ├── charts/
    # └── templates/
    #     ├── _helpers.tpl
    #     ├── deployment.yaml
    #     ├── service.yaml
    #     ├── ingress.yaml
    #     ├── configmap.yaml
    #     ├── secret.yaml
    #     ├── db-migration-hook.yaml
    #     └── NOTES.txt
    ```

    **Étape 2 : Configurer Chart.yaml**

    ```yaml
    # Chart.yaml
    apiVersion: v2
    name: blogapp
    description: A Helm chart for BlogApp (Frontend + Backend + PostgreSQL)
    type: application
    version: 1.0.0
    appVersion: "2.1.0"

    keywords:
      - blog
      - nodejs
      - react
      - postgresql

    home: https://github.com/myorg/blogapp
    sources:
      - https://github.com/myorg/blogapp

    maintainers:
      - name: DevOps Team
        email: devops@example.com

    dependencies:
      - name: postgresql
        version: "12.x.x"
        repository: "https://charts.bitnami.com/bitnami"
        condition: postgresql.enabled
        tags:
          - database
    ```

    **Étape 3 : Configurer values.yaml (défaut)**

    ```yaml
    # values.yaml
    replicaCount: 1

    image:
      repository: mycompany/blogapp-backend
      pullPolicy: IfNotPresent
      tag: ""  # Defaults to appVersion

    imagePullSecrets: []
    nameOverride: ""
    fullnameOverride: ""

    service:
      type: ClusterIP
      port: 80
      targetPort: 3000

    ingress:
      enabled: false
      className: nginx
      annotations:
        cert-manager.io/cluster-issuer: letsencrypt-prod
      hosts:
        - host: blog.local
          paths:
            - path: /
              pathType: Prefix
      tls:
        - secretName: blogapp-tls
          hosts:
            - blog.local

    resources:
      limits:
        cpu: 500m
        memory: 512Mi
      requests:
        cpu: 100m
        memory: 128Mi

    livenessProbe:
      httpGet:
        path: /health
        port: http
      initialDelaySeconds: 30
      periodSeconds: 10

    readinessProbe:
      httpGet:
        path: /ready
        port: http
      initialDelaySeconds: 10
      periodSeconds: 5

    autoscaling:
      enabled: false
      minReplicas: 2
      maxReplicas: 10
      targetCPUUtilizationPercentage: 70

    nodeSelector: {}
    tolerations: []
    affinity: {}

    # Configuration de l'application
    config:
      nodeEnv: production
      logLevel: info
      port: 3000

    # PostgreSQL (dépendance)
    postgresql:
      enabled: true
      auth:
        username: blogapp
        password: changeme
        database: blogapp
      primary:
        persistence:
          enabled: true
          size: 10Gi

    # Migration de base de données
    migration:
      enabled: true
      image:
        repository: mycompany/blogapp-migrations
        tag: latest
    ```

    **Étape 4 : Values par Environnement**

    ```yaml
    # values-dev.yaml
    replicaCount: 1

    image:
      tag: "dev-latest"

    ingress:
      enabled: false

    resources:
      limits:
        cpu: 200m
        memory: 256Mi
      requests:
        cpu: 50m
        memory: 64Mi

    config:
      nodeEnv: development
      logLevel: debug

    postgresql:
      auth:
        password: dev123
      primary:
        persistence:
          enabled: false  # Pas de persistence en dev

    migration:
      enabled: false  # Pas de migration en dev
    ```

    ```yaml
    # values-staging.yaml
    replicaCount: 2

    image:
      tag: "staging-v2.1.0"

    ingress:
      enabled: true
      hosts:
        - host: blog-staging.example.com
          paths:
            - path: /
              pathType: Prefix
      tls:
        - secretName: blogapp-staging-tls
          hosts:
            - blog-staging.example.com

    resources:
      limits:
        cpu: 500m
        memory: 512Mi
      requests:
        cpu: 100m
        memory: 128Mi

    config:
      nodeEnv: staging
      logLevel: info

    postgresql:
      auth:
        password: staging-secret-pwd
      primary:
        persistence:
          enabled: true
          size: 5Gi

    autoscaling:
      enabled: false
    ```

    ```yaml
    # values-prod.yaml
    replicaCount: 3

    image:
      tag: "v2.1.0"

    ingress:
      enabled: true
      className: nginx
      annotations:
        cert-manager.io/cluster-issuer: letsencrypt-prod
        nginx.ingress.kubernetes.io/rate-limit: "100"
      hosts:
        - host: blog.example.com
          paths:
            - path: /
              pathType: Prefix
      tls:
        - secretName: blogapp-prod-tls
          hosts:
            - blog.example.com

    resources:
      limits:
        cpu: 1000m
        memory: 1Gi
      requests:
        cpu: 250m
        memory: 256Mi

    config:
      nodeEnv: production
      logLevel: warn

    postgresql:
      enabled: true
      auth:
        existingSecret: blogapp-db-secret
      primary:
        persistence:
          enabled: true
          size: 20Gi
          storageClass: fast-ssd

    autoscaling:
      enabled: true
      minReplicas: 3
      maxReplicas: 10
      targetCPUUtilizationPercentage: 70

    affinity:
      podAntiAffinity:
        preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                  - key: app.kubernetes.io/name
                    operator: In
                    values:
                      - blogapp
              topologyKey: kubernetes.io/hostname
    ```

    **Étape 5 : Templates - Deployment**

    ```yaml
    # templates/deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: {{ include "blogapp.fullname" . }}
      labels:
        {{- include "blogapp.labels" . | nindent 4 }}
    spec:
      {{- if not .Values.autoscaling.enabled }}
      replicas: {{ .Values.replicaCount }}
      {{- end }}
      selector:
        matchLabels:
          {{- include "blogapp.selectorLabels" . | nindent 6 }}
      template:
        metadata:
          annotations:
            checksum/config: {{ include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
          labels:
            {{- include "blogapp.selectorLabels" . | nindent 8 }}
        spec:
          {{- with .Values.imagePullSecrets }}
          imagePullSecrets:
            {{- toYaml . | nindent 8 }}
          {{- end }}
          containers:
            - name: {{ .Chart.Name }}
              image: "{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}"
              imagePullPolicy: {{ .Values.image.pullPolicy }}
              ports:
                - name: http
                  containerPort: {{ .Values.config.port }}
                  protocol: TCP
              env:
                - name: NODE_ENV
                  value: {{ .Values.config.nodeEnv | quote }}
                - name: LOG_LEVEL
                  value: {{ .Values.config.logLevel | quote }}
                - name: PORT
                  value: {{ .Values.config.port | quote }}
                - name: DATABASE_HOST
                  value: {{ include "blogapp.fullname" . }}-postgresql
                - name: DATABASE_PORT
                  value: "5432"
                - name: DATABASE_NAME
                  value: {{ .Values.postgresql.auth.database | quote }}
                - name: DATABASE_USER
                  value: {{ .Values.postgresql.auth.username | quote }}
                - name: DATABASE_PASSWORD
                  valueFrom:
                    secretKeyRef:
                      name: {{ include "blogapp.fullname" . }}-postgresql
                      key: password
              {{- with .Values.livenessProbe }}
              livenessProbe:
                {{- toYaml . | nindent 16 }}
              {{- end }}
              {{- with .Values.readinessProbe }}
              readinessProbe:
                {{- toYaml . | nindent 16 }}
              {{- end }}
              resources:
                {{- toYaml .Values.resources | nindent 16 }}
          {{- with .Values.nodeSelector }}
          nodeSelector:
            {{- toYaml . | nindent 8 }}
          {{- end }}
          {{- with .Values.affinity }}
          affinity:
            {{- toYaml . | nindent 8 }}
          {{- end }}
          {{- with .Values.tolerations }}
          tolerations:
            {{- toYaml . | nindent 8 }}
          {{- end }}
    ```

    **Étape 6 : Hook de Migration**

    ```yaml
    # templates/db-migration-hook.yaml
    {{- if .Values.migration.enabled }}
    apiVersion: batch/v1
    kind: Job
    metadata:
      name: {{ include "blogapp.fullname" . }}-db-migrate
      labels:
        {{- include "blogapp.labels" . | nindent 4 }}
      annotations:
        "helm.sh/hook": pre-install,pre-upgrade
        "helm.sh/hook-weight": "-5"
        "helm.sh/hook-delete-policy": before-hook-creation
    spec:
      backoffLimit: 3
      template:
        metadata:
          labels:
            {{- include "blogapp.selectorLabels" . | nindent 12 }}
        spec:
          restartPolicy: Never
          containers:
            - name: db-migrate
              image: "{{ .Values.migration.image.repository }}:{{ .Values.migration.image.tag }}"
              command:
                - /bin/sh
                - -c
                - |
                  echo "Running database migrations..."
                  npm run migrate
                  echo "Migrations completed successfully"
              env:
                - name: DATABASE_HOST
                  value: {{ include "blogapp.fullname" . }}-postgresql
                - name: DATABASE_PORT
                  value: "5432"
                - name: DATABASE_NAME
                  value: {{ .Values.postgresql.auth.database | quote }}
                - name: DATABASE_USER
                  value: {{ .Values.postgresql.auth.username | quote }}
                - name: DATABASE_PASSWORD
                  valueFrom:
                    secretKeyRef:
                      name: {{ include "blogapp.fullname" . }}-postgresql
                      key: password
    {{- end }}
    ```

    **Étape 7 : Templates - Ingress**

    ```yaml
    # templates/ingress.yaml
    {{- if .Values.ingress.enabled }}
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: {{ include "blogapp.fullname" . }}
      labels:
        {{- include "blogapp.labels" . | nindent 4 }}
      {{- with .Values.ingress.annotations }}
      annotations:
        {{- toYaml . | nindent 4 }}
      {{- end }}
    spec:
      {{- if .Values.ingress.className }}
      ingressClassName: {{ .Values.ingress.className }}
      {{- end }}
      {{- if .Values.ingress.tls }}
      tls:
        {{- range .Values.ingress.tls }}
        - hosts:
            {{- range .hosts }}
            - {{ . | quote }}
            {{- end }}
          secretName: {{ .secretName }}
        {{- end }}
      {{- end }}
      rules:
        {{- range .Values.ingress.hosts }}
        - host: {{ .host | quote }}
          http:
            paths:
              {{- range .paths }}
              - path: {{ .path }}
                pathType: {{ .pathType }}
                backend:
                  service:
                    name: {{ include "blogapp.fullname" $ }}
                    port:
                      number: {{ $.Values.service.port }}
              {{- end }}
        {{- end }}
    {{- end }}
    ```

    **Étape 8 : NOTES.txt**

    ```
    # templates/NOTES.txt
    🎉 BlogApp a été déployé avec succès !

    Application: {{ include "blogapp.fullname" . }}
    Namespace: {{ .Release.Namespace }}
    Version: {{ .Chart.AppVersion }}

    {{- if .Values.ingress.enabled }}

    🌐 L'application est accessible via :
    {{- range .Values.ingress.hosts }}
      https://{{ .host }}
    {{- end }}
    {{- else }}

    Pour accéder à l'application localement :

      export POD_NAME=$(kubectl get pods --namespace {{ .Release.Namespace }} -l "app.kubernetes.io/name={{ include "blogapp.name" . }},app.kubernetes.io/instance={{ .Release.Name }}" -o jsonpath="{.items[0].metadata.name}")
      kubectl port-forward $POD_NAME 8080:{{ .Values.config.port }}

      Visitez http://127.0.0.1:8080
    {{- end }}

    📊 Commandes utiles :

      # Voir les pods
      kubectl get pods -l app.kubernetes.io/name={{ include "blogapp.name" . }}

      # Voir les logs
      kubectl logs -l app.kubernetes.io/name={{ include "blogapp.name" . }} -f

      # Statut de la release
      helm status {{ .Release.Name }}
    ```

    **Étape 9 : Validation et Déploiement**

    ```bash
    # Installer les dépendances
    helm dependency update

    # Lint le chart
    helm lint .
    helm lint . -f values-dev.yaml
    helm lint . -f values-prod.yaml

    # Voir le YAML généré (dev)
    helm template blogapp . -f values-dev.yaml > /tmp/dev-manifests.yaml
    less /tmp/dev-manifests.yaml

    # Voir le YAML généré (prod)
    helm template blogapp . -f values-prod.yaml > /tmp/prod-manifests.yaml
    diff /tmp/dev-manifests.yaml /tmp/prod-manifests.yaml

    # Dry-run
    helm install blogapp-dev . -f values-dev.yaml --dry-run --debug

    # Packager
    cd ..
    helm package blogapp
    # Résultat: blogapp-1.0.0.tgz

    # Déployer en dev
    helm install blogapp-dev ./blogapp -f blogapp/values-dev.yaml \
      --namespace dev \
      --create-namespace

    # Déployer en staging
    helm install blogapp-staging ./blogapp -f blogapp/values-staging.yaml \
      --namespace staging \
      --create-namespace

    # Déployer en production
    helm install blogapp-prod ./blogapp -f blogapp/values-prod.yaml \
      --namespace production \
      --create-namespace

    # Vérifier les releases
    helm list -A

    # Voir les différences entre environnements
    helm get values blogapp-dev -n dev
    helm get values blogapp-prod -n production

    # Tester une upgrade
    helm upgrade blogapp-dev ./blogapp -f blogapp/values-dev.yaml \
      --namespace dev \
      --set image.tag=dev-v2.1.1

    # Rollback si nécessaire
    helm rollback blogapp-dev 1 -n dev
    ```

    **Validation Complète**

    ```bash
    # 1. Vérifier que tout est déployé
    kubectl get all -n dev
    kubectl get all -n staging
    kubectl get all -n production

    # 2. Vérifier PostgreSQL
    kubectl get pods -l app.kubernetes.io/name=postgresql -n production

    # 3. Vérifier le Hook de migration
    kubectl get jobs -n production
    kubectl logs -l job-name -n production

    # 4. Vérifier l'Ingress (prod uniquement)
    kubectl get ingress -n production

    # 5. Test de l'application
    kubectl run test --rm -it --image=curlimages/curl -n production -- sh
    # Dans le pod:
    # curl http://blogapp-prod:80/health

    # 6. Historique des releases
    helm history blogapp-dev -n dev
    helm history blogapp-prod -n production
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
