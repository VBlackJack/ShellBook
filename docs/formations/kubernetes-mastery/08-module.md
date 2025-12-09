---
tags:
  - formation
  - kubernetes
  - observability
  - monitoring
  - probes
---

# Module 8 : Observabilité

## Objectifs du Module

- Configurer les Probes (Liveness, Readiness, Startup)
- Déployer Prometheus sur Kubernetes
- Configurer le Metrics Server
- Implémenter le logging centralisé

**Durée :** 3 heures

---

## 1. Health Probes

### 1.1 Types de Probes

```text
KUBERNETES PROBES
═════════════════

Liveness Probe
──────────────
"Le container est-il vivant ?"
→ Si échec : Redémarrage du container

Readiness Probe
───────────────
"Le container est-il prêt à recevoir du trafic ?"
→ Si échec : Retiré du Service (plus de trafic)

Startup Probe
─────────────
"L'application a-t-elle démarré ?"
→ Désactive Liveness/Readiness pendant le démarrage
→ Pour les applications à démarrage lent
```

### 1.2 Configuration Complète

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-probes
spec:
  containers:
    - name: app
      image: myapp:1.0
      ports:
        - containerPort: 8080

      # Startup Probe - vérifie le démarrage
      startupProbe:
        httpGet:
          path: /health/startup
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 10
        failureThreshold: 30  # 30 * 10s = 5 min pour démarrer

      # Liveness Probe - vérifie que l'app est vivante
      livenessProbe:
        httpGet:
          path: /health/live
          port: 8080
          httpHeaders:
            - name: X-Custom-Header
              value: Probe
        initialDelaySeconds: 10
        periodSeconds: 5
        timeoutSeconds: 3
        failureThreshold: 3
        successThreshold: 1

      # Readiness Probe - vérifie que l'app est prête
      readinessProbe:
        httpGet:
          path: /health/ready
          port: 8080
        initialDelaySeconds: 5
        periodSeconds: 5
        failureThreshold: 3
```

### 1.3 Types de Probes

```yaml
# HTTP GET
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
    scheme: HTTP  # ou HTTPS

# TCP Socket
livenessProbe:
  tcpSocket:
    port: 3306

# Exec command
livenessProbe:
  exec:
    command:
      - cat
      - /tmp/healthy

# gRPC (K8s 1.24+)
livenessProbe:
  grpc:
    port: 50051
    service: health.v1.Health
```

---

## 2. Metrics Server

### 2.1 Installation

```bash
# Installation
kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

# Pour minikube/kind (TLS skip)
kubectl patch deployment metrics-server -n kube-system --type='json' -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--kubelet-insecure-tls"}]'

# Vérifier
kubectl top nodes
kubectl top pods
kubectl top pods -A --containers
```

### 2.2 HPA (Horizontal Pod Autoscaler)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: app-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: app
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
```

---

## 3. Prometheus sur Kubernetes

### 3.1 Installation avec Helm

```bash
# Ajouter le repo
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update

# Installation kube-prometheus-stack (recommandé)
helm install prometheus prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --create-namespace \
  --set grafana.adminPassword=admin123

# Vérifier
kubectl get pods -n monitoring

# Accéder à Grafana
kubectl port-forward svc/prometheus-grafana 3000:80 -n monitoring

# Accéder à Prometheus
kubectl port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090 -n monitoring
```

### 3.2 ServiceMonitor

```yaml
# ServiceMonitor pour scraper une application
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: app-monitor
  namespace: monitoring
  labels:
    release: prometheus  # Label pour que Prometheus le découvre
spec:
  selector:
    matchLabels:
      app: myapp
  namespaceSelector:
    matchNames:
      - default
  endpoints:
    - port: metrics
      path: /metrics
      interval: 30s
```

### 3.3 PrometheusRule

```yaml
# Règles d'alerte
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: app-alerts
  namespace: monitoring
  labels:
    release: prometheus
spec:
  groups:
    - name: app.rules
      rules:
        - alert: HighErrorRate
          expr: |
            sum(rate(http_requests_total{status=~"5.."}[5m])) by (service)
            / sum(rate(http_requests_total[5m])) by (service) > 0.05
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High error rate on {{ $labels.service }}"
```

---

## 4. Logging

### 4.1 Logs Kubernetes

```bash
# Logs d'un pod
kubectl logs <pod-name>
kubectl logs <pod-name> -c <container-name>
kubectl logs <pod-name> --previous
kubectl logs <pod-name> -f  # Follow

# Logs de tous les pods d'un deployment
kubectl logs -l app=nginx

# Logs avec timestamp
kubectl logs <pod-name> --timestamps
```

### 4.2 Loki Stack

```bash
# Installation avec Helm
helm repo add grafana https://grafana.github.io/helm-charts
helm install loki grafana/loki-stack \
  --namespace monitoring \
  --set grafana.enabled=true \
  --set promtail.enabled=true
```

---

## 5. Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer une application web avec observabilité complète (health probes, métriques, monitoring)

    **Contexte** : Vous devez déployer une API REST qui expose des métriques Prometheus et nécessite des health checks. L'application met 20 secondes à démarrer, se connecte à une base Redis, et doit pouvoir scale automatiquement selon la charge CPU.

    **Tâches à réaliser** :

    1. Créer un Deployment avec les trois types de probes configurées
    2. Installer le Metrics Server et vérifier son fonctionnement
    3. Configurer un HorizontalPodAutoscaler (2-10 replicas, 70% CPU)
    4. Installer Prometheus avec Helm et créer un ServiceMonitor
    5. Configurer une règle d'alerte pour le taux d'erreur HTTP

    **Critères de validation** :

    - [ ] Les pods démarrent correctement avec les probes
    - [ ] `kubectl top pods` affiche les métriques
    - [ ] Le HPA scale automatiquement sous charge
    - [ ] Prometheus scrape les métriques de l'application
    - [ ] L'alerte se déclenche en cas d'erreurs

??? quote "Solution"
    **Étape 1 : Deployment avec Probes**

    ```yaml
    # api-deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: api-backend
      labels:
        app: api-backend
    spec:
      replicas: 2
      selector:
        matchLabels:
          app: api-backend
      template:
        metadata:
          labels:
            app: api-backend
          annotations:
            prometheus.io/scrape: "true"
            prometheus.io/port: "8080"
            prometheus.io/path: "/metrics"
        spec:
          containers:
            - name: api
              image: mycompany/api-backend:1.0
              ports:
                - name: http
                  containerPort: 8080
                - name: metrics
                  containerPort: 8080

              # Startup Probe - 20s pour démarrer
              startupProbe:
                httpGet:
                  path: /health/startup
                  port: 8080
                initialDelaySeconds: 5
                periodSeconds: 5
                failureThreshold: 4  # 4 * 5s = 20s max

              # Liveness Probe - vérifie que l'app tourne
              livenessProbe:
                httpGet:
                  path: /health/live
                  port: 8080
                initialDelaySeconds: 10
                periodSeconds: 10
                timeoutSeconds: 3
                failureThreshold: 3

              # Readiness Probe - vérifie Redis
              readinessProbe:
                httpGet:
                  path: /health/ready
                  port: 8080
                initialDelaySeconds: 5
                periodSeconds: 5
                timeoutSeconds: 3

              resources:
                requests:
                  cpu: 100m
                  memory: 128Mi
                limits:
                  cpu: 500m
                  memory: 256Mi

              env:
                - name: REDIS_URL
                  value: "redis:6379"
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: api-backend
      labels:
        app: api-backend
    spec:
      selector:
        app: api-backend
      ports:
        - name: http
          port: 80
          targetPort: 8080
        - name: metrics
          port: 9090
          targetPort: 8080
    ```

    ```bash
    kubectl apply -f api-deployment.yaml

    # Vérifier les probes
    kubectl describe pod -l app=api-backend | grep -A10 "Liveness\|Readiness\|Startup"

    # Observer le démarrage
    kubectl get pods -l app=api-backend -w
    ```

    **Étape 2 : Installer Metrics Server**

    ```bash
    # Installation
    kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml

    # Pour minikube/kind (désactiver TLS)
    kubectl patch deployment metrics-server -n kube-system --type='json' \
      -p='[{"op": "add", "path": "/spec/template/spec/containers/0/args/-", "value": "--kubelet-insecure-tls"}]'

    # Attendre que le pod soit prêt
    kubectl wait --for=condition=Ready pod -l k8s-app=metrics-server -n kube-system --timeout=120s

    # Vérifier
    kubectl top nodes
    kubectl top pods -l app=api-backend
    ```

    **Étape 3 : Configurer le HPA**

    ```yaml
    # api-hpa.yaml
    apiVersion: autoscaling/v2
    kind: HorizontalPodAutoscaler
    metadata:
      name: api-backend-hpa
    spec:
      scaleTargetRef:
        apiVersion: apps/v1
        kind: Deployment
        name: api-backend
      minReplicas: 2
      maxReplicas: 10
      metrics:
        - type: Resource
          resource:
            name: cpu
            target:
              type: Utilization
              averageUtilization: 70
      behavior:
        scaleDown:
          stabilizationWindowSeconds: 300
          policies:
            - type: Percent
              value: 50
              periodSeconds: 60
        scaleUp:
          stabilizationWindowSeconds: 0
          policies:
            - type: Percent
              value: 100
              periodSeconds: 15
    ```

    ```bash
    kubectl apply -f api-hpa.yaml

    # Vérifier le HPA
    kubectl get hpa api-backend-hpa
    kubectl describe hpa api-backend-hpa

    # Générer de la charge (optionnel)
    kubectl run load-generator --image=busybox --restart=Never -- /bin/sh -c "while true; do wget -q -O- http://api-backend; done"

    # Observer le scaling
    kubectl get hpa api-backend-hpa -w
    ```

    **Étape 4 : Installer Prometheus**

    ```bash
    # Ajouter le repo Helm
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update

    # Installer kube-prometheus-stack
    helm install prometheus prometheus-community/kube-prometheus-stack \
      --namespace monitoring \
      --create-namespace \
      --set grafana.adminPassword=admin123 \
      --set prometheus.prometheusSpec.serviceMonitorSelectorNilUsesHelmValues=false

    # Attendre le déploiement
    kubectl wait --for=condition=Ready pods --all -n monitoring --timeout=300s

    # Accéder à Grafana
    kubectl port-forward svc/prometheus-grafana 3000:80 -n monitoring
    # Login: admin / admin123
    ```

    **Créer le ServiceMonitor**

    ```yaml
    # api-servicemonitor.yaml
    apiVersion: monitoring.coreos.com/v1
    kind: ServiceMonitor
    metadata:
      name: api-backend-monitor
      namespace: monitoring
      labels:
        release: prometheus
    spec:
      selector:
        matchLabels:
          app: api-backend
      namespaceSelector:
        matchNames:
          - default
      endpoints:
        - port: metrics
          path: /metrics
          interval: 30s
    ```

    ```bash
    kubectl apply -f api-servicemonitor.yaml

    # Vérifier dans Prometheus
    kubectl port-forward svc/prometheus-kube-prometheus-prometheus 9090:9090 -n monitoring
    # Ouvrir http://localhost:9090 et chercher "api_backend" dans les métriques
    ```

    **Étape 5 : Règle d'Alerte**

    ```yaml
    # api-alerts.yaml
    apiVersion: monitoring.coreos.com/v1
    kind: PrometheusRule
    metadata:
      name: api-backend-alerts
      namespace: monitoring
      labels:
        release: prometheus
    spec:
      groups:
        - name: api-backend.rules
          interval: 30s
          rules:
            - alert: HighErrorRate
              expr: |
                sum(rate(http_requests_total{service="api-backend",status=~"5.."}[5m]))
                / sum(rate(http_requests_total{service="api-backend"}[5m])) > 0.05
              for: 5m
              labels:
                severity: warning
                service: api-backend
              annotations:
                summary: "Taux d'erreur élevé sur api-backend"
                description: "{{ $value | humanizePercentage }} des requêtes échouent (>5%)"

            - alert: HighResponseTime
              expr: |
                histogram_quantile(0.95,
                  rate(http_request_duration_seconds_bucket{service="api-backend"}[5m])
                ) > 1
              for: 5m
              labels:
                severity: warning
                service: api-backend
              annotations:
                summary: "Temps de réponse élevé sur api-backend"
                description: "Le p95 est à {{ $value }}s (>1s)"
    ```

    ```bash
    kubectl apply -f api-alerts.yaml

    # Vérifier les règles
    kubectl get prometheusrule -n monitoring

    # Vérifier dans Prometheus UI
    # Alerts > Rules
    ```

    **Validation Complète**

    ```bash
    # 1. Vérifier les probes
    kubectl get pods -l app=api-backend
    kubectl describe pod -l app=api-backend | grep -A5 "Liveness\|Readiness"

    # 2. Vérifier les métriques
    kubectl top pods -l app=api-backend
    kubectl top nodes

    # 3. Vérifier le HPA
    kubectl get hpa
    kubectl describe hpa api-backend-hpa

    # 4. Vérifier Prometheus
    kubectl get servicemonitor -n monitoring
    kubectl get prometheusrule -n monitoring

    # 5. Test de bout en bout
    kubectl run test --rm -it --image=curlimages/curl -- sh
    # Dans le pod: curl http://api-backend/health/ready
    ```

---

## Quiz

1. **Quelle probe retire un pod du Service en cas d'échec ?**
   - [ ] A. Liveness
   - [ ] B. Readiness
   - [ ] C. Startup

2. **Quel composant fournit les métriques pour `kubectl top` ?**
   - [ ] A. Prometheus
   - [ ] B. Metrics Server
   - [ ] C. cAdvisor

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 7 - Scheduling](07-module.md)

**Suivant :** [Module 9 - Helm](09-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 7 : Scheduling Avancé](07-module.md) | [Module 9 : Helm et Packaging →](09-module.md) |

[Retour au Programme](index.md){ .md-button }
