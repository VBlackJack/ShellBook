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

```
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

## 5. Exercice Pratique

### Tâches

1. Configurer des probes sur un deployment
2. Installer le Metrics Server
3. Créer un HPA
4. Installer Prometheus avec Helm

### Validation

```bash
# Tester les probes
kubectl describe pod <pod-name> | grep -A10 "Liveness\|Readiness"

# Vérifier les métriques
kubectl top pods

# Vérifier le HPA
kubectl get hpa
kubectl describe hpa app-hpa
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
