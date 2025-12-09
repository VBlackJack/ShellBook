---
tags:
  - formation
  - kubernetes
  - tp
  - production
---

# TP Final : Plateforme Production

## Objectifs

- Déployer une application complète production-ready
- Implémenter la haute disponibilité
- Configurer la sécurité end-to-end
- Mettre en place le monitoring et l'alerting

**Durée :** 2 heures

---

## Scénario

Vous êtes l'architecte Kubernetes chez **CloudShop**, une startup e-commerce. Vous devez déployer leur plateforme sur Kubernetes avec les exigences suivantes :

- Haute disponibilité (multi-replicas)
- Sécurité (RBAC, Network Policies, Pod Security)
- Observabilité (Prometheus, Grafana)
- GitOps ready

---

## Architecture

![Kubernetes TP Microservices Architecture](../../assets/diagrams/k8s-tp-microservices-architecture.jpeg)

```
ARCHITECTURE CLOUDSHOP
══════════════════════

                            ┌─────────────────┐
                            │   Ingress       │
                            │   Controller    │
                            └────────┬────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                │                │
                    ▼                ▼                ▼
             ┌──────────┐     ┌──────────┐     ┌──────────┐
             │ Frontend │     │   API    │     │  Admin   │
             │  (React) │     │  (Go)    │     │  (Vue)   │
             │  3 pods  │     │  5 pods  │     │  2 pods  │
             └────┬─────┘     └────┬─────┘     └──────────┘
                  │                │
                  │         ┌──────┴──────┐
                  │         │             │
                  │         ▼             ▼
                  │    ┌─────────┐   ┌─────────┐
                  │    │PostgreSQL│   │  Redis  │
                  │    │(StatefulSet)│ │(Cluster)│
                  │    │  3 pods  │   │ 3 pods  │
                  │    └─────────┘   └─────────┘
                  │
                  ▼
             ┌──────────┐
             │ CDN/S3   │
             │ (Static) │
             └──────────┘
```

---

## Partie 1 : Namespace et RBAC (20 min)

### 1.1 Créer les Namespaces

```yaml
# namespaces.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cloudshop-prod
  labels:
    name: cloudshop-prod
    environment: production
    pod-security.kubernetes.io/enforce: baseline
    pod-security.kubernetes.io/warn: restricted

---
apiVersion: v1
kind: Namespace
metadata:
  name: cloudshop-staging
  labels:
    name: cloudshop-staging
    environment: staging
```

### 1.2 RBAC

```yaml
# rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cloudshop-api
  namespace: cloudshop-prod

---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: cloudshop-api-role
  namespace: cloudshop-prod
rules:
  - apiGroups: [""]
    resources: ["configmaps", "secrets"]
    verbs: ["get", "list"]
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cloudshop-api-binding
  namespace: cloudshop-prod
subjects:
  - kind: ServiceAccount
    name: cloudshop-api
    namespace: cloudshop-prod
roleRef:
  kind: Role
  name: cloudshop-api-role
  apiGroup: rbac.authorization.k8s.io
```

---

## Partie 2 : Base de Données (25 min)

### 2.1 PostgreSQL StatefulSet

```yaml
# postgres.yaml
apiVersion: v1
kind: Secret
metadata:
  name: postgres-secret
  namespace: cloudshop-prod
type: Opaque
stringData:
  POSTGRES_USER: cloudshop
  POSTGRES_PASSWORD: "S3cur3P@ssw0rd!"
  POSTGRES_DB: cloudshop

---
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: cloudshop-prod
spec:
  clusterIP: None
  selector:
    app: postgres
  ports:
    - port: 5432

---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
  namespace: cloudshop-prod
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
        - name: postgres
          image: postgres:15-alpine
          ports:
            - containerPort: 5432
          envFrom:
            - secretRef:
                name: postgres-secret
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
          resources:
            requests:
              cpu: 250m
              memory: 512Mi
            limits:
              cpu: 1
              memory: 1Gi
          livenessProbe:
            exec:
              command: ["pg_isready", "-U", "cloudshop"]
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            exec:
              command: ["pg_isready", "-U", "cloudshop"]
            initialDelaySeconds: 5
            periodSeconds: 5
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 10Gi
```

### 2.2 Redis

```yaml
# redis.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: redis
  namespace: cloudshop-prod
spec:
  replicas: 1
  selector:
    matchLabels:
      app: redis
  template:
    metadata:
      labels:
        app: redis
    spec:
      containers:
        - name: redis
          image: redis:7-alpine
          ports:
            - containerPort: 6379
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
          readinessProbe:
            tcpSocket:
              port: 6379
            initialDelaySeconds: 5
            periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: redis
  namespace: cloudshop-prod
spec:
  selector:
    app: redis
  ports:
    - port: 6379
```

---

## Partie 3 : Application (30 min)

### 3.1 API Backend

```yaml
# api.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: api-config
  namespace: cloudshop-prod
data:
  DATABASE_HOST: postgres
  DATABASE_PORT: "5432"
  REDIS_HOST: redis
  REDIS_PORT: "6379"
  LOG_LEVEL: info

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
  namespace: cloudshop-prod
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      serviceAccountName: cloudshop-api
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: api
          image: cloudshop/api:v1.0.0
          ports:
            - containerPort: 8080
              name: http
          envFrom:
            - configMapRef:
                name: api-config
          env:
            - name: DATABASE_USER
              valueFrom:
                secretKeyRef:
                  name: postgres-secret
                  key: POSTGRES_USER
            - name: DATABASE_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgres-secret
                  key: POSTGRES_PASSWORD
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          livenessProbe:
            httpGet:
              path: /health/live
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /health/ready
              port: 8080
            initialDelaySeconds: 5
            periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: api
  namespace: cloudshop-prod
spec:
  selector:
    app: api
  ports:
    - port: 80
      targetPort: 8080
```

### 3.2 Frontend

```yaml
# frontend.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
  namespace: cloudshop-prod
spec:
  replicas: 2
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      containers:
        - name: frontend
          image: cloudshop/frontend:v1.0.0
          ports:
            - containerPort: 80
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 200m
              memory: 128Mi
          livenessProbe:
            httpGet:
              path: /
              port: 80
            initialDelaySeconds: 5
            periodSeconds: 10

---
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: cloudshop-prod
spec:
  selector:
    app: frontend
  ports:
    - port: 80
```

---

## Partie 4 : Ingress et Network Policies (15 min)

### 4.1 Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: cloudshop-ingress
  namespace: cloudshop-prod
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - cloudshop.example.com
        - api.cloudshop.example.com
      secretName: cloudshop-tls
  rules:
    - host: cloudshop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: frontend
                port:
                  number: 80
    - host: api.cloudshop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 80
```

### 4.2 Network Policies

```yaml
# network-policies.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: cloudshop-prod
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-policy
  namespace: cloudshop-prod
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: postgres
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - podSelector:
            matchLabels:
              app: redis
      ports:
        - protocol: TCP
          port: 6379
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: postgres-policy
  namespace: cloudshop-prod
spec:
  podSelector:
    matchLabels:
      app: postgres
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: api
      ports:
        - protocol: TCP
          port: 5432
```

---

## Partie 5 : Autoscaling et Monitoring (20 min)

### 5.1 HPA

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-hpa
  namespace: cloudshop-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api
  minReplicas: 3
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
```

### 5.2 ServiceMonitor

```yaml
# servicemonitor.yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: cloudshop-api
  namespace: monitoring
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app: api
  namespaceSelector:
    matchNames:
      - cloudshop-prod
  endpoints:
    - port: http
      path: /metrics
      interval: 30s
```

### 5.3 PrometheusRule

```yaml
# alerts.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: cloudshop-alerts
  namespace: monitoring
  labels:
    release: prometheus
spec:
  groups:
    - name: cloudshop.rules
      rules:
        - alert: CloudshopAPIDown
          expr: up{job="cloudshop-api"} == 0
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: "CloudShop API is down"

        - alert: CloudshopHighLatency
          expr: |
            histogram_quantile(0.95,
              sum(rate(http_request_duration_seconds_bucket{job="cloudshop-api"}[5m])) by (le)
            ) > 0.5
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "CloudShop API P95 latency > 500ms"
```

---

## Validation

### Checklist

- [ ] Namespaces créés avec Pod Security
- [ ] RBAC configuré
- [ ] PostgreSQL StatefulSet fonctionnel
- [ ] Redis déployé
- [ ] API avec probes et security context
- [ ] Frontend déployé
- [ ] Ingress avec TLS
- [ ] Network Policies appliquées
- [ ] HPA configuré
- [ ] ServiceMonitor actif

### Commandes de Vérification

```bash
# Vérifier les ressources
kubectl get all -n cloudshop-prod

# Tester la connectivité
kubectl run test --rm -it --image=busybox -n cloudshop-prod -- wget -qO- http://api/health/ready

# Vérifier les Network Policies
kubectl get networkpolicies -n cloudshop-prod

# Vérifier le HPA
kubectl get hpa -n cloudshop-prod

# Vérifier le monitoring
kubectl get servicemonitors -n monitoring
```

---

## Évaluation

| Critère | Points |
|---------|--------|
| Namespaces et RBAC | 15 |
| Base de données (PostgreSQL + Redis) | 20 |
| Application (API + Frontend) | 25 |
| Ingress et Network Policies | 20 |
| Autoscaling et Monitoring | 15 |
| Bonnes pratiques sécurité | 5 |

**Total : 100 points**
**Seuil de réussite : 70 points**

---

**Précédent :** [Module 11 - Troubleshooting](11-module.md)

**Retour au programme :** [Index](index.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 11 : Opérations et Troubleshoo...](11-module.md) | [Programme →](index.md) |

[Retour au Programme](index.md){ .md-button }
