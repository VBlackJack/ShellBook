---
tags:
  - formation
  - kubernetes
  - scheduling
  - affinity
  - taints
---

# Module 7 : Scheduling Avancé

## Objectifs du Module

- Configurer Node Selectors et Node Affinity
- Implémenter les Taints et Tolerations
- Gérer Pod Priority et Preemption
- Configurer Resource Quotas et Limits

**Durée :** 2 heures

---

## 1. Node Selector

```yaml
# Simple node selector
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod
spec:
  nodeSelector:
    gpu: "true"
    disktype: ssd
  containers:
    - name: gpu-app
      image: nvidia/cuda
```

```bash
# Labelliser les nodes
kubectl label nodes worker-1 gpu=true
kubectl label nodes worker-1 disktype=ssd

# Vérifier les labels
kubectl get nodes --show-labels
kubectl get nodes -l gpu=true
```

---

## 2. Node Affinity

```yaml
# Node Affinity - plus flexible que nodeSelector
apiVersion: v1
kind: Pod
metadata:
  name: affinity-pod
spec:
  affinity:
    nodeAffinity:
      # Required = must match (hard)
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
          - matchExpressions:
              - key: kubernetes.io/os
                operator: In
                values:
                  - linux
              - key: node-type
                operator: In
                values:
                  - compute
                  - gpu

      # Preferred = try to match (soft)
      preferredDuringSchedulingIgnoredDuringExecution:
        - weight: 80
          preference:
            matchExpressions:
              - key: zone
                operator: In
                values:
                  - eu-west-1a
        - weight: 20
          preference:
            matchExpressions:
              - key: instance-type
                operator: In
                values:
                  - m5.large
  containers:
    - name: app
      image: nginx
```

---

## 3. Pod Affinity et Anti-Affinity

```yaml
# Pod Affinity - scheduler avec d'autres pods
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
spec:
  replicas: 3
  selector:
    matchLabels:
      app: frontend
  template:
    metadata:
      labels:
        app: frontend
    spec:
      affinity:
        # Pod Affinity: scheduler près des pods backend
        podAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            - labelSelector:
                matchLabels:
                  app: backend
              topologyKey: kubernetes.io/hostname

        # Pod Anti-Affinity: éviter d'être sur le même node
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: frontend
                topologyKey: kubernetes.io/hostname
      containers:
        - name: frontend
          image: nginx
```

---

## 4. Taints et Tolerations

### 4.1 Concept

```
TAINTS & TOLERATIONS
════════════════════

Taint (sur le Node)         = "Repousse" les pods
Toleration (sur le Pod)     = "Tolère" un taint spécifique

Effects:
- NoSchedule     : Pas de scheduling de nouveaux pods
- PreferNoSchedule : Évite le scheduling si possible
- NoExecute      : Expulse les pods existants

┌─────────────────────────────────────────────────────────────┐
│                         NODE                                 │
│                                                              │
│   Taint: dedicated=gpu:NoSchedule                           │
│                                                              │
│   ┌─────────────┐                                           │
│   │   Pod A     │ ← Tolère gpu:NoSchedule → Schedulé       │
│   └─────────────┘                                           │
│                                                              │
│   ┌─────────────┐                                           │
│   │   Pod B     │ ← Pas de toleration → NON Schedulé       │
│   └─────────────┘                                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Configuration

```bash
# Ajouter un taint
kubectl taint nodes worker-1 dedicated=gpu:NoSchedule

# Voir les taints
kubectl describe node worker-1 | grep Taints

# Supprimer un taint
kubectl taint nodes worker-1 dedicated=gpu:NoSchedule-
```

```yaml
# Pod avec toleration
apiVersion: v1
kind: Pod
metadata:
  name: gpu-pod
spec:
  tolerations:
    - key: "dedicated"
      operator: "Equal"
      value: "gpu"
      effect: "NoSchedule"
    # Ou tolère toutes les valeurs
    - key: "dedicated"
      operator: "Exists"
      effect: "NoSchedule"
  containers:
    - name: app
      image: nvidia/cuda
```

---

## 5. Resource Quotas et LimitRange

### 5.1 ResourceQuota

```yaml
# Quota par namespace
apiVersion: v1
kind: ResourceQuota
metadata:
  name: compute-quota
  namespace: development
spec:
  hard:
    requests.cpu: "10"
    requests.memory: 20Gi
    limits.cpu: "20"
    limits.memory: 40Gi
    pods: "20"
    services: "10"
    persistentvolumeclaims: "10"
    requests.storage: 100Gi
```

### 5.2 LimitRange

```yaml
# Limites par défaut pour les containers
apiVersion: v1
kind: LimitRange
metadata:
  name: default-limits
  namespace: development
spec:
  limits:
    - type: Container
      default:
        cpu: "500m"
        memory: "256Mi"
      defaultRequest:
        cpu: "100m"
        memory: "128Mi"
      min:
        cpu: "50m"
        memory: "64Mi"
      max:
        cpu: "2"
        memory: "2Gi"

    - type: Pod
      max:
        cpu: "4"
        memory: "4Gi"

    - type: PersistentVolumeClaim
      min:
        storage: 1Gi
      max:
        storage: 50Gi
```

---

## 6. Pod Priority et Preemption

```yaml
# PriorityClass
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: high-priority
value: 1000000
globalDefault: false
preemptionPolicy: PreemptLowerPriority
description: "Critical workloads"

---
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: low-priority
value: 1000
preemptionPolicy: Never

---
# Pod avec priorité
apiVersion: v1
kind: Pod
metadata:
  name: critical-pod
spec:
  priorityClassName: high-priority
  containers:
    - name: app
      image: nginx
```

---

## 7. Exercice Pratique

### Tâches

1. Labelliser des nodes
2. Créer un pod avec node affinity
3. Configurer des taints et tolerations
4. Mettre en place des ResourceQuotas

### Validation

```bash
# Vérifier le scheduling
kubectl get pods -o wide
kubectl describe pod <pod-name> | grep -A5 Events

# Vérifier les quotas
kubectl describe resourcequota -n development
```

---

## Quiz

1. **Quel effet de taint expulse les pods existants ?**
   - [ ] A. NoSchedule
   - [ ] B. PreferNoSchedule
   - [ ] C. NoExecute

2. **Quelle affinity est obligatoire (hard) ?**
   - [ ] A. preferredDuringSchedulingIgnoredDuringExecution
   - [ ] B. requiredDuringSchedulingIgnoredDuringExecution
   - [ ] C. Les deux

**Réponses :** 1-C, 2-B

---

**Précédent :** [Module 6 - Sécurité](06-module.md)

**Suivant :** [Module 8 - Observabilité](08-module.md)
