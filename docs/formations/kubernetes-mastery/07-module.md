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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Maîtriser le scheduling avancé et la gestion des ressources

    **Contexte** : Vous gérez un cluster multi-tenants où certains nodes sont équipés de GPUs coûteux. Vous devez configurer le scheduling pour que seules les applications GPU soient placées sur ces nodes, et limiter la consommation de ressources par namespace.

    **Tâches à réaliser** :

    1. Labelliser un node comme "gpu-node"
    2. Appliquer un taint sur ce node pour repousser les pods normaux
    3. Créer un Deployment avec toleration pour utiliser les nodes GPU
    4. Configurer un ResourceQuota pour un namespace
    5. Créer un LimitRange avec des limites par défaut

    **Critères de validation** :

    - [ ] Le node GPU a les labels et taints appropriés
    - [ ] Les pods GPU sont schedulés uniquement sur les nodes GPU
    - [ ] Les pods normaux ne sont PAS schedulés sur les nodes GPU
    - [ ] Le ResourceQuota limite correctement les ressources
    - [ ] Le LimitRange applique des valeurs par défaut

??? quote "Solution"
    **Étape 1 : Labelliser et tainter le node**

    ```bash
    # Lister les nodes
    kubectl get nodes

    # Choisir un node et le labelliser (remplacer <node-name>)
    NODE_NAME=$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
    kubectl label nodes $NODE_NAME gpu=true
    kubectl label nodes $NODE_NAME node-type=gpu-enabled

    # Vérifier les labels
    kubectl get nodes --show-labels | grep gpu

    # Appliquer un taint
    kubectl taint nodes $NODE_NAME dedicated=gpu:NoSchedule

    # Vérifier le taint
    kubectl describe node $NODE_NAME | grep -A5 Taints
    ```

    **Étape 2 : Créer un namespace avec quotas**

    ```yaml
    # namespace-gpu.yaml
    apiVersion: v1
    kind: Namespace
    metadata:
      name: gpu-workloads

    ---
    apiVersion: v1
    kind: ResourceQuota
    metadata:
      name: gpu-quota
      namespace: gpu-workloads
    spec:
      hard:
        requests.cpu: "4"
        requests.memory: "8Gi"
        limits.cpu: "8"
        limits.memory: "16Gi"
        pods: "10"
        services: "5"

    ---
    apiVersion: v1
    kind: LimitRange
    metadata:
      name: gpu-limits
      namespace: gpu-workloads
    spec:
      limits:
        - type: Container
          default:
            cpu: "500m"
            memory: "512Mi"
          defaultRequest:
            cpu: "100m"
            memory: "128Mi"
          min:
            cpu: "50m"
            memory: "64Mi"
          max:
            cpu: "2"
            memory: "2Gi"
    ```

    ```bash
    kubectl apply -f namespace-gpu.yaml
    kubectl describe resourcequota gpu-quota -n gpu-workloads
    kubectl describe limitrange gpu-limits -n gpu-workloads
    ```

    **Étape 3 : Déployer une application GPU**

    ```yaml
    # gpu-deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: gpu-app
      namespace: gpu-workloads
    spec:
      replicas: 2
      selector:
        matchLabels:
          app: gpu-app
      template:
        metadata:
          labels:
            app: gpu-app
        spec:
          # NodeSelector pour cibler les nodes GPU
          nodeSelector:
            gpu: "true"
            node-type: gpu-enabled

          # Toleration pour le taint
          tolerations:
            - key: "dedicated"
              operator: "Equal"
              value: "gpu"
              effect: "NoSchedule"

          # Node Affinity (alternative/complément au nodeSelector)
          affinity:
            nodeAffinity:
              requiredDuringSchedulingIgnoredDuringExecution:
                nodeSelectorTerms:
                  - matchExpressions:
                      - key: gpu
                        operator: In
                        values:
                          - "true"

          containers:
            - name: app
              image: nvidia/cuda:11.8.0-base-ubuntu22.04
              command: ["sleep", "infinity"]
              resources:
                requests:
                  cpu: 200m
                  memory: 256Mi
                limits:
                  cpu: 500m
                  memory: 512Mi
    ```

    ```bash
    kubectl apply -f gpu-deployment.yaml

    # Vérifier que les pods sont sur le node GPU
    kubectl get pods -n gpu-workloads -o wide
    kubectl describe pod -n gpu-workloads -l app=gpu-app | grep Node:
    ```

    **Étape 4 : Déployer une application normale (sans GPU)**

    ```yaml
    # normal-deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: normal-app
      namespace: gpu-workloads
    spec:
      replicas: 2
      selector:
        matchLabels:
          app: normal-app
      template:
        metadata:
          labels:
            app: normal-app
        spec:
          # Pas de toleration = ne peut pas aller sur node GPU
          containers:
            - name: app
              image: nginx:alpine
              resources:
                requests:
                  cpu: 50m
                  memory: 64Mi
                limits:
                  cpu: 100m
                  memory: 128Mi
    ```

    ```bash
    kubectl apply -f normal-deployment.yaml

    # Vérifier que les pods NE SONT PAS sur le node GPU
    kubectl get pods -n gpu-workloads -o wide
    ```

    **Étape 5 : Test Pod Affinity/Anti-Affinity**

    ```yaml
    # affinity-deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: frontend
      namespace: gpu-workloads
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: frontend
      template:
        metadata:
          labels:
            app: frontend
            tier: frontend
        spec:
          # Anti-affinity: éviter de mettre 2 pods sur le même node
          affinity:
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
              image: nginx:alpine
              resources:
                requests:
                  cpu: 50m
                  memory: 32Mi
    ```

    ```bash
    kubectl apply -f affinity-deployment.yaml
    kubectl get pods -n gpu-workloads -l app=frontend -o wide
    ```

    **Étape 6 : Tester les quotas**

    ```bash
    # Vérifier l'utilisation du quota
    kubectl describe resourcequota gpu-quota -n gpu-workloads

    # Essayer de dépasser le quota
    kubectl create deployment quota-test --image=nginx --replicas=20 -n gpu-workloads

    # Observer que certains pods restent Pending
    kubectl get pods -n gpu-workloads

    # Voir pourquoi
    kubectl describe replicaset -n gpu-workloads | grep -A5 "exceeded quota"
    ```

    **Étape 7 : Test de PriorityClass**

    ```yaml
    # priority.yaml
    apiVersion: scheduling.k8s.io/v1
    kind: PriorityClass
    metadata:
      name: high-priority
    value: 1000000
    globalDefault: false
    description: "High priority for critical workloads"

    ---
    apiVersion: v1
    kind: Pod
    metadata:
      name: high-priority-pod
      namespace: gpu-workloads
    spec:
      priorityClassName: high-priority
      containers:
        - name: app
          image: nginx:alpine
    ```

    ```bash
    kubectl apply -f priority.yaml
    kubectl get priorityclass
    kubectl get pod high-priority-pod -n gpu-workloads -o yaml | grep priority
    ```

    **Vérifications** :

    ```bash
    # Nodes et labels
    kubectl get nodes --show-labels | grep gpu

    # Taints
    kubectl get nodes -o custom-columns=NAME:.metadata.name,TAINTS:.spec.taints

    # Scheduling des pods
    kubectl get pods -n gpu-workloads -o wide

    # Quotas et limites
    kubectl describe quota -n gpu-workloads
    kubectl describe limitrange -n gpu-workloads

    # Utilisation des ressources
    kubectl top nodes
    kubectl top pods -n gpu-workloads
    ```

    **Nettoyage** :

    ```bash
    # Supprimer le namespace
    kubectl delete namespace gpu-workloads

    # Supprimer le taint du node
    kubectl taint nodes $NODE_NAME dedicated=gpu:NoSchedule-

    # Supprimer les labels
    kubectl label nodes $NODE_NAME gpu- node-type-

    # Supprimer la PriorityClass
    kubectl delete priorityclass high-priority
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

---

## Navigation

| | |
|:---|---:|
| [← Module 6 : Sécurité et RBAC](06-module.md) | [Module 8 : Observabilité →](08-module.md) |

[Retour au Programme](index.md){ .md-button }
