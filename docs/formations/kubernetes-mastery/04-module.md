---
tags:
  - formation
  - kubernetes
  - networking
  - services
  - ingress
---

# Module 4 : Networking

## Objectifs du Module

- Comprendre le modèle réseau Kubernetes
- Maîtriser les Services (ClusterIP, NodePort, LoadBalancer)
- Configurer les Ingress Controllers
- Implémenter des Network Policies

**Durée :** 4 heures

---

## 1. Modèle Réseau Kubernetes

### 1.1 Principes Fondamentaux

```
MODÈLE RÉSEAU KUBERNETES
════════════════════════

Règles fondamentales :
1. Tous les pods peuvent communiquer sans NAT
2. Tous les nodes peuvent communiquer avec tous les pods sans NAT
3. L'IP d'un pod est la même vue de l'intérieur et de l'extérieur

┌─────────────────────────────────────────────────────────────────┐
│                         CLUSTER                                  │
│                                                                  │
│   Pod Network CIDR: 10.244.0.0/16                               │
│   Service CIDR: 10.96.0.0/12                                    │
│                                                                  │
│   ┌─────────────────────┐   ┌─────────────────────┐            │
│   │      Node 1         │   │      Node 2         │            │
│   │                     │   │                     │            │
│   │  ┌───────┐ ┌───────┐│   │┌───────┐ ┌───────┐ │            │
│   │  │Pod A  │ │Pod B  ││   ││Pod C  │ │Pod D  │ │            │
│   │  │.1.5   │ │.1.6   ││   ││.2.3   │ │.2.4   │ │            │
│   │  └───────┘ └───────┘│   │└───────┘ └───────┘ │            │
│   │     10.244.1.0/24   │   │   10.244.2.0/24    │            │
│   └─────────────────────┘   └─────────────────────┘            │
│                                                                  │
│   Pod A (10.244.1.5) ←──────────────────→ Pod C (10.244.2.3)   │
│                     Communication directe                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 1.2 CNI Plugins

```bash
# CNI = Container Network Interface
# Plugins populaires:

# Calico - Le plus complet
# - Network Policies
# - BGP routing
# - IPIP ou VXLAN encapsulation

# Cilium - eBPF based
# - Network Policies avancées (L7)
# - Observabilité
# - Service mesh intégré

# Flannel - Simple
# - VXLAN overlay
# - Pas de Network Policies

# Weave - Mesh network
# - Encryption
# - Multicast

# Vérifier le CNI installé
ls /etc/cni/net.d/
kubectl get pods -n kube-system | grep -E "calico|cilium|flannel|weave"
```

---

## 2. Services

### 2.1 Types de Services

```
TYPES DE SERVICES
═════════════════

ClusterIP (défaut)
──────────────────
┌─────────────────────────────────────────┐
│ Accessible uniquement dans le cluster   │
│ IP virtuelle stable                     │
│ Load balancing vers les pods           │
└─────────────────────────────────────────┘

NodePort
────────
┌─────────────────────────────────────────┐
│ ClusterIP + port sur chaque node        │
│ Port: 30000-32767                       │
│ Accessible: <NodeIP>:<NodePort>        │
└─────────────────────────────────────────┘

LoadBalancer
────────────
┌─────────────────────────────────────────┐
│ NodePort + Load Balancer externe        │
│ Cloud provider ou MetalLB (bare metal)  │
│ IP externe attribuée                    │
└─────────────────────────────────────────┘

ExternalName
────────────
┌─────────────────────────────────────────┐
│ Alias DNS vers un service externe       │
│ Pas de proxy, juste CNAME              │
└─────────────────────────────────────────┘
```

### 2.2 Service ClusterIP

```yaml
# service-clusterip.yaml
apiVersion: v1
kind: Service
metadata:
  name: backend-service
spec:
  type: ClusterIP  # Défaut
  selector:
    app: backend
  ports:
    - name: http
      port: 80         # Port du service
      targetPort: 8080 # Port du container
      protocol: TCP
```

```bash
# DNS du service
# <service-name>.<namespace>.svc.cluster.local
# backend-service.default.svc.cluster.local

# Test depuis un pod
kubectl run test --rm -it --image=busybox -- sh
nslookup backend-service
wget -qO- http://backend-service
```

### 2.3 Service NodePort

```yaml
# service-nodeport.yaml
apiVersion: v1
kind: Service
metadata:
  name: frontend-service
spec:
  type: NodePort
  selector:
    app: frontend
  ports:
    - port: 80
      targetPort: 80
      nodePort: 30080  # Optionnel, sinon auto (30000-32767)
```

```bash
# Accès
curl http://<NODE_IP>:30080
```

### 2.4 Service LoadBalancer

```yaml
# service-loadbalancer.yaml
apiVersion: v1
kind: Service
metadata:
  name: public-service
  annotations:
    # Annotations spécifiques au cloud provider
    service.beta.kubernetes.io/aws-load-balancer-type: "nlb"
spec:
  type: LoadBalancer
  selector:
    app: public-app
  ports:
    - port: 443
      targetPort: 8443
  # Optionnel: IP spécifique
  loadBalancerIP: 1.2.3.4
  # Limiter les IPs sources
  loadBalancerSourceRanges:
    - 10.0.0.0/8
```

### 2.5 Headless Service

```yaml
# service-headless.yaml
apiVersion: v1
kind: Service
metadata:
  name: db-headless
spec:
  clusterIP: None  # Headless!
  selector:
    app: database
  ports:
    - port: 5432
```

```bash
# DNS retourne les IPs des pods directement
nslookup db-headless
# Server:    10.96.0.10
# Name:      db-headless.default.svc.cluster.local
# Address 1: 10.244.1.5 db-0.db-headless.default.svc.cluster.local
# Address 2: 10.244.2.3 db-1.db-headless.default.svc.cluster.local

# Utile pour StatefulSets et service discovery
```

---

## 3. Ingress

### 3.1 Concept

```
INGRESS - ROUTAGE HTTP/HTTPS
════════════════════════════

                    Internet
                        │
                        ▼
              ┌─────────────────┐
              │  Load Balancer  │
              │   (cloud/LB)    │
              └────────┬────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                    INGRESS CONTROLLER                         │
│              (nginx, traefik, haproxy...)                    │
│                                                               │
│   Rules:                                                      │
│   ┌───────────────────────────────────────────────────────┐  │
│   │ shop.example.com    → service: shop-frontend:80       │  │
│   │ api.example.com     → service: api-backend:8080       │  │
│   │ example.com/api/*   → service: api-backend:8080       │  │
│   │ example.com/*       → service: default-backend:80     │  │
│   └───────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
   ┌─────────┐   ┌─────────┐   ┌─────────┐
   │  shop   │   │   api   │   │ default │
   │ service │   │ service │   │ service │
   └─────────┘   └─────────┘   └─────────┘
```

### 3.2 Installation Ingress Controller

```bash
# Nginx Ingress Controller
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.8.2/deploy/static/provider/cloud/deploy.yaml

# Traefik (via Helm)
helm repo add traefik https://traefik.github.io/charts
helm install traefik traefik/traefik

# Vérifier
kubectl get pods -n ingress-nginx
kubectl get svc -n ingress-nginx
```

### 3.3 Manifest Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: main-ingress
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - example.com
        - api.example.com
      secretName: tls-secret
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: frontend
                port:
                  number: 80
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 8080

    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: api
                port:
                  number: 8080
```

### 3.4 Annotations Nginx Ingress

```yaml
metadata:
  annotations:
    # SSL/TLS
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"

    # Timeouts
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "30"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"

    # Body size
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"

    # Rate limiting
    nginx.ingress.kubernetes.io/limit-rps: "10"
    nginx.ingress.kubernetes.io/limit-connections: "5"

    # Auth
    nginx.ingress.kubernetes.io/auth-type: basic
    nginx.ingress.kubernetes.io/auth-secret: basic-auth
    nginx.ingress.kubernetes.io/auth-realm: "Authentication Required"

    # CORS
    nginx.ingress.kubernetes.io/enable-cors: "true"
    nginx.ingress.kubernetes.io/cors-allow-origin: "*"

    # Whitelist
    nginx.ingress.kubernetes.io/whitelist-source-range: "10.0.0.0/8"
```

---

## 4. Network Policies

### 4.1 Concept

```
NETWORK POLICIES - FIREWALL L3/L4
═════════════════════════════════

Par défaut: Tout le trafic est autorisé
Avec NetworkPolicy: Deny par défaut si appliqué

┌─────────────────────────────────────────────────────────────┐
│                      NAMESPACE: production                   │
│                                                              │
│   ┌─────────────┐       NetworkPolicy        ┌────────────┐ │
│   │   frontend  │ ───────ALLOW──────────────▶│  backend   │ │
│   │   pods      │       (port 8080)          │   pods     │ │
│   └─────────────┘                            └─────┬──────┘ │
│                                                    │        │
│                                              ALLOW │ 5432   │
│                                                    ▼        │
│                                              ┌────────────┐ │
│                                              │  database  │ │
│                                              │   pods     │ │
│                                              └────────────┘ │
│                                                              │
│   ┌─────────────┐                                           │
│   │  attacker   │ ─────X DENY X──────────▶ (tous les pods) │
│   └─────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Exemples Network Policies

```yaml
# Deny all ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: production
spec:
  podSelector: {}  # Tous les pods
  policyTypes:
    - Ingress

---
# Allow specific ingress
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: backend-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        # Depuis les pods frontend
        - podSelector:
            matchLabels:
              app: frontend
        # Depuis le namespace monitoring
        - namespaceSelector:
            matchLabels:
              name: monitoring
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        # Vers la base de données
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
    # Autoriser DNS
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
```

### 4.3 Patterns Courants

```yaml
# Allow from specific namespace
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-monitoring
spec:
  podSelector:
    matchLabels:
      app: api
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              purpose: monitoring

---
# Allow from specific CIDR
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-office
spec:
  podSelector:
    matchLabels:
      app: admin
  ingress:
    - from:
        - ipBlock:
            cidr: 192.168.1.0/24
            except:
              - 192.168.1.100/32
```

---

## 5. DNS et Service Discovery

### 5.1 CoreDNS

```bash
# Vérifier CoreDNS
kubectl get pods -n kube-system -l k8s-app=kube-dns
kubectl get configmap coredns -n kube-system -o yaml

# Format DNS
# <service>.<namespace>.svc.cluster.local
# <pod-ip-dashed>.<namespace>.pod.cluster.local

# Test DNS
kubectl run dns-test --rm -it --image=busybox:1.28 -- nslookup kubernetes.default
```

### 5.2 Personnalisation DNS

```yaml
# Pod avec DNS personnalisé
apiVersion: v1
kind: Pod
metadata:
  name: custom-dns
spec:
  dnsPolicy: "None"
  dnsConfig:
    nameservers:
      - 8.8.8.8
    searches:
      - default.svc.cluster.local
      - svc.cluster.local
    options:
      - name: ndots
        value: "5"
  containers:
    - name: app
      image: nginx
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Mettre en place une architecture réseau complète avec Services, Ingress et Network Policies

    **Contexte** : Vous devez déployer une application microservices composée d'un frontend React et d'un backend API. L'application doit être accessible depuis l'extérieur via un nom de domaine, et le réseau doit être sécurisé avec des Network Policies.

    **Tâches à réaliser** :

    1. Déployer un backend API avec un Service ClusterIP
    2. Déployer un frontend avec un Service ClusterIP
    3. Configurer un Ingress pour exposer le frontend et l'API sur des chemins différents
    4. Créer des Network Policies pour sécuriser la communication
    5. Tester la connectivité entre les composants

    **Critères de validation** :

    - [ ] Le backend est accessible uniquement en interne via son Service
    - [ ] Le frontend peut communiquer avec le backend
    - [ ] L'Ingress route correctement le trafic HTTP
    - [ ] Les Network Policies bloquent les communications non autorisées
    - [ ] Le DNS interne fonctionne correctement

??? quote "Solution"
    **Étape 1 : Déployer le backend API**

    ```yaml
    # backend-deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: backend-api
      labels:
        app: backend-api
    spec:
      replicas: 2
      selector:
        matchLabels:
          app: backend-api
      template:
        metadata:
          labels:
            app: backend-api
            tier: backend
        spec:
          containers:
            - name: api
              image: nginxdemos/hello:plain-text
              ports:
                - containerPort: 8080
              resources:
                requests:
                  cpu: 50m
                  memory: 64Mi
                limits:
                  cpu: 100m
                  memory: 128Mi

    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: backend-service
      labels:
        app: backend-api
    spec:
      type: ClusterIP
      selector:
        app: backend-api
      ports:
        - name: http
          port: 80
          targetPort: 8080
    ```

    ```bash
    kubectl apply -f backend-deployment.yaml
    kubectl get pods -l app=backend-api
    kubectl get svc backend-service
    ```

    **Étape 2 : Déployer le frontend**

    ```yaml
    # frontend-deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: frontend
      labels:
        app: frontend
    spec:
      replicas: 2
      selector:
        matchLabels:
          app: frontend
      template:
        metadata:
          labels:
            app: frontend
            tier: frontend
        spec:
          containers:
            - name: nginx
              image: nginx:alpine
              ports:
                - containerPort: 80
              resources:
                requests:
                  cpu: 50m
                  memory: 32Mi
                limits:
                  cpu: 100m
                  memory: 64Mi

    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: frontend-service
      labels:
        app: frontend
    spec:
      type: ClusterIP
      selector:
        app: frontend
      ports:
        - name: http
          port: 80
          targetPort: 80
    ```

    ```bash
    kubectl apply -f frontend-deployment.yaml
    kubectl get pods -l app=frontend
    kubectl get svc frontend-service
    ```

    **Étape 3 : Configurer l'Ingress**

    ```yaml
    # ingress.yaml
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: app-ingress
      annotations:
        nginx.ingress.kubernetes.io/rewrite-target: /
        nginx.ingress.kubernetes.io/ssl-redirect: "false"
    spec:
      ingressClassName: nginx
      rules:
        - host: myapp.local
          http:
            paths:
              - path: /
                pathType: Prefix
                backend:
                  service:
                    name: frontend-service
                    port:
                      number: 80
              - path: /api
                pathType: Prefix
                backend:
                  service:
                    name: backend-service
                    port:
                      number: 80
    ```

    ```bash
    kubectl apply -f ingress.yaml
    kubectl get ingress

    # Tester (depuis votre machine, ajouter myapp.local à /etc/hosts)
    # Pour minikube:
    minikube ip  # Noter l'IP

    # Ajouter à /etc/hosts: <MINIKUBE_IP> myapp.local
    curl http://myapp.local/
    curl http://myapp.local/api
    ```

    **Étape 4 : Network Policies**

    ```yaml
    # network-policies.yaml
    # 1. Deny all par défaut
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: default-deny-all
    spec:
      podSelector: {}
      policyTypes:
        - Ingress
        - Egress

    ---
    # 2. Autoriser le frontend à contacter le backend
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: frontend-to-backend
    spec:
      podSelector:
        matchLabels:
          app: frontend
      policyTypes:
        - Egress
      egress:
        - to:
            - podSelector:
                matchLabels:
                  app: backend-api
          ports:
            - protocol: TCP
              port: 8080
        # Autoriser DNS
        - to:
            - namespaceSelector: {}
              podSelector:
                matchLabels:
                  k8s-app: kube-dns
          ports:
            - protocol: UDP
              port: 53

    ---
    # 3. Autoriser le backend à recevoir du frontend
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: backend-ingress
    spec:
      podSelector:
        matchLabels:
          app: backend-api
      policyTypes:
        - Ingress
      ingress:
        - from:
            - podSelector:
                matchLabels:
                  app: frontend
          ports:
            - protocol: TCP
              port: 8080
        # Autoriser depuis l'ingress controller
        - from:
            - namespaceSelector:
                matchLabels:
                  name: ingress-nginx
          ports:
            - protocol: TCP
              port: 8080

    ---
    # 4. Autoriser le frontend depuis l'ingress
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: frontend-ingress
    spec:
      podSelector:
        matchLabels:
          app: frontend
      policyTypes:
        - Ingress
      ingress:
        - from:
            - namespaceSelector:
                matchLabels:
                  name: ingress-nginx
          ports:
            - protocol: TCP
              port: 80
    ```

    ```bash
    kubectl apply -f network-policies.yaml
    kubectl get networkpolicies
    kubectl describe networkpolicy frontend-to-backend
    ```

    **Étape 5 : Tests de connectivité**

    ```bash
    # Test DNS interne
    kubectl run test --rm -it --image=busybox -- nslookup backend-service
    kubectl run test --rm -it --image=busybox -- nslookup frontend-service

    # Test depuis un pod frontend vers backend (devrait fonctionner)
    FRONTEND_POD=$(kubectl get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')
    kubectl exec $FRONTEND_POD -- wget -qO- http://backend-service

    # Test depuis un pod externe (devrait échouer avec Network Policy)
    kubectl run test --rm -it --image=busybox -- wget -T 5 -qO- http://backend-service
    # Timeout attendu car bloqué par Network Policy

    # Test via Ingress (devrait fonctionner)
    curl http://myapp.local/
    curl http://myapp.local/api
    ```

    **Vérifications** :

    ```bash
    # Services et Endpoints
    kubectl get svc
    kubectl get endpoints

    # Ingress
    kubectl describe ingress app-ingress

    # Network Policies
    kubectl get networkpolicies
    kubectl describe networkpolicy backend-ingress

    # Pods et leur réseau
    kubectl get pods -o wide
    ```

    **Nettoyage** :

    ```bash
    kubectl delete deployment backend-api frontend
    kubectl delete service backend-service frontend-service
    kubectl delete ingress app-ingress
    kubectl delete networkpolicy --all
    ```

---

## Quiz

1. **Quel type de Service expose un port sur chaque node ?**
   - [ ] A. ClusterIP
   - [ ] B. NodePort
   - [ ] C. LoadBalancer

2. **Quel composant gère le routage HTTP/HTTPS ?**
   - [ ] A. Service
   - [ ] B. Ingress
   - [ ] C. NetworkPolicy

3. **Par défaut, sans NetworkPolicy, le trafic est :**
   - [ ] A. Bloqué
   - [ ] B. Autorisé
   - [ ] C. Journalisé

**Réponses :** 1-B, 2-B, 3-B

---

**Précédent :** [Module 3 - Configuration](03-module.md)

**Suivant :** [Module 5 - Stockage](05-module.md)
