---
tags:
  - formation
  - kubernetes
  - architecture
  - installation
---

# Module 1 : Architecture et Concepts

## Objectifs du Module

- Comprendre l'architecture Kubernetes
- Identifier les composants du Control Plane
- Comprendre le rôle des Worker Nodes
- Installer un cluster avec kubeadm

**Durée :** 3 heures

---

## 1. Vue d'Ensemble

### 1.1 Qu'est-ce que Kubernetes ?

```
KUBERNETES - ORCHESTRATEUR DE CONTAINERS
════════════════════════════════════════

Problématique                    Solution Kubernetes
─────────────                    ──────────────────

┌─────────────────┐              ┌─────────────────────────────┐
│ 100s de         │              │ Orchestration automatique   │
│ containers      │     →        │ - Scheduling                │
│ à gérer         │              │ - Self-healing              │
│                 │              │ - Scaling                   │
└─────────────────┘              │ - Rolling updates           │
                                 │ - Service discovery         │
┌─────────────────┐              │ - Load balancing            │
│ Multi-serveurs  │     →        │ - Storage orchestration     │
│ à coordonner    │              │ - Secret management         │
└─────────────────┘              └─────────────────────────────┘

Kubernetes = "K8s" (K + 8 lettres + s)
Origine: Google Borg → Kubernetes (2014, CNCF)
```

### 1.2 Concepts Clés

```
CONCEPTS FONDAMENTAUX
═════════════════════

CLUSTER
└── Un ensemble de machines (nodes) géré par Kubernetes

NODE
├── Control Plane (Master) : Gère le cluster
└── Worker : Exécute les workloads

POD
└── Plus petite unité déployable
    └── 1+ containers partageant réseau et storage

WORKLOADS
├── Deployment    : Applications stateless
├── StatefulSet   : Applications stateful
├── DaemonSet     : Un pod par node
├── Job/CronJob   : Tâches ponctuelles/planifiées
└── ReplicaSet    : Assure N réplicas (géré par Deployment)

SERVICES
├── ClusterIP     : IP interne au cluster
├── NodePort      : Expose sur un port de chaque node
├── LoadBalancer  : Load balancer externe
└── ExternalName  : Alias DNS

CONFIGURATION
├── ConfigMap     : Configuration non-sensible
├── Secret        : Données sensibles
└── PV/PVC        : Stockage persistant
```

---

## 2. Architecture du Control Plane

### 2.1 Vue d'Ensemble

```
CONTROL PLANE ARCHITECTURE
══════════════════════════

┌─────────────────────────────────────────────────────────────────┐
│                        CONTROL PLANE                             │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                      API SERVER                             │ │
│  │  - Point d'entrée unique (REST API)                        │ │
│  │  - Authentification / Autorisation                         │ │
│  │  - Validation des manifests                                │ │
│  │  - Communication avec etcd                                 │ │
│  └────────────────────────────────────────────────────────────┘ │
│         │              │              │              │           │
│         ▼              ▼              ▼              ▼           │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐ │
│  │   etcd   │   │Scheduler │   │Controller│   │ Cloud        │ │
│  │          │   │          │   │ Manager  │   │ Controller   │ │
│  │ Key-Value│   │ Assigne  │   │          │   │ Manager      │ │
│  │ Store    │   │ Pods aux │   │ Boucles  │   │ (optionnel)  │ │
│  │ (source  │   │ Nodes    │   │ de       │   │              │ │
│  │ of truth)│   │          │   │ contrôle │   │ Intégration  │ │
│  │          │   │          │   │          │   │ cloud        │ │
│  └──────────┘   └──────────┘   └──────────┘   └──────────────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 API Server

```yaml
# L'API Server est le cœur de Kubernetes
# Toutes les communications passent par lui

# Endpoints principaux
# /api/v1/namespaces
# /api/v1/pods
# /api/v1/services
# /apis/apps/v1/deployments

# Exemple de requête API
# kubectl get pods = GET /api/v1/namespaces/default/pods

# Vérifier la santé de l'API Server
kubectl get --raw='/healthz'
kubectl get --raw='/readyz'

# Lister les API disponibles
kubectl api-resources
kubectl api-versions
```

### 2.3 etcd

```bash
# etcd = base de données clé-valeur distribuée
# Stocke TOUT l'état du cluster

# Caractéristiques
# - Consensus Raft (haute disponibilité)
# - Données chiffrées au repos
# - Backup critique

# Accéder à etcd (en cas de debug)
ETCDCTL_API=3 etcdctl \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only | head -20

# Backup etcd
ETCDCTL_API=3 etcdctl snapshot save /backup/etcd-snapshot.db \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key

# Restaurer etcd
ETCDCTL_API=3 etcdctl snapshot restore /backup/etcd-snapshot.db \
  --data-dir=/var/lib/etcd-restored
```

### 2.4 Scheduler

```
SCHEDULER - ALGORITHME DE PLACEMENT
═══════════════════════════════════

1. FILTRAGE (Predicates)
   ────────────────────
   Exclure les nodes non viables :
   - Resources insuffisantes
   - NodeSelector non matching
   - Taints non tolérées
   - Affinity/Anti-affinity non respectée

2. SCORING (Priorities)
   ────────────────────
   Classer les nodes restants :
   - Équilibrage des resources
   - Préférences d'affinité
   - Spread des pods
   - Image déjà présente

3. BINDING
   ────────────────────
   Assigner le pod au node choisi
   (Mise à jour dans etcd via API Server)


   Pod créé                   Pod schedulé
      │                           │
      ▼                           ▼
┌──────────┐    Filter    ┌──────────────┐    Score    ┌────────┐
│ Pending  │ ───────────▶ │ Nodes viables│ ──────────▶ │ Binding│
└──────────┘              └──────────────┘             └────────┘
```

### 2.5 Controller Manager

```yaml
# Le Controller Manager exécute les boucles de contrôle
# Chaque controller surveille et réconcilie un type de ressource

# Controllers principaux :
# - ReplicaSet Controller : Maintient le nombre de replicas
# - Deployment Controller : Gère les rollouts
# - Node Controller : Surveille la santé des nodes
# - Service Controller : Gère les LoadBalancers cloud
# - Endpoint Controller : Peuple les Endpoints
# - Namespace Controller : Gère le cycle de vie des namespaces
# - ServiceAccount Controller : Crée les SA par défaut

# Boucle de contrôle (Reconciliation Loop)
#
#  ┌─────────────────────────────────────────────┐
#  │                                             │
#  ▼                                             │
# Observe ─────▶ Compare ─────▶ Act ─────────────┘
# (État actuel)  (vs désiré)   (Réconcilier)
```

---

## 3. Architecture des Worker Nodes

### 3.1 Composants

```
WORKER NODE ARCHITECTURE
════════════════════════

┌─────────────────────────────────────────────────────────────────┐
│                        WORKER NODE                               │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                       KUBELET                               │ │
│  │  - Agent principal sur chaque node                         │ │
│  │  - Reçoit les PodSpecs de l'API Server                    │ │
│  │  - Gère le cycle de vie des containers                    │ │
│  │  - Rapporte le status au Control Plane                    │ │
│  │  - Exécute les probes (liveness, readiness)               │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│                              ▼                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                  CONTAINER RUNTIME                          │ │
│  │  - containerd (défaut depuis K8s 1.24)                     │ │
│  │  - CRI-O                                                    │ │
│  │  - (Docker via dockershim - deprecated)                    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                              │                                   │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                      KUBE-PROXY                             │ │
│  │  - Gère les règles réseau (iptables/IPVS)                 │ │
│  │  - Permet la communication Service → Pod                   │ │
│  │  - Load balancing interne                                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                         CNI                                 │ │
│  │  - Plugin réseau (Calico, Cilium, Flannel, Weave)         │ │
│  │  - Assigne les IPs aux pods                                │ │
│  │  - Gère le routage inter-pods                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                        PODS                               │   │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐     │   │
│  │  │ Pod A   │  │ Pod B   │  │ Pod C   │  │ Pod D   │     │   │
│  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘     │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Kubelet

```bash
# Configuration kubelet
# /var/lib/kubelet/config.yaml

# Vérifier le status
systemctl status kubelet

# Logs kubelet
journalctl -u kubelet -f

# Configuration importante
cat /var/lib/kubelet/config.yaml
# - clusterDNS
# - clusterDomain
# - cgroupDriver (systemd recommandé)
# - containerRuntimeEndpoint

# Kubelet Static Pods
# /etc/kubernetes/manifests/
# Les pods définis ici sont gérés directement par kubelet
ls /etc/kubernetes/manifests/
# kube-apiserver.yaml
# kube-controller-manager.yaml
# kube-scheduler.yaml
# etcd.yaml
```

### 3.3 Container Runtime

```bash
# containerd est le runtime par défaut depuis K8s 1.24

# Vérifier containerd
systemctl status containerd
containerd --version

# CLI pour containerd
crictl ps
crictl images
crictl logs <container-id>

# Configuration containerd
cat /etc/containerd/config.toml

# Plugins CNI
ls /etc/cni/net.d/
ls /opt/cni/bin/
```

---

## 4. Installation avec kubeadm

### 4.1 Prérequis

```bash
# Sur TOUS les nodes (control plane + workers)

# 1. Désactiver le swap
sudo swapoff -a
sudo sed -i '/ swap / s/^/#/' /etc/fstab

# 2. Charger les modules kernel
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

# 3. Paramètres sysctl
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

sudo sysctl --system

# 4. Installer containerd
sudo apt-get update
sudo apt-get install -y containerd

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml

# Configurer SystemdCgroup = true
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl restart containerd
sudo systemctl enable containerd
```

### 4.2 Installation kubeadm, kubelet, kubectl

```bash
# Ajouter le repo Kubernetes
sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl

curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg

echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list

# Installer les composants
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

# Vérifier
kubeadm version
kubectl version --client
kubelet --version
```

### 4.3 Initialisation du Control Plane

```bash
# Sur le node Control Plane uniquement

# Initialiser le cluster
sudo kubeadm init \
  --pod-network-cidr=10.244.0.0/16 \
  --apiserver-advertise-address=<IP_CONTROL_PLANE>

# Configurer kubectl pour l'utilisateur courant
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

# Vérifier le cluster
kubectl cluster-info
kubectl get nodes
# STATUS = NotReady (pas encore de CNI)

# Installer un CNI (Calico)
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calico.yaml

# Ou Flannel
kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml

# Vérifier que le node passe Ready
kubectl get nodes
# STATUS = Ready
```

### 4.4 Joindre les Worker Nodes

```bash
# Sur chaque Worker Node

# Utiliser la commande affichée par kubeadm init
sudo kubeadm join <IP_CONTROL_PLANE>:6443 \
  --token <TOKEN> \
  --discovery-token-ca-cert-hash sha256:<HASH>

# Si le token a expiré, en créer un nouveau (sur le control plane)
kubeadm token create --print-join-command

# Vérifier depuis le control plane
kubectl get nodes
# Tous les nodes doivent être Ready
```

### 4.5 Configuration Post-Installation

```bash
# Autoriser le scheduling sur le control plane (optionnel, dev only)
kubectl taint nodes --all node-role.kubernetes.io/control-plane-

# Vérifier les pods système
kubectl get pods -n kube-system

# Déployer un test
kubectl create deployment nginx --image=nginx
kubectl expose deployment nginx --port=80 --type=NodePort
kubectl get svc nginx

# Accéder via NodePort
curl http://<NODE_IP>:<NODE_PORT>
```

---

## 5. Alternatives d'Installation

### 5.1 minikube (Local Dev)

```bash
# Installation minikube
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Démarrer un cluster
minikube start --driver=docker --cpus=2 --memory=4096

# Addons utiles
minikube addons enable ingress
minikube addons enable metrics-server
minikube addons enable dashboard

# Dashboard
minikube dashboard

# Accéder aux services
minikube service <service-name>

# Tunnel pour LoadBalancer
minikube tunnel
```

### 5.2 kind (Kubernetes IN Docker)

```bash
# Installation kind
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# Créer un cluster simple
kind create cluster

# Cluster multi-nodes
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
- role: worker
EOF

# Charger une image dans kind
kind load docker-image my-app:latest
```

### 5.3 k3s (Lightweight)

```bash
# Installation k3s (single node)
curl -sfL https://get.k3s.io | sh -

# Vérifier
sudo k3s kubectl get nodes

# Copier la config
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER ~/.kube/config

# Ajouter un agent (worker)
# Sur le server, récupérer le token
sudo cat /var/lib/rancher/k3s/server/node-token

# Sur le worker
curl -sfL https://get.k3s.io | K3S_URL=https://<SERVER_IP>:6443 K3S_TOKEN=<TOKEN> sh -
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Installer et explorer votre premier cluster Kubernetes

    **Contexte** : Vous devez mettre en place un environnement Kubernetes local pour comprendre son architecture et ses composants fondamentaux.

    **Tâches à réaliser** :

    1. Installer un cluster Kubernetes avec minikube ou kind
    2. Explorer les composants du Control Plane dans le namespace kube-system
    3. Vérifier la communication avec l'API Server et lister les ressources disponibles
    4. Créer votre premier déploiement nginx et examiner son cycle de vie
    5. Identifier sur quel node le pod a été schedulé et pourquoi

    **Critères de validation** :

    - [ ] Cluster opérationnel avec status "Ready"
    - [ ] Tous les composants du Control Plane sont Running
    - [ ] L'API Server répond correctement aux requêtes
    - [ ] Le pod nginx est déployé et accessible
    - [ ] Vous pouvez expliquer le rôle de chaque composant observé

??? quote "Solution"
    **Étape 1 : Installation du cluster**

    ```bash
    # Option 1: minikube
    minikube start --driver=docker --cpus=2 --memory=4096

    # Option 2: kind
    kind create cluster --name demo
    ```

    **Étape 2 : Explorer les composants du Control Plane**

    ```bash
    # Lister les pods système
    kubectl get pods -n kube-system

    # Détails de l'API Server
    kubectl describe pod -n kube-system -l component=kube-apiserver

    # Détails du Scheduler
    kubectl describe pod -n kube-system -l component=kube-scheduler

    # Détails du Controller Manager
    kubectl describe pod -n kube-system -l component=kube-controller-manager

    # Détails d'etcd
    kubectl describe pod -n kube-system -l component=etcd
    ```

    **Étape 3 : Vérifier l'API Server**

    ```bash
    # Informations du cluster
    kubectl cluster-info

    # Santé de l'API
    kubectl get --raw='/healthz'
    kubectl get --raw='/readyz'

    # Lister toutes les ressources API disponibles
    kubectl api-resources | head -20

    # Versions des APIs
    kubectl api-versions
    ```

    **Étape 4 : Premier déploiement**

    ```bash
    # Créer un déploiement nginx
    kubectl create deployment nginx --image=nginx:1.25

    # Vérifier le déploiement
    kubectl get deployments
    kubectl get replicasets
    kubectl get pods

    # Examiner en détail
    kubectl describe pod nginx-<pod-id>

    # Voir les événements
    kubectl get events --sort-by=.metadata.creationTimestamp
    ```

    **Étape 5 : Analyse du scheduling**

    ```bash
    # Identifier le node
    kubectl get pods -o wide

    # Examiner les événements de scheduling
    kubectl describe pod nginx-<pod-id> | grep -A5 Events

    # Information sur le node
    kubectl describe node <node-name>
    ```

    **Explication** : Le Scheduler a assigné le pod au node en fonction des ressources disponibles (CPU, mémoire) et des contraintes éventuelles (nodeSelector, affinity, taints).

---

## Quiz

1. **Quel composant stocke l'état du cluster ?**
   - [ ] A. API Server
   - [ ] B. etcd
   - [ ] C. Controller Manager

2. **Quel composant assigne les pods aux nodes ?**
   - [ ] A. Kubelet
   - [ ] B. Scheduler
   - [ ] C. Kube-proxy

3. **Quel est le runtime container par défaut depuis K8s 1.24 ?**
   - [ ] A. Docker
   - [ ] B. containerd
   - [ ] C. CRI-O

4. **Quelle commande initialise un cluster avec kubeadm ?**
   - [ ] A. kubeadm create
   - [ ] B. kubeadm init
   - [ ] C. kubeadm start

**Réponses :** 1-B, 2-B, 3-B, 4-B

---

**Suivant :** [Module 2 - Workloads](02-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Programme](index.md) | [Module 2 : Workloads Fondamentaux →](02-module.md) |

[Retour au Programme](index.md){ .md-button }
