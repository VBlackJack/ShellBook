---
tags:
  - tutos
  - containers
  - kubernetes
  - k3s
  - devops
  - rocky
---

# K3s sur Rocky Linux 9

Installation de **K3s**, distribution Kubernetes légère.

| Composant | Version |
|-----------|---------|
| Rocky Linux | 9.x |
| K3s | 1.28+ |

**Durée estimée :** 35 minutes

---

## K3s vs K8s

| Critère | K3s | K8s (vanilla) |
|---------|-----|---------------|
| RAM | ~512MB | ~2GB+ |
| Binaire | ~50MB | Multiple composants |
| Installation | 1 commande | Complexe |
| Base de données | SQLite/etcd | etcd |
| Cas d'usage | Edge, IoT, dev | Production |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         K3s Server                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │  API Server │  │  Scheduler  │  │ Controller  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │   Flannel   │  │  CoreDNS    │  │   Traefik   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│  K3s Agent  │       │  K3s Agent  │       │  K3s Agent  │
│   Worker 1  │       │   Worker 2  │       │   Worker 3  │
└─────────────┘       └─────────────┘       └─────────────┘
```

---

## 1. Prérequis

```bash
# Hostname unique
hostnamectl set-hostname k3s-master  # ou k3s-worker-1

# /etc/hosts
cat >> /etc/hosts << 'EOF'
192.168.1.10 k3s-master
192.168.1.11 k3s-worker-1
192.168.1.12 k3s-worker-2
EOF

# Désactiver swap
swapoff -a
sed -i '/swap/d' /etc/fstab

# Firewall (ou désactiver)
firewall-cmd --permanent --add-port=6443/tcp  # API
firewall-cmd --permanent --add-port=10250/tcp # Kubelet
firewall-cmd --permanent --add-port=8472/udp  # Flannel VXLAN
firewall-cmd --permanent --add-port=51820/udp # Flannel WireGuard
firewall-cmd --reload
```

---

## 2. Installation Master (Server)

### Installation simple

```bash
curl -sfL https://get.k3s.io | sh -

# Vérifier
systemctl status k3s
kubectl get nodes
```

### Installation avec options

```bash
curl -sfL https://get.k3s.io | sh -s - \
    --write-kubeconfig-mode 644 \
    --disable traefik \
    --node-name k3s-master \
    --cluster-init
```

### Options courantes

| Option | Description |
|--------|-------------|
| `--disable traefik` | Sans Traefik (installer autre ingress) |
| `--disable servicelb` | Sans LoadBalancer intégré |
| `--flannel-backend=wireguard` | Chiffrement réseau |
| `--cluster-init` | Mode HA avec etcd |
| `--tls-san IP` | Ajouter SAN au certificat |

---

## 3. Récupérer le token

```bash
cat /var/lib/rancher/k3s/server/node-token
```

---

## 4. Ajouter des Workers (Agents)

```bash
curl -sfL https://get.k3s.io | K3S_URL=https://k3s-master:6443 \
    K3S_TOKEN=<NODE_TOKEN> sh -s - \
    --node-name k3s-worker-1
```

### Vérifier le cluster

```bash
kubectl get nodes
```

---

## 5. kubectl local

### Sur le master

```bash
# Déjà configuré
kubectl get nodes
```

### Sur une machine externe

```bash
# Copier la config
scp root@k3s-master:/etc/rancher/k3s/k3s.yaml ~/.kube/config

# Modifier l'IP du serveur
sed -i 's/127.0.0.1/k3s-master/' ~/.kube/config

# Installer kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
mv kubectl /usr/local/bin/
```

---

## 6. Déployer une application

### Deployment

```yaml
# nginx-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:alpine
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: nginx
spec:
  type: LoadBalancer
  ports:
  - port: 80
    targetPort: 80
  selector:
    app: nginx
```

```bash
kubectl apply -f nginx-deployment.yaml
kubectl get pods
kubectl get svc
```

---

## 7. Ingress (Traefik)

### Activer Traefik (par défaut)

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nginx-ingress
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: web
spec:
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: nginx
            port:
              number: 80
```

```bash
kubectl apply -f ingress.yaml
```

---

## 8. Stockage persistant

### Local Path Provisioner (par défaut)

```yaml
# pvc.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: local-pvc
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: local-path
  resources:
    requests:
      storage: 5Gi
```

### Longhorn (recommandé)

```bash
kubectl apply -f https://raw.githubusercontent.com/longhorn/longhorn/master/deploy/longhorn.yaml

# Interface
kubectl -n longhorn-system get pods
```

---

## 9. Helm

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Exemple : installer WordPress
helm install wordpress bitnami/wordpress
```

---

## 10. Haute disponibilité (HA)

### Premier master

```bash
curl -sfL https://get.k3s.io | sh -s - server \
    --cluster-init \
    --tls-san k3s-vip \
    --node-name k3s-master-1
```

### Masters additionnels

```bash
curl -sfL https://get.k3s.io | sh -s - server \
    --server https://k3s-master-1:6443 \
    --token <TOKEN> \
    --tls-san k3s-vip \
    --node-name k3s-master-2
```

---

## 11. Monitoring

### Metrics Server (inclus)

```bash
kubectl top nodes
kubectl top pods
```

### Prometheus + Grafana

```bash
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm install prometheus prometheus-community/kube-prometheus-stack
```

---

## 12. Backup et restore

### Backup etcd

```bash
# K3s utilise SQLite par défaut
cp /var/lib/rancher/k3s/server/db/state.db /backup/

# Avec etcd
k3s etcd-snapshot save --name backup-$(date +%Y%m%d)
```

### Restore

```bash
k3s server --cluster-reset --cluster-reset-restore-path=/backup/snapshot.db
```

---

## Commandes utiles

```bash
# Status cluster
kubectl cluster-info
kubectl get nodes -o wide
kubectl get pods -A

# Logs
kubectl logs pod-name
kubectl logs -f deployment/nginx

# Shell dans un pod
kubectl exec -it pod-name -- /bin/sh

# Services K3s
systemctl status k3s
journalctl -u k3s -f

# Désinstaller
/usr/local/bin/k3s-uninstall.sh  # master
/usr/local/bin/k3s-agent-uninstall.sh  # worker
```

---

## Dépannage

```bash
# Logs K3s
journalctl -u k3s -f
journalctl -u k3s-agent -f

# Pods en erreur
kubectl describe pod pod-name
kubectl get events

# Network
kubectl run -it --rm debug --image=busybox -- sh
# ping, nslookup...

# Crictl (containerd)
crictl ps
crictl logs container-id
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
