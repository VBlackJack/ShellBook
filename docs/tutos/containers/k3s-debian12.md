---
tags:
  - tutos
  - containers
  - kubernetes
  - k3s
  - devops
  - debian
---

# K3s sur Debian 12

Installation de **K3s** sur Debian 12 Bookworm.

| Composant | Version |
|-----------|---------|
| Debian | 12 Bookworm |
| K3s | 1.28+ |

**Durée estimée :** 30 minutes

---

## 1. Prérequis

```bash
# Hostname
hostnamectl set-hostname k3s-master

# /etc/hosts
cat >> /etc/hosts << 'EOF'
192.168.1.10 k3s-master
192.168.1.11 k3s-worker-1
192.168.1.12 k3s-worker-2
EOF

# Désactiver swap
swapoff -a
sed -i '/swap/d' /etc/fstab

# Firewall
ufw allow 6443/tcp   # API
ufw allow 10250/tcp  # Kubelet
ufw allow 8472/udp   # Flannel
ufw reload
```

---

## 2. Installation Master

```bash
curl -sfL https://get.k3s.io | sh -

# Vérifier
systemctl status k3s
kubectl get nodes
```

### Avec options

```bash
curl -sfL https://get.k3s.io | sh -s - \
    --write-kubeconfig-mode 644 \
    --node-name k3s-master
```

---

## 3. Token

```bash
cat /var/lib/rancher/k3s/server/node-token
```

---

## 4. Workers

```bash
curl -sfL https://get.k3s.io | K3S_URL=https://k3s-master:6443 \
    K3S_TOKEN=<TOKEN> sh -s - \
    --node-name k3s-worker-1
```

```bash
kubectl get nodes
```

---

## 5. Déployer une app

```yaml
# app.yaml
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
  selector:
    app: nginx
```

```bash
kubectl apply -f app.yaml
kubectl get pods
kubectl get svc
```

---

## 6. Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nginx-ingress
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

---

## 7. Helm

```bash
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

helm repo add bitnami https://charts.bitnami.com/bitnami
helm install wordpress bitnami/wordpress
```

---

## 8. Stockage

```yaml
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

---

## 9. HA Cluster

```bash
# Master 1
curl -sfL https://get.k3s.io | sh -s - server --cluster-init

# Masters 2+
curl -sfL https://get.k3s.io | sh -s - server \
    --server https://k3s-master-1:6443 \
    --token <TOKEN>
```

---

## Comparatif Rocky vs Debian

| Aspect | Rocky 9 | Debian 12 |
|--------|---------|-----------|
| Firewall | firewalld | ufw |
| SELinux | Oui | Non |
| Installation | Identique | Identique |

---

## Commandes

```bash
kubectl get nodes              # Nœuds
kubectl get pods -A            # Tous les pods
kubectl logs pod-name          # Logs
kubectl exec -it pod -- sh     # Shell
kubectl top nodes              # Métriques
systemctl status k3s           # Service
journalctl -u k3s -f           # Logs K3s
```

---

## Désinstallation

```bash
/usr/local/bin/k3s-uninstall.sh        # Master
/usr/local/bin/k3s-agent-uninstall.sh  # Worker
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
