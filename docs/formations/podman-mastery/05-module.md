---
tags:
  - formation
  - podman
  - pods
  - kubernetes
---

# Module 5 : Pods & Multi-Conteneurs

## Objectifs du Module

- Comprendre le concept de Pod
- Créer et gérer des pods multi-conteneurs
- Générer des manifests Kubernetes
- Utiliser podman play kube

**Durée :** 2 heures

---

## 1. Concept de Pod

```
POD : GROUPE DE CONTENEURS
═════════════════════════════════════════════════════════

┌─────────────────────────────────────────────────────┐
│                       POD                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │
│  │ Container 1 │  │ Container 2 │  │ Container 3 │  │
│  │   (nginx)   │  │   (php-fpm) │  │  (redis)    │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  │
│                                                      │
│  Partage :                                           │
│  ✓ Network namespace (même IP, localhost)           │
│  ✓ IPC namespace (shared memory)                    │
│  ✓ Volumes                                          │
│  ✗ PID namespace (optionnel)                        │
│                                                      │
│  IP: 10.88.0.5                                       │
│  Ports exposés: 80, 9000, 6379                      │
└─────────────────────────────────────────────────────┘

Avantages :
✓ Communication localhost entre conteneurs
✓ Déploiement atomique
✓ Compatible Kubernetes (même concept)
```

---

## 2. Création de Pods

### Créer un Pod Vide

```bash
# Créer un pod
podman pod create --name myapp-pod

# Créer avec options
podman pod create \
  --name webapp \
  --publish 8080:80 \
  --publish 5432:5432 \
  --network podman

# Lister les pods
podman pod ls

# Inspecter
podman pod inspect webapp
```

### Ajouter des Conteneurs au Pod

```bash
# Créer le pod
podman pod create --name lamp-stack -p 8080:80

# Ajouter nginx
podman run -d --pod lamp-stack --name web nginx:alpine

# Ajouter PHP-FPM
podman run -d --pod lamp-stack --name php php:fpm-alpine

# Ajouter Redis
podman run -d --pod lamp-stack --name cache redis:alpine

# Voir les conteneurs du pod
podman pod ps
podman ps --pod
```

### Gestion des Pods

```bash
# Démarrer/Arrêter tous les conteneurs du pod
podman pod start lamp-stack
podman pod stop lamp-stack
podman pod restart lamp-stack

# Supprimer le pod (et ses conteneurs)
podman pod rm -f lamp-stack

# Stats du pod
podman pod stats lamp-stack

# Logs de tous les conteneurs
podman pod logs lamp-stack
```

---

## 3. Communication Intra-Pod

```bash
# Créer un pod de test
podman pod create --name comm-test -p 8080:80

# Lancer nginx
podman run -d --pod comm-test --name nginx nginx:alpine

# Lancer un conteneur pour tester
podman run -it --rm --pod comm-test alpine sh

# Dans le conteneur :
# Les autres conteneurs sont accessibles via localhost
wget -qO- http://localhost:80
# Fonctionne! nginx répond sur localhost
```

### Exemple Pratique : WordPress

```bash
# Créer le pod
podman pod create \
  --name wordpress \
  -p 8080:80

# MySQL
podman run -d --pod wordpress \
  --name wp-db \
  -e MYSQL_ROOT_PASSWORD=rootpass \
  -e MYSQL_DATABASE=wordpress \
  -e MYSQL_USER=wpuser \
  -e MYSQL_PASSWORD=wppass \
  -v wp-db-data:/var/lib/mysql \
  mysql:8

# WordPress (connecté à MySQL via localhost!)
podman run -d --pod wordpress \
  --name wp-app \
  -e WORDPRESS_DB_HOST=127.0.0.1:3306 \
  -e WORDPRESS_DB_USER=wpuser \
  -e WORDPRESS_DB_PASSWORD=wppass \
  -e WORDPRESS_DB_NAME=wordpress \
  wordpress:latest

# Tester
curl http://localhost:8080
```

---

## 4. Génération de Manifests Kubernetes

### Générer depuis un Pod

```bash
# Créer un pod
podman pod create --name k8s-demo -p 8080:80
podman run -d --pod k8s-demo --name nginx nginx:alpine
podman run -d --pod k8s-demo --name redis redis:alpine

# Générer le manifest Kubernetes
podman generate kube k8s-demo > k8s-demo.yaml

# Voir le contenu
cat k8s-demo.yaml
```

### Exemple de Manifest Généré

```yaml
# k8s-demo.yaml (généré par podman generate kube)
apiVersion: v1
kind: Pod
metadata:
  labels:
    app: k8s-demo
  name: k8s-demo
spec:
  containers:
    - name: nginx
      image: docker.io/library/nginx:alpine
      ports:
        - containerPort: 80
          hostPort: 8080
      resources: {}
    - name: redis
      image: docker.io/library/redis:alpine
      resources: {}
  restartPolicy: Always
```

### Générer avec Services

```bash
# Générer pod + service
podman generate kube --service k8s-demo > k8s-demo-full.yaml
```

```yaml
# Service généré
apiVersion: v1
kind: Service
metadata:
  name: k8s-demo
spec:
  ports:
    - name: "80"
      port: 80
      targetPort: 80
  selector:
    app: k8s-demo
  type: ClusterIP
---
apiVersion: v1
kind: Pod
# ... (pod spec)
```

---

## 5. Podman Play Kube

### Déployer un Manifest Kubernetes

```bash
# Déployer depuis un fichier YAML
podman play kube k8s-demo.yaml

# Avec variables d'environnement
podman play kube --configmap cm.yaml deployment.yaml

# Déployer depuis une URL
podman play kube https://example.com/manifest.yaml

# Options utiles
podman play kube \
  --network mynetwork \
  --replace \
  --start \
  k8s-demo.yaml
```

### Exemple : Déployer une Stack Complète

```yaml
# stack.yaml
apiVersion: v1
kind: Pod
metadata:
  name: web-stack
  labels:
    app: web-stack
spec:
  containers:
    - name: nginx
      image: nginx:alpine
      ports:
        - containerPort: 80
          hostPort: 8080
      volumeMounts:
        - name: html
          mountPath: /usr/share/nginx/html

    - name: api
      image: python:3.11-alpine
      command: ["python", "-m", "http.server", "8000"]
      ports:
        - containerPort: 8000

  volumes:
    - name: html
      hostPath:
        path: /tmp/html
        type: DirectoryOrCreate
```

```bash
# Déployer
podman play kube stack.yaml

# Vérifier
podman pod ps
podman ps --pod

# Tester
curl http://localhost:8080

# Supprimer
podman play kube --down stack.yaml
```

### ConfigMaps et Secrets

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  APP_ENV: production
  LOG_LEVEL: info

---
# secret.yaml (base64 encoded)
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
data:
  DB_PASSWORD: c2VjcmV0MTIz  # secret123

---
# pod.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app
spec:
  containers:
    - name: app
      image: myapp:v1
      envFrom:
        - configMapRef:
            name: app-config
        - secretRef:
            name: app-secrets
```

```bash
# Déployer avec configmap et secret
podman play kube configmap.yaml secret.yaml pod.yaml
```

---

## 6. Cas d'Usage Avancés

### Pod avec Init Container

```yaml
# init-container.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-init
spec:
  initContainers:
    - name: init-db
      image: busybox
      command: ['sh', '-c', 'until nc -z localhost 5432; do sleep 2; done']

  containers:
    - name: app
      image: myapp:v1
      ports:
        - containerPort: 8080

    - name: db
      image: postgres:15-alpine
      env:
        - name: POSTGRES_PASSWORD
          value: secret
```

### Pod avec Sidecar Logging

```yaml
# sidecar-logging.yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-logging
spec:
  containers:
    - name: app
      image: nginx:alpine
      volumeMounts:
        - name: logs
          mountPath: /var/log/nginx

    - name: log-shipper
      image: fluent/fluent-bit:latest
      volumeMounts:
        - name: logs
          mountPath: /var/log/nginx
          readOnly: true

  volumes:
    - name: logs
      emptyDir: {}
```

---

## 7. Exercice Pratique

### Objectif

Créer une application 3-tiers avec pods et la convertir en manifest Kubernetes.

### Étapes

```bash
# 1. Créer le pod principal
podman pod create \
  --name ecommerce \
  -p 80:80 \
  -p 8080:8080

# 2. Ajouter la base de données
podman run -d --pod ecommerce \
  --name db \
  -e POSTGRES_USER=app \
  -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=shop \
  -v ecommerce-db:/var/lib/postgresql/data \
  postgres:15-alpine

# 3. Ajouter le cache Redis
podman run -d --pod ecommerce \
  --name cache \
  redis:7-alpine

# 4. Ajouter l'API (simulée avec httpbin)
podman run -d --pod ecommerce \
  --name api \
  kennethreitz/httpbin

# 5. Ajouter le frontend nginx
cat > /tmp/nginx-ecommerce.conf << 'EOF'
server {
    listen 80;
    location / {
        root /usr/share/nginx/html;
    }
    location /api/ {
        proxy_pass http://127.0.0.1:8080/;
    }
}
EOF

podman run -d --pod ecommerce \
  --name frontend \
  -v /tmp/nginx-ecommerce.conf:/etc/nginx/conf.d/default.conf:ro,Z \
  nginx:alpine

# 6. Vérifier le pod
echo "=== Pod Status ==="
podman pod ps
podman ps --pod --filter pod=ecommerce

# 7. Tester
echo "=== Testing ==="
curl -s http://localhost/api/get | jq .

# 8. Générer le manifest Kubernetes
echo "=== Generating Kubernetes manifest ==="
podman generate kube --service ecommerce > ecommerce-k8s.yaml
cat ecommerce-k8s.yaml

# 9. Supprimer et recréer depuis le manifest
echo "=== Recreating from manifest ==="
podman pod rm -f ecommerce
podman play kube ecommerce-k8s.yaml

# 10. Vérifier
podman pod ps

# Cleanup
podman play kube --down ecommerce-k8s.yaml
podman volume rm ecommerce-db
rm /tmp/nginx-ecommerce.conf ecommerce-k8s.yaml
```

---

## Quiz

1. **Qu'est-ce que les conteneurs d'un pod partagent ?**
   - [ ] A. Le filesystem uniquement
   - [ ] B. Le network namespace (même IP)
   - [ ] C. Les variables d'environnement

**Réponse :** B - Les conteneurs d'un pod partagent le network namespace (et optionnellement IPC/PID)

2. **Comment générer un manifest Kubernetes depuis un pod ?**
   - [ ] A. podman export kube
   - [ ] B. podman generate kube
   - [ ] C. podman create yaml

**Réponse :** B

3. **Comment déployer un manifest Kubernetes avec Podman ?**
   - [ ] A. podman apply -f
   - [ ] B. podman kube apply
   - [ ] C. podman play kube

**Réponse :** C

---

**Précédent :** [Module 4 - Skopeo](04-module.md)

**Suivant :** [Module 6 - Intégration Systemd](06-module.md)
