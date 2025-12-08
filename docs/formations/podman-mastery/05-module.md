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

![Structure d'un Pod Podman](../../assets/diagrams/podman-pod-structure.jpeg)

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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Créer une application 3-tiers complète avec des pods Podman et générer un manifest Kubernetes pour la portabilité

    **Contexte** : Vous devez déployer une application e-commerce composée de plusieurs services : une base de données PostgreSQL, un cache Redis, une API backend, et un frontend Nginx. Tous ces services doivent communiquer via localhost dans un même pod. Vous générerez ensuite un manifest Kubernetes compatible pour faciliter la migration vers un cluster.

    **Tâches à réaliser** :

    1. Créer un pod avec les ports exposés nécessaires
    2. Déployer PostgreSQL avec persistance des données
    3. Ajouter Redis comme système de cache
    4. Déployer une API backend (simulée avec httpbin)
    5. Configurer Nginx comme reverse proxy et serveur frontend
    6. Vérifier la communication entre les conteneurs via localhost
    7. Générer un manifest Kubernetes depuis le pod
    8. Détruire le pod et le recréer depuis le manifest
    9. Valider que tout fonctionne après recréation

    **Critères de validation** :

    - [ ] Le pod contient 4 conteneurs actifs
    - [ ] PostgreSQL stocke les données dans un volume persistant
    - [ ] Tous les conteneurs communiquent via localhost
    - [ ] Nginx proxy les requêtes vers l'API
    - [ ] Le manifest Kubernetes est généré et valide
    - [ ] Le pod peut être recréé depuis le manifest

??? quote "Solution"
    Voici la solution complète pour créer une application multi-conteneurs :

    ```bash
    # 1. Créer le pod principal avec les ports exposés
    echo "=== Creating ecommerce pod ==="
    podman pod create \
      --name ecommerce \
      --publish 80:80 \
      --publish 8080:8080 \
      --network podman

    # Vérifier le pod vide
    podman pod ps
    podman pod inspect ecommerce | jq '.InfraConfig.PortBindings'

    # 2. Ajouter PostgreSQL avec volume persistant
    echo "=== Adding PostgreSQL database ==="
    podman run -d --pod ecommerce \
      --name db \
      -e POSTGRES_USER=ecommerce \
      -e POSTGRES_PASSWORD=SecureP@ss123 \
      -e POSTGRES_DB=shop \
      -v ecommerce-db:/var/lib/postgresql/data:Z \
      postgres:15-alpine

    # Attendre que PostgreSQL démarre
    sleep 5

    # Tester la connexion PostgreSQL
    podman exec -it db psql -U ecommerce -d shop -c "\l"

    # 3. Ajouter Redis pour le cache
    echo "=== Adding Redis cache ==="
    podman run -d --pod ecommerce \
      --name cache \
      redis:7-alpine \
      redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru

    # Tester Redis
    podman exec cache redis-cli ping
    # Réponse: PONG

    # 4. Ajouter l'API backend
    echo "=== Adding API backend ==="
    podman run -d --pod ecommerce \
      --name api \
      -e GUNICORN_CMD_ARGS="--bind=0.0.0.0:8080" \
      kennethreitz/httpbin

    # Attendre que l'API démarre
    sleep 3

    # 5. Créer la configuration Nginx
    echo "=== Configuring Nginx frontend ==="
    mkdir -p ~/podman-lab/ecommerce
    cat > ~/podman-lab/ecommerce/nginx.conf << 'EOF'
    server {
        listen 80;
        server_name localhost;

        # Page d'accueil
        location / {
            root /usr/share/nginx/html;
            index index.html;
        }

        # Proxy vers l'API (même pod = localhost!)
        location /api/ {
            proxy_pass http://127.0.0.1:8080/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # Health check
        location /health {
            access_log off;
            return 200 "healthy\n";
            add_header Content-Type text/plain;
        }
    }
    EOF

    # Créer une page HTML simple
    cat > ~/podman-lab/ecommerce/index.html << 'EOF'
    <!DOCTYPE html>
    <html>
    <head>
        <title>E-Commerce Demo</title>
        <style>
            body { font-family: Arial; margin: 50px; background: #f0f0f0; }
            h1 { color: #892CA0; }
            .card { background: white; padding: 20px; margin: 20px 0; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>E-Commerce Application - Podman Pod</h1>
        <div class="card">
            <h2>Architecture</h2>
            <ul>
                <li>Frontend: Nginx</li>
                <li>Backend API: httpbin</li>
                <li>Cache: Redis</li>
                <li>Database: PostgreSQL</li>
            </ul>
        </div>
        <div class="card">
            <h2>Test Links</h2>
            <ul>
                <li><a href="/api/get">API Test (GET)</a></li>
                <li><a href="/api/headers">Show Headers</a></li>
                <li><a href="/health">Health Check</a></li>
            </ul>
        </div>
    </body>
    </html>
    EOF

    # 6. Ajouter Nginx au pod
    podman run -d --pod ecommerce \
      --name frontend \
      -v ~/podman-lab/ecommerce/nginx.conf:/etc/nginx/conf.d/default.conf:ro,Z \
      -v ~/podman-lab/ecommerce/index.html:/usr/share/nginx/html/index.html:ro,Z \
      nginx:alpine

    # 7. Vérifier l'état du pod complet
    echo "=== Pod Status ==="
    podman pod ps
    podman ps --pod --filter pod=ecommerce

    # Statistiques du pod
    podman pod stats ecommerce --no-stream

    # 8. Tester l'application
    echo "=== Testing Application ==="

    # Page d'accueil
    curl -s http://localhost/ | grep "E-Commerce"

    # API via le proxy Nginx
    curl -s http://localhost/api/get | jq '.url'

    # Health check
    curl http://localhost/health

    # Tester la communication intra-pod
    podman exec api curl -s http://127.0.0.1:6379  # Redis (devrait échouer mais prouver la connectivité)
    podman exec cache redis-cli set test "hello from pod"
    podman exec cache redis-cli get test

    # 9. Générer le manifest Kubernetes
    echo "=== Generating Kubernetes manifest ==="
    podman generate kube --service ecommerce > ~/podman-lab/ecommerce/ecommerce-k8s.yaml

    # Afficher le manifest
    cat ~/podman-lab/ecommerce/ecommerce-k8s.yaml

    # Vérifier la structure
    grep -E "(apiVersion|kind|name:)" ~/podman-lab/ecommerce/ecommerce-k8s.yaml

    # 10. Test de portabilité : supprimer et recréer depuis le manifest
    echo "=== Testing Kubernetes manifest ==="

    # Sauvegarder les données actuelles
    podman exec db pg_dump -U ecommerce shop > ~/podman-lab/ecommerce/backup.sql

    # Supprimer le pod original
    podman pod stop ecommerce
    podman pod rm -f ecommerce

    # Vérifier qu'il n'existe plus
    podman pod ps -a

    # Recréer depuis le manifest
    podman play kube ~/podman-lab/ecommerce/ecommerce-k8s.yaml

    # Vérifier que le pod est recréé
    sleep 5
    podman pod ps
    podman ps --pod

    # Tester à nouveau
    curl -s http://localhost/ | grep "E-Commerce"
    curl -s http://localhost/api/headers | jq .headers

    # 11. Vérifier les logs du pod
    echo "=== Pod Logs ==="
    podman pod logs ecommerce --tail=20

    # Logs d'un conteneur spécifique
    podman logs ecommerce-frontend --tail=10

    # 12. Cleanup final
    echo "=== Cleanup ==="
    podman play kube --down ~/podman-lab/ecommerce/ecommerce-k8s.yaml
    podman volume rm ecommerce-db
    rm -rf ~/podman-lab/ecommerce

    echo "✓ Exercise completed successfully!"
    ```

    !!! success "Avantages des Pods"
        - **Communication localhost** : Pas besoin de découverte de service
        - **Déploiement atomique** : Tous les conteneurs démarrent/arrêtent ensemble
        - **Partage de ressources** : Network namespace, IPC, volumes partagés
        - **Compatible K8s** : Transition facile vers Kubernetes

    !!! tip "Communication dans un Pod"
        Dans un pod, tous les conteneurs partagent le network namespace :
        ```bash
        # Depuis n'importe quel conteneur du pod
        curl http://localhost:5432  # PostgreSQL
        curl http://localhost:6379  # Redis
        curl http://localhost:8080  # API
        curl http://localhost:80    # Nginx
        ```

    !!! note "Manifest Kubernetes généré"
        Le manifest généré contient :
        - **Service** : Expose les ports du pod
        - **Pod** : Définit les conteneurs et leurs configurations
        - **PersistentVolumeClaim** : Pour les volumes (si utilisés)

        Utilisable directement avec :
        ```bash
        kubectl apply -f ecommerce-k8s.yaml  # Sur Kubernetes
        podman play kube ecommerce-k8s.yaml  # Sur Podman
        ```

    !!! warning "Limitations"
        - Les pods Podman ne supportent pas tous les features K8s
        - Les init containers sont supportés mais limités
        - Les health checks doivent être configurés manuellement
        - Les resource limits peuvent différer

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

---

## Navigation

| | |
|:---|---:|
| [← Module 4 : Skopeo & Gestion des Regis...](04-module.md) | [Module 6 : Intégration Systemd →](06-module.md) |

[Retour au Programme](index.md){ .md-button }
