---
tags:
  - formation
  - kubernetes
  - configmaps
  - secrets
  - configuration
---

# Module 3 : Configuration et Secrets

## Objectifs du Module

- Gérer la configuration avec ConfigMaps
- Sécuriser les données sensibles avec Secrets
- Injecter la configuration dans les pods
- Implémenter les bonnes pratiques de gestion des secrets

**Durée :** 2 heures

---

## 1. ConfigMaps

### 1.1 Concept

```
CONFIGMAP - CONFIGURATION EXTERNALISÉE
══════════════════════════════════════

┌─────────────────────────────────────────────────────────────┐
│                       CONFIGMAP                              │
│                                                              │
│   Key-Value pairs ou fichiers de configuration              │
│                                                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  DATABASE_HOST=postgres                              │   │
│   │  DATABASE_PORT=5432                                  │   │
│   │  LOG_LEVEL=info                                      │   │
│   │  nginx.conf=<contenu du fichier>                    │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                              │
│   Utilisations :                                             │
│   - Variables d'environnement                               │
│   - Arguments de commande                                   │
│   - Fichiers de configuration montés                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Création de ConfigMaps

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  # Valeurs simples
  DATABASE_HOST: "postgres-service"
  DATABASE_PORT: "5432"
  LOG_LEVEL: "info"

  # Fichier de configuration inline
  config.json: |
    {
      "apiVersion": "v1",
      "debug": false,
      "features": {
        "newUI": true,
        "darkMode": false
      }
    }

  # Fichier nginx.conf
  nginx.conf: |
    server {
        listen 80;
        server_name localhost;
        location / {
            root /usr/share/nginx/html;
            index index.html;
        }
    }
```

```bash
# Création imperative
kubectl create configmap app-config \
  --from-literal=DATABASE_HOST=postgres \
  --from-literal=LOG_LEVEL=info

# Depuis un fichier
kubectl create configmap nginx-config \
  --from-file=nginx.conf

# Depuis un répertoire
kubectl create configmap config-dir \
  --from-file=./config/

# Depuis un fichier .env
kubectl create configmap env-config \
  --from-env-file=.env

# Vérifier
kubectl get configmap app-config -o yaml
kubectl describe configmap app-config
```

### 1.3 Utilisation dans les Pods

```yaml
# Pod avec ConfigMap
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  containers:
    - name: app
      image: myapp:1.0

      # Option 1: Variables d'environnement individuelles
      env:
        - name: DB_HOST
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: DATABASE_HOST
        - name: DB_PORT
          valueFrom:
            configMapKeyRef:
              name: app-config
              key: DATABASE_PORT

      # Option 2: Toutes les clés comme env vars
      envFrom:
        - configMapRef:
            name: app-config
          prefix: APP_  # Optionnel: préfixe les variables

      # Option 3: Volume monté
      volumeMounts:
        - name: config-volume
          mountPath: /etc/app/config
          readOnly: true

        - name: nginx-config
          mountPath: /etc/nginx/nginx.conf
          subPath: nginx.conf  # Monte un seul fichier

  volumes:
    - name: config-volume
      configMap:
        name: app-config
        items:  # Optionnel: sélectionner des clés
          - key: config.json
            path: config.json

    - name: nginx-config
      configMap:
        name: nginx-config
```

### 1.4 ConfigMap Immutable

```yaml
# ConfigMap immutable (K8s 1.21+)
apiVersion: v1
kind: ConfigMap
metadata:
  name: immutable-config
data:
  setting: "value"
immutable: true  # Ne peut plus être modifié
# Avantages: Performance (pas de watch), sécurité
```

---

## 2. Secrets

### 2.1 Types de Secrets

```
TYPES DE SECRETS KUBERNETES
═══════════════════════════

Opaque                  │ Données arbitraires (défaut)
kubernetes.io/tls       │ Certificats TLS
kubernetes.io/dockerconfigjson │ Credentials Docker registry
kubernetes.io/basic-auth │ Basic authentication
kubernetes.io/ssh-auth  │ SSH credentials
kubernetes.io/service-account-token │ Token Service Account
```

### 2.2 Création de Secrets

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials
type: Opaque
data:
  # Valeurs encodées en base64
  username: YWRtaW4=       # echo -n 'admin' | base64
  password: cGFzc3dvcmQxMjM=  # echo -n 'password123' | base64

---
# Avec stringData (plus lisible, encodé automatiquement)
apiVersion: v1
kind: Secret
metadata:
  name: db-credentials-v2
type: Opaque
stringData:
  username: admin
  password: password123
```

```bash
# Création imperative
kubectl create secret generic db-credentials \
  --from-literal=username=admin \
  --from-literal=password=password123

# Depuis un fichier
kubectl create secret generic tls-certs \
  --from-file=cert.pem \
  --from-file=key.pem

# Secret TLS
kubectl create secret tls my-tls-secret \
  --cert=tls.crt \
  --key=tls.key

# Docker registry
kubectl create secret docker-registry regcred \
  --docker-server=https://index.docker.io/v1/ \
  --docker-username=myuser \
  --docker-password=mypassword \
  --docker-email=my@email.com

# Vérifier (attention: données visibles!)
kubectl get secret db-credentials -o yaml
kubectl get secret db-credentials -o jsonpath='{.data.password}' | base64 -d
```

### 2.3 Utilisation dans les Pods

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: app-with-secrets
spec:
  containers:
    - name: app
      image: myapp:1.0

      # Variables d'environnement depuis Secret
      env:
        - name: DB_USERNAME
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: username
        - name: DB_PASSWORD
          valueFrom:
            secretKeyRef:
              name: db-credentials
              key: password

      # Ou toutes les clés
      envFrom:
        - secretRef:
            name: db-credentials

      # Volume monté (fichiers avec permissions 0400)
      volumeMounts:
        - name: secrets-volume
          mountPath: /etc/secrets
          readOnly: true

  volumes:
    - name: secrets-volume
      secret:
        secretName: db-credentials
        defaultMode: 0400  # Permissions restrictives

  # Pour les images privées
  imagePullSecrets:
    - name: regcred
```

### 2.4 Bonnes Pratiques Secrets

```yaml
# 1. RBAC restrictif
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["specific-secret"]  # Limiter aux secrets nécessaires
    verbs: ["get"]

---
# 2. Encryption at rest (kube-apiserver config)
# /etc/kubernetes/manifests/kube-apiserver.yaml
# --encryption-provider-config=/etc/kubernetes/encryption-config.yaml

# encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <BASE64_ENCODED_32_BYTE_KEY>
      - identity: {}
```

---

## 3. Gestion Avancée des Secrets

### 3.1 Sealed Secrets (Bitnami)

```bash
# Installation du controller
kubectl apply -f https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/controller.yaml

# Installation kubeseal CLI
wget https://github.com/bitnami-labs/sealed-secrets/releases/download/v0.24.0/kubeseal-0.24.0-linux-amd64.tar.gz
tar xzf kubeseal-0.24.0-linux-amd64.tar.gz
sudo mv kubeseal /usr/local/bin/

# Créer un SealedSecret
kubectl create secret generic my-secret \
  --from-literal=password=supersecret \
  --dry-run=client -o yaml | \
  kubeseal --format yaml > sealed-secret.yaml

# Le SealedSecret peut être versionné en Git
cat sealed-secret.yaml
# apiVersion: bitnami.com/v1alpha1
# kind: SealedSecret
# ...
```

### 3.2 External Secrets Operator

```yaml
# Installation
# helm install external-secrets external-secrets/external-secrets

# SecretStore (connexion au provider)
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: vault-backend
spec:
  provider:
    vault:
      server: "https://vault.example.com"
      path: "secret"
      auth:
        kubernetes:
          mountPath: "kubernetes"
          role: "my-role"

---
# ExternalSecret (synchronisation)
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: db-credentials
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: SecretStore
  target:
    name: db-credentials  # Secret K8s créé
  data:
    - secretKey: username
      remoteRef:
        key: secret/data/db
        property: username
    - secretKey: password
      remoteRef:
        key: secret/data/db
        property: password
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Gérer la configuration et les secrets d'une application de manière sécurisée

    **Contexte** : Vous devez déployer une application web qui se connecte à une base de données PostgreSQL. L'application nécessite des variables de configuration (environnement, log level, URL d'API) et des credentials sensibles (utilisateur et mot de passe de la base de données).

    **Tâches à réaliser** :

    1. Créer un ConfigMap contenant les variables de configuration de l'application
    2. Créer un Secret contenant les credentials de la base de données
    3. Déployer un pod qui utilise à la fois le ConfigMap et le Secret
    4. Vérifier que les variables sont correctement injectées dans le container
    5. Modifier le ConfigMap et observer si le pod récupère les nouveaux valeurs

    **Critères de validation** :

    - [ ] Le ConfigMap contient au moins 3 variables de configuration
    - [ ] Le Secret contient les credentials de manière sécurisée
    - [ ] Le pod démarre correctement et accède aux variables
    - [ ] Les variables d'environnement sont visibles dans le container
    - [ ] Le Secret n'est pas visible en clair dans les manifests

??? quote "Solution"
    **Étape 1 : Créer le ConfigMap**

    ```yaml
    # configmap.yaml
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: webapp-config
    data:
      APP_ENV: "production"
      LOG_LEVEL: "info"
      API_URL: "https://api.example.com"
      DATABASE_HOST: "postgres-service"
      DATABASE_PORT: "5432"
      DATABASE_NAME: "webapp_db"
    ```

    ```bash
    kubectl apply -f configmap.yaml
    kubectl describe configmap webapp-config
    ```

    **Étape 2 : Créer le Secret**

    ```yaml
    # secret.yaml
    apiVersion: v1
    kind: Secret
    metadata:
      name: webapp-secrets
    type: Opaque
    stringData:
      DB_USER: "webapp_user"
      DB_PASSWORD: "S3cur3P@ssw0rd!"
      API_KEY: "abc123def456"
    ```

    ```bash
    kubectl apply -f secret.yaml

    # Vérifier le secret (attention: données visibles!)
    kubectl get secret webapp-secrets -o yaml

    # Décoder une valeur
    kubectl get secret webapp-secrets -o jsonpath='{.data.DB_PASSWORD}' | base64 -d
    ```

    **Étape 3 : Déployer l'application**

    ```yaml
    # deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: webapp
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: webapp
      template:
        metadata:
          labels:
            app: webapp
        spec:
          containers:
            - name: app
              image: nginx:alpine
              # Injecter toutes les variables du ConfigMap
              envFrom:
                - configMapRef:
                    name: webapp-config
                # Injecter toutes les variables du Secret
                - secretRef:
                    name: webapp-secrets
              # Ou injecter des variables individuelles
              env:
                - name: SPECIAL_VAR
                  value: "custom-value"
              ports:
                - containerPort: 80
              resources:
                requests:
                  cpu: 50m
                  memory: 64Mi
                limits:
                  cpu: 100m
                  memory: 128Mi
    ```

    ```bash
    kubectl apply -f deployment.yaml
    kubectl get pods -l app=webapp
    ```

    **Étape 4 : Vérifier l'injection**

    ```bash
    # Récupérer le nom du pod
    POD=$(kubectl get pod -l app=webapp -o jsonpath='{.items[0].metadata.name}')

    # Afficher toutes les variables d'environnement
    kubectl exec $POD -- env | sort

    # Filtrer les variables injectées
    kubectl exec $POD -- env | grep -E "APP_|LOG_|API_|DATABASE_|DB_"

    # Vérifier qu'on voit bien les valeurs
    kubectl exec $POD -- sh -c 'echo "Environment: $APP_ENV"'
    kubectl exec $POD -- sh -c 'echo "DB User: $DB_USER"'
    ```

    **Étape 5 : Modifier le ConfigMap**

    ```bash
    # Modifier le ConfigMap
    kubectl edit configmap webapp-config
    # Changer LOG_LEVEL de "info" à "debug"

    # Les pods existants ne verront PAS automatiquement les changements
    # Il faut les redémarrer
    kubectl rollout restart deployment webapp

    # Attendre que le nouveau pod démarre
    kubectl rollout status deployment webapp

    # Vérifier la nouvelle valeur
    POD=$(kubectl get pod -l app=webapp -o jsonpath='{.items[0].metadata.name}')
    kubectl exec $POD -- env | grep LOG_LEVEL
    ```

    **Variante : Monter comme volumes**

    ```yaml
    # deployment-volumes.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: webapp-volumes
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: webapp-volumes
      template:
        metadata:
          labels:
            app: webapp-volumes
        spec:
          containers:
            - name: app
              image: nginx:alpine
              volumeMounts:
                # Monter le ConfigMap
                - name: config-volume
                  mountPath: /etc/config
                  readOnly: true
                # Monter le Secret
                - name: secret-volume
                  mountPath: /etc/secrets
                  readOnly: true
          volumes:
            - name: config-volume
              configMap:
                name: webapp-config
            - name: secret-volume
              secret:
                secretName: webapp-secrets
                defaultMode: 0400
    ```

    ```bash
    kubectl apply -f deployment-volumes.yaml
    POD=$(kubectl get pod -l app=webapp-volumes -o jsonpath='{.items[0].metadata.name}')

    # Voir les fichiers montés
    kubectl exec $POD -- ls -la /etc/config
    kubectl exec $POD -- cat /etc/config/APP_ENV
    kubectl exec $POD -- ls -la /etc/secrets
    ```

    **Nettoyage** :

    ```bash
    kubectl delete deployment webapp webapp-volumes
    kubectl delete configmap webapp-config
    kubectl delete secret webapp-secrets
    ```

---

## Quiz

1. **Comment encoder une valeur pour un Secret ?**
   - [ ] A. SHA256
   - [ ] B. Base64
   - [ ] C. MD5

2. **Quelle section utiliser pour des secrets lisibles dans le manifest ?**
   - [ ] A. data
   - [ ] B. stringData
   - [ ] C. plainData

3. **Quel outil permet de versionner des secrets chiffrés en Git ?**
   - [ ] A. ConfigMap
   - [ ] B. Sealed Secrets
   - [ ] C. PersistentVolume

**Réponses :** 1-B, 2-B, 3-B

---

**Précédent :** [Module 2 - Workloads](02-module.md)

**Suivant :** [Module 4 - Networking](04-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 2 : Workloads Fondamentaux](02-module.md) | [Module 4 : Networking →](04-module.md) |

[Retour au Programme](index.md){ .md-button }
