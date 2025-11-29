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

## 4. Exercice Pratique

### Tâches

1. Créer un ConfigMap avec configuration applicative
2. Créer un Secret pour les credentials DB
3. Déployer une application utilisant les deux
4. Vérifier l'injection de configuration

### Solution

```yaml
# 1. ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-settings
data:
  APP_ENV: "production"
  LOG_LEVEL: "info"
  API_URL: "https://api.example.com"

---
# 2. Secret
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
stringData:
  DB_USER: "appuser"
  DB_PASS: "s3cr3tp@ss"

---
# 3. Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
    spec:
      containers:
        - name: app
          image: nginx
          envFrom:
            - configMapRef:
                name: app-settings
            - secretRef:
                name: app-secrets
```

```bash
# Vérification
kubectl exec -it <pod-name> -- env | grep -E "APP_|DB_|LOG_"
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
