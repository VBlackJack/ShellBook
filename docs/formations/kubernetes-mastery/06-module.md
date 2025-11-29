---
tags:
  - formation
  - kubernetes
  - security
  - rbac
  - pod-security
---

# Module 6 : Sécurité et RBAC

## Objectifs du Module

- Comprendre l'authentification et l'autorisation Kubernetes
- Configurer RBAC (Roles, ClusterRoles, Bindings)
- Gérer les Service Accounts
- Implémenter les Pod Security Standards

**Durée :** 4 heures

---

## 1. Authentification

### 1.1 Méthodes d'Authentification

```
AUTHENTIFICATION KUBERNETES
═══════════════════════════

┌─────────────────────────────────────────────────────────────┐
│                      API SERVER                              │
│                                                              │
│   Authentication Plugins (dans l'ordre):                    │
│                                                              │
│   1. Client Certificates (X509)                             │
│      └─ CN=user, O=group                                    │
│                                                              │
│   2. Bearer Tokens                                          │
│      ├─ Service Account Tokens                              │
│      ├─ Bootstrap Tokens                                    │
│      └─ OIDC Tokens                                         │
│                                                              │
│   3. Authentication Proxy                                   │
│      └─ X-Remote-User header                                │
│                                                              │
│   4. Webhook Token Authentication                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Créer un Utilisateur avec Certificat

```bash
# Générer une clé privée
openssl genrsa -out john.key 2048

# Créer un CSR
openssl req -new -key john.key -out john.csr -subj "/CN=john/O=developers"

# Créer un CertificateSigningRequest Kubernetes
cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: john-csr
spec:
  request: $(cat john.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages:
    - client auth
EOF

# Approuver le CSR
kubectl certificate approve john-csr

# Récupérer le certificat
kubectl get csr john-csr -o jsonpath='{.status.certificate}' | base64 -d > john.crt

# Configurer kubectl pour John
kubectl config set-credentials john \
  --client-certificate=john.crt \
  --client-key=john.key

kubectl config set-context john-context \
  --cluster=kubernetes \
  --user=john \
  --namespace=default

# Tester
kubectl --context=john-context get pods
```

---

## 2. RBAC

### 2.1 Concept

```
RBAC - ROLE-BASED ACCESS CONTROL
════════════════════════════════

┌────────────────────────────────────────────────────────────────┐
│                                                                 │
│   WHO (Subject)          WHAT (Role)         WHERE (Binding)   │
│   ─────────────          ──────────          ───────────────   │
│                                                                 │
│   ┌─────────┐            ┌─────────┐         ┌──────────────┐  │
│   │  User   │◄───────────│  Role   │◄────────│ RoleBinding  │  │
│   │  Group  │            │(namespace)│        │ (namespace)  │  │
│   │  SA     │            └─────────┘         └──────────────┘  │
│   └─────────┘                                                   │
│                          ┌─────────────┐     ┌──────────────┐  │
│                          │ClusterRole  │◄────│ClusterRole   │  │
│                          │(cluster-wide)│     │Binding       │  │
│                          └─────────────┘     │(cluster-wide)│  │
│                                              └──────────────┘  │
│                                                                 │
│   Role = Permissions (verbs sur resources)                     │
│   Binding = Lie un Subject à un Role                           │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### 2.2 Role et RoleBinding (Namespace-scoped)

```yaml
# role.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: development
rules:
  - apiGroups: [""]  # "" = core API group
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]

  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]

  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list"]
    resourceNames: ["my-deployment"]  # Optionnel: ressources spécifiques

---
# rolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: development
subjects:
  - kind: User
    name: john
    apiGroup: rbac.authorization.k8s.io
  - kind: Group
    name: developers
    apiGroup: rbac.authorization.k8s.io
  - kind: ServiceAccount
    name: ci-bot
    namespace: development
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
```

### 2.3 ClusterRole et ClusterRoleBinding

```yaml
# clusterrole.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-admin-readonly
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]

  - nonResourceURLs: ["/healthz", "/version"]
    verbs: ["get"]

---
# clusterrolebinding.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-readonly-binding
subjects:
  - kind: Group
    name: auditors
    apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: cluster-admin-readonly
  apiGroup: rbac.authorization.k8s.io
```

### 2.4 Verbs RBAC

```yaml
# Verbs disponibles
verbs:
  - get        # Lire une ressource spécifique
  - list       # Lister les ressources
  - watch      # Watch pour changements
  - create     # Créer une ressource
  - update     # Mettre à jour entièrement
  - patch      # Mettre à jour partiellement
  - delete     # Supprimer une ressource
  - deletecollection  # Supprimer plusieurs ressources

# Raccourcis
verbs: ["*"]  # Tous les verbs
```

### 2.5 Aggregated ClusterRoles

```yaml
# ClusterRole agrégé
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring-endpoints
  labels:
    rbac.example.com/aggregate-to-monitoring: "true"
rules:
  - apiGroups: [""]
    resources: ["services", "endpoints", "pods"]
    verbs: ["get", "list", "watch"]

---
# ClusterRole qui agrège d'autres rôles
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: monitoring
aggregationRule:
  clusterRoleSelectors:
    - matchLabels:
        rbac.example.com/aggregate-to-monitoring: "true"
rules: []  # Les rules sont agrégées automatiquement
```

---

## 3. Service Accounts

### 3.1 Concept

```yaml
# ServiceAccount pour les pods
apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-service-account
  namespace: default
automountServiceAccountToken: true  # Défaut: true

---
# Pod utilisant le ServiceAccount
apiVersion: v1
kind: Pod
metadata:
  name: app-pod
spec:
  serviceAccountName: app-service-account
  automountServiceAccountToken: true
  containers:
    - name: app
      image: myapp
      # Token monté dans /var/run/secrets/kubernetes.io/serviceaccount/token
```

### 3.2 Token ServiceAccount

```bash
# Créer un token (K8s 1.24+)
kubectl create token app-service-account

# Token longue durée (secret)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: app-sa-token
  annotations:
    kubernetes.io/service-account.name: app-service-account
type: kubernetes.io/service-account-token
EOF

# Récupérer le token
kubectl get secret app-sa-token -o jsonpath='{.data.token}' | base64 -d
```

### 3.3 RBAC pour ServiceAccount

```yaml
# Donner des permissions au ServiceAccount
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: configmap-reader
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-configmap-reader
  namespace: default
subjects:
  - kind: ServiceAccount
    name: app-service-account
    namespace: default
roleRef:
  kind: Role
  name: configmap-reader
  apiGroup: rbac.authorization.k8s.io
```

---

## 4. Pod Security Standards

### 4.1 Niveaux de Sécurité

```
POD SECURITY STANDARDS (PSS)
════════════════════════════

Privileged    │ Pas de restrictions (cluster admins)
Baseline      │ Restrictions minimales (défaut raisonnable)
Restricted    │ Restrictions maximales (hardened)

Modes d'application:
- enforce : Rejette les pods non conformes
- audit   : Log dans l'audit log
- warn    : Avertissement à l'utilisateur
```

### 4.2 Pod Security Admission

```yaml
# Appliquer PSS à un namespace
apiVersion: v1
kind: Namespace
metadata:
  name: secure-namespace
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

### 4.3 Pod Conforme au Mode Restricted

```yaml
# Pod conforme au mode restricted
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: app
      image: myapp:1.0
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      resources:
        limits:
          cpu: "500m"
          memory: "128Mi"
        requests:
          cpu: "100m"
          memory: "64Mi"
```

---

## 5. Network Policies (Sécurité Réseau)

```yaml
# Deny all par défaut
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
    - Ingress
    - Egress

---
# Autoriser uniquement le trafic nécessaire
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: api-policy
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: frontend
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: database
      ports:
        - protocol: TCP
          port: 5432
```

---

## 6. Exercice Pratique

### Tâches

1. Créer un utilisateur avec certificat
2. Créer un Role avec permissions limitées
3. Lier l'utilisateur au Role
4. Créer un ServiceAccount avec RBAC
5. Appliquer Pod Security Standards

### Vérification

```bash
# Tester les permissions
kubectl auth can-i get pods --as john
kubectl auth can-i delete pods --as john
kubectl auth can-i get pods --as system:serviceaccount:default:app-sa

# Lister les roles
kubectl get roles,rolebindings -A
kubectl get clusterroles,clusterrolebindings
```

---

## Quiz

1. **Quelle ressource lie un Subject à un Role ?**
   - [ ] A. Role
   - [ ] B. RoleBinding
   - [ ] C. ClusterRole

2. **Quel mode PSS est le plus restrictif ?**
   - [ ] A. Privileged
   - [ ] B. Baseline
   - [ ] C. Restricted

3. **Où est monté le token ServiceAccount dans un pod ?**
   - [ ] A. /etc/kubernetes/token
   - [ ] B. /var/run/secrets/kubernetes.io/serviceaccount/
   - [ ] C. /root/.kube/token

**Réponses :** 1-B, 2-C, 3-B

---

**Précédent :** [Module 5 - Stockage](05-module.md)

**Suivant :** [Module 7 - Scheduling](07-module.md)
