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

![Méthodes d'Authentification Kubernetes](../../assets/diagrams/k8s-authentication-methods.jpeg)

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

![Modèle RBAC Kubernetes](../../assets/diagrams/k8s-rbac-model.jpeg)

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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Mettre en place un système RBAC complet et sécuriser les pods

    **Contexte** : Vous devez créer un environnement sécurisé pour une équipe de développeurs. Ils doivent pouvoir déployer et gérer leurs applications dans un namespace dédié, mais sans accès aux ressources critiques du cluster.

    **Tâches à réaliser** :

    1. Créer un namespace "dev-team" avec Pod Security Standards en mode baseline
    2. Créer un ServiceAccount "developer" pour l'équipe
    3. Créer un Role limitant les permissions aux pods, deployments et services
    4. Lier le ServiceAccount au Role avec un RoleBinding
    5. Déployer un pod sécurisé respectant les Pod Security Standards

    **Critères de validation** :

    - [ ] Le namespace est créé avec Pod Security Standards
    - [ ] Le ServiceAccount a des permissions limitées au namespace
    - [ ] Les développeurs peuvent gérer pods/deployments/services
    - [ ] Les développeurs ne peuvent PAS accéder aux secrets
    - [ ] Le pod déployé respecte les contraintes de sécurité

??? quote "Solution"
    **Étape 1 : Créer le namespace avec Pod Security**

    ```yaml
    # namespace.yaml
    apiVersion: v1
    kind: Namespace
    metadata:
      name: dev-team
      labels:
        name: dev-team
        pod-security.kubernetes.io/enforce: baseline
        pod-security.kubernetes.io/audit: restricted
        pod-security.kubernetes.io/warn: restricted
    ```

    ```bash
    kubectl apply -f namespace.yaml
    kubectl get namespace dev-team --show-labels
    ```

    **Étape 2 : Créer le ServiceAccount**

    ```yaml
    # serviceaccount.yaml
    apiVersion: v1
    kind: ServiceAccount
    metadata:
      name: developer
      namespace: dev-team
    automountServiceAccountToken: true
    ```

    ```bash
    kubectl apply -f serviceaccount.yaml
    kubectl get sa -n dev-team
    ```

    **Étape 3 : Créer le Role**

    ```yaml
    # role.yaml
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: developer-role
      namespace: dev-team
    rules:
      # Permissions sur les pods
      - apiGroups: [""]
        resources: ["pods", "pods/log", "pods/status"]
        verbs: ["get", "list", "watch", "create", "delete"]
      - apiGroups: [""]
        resources: ["pods/exec"]
        verbs: ["create"]

      # Permissions sur les deployments
      - apiGroups: ["apps"]
        resources: ["deployments", "replicasets"]
        verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

      # Permissions sur les services
      - apiGroups: [""]
        resources: ["services"]
        verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]

      # Permissions limitées sur configmaps (lecture seule)
      - apiGroups: [""]
        resources: ["configmaps"]
        verbs: ["get", "list"]

      # PAS de permissions sur les secrets!
    ```

    ```bash
    kubectl apply -f role.yaml
    kubectl describe role developer-role -n dev-team
    ```

    **Étape 4 : Créer le RoleBinding**

    ```yaml
    # rolebinding.yaml
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      name: developer-binding
      namespace: dev-team
    subjects:
      - kind: ServiceAccount
        name: developer
        namespace: dev-team
    roleRef:
      kind: Role
      name: developer-role
      apiGroup: rbac.authorization.k8s.io
    ```

    ```bash
    kubectl apply -f rolebinding.yaml
    kubectl describe rolebinding developer-binding -n dev-team
    ```

    **Étape 5 : Déployer un pod sécurisé**

    ```yaml
    # secure-pod.yaml
    apiVersion: v1
    kind: Pod
    metadata:
      name: secure-app
      namespace: dev-team
    spec:
      serviceAccountName: developer
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: app
          image: nginx:alpine
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          ports:
            - containerPort: 80
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 100m
              memory: 128Mi
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            - name: cache
              mountPath: /var/cache/nginx
            - name: run
              mountPath: /var/run
      volumes:
        - name: tmp
          emptyDir: {}
        - name: cache
          emptyDir: {}
        - name: run
          emptyDir: {}
    ```

    ```bash
    kubectl apply -f secure-pod.yaml
    kubectl get pods -n dev-team
    kubectl describe pod secure-app -n dev-team
    ```

    **Étape 6 : Tester les permissions**

    ```bash
    # Créer un token pour le ServiceAccount
    TOKEN=$(kubectl create token developer -n dev-team)

    # Tester avec kubectl
    # Devrait fonctionner : lister les pods
    kubectl auth can-i list pods -n dev-team --as=system:serviceaccount:dev-team:developer
    # Résultat: yes

    # Devrait fonctionner : créer un deployment
    kubectl auth can-i create deployments -n dev-team --as=system:serviceaccount:dev-team:developer
    # Résultat: yes

    # Devrait échouer : lire les secrets
    kubectl auth can-i get secrets -n dev-team --as=system:serviceaccount:dev-team:developer
    # Résultat: no

    # Devrait échouer : accès à un autre namespace
    kubectl auth can-i get pods -n kube-system --as=system:serviceaccount:dev-team:developer
    # Résultat: no

    # Tester toutes les permissions
    kubectl auth can-i --list -n dev-team --as=system:serviceaccount:dev-team:developer
    ```

    **Étape 7 : Tests additionnels**

    ```bash
    # Créer un deployment avec le ServiceAccount
    kubectl create deployment nginx --image=nginx:alpine --replicas=2 -n dev-team

    # Vérifier que le pod peut lister d'autres pods (via API interne)
    kubectl exec -it secure-app -n dev-team -- sh
    # Dans le pod:
    # TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
    # curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/dev-team/pods
    ```

    **Étape 8 : Test de violation de sécurité**

    ```yaml
    # insecure-pod.yaml (devrait être rejeté ou averti)
    apiVersion: v1
    kind: Pod
    metadata:
      name: insecure-app
      namespace: dev-team
    spec:
      containers:
        - name: app
          image: nginx
          securityContext:
            privileged: true  # Violation!
    ```

    ```bash
    kubectl apply -f insecure-pod.yaml
    # Devrait afficher un warning ou être rejeté selon le niveau de Pod Security
    ```

    **Vérifications finales** :

    ```bash
    # Lister toutes les ressources RBAC
    kubectl get roles,rolebindings -n dev-team
    kubectl get serviceaccounts -n dev-team

    # Vérifier les Pod Security labels
    kubectl get namespace dev-team -o yaml | grep pod-security

    # Auditer les permissions
    kubectl describe role developer-role -n dev-team
    kubectl describe rolebinding developer-binding -n dev-team
    ```

    **Nettoyage** :

    ```bash
    kubectl delete namespace dev-team
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

---

## Navigation

| | |
|:---|---:|
| [← Module 5 : Stockage](05-module.md) | [Module 7 : Scheduling Avancé →](07-module.md) |

[Retour au Programme](index.md){ .md-button }
