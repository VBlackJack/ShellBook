---
tags:
  - formation
  - kubernetes
  - gitops
  - argocd
  - flux
---

# Module 10 : GitOps et CI/CD

## Objectifs du Module

- Comprendre les principes GitOps
- Déployer et configurer ArgoCD
- Implémenter Flux CD
- Configurer des pipelines CI/CD

**Durée :** 4 heures

---

## 1. Principes GitOps

### 1.1 Concept

```
GITOPS PRINCIPLES
═════════════════

1. DÉCLARATIF
   └─ L'état désiré est décrit de manière déclarative

2. VERSIONNÉ
   └─ Git comme source de vérité unique

3. AUTOMATISÉ
   └─ Changements appliqués automatiquement

4. RÉCONCILIATION CONTINUE
   └─ Agents assurent que l'état réel = état désiré


┌─────────────────────────────────────────────────────────────┐
│                      FLUX GITOPS                             │
│                                                              │
│   Developer                                                  │
│      │                                                       │
│      │ git push                                              │
│      ▼                                                       │
│   ┌─────────┐                                               │
│   │   Git   │ ◄────────────── Source of Truth               │
│   │  Repo   │                                               │
│   └────┬────┘                                               │
│        │                                                     │
│        │ Watch/Pull                                         │
│        ▼                                                     │
│   ┌─────────────┐                                           │
│   │  GitOps     │                                           │
│   │  Operator   │  (ArgoCD / Flux)                         │
│   └──────┬──────┘                                           │
│          │                                                   │
│          │ Reconcile                                        │
│          ▼                                                   │
│   ┌─────────────┐                                           │
│   │ Kubernetes  │                                           │
│   │  Cluster    │                                           │
│   └─────────────┘                                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. ArgoCD

### 2.1 Installation

```bash
# Créer le namespace
kubectl create namespace argocd

# Installer ArgoCD
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Attendre que les pods soient prêts
kubectl wait --for=condition=Ready pods --all -n argocd --timeout=300s

# Récupérer le mot de passe admin
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Exposer l'UI
kubectl port-forward svc/argocd-server -n argocd 8080:443

# Installer le CLI
curl -sSL -o argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
chmod +x argocd && sudo mv argocd /usr/local/bin/

# Login CLI
argocd login localhost:8080
```

### 2.2 Application ArgoCD

```yaml
# application.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: myapp
  namespace: argocd
spec:
  project: default

  source:
    repoURL: https://github.com/myorg/myapp-manifests.git
    targetRevision: main
    path: k8s/overlays/production

  destination:
    server: https://kubernetes.default.svc
    namespace: production

  syncPolicy:
    automated:
      prune: true        # Supprimer les ressources orphelines
      selfHeal: true     # Réconcilier si drift détecté
      allowEmpty: false
    syncOptions:
      - CreateNamespace=true
      - PruneLast=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

### 2.3 Application avec Helm

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: myapp-helm
  namespace: argocd
spec:
  project: default

  source:
    repoURL: https://github.com/myorg/helm-charts.git
    targetRevision: main
    path: charts/myapp
    helm:
      valueFiles:
        - values-production.yaml
      parameters:
        - name: image.tag
          value: "v2.0.0"

  destination:
    server: https://kubernetes.default.svc
    namespace: production

  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

### 2.4 ApplicationSet

```yaml
# Déployer sur plusieurs clusters/environnements
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: myapp-multi-env
  namespace: argocd
spec:
  generators:
    - list:
        elements:
          - env: staging
            cluster: staging-cluster
            revision: develop
          - env: production
            cluster: production-cluster
            revision: main

  template:
    metadata:
      name: 'myapp-{{env}}'
    spec:
      project: default
      source:
        repoURL: https://github.com/myorg/myapp.git
        targetRevision: '{{revision}}'
        path: k8s/overlays/{{env}}
      destination:
        server: '{{cluster}}'
        namespace: '{{env}}'
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
```

---

## 3. Flux CD

### 3.1 Installation

```bash
# Installer Flux CLI
curl -s https://fluxcd.io/install.sh | sudo bash

# Bootstrap Flux sur le cluster
flux bootstrap github \
  --owner=myorg \
  --repository=fleet-infra \
  --branch=main \
  --path=clusters/production \
  --personal

# Vérifier
flux check
kubectl get all -n flux-system
```

### 3.2 GitRepository

```yaml
# Source Git
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: myapp
  namespace: flux-system
spec:
  interval: 1m
  url: https://github.com/myorg/myapp
  ref:
    branch: main
  secretRef:
    name: github-token  # Si repo privé
```

### 3.3 Kustomization

```yaml
# Déploiement avec Kustomize
apiVersion: kustomize.toolkit.fluxcd.io/v1
kind: Kustomization
metadata:
  name: myapp
  namespace: flux-system
spec:
  interval: 10m
  sourceRef:
    kind: GitRepository
    name: myapp
  path: ./k8s/overlays/production
  prune: true
  targetNamespace: production
  healthChecks:
    - apiVersion: apps/v1
      kind: Deployment
      name: myapp
      namespace: production
```

### 3.4 HelmRelease

```yaml
# Déploiement avec Helm
apiVersion: helm.toolkit.fluxcd.io/v2beta1
kind: HelmRelease
metadata:
  name: myapp
  namespace: production
spec:
  interval: 5m
  chart:
    spec:
      chart: myapp
      version: "1.0.0"
      sourceRef:
        kind: HelmRepository
        name: myrepo
        namespace: flux-system
  values:
    replicaCount: 3
    image:
      tag: v2.0.0
  upgrade:
    remediation:
      retries: 3
```

---

## 4. Kustomize

### 4.1 Structure

```
myapp/
├── base/
│   ├── kustomization.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   └── configmap.yaml
└── overlays/
    ├── staging/
    │   ├── kustomization.yaml
    │   └── replica-patch.yaml
    └── production/
        ├── kustomization.yaml
        ├── replica-patch.yaml
        └── ingress.yaml
```

### 4.2 Base

```yaml
# base/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - deployment.yaml
  - service.yaml
  - configmap.yaml

commonLabels:
  app: myapp
```

### 4.3 Overlay

```yaml
# overlays/production/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: production

resources:
  - ../../base
  - ingress.yaml

patches:
  - path: replica-patch.yaml

images:
  - name: myapp
    newTag: v2.0.0

configMapGenerator:
  - name: app-config
    behavior: merge
    literals:
      - LOG_LEVEL=warn
```

```yaml
# overlays/production/replica-patch.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  replicas: 5
```

```bash
# Prévisualiser
kubectl kustomize overlays/production

# Appliquer
kubectl apply -k overlays/production
```

---

## 5. Pipeline CI/CD

### 5.1 GitHub Actions

```yaml
# .github/workflows/deploy.yaml
name: Deploy to Kubernetes

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build and push image
        run: |
          docker build -t myorg/myapp:${{ github.sha }} .
          docker push myorg/myapp:${{ github.sha }}

      - name: Update manifests
        run: |
          cd k8s/overlays/production
          kustomize edit set image myorg/myapp:${{ github.sha }}

      - name: Commit and push
        run: |
          git config user.name github-actions
          git config user.email github-actions@github.com
          git add .
          git commit -m "Update image to ${{ github.sha }}"
          git push
```

### 5.2 GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - build
  - deploy

build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA

deploy:
  stage: deploy
  script:
    - |
      cd k8s/overlays/production
      kustomize edit set image myapp=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
      git add .
      git commit -m "Deploy $CI_COMMIT_SHA"
      git push origin main
  only:
    - main
```

---

## 6. Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Mettre en place un pipeline GitOps complet avec ArgoCD pour déployer une application sur plusieurs environnements

    **Contexte** : Votre équipe souhaite adopter GitOps pour gérer les déploiements d'une application microservices. Vous devez configurer ArgoCD pour déployer automatiquement l'application "ShopAPI" sur trois environnements (dev, staging, production) à partir d'un repository Git, en utilisant Kustomize pour gérer les différences de configuration.

    **Tâches à réaliser** :

    1. Installer ArgoCD sur le cluster
    2. Créer une structure Kustomize avec base + overlays (dev, staging, prod)
    3. Créer des Applications ArgoCD pour chaque environnement
    4. Configurer le sync automatique avec self-heal et prune
    5. Créer un ApplicationSet pour gérer tous les environnements
    6. Simuler un drift et observer la réconciliation automatique

    **Critères de validation** :

    - [ ] ArgoCD est installé et accessible
    - [ ] Les 3 environnements sont déployés avec des configs différentes
    - [ ] Le sync automatique fonctionne (push Git → déploiement)
    - [ ] Le self-heal détecte et corrige les drifts
    - [ ] L'ApplicationSet gère les 3 environnements

??? quote "Solution"
    **Étape 1 : Installer ArgoCD**

    ```bash
    # Créer le namespace
    kubectl create namespace argocd

    # Installer ArgoCD
    kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

    # Attendre que tous les pods soient prêts
    kubectl wait --for=condition=Ready pods --all -n argocd --timeout=300s

    # Récupérer le mot de passe admin initial
    ARGOCD_PASSWORD=$(kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d)
    echo "ArgoCD Admin Password: $ARGOCD_PASSWORD"

    # Exposer l'UI (dans un terminal séparé)
    kubectl port-forward svc/argocd-server -n argocd 8080:443

    # Installer le CLI ArgoCD
    curl -sSL -o argocd https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64
    chmod +x argocd
    sudo mv argocd /usr/local/bin/

    # Login via CLI
    argocd login localhost:8080 --username admin --password $ARGOCD_PASSWORD --insecure

    # Changer le mot de passe (optionnel)
    argocd account update-password
    ```

    **Étape 2 : Créer la Structure Kustomize**

    ```bash
    # Créer la structure (simulation - normalement dans un repo Git)
    mkdir -p shopapi-manifests/{base,overlays/{dev,staging,production}}
    cd shopapi-manifests
    ```

    ```yaml
    # base/kustomization.yaml
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization

    resources:
      - deployment.yaml
      - service.yaml
      - configmap.yaml

    commonLabels:
      app: shopapi
      managed-by: argocd
    ```

    ```yaml
    # base/deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: shopapi
    spec:
      replicas: 2
      selector:
        matchLabels:
          app: shopapi
      template:
        metadata:
          labels:
            app: shopapi
        spec:
          containers:
            - name: api
              image: mycompany/shopapi:latest
              ports:
                - containerPort: 8080
                  name: http
              env:
                - name: ENVIRONMENT
                  valueFrom:
                    configMapKeyRef:
                      name: shopapi-config
                      key: environment
                - name: LOG_LEVEL
                  valueFrom:
                    configMapKeyRef:
                      name: shopapi-config
                      key: log_level
              resources:
                requests:
                  cpu: 100m
                  memory: 128Mi
                limits:
                  cpu: 500m
                  memory: 256Mi
              livenessProbe:
                httpGet:
                  path: /health
                  port: 8080
                initialDelaySeconds: 30
                periodSeconds: 10
              readinessProbe:
                httpGet:
                  path: /ready
                  port: 8080
                initialDelaySeconds: 10
                periodSeconds: 5
    ```

    ```yaml
    # base/service.yaml
    apiVersion: v1
    kind: Service
    metadata:
      name: shopapi
    spec:
      selector:
        app: shopapi
      ports:
        - port: 80
          targetPort: 8080
          name: http
      type: ClusterIP
    ```

    ```yaml
    # base/configmap.yaml
    apiVersion: v1
    kind: ConfigMap
    metadata:
      name: shopapi-config
    data:
      environment: "base"
      log_level: "info"
    ```

    **Overlays par Environnement**

    ```yaml
    # overlays/dev/kustomization.yaml
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization

    namespace: dev

    resources:
      - ../../base

    patches:
      - patch: |-
          - op: replace
            path: /spec/replicas
            value: 1
        target:
          kind: Deployment
          name: shopapi

    images:
      - name: mycompany/shopapi
        newTag: dev-latest

    configMapGenerator:
      - name: shopapi-config
        behavior: merge
        literals:
          - environment=development
          - log_level=debug
    ```

    ```yaml
    # overlays/staging/kustomization.yaml
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization

    namespace: staging

    resources:
      - ../../base

    patches:
      - patch: |-
          - op: replace
            path: /spec/replicas
            value: 2
        target:
          kind: Deployment
          name: shopapi

    images:
      - name: mycompany/shopapi
        newTag: staging-v1.2.0

    configMapGenerator:
      - name: shopapi-config
        behavior: merge
        literals:
          - environment=staging
          - log_level=info
    ```

    ```yaml
    # overlays/production/kustomization.yaml
    apiVersion: kustomize.config.k8s.io/v1beta1
    kind: Kustomization

    namespace: production

    resources:
      - ../../base
      - ingress.yaml

    patches:
      - patch: |-
          - op: replace
            path: /spec/replicas
            value: 5
        target:
          kind: Deployment
          name: shopapi
      - patch: |-
          - op: add
            path: /spec/template/spec/affinity
            value:
              podAntiAffinity:
                preferredDuringSchedulingIgnoredDuringExecution:
                  - weight: 100
                    podAffinityTerm:
                      labelSelector:
                        matchExpressions:
                          - key: app
                            operator: In
                            values:
                              - shopapi
                      topologyKey: kubernetes.io/hostname
        target:
          kind: Deployment
          name: shopapi

    images:
      - name: mycompany/shopapi
        newTag: v1.2.0

    configMapGenerator:
      - name: shopapi-config
        behavior: merge
        literals:
          - environment=production
          - log_level=warn
    ```

    ```yaml
    # overlays/production/ingress.yaml
    apiVersion: networking.k8s.io/v1
    kind: Ingress
    metadata:
      name: shopapi
      annotations:
        cert-manager.io/cluster-issuer: letsencrypt-prod
    spec:
      ingressClassName: nginx
      tls:
        - hosts:
            - api.shop.example.com
          secretName: shopapi-tls
      rules:
        - host: api.shop.example.com
          http:
            paths:
              - path: /
                pathType: Prefix
                backend:
                  service:
                    name: shopapi
                    port:
                      number: 80
    ```

    **Tester Kustomize localement**

    ```bash
    # Prévisualiser chaque environnement
    kubectl kustomize overlays/dev
    kubectl kustomize overlays/staging
    kubectl kustomize overlays/production

    # Vérifier les différences
    kubectl kustomize overlays/dev > /tmp/dev.yaml
    kubectl kustomize overlays/production > /tmp/prod.yaml
    diff /tmp/dev.yaml /tmp/prod.yaml
    ```

    **Étape 3 : Créer les Applications ArgoCD (Méthode 1 - Manuel)**

    ```yaml
    # argocd/dev-application.yaml
    apiVersion: argoproj.io/v1alpha1
    kind: Application
    metadata:
      name: shopapi-dev
      namespace: argocd
      finalizers:
        - resources-finalizer.argocd.argoproj.io
    spec:
      project: default

      source:
        repoURL: https://github.com/myorg/shopapi-manifests.git
        targetRevision: main
        path: overlays/dev

      destination:
        server: https://kubernetes.default.svc
        namespace: dev

      syncPolicy:
        automated:
          prune: true        # Supprimer ressources orphelines
          selfHeal: true     # Réconcilier automatiquement les drifts
          allowEmpty: false
        syncOptions:
          - CreateNamespace=true
          - PruneLast=true
        retry:
          limit: 5
          backoff:
            duration: 5s
            factor: 2
            maxDuration: 3m
    ```

    ```yaml
    # argocd/staging-application.yaml
    apiVersion: argoproj.io/v1alpha1
    kind: Application
    metadata:
      name: shopapi-staging
      namespace: argocd
      finalizers:
        - resources-finalizer.argocd.argoproj.io
    spec:
      project: default

      source:
        repoURL: https://github.com/myorg/shopapi-manifests.git
        targetRevision: main
        path: overlays/staging

      destination:
        server: https://kubernetes.default.svc
        namespace: staging

      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true
          - PruneLast=true
    ```

    ```yaml
    # argocd/production-application.yaml
    apiVersion: argoproj.io/v1alpha1
    kind: Application
    metadata:
      name: shopapi-production
      namespace: argocd
      finalizers:
        - resources-finalizer.argocd.argoproj.io
    spec:
      project: default

      source:
        repoURL: https://github.com/myorg/shopapi-manifests.git
        targetRevision: main
        path: overlays/production

      destination:
        server: https://kubernetes.default.svc
        namespace: production

      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true
          - PruneLast=true
    ```

    ```bash
    # Appliquer les Applications
    kubectl apply -f argocd/dev-application.yaml
    kubectl apply -f argocd/staging-application.yaml
    kubectl apply -f argocd/production-application.yaml

    # Vérifier via CLI
    argocd app list
    argocd app get shopapi-dev
    argocd app get shopapi-staging
    argocd app get shopapi-production

    # Forcer un sync manuel (si nécessaire)
    argocd app sync shopapi-dev
    ```

    **Étape 4 : ApplicationSet (Méthode 2 - Recommandée)**

    ```yaml
    # argocd/shopapi-applicationset.yaml
    apiVersion: argoproj.io/v1alpha1
    kind: ApplicationSet
    metadata:
      name: shopapi
      namespace: argocd
    spec:
      generators:
        - list:
            elements:
              - env: dev
                replicas: "1"
                namespace: dev
                revision: main
              - env: staging
                replicas: "2"
                namespace: staging
                revision: main
              - env: production
                replicas: "5"
                namespace: production
                revision: main

      template:
        metadata:
          name: 'shopapi-{{env}}'
          namespace: argocd
          finalizers:
            - resources-finalizer.argocd.argoproj.io
        spec:
          project: default

          source:
            repoURL: https://github.com/myorg/shopapi-manifests.git
            targetRevision: '{{revision}}'
            path: 'overlays/{{env}}'

          destination:
            server: https://kubernetes.default.svc
            namespace: '{{namespace}}'

          syncPolicy:
            automated:
              prune: true
              selfHeal: true
              allowEmpty: false
            syncOptions:
              - CreateNamespace=true
              - PruneLast=true
            retry:
              limit: 5
              backoff:
                duration: 5s
                factor: 2
                maxDuration: 3m

          # Health checks spécifiques
          ignoreDifferences:
            - group: apps
              kind: Deployment
              jsonPointers:
                - /spec/replicas  # Ignorer si HPA présent
    ```

    ```bash
    # Appliquer l'ApplicationSet
    kubectl apply -f argocd/shopapi-applicationset.yaml

    # Vérifier que les 3 Applications sont créées
    argocd app list
    kubectl get applications -n argocd

    # Voir les détails
    argocd app get shopapi-dev
    argocd app get shopapi-staging
    argocd app get shopapi-production
    ```

    **Étape 5 : Tester le Sync Automatique**

    ```bash
    # Simuler un changement dans Git (modifier l'image tag)
    # Dans overlays/dev/kustomization.yaml, changer:
    # newTag: dev-latest → newTag: dev-v1.2.1

    # Push vers Git
    git add .
    git commit -m "Update dev image to v1.2.1"
    git push

    # Observer le sync automatique (30-60 secondes)
    argocd app get shopapi-dev --watch

    # Voir les logs de sync
    argocd app logs shopapi-dev --follow
    ```

    **Étape 6 : Tester le Self-Heal (Drift Detection)**

    ```bash
    # Simuler un drift en modifiant manuellement le Deployment
    kubectl scale deployment shopapi -n dev --replicas=5

    # ArgoCD détecte le drift (OutOfSync)
    argocd app get shopapi-dev

    # Après quelques secondes, self-heal restaure l'état désiré (1 replica)
    kubectl get deployment shopapi -n dev --watch

    # Vérifier que le drift a été corrigé
    argocd app get shopapi-dev
    # Status: Synced, Healthy

    # Voir l'historique des syncs
    argocd app history shopapi-dev
    ```

    **Validation Complète**

    ```bash
    # 1. Vérifier ArgoCD
    kubectl get all -n argocd
    argocd version

    # 2. Vérifier toutes les Applications
    argocd app list
    argocd app get shopapi-dev
    argocd app get shopapi-staging
    argocd app get shopapi-production

    # 3. Vérifier les déploiements
    kubectl get all -n dev
    kubectl get all -n staging
    kubectl get all -n production

    # 4. Vérifier les différences de config
    kubectl get deployment shopapi -n dev -o yaml | grep replicas
    kubectl get deployment shopapi -n staging -o yaml | grep replicas
    kubectl get deployment shopapi -n production -o yaml | grep replicas

    kubectl get configmap shopapi-config -n dev -o yaml
    kubectl get configmap shopapi-config -n production -o yaml

    # 5. Vérifier l'Ingress (prod seulement)
    kubectl get ingress -n production

    # 6. Test de bout en bout
    kubectl run test --rm -it --image=curlimages/curl -n dev -- sh
    # Dans le pod: curl http://shopapi/health

    # 7. Voir l'état dans l'UI ArgoCD
    # Ouvrir http://localhost:8080
    # Login: admin / <password>

    # 8. Tester un rollback
    argocd app rollback shopapi-dev 1

    # 9. Vérifier les métriques ArgoCD
    kubectl get servicemonitor -n argocd
    ```

    **Commandes Utiles pour le Debug**

    ```bash
    # Voir les logs ArgoCD
    kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller

    # Voir les événements
    kubectl get events -n argocd --sort-by=.lastTimestamp

    # Refresh manuel (forcer la détection)
    argocd app get shopapi-dev --refresh

    # Diff entre Git et Cluster
    argocd app diff shopapi-dev

    # Manifests générés
    argocd app manifests shopapi-dev

    # Désactiver le sync auto temporairement
    argocd app set shopapi-dev --sync-policy none

    # Réactiver
    argocd app set shopapi-dev --sync-policy automated --auto-prune --self-heal
    ```

---

## Quiz

1. **Quel est le principe fondamental de GitOps ?**
   - [ ] A. Push vers le cluster
   - [ ] B. Git comme source de vérité
   - [ ] C. Déploiement manuel

2. **Quel outil permet de personnaliser les manifests par environnement ?**
   - [ ] A. Helm uniquement
   - [ ] B. Kustomize
   - [ ] C. kubectl

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 9 - Helm](09-module.md)

**Suivant :** [Module 11 - Troubleshooting](11-module.md)
