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

## 6. Exercice Pratique

### Tâches

1. Installer ArgoCD
2. Créer une Application pointant vers un repo Git
3. Configurer le sync automatique
4. Créer une structure Kustomize multi-environnement

### Validation

```bash
# Vérifier ArgoCD
argocd app list
argocd app get myapp

# Vérifier Flux
flux get all
flux logs
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
