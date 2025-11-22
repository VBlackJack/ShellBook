# GitHub Actions for Ops

`#cicd` `#github-actions` `#pipeline` `#automation`

CI/CD avec GitHub Actions pour l'automatisation Ops.

---

## Anatomie d'un Workflow

### Hiérarchie

```
Workflow (.github/workflows/deploy.yml)
├── Job 1 (build)
│   ├── Step 1: Checkout code
│   ├── Step 2: Run tests
│   └── Step 3: Build artifact
├── Job 2 (deploy) ← Dépend de Job 1
│   ├── Step 1: Download artifact
│   └── Step 2: Deploy to server
└── Job 3 (notify) ← Parallèle à Job 2
    └── Step 1: Send Slack notification
```

| Niveau | Description | Exécution |
|--------|-------------|-----------|
| **Workflow** | Fichier YAML dans `.github/workflows/` | Déclenché par événement |
| **Job** | Unité d'exécution sur un runner | Parallèle par défaut |
| **Step** | Commande ou action atomique | Séquentiel dans un job |

### Structure de Base

```yaml
name: Mon Workflow

# Déclencheurs
on:
  push:
    branches: [main, develop]
  pull_request:
  schedule:
    - cron: '0 2 * * *'  # 2h du matin chaque jour

# Variables d'environnement globales
env:
  NODE_VERSION: '18'

# Jobs
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run tests
        run: npm test

  build:
    needs: test  # Attend que "test" soit terminé
    runs-on: ubuntu-latest
    steps:
      - name: Build
        run: echo "Building..."
```

### Triggers (`on:`)

```yaml
# Push sur branches spécifiques
on:
  push:
    branches:
      - main
      - 'release/**'

# Pull Request vers main
on:
  pull_request:
    branches: [main]

# Déclenchement manuel (bouton dans l'UI)
on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment to deploy'
        required: true
        type: choice
        options:
          - dev
          - staging
          - production

# Planification (Cron)
on:
  schedule:
    - cron: '0 2 * * *'      # 2h tous les jours
    - cron: '0 0 * * 0'      # Dimanche minuit

# Multiple triggers
on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:
```

---

## Exemple de Pipeline Ops

### Workflow Complet : Lint → Build → Push

```yaml
# .github/workflows/docker-build.yml
name: Docker Build & Push

on:
  push:
    branches: [main, develop]
  pull_request:

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  # Job 1 : Linting
  lint:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: ShellCheck
        uses: ludeeus/action-shellcheck@master
        with:
          scandir: './scripts'

      - name: Ansible Lint
        uses: ansible/ansible-lint-action@v6
        with:
          args: 'playbooks/'

  # Job 2 : Build Docker
  build:
    needs: lint
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Container Registry
        if: github.ref == 'refs/heads/main'
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}
          tags: |
            type=ref,event=branch
            type=sha,prefix={{branch}}-
            type=semver,pattern={{version}}

      - name: Build Docker image
        uses: docker/build-push-action@v5
        with:
          context: .
          push: false
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha
          cache-to: type=gha,mode=max

      - name: Push to Registry (main only)
        if: github.ref == 'refs/heads/main'
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

  # Job 3 : Scan de sécurité
  security:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          format: 'sarif'
          output: 'trivy-results.sarif'

      - name: Upload Trivy results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
```

### Actions Standards Utilisées

| Action | Usage |
|--------|-------|
| `actions/checkout@v4` | Clone le dépôt |
| `actions/setup-node@v4` | Installer Node.js |
| `actions/setup-python@v5` | Installer Python |
| `docker/setup-buildx-action@v3` | Builder Docker multi-arch |
| `docker/login-action@v3` | Login registry |
| `docker/build-push-action@v5` | Build et push image |
| `actions/upload-artifact@v4` | Partager fichiers entre jobs |
| `actions/download-artifact@v4` | Télécharger artifacts |

---

## Gestion des Secrets (SecNumCloud)

### Ne JAMAIS Commiter de Secrets

!!! danger "Règle d'Or"
    - ❌ Jamais de secrets en clair dans le code
    - ❌ Jamais dans les variables d'environnement du workflow
    - ✅ Toujours via GitHub Secrets

```yaml
# MAUVAIS ❌
env:
  API_KEY: sk_live_123456789  # INTERDIT !

# BON ✅
env:
  API_KEY: ${{ secrets.API_KEY }}
```

### Créer des Secrets

```
Repo → Settings → Secrets and variables → Actions → New repository secret
```

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to server
        env:
          SSH_KEY: ${{ secrets.SSH_PRIVATE_KEY }}
          API_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: |
          echo "$SSH_KEY" > key.pem
          chmod 600 key.pem
          ssh -i key.pem user@server 'deploy.sh'
```

### Secrets par Environnement

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production  # Environnement spécifique
    steps:
      - name: Deploy
        env:
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}  # Secret de l'env "production"
        run: ./deploy.sh
```

### Configuration des Environnements

```
Repo → Settings → Environments → New environment
```

Options disponibles :

- **Protection Rules** : Validation manuelle obligatoire
- **Reviewers** : Liste des approbateurs
- **Wait timer** : Délai avant exécution
- **Branch filter** : Limiter aux branches spécifiques

```yaml
jobs:
  deploy-prod:
    runs-on: ubuntu-latest
    environment:
      name: production
      url: https://app.example.com
    steps:
      - name: Deploy to production
        run: kubectl apply -f k8s/
```

!!! tip "Protection Production"
    Configurez **toujours** une validation manuelle pour l'environnement de production.

---

## Self-Hosted Runners

### Pourquoi Self-Hosted ?

| Cas d'Usage | Raison |
|-------------|--------|
| Accès réseau privé | Déployer sur des serveurs internes |
| Pas de sortie Internet | Réseaux isolés (air-gap) |
| Ressources spécifiques | GPU, hardware particulier |
| Performance | Éviter les temps d'attente de queue |
| Coût | Grosse utilisation = moins cher |

### Installation

```bash
# Sur le serveur runner
# Settings → Actions → Runners → New self-hosted runner

# Télécharger
mkdir actions-runner && cd actions-runner
curl -o actions-runner-linux-x64-2.311.0.tar.gz -L \
  https://github.com/actions/runner/releases/download/v2.311.0/actions-runner-linux-x64-2.311.0.tar.gz
tar xzf ./actions-runner-linux-x64-2.311.0.tar.gz

# Configurer
./config.sh --url https://github.com/myorg/myrepo --token TOKEN

# Installer comme service
sudo ./svc.sh install
sudo ./svc.sh start
```

### Utilisation

```yaml
jobs:
  deploy:
    runs-on: self-hosted  # Utilise un runner self-hosted
    steps:
      - uses: actions/checkout@v4
      - name: Deploy
        run: ./deploy-to-internal-server.sh
```

### Labels pour Ciblage

```bash
# Ajouter des labels lors de la config
./config.sh --url ... --labels linux,docker,production
```

```yaml
jobs:
  deploy:
    runs-on: [self-hosted, linux, production]  # Cible un runner spécifique
```

### Risques de Sécurité

!!! danger "JAMAIS sur des Repos Publics"
    Ne **JAMAIS** utiliser de self-hosted runners sur des dépôts publics.

    **Attaque possible :**
    1. Attaquant ouvre une PR malveillante
    2. Le workflow exécute du code arbitraire
    3. Compromission du runner et du réseau interne

    **Mitigation :**
    - ✅ Repos privés uniquement
    - ✅ Validation manuelle des PR externes (via Environments)
    - ✅ Isolation réseau du runner
    - ✅ Principe du moindre privilège

---

## Référence Rapide

```yaml
# === WORKFLOW DE BASE ===
name: CI
on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm test

# === SECRETS ===
env:
  API_KEY: ${{ secrets.API_KEY }}

# === ENVIRONMENTS ===
jobs:
  deploy:
    environment: production
    steps:
      - run: kubectl apply -f k8s/

# === SELF-HOSTED ===
jobs:
  deploy:
    runs-on: [self-hosted, linux]
    steps:
      - run: ./deploy.sh

# === CONDITIONS ===
- name: Deploy (main only)
  if: github.ref == 'refs/heads/main'
  run: ./deploy.sh
```
