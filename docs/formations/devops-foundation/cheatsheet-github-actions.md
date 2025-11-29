---
tags:
  - formation
  - devops
  - github-actions
  - cicd
  - cheatsheet
---

# Cheat Sheet GitHub Actions

Référence rapide pour la syntaxe et les patterns GitHub Actions.

---

## Structure d'un Workflow

```yaml
# .github/workflows/ci.yml
name: CI Pipeline                    # Nom affiché dans GitHub

on:                                  # Triggers (événements déclencheurs)
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:                                 # Variables globales
  NODE_VERSION: '20'

jobs:                                # Liste des jobs
  build:                             # Nom du job
    runs-on: ubuntu-latest           # Runner (machine d'exécution)
    steps:                           # Étapes séquentielles
      - name: Checkout
        uses: actions/checkout@v4
      - name: Build
        run: npm run build
```

---

## Triggers (on:)

### Événements Push/PR

```yaml
on:
  push:
    branches: [main, develop]        # Sur ces branches uniquement
    branches-ignore: [temp/*]        # Ignorer ces branches
    paths: ['src/**', '*.js']        # Seulement si ces fichiers changent
    paths-ignore: ['docs/**']        # Ignorer ces chemins
    tags: ['v*']                     # Sur tags matchant ce pattern

  pull_request:
    branches: [main]
    types: [opened, synchronize, reopened]  # Types d'événements PR
```

### Autres Événements

```yaml
on:
  # Manuel (bouton dans GitHub UI)
  workflow_dispatch:
    inputs:
      environment:
        description: 'Target environment'
        required: true
        default: 'staging'
        type: choice
        options: [staging, production]

  # Planifié (cron)
  schedule:
    - cron: '0 2 * * *'              # Tous les jours à 2h UTC

  # Autres workflows
  workflow_call:                     # Workflow réutilisable
  workflow_run:                      # Après un autre workflow
    workflows: [Build]
    types: [completed]

  # Release
  release:
    types: [published, created]

  # Issues/PR comments
  issue_comment:
    types: [created]
```

---

## Jobs

### Configuration de Base

```yaml
jobs:
  build:
    name: Build Application          # Nom affiché
    runs-on: ubuntu-latest           # Runner
    timeout-minutes: 30              # Timeout (défaut: 360)
    continue-on-error: false         # Stopper le workflow si échec

    steps:
      - uses: actions/checkout@v4
```

### Runners Disponibles

| Runner | OS | Usage |
|--------|-----|-------|
| `ubuntu-latest` | Ubuntu 22.04 | Standard Linux |
| `ubuntu-22.04` | Ubuntu 22.04 | Version spécifique |
| `windows-latest` | Windows Server 2022 | Apps Windows |
| `macos-latest` | macOS 14 (Sonoma) | Apps Apple |
| `self-hosted` | Custom | Runners privés |

### Dépendances entre Jobs

```yaml
jobs:
  lint:
    runs-on: ubuntu-latest
    steps: [...]

  test:
    runs-on: ubuntu-latest
    needs: lint                      # Attend que lint soit OK
    steps: [...]

  build:
    runs-on: ubuntu-latest
    needs: [lint, test]              # Attend lint ET test
    steps: [...]

  deploy:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'  # Condition
    steps: [...]
```

### Matrice (Tests Multi-Versions)

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node: [18, 20, 22]
        os: [ubuntu-latest, windows-latest]
      fail-fast: false               # Continuer même si un job échoue

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
      - run: npm test
```

---

## Steps

### Actions vs Run

```yaml
steps:
  # Action (réutilisable depuis Marketplace)
  - name: Checkout code
    uses: actions/checkout@v4
    with:
      fetch-depth: 0                 # Historique complet

  # Commande shell
  - name: Build
    run: npm run build

  # Script multi-lignes
  - name: Deploy
    run: |
      echo "Deploying..."
      ./deploy.sh
      echo "Done"

  # Shell spécifique
  - name: PowerShell
    shell: pwsh
    run: Get-Process
```

### Conditions (if:)

```yaml
steps:
  # Exécuter seulement sur main
  - name: Deploy
    if: github.ref == 'refs/heads/main'
    run: ./deploy.sh

  # Exécuter même si step précédent échoue
  - name: Cleanup
    if: always()
    run: ./cleanup.sh

  # Exécuter seulement si échec
  - name: Notify failure
    if: failure()
    run: ./notify.sh

  # Exécuter seulement si succès
  - name: Celebrate
    if: success()
    run: echo "All good!"

  # Condition complexe
  - name: Release
    if: |
      github.event_name == 'push' &&
      startsWith(github.ref, 'refs/tags/v')
    run: ./release.sh
```

---

## Variables & Secrets

### Variables d'Environnement

```yaml
env:                                 # Global (workflow)
  APP_NAME: myapp

jobs:
  build:
    env:                             # Job level
      NODE_ENV: production

    steps:
      - name: Print
        env:                         # Step level
          DEBUG: true
        run: |
          echo "App: $APP_NAME"
          echo "Env: $NODE_ENV"
          echo "Debug: $DEBUG"
```

### Contextes GitHub

```yaml
steps:
  - run: |
      echo "Repo: ${{ github.repository }}"
      echo "Branch: ${{ github.ref_name }}"
      echo "SHA: ${{ github.sha }}"
      echo "Actor: ${{ github.actor }}"
      echo "Event: ${{ github.event_name }}"
      echo "Run ID: ${{ github.run_id }}"
      echo "Run Number: ${{ github.run_number }}"
```

### Secrets

```yaml
steps:
  - name: Deploy
    env:
      API_KEY: ${{ secrets.API_KEY }}
      SSH_KEY: ${{ secrets.SSH_PRIVATE_KEY }}
    run: ./deploy.sh

  # Secrets dans with:
  - uses: some/action@v1
    with:
      token: ${{ secrets.GITHUB_TOKEN }}  # Token automatique
```

### Outputs entre Steps

```yaml
steps:
  - name: Get version
    id: version
    run: echo "version=$(cat VERSION)" >> $GITHUB_OUTPUT

  - name: Use version
    run: echo "Version is ${{ steps.version.outputs.version }}"
```

### Outputs entre Jobs

```yaml
jobs:
  prepare:
    runs-on: ubuntu-latest
    outputs:
      version: ${{ steps.version.outputs.version }}
    steps:
      - id: version
        run: echo "version=1.0.0" >> $GITHUB_OUTPUT

  deploy:
    needs: prepare
    runs-on: ubuntu-latest
    steps:
      - run: echo "Deploying ${{ needs.prepare.outputs.version }}"
```

---

## Actions Essentielles

### Checkout

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0                   # Tout l'historique (tags, etc.)
    ref: develop                     # Branche spécifique
    token: ${{ secrets.PAT }}        # Pour repos privés
```

### Setup Runtimes

```yaml
# Node.js
- uses: actions/setup-node@v4
  with:
    node-version: '20'
    cache: 'npm'                     # Cache node_modules

# Python
- uses: actions/setup-python@v5
  with:
    python-version: '3.12'
    cache: 'pip'

# Go
- uses: actions/setup-go@v5
  with:
    go-version: '1.22'

# Java
- uses: actions/setup-java@v4
  with:
    distribution: 'temurin'
    java-version: '21'
```

### Cache

```yaml
- uses: actions/cache@v4
  with:
    path: ~/.npm
    key: ${{ runner.os }}-node-${{ hashFiles('**/package-lock.json') }}
    restore-keys: |
      ${{ runner.os }}-node-
```

### Artifacts

```yaml
# Upload
- uses: actions/upload-artifact@v4
  with:
    name: build-output
    path: dist/
    retention-days: 5

# Download (dans un autre job)
- uses: actions/download-artifact@v4
  with:
    name: build-output
    path: dist/
```

---

## Patterns Courants

### Pipeline Complet

```yaml
name: CI/CD

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm run lint

  test:
    runs-on: ubuntu-latest
    needs: lint
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm test

  build:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npm run build
      - uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  deploy:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    environment: production
    steps:
      - uses: actions/download-artifact@v4
        with:
          name: dist
      - run: ./deploy.sh
```

### Docker Build & Push

```yaml
jobs:
  docker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}
```

### Release Automatique

```yaml
on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci && npm run build

      - uses: softprops/action-gh-release@v1
        with:
          files: dist/*
          generate_release_notes: true
```

---

## Expressions Utiles

```yaml
# Comparaisons
if: github.ref == 'refs/heads/main'
if: github.event_name == 'pull_request'
if: contains(github.event.head_commit.message, '[skip ci]')
if: startsWith(github.ref, 'refs/tags/')

# Logique
if: github.ref == 'refs/heads/main' && github.event_name == 'push'
if: github.ref == 'refs/heads/main' || github.ref == 'refs/heads/develop'
if: "!contains(github.event.head_commit.message, '[skip ci]')"

# Fonctions
${{ toJSON(github) }}               # Debug: voir tout le contexte
${{ hashFiles('**/package-lock.json') }}
${{ format('Hello {0}', github.actor) }}
${{ join(matrix.node, ', ') }}
```

---

## Debug & Troubleshooting

```yaml
steps:
  # Activer le debug
  - run: echo "ACTIONS_STEP_DEBUG=true" >> $GITHUB_ENV

  # Voir le contexte complet
  - run: echo '${{ toJSON(github) }}'

  # Voir les secrets disponibles (noms seulement)
  - run: echo '${{ toJSON(secrets) }}'

  # SSH dans le runner (pour debug)
  - uses: mxschmitt/action-tmate@v3
    if: failure()
```

### Variables de Debug

Définir dans Settings > Secrets :

- `ACTIONS_STEP_DEBUG`: `true` (logs détaillés des steps)
- `ACTIONS_RUNNER_DEBUG`: `true` (logs du runner)

---

## Bonnes Pratiques

1. **Versionner les actions** : `@v4` pas `@main`
2. **Utiliser le cache** pour accélérer les builds
3. **Fail fast** : linting avant tests
4. **Secrets** : jamais en clair, toujours via `secrets.*`
5. **Timeouts** : définir pour éviter les jobs bloqués
6. **Conditions** : `if:` pour éviter les exécutions inutiles
7. **Artifacts** : retention courte (économie stockage)

---

**Retour au :** [Programme de la Formation](index.md) | [Catalogue](../index.md)
