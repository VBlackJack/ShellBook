---
tags:
  - formation
  - devops
  - tp
  - projet
  - pratique
---

# Module 5 : TP Final - Le Projet Ops-Tools

## Objectif du Module

Mettre en pratique **tous les concepts** appris dans les modules précédents en construisant un projet réel : un dépôt Git d'outils SysAdmin avec un pipeline CI/CD complet garantissant la qualité du code.

**Durée :** 2 heures

## Introduction : De la Théorie à la Pratique

### Récapitulatif de la Formation

Au cours des 4 modules précédents, vous avez appris :

| Module | Compétence Acquise |
|--------|-------------------|
| **Module 1 - Git** | Initialiser un repo, commits, push/pull |
| **Module 2 - Branches** | Feature branches, Pull Requests, résolution de conflits |
| **Module 3 - CI/CD** | GitHub Actions, pipelines automatisés, jobs parallèles |
| **Module 4 - Qualité** | ShellCheck, yamllint, Quality Gates, cycle Red-Green |

### Aujourd'hui : Vous Ne Suivez Pas un Tutoriel

**Aujourd'hui, vous êtes un ingénieur DevOps.**

Vous ne suivez pas un tutoriel pas-à-pas. Vous **construisez un projet de A à Z** en appliquant les bonnes pratiques professionnelles :

- ✅ **Git Workflows** : Feature branches, commits atomiques
- ✅ **CI/CD Automation** : Pipeline GitHub Actions automatique
- ✅ **Quality Gates** : Impossible de merger du code de mauvaise qualité
- ✅ **Docs-as-Code** : Documentation dans le repo (README.md)
- ✅ **GitOps** : Le repo Git est la source de vérité

!!! quote "Philosophie DevOps"
    **"Si ce n'est pas dans Git, ça n'existe pas."**

    **"Si le pipeline est rouge, on ne merge pas."**

    **"Automatise tout ce qui peut l'être."**

## Le Projet : Ops-Tools

### Description

**Ops-Tools** est un dépôt Git contenant des scripts Bash réutilisables pour les SysAdmin :

- 🗄️ **backup.sh** : Script de sauvegarde de fichiers/dossiers
- 📊 **monitoring.sh** : Vérification d'espace disque, CPU, RAM
- 🧹 **cleanup.sh** : Nettoyage de logs anciens, cache

**Contraintes :**

- ✅ Tous les scripts doivent passer **ShellCheck** (0 erreur)
- ✅ Pipeline CI/CD qui **échoue** si un script a des erreurs
- ✅ Documentation complète (README.md avec usage)
- ✅ Feature branches (pas de commit direct sur `main`)
- ✅ Pull Requests obligatoires avant merge

### Architecture Finale

```
ops-tools/
├── .github/
│   └── workflows/
│       └── quality.yml       # Pipeline CI/CD
├── scripts/
│   ├── backup.sh             # Script de backup
│   ├── monitoring.sh         # Script de monitoring
│   └── cleanup.sh            # Script de nettoyage
├── .gitignore                # Fichiers à ignorer
└── README.md                 # Documentation
```

## Étape 1 : Initialisation (Git)

### Objectif

Créer le projet Git avec une structure propre et un `.gitignore` approprié.

### Actions

**1.1 - Créer le répertoire du projet**

```bash
# Créer le dossier ops-tools
mkdir ops-tools
cd ops-tools

# Initialiser Git
git init
# Initialized empty Git repository in /home/user/ops-tools/.git/
```

**1.2 - Créer le fichier `.gitignore`**

```bash
cat > .gitignore <<'EOF'
# Logs
*.log
logs/

# Temporary files
*.tmp
*.swp
*~

# OS files
.DS_Store
Thumbs.db

# Backup files
*.bak
*.old

# Secrets (ne JAMAIS commiter)
secrets/
.env
credentials.json
EOF
```

**1.3 - Créer le README initial**

```bash
cat > README.md <<'EOF'
# Ops-Tools

Collection d'outils Bash pour SysAdmin.

## Scripts Disponibles

- `scripts/backup.sh` - Sauvegarde de fichiers/dossiers
- `scripts/monitoring.sh` - Monitoring système (disque, CPU, RAM)
- `scripts/cleanup.sh` - Nettoyage logs et cache

## Prérequis

- Bash 4.0+
- ShellCheck (pour le développement)

## Utilisation

```bash
# Backup
./scripts/backup.sh /source /destination

# Monitoring
./scripts/monitoring.sh

# Cleanup
./scripts/cleanup.sh /var/log
```

## CI/CD

Ce projet utilise GitHub Actions pour garantir la qualité du code :

- ✅ ShellCheck sur tous les scripts `.sh`
- ✅ Quality Gate : Red pipeline = Pas de merge

## Contribution

1. Fork le projet
2. Créer une branche `feat/nom-feature`
3. Commit avec messages Conventional Commits
4. Pousser et créer une Pull Request
5. Attendre validation du pipeline ✅

## Licence

MIT
EOF
```

**1.4 - Premier commit**

```bash
# Ajouter les fichiers
git add .gitignore README.md

# Créer le commit initial
git commit -m "chore: Initialisation projet Ops-Tools"
# [main (root-commit) abc123] chore: Initialisation projet Ops-Tools
#  2 files changed, 45 insertions(+)

# Vérifier l'historique
git log --oneline
# abc123 (HEAD -> main) chore: Initialisation projet Ops-Tools
```

!!! success "Checkpoint 1"
    ✅ Dépôt Git initialisé

    ✅ `.gitignore` créé (prévient les commits accidentels)

    ✅ README.md documenté

    ✅ Premier commit dans l'historique

## Étape 2 : La CI d'Abord (GitHub Actions)

### Objectif

Implémenter le pipeline CI/CD **AVANT** d'écrire le moindre script. C'est le principe **"CI First"** : garantir la qualité dès le départ.

### Actions

**2.1 - Créer la structure GitHub Actions**

```bash
# Créer le répertoire workflows
mkdir -p .github/workflows
```

**2.2 - Créer le pipeline `quality.yml`**

```bash
cat > .github/workflows/quality.yml <<'EOF'
name: Quality Checks

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  shellcheck:
    name: ShellCheck - Bash Linting
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install ShellCheck
        run: sudo apt-get update && sudo apt-get install -y shellcheck

      - name: Run ShellCheck on all scripts
        run: |
          echo "🔍 Vérification de tous les scripts Bash..."

          # Trouver tous les fichiers .sh
          SCRIPTS=$(find scripts/ -name "*.sh" -type f 2>/dev/null || echo "")

          if [ -z "$SCRIPTS" ]; then
            echo "⚠️  Aucun script trouvé dans scripts/"
            exit 0
          fi

          # Variable pour tracker les erreurs
          HAS_ERRORS=0

          # Vérifier chaque script
          while IFS= read -r script; do
            echo ""
            echo "📄 Checking: $script"
            echo "================================"

            if shellcheck "$script"; then
              echo "✅ $script : OK"
            else
              echo "❌ $script : ERREURS DÉTECTÉES"
              HAS_ERRORS=1
            fi
          done <<< "$SCRIPTS"

          echo ""
          echo "================================"

          if [ $HAS_ERRORS -eq 1 ]; then
            echo "❌ Pipeline échoué : Corriger les erreurs ShellCheck"
            exit 1
          else
            echo "✅ Tous les scripts sont conformes !"
            exit 0
          fi

  yaml-lint:
    name: Yamllint - YAML Validation
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install yamllint
        run: pip install yamllint

      - name: Run yamllint
        run: |
          echo "🔍 Vérification des fichiers YAML..."
          yamllint .github/
          echo "✅ Fichiers YAML valides"

  summary:
    name: Quality Summary
    runs-on: ubuntu-latest
    needs: [shellcheck, yaml-lint]

    steps:
      - name: All checks passed
        run: |
          echo "=================================="
          echo "✅ QUALITY GATE : PASSED"
          echo "=================================="
          echo "Tous les checks de qualité sont OK"
          echo "Le code peut être mergé dans main"
EOF
```

**2.3 - Commiter le pipeline**

```bash
git add .github/

git commit -m "ci: Ajout pipeline GitHub Actions (ShellCheck + Yamllint)"
# [main def456] ci: Ajout pipeline GitHub Actions

git log --oneline
# def456 (HEAD -> main) ci: Ajout pipeline GitHub Actions
# abc123 chore: Initialisation projet Ops-Tools
```

**2.4 - Pousser vers GitHub**

```bash
# Créer un repo sur GitHub (via l'interface web ou gh CLI)
gh repo create ops-tools --public --source=. --remote=origin --push

# Ou avec git remote add
git remote add origin git@github.com:votre-username/ops-tools.git
git push -u origin main
```

!!! success "Checkpoint 2"
    ✅ Pipeline CI/CD créé

    ✅ ShellCheck automatique sur tous les `.sh`

    ✅ Yamllint pour valider les workflows

    ✅ Le pipeline est dans Git (versionné)

## Étape 3 : Le Développement (Feature Branch)

### Objectif

Développer le script `backup.sh` dans une **feature branch** (pas directement sur `main`).

**⚠️ IMPORTANT :** Vous allez **volontairement introduire une erreur** pour tester le pipeline.

### Actions

**3.1 - Créer la feature branch**

```bash
# Partir de main à jour
git switch main
git pull origin main

# Créer et basculer vers la branche feature
git switch -c feat/backup-script

# Vérifier la branche active
git branch
#   main
# * feat/backup-script
```

**3.2 - Créer le répertoire scripts**

```bash
mkdir -p scripts
```

**3.3 - Écrire le script `backup.sh` (avec ERREUR intentionnelle)**

```bash
cat > scripts/backup.sh <<'EOF'
#!/bin/bash
# backup.sh - Script de sauvegarde de fichiers/dossiers

SOURCE=$1
DEST=$2

# ERREUR VOLONTAIRE : Variables non quotées (SC2086)
echo "Backup de $SOURCE vers $DEST"

# ERREUR VOLONTAIRE : Pas de validation des arguments
cp -r $SOURCE $DEST

echo "Backup terminé"
EOF

chmod +x scripts/backup.sh
```

**3.4 - Tester localement (optionnel mais recommandé)**

```bash
# Test local avec ShellCheck
shellcheck scripts/backup.sh

# Résultat attendu :
# In scripts/backup.sh line 7:
# echo "Backup de $SOURCE vers $DEST"
#                ^-----^ SC2086: Double quote to prevent globbing
#                               ^---^ SC2086: Double quote to prevent globbing
```

**3.5 - Commiter (avec les erreurs)**

```bash
git add scripts/backup.sh

git commit -m "feat: Ajout script backup.sh (version initiale)"
# [feat/backup-script ghi789] feat: Ajout script backup.sh
```

!!! success "Checkpoint 3"
    ✅ Feature branch créée (`feat/backup-script`)

    ✅ Script `backup.sh` créé (avec erreurs volontaires)

    ✅ Commit dans la branche feature

## Étape 4 : La Preuve (Push & Fail)

### Objectif

Pousser la branche feature vers GitHub et **observer l'échec du pipeline** (Red).

### Actions

**4.1 - Pousser la feature branch**

```bash
git push -u origin feat/backup-script
# Enumerating objects: 5, done.
# Writing objects: 100% (5/5), 450 bytes | 450.00 KiB/s, done.
# To github.com:username/ops-tools.git
#  * [new branch]      feat/backup-script -> feat/backup-script
```

**4.2 - Aller sur GitHub Actions**

1. Ouvrir le repo sur GitHub : `https://github.com/username/ops-tools`
2. Cliquer sur l'onglet **"Actions"**
3. Observer le workflow **"Quality Checks"** en cours d'exécution

**4.3 - Observer l'ÉCHEC (🔴 Red Pipeline)**

**Résultat attendu :**

```
❌ Quality Checks
  ❌ ShellCheck - Bash Linting (15s)
    ✅ Checkout repository
    ✅ Install ShellCheck
    ❌ Run ShellCheck on all scripts
       🔍 Vérification de tous les scripts Bash...

       📄 Checking: scripts/backup.sh
       ================================

       In scripts/backup.sh line 7:
       echo "Backup de $SOURCE vers $DEST"
                      ^-----^ SC2086: Double quote to prevent globbing
                                     ^---^ SC2086: Double quote to prevent globbing

       In scripts/backup.sh line 10:
       cp -r $SOURCE $DEST
             ^-----^ SC2086: Double quote to prevent globbing
                     ^---^ SC2086: Double quote to prevent globbing

       ❌ scripts/backup.sh : ERREURS DÉTECTÉES

       ================================
       ❌ Pipeline échoué : Corriger les erreurs ShellCheck

  🚫 Summary (skipped - job failed)
```

!!! danger "Checkpoint 4 - Pipeline Rouge 🔴"
    ❌ Le pipeline a **échoué** comme prévu

    ❌ ShellCheck a détecté 4 erreurs (SC2086)

    ❌ Le job `summary` n'a **pas été exécuté** (dépendance)

    **→ C'est normal ! Le pipeline fait son travail : bloquer du code de mauvaise qualité.**

## Étape 5 : La Correction (Refactor)

### Objectif

Corriger les erreurs détectées par ShellCheck et re-pousser pour obtenir un **pipeline vert** (Green).

### Actions

**5.1 - Corriger le script localement**

```bash
cat > scripts/backup.sh <<'EOF'
#!/bin/bash
# backup.sh - Script de sauvegarde de fichiers/dossiers

set -euo pipefail  # Arrêter sur erreur

SOURCE="${1:-}"
DEST="${2:-}"

# Validation des arguments
if [[ -z "${SOURCE}" ]] || [[ -z "${DEST}" ]]; then
  echo "Usage: $0 <source> <destination>"
  echo ""
  echo "Exemple:"
  echo "  $0 /home/user/docs /backup/docs"
  exit 1
fi

# Vérification que la source existe
if [[ ! -e "${SOURCE}" ]]; then
  echo "Erreur: Source '${SOURCE}' introuvable"
  exit 1
fi

# Créer le répertoire de destination si besoin
mkdir -p "${DEST}"

# Backup avec log
echo "================================"
echo "Backup en cours..."
echo "Source: ${SOURCE}"
echo "Destination: ${DEST}"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo "================================"

if cp -r "${SOURCE}" "${DEST}"; then
  echo "✅ Backup réussi : ${SOURCE} → ${DEST}"
else
  echo "❌ Erreur lors du backup"
  exit 1
fi
EOF
```

**5.2 - Vérifier localement**

```bash
shellcheck scripts/backup.sh
# (Aucune sortie = 0 erreur)

echo $?
# 0
```

**5.3 - Commiter la correction**

```bash
git add scripts/backup.sh

git commit -m "fix(backup): Correction erreurs ShellCheck (SC2086)

- Variables quotées pour prévenir globbing
- Ajout set -euo pipefail
- Validation des arguments
- Vérification existence source
- Logging amélioré
"

# [feat/backup-script jkl012] fix(backup): Correction erreurs ShellCheck
```

**5.4 - Pousser la correction**

```bash
git push origin feat/backup-script
```

**5.5 - Observer le SUCCÈS (🟢 Green Pipeline)**

**Résultat attendu dans GitHub Actions :**

```
✅ Quality Checks
  ✅ ShellCheck - Bash Linting (12s)
    ✅ Checkout repository
    ✅ Install ShellCheck
    ✅ Run ShellCheck on all scripts
       🔍 Vérification de tous les scripts Bash...

       📄 Checking: scripts/backup.sh
       ================================
       ✅ scripts/backup.sh : OK

       ================================
       ✅ Tous les scripts sont conformes !

  ✅ Yamllint - YAML Validation (8s)
    ✅ Checkout repository
    ✅ Setup Python
    ✅ Install yamllint
    ✅ Run yamllint
       🔍 Vérification des fichiers YAML...
       ✅ Fichiers YAML valides

  ✅ Quality Summary (2s)
    ✅ All checks passed
       ==================================
       ✅ QUALITY GATE : PASSED
       ==================================
       Tous les checks de qualité sont OK
       Le code peut être mergé dans main
```

!!! success "Checkpoint 5 - Pipeline Vert 🟢"
    ✅ Erreurs corrigées

    ✅ ShellCheck : 0 erreur

    ✅ Pipeline **passe** avec succès

    ✅ Le code est **prêt à être mergé**

## Étape 6 : Le Merge (Pull Request)

### Objectif

Créer une Pull Request et merger la feature branch dans `main` après validation du pipeline.

### Actions

**6.1 - Créer la Pull Request**

**Option 1 : Via l'interface GitHub**

1. Aller sur `https://github.com/username/ops-tools`
2. Cliquer sur **"Pull requests"** → **"New pull request"**
3. Base: `main` ← Compare: `feat/backup-script`
4. Titre : `feat: Ajout script backup.sh`
5. Description :

```markdown
## Description

Ajout du script `backup.sh` pour sauvegarder fichiers/dossiers.

## Modifications

- ✅ Script `backup.sh` avec validation arguments
- ✅ Gestion d'erreurs (`set -euo pipefail`)
- ✅ Logging détaillé
- ✅ 0 erreur ShellCheck

## Tests

- ✅ Pipeline CI/CD : Green
- ✅ ShellCheck : Passed
- ✅ Yamllint : Passed

## Checklist

- [x] Code respecte les standards (ShellCheck)
- [x] Pipeline CI/CD passe
- [x] Documentation à jour (README.md)
```

**Option 2 : Via `gh` CLI**

```bash
gh pr create \
  --title "feat: Ajout script backup.sh" \
  --body "Ajout script backup avec validation et gestion d'erreurs. Pipeline CI/CD ✅" \
  --base main \
  --head feat/backup-script
```

**6.2 - Review de la PR**

Observer dans l'interface GitHub :

- ✅ **Checks** : `All checks have passed` (vert)
- ✅ **Files changed** : `scripts/backup.sh` (+40 lignes)
- ✅ **Commits** : 2 commits (initial + fix)

**6.3 - Merger la Pull Request**

Cliquer sur **"Merge pull request"** → **"Confirm merge"**

**Option CLI :**

```bash
gh pr merge --squash --delete-branch
# ✓ Merged pull request #1 (feat: Ajout script backup.sh)
# ✓ Deleted branch feat/backup-script
```

**6.4 - Mettre à jour `main` localement**

```bash
git switch main

git pull origin main
# Updating def456..mno345
# Fast-forward
#  scripts/backup.sh | 40 ++++++++++++++++++++++++++++++++++++++++
#  1 file changed, 40 insertions(+)

git log --oneline
# mno345 (HEAD -> main, origin/main) feat: Ajout script backup.sh
# def456 ci: Ajout pipeline GitHub Actions
# abc123 chore: Initialisation projet Ops-Tools
```

!!! success "Checkpoint 6 - Projet Terminé 🎉"
    ✅ Pull Request créée et validée

    ✅ Pipeline vert sur la PR

    ✅ Code mergé dans `main`

    ✅ Branche feature supprimée (cleanup)

    ✅ `main` local à jour

## Conclusion : Vous Êtes DevOps

### Ce Que Vous Avez Accompli

En complétant ce TP, vous avez mis en œuvre un **workflow DevOps professionnel complet** :

**🔀 Module 1 (Git) :**
- ✅ Initialisation repo Git
- ✅ Commits atomiques avec messages Conventional Commits
- ✅ `.gitignore` pour éviter les secrets

**🌿 Module 2 (Branches) :**
- ✅ Feature branches (`feat/backup-script`)
- ✅ Pas de commit direct sur `main`
- ✅ Pull Request avec review

**🚀 Module 3 (CI/CD) :**
- ✅ Pipeline GitHub Actions automatique
- ✅ Déclenchement sur `push` et `pull_request`
- ✅ Jobs parallèles (shellcheck, yamllint)

**✅ Module 4 (Qualité) :**
- ✅ Quality Gates (Red pipeline = No merge)
- ✅ ShellCheck pour prévenir les bugs
- ✅ Cycle Red → Fix → Green

### Vous Êtes Maintenant un Praticien

**🎓 Docs-as-Code :** Votre projet Git contient tout (code + doc + CI).

**🔄 GitOps :** Le repo Git est la source de vérité.

**🛡️ Quality First :** Impossible de merger du code de mauvaise qualité.

**⚡ Automation :** Les tests s'exécutent automatiquement, pas manuellement.

!!! quote "Citation DevOps"
    **"You are not a developer who learned Git. You are a DevOps engineer who automates quality."**

### Prochaines Étapes

**Pour aller plus loin avec Ops-Tools :**

1. **Ajouter plus de scripts** :
   - `scripts/monitoring.sh` : Vérifier CPU, RAM, disque
   - `scripts/cleanup.sh` : Nettoyer logs anciens

2. **Améliorer le pipeline** :
   - Ajouter `hadolint` pour vérifier les Dockerfiles
   - Ajouter tests fonctionnels (BATS - Bash Automated Testing System)

3. **Déploiement** :
   - Packager les scripts dans un `.deb` ou `.rpm`
   - Publier sur GitHub Releases

4. **Documentation** :
   - Ajouter une page MkDocs
   - Générer la doc avec GitHub Pages

**Pour continuer votre parcours DevOps :**

- 🚀 Formation **"Hardening Linux"** : Sécuriser vos scripts et serveurs
- 💠 Formation **"Ansible Mastery"** : Automatiser le déploiement de vos scripts
- ☸️ Guide **"Kubernetes Survival"** : Orchestrer vos outils dans des containers

## Solution Complète

??? quote "Fichiers Finaux du Projet"
    ### `scripts/backup.sh` (Version Finale)

    ```bash
    #!/bin/bash
    # backup.sh - Script de sauvegarde de fichiers/dossiers
    # Usage: ./backup.sh <source> <destination>

    set -euo pipefail  # Arrêter sur erreur, variables non définies, erreurs de pipe

    # Variables
    SOURCE="${1:-}"
    DEST="${2:-}"
    TIMESTAMP=$(date '+%Y%m%d_%H%M%S')
    LOG_FILE="/var/log/backup_${TIMESTAMP}.log"

    # Fonction de logging
    log() {
      local message="$1"
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] ${message}" | tee -a "${LOG_FILE}"
    }

    # Validation des arguments
    if [[ -z "${SOURCE}" ]] || [[ -z "${DEST}" ]]; then
      echo "Usage: $0 <source> <destination>"
      echo ""
      echo "Exemples:"
      echo "  $0 /home/user/docs /backup/docs"
      echo "  $0 /etc/nginx /backup/nginx"
      exit 1
    fi

    # Vérification que la source existe
    if [[ ! -e "${SOURCE}" ]]; then
      log "ERROR: Source '${SOURCE}' introuvable"
      exit 1
    fi

    # Créer le répertoire de destination si besoin
    if ! mkdir -p "${DEST}"; then
      log "ERROR: Impossible de créer '${DEST}'"
      exit 1
    fi

    # Backup avec log
    log "===================================="
    log "Démarrage du backup"
    log "===================================="
    log "Source: ${SOURCE}"
    log "Destination: ${DEST}"
    log "Timestamp: ${TIMESTAMP}"

    # Copie avec préservation des permissions
    if cp -rp "${SOURCE}" "${DEST}/"; then
      BACKUP_SIZE=$(du -sh "${DEST}" | cut -f1)
      log "✅ Backup réussi"
      log "Taille: ${BACKUP_SIZE}"
      log "Emplacement: ${DEST}"
    else
      log "❌ Erreur lors du backup"
      exit 1
    fi

    log "===================================="
    log "Backup terminé avec succès"
    log "Log disponible: ${LOG_FILE}"
    log "===================================="
    ```

    ### `.github/workflows/quality.yml` (Version Finale)

    ```yaml
    name: Quality Checks

    on:
      push:
        branches: [main]
      pull_request:
        branches: [main]

    jobs:
      shellcheck:
        name: ShellCheck - Bash Linting
        runs-on: ubuntu-latest

        steps:
          - name: Checkout repository
            uses: actions/checkout@v4

          - name: Install ShellCheck
            run: sudo apt-get update && sudo apt-get install -y shellcheck

          - name: Run ShellCheck on all scripts
            run: |
              echo "🔍 Vérification de tous les scripts Bash..."

              # Trouver tous les fichiers .sh
              SCRIPTS=$(find scripts/ -name "*.sh" -type f 2>/dev/null || echo "")

              if [ -z "$SCRIPTS" ]; then
                echo "⚠️  Aucun script trouvé dans scripts/"
                exit 0
              fi

              # Variable pour tracker les erreurs
              HAS_ERRORS=0

              # Vérifier chaque script
              while IFS= read -r script; do
                echo ""
                echo "📄 Checking: $script"
                echo "================================"

                if shellcheck "$script"; then
                  echo "✅ $script : OK"
                else
                  echo "❌ $script : ERREURS DÉTECTÉES"
                  HAS_ERRORS=1
                fi
              done <<< "$SCRIPTS"

              echo ""
              echo "================================"

              if [ $HAS_ERRORS -eq 1 ]; then
                echo "❌ Pipeline échoué : Corriger les erreurs ShellCheck"
                exit 1
              else
                echo "✅ Tous les scripts sont conformes !"
                exit 0
              fi

      yaml-lint:
        name: Yamllint - YAML Validation
        runs-on: ubuntu-latest

        steps:
          - name: Checkout repository
            uses: actions/checkout@v4

          - name: Setup Python
            uses: actions/setup-python@v5
            with:
              python-version: '3.11'

          - name: Install yamllint
            run: pip install yamllint

          - name: Run yamllint
            run: |
              echo "🔍 Vérification des fichiers YAML..."
              yamllint .github/
              echo "✅ Fichiers YAML valides"

      summary:
        name: Quality Summary
        runs-on: ubuntu-latest
        needs: [shellcheck, yaml-lint]

        steps:
          - name: All checks passed
            run: |
              echo "=================================="
              echo "✅ QUALITY GATE : PASSED"
              echo "=================================="
              echo "Tous les checks de qualité sont OK"
              echo "Le code peut être mergé dans main"
    ```

    ### Structure Finale du Projet

    ```
    ops-tools/
    ├── .github/
    │   └── workflows/
    │       └── quality.yml
    ├── scripts/
    │   └── backup.sh
    ├── .gitignore
    └── README.md
    ```

    ### Commandes Git Complètes

    ```bash
    # Initialisation
    mkdir ops-tools && cd ops-tools
    git init
    # Créer .gitignore, README.md
    git add .
    git commit -m "chore: Initialisation projet Ops-Tools"

    # Pipeline CI
    mkdir -p .github/workflows
    # Créer quality.yml
    git add .github/
    git commit -m "ci: Ajout pipeline GitHub Actions"
    git push -u origin main

    # Feature branch
    git switch -c feat/backup-script
    mkdir -p scripts
    # Créer backup.sh (avec erreurs)
    git add scripts/backup.sh
    git commit -m "feat: Ajout script backup.sh (version initiale)"
    git push -u origin feat/backup-script

    # Correction après échec pipeline
    # Corriger backup.sh
    git add scripts/backup.sh
    git commit -m "fix(backup): Correction erreurs ShellCheck"
    git push origin feat/backup-script

    # Merge via Pull Request
    gh pr create --title "feat: Ajout script backup.sh" --base main
    gh pr merge --squash --delete-branch

    # Mise à jour local
    git switch main
    git pull origin main
    ```

**Félicitations ! Vous avez terminé la formation "Le Socle DevOps". 🎓🚀**

---

**Retour au :** [Programme de la Formation](index.md) | [Catalogue](../index.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 4 : Qualité de Code & Linting](04-module.md) | [Programme →](index.md) |

[Retour au Programme](index.md){ .md-button }
