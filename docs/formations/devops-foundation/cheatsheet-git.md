---
tags:
  - formation
  - devops
  - git
  - cheatsheet
  - reference
---

# Cheat Sheet Git

Référence rapide des commandes Git essentielles. Imprimable format A4.

---

## Configuration Initiale

```bash
# Identité (obligatoire)
git config --global user.name "Prénom Nom"
git config --global user.email "email@example.com"

# Éditeur par défaut
git config --global core.editor "code --wait"  # VS Code
git config --global core.editor "vim"          # Vim

# Branche par défaut
git config --global init.defaultBranch main

# Voir la configuration
git config --list
```

---

## Les 3 Zones Git

```
┌─────────────────┐    git add     ┌─────────────────┐   git commit   ┌─────────────────┐
│ Working         │ ────────────▶  │ Staging         │ ────────────▶  │ Repository      │
│ Directory       │                │ Area (Index)    │                │ (.git)          │
│                 │ ◀────────────  │                 │                │                 │
└─────────────────┘  git restore   └─────────────────┘                └─────────────────┘
```

---

## Commandes de Base

### Initialisation & Clonage

```bash
git init                          # Créer un repo local
git clone <url>                   # Cloner un repo distant
git clone <url> <dossier>         # Cloner dans un dossier spécifique
```

### Statut & Historique

```bash
git status                        # État du repo (modifiés, staged, untracked)
git status -s                     # Format court
git log                           # Historique des commits
git log --oneline                 # Format condensé
git log --oneline --graph         # Avec branches visualisées
git log -5                        # 5 derniers commits
git diff                          # Différences non stagées
git diff --staged                 # Différences stagées (prêtes à commit)
```

### Staging & Commit

```bash
git add <fichier>                 # Stager un fichier
git add .                         # Stager tous les fichiers modifiés
git add -A                        # Stager tout (modifiés + supprimés + nouveaux)
git add -p                        # Stager interactivement (par hunks)

git commit -m "message"           # Commiter avec message
git commit -am "message"          # Add + Commit (fichiers trackés uniquement)
git commit --amend                # Modifier le dernier commit (attention!)
```

### Annuler des Changements

```bash
git restore <fichier>             # Annuler modifications (working → dernier commit)
git restore --staged <fichier>    # Unstage (staged → working)
git reset HEAD~1                  # Annuler dernier commit (garde les fichiers)
git reset --hard HEAD~1           # Annuler dernier commit (SUPPRIME les fichiers!)
git revert <commit>               # Créer un commit inverse (safe)
```

---

## Branches

### Gestion des Branches

```bash
git branch                        # Lister branches locales
git branch -a                     # Lister toutes (locales + remotes)
git branch -v                     # Avec dernier commit
git branch <nom>                  # Créer une branche
git branch -d <nom>               # Supprimer (si mergée)
git branch -D <nom>               # Supprimer (force)
git branch -m <ancien> <nouveau>  # Renommer
```

### Navigation

```bash
git switch <branche>              # Basculer vers une branche (moderne)
git switch -c <branche>           # Créer et basculer (moderne)
git checkout <branche>            # Basculer (ancienne syntaxe)
git checkout -b <branche>         # Créer et basculer (ancienne syntaxe)
```

### Merge & Rebase

```bash
git merge <branche>               # Fusionner branche dans HEAD
git merge --no-ff <branche>       # Forcer un merge commit
git rebase <branche>              # Réappliquer commits sur branche (réécrit!)
git rebase -i HEAD~3              # Rebase interactif (3 derniers commits)
```

---

## Remote (Dépôt Distant)

### Configuration

```bash
git remote -v                     # Lister les remotes
git remote add origin <url>       # Ajouter un remote
git remote set-url origin <url>   # Modifier l'URL
git remote remove origin          # Supprimer un remote
```

### Synchronisation

```bash
git fetch                         # Récupérer sans merger
git fetch --all                   # Récupérer tous les remotes
git pull                          # Fetch + Merge
git pull --rebase                 # Fetch + Rebase (historique propre)
git push                          # Envoyer vers remote
git push -u origin <branche>      # Push + définir upstream
git push origin --delete <branche># Supprimer branche distante
```

---

## Stash (Mise de Côté)

```bash
git stash                         # Mettre de côté les modifications
git stash -m "message"            # Avec message descriptif
git stash list                    # Lister les stashs
git stash show                    # Voir le contenu du dernier stash
git stash pop                     # Appliquer et supprimer le stash
git stash apply                   # Appliquer sans supprimer
git stash drop                    # Supprimer le dernier stash
git stash clear                   # Supprimer tous les stashs
```

---

## Tags (Versions)

```bash
git tag                           # Lister les tags
git tag v1.0.0                    # Créer un tag léger
git tag -a v1.0.0 -m "Release"    # Créer un tag annoté
git tag -a v1.0.0 <commit>        # Tagger un commit spécifique
git push origin v1.0.0            # Pousser un tag
git push origin --tags            # Pousser tous les tags
git tag -d v1.0.0                 # Supprimer localement
git push origin --delete v1.0.0   # Supprimer sur remote
```

---

## Inspection & Debug

```bash
git show <commit>                 # Détails d'un commit
git blame <fichier>               # Qui a modifié chaque ligne
git bisect start                  # Recherche binaire de bug
git bisect good <commit>          # Marquer comme OK
git bisect bad <commit>           # Marquer comme bugué
git reflog                        # Historique de HEAD (récupération!)
```

---

## Cherry-Pick

```bash
git cherry-pick <commit>          # Appliquer un commit spécifique
git cherry-pick <c1> <c2>         # Appliquer plusieurs commits
git cherry-pick --abort           # Annuler en cas de conflit
```

---

## Résolution de Conflits

```bash
# 1. Identifier les conflits
git status                        # Fichiers en conflit marqués "both modified"

# 2. Ouvrir et résoudre manuellement
# Chercher les marqueurs:
# <<<<<<< HEAD
# (votre version)
# =======
# (version à merger)
# >>>>>>> branche

# 3. Marquer comme résolu
git add <fichier>

# 4. Finaliser
git commit                        # Termine le merge
git merge --abort                 # Annuler le merge si besoin
```

---

## Patterns de Nommage

### Branches

| Pattern | Usage |
|---------|-------|
| `main` | Branche principale (production) |
| `develop` | Branche d'intégration |
| `feature/<nom>` | Nouvelle fonctionnalité |
| `bugfix/<nom>` | Correction de bug |
| `hotfix/<nom>` | Correctif urgent production |
| `release/<version>` | Préparation release |

### Commits (Conventional Commits)

| Préfixe | Usage |
|---------|-------|
| `feat:` | Nouvelle fonctionnalité |
| `fix:` | Correction de bug |
| `docs:` | Documentation |
| `style:` | Formatage (pas de logique) |
| `refactor:` | Refactoring |
| `test:` | Ajout/modification tests |
| `chore:` | Maintenance, build |
| `ci:` | Pipeline CI/CD |

---

## Workflow GitHub Flow

```bash
# 1. Partir de main à jour
git switch main && git pull

# 2. Créer feature branch
git switch -c feature/ma-feature

# 3. Travailler et commiter
git add . && git commit -m "feat: description"

# 4. Pousser
git push -u origin feature/ma-feature

# 5. Créer Pull Request (GitHub UI ou gh CLI)
gh pr create

# 6. Après merge, nettoyer
git switch main && git pull
git branch -d feature/ma-feature
```

---

## Raccourcis Utiles (.gitconfig)

```ini
[alias]
    st = status -s
    co = checkout
    sw = switch
    br = branch
    ci = commit
    lg = log --oneline --graph --all
    last = log -1 HEAD
    unstage = restore --staged
    undo = reset HEAD~1
    amend = commit --amend --no-edit
```

Ajouter dans `~/.gitconfig` ou via :

```bash
git config --global alias.st "status -s"
git config --global alias.lg "log --oneline --graph --all"
```

---

## Fichier .gitignore

```gitignore
# Logs
*.log
logs/

# Dépendances
node_modules/
vendor/
.venv/

# Build
dist/
build/
*.exe

# IDE
.idea/
.vscode/
*.swp

# OS
.DS_Store
Thumbs.db

# Secrets (JAMAIS commiter!)
.env
*.key
credentials.json
secrets/
```

---

**Retour au :** [Programme de la Formation](index.md) | [Catalogue](../index.md)
