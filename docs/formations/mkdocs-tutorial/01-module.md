---
tags:
  - mkdocs
  - installation
  - python
  - pip
---

# Module 1 : Installation & Premier Site

**Durée estimée :** 30 minutes

---

## Objectifs

À la fin de ce module, vous saurez :

- Installer Python et pip
- Installer MkDocs avec le thème Material
- Créer un projet de documentation
- Lancer un serveur de prévisualisation
- Comprendre la structure des fichiers

---

## 1. Installation de Python

MkDocs est écrit en Python. Vérifions d'abord que Python est installé :

```bash
python --version
# ou
python3 --version
```

!!! info "Version Requise"
    MkDocs Material nécessite **Python 3.8 ou supérieur**.

=== "Windows"

    ```powershell
    # Option 1 : Télécharger depuis python.org
    # https://www.python.org/downloads/

    # Option 2 : Avec Chocolatey
    choco install python

    # Option 3 : Avec winget
    winget install Python.Python.3.12
    ```

    !!! warning "Cochez 'Add Python to PATH'"
        Lors de l'installation, cochez la case **"Add Python to PATH"** pour pouvoir utiliser `python` depuis n'importe quel terminal.

=== "Linux (Ubuntu/Debian)"

    ```bash
    sudo apt update
    sudo apt install python3 python3-pip python3-venv
    ```

=== "Linux (RHEL/Rocky)"

    ```bash
    sudo dnf install python3 python3-pip
    ```

=== "macOS"

    ```bash
    # Avec Homebrew
    brew install python
    ```

---

## 2. Installation de MkDocs Material

### Méthode Recommandée : Environnement Virtuel

```bash
# Créer un dossier pour votre projet
mkdir mon-site-docs
cd mon-site-docs

# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement virtuel
# Linux/macOS:
source venv/bin/activate
# Windows:
.\venv\Scripts\activate

# Installer MkDocs Material (inclut MkDocs)
pip install mkdocs-material
```

!!! tip "Pourquoi un Environnement Virtuel ?"
    Un environnement virtuel isole les dépendances de votre projet. Cela évite les conflits entre projets et facilite la reproductibilité.

### Vérifier l'Installation

```bash
mkdocs --version
# mkdocs, version 1.6.x
```

### Créer un fichier requirements.txt

Pour faciliter l'installation sur d'autres machines :

```bash
pip freeze > requirements.txt
```

Contenu typique :

```text
mkdocs-material>=9.5
mkdocs-mermaid2-plugin>=1.1
```

---

## 3. Créer Votre Premier Site

### Initialiser le Projet

```bash
mkdocs new .
```

Cette commande crée la structure suivante :

```text
mon-site-docs/
├── docs/
│   └── index.md      # Page d'accueil
├── mkdocs.yml        # Configuration
└── venv/             # Environnement virtuel
```

### Configuration de Base

Éditez `mkdocs.yml` :

```yaml
# Informations du site
site_name: Ma Documentation
site_url: https://monuser.github.io/mon-site-docs
site_author: Votre Nom
site_description: Documentation technique de mon projet

# Thème Material
theme:
  name: material
  language: fr
  palette:
    primary: indigo
    accent: amber
  features:
    - navigation.instant
    - navigation.tabs
    - navigation.top
    - search.highlight
    - content.code.copy

# Extensions Markdown
markdown_extensions:
  - admonition
  - pymdownx.details
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format
  - pymdownx.tabbed:
      alternate_style: true
  - pymdownx.highlight:
      anchor_linenums: true
  - pymdownx.inlinehilite
  - tables
  - attr_list
  - md_in_html

# Plugins
plugins:
  - search:
      lang: fr
```

### Page d'Accueil

Éditez `docs/index.md` :

```markdown
# Bienvenue sur Ma Documentation

Ceci est votre premier site MkDocs !

## Démarrage Rapide

!!! tip "Astuce"
    Utilisez `mkdocs serve` pour prévisualiser vos modifications en temps réel.

## Exemple de Code

```bash
echo "Hello, MkDocs!"
```

## Exemple de Diagramme

```mermaid
flowchart LR
    A[Début] --> B[Milieu]
    B --> C[Fin]
```
```

---

## 4. Prévisualisation Locale

```bash
mkdocs serve
```

Sortie attendue :

```text
INFO    -  Building documentation...
INFO    -  Cleaning site directory
INFO    -  Documentation built in 0.50 seconds
INFO    -  [14:30:00] Watching paths for changes: 'docs', 'mkdocs.yml'
INFO    -  [14:30:00] Serving on http://127.0.0.1:8000/
```

Ouvrez **http://localhost:8000** dans votre navigateur.

!!! success "Rechargement Automatique"
    Modifiez un fichier `.md` et sauvegardez : la page se recharge automatiquement !

### Options Utiles

```bash
# Changer le port
mkdocs serve -a 0.0.0.0:8080

# Mode strict (erreurs = échec)
mkdocs serve --strict

# Ouvrir automatiquement le navigateur
mkdocs serve --open
```

---

## 5. Structure des Fichiers

### Arborescence Typique

```text
mon-site-docs/
├── docs/
│   ├── index.md              # Page d'accueil
│   ├── getting-started.md    # Guide de démarrage
│   ├── installation/
│   │   ├── index.md          # Index de la section
│   │   ├── linux.md
│   │   └── windows.md
│   ├── guides/
│   │   ├── basic.md
│   │   └── advanced.md
│   └── assets/
│       ├── images/
│       │   └── logo.png
│       └── stylesheets/
│           └── extra.css
├── mkdocs.yml
├── requirements.txt
└── .gitignore
```

### Navigation dans mkdocs.yml

```yaml
nav:
  - Accueil: index.md
  - Démarrage: getting-started.md
  - Installation:
      - Vue d'ensemble: installation/index.md
      - Linux: installation/linux.md
      - Windows: installation/windows.md
  - Guides:
      - Basique: guides/basic.md
      - Avancé: guides/advanced.md
```

!!! info "Navigation Automatique"
    Si vous ne définissez pas `nav`, MkDocs génère automatiquement la navigation basée sur la structure des dossiers.

---

## 6. Build pour Production

```bash
# Générer le site statique
mkdocs build

# Le site est dans le dossier 'site/'
ls site/
```

Contenu du dossier `site/` :

```text
site/
├── index.html
├── getting-started/
│   └── index.html
├── assets/
│   ├── javascripts/
│   └── stylesheets/
├── search/
│   └── search_index.json
└── sitemap.xml
```

!!! warning "Ne pas versionner site/"
    Ajoutez `site/` à votre `.gitignore`. Ce dossier est généré automatiquement.

---

## 7. Fichier .gitignore

Créez un fichier `.gitignore` :

```text
# Environnement virtuel
venv/
.venv/

# Build MkDocs
site/

# Python
__pycache__/
*.pyc
.pytest_cache/

# IDE
.idea/
.vscode/
*.swp

# OS
.DS_Store
Thumbs.db
```

---

## Exercice Pratique

### Objectif

Créer un site de documentation avec 3 pages.

### Instructions

1. **Créer le projet** :
   ```bash
   mkdir exercice-mkdocs && cd exercice-mkdocs
   python -m venv venv
   source venv/bin/activate  # ou .\venv\Scripts\activate sur Windows
   pip install mkdocs-material
   mkdocs new .
   ```

2. **Configurer** `mkdocs.yml` avec le thème Material

3. **Créer 3 pages** :
   - `docs/index.md` : Page d'accueil
   - `docs/installation.md` : Guide d'installation
   - `docs/usage.md` : Guide d'utilisation

4. **Ajouter la navigation** dans `mkdocs.yml`

5. **Prévisualiser** avec `mkdocs serve`

### Solution

??? example "Voir la solution"

    **mkdocs.yml :**
    ```yaml
    site_name: Mon Exercice MkDocs
    theme:
      name: material
      language: fr

    nav:
      - Accueil: index.md
      - Installation: installation.md
      - Utilisation: usage.md

    markdown_extensions:
      - admonition
      - pymdownx.superfences
    ```

    **docs/index.md :**
    ```markdown
    # Bienvenue

    Ceci est mon premier site MkDocs !

    ## Navigation

    - [Installation](installation.md)
    - [Utilisation](usage.md)
    ```

    **docs/installation.md :**
    ```markdown
    # Installation

    ## Prérequis

    - Python 3.8+
    - pip

    ## Étapes

    ```bash
    pip install mkdocs-material
    ```
    ```

    **docs/usage.md :**
    ```markdown
    # Utilisation

    ## Commandes

    | Commande | Description |
    |----------|-------------|
    | `mkdocs serve` | Serveur local |
    | `mkdocs build` | Build production |
    ```
    ```

---

## Résumé

| Commande | Description |
|----------|-------------|
| `pip install mkdocs-material` | Installer MkDocs + Material |
| `mkdocs new .` | Créer un nouveau projet |
| `mkdocs serve` | Serveur de développement |
| `mkdocs build` | Générer le site statique |
| `mkdocs --help` | Aide |

---

## Prochaine Étape

Vous avez créé votre premier site MkDocs ! Dans le prochain module, nous verrons comment le déployer automatiquement sur GitHub Pages.

[:octicons-arrow-right-24: Module 2 : Déploiement GitHub Pages](02-module.md)
