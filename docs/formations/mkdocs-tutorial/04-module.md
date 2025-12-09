---
tags:
  - mkdocs
  - configuration
  - material
  - plugins
  - customization
---

# Module 4 : Configuration Avancée

**Durée estimée :** 1 heure

---

## Objectifs

À la fin de ce module, vous saurez :

- Personnaliser le thème Material (couleurs, polices, logo)
- Configurer la navigation avancée
- Utiliser les plugins essentiels
- Maîtriser les admonitions et tabs
- Optimiser le SEO et ajouter des analytics

---

## 1. Configuration Complète mkdocs.yml

Voici un fichier de configuration complet et commenté :

```yaml
# ============================================================
# INFORMATIONS DU SITE
# ============================================================
site_name: Ma Documentation
site_url: https://monuser.github.io/mon-site/
site_author: Votre Nom
site_description: >-
  Documentation technique complète pour mon projet.
  Guides, tutoriels et références.

# Repository GitHub (affiche le bouton "Edit on GitHub")
repo_name: monuser/mon-site
repo_url: https://github.com/monuser/mon-site
edit_uri: edit/main/docs/

# ============================================================
# THÈME MATERIAL
# ============================================================
theme:
  name: material
  language: fr

  # Logo et favicon
  logo: assets/images/logo.png
  favicon: assets/images/favicon.ico

  # Palette de couleurs (mode clair/sombre)
  palette:
    # Mode clair
    - scheme: default
      primary: indigo
      accent: amber
      toggle:
        icon: material/brightness-7
        name: Passer en mode sombre

    # Mode sombre
    - scheme: slate
      primary: indigo
      accent: amber
      toggle:
        icon: material/brightness-4
        name: Passer en mode clair

  # Police de caractères
  font:
    text: Roboto
    code: Roboto Mono

  # Fonctionnalités
  features:
    # Navigation
    - navigation.instant        # Chargement instantané (SPA)
    - navigation.instant.prefetch
    - navigation.tracking       # URL mise à jour au scroll
    - navigation.tabs           # Onglets en haut
    - navigation.tabs.sticky    # Onglets fixes au scroll
    - navigation.sections       # Sections dans le menu
    - navigation.expand         # Sous-menus dépliés
    - navigation.path           # Fil d'Ariane
    - navigation.top            # Bouton retour en haut
    - navigation.footer         # Navigation pied de page

    # Table des matières
    - toc.follow                # TOC suit le scroll
    - toc.integrate             # TOC intégrée dans le menu

    # Recherche
    - search.suggest            # Suggestions de recherche
    - search.highlight          # Surlignage des résultats
    - search.share              # Partager les recherches

    # Contenu
    - content.code.copy         # Bouton copier le code
    - content.code.annotate     # Annotations dans le code
    - content.tabs.link         # Lier les tabs entre pages

  # Icônes personnalisées
  icon:
    repo: fontawesome/brands/github
    edit: material/pencil

# ============================================================
# EXTENSIONS MARKDOWN
# ============================================================
markdown_extensions:
  # Tables
  - tables

  # Attributs HTML
  - attr_list
  - md_in_html

  # Définitions
  - def_list

  # Notes de bas de page
  - footnotes

  # Admonitions (encadrés)
  - admonition
  - pymdownx.details

  # Onglets
  - pymdownx.tabbed:
      alternate_style: true

  # Code
  - pymdownx.highlight:
      anchor_linenums: true
      line_spans: __span
      pygments_lang_class: true
  - pymdownx.inlinehilite
  - pymdownx.snippets
  - pymdownx.superfences:
      custom_fences:
        - name: mermaid
          class: mermaid
          format: !!python/name:pymdownx.superfences.fence_code_format

  # Formatage
  - pymdownx.critic
  - pymdownx.caret
  - pymdownx.keys
  - pymdownx.mark
  - pymdownx.tilde

  # Emojis
  - pymdownx.emoji:
      emoji_index: !!python/name:material.extensions.emoji.twemoji
      emoji_generator: !!python/name:material.extensions.emoji.to_svg

  # Listes de tâches
  - pymdownx.tasklist:
      custom_checkbox: true

  # Table des matières
  - toc:
      permalink: true
      title: Sur cette page

# ============================================================
# PLUGINS
# ============================================================
plugins:
  # Recherche
  - search:
      lang: fr
      separator: '[\s\-\.]+'

  # Date de modification
  - git-revision-date-localized:
      enable_creation_date: true
      type: timeago
      fallback_to_build_date: true

  # Redimensionnement images
  - glightbox

  # Minification
  - minify:
      minify_html: true

# ============================================================
# PERSONNALISATION
# ============================================================
extra:
  # Liens sociaux
  social:
    - icon: fontawesome/brands/github
      link: https://github.com/monuser
    - icon: fontawesome/brands/twitter
      link: https://twitter.com/monuser
    - icon: fontawesome/brands/linkedin
      link: https://linkedin.com/in/monuser

  # Analytics
  analytics:
    provider: google
    property: G-XXXXXXXXXX

  # Bannière d'annonce
  # announcement: "Nouvelle version 2.0 disponible !"

  # Générateur (footer)
  generator: false

# CSS personnalisé
extra_css:
  - assets/stylesheets/extra.css

# JavaScript personnalisé
extra_javascript:
  - assets/javascripts/extra.js

# ============================================================
# NAVIGATION
# ============================================================
nav:
  - Accueil: index.md
  - Démarrage:
      - Installation: getting-started/installation.md
      - Configuration: getting-started/configuration.md
      - Premier pas: getting-started/first-steps.md
  - Guides:
      - guides/index.md
      - Basique: guides/basic.md
      - Avancé: guides/advanced.md
  - Référence:
      - API: reference/api.md
      - CLI: reference/cli.md
  - À propos: about.md
```

---

## 2. Palette de Couleurs

### Couleurs Disponibles

Material propose ces couleurs primaires :

| Couleur | Code |
|---------|------|
| `red` | Rouge |
| `pink` | Rose |
| `purple` | Violet |
| `deep purple` | Violet foncé |
| `indigo` | Indigo |
| `blue` | Bleu |
| `light blue` | Bleu clair |
| `cyan` | Cyan |
| `teal` | Sarcelle |
| `green` | Vert |
| `light green` | Vert clair |
| `lime` | Citron vert |
| `yellow` | Jaune |
| `amber` | Ambre |
| `orange` | Orange |
| `deep orange` | Orange foncé |
| `brown` | Marron |
| `grey` | Gris |
| `blue grey` | Gris bleu |

### Mode Clair/Sombre

```yaml
theme:
  palette:
    # Mode clair par défaut
    - scheme: default
      primary: blue
      accent: orange
      toggle:
        icon: material/brightness-7
        name: Mode sombre

    # Mode sombre
    - scheme: slate
      primary: blue
      accent: orange
      toggle:
        icon: material/brightness-4
        name: Mode clair
```

### CSS Personnalisé

Créez `docs/assets/stylesheets/extra.css` :

```css
/* Couleur primaire personnalisée */
:root {
  --md-primary-fg-color: #1a237e;
  --md-primary-fg-color--light: #534bae;
  --md-primary-fg-color--dark: #000051;
  --md-accent-fg-color: #ff6f00;
}

/* Mode sombre */
[data-md-color-scheme="slate"] {
  --md-primary-fg-color: #303f9f;
}

/* Personnaliser les admonitions */
.md-typeset .admonition.custom,
.md-typeset details.custom {
  border-color: #ff5722;
}

.md-typeset .custom > .admonition-title,
.md-typeset .custom > summary {
  background-color: rgba(255, 87, 34, 0.1);
}
```

---

## 3. Navigation Avancée

### Onglets (Tabs)

```yaml
theme:
  features:
    - navigation.tabs
    - navigation.tabs.sticky
```

Résultat : Les sections de premier niveau deviennent des onglets.

### Sections Dépliées

```yaml
theme:
  features:
    - navigation.sections
    - navigation.expand
```

### Table des Matières Intégrée

```yaml
theme:
  features:
    - toc.integrate  # TOC dans le menu latéral
```

### Navigation Multi-niveaux

```yaml
nav:
  - Accueil: index.md
  - Guides:
      - Vue d'ensemble: guides/index.md
      - Débutant:
          - Introduction: guides/beginner/intro.md
          - Installation: guides/beginner/install.md
      - Avancé:
          - Architecture: guides/advanced/architecture.md
          - Performance: guides/advanced/performance.md
```

---

## 4. Admonitions Complètes

### Types Disponibles

!!! note "Note"
    Information générale.

!!! abstract "Résumé"
    Résumé ou TL;DR.

!!! info "Information"
    Information importante.

!!! tip "Astuce"
    Conseil utile.

!!! success "Succès"
    Opération réussie.

!!! question "Question"
    Point d'interrogation.

!!! warning "Attention"
    Avertissement.

!!! failure "Échec"
    Erreur ou échec.

!!! danger "Danger"
    Risque critique.

!!! bug "Bug"
    Bug connu.

!!! example "Exemple"
    Exemple pratique.

!!! quote "Citation"
    Citation ou extrait.

### Syntaxe

```markdown
!!! note "Titre personnalisé"
    Contenu de la note avec **formatage** possible.

    - Listes
    - Code inclus

    ```bash
    echo "Hello"
    ```
```

### Admonitions Pliables

```markdown
??? info "Cliquez pour déplier"
    Contenu caché par défaut.

???+ warning "Déplié par défaut"
    Contenu visible mais pliable.
```

??? info "Exemple pliable"
    Ce contenu est caché par défaut. Cliquez pour le voir !

???+ warning "Déplié par défaut"
    Ce contenu est visible mais peut être replié.

---

## 5. Onglets de Contenu

### Syntaxe

```markdown
=== "Python"

    ```python
    print("Hello, World!")
    ```

=== "JavaScript"

    ```javascript
    console.log("Hello, World!");
    ```

=== "Bash"

    ```bash
    echo "Hello, World!"
    ```
```

### Rendu

=== "Python"

    ```python
    print("Hello, World!")
    ```

=== "JavaScript"

    ```javascript
    console.log("Hello, World!");
    ```

=== "Bash"

    ```bash
    echo "Hello, World!"
    ```

### Onglets Liés

Avec `content.tabs.link`, les onglets sont synchronisés entre les pages.

---

## 6. Plugins Essentiels

### Installation

```bash
pip install \
  mkdocs-material \
  mkdocs-git-revision-date-localized-plugin \
  mkdocs-glightbox \
  mkdocs-minify-plugin
```

### git-revision-date-localized

Affiche la date de dernière modification :

```yaml
plugins:
  - git-revision-date-localized:
      enable_creation_date: true
      type: timeago  # ou date, datetime, iso_date
```

Rendu : "Dernière mise à jour : il y a 2 jours"

### glightbox

Zoom sur les images au clic :

```yaml
plugins:
  - glightbox
```

### minify

Minifie le HTML en production :

```yaml
plugins:
  - minify:
      minify_html: true
```

### search (intégré)

```yaml
plugins:
  - search:
      lang: fr
      separator: '[\s\-\.]+'
```

---

## 7. Annotations de Code

### Syntaxe

````markdown
```python
def hello():
    print("Hello")  # (1)!

hello()  # (2)!
```

1. Cette fonction affiche "Hello"
2. Appel de la fonction
````

### Rendu

```python
def hello():
    print("Hello")  # (1)!

hello()  # (2)!
```

1. Cette fonction affiche "Hello"
2. Appel de la fonction

---

## 8. Raccourcis Clavier

Avec l'extension `pymdownx.keys` :

```markdown
Appuyez sur ++ctrl+c++ pour copier.

Raccourcis : ++cmd+shift+p++ ou ++ctrl+shift+p++
```

Appuyez sur ++ctrl+c++ pour copier.

Raccourcis : ++cmd+shift+p++ ou ++ctrl+shift+p++

---

## 9. SEO et Analytics

### Meta Tags

```yaml
extra:
  meta:
    - name: keywords
      content: documentation, mkdocs, tutorial
    - name: author
      content: Votre Nom
```

### Google Analytics

```yaml
extra:
  analytics:
    provider: google
    property: G-XXXXXXXXXX
    feedback:
      title: Cette page vous a-t-elle été utile ?
      ratings:
        - icon: material/emoticon-happy-outline
          name: Oui
          data: 1
          note: Merci !
        - icon: material/emoticon-sad-outline
          name: Non
          data: 0
          note: Merci pour le retour.
```

### Sitemap

Généré automatiquement par MkDocs dans `sitemap.xml`.

---

## 10. Icônes et Emojis

### Icônes Material

```markdown
:material-account: Compte
:material-github: GitHub
:material-docker: Docker
:material-kubernetes: Kubernetes
:material-check: Validé
:material-close: Fermé
```

:material-account: Compte
:material-github: GitHub
:material-docker: Docker
:material-kubernetes: Kubernetes

### FontAwesome

```markdown
:fontawesome-brands-linux: Linux
:fontawesome-brands-windows: Windows
:fontawesome-brands-apple: Apple
:fontawesome-solid-rocket: Rocket
```

:fontawesome-brands-linux: Linux
:fontawesome-brands-windows: Windows
:fontawesome-brands-apple: Apple

### Octicons

```markdown
:octicons-check-16: Check
:octicons-x-16: X
:octicons-arrow-right-24: Suivant
```

---

## 11. Listes de Tâches

```markdown
- [x] Tâche terminée
- [ ] Tâche en cours
- [ ] Tâche à faire
```

- [x] Tâche terminée
- [ ] Tâche en cours
- [ ] Tâche à faire

---

## Exercice Pratique

### Objectif

Configurer un site MkDocs avec toutes les fonctionnalités avancées.

### Instructions

1. Activer le mode clair/sombre
2. Ajouter des onglets de navigation
3. Créer une page avec :
   - 3 types d'admonitions
   - Des onglets de contenu (Linux/Windows/macOS)
   - Un diagramme Mermaid
   - Des annotations de code
4. Configurer les plugins recommandés

### Checklist

- [ ] Palette clair/sombre configurée
- [ ] Navigation avec onglets
- [ ] Admonitions fonctionnelles
- [ ] Tabs de contenu
- [ ] Mermaid activé
- [ ] Plugins installés

---

## Prochaine Étape

Vous maîtrisez maintenant la configuration avancée ! Passons au TP final pour créer un projet complet.

[:octicons-arrow-right-24: TP Final : Projet Complet](05-tp-final.md)
