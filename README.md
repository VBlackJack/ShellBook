# ShellBook

![Build Status](https://github.com/VBlackJack/ShellBook/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)
![MkDocs](https://img.shields.io/badge/mkdocs-material-526CFE.svg)

**La Base de Connaissance Opérationnelle pour l'Ingénieur SysOps & DevOps**

Documentation-as-Code couvrant Linux, Windows, Kubernetes, DevOps et Sécurité.

🌐 **Site en ligne** : [https://vblackjack.github.io/ShellBook/](https://vblackjack.github.io/ShellBook/)

---

## 📋 Présentation

ShellBook est une base de connaissance structurée pour les ingénieurs systèmes et DevOps. Elle regroupe :

- **30+ guides Linux** : Administration système, réseau, sécurité, automatisation
- **6 guides Windows** : PowerShell, Active Directory, sécurité Windows
- **6 guides DevOps** : Docker, Kubernetes, CI/CD, Ansible, Observabilité
- **6 guides Security** : Certificats, pentest, hardening, conformité SecNumCloud

### Caractéristiques clés

✅ **Recherche Instantanée** : Ctrl+K pour trouver n'importe quelle commande
✅ **Tags Filtrables** : Chaque page est taguée par technologie
✅ **Quick Reference** : Résumé des commandes en fin de chaque guide
✅ **Exemples Pratiques** : Code blocks, YAML, configurations réelles
✅ **Standards SecNumCloud** : Conformité sécurité française

---

## 📁 Structure du Projet

```
ShellBook/
├── docs/                           # Contenu documentation
│   ├── index.md                    # Landing page
│   ├── linux/                      # 30+ guides Linux
│   │   ├── productivity.md
│   │   ├── modern-tools.md
│   │   ├── debugging.md
│   │   ├── ssh-hardening.md
│   │   ├── firewall-ufw.md
│   │   └── ...
│   ├── windows/                    # 6 guides Windows
│   │   ├── index.md
│   │   ├── powershell-foundations.md
│   │   ├── active-directory.md
│   │   └── windows-security.md
│   ├── devops/                     # 6 guides DevOps
│   │   ├── docker-advanced.md
│   │   ├── cicd-github-actions.md
│   │   ├── observability-stack.md
│   │   ├── kubernetes-survival.md
│   │   ├── kubernetes-networking.md
│   │   └── ansible/
│   │       ├── fundamentals.md
│   │       ├── playbooks.md
│   │       └── industrialization.md
│   ├── security/                   # 6 guides Security
│   │   ├── certificates.md
│   │   ├── openssl-cli.md
│   │   ├── exegol.md
│   │   └── ctf-guide.md
│   ├── network/
│   │   └── fundamentals.md
│   └── concepts/
│       ├── web-flow.md
│       ├── databases.md
│       └── devops-pillars.md
├── .github/
│   └── workflows/
│       └── ci.yml                  # Pipeline GitHub Actions
├── mkdocs.yml                      # Configuration MkDocs
├── requirements.txt                # Dépendances Python
└── README.md                       # Ce fichier
```

---

## 🚀 Workflow de Contribution

### Prérequis

```bash
# Python 3.8+
python --version

# Installer les dépendances
pip install -r requirements.txt
```

### 1️⃣ Créer une branche

```bash
git checkout -b feature/new-guide-name
```

### 2️⃣ Ajouter un fichier Markdown

Créer un nouveau guide dans le dossier approprié :

```bash
# Exemple : nouveau guide Linux
touch docs/linux/new-feature.md
```

**Structure type d'un guide :**

```markdown
# Titre du Guide

`#tag1` `#tag2` `#tag3`

Description courte du guide.

---

## Section 1

Contenu...

### Sous-section

```bash
# Commandes avec commentaires
command --option
```

## Section 2

| Header 1 | Header 2 |
|----------|----------|
| Data 1   | Data 2   |

!!! tip "Astuce"
    Utilisez les admonitions Material for MkDocs.

---

## Quick Reference

```bash
# Résumé des commandes essentielles
cmd1
cmd2
```
```

### 3️⃣ Mettre à jour `mkdocs.yml`

Ajouter la nouvelle page dans la navigation :

```yaml
nav:
  - Linux:
    - linux/new-feature.md    # ← Ajouter ici
```

**Exemple avec sous-menu :**

```yaml
nav:
  - DevOps:
    - CI/CD & Obs:
      - devops/cicd-github-actions.md
      - devops/observability-stack.md
```

### 4️⃣ Tester en local

```bash
# Lancer le serveur de développement
mkdocs serve

# Accéder à http://127.0.0.1:8000
```

**Vérifications :**
- ✅ La page apparaît dans la navigation
- ✅ Les liens internes fonctionnent
- ✅ Les code blocks sont bien formatés
- ✅ Les admonitions s'affichent correctement

### 5️⃣ Commit et Push

```bash
git add docs/linux/new-feature.md mkdocs.yml
git commit -m "feat(linux): Add new-feature guide"
git push origin feature/new-guide-name
```

### 6️⃣ Créer une Pull Request

Sur GitHub, créer une PR vers `main` :

1. Titre descriptif : `feat(linux): Add new-feature guide`
2. Description : Expliquer le contenu du guide
3. Demander une review si nécessaire

### 7️⃣ Déploiement Automatique

Une fois mergée dans `main`, **GitHub Actions** déploie automatiquement :

```
main branch → GitHub Actions → Build → Deploy → GitHub Pages
```

Le site est mis à jour en ~2 minutes : https://vblackjack.github.io/ShellBook/

---

## 🛠️ Stack Technique

### Documentation

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| **Générateur** | [MkDocs](https://www.mkdocs.org/) | Transformation Markdown → HTML |
| **Thème** | [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) | Design moderne, recherche, navigation |
| **Langage** | Python 3.8+ | Runtime MkDocs |
| **Format** | Markdown (CommonMark) | Contenu des guides |

### CI/CD

| Composant | Technologie | Rôle |
|-----------|-------------|------|
| **Pipeline** | [GitHub Actions](https://github.com/features/actions) | Automatisation build + deploy |
| **Workflow** | `.github/workflows/ci.yml` | Configuration du pipeline |
| **Hébergement** | [GitHub Pages](https://pages.github.com/) | Hébergement statique gratuit |

### Workflow GitHub Actions

**Fichier** : [`.github/workflows/ci.yml`](.github/workflows/ci.yml)

**Déclenchement** : Push sur `main` ou PR

**Étapes** :
1. **Checkout** du code
2. **Setup Python** 3.x
3. **Install dependencies** (`pip install -r requirements.txt`)
4. **Build** le site statique (`mkdocs build`)
5. **Deploy** vers GitHub Pages (branche `gh-pages`)

**Durée** : ~1-2 minutes

---

## 🔧 Commandes Utiles

### Développement Local

```bash
# Serveur de développement avec hot-reload
mkdocs serve

# Serveur accessible depuis le réseau
mkdocs serve --dev-addr=0.0.0.0:8000

# Build sans déployer (vérifier les erreurs)
mkdocs build --strict
```

### Maintenance

```bash
# Mettre à jour les dépendances
pip install --upgrade -r requirements.txt

# Vérifier les liens cassés (plugin optionnel)
pip install mkdocs-linkcheck
mkdocs build

# Rechercher dans tous les guides
grep -r "mot-clé" docs/
```

### Git

```bash
# Voir l'historique des modifications
git log --oneline docs/linux/

# Voir les différences avant commit
git diff docs/

# Lister toutes les branches
git branch -a
```

---

## 📊 Statistiques du Projet

- **Guides** : 50+ fichiers Markdown
- **Lignes de code** : ~15,000 lignes
- **Taille** : ~500 KB de contenu
- **Couverture** :
  - 30+ guides Linux
  - 6 guides Windows
  - 6 guides DevOps
  - 6 guides Security

---

## 🤝 Contribution

Les contributions sont les bienvenues ! Suivez le workflow ci-dessus.

**Types de contributions :**
- ✅ Nouveaux guides
- ✅ Corrections de typos
- ✅ Ajout d'exemples
- ✅ Amélioration de la navigation
- ✅ Traduction (EN/FR)

**Standards :**
- Respecter le format Markdown
- Ajouter des tags en haut de chaque guide
- Inclure une section "Quick Reference"
- Tester en local avant de commit
- Suivre les conventions SecNumCloud pour la sécurité

---

## 📝 Conventions de Commit

Suivre [Conventional Commits](https://www.conventionalcommits.org/) :

```
feat(linux): Add SSH hardening guide
fix(windows): Correct PowerShell syntax
docs(readme): Update contribution workflow
refactor(nav): Reorganize DevOps section
```

**Types :**
- `feat`: Nouvelle fonctionnalité ou guide
- `fix`: Correction de bug ou typo
- `docs`: Modification de documentation
- `refactor`: Refactoring sans changement fonctionnel
- `chore`: Maintenance (dépendances, config)

---

## 🔒 Sécurité

- **Pas de secrets** : Ne jamais commiter de clés, tokens, mots de passe
- **SecNumCloud** : Conformité aux standards de sécurité français
- **GitHub Secrets** : Utiliser les secrets GitHub Actions pour les credentials
- **Validation manuelle** : Protection de la branche `main` recommandée

---

## 📖 Ressources

- **Documentation MkDocs** : https://www.mkdocs.org/
- **Material for MkDocs** : https://squidfunk.github.io/mkdocs-material/
- **Markdown Guide** : https://www.markdownguide.org/
- **GitHub Actions** : https://docs.github.com/en/actions

---

## 📄 License

MIT License - Voir [LICENSE](LICENSE) pour plus de détails.

---

## 🙋 Support

- **Issues** : [GitHub Issues](https://github.com/VBlackJack/ShellBook/issues)
- **Discussions** : [GitHub Discussions](https://github.com/VBlackJack/ShellBook/discussions)

---

<div align="center">
  <p><strong>ShellBook</strong> - Votre cerveau opérationnel externalisé</p>
  <p>Linux • Windows • Kubernetes • DevOps • Security</p>
  <p>Made with ❤️ and <a href="https://www.mkdocs.org/">MkDocs</a></p>
</div>
