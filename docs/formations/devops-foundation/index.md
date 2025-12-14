---
tags:
  - formation
  - devops
  - git
  - cicd
---

# Le Socle DevOps : Introduction & Programme

## Objectifs de cette Formation

À l'issue de ce parcours, vous serez capable de :

- 🔀 **Maîtriser Git** : Comprendre les concepts (commit, push, pull, merge)
- 🌿 **Gérer les branches** : Créer des branches, faire des Pull Requests, résoudre des conflits
- 🚀 **Créer un pipeline CI/CD** : Automatiser les tests et déploiements avec GitLab CI
- ✅ **Implémenter le linting** : Valider la qualité du code (YAML, Shell, Markdown)
- 🧪 **Mettre en pratique** : Projet final intégrant tous les concepts

## Public Cible

Cette formation s'adresse aux **professionnels IT** souhaitant adopter les pratiques DevOps :

- Administrateurs systèmes en transition DevOps
- Développeurs voulant comprendre les pipelines CI/CD
- Technical Writers travaillant sur des projets Docs-as-Code
- DevOps juniors cherchant à structurer leurs connaissances

**Niveau requis :** Débutant (connaissance basique du terminal Linux)

## Prérequis

!!! info "Connaissances Nécessaires"
    Avant de commencer, assurez-vous de disposer de :

    - ✅ **Accès terminal** : Bash, Zsh ou PowerShell
    - ✅ **Compte GitHub/GitLab** : Pour les exercices pratiques
    - ✅ **Git installé** : Version 2.30+ recommandée
    - ✅ **Éditeur de texte** : VS Code, Vim, Nano

    **Ressources :**

    - [Guide Git SysOps](../../devops/git-sysops.md) : Introduction à Git
    - [Docs-as-Code](../../devops/docs-as-code.md) : Workflow Git pour la documentation

## Programme

### Module 1 : Comprendre Git (45 min)

**Objectif :** Maîtriser les concepts fondamentaux de Git et le workflow de base.

**Contenu :**

- Qu'est-ce que Git ? (vs SVN, historique)
- Les 3 zones : Working Directory, Staging Area, Repository
- Commandes essentielles : `init`, `add`, `commit`, `status`, `log`
- Diagramme Mermaid : Flux Local → Staging → Repo

[:octicons-arrow-right-24: Accéder au Module 1](01-module.md)

### Module 2 : Branches & Pull Requests (1h)

**Objectif :** Travailler en équipe avec les branches et les Pull Requests.

**Contenu :**

- Créer et naviguer entre branches (`git branch`, `git checkout`, `git switch`)
- Stratégies de branches (Git Flow, GitHub Flow, Trunk-Based)
- Pull Requests : Création, review, merge
- Résolution de conflits (merge conflicts)
- Diagramme : Git Flow vs GitHub Flow

[:octicons-arrow-right-24: Accéder au Module 2](02-module.md)

### Module 3 : Pipeline CI/CD avec GitLab (1h30)

**Objectif :** Automatiser les tests et déploiements avec GitLab CI.

**Contenu :**

- Anatomie d'un `.gitlab-ci.yml`
- Stages, jobs, artifacts
- Runners GitLab (shared, specific)
- Variables et secrets (`CI_COMMIT_SHA`, `CI_REGISTRY_IMAGE`)
- Exemple : Pipeline pour une app Python (lint → test → build → deploy)

[:octicons-arrow-right-24: Accéder au Module 3](03-module.md)

### Module 4 : Linting & Quality Gates (1h)

**Objectif :** Garantir la qualité du code avec le linting automatisé.

**Contenu :**

- Linters pour YAML (yamllint), Shell (shellcheck), Markdown (markdownlint)
- Pre-commit hooks locaux
- Intégration dans le pipeline CI/CD
- Quality Gates : Fail le build si le linting échoue
- Exemple : `.gitlab-ci.yml` avec stage `lint`

[:octicons-arrow-right-24: Accéder au Module 4](04-module.md)

### Module 5 : TP Final - Projet Complet (2h)

**Objectif :** Mettre en pratique tous les concepts sur un projet réel.

**Contexte :**

Vous êtes SysOps dans une équipe qui gère une documentation technique (ShellBook). Votre mission :

1. Forker le repo
2. Créer une branche `feature/ma-doc`
3. Ajouter un guide Markdown
4. Passer le linting (yamllint, markdownlint)
5. Créer une Pull Request
6. Merger après validation du pipeline

[:octicons-arrow-right-24: Accéder au TP Final](05-tp-final.md)

## Durée Estimée

| Module | Durée | Type |
|--------|-------|------|
| Module 1 : Git Fundamentals | 45 min | Lecture + Exercice |
| Module 2 : Branches & PR | 1h | Pratique guidée |
| Module 3 : Pipeline CI/CD | 1h30 | Hands-on |
| Module 4 : Linting | 1h | Configuration |
| Module 5 : TP Final | 2h | Projet autonome |
| **Total** | **6h15** | **Formation complète** |

!!! tip "Organisation Recommandée"
    **Format présentiel :** 2 jours (3h + 3h par jour)

    **Format asynchrone :** 1 semaine à votre rythme

    **Pause recommandée :** 15 min toutes les heures

## Compétences Acquises

À la fin de cette formation, vous serez capable de :

- ✅ Créer un dépôt Git et gérer l'historique des commits
- ✅ Travailler en branches et gérer les Pull Requests
- ✅ Résoudre des conflits Git de manière autonome
- ✅ Écrire un pipeline CI/CD GitLab fonctionnel
- ✅ Intégrer le linting dans un workflow DevOps
- ✅ Collaborer efficacement sur des projets open source

## Certification

Cette formation ne délivre pas de certification officielle, mais prépare aux certifications suivantes :

- **GitLab Certified Associate** : Git & CI/CD
- **GitHub Actions Certification** : Workflows CI/CD
- **Linux Foundation** : DevOps Foundation

Une fois la formation complétée, vous pouvez valider vos compétences avec le **TP Final** comme portfolio.

## Ressources de la Formation

<div class="grid cards" markdown>

-   :material-book-alphabet:{ .lg .middle } **Glossaire DevOps**

    ---

    Définitions des termes essentiels : CI, CD, IaC, GitOps, Pipeline, etc.

    [:octicons-arrow-right-24: Consulter le Glossaire](glossaire.md)

-   :material-file-document:{ .lg .middle } **Cheat Sheet Git**

    ---

    Référence rapide de toutes les commandes Git essentielles. Format imprimable.

    [:octicons-arrow-right-24: Voir le Cheat Sheet](cheatsheet-git.md)

-   :octicons-workflow-16:{ .lg .middle } **Cheat Sheet GitHub Actions**

    ---

    Syntaxe YAML, triggers, jobs, steps, secrets, et patterns courants.

    [:octicons-arrow-right-24: Voir le Cheat Sheet](cheatsheet-github-actions.md)

-   :material-tag-text:{ .lg .middle } **Memo Conventional Commits**

    ---

    Convention de nommage des commits pour un historique propre et automatisable.

    [:octicons-arrow-right-24: Voir la Fiche Memo](memo-conventional-commits.md)

-   :material-shield-check:{ .lg .middle } **Memo ShellCheck**

    ---

    Règles ShellCheck critiques, bonnes pratiques Bash, et template sécurisé.

    [:octicons-arrow-right-24: Voir la Fiche Memo](memo-shellcheck.md)

</div>

## Ressources Externes

- [Documentation Git Officielle](https://git-scm.com/doc)
- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [GitHub Flow Guide](https://docs.github.com/en/get-started/quickstart/github-flow)
- [Pre-commit Framework](https://pre-commit.com/)
- [Guide CI/CD ShellBook](../../devops/cicd-gitlab.md)

### Outils de Test

- [Mockaroo](https://mockaroo.com/) - Générateur de données de test réalistes (CSV, JSON, SQL, Excel). Idéal pour remplir des BDD de dev, tests de charge, et prototypage. 1000 lignes gratuites, API REST disponible.
- [GenerateData](https://generatedata.com/) - Générateur open source (GPL 3) avec 30+ types de données et 12+ formats d'export. Self-hostable (PHP/MySQL) ou version web gratuite.

## Support

**Questions ou problèmes ?**

- 💬 [Discussions GitHub](https://github.com/VBlackJack/ShellBook/discussions)
- 🐛 [Issues GitHub](https://github.com/VBlackJack/ShellBook/issues)
- 📧 Contact : devops@shellbook.io

---

**Prêt ?** Commencez par le [Module 1 : Comprendre Git](01-module.md) 🚀
