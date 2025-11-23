---
tags:
  - formations
  - catalogue
  - apprentissage
---

# Catalogue des Formations

Bienvenue dans l'espace **Formations** de ShellBook. Contrairement aux guides de référence, cette section propose des **parcours pédagogiques structurés** pour monter en compétence de manière progressive.

## Philosophie des Formations

- **Séquentiel** : Modules ordonnés (1 → 2 → 3)
- **Pratique** : Exercices avec solutions
- **Production-Ready** : Exemples issus du terrain
- **Certification-Oriented** : Prépare aux certifications (CKA, RHCSA, etc.)

## Formations Disponibles

<div class="grid cards" markdown>

-   :fontawesome-solid-rocket:{ .lg .middle } **Le Socle DevOps**

    ---

    Maîtrisez les fondamentaux DevOps : Git, branches, pull requests, CI/CD, et pipelines automatisés. De zéro à la production.

    **Compétences :** Git workflows, GitLab CI/CD, Tests automatisés
    **Durée :** 2 jours (16h)

    [:octicons-arrow-right-24: Accéder à la Formation](devops-foundation/)

-   :fontawesome-solid-shield-halved:{ .lg .middle } **Hardening Linux & Sécurité**

    ---

    Sécurisez vos serveurs Linux selon les standards SecNumCloud. SSH, sudo, firewall, audit et conformité ANSSI.

    **Compétences :** SSH Hardening, Firewalld, OpenSCAP, Audit
    **Durée :** 3 jours (24h)

    [:octicons-arrow-right-24: Accéder à la Formation](linux-hardening/)

-   :fontawesome-solid-diagram-project:{ .lg .middle } **Ansible : De Zéro à l'Indus**

    ---

    Automatisez votre infrastructure avec Ansible. Architecture, playbooks, roles, Vault, et patterns d'industrialisation.

    **Compétences :** Playbooks, Roles, Vault, Galaxy, Testing
    **Durée :** 4 jours (32h)

    [:octicons-arrow-right-24: Accéder à la Formation](ansible-mastery/)

-   :material-ubuntu:{ .lg .middle } **Katello : Maîtriser le Cycle de Vie Linux**

    ---

    Gérez centralement les mises à jour Linux (RHEL/Rocky/CentOS). Synchronisation repos, Content Views, Lifecycle Environments, Patch Management.

    **Compétences :** Foreman, Pulp, Content Views, Errata Management
    **Durée :** 3 jours (24h)

    [:octicons-arrow-right-24: Accéder à la Formation](katello/)

-   :material-package-variant:{ .lg .middle } **Chocolatey Factory : Packaging Windows**

    ---

    Maîtrisez Chocolatey pour gérer les packages Windows. Création de packages, repository privé, déploiement automatisé via Ansible/GPO.

    **Compétences :** Packaging, Chocolatey Server, Automatisation
    **Durée :** 2 jours (16h)

    [:octicons-arrow-right-24: Accéder à la Formation](chocolatey/)

-   :material-microsoft-windows:{ .lg .middle } **Windows Server Mastery**

    ---

    Administration moderne Windows Server : PowerShell, Active Directory, GPO, sécurité et hardening selon les best practices Microsoft.

    **Compétences :** PowerShell, AD, GPO, Tiering Model, LAPS
    **Durée :** 3 jours (24h)

    [:octicons-arrow-right-24: Accéder à la Formation](windows-server/)

-   :material-update:{ .lg .middle } **Windows Patch Management (WSUS)**

    ---

    Déployez une infrastructure WSUS complète. Architecture, Deployment Rings, GPO, maintenance automatisée et troubleshooting avancé.

    **Compétences :** WSUS, Deployment Rings, GPO PowerShell, Maintenance
    **Durée :** 3 jours (24h)

    [:octicons-arrow-right-24: Accéder à la Formation](windows-patching/)

</div>

## Comment Utiliser Cette Section ?

### 1. Choisir un Parcours

Consultez les formations disponibles ci-dessus. Chaque carte indique les compétences acquises et la durée estimée.

### 2. Suivre le Syllabus

Chaque formation contient une page **"Introduction & Programme"** avec :

- **Objectifs** : Ce que vous saurez faire à la fin
- **Prérequis** : Connaissances nécessaires avant de commencer
- **Programme** : Liste séquentielle des modules

### 3. Travailler les Modules

Chaque module suit cette structure :

- **Concept** : Explication théorique (avec diagrammes Mermaid)
- **Pratique** : Commandes/configurations à exécuter
- **Exercice** : Mise en situation (admonition `!!! example`)
- **Solution** : Correction détaillée (collapsible `??? quote`)

!!! tip "Conseil Pédagogique"
    **Faites les exercices AVANT de regarder la solution.** C'est en se trompant qu'on apprend le mieux. La solution est là pour valider, pas pour copier-coller.

## Créer une Nouvelle Formation

Vous êtes auteur de contenu ? Utilisez le [Template de Formation](template/) comme base.

**Structure recommandée :**

```
docs/formations/
└── ma-formation/
    ├── index.md           # Syllabus (objectifs, programme)
    ├── 01-module.md       # Module 1
    ├── 02-module.md       # Module 2
    ├── 03-module.md       # Module 3
    └── 99-conclusion.md   # Ressources, certification
```

**Navigation dans mkdocs.yml :**

```yaml
- 🎓 Formations:
  - 📘 Ma Formation:
    - Introduction: formations/ma-formation/index.md
    - Module 1: formations/ma-formation/01-module.md
    - Module 2: formations/ma-formation/02-module.md
    - Conclusion: formations/ma-formation/99-conclusion.md
```

## Contribution

Les formations sont ouvertes aux contributions ! Pour proposer un nouveau parcours :

1. Forker le repo [ShellBook](https://github.com/VBlackJack/ShellBook)
2. Créer une branche `formation/nom-du-cours`
3. Utiliser le template comme structure
4. Soumettre une Pull Request

Voir le [Guide de Contribution](../devops/docs-as-code.md) pour plus de détails.

## Roadmap

| Formation | Statut | Date Prévisionnelle |
|-----------|--------|---------------------|
| Le Socle DevOps | ✅ Disponible | 2025-01-15 |
| Hardening Linux | 🔄 En cours | 2025-02-01 |
| Ansible Mastery | 🔄 En cours | 2025-02-15 |
| Kubernetes Fundamentals | 📝 Planifié | 2025-03-01 |
| Terraform : Infrastructure as Code | 💡 Idée | 2025-Q2 |

---

**Besoin d'aide ?** Ouvrez une [issue GitHub](https://github.com/VBlackJack/ShellBook/issues) ou consultez le [guide Docs-as-Code](../devops/docs-as-code.md).
