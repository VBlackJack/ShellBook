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
    **Durée :** 1 jour (6h)

    [:octicons-arrow-right-24: Accéder à la Formation](devops-foundation/)

-   :fontawesome-solid-lock:{ .lg .middle } **PKI & Certificats**

    ---

    Maîtrisez l'infrastructure de confiance : cryptographie, certificats X.509, déploiement PKI, automatisation et conformité SecNumCloud.

    **Compétences :** OpenSSL, X.509, CA Root/Sub-CA, CRL/OCSP, mTLS, Vault PKI
    **Durée :** 2 jours (16h)

    [:octicons-arrow-right-24: Accéder à la Formation](pki-certificates/)

-   :fontawesome-solid-shield-halved:{ .lg .middle } **Hardening Linux & Sécurité**

    ---

    Sécurisez vos serveurs Linux selon les standards SecNumCloud. SSH, sudo, firewall, audit et conformité ANSSI.

    **Compétences :** SSH Hardening, Firewalld, OpenSCAP, Audit
    **Durée :** 1.5 jours (10h)

    [:octicons-arrow-right-24: Accéder à la Formation](linux-hardening/)

-   :fontawesome-solid-diagram-project:{ .lg .middle } **Ansible : De Zéro à l'Indus**

    ---

    Automatisez votre infrastructure avec Ansible. Architecture, playbooks, roles, Vault, et patterns d'industrialisation.

    **Compétences :** Playbooks, Roles, Vault, Galaxy, Testing
    **Durée :** 2 jours (14h)

    [:octicons-arrow-right-24: Accéder à la Formation](ansible-mastery/)

-   :material-ubuntu:{ .lg .middle } **Katello : Maîtriser le Cycle de Vie Linux**

    ---

    Gérez centralement les mises à jour Linux (RHEL/Rocky/CentOS). Synchronisation repos, Content Views, Lifecycle Environments, Patch Management.

    **Compétences :** Foreman, Pulp, Content Views, Errata Management
    **Durée :** 2 jours (15h)

    [:octicons-arrow-right-24: Accéder à la Formation](katello/)

-   :material-package-variant:{ .lg .middle } **Chocolatey Factory : Packaging Windows**

    ---

    Maîtrisez Chocolatey pour gérer les packages Windows. Création de packages, repository privé, déploiement automatisé via Ansible/GPO.

    **Compétences :** Packaging, Chocolatey Server, Automatisation
    **Durée :** 1.5 jours (12h)

    [:octicons-arrow-right-24: Accéder à la Formation](chocolatey/)

-   :material-microsoft-windows:{ .lg .middle } **Windows Server Mastery**

    ---

    Administration moderne Windows Server : PowerShell, Active Directory, GPO, sécurité et hardening selon les best practices Microsoft.

    **Compétences :** PowerShell, AD, GPO, Tiering Model, LAPS
    **Durée :** 1.5 jours (12h)

    [:octicons-arrow-right-24: Accéder à la Formation](windows-server/)

-   :material-update:{ .lg .middle } **Windows Patch Management (WSUS)**

    ---

    Déployez une infrastructure WSUS complète. Architecture, Deployment Rings, GPO, maintenance automatisée et troubleshooting avancé.

    **Compétences :** WSUS, Deployment Rings, GPO PowerShell, Maintenance
    **Durée :** 2 jours (14h)

    [:octicons-arrow-right-24: Accéder à la Formation](windows-patching/)

-   :material-disc:{ .lg .middle } **NTLite Mastery : Personnalisation d'Images Windows**

    ---

    Créez des images Windows sur mesure : debloating, intégration drivers/updates, automatisation OOBE, et déploiement VPN/certificats entreprise.

    **Compétences :** Debloating, Post-Setup, Unattended XML, VPN/PKI Integration
    **Durée :** 2.5 jours (18h) - 6 modules

    [:octicons-arrow-right-24: Accéder à la Formation](ntlite/)

-   :material-database:{ .lg .middle } **SQL Server DBA : Administration Professionnelle**

    ---

    Administrez SQL Server en production : architecture, sécurité, maintenance (Ola Hallengren), automatisation (dbatools), et projet Phoenix complet.

    **Compétences :** Installation, Sécurité, Backups, Automatisation PowerShell
    **Durée :** 4 jours (22h) - 5 modules

    [:octicons-arrow-right-24: Accéder à la Formation](sql-server/)

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

## Formations Disponibles

| Formation | Modules | Statut |
|-----------|---------|--------|
| 🚀 Le Socle DevOps | 5 modules | ✅ Disponible |
| 🔒 PKI & Certificats | 5 modules | ✅ Disponible |
| 🔐 Hardening Linux | 5 modules | ✅ Disponible |
| 💠 Ansible Mastery | 4 modules | ✅ Disponible |
| 🦁 Katello Lifecycle | 5 modules | ✅ Disponible |
| 🏰 Windows Server Mastery | 4 modules | ✅ Disponible |
| ♻️ Windows Patch Management | 5 modules | ✅ Disponible |
| 🍫 Chocolatey Factory | 5 modules | ✅ Disponible |
| 💿 NTLite Mastery | 6 modules | ✅ Disponible |
| 🛢️ SQL Server DBA | 5 modules | ✅ Disponible |

---

**Besoin d'aide ?** Ouvrez une [issue GitHub](https://github.com/VBlackJack/ShellBook/issues) ou consultez le [guide Docs-as-Code](../devops/docs-as-code.md).
