---
title: Katello - Maîtriser le Cycle de Vie Linux
description: Formation complète sur la gestion centralisée des contenus et patchs Linux avec Katello
tags:
  - linux
  - katello
  - foreman
  - rhel
  - patch-management
  - formation
---

# 🦁 Katello : Maîtriser le Cycle de Vie Linux

!!! abstract "Vue d'ensemble"
    Formation complète sur **Katello**, la solution de gestion du cycle de vie des contenus Linux (packages RPM, patchs, errata). Apprenez à synchroniser, organiser et distribuer les mises à jour pour RHEL, CentOS, Rocky Linux et dérivés sur des infrastructures de 100 à 10 000+ serveurs.

## 🎯 Objectifs pédagogiques

À l'issue de cette formation, vous serez capable de :

- ✅ **Comprendre l'architecture Katello** : Foreman, Pulp, Candlepin, Smart Proxies
- ✅ **Installer Katello** : Déployer la stack complète sur Rocky Linux 9
- ✅ **Gérer le contenu** : Synchroniser des repos Red Hat/CentOS, créer des Content Views
- ✅ **Organiser les environnements** : Lifecycle Environments (Library → Dev → Test → Prod)
- ✅ **Enregistrer les hôtes** : Subscription-manager, activation keys, host collections
- ✅ **Gérer les patchs** : Appliquer les errata (CVE), planifier les maintenances
- ✅ **Automatiser** : Ansible + Katello API, Hammer CLI
- ✅ **Monitorer** : Compliance, reporting, alertes

## 📚 Programme détaillé

### Module 1 : Architecture & Installation Katello
**Durée estimée : 3h**

- 🏗️ **La Stack Katello**
    - Foreman (Lifecycle Management)
    - Katello (Content Management)
    - Pulp (Repository Storage)
    - Candlepin (Subscription Management)
    - Smart Proxies (Architecture distribuée)
- 💻 **Installation sur Rocky Linux 9**
    - Prérequis matériels (16 GB RAM minimum)
    - Installation via `foreman-installer --scenario katello`
    - Configuration firewall et SELinux
    - Premier accès à l'interface Web
- 🎓 **Exercice : "First Launch"**
    - Déployer Katello sur une VM Rocky Linux 9
    - Vérifier les services (Foreman, Pulp, Candlepin)
    - Accéder à l'UI (https://katello.example.com)

### Module 2 : Gestion du Contenu (Content Views)
**Durée estimée : 3h**

- 📦 **Repositories & Products**
    - Synchroniser des repos upstream (RHEL, CentOS Stream, EPEL)
    - Créer des Products (ex: "RHEL 9", "Rocky Linux 9")
    - Gérer les miroirs locaux
- 🔄 **Content Views**
    - Concept : Snapshot versionné d'un ensemble de repos
    - Créer une Content View (ex: "Rocky-9-Base")
    - Filtres : Inclure/Exclure des packages ou errata
    - Publier et promouvoir entre environnements
- 🌍 **Lifecycle Environments**
    - Architecture : Library → Dev → Test → Prod
    - Promotion de Content Views (Dev → Test → Prod)
- 🎓 **Exercice : "The Production Pipeline"**
    - Synchroniser Rocky Linux 9 BaseOS + AppStream
    - Créer une Content View "Rocky-9-Prod"
    - Filtrer pour exclure les kernel > 5.14.0-400
    - Promouvoir Dev → Test → Prod

### Module 3 : Enregistrement des Hôtes
**Durée estimée : 2h30**

- 🔑 **Activation Keys**
    - Créer des clés d'activation (Dev, Test, Prod)
    - Associer des Content Views et environnements
    - Configurer les repos actifs par défaut
- 📡 **Enregistrement des clients**
    - Installation du client : `subscription-manager register`
    - Bootstrap script (katello-ca-consumer)
    - Vérification : `subscription-manager status`
- 👥 **Host Collections**
    - Organiser les hôtes par fonction (Web, DB, App)
    - Actions en masse (update, errata apply)
- 🎓 **Exercice : "The Fleet"**
    - Créer 3 activation keys (Dev/Test/Prod)
    - Enregistrer 5 serveurs Rocky Linux
    - Appliquer des errata en masse via Host Collections

### Module 4 : Patch Management & Errata
**Durée estimée : 2h30**

- 🔍 **Errata Management**
    - Types d'errata : Security (CVE), Bugfix, Enhancement
    - Consulter les errata disponibles
    - Filtrer par criticité (Critical, Important, Moderate)
- 🚀 **Application des patchs**
    - Méthode 1 : Via Katello UI (Remote Execution)
    - Méthode 2 : Via Hammer CLI (script)
    - Méthode 3 : Via Ansible (katello.foreman collection)
- 📊 **Reporting & Compliance**
    - Dashboards : Hôtes non conformes
    - Rapports d'errata applicables
    - Suivi des installations
- 🎓 **Exercice : "Patch Tuesday Linux"**
    - Identifier les CVE critiques pour Rocky 9
    - Appliquer les errata sur l'environnement Dev
    - Valider (48h), puis promouvoir Test → Prod
    - Générer un rapport de conformité

### Module 5 : TP Final - Infrastructure Multi-Sites
**Durée estimée : 4h**

- 🏢 **Scénario : GlobalTech**
    - 3 sites : Paris (HQ), Lyon, Marseille
    - 500 serveurs Rocky Linux 9 (Web, DB, App)
- 🚀 **Mission**
    - Déployer Katello Central (Paris)
    - Configurer Smart Proxies (Lyon, Marseille)
    - Créer 3 Content Views (Base, Web, DB)
    - Définir 4 Lifecycle Environments (Library → Dev → Test → Prod)
    - Enregistrer les 500 serveurs
    - Appliquer les patchs de sécurité du mois
- ✅ **Validation**
    - Script `Test-Katello-Infra.sh` (10 checks automatisés)
    - Conformité : 100% des serveurs patchés
    - Reporting : Dashboard complet

## 🎓 Prérequis

### Connaissances requises
- ✅ Administration Linux (RHEL/CentOS/Rocky) niveau intermédiaire
- ✅ Gestion de packages RPM (`dnf`, `yum`)
- ✅ Notions de scripting Bash/Python
- ✅ Concepts réseaux (DNS, DHCP, Firewall)

### Environnement technique
- 💻 **Serveur Katello** : Rocky Linux 9 (4 vCPU, 16 GB RAM, 500 GB Disk)
- 💻 **Clients de test** : Rocky Linux 9 (×5 minimum)
- 🌐 **Accès Internet** : Pour synchroniser les repos upstream
- 🔧 **Optionnel** : Ansible Control Node (pour automatisation)

!!! tip "Laboratoire virtuel"
    Un environnement Vagrant est fourni pour simuler l'infrastructure complète (Katello + 10 clients).

## 📖 Méthodologie pédagogique

Chaque module suit la structure **CoPrEx** :

1. **📘 Concept** : Explication théorique avec diagrammes Mermaid
2. **💻 Pratique** : Commandes CLI (Hammer) et API REST avec exemples commentés
3. **🎓 Exercice** : Mise en situation réaliste avec objectifs clairs
4. **✅ Solution** : Correction détaillée avec scripts complets

## 🔗 Références complémentaires

- [Documentation officielle Katello](https://theforeman.org/plugins/katello/)
- [Foreman Documentation](https://theforeman.org/documentation.html)
- [Red Hat Satellite (équivalent commercial)](https://access.redhat.com/products/red-hat-satellite)
- [Pulp Project](https://pulpproject.org/)
- [Guide ShellBook : Package Management Linux](../../linux/package-management.md)

## 🚀 Prêt à commencer ?

Rendez-vous au [Module 1 : Architecture & Installation Katello](01-module.md) pour débuter la formation !

---

!!! question "Besoin d'aide ?"
    Cette formation fait partie du parcours **Écosystème Linux** de ShellBook. Pour des questions ou suggestions, ouvrez une issue sur le [dépôt GitHub](https://github.com/VBlackJack/ShellBook).
