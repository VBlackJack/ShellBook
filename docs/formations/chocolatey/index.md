---
title: Chocolatey Factory - Packaging Windows
description: Formation complète sur la gestion de packages Windows avec Chocolatey
tags:
  - windows
  - chocolatey
  - packaging
  - automation
  - formation
---

# 🍫 Chocolatey Factory : Packaging Windows

!!! abstract "Vue d'ensemble"
    Formation complète sur **Chocolatey**, le gestionnaire de packages pour Windows. Apprenez à créer, déployer et gérer des packages d'applications Windows de manière automatisée, du poste de travail aux serveurs, avec un repository privé et une intégration CI/CD.

## 🎯 Objectifs pédagogiques

À l'issue de cette formation, vous serez capable de :

- ✅ **Maîtriser le client Chocolatey** : Installation, recherche, installation/désinstallation de packages
- ✅ **Créer des packages** : Packaging d'applications (MSI, EXE, ZIP) avec nuspec et PowerShell
- ✅ **Déployer un repository privé** : Chocolatey Server, Artifactory ou Nexus
- ✅ **Automatiser les déploiements** : Ansible, GPO, Intune, SCCM
- ✅ **Gérer les versions** : Update, pinning, rollback
- ✅ **Sécuriser** : Signatures, checksums, source validation
- ✅ **Intégrer CI/CD** : GitLab CI, GitHub Actions pour packager automatiquement

## 📚 Programme détaillé

### Module 1 : Client & CLI Chocolatey
**Durée estimée : 2h**

- 🍫 **Introduction à Chocolatey**
    - Pourquoi Chocolatey ? (vs winget, SCCM, scripts manuels)
    - Architecture : Client → Repository (public/privé)
    - Comparaison : chocolatey.org vs Chocolatey for Business
- 💻 **Installation du client**
    - Installation via PowerShell (one-liner)
    - Configuration : sources, proxy, cache
    - Vérification : `choco --version`
- 🔍 **Commandes essentielles**
    - `choco search` : Rechercher des packages
    - `choco install` : Installer (avec --yes, --force)
    - `choco upgrade` : Mettre à jour
    - `choco uninstall` : Désinstaller
    - `choco list --local-only` : Lister les packages installés
- 🎓 **Exercice : "The Workstation Setup"**
    - Installer Chocolatey sur Windows 11
    - Installer 7zip, Git, VSCode, Chrome via Chocolatey
    - Créer un script `setup-workstation.ps1` pour automatiser

### Module 2 : Création de Paquets (Packaging)
**Durée estimée : 3h**

- 📦 **Anatomie d'un package Chocolatey**
    - Structure : `.nuspec` (métadonnées) + `tools\chocolateyInstall.ps1`
    - Manifest nuspec : id, version, authors, dependencies
    - Script PowerShell : Install-ChocolateyPackage, Uninstall
- 🛠️ **Créer un package MSI**
    - Étape 1 : `choco new myapp` (génère le template)
    - Étape 2 : Éditer `myapp.nuspec`
    - Étape 3 : Télécharger le MSI (ou embarquer localement)
    - Étape 4 : `choco pack` (génère myapp.1.0.0.nupkg)
    - Étape 5 : Tester avec `choco install myapp -source .`
- 🔒 **Checksums & Sécurité**
    - Générer les checksums : `checksum -t sha256 -f installer.msi`
    - Valider les téléchargements (éviter MITM attacks)
- 🎓 **Exercice : "Package Notepad++"**
    - Créer un package pour Notepad++ 8.6.0
    - Télécharger l'installer depuis GitHub Releases
    - Générer le checksum SHA256
    - Packager et tester l'installation
    - Gérer la désinstallation proprement

### Module 3 : Serveur Privé (Internal Repository)
**Durée estimée : 2h30**

- 🏢 **Pourquoi un repository privé ?**
    - Contrôle des versions approuvées
    - Packages internes (apps métier)
    - Pas de dépendance Internet (air-gapped environments)
- 🖥️ **Solutions de hosting**
    - **Chocolatey Server** (simple, gratuit, ASP.NET)
    - **Artifactory** / **Nexus** (enterprise-grade)
    - **File Share** (basique, SMB)
- 🚀 **Déployer Chocolatey Server**
    - Installation sur Windows Server 2022
    - Configuration IIS (port 80/443)
    - Ajouter la source sur les clients : `choco source add -n internal -s http://choco.corp.local`
- 📤 **Pousser des packages**
    - `choco push myapp.1.0.0.nupkg -s http://choco.corp.local -k API_KEY`
- 🎓 **Exercice : "The Corporate Repository"**
    - Déployer Chocolatey Server sur un serveur
    - Pousser 3 packages (7zip, Notepad++, Chrome)
    - Configurer 5 clients pour utiliser le repo privé
    - Installer les packages depuis le repo interne

### Module 4 : Déploiement Automatisé
**Durée estimée : 3h**

- 🤖 **Méthode 1 : Ansible**
    - Module `win_chocolatey` : Install, upgrade, uninstall
    - Playbook : Déployer une stack complète (IIS, SQL, .NET)
- 📋 **Méthode 2 : Group Policy (GPO)**
    - Scheduled Task via GPO (script PowerShell + choco install)
    - Startup Script (Computer Configuration)
    - Déploiement silencieux : `--yes --no-progress`
- ☁️ **Méthode 3 : Intune / SCCM**
    - Créer une app Intune avec Chocolatey wrapper
    - Déployer sur des groupes AD (Dev, Test, Prod)
- 🎓 **Exercice : "Mass Deployment"**
    - Créer un playbook Ansible pour déployer :
        - Google Chrome
        - 7zip
        - Notepad++
        - Git
    - Tester sur 10 VMs Windows 11
    - Vérifier avec `choco list --local-only`

### Module 5 : TP Final - Chocolatey Factory Complète
**Durée estimée : 4h**

- 🏢 **Scénario : DevOps Corp**
    - 200 postes de travail Windows 11
    - 50 serveurs Windows Server 2022
    - Besoin : Standardiser les apps installées
- 🚀 **Mission**
    - Déployer Chocolatey Server (repository privé)
    - Créer 10 packages d'applications métier :
        - 7zip, Chrome, Firefox, VSCode, Git, Postman
        - SQL Server Management Studio, Putty, WinSCP, FileZilla
    - Configurer 3 "stacks" :
        - **Developer Stack** : VSCode, Git, Postman, Docker Desktop
        - **Admin Stack** : Putty, WinSCP, SSMS, Sysinternals
        - **User Stack** : Chrome, 7zip, PDF Reader
    - Déployer via Ansible sur les 200 postes
    - Créer un pipeline GitLab CI pour auto-packager les nouvelles versions
- ✅ **Validation**
    - Script `Test-ChocoFactory.ps1` (10 checks)
    - 100% des postes avec les bonnes apps
    - Repository privé opérationnel

## 🎓 Prérequis

### Connaissances requises
- ✅ Administration Windows (niveau intermédiaire)
- ✅ PowerShell (niveau basique)
- ✅ Notions de packaging (MSI, EXE)
- ✅ Git (pour le TP CI/CD)

### Environnement technique
- 💻 **Serveur Chocolatey** : Windows Server 2022 (2 vCPU, 4 GB RAM, 100 GB Disk)
- 💻 **Clients de test** : Windows 11 Pro (×5 minimum)
- 🌐 **Accès Internet** : Pour télécharger les installers
- 🔧 **Optionnel** : Ansible Control Node (Linux/WSL) pour automatisation

!!! tip "Laboratoire virtuel"
    Un environnement Vagrant est fourni avec 1 Chocolatey Server + 5 clients Windows 11.

## 📖 Méthodologie pédagogique

Chaque module suit la structure **CoPrEx** :

1. **📘 Concept** : Explication théorique avec architecture
2. **💻 Pratique** : Commandes CLI et scripts PowerShell commentés
3. **🎓 Exercice** : Mise en situation réaliste avec objectifs clairs
4. **✅ Solution** : Correction détaillée avec scripts complets

## 🔗 Références complémentaires

- [Documentation officielle Chocolatey](https://docs.chocolatey.org/)
- [Chocolatey Community Repository](https://community.chocolatey.org/packages)
- [Chocolatey for Business](https://chocolatey.org/compare)
- [Packaging Best Practices](https://docs.chocolatey.org/en-us/create/create-packages)
- [Guide ShellBook : Windows Productivity](../../windows/productivity.md)

## 🚀 Prêt à commencer ?

Rendez-vous au **Module 1 : Client & CLI Chocolatey** pour débuter la formation !

---

!!! question "Besoin d'aide ?"
    Cette formation fait partie du parcours **Écosystème Microsoft** de ShellBook. Pour des questions ou suggestions, ouvrez une issue sur le [dépôt GitHub](https://github.com/VBlackJack/ShellBook).
