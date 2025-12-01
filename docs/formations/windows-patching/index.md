---
title: Windows Patch Management
description: Formation complète sur la gestion des mises à jour Windows avec WSUS
tags:
  - windows
  - wsus
  - patching
  - formation
---

# ♻️ Windows Patch Management

!!! abstract "Vue d'ensemble"
    Formation complète sur la gestion centralisée des mises à jour Windows Server avec WSUS (Windows Server Update Services). Apprenez à déployer, configurer et maintenir une infrastructure de gestion des correctifs sécurisée et efficace.

## 🎯 Objectifs pédagogiques

À l'issue de cette formation, vous serez capable de :

- ✅ **Maîtriser le cycle de vie des mises à jour** : Comprendre l'architecture WSUS et les flux de synchronisation
- ✅ **Installer et configurer WSUS** : Déployer un serveur WSUS en production avec les bonnes pratiques
- ✅ **Gérer les groupes de clients** : Organiser les ordinateurs par criticité (Dev, Test, Prod)
- ✅ **Automatiser via GPO** : Configurer les clients Windows pour utiliser WSUS automatiquement
- ✅ **Assurer la maintenance** : Nettoyer la base WSUS et optimiser les performances
- ✅ **Dépanner les problèmes** : Diagnostiquer les échecs de synchronisation et d'approbation

## 📚 Programme détaillé

### Module 1 : Architecture WSUS & Installation
**Durée estimée : 2h**

- 🏗️ **Architecture & Concepts**
    - Flux de synchronisation (Microsoft Update → WSUS → Clients)
    - Database : WID vs SQL Server
    - Stratégie de stockage (Content vs Metadata)
- 💻 **Installation PowerShell**
    - Role UpdateServices
    - Post-configuration avec wsusutil
    - Première synchronisation
- 🎓 **Exercice : "First Sync"**
    - Déployer un serveur WSUS
    - Configurer le stockage sur D:\WSUS
    - Sélectionner Windows Server 2022 + Security Updates uniquement

### Module 2 : Gestion des Mises à Jour
**Durée estimée : 2h30**

- 📦 **Products & Classifications**
    - Choisir les produits Microsoft (Windows Server, Defender, SQL, Office)
    - Catégories de mises à jour (Critical, Security, Updates, Service Packs)
- 👥 **Computer Target Groups**
    - Créer des groupes (DEV, TEST, PROD)
    - Side-by-side assignment vs Server-side assignment
- ✅ **Workflow d'approbation**
    - Approuver manuellement
    - Automatic Approval Rules
    - Deadlines & Installation behavior
- 🎓 **Exercice : "Ring Deployment"**
    - Créer 3 groupes (Dev/Test/Prod)
    - Approuver KB pour Dev immédiatement
    - Déployer en Prod avec deadline +7 jours

### Module 3 : Configuration des Clients (GPO)
**Durée estimée : 2h**

- 🔧 **Group Policy Settings**
    - Configure Automatic Updates (Mode 4 : Auto Download and Schedule)
    - Specify intranet Microsoft update service location
    - No auto-restart with logged on users
- 📊 **Reporting & Compliance**
    - WSUS Console : Update Status Report
    - Computer Status Report
    - PowerShell : Get-WsusComputer -UpdateErrors
- 🎓 **Exercice : "GPO Rollout"**
    - Créer GPO "WSUS-Clients-Prod"
    - Configurer WSUS Server URL (http://wsus.corp.local:8530)
    - Forcer le reporting status toutes les 4h
    - Tester avec gpupdate /force + wuauclt /detectnow

### Module 4 : Maintenance & Dépannage
**Durée estimée : 2h**

- 🧹 **Maintenance WSUS**
    - WSUS Server Cleanup Wizard (Declined updates, Obsolete computers)
    - Re-indexing SQL/WID Database
    - Automatic maintenance via PowerShell
- 🔍 **Troubleshooting**
    - Logs clients : C:\Windows\WindowsUpdate.log
    - Logs serveur : Event Viewer > WSUS
    - Sync errors : Proxy, Firewall, Certificates
- 🎓 **Exercice : "Health Check Script"**
    - Créer un script Invoke-WSUSMaintenance.ps1
    - Vérifier le dernier sync (< 24h)
    - Nettoyer les updates obsolètes
    - Re-indexer si nécessaire
    - Envoyer un rapport par email

### Module 5 : TP Final - Infrastructure Multi-Sites
**Durée estimée : 3h**

- 🏢 **Scénario réel**
    - Siège social : WSUS-HQ (Upstream Microsoft Update)
    - Filiale : WSUS-BRANCH (Replica mode ou Autonomous mode)
- 🚀 **Déploiement complet**
    - Installer WSUS-HQ avec SQL Server
    - Configurer WSUS-BRANCH en mode Replica
    - Créer 6 groupes (HQ-Dev/Test/Prod + BRANCH-Dev/Test/Prod)
    - Déployer 3 GPO (une par environnement)
    - Approuver Windows Server 2022 Security Updates pour Q1 2025
- ✅ **Validation**
    - Script Test-WSUSInfra.ps1
    - 10 checks automatisés (Sync OK, Groups created, GPO applied, Clients reporting)

## 🎓 Prérequis

### Connaissances requises
- ✅ Administration Windows Server (Rôles & Fonctionnalités)
- ✅ PowerShell niveau intermédiaire (Get-*, Set-*, New-*)
- ✅ Active Directory : Notions de GPO (Computer Configuration)
- ✅ Réseau : DNS, Proxy, Firewall basics

### Environnement technique
- 💻 **Serveur WSUS** : Windows Server 2022 (4 vCPU, 8 GB RAM, 200 GB Disk)
- 💻 **Clients de test** : Windows Server 2022 ou Windows 10/11 (x3)
- 🌐 **Accès Internet** : Pour synchroniser depuis Microsoft Update
- 🔐 **Active Directory** : Domaine existant (pour les GPO)

!!! tip "Suggestion"
    Si vous n'avez pas d'infrastructure AD, le Module 1 peut être réalisé sur un serveur standalone. Les Modules 3-5 nécessitent un domaine.

## 📖 Méthodologie pédagogique

Chaque module suit la structure **CoPrEx** :

1. **📘 Concept** : Explication théorique avec schémas Mermaid
2. **💻 Pratique** : Commandes PowerShell avec exemples commentés
3. **🎓 Exercice** : Mise en situation réaliste avec objectifs clairs
4. **✅ Solution** : Correction détaillée avec scripts complets

## 🔗 Références complémentaires

- [Documentation WSUS (Microsoft Learn)](https://learn.microsoft.com/fr-fr/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus)
- [PSWindowsUpdate Module (Community)](https://www.powershellgallery.com/packages/PSWindowsUpdate)
- [Guide de référence ShellBook : Update Management](../../windows/update-management.md)

## 📑 Accès aux Modules

| Module | Titre | Durée |
|--------|-------|-------|
| [Module 1](01-module.md) | Architecture WSUS & Installation | 2h |
| [Module 2](02-module.md) | Gestion des Mises à Jour | 2h30 |
| [Module 3](03-module.md) | Configuration des Clients (GPO) | 2h |
| [Module 4](04-module.md) | Maintenance & Dépannage | 2h |
| [TP Final](05-tp-final.md) | Infrastructure Multi-Sites | 3h |

## 🚀 Prêt à commencer ?

Rendez-vous au [Module 1 : Architecture & Installation WSUS](01-module.md) pour débuter la formation !

---

!!! question "Besoin d'aide ?"
    Cette formation fait partie du parcours **Écosystème Microsoft** de ShellBook. Pour des questions ou suggestions, ouvrez une issue sur le [dépôt GitHub](https://github.com/VBlackJack/ShellBook).
