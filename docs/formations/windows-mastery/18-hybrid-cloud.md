---
tags:
  - formation
  - windows-server
  - azure
  - hybrid
  - cloud
---

# Module 18 : Hybrid Cloud

## Objectifs du Module

Ce module couvre l'intégration hybride avec Azure :

- Configurer Azure AD Connect pour la synchronisation
- Déployer Azure Arc pour la gestion des serveurs
- Utiliser Azure Site Recovery pour la DR
- Implémenter Azure File Sync
- Gérer les identités hybrides

**Durée :** 9 heures

**Niveau :** Expert

---

## 1. Azure AD Connect

### 1.1 Prérequis

```
AZURE AD CONNECT - PRÉREQUIS
────────────────────────────

On-Premises:
• Windows Server 2016+ (dédié recommandé)
• .NET Framework 4.7.1+
• Compte Enterprise Admin ou Domain Admin
• SQL Server Express (installé automatiquement) ou SQL Server

Azure:
• Licence Azure AD Premium (pour certaines features)
• Global Administrator
• Domaine personnalisé vérifié (ex: corp.com)

Réseau:
• Port 443 sortant vers Azure
• Pas de proxy pour *.msappproxy.net
```

### 1.2 Installation

```powershell
# Télécharger Azure AD Connect
# https://www.microsoft.com/download/details.aspx?id=47594

# Modes de synchronisation:
# - Password Hash Sync (PHS) - Recommandé, simple
# - Pass-through Authentication (PTA) - Pas de hash dans le cloud
# - Federation (ADFS) - Complexe, on-premises auth

# Installation via GUI recommandée
# AzureADConnect.msi

# Après installation, vérifier:
Get-ADSyncScheduler
Get-ADSyncConnectorRunStatus
```

### 1.3 Configuration PowerShell

```powershell
# Importer le module
Import-Module ADSync

# Forcer une synchronisation
Start-ADSyncSyncCycle -PolicyType Delta
Start-ADSyncSyncCycle -PolicyType Initial

# Vérifier l'état
Get-ADSyncScheduler

# Voir les erreurs
Get-ADSyncRunStepResult -RunHistoryId (Get-ADSyncRunHistory -NumberRequested 1).RunHistoryId

# Configurer le filtrage par OU
# Via GUI: Azure AD Connect → Configure → Customize synchronization options
```

---

## 2. Azure Arc

### 2.1 Onboarding des Serveurs

```powershell
# Télécharger l'agent Azure Arc
# Depuis le portail Azure: Azure Arc → Servers → Add

# Installation silencieuse
$env:SUBSCRIPTION_ID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$env:RESOURCE_GROUP = "Arc-Servers"
$env:TENANT_ID = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
$env:LOCATION = "westeurope"

# Installer l'agent
msiexec.exe /i AzureConnectedMachineAgent.msi /qn

# Connecter à Azure
& "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect `
    --resource-group $env:RESOURCE_GROUP `
    --tenant-id $env:TENANT_ID `
    --location $env:LOCATION `
    --subscription-id $env:SUBSCRIPTION_ID `
    --cloud "AzureCloud"

# Vérifier la connexion
& "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" show
```

### 2.2 Gestion via Azure Arc

```powershell
# Avec Azure CLI ou PowerShell Az
# Extensions disponibles:
# - Log Analytics
# - Azure Monitor
# - Azure Policy
# - Update Management

# Installer une extension
az connectedmachine extension create `
    --machine-name "SRV01" `
    --resource-group "Arc-Servers" `
    --name "MicrosoftMonitoringAgent" `
    --type "MicrosoftMonitoringAgent" `
    --publisher "Microsoft.EnterpriseCloud.Monitoring" `
    --settings '{"workspaceId": "xxxxx"}'
```

---

## 3. Azure Site Recovery

### 3.1 Configuration pour DR

```powershell
# Composants:
# - Recovery Services Vault (Azure)
# - Configuration Server (on-premises, pour VMware)
# - Process Server
# - Master Target Server

# Pour Hyper-V vers Azure:
# 1. Créer un Recovery Services Vault
# 2. Préparer l'infrastructure
# 3. Installer Azure Site Recovery Provider sur les hôtes Hyper-V
# 4. Configurer la réplication

# Via Az PowerShell
$vault = Get-AzRecoveryServicesVault -Name "MyVault" -ResourceGroupName "DR-RG"
Set-AzRecoveryServicesAsrVaultContext -Vault $vault

# Obtenir les éléments répliqués
Get-AzRecoveryServicesAsrReplicationProtectedItem
```

### 3.2 Test de Failover

```powershell
# Test failover (sans impact production)
$protectedItem = Get-AzRecoveryServicesAsrReplicationProtectedItem -ProtectionContainer $container

Start-AzRecoveryServicesAsrTestFailoverJob `
    -ReplicationProtectedItem $protectedItem `
    -Direction PrimaryToRecovery `
    -AzureVMNetworkId "/subscriptions/.../virtualNetworks/test-vnet"

# Nettoyer le test
Start-AzRecoveryServicesAsrTestFailoverCleanupJob -ReplicationProtectedItem $protectedItem
```

---

## 4. Azure File Sync

### 4.1 Déploiement

```powershell
# Architecture:
# Azure Storage Account → Sync Group → Server Endpoint (on-prem)

# 1. Créer le Storage Account et File Share dans Azure

# 2. Créer le Storage Sync Service
# Portail Azure → Storage Sync Services → Create

# 3. Installer l'agent sur le serveur on-prem
# Télécharger depuis le portail

# 4. Enregistrer le serveur
# L'agent ouvre une fenêtre d'authentification

# 5. Créer un Sync Group et ajouter les endpoints
```

### 4.2 Configuration Cloud Tiering

```powershell
# Cloud Tiering = Fichiers peu utilisés stockés uniquement dans Azure

# Configurer via le portail ou PowerShell
# Server Endpoint → Cloud Tiering: Enabled
# - Volume Free Space Policy: 20% (minimum d'espace libre)
# - Date Policy: 30 days (fichiers non accédés depuis X jours)

# Vérifier l'état
Invoke-AzStorageSyncCloudTieringRecommendation -ResourceGroupName "RG" -StorageSyncServiceName "SSS" -SyncGroupName "SG"
```

---

## 5. Identités Hybrides

### 5.1 Seamless SSO

```powershell
# Permet aux utilisateurs de se connecter automatiquement
# aux ressources Azure AD depuis le réseau d'entreprise

# Configuration:
# 1. Azure AD Connect → Configure → Change user sign-in
# 2. Enable Single Sign-On

# Créer le compte ordinateur AZUREADSSOACC dans AD
# GPO pour ajouter la zone Intranet: https://autologon.microsoftazuread-sso.com

# Vérifier
Get-ADComputer -Filter 'Name -like "AZUREADSSOACC*"'
```

### 5.2 Password Writeback

```powershell
# Permet la réinitialisation de MDP depuis Azure AD → AD on-prem

# Prérequis:
# - Azure AD Premium P1 ou P2
# - Azure AD Connect avec Password Writeback activé

# Configuration dans Azure AD Connect:
# Optional features → Password writeback

# Tester:
# 1. Utilisateur va sur portal.azure.com
# 2. Clique "Can't access your account?"
# 3. Réinitialise son mot de passe
# 4. Le MDP est synchronisé vers AD on-prem
```

---

## 6. Exercice Pratique

### Configuration Hybride Complète

```powershell
# Scénario: Intégrer un AD on-prem avec Azure

# 1. Vérifier le domaine dans Azure AD
# Azure Portal → Azure Active Directory → Custom domain names

# 2. Installer Azure AD Connect
# Mode: Password Hash Sync + Seamless SSO

# 3. Configurer le filtrage
# Uniquement l'OU "OU=Cloud,DC=corp,DC=local"

# 4. Forcer la sync initiale
Import-Module ADSync
Start-ADSyncSyncCycle -PolicyType Initial

# 5. Vérifier dans Azure AD
# Les utilisateurs de l'OU Cloud doivent apparaître

# 6. Tester le SSO
# Se connecter à portal.azure.com depuis un poste joint au domaine
# Sans entrer de mot de passe si SSO configuré
```

---

## Quiz

1. **Quel mode Azure AD Connect n'envoie pas de hash de mot de passe vers Azure ?**
   - [ ] A. Password Hash Sync
   - [ ] B. Pass-through Authentication
   - [ ] C. Les deux

2. **Qu'est-ce que le Cloud Tiering dans Azure File Sync ?**
   - [ ] A. Backup des fichiers
   - [ ] B. Fichiers peu utilisés stockés uniquement dans Azure
   - [ ] C. Compression des fichiers

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 17 : Conteneurs Windows](17-conteneurs-windows.md)

**Suivant :** [Module 19 : Infrastructure as Code](19-infrastructure-as-code.md)
