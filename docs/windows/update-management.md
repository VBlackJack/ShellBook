# Update Management: WSUS & Modern Patching

`#wsus` `#updates` `#hotpatching` `#pswindowsupdate` `#azure-arc`

Gestion moderne des mises à jour Windows Server : PSWindowsUpdate, WSUS Legacy, et Hotpatching (2025).

---

## L'Outil Indispensable : PSWindowsUpdate

### Qu'est-ce que PSWindowsUpdate ?

**PSWindowsUpdate = Le module PowerShell communautaire que tout admin Windows utilise**

```
┌─────────────────────────────────────────────────────────────┐
│                   POURQUOI PSWINDOWSUPDATE ?                 │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  GUI Windows Update                 PSWindowsUpdate          │
│  ───────────────                    ─────────────            │
│  ✗ Clic manuel                      ✓ Automatisation         │
│  ✗ Un serveur à la fois             ✓ Multi-serveurs         │
│  ✗ Pas de filtrage                  ✓ Filtres avancés        │
│  ✗ Pas de reporting                 ✓ Logs détaillés         │
│  ✗ Pas de reboot contrôlé           ✓ Reboot planifié        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Installation

```powershell
# Installer le module (depuis PowerShell Gallery)
Install-Module PSWindowsUpdate -Force

# Vérifier l'installation
Get-Module PSWindowsUpdate -ListAvailable

# Importer le module
Import-Module PSWindowsUpdate

# Lister les commandes disponibles
Get-Command -Module PSWindowsUpdate
```

**Commandes principales :**

| Commande | Description |
|----------|-------------|
| `Get-WindowsUpdate` | Lister les mises à jour disponibles |
| `Install-WindowsUpdate` | Installer les mises à jour |
| `Hide-WindowsUpdate` | Masquer une mise à jour |
| `Show-WindowsUpdate` | Afficher une mise à jour masquée |
| `Get-WUHistory` | Historique des installations |
| `Get-WURebootStatus` | Vérifier si un reboot est requis |

### Usage de Base

```powershell
# Lister les mises à jour disponibles
Get-WindowsUpdate

# Output:
# ComputerName Status KB        Size Title
# ------------ ------ --        ---- -----
# SRV01        ------ KB5034441 145M 2024-01 Cumulative Update for Windows Server 2022

# Installer toutes les mises à jour
Install-WindowsUpdate -AcceptAll -AutoReboot

# Installer sans redémarrer
Install-WindowsUpdate -AcceptAll -IgnoreReboot

# Installer uniquement les mises à jour critiques
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Criteria "IsInstalled=0 and Type='Software'" -AutoReboot

# Installer uniquement les mises à jour de sécurité
Get-WindowsUpdate -Category 'Security Updates' | Install-WindowsUpdate -AcceptAll
```

### Filtrage Avancé

```powershell
# Exclure les mises à jour de pilotes
Install-WindowsUpdate -AcceptAll -NotCategory "Drivers" -AutoReboot

# Exclure un KB spécifique (problématique)
Install-WindowsUpdate -AcceptAll -NotKBArticleID "KB5034441" -AutoReboot

# Installer uniquement les définitions Windows Defender
Get-WindowsUpdate -Category "Definition Updates" | Install-WindowsUpdate -AcceptAll

# Télécharger sans installer (pré-staging)
Get-WindowsUpdate -Download -AcceptAll

# Installer les mises à jour déjà téléchargées
Install-WindowsUpdate -AcceptAll -AutoReboot
```

### Gestion Multi-Serveurs

```powershell
# Liste de serveurs
$Servers = @("SRV01", "SRV02", "SRV03")

# Vérifier les mises à jour sur tous les serveurs
$Servers | ForEach-Object {
    Get-WindowsUpdate -ComputerName $_
}

# Installer sur tous les serveurs
$Servers | ForEach-Object {
    Invoke-Command -ComputerName $_ -ScriptBlock {
        Import-Module PSWindowsUpdate
        Install-WindowsUpdate -AcceptAll -AutoReboot
    }
}

# Avec reporting
$Report = @()
foreach ($Server in $Servers) {
    $Updates = Get-WindowsUpdate -ComputerName $Server
    $Report += [PSCustomObject]@{
        Server        = $Server
        UpdatesCount  = $Updates.Count
        Updates       = $Updates.Title -join "; "
    }
}
$Report | Export-Csv "Updates_Report.csv" -NoTypeInformation
```

### Planification avec Tâches Planifiées

```powershell
# Créer une tâche planifiée pour installer les mises à jour tous les mardis à 3h
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument '-NoProfile -Command "Import-Module PSWindowsUpdate; Install-WindowsUpdate -AcceptAll -AutoReboot"'

$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Tuesday -At 3AM

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Windows Updates - Auto Install" `
    -Action $Action `
    -Trigger $Trigger `
    -Principal $Principal `
    -Description "Installation automatique des mises à jour Windows"
```

### Historique et Reporting

```powershell
# Historique des mises à jour
Get-WUHistory

# Dernières 10 mises à jour
Get-WUHistory | Select-Object -First 10 ComputerName, Date, Title, Result

# Mises à jour échouées
Get-WUHistory | Where-Object Result -eq "Failed"

# Vérifier si un reboot est requis
Get-WURebootStatus

# Export CSV pour audit
Get-WUHistory | Export-Csv "Update_History.csv" -NoTypeInformation
```

!!! tip "Astuce Production"
    Utilisez PSWindowsUpdate avec **Ansible** ou **Scheduled Tasks** pour automatiser les patchs sur votre parc :

    ```yaml
    # Playbook Ansible
    - name: Install Windows Updates
      win_updates:
        category_names:
          - SecurityUpdates
          - CriticalUpdates
        reboot: yes
        reboot_timeout: 3600
    ```

---

## WSUS : Gestion Legacy (2019/2022)

### Qu'est-ce que WSUS ?

**WSUS (Windows Server Update Services) = Serveur de mises à jour local**

```
┌─────────────────────────────────────────────────────────────┐
│                      ARCHITECTURE WSUS                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Microsoft Update  ──→  WSUS Server  ──→  Clients Windows   │
│  (Internet)              (Interne)         (Parc)           │
│                                                              │
│  Avantages :                                                │
│  ✓ Contrôle des mises à jour (approuver/refuser)            │
│  ✓ Bande passante économisée (téléchargement unique)        │
│  ✓ Reporting centralisé                                     │
│  ✓ Déploiement par groupes                                  │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

!!! warning "WSUS est officiellement Deprecated dans Server 2025"
    Microsoft recommande désormais **Azure Update Management** ou **Microsoft Endpoint Manager (SCCM)**.

    Cependant, WSUS fonctionne encore sur Server 2025 pour les environnements on-premises purs.

### Installation WSUS

```powershell
# Installer le rôle WSUS (avec base de données interne WID)
Install-WindowsFeature -Name UpdateServices -IncludeManagementTools

# Avec base de données SQL Server (pour gros parcs >500 clients)
Install-WindowsFeature -Name UpdateServices, UpdateServices-DB -IncludeManagementTools

# Post-installation : Configurer le répertoire de stockage
# (Prévoir 50-100 GB minimum)
$WSUSUtil = "C:\Program Files\Update Services\Tools\wsusutil.exe"
& $WSUSUtil postinstall CONTENT_DIR=D:\WSUS
```

### Configuration WSUS

```powershell
# Se connecter au serveur WSUS
$WSUSServer = Get-WsusServer

# Configurer la synchronisation avec Microsoft Update
Set-WsusServerSynchronization -SyncFromMU

# Sélectionner les produits (Windows Server, Defender, etc.)
Get-WsusProduct | Where-Object {
    $_.Product.Title -like "*Windows Server*" -or
    $_.Product.Title -like "*Defender*"
} | Set-WsusProduct

# Sélectionner les classifications (Critical, Security, etc.)
Get-WsusClassification | Where-Object {
    $_.Classification.Title -in @("Critical Updates", "Security Updates", "Update Rollups")
} | Set-WsusClassification

# Configurer la synchronisation automatique (tous les jours à 2h)
$Subscription = $WSUSServer.GetSubscription()
$Subscription.SynchronizeAutomatically = $true
$Subscription.SynchronizeAutomaticallyTimeOfDay = "02:00:00"
$Subscription.NumberOfSynchronizationsPerDay = 1
$Subscription.Save()

# Lancer la première synchronisation (long, 1-3h)
$Subscription.StartSynchronization()
```

### Gestion des Groupes et Déploiement

```powershell
# Créer des groupes de déploiement
$WSUSServer = Get-WsusServer

# Groupe "Production Servers"
$ProdGroup = $WSUSServer.CreateComputerTargetGroup("Production Servers")

# Groupe "Test Servers"
$TestGroup = $WSUSServer.CreateComputerTargetGroup("Test Servers")

# Approuver les mises à jour pour un groupe
# (via GUI recommandé, ou PowerShell)
Get-WsusUpdate -Approval Unapproved -Status FailedOrNeeded |
    Where-Object { $_.Title -like "*Security*" } |
    Approve-WsusUpdate -Action Install -TargetGroupName "Test Servers"

# Refuser une mise à jour problématique
Get-WsusUpdate | Where-Object { $_.KnowledgebaseArticles -contains "5034441" } |
    Deny-WsusUpdate
```

### Configuration Clients (GPO)

**Méthode recommandée : GPO**

```
GPO Path: Computer Configuration → Policies → Administrative Templates
          → Windows Components → Windows Update

Paramètres à configurer :
├── Configure Automatic Updates               → Enabled (4 - Auto download and schedule install)
├── Specify intranet Microsoft update service → Enabled
│   └── http://wsus.corp.local:8530
├── Enable client-side targeting              → Enabled
│   └── Target group name: "Production Servers"
└── No auto-restart with logged on users      → Enabled
```

**Méthode PowerShell (sans GPO) :**

```powershell
# Configurer le client pour utiliser WSUS
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
    -Name "WUServer" -Value "http://wsus.corp.local:8530"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
    -Name "WUStatusServer" -Value "http://wsus.corp.local:8530"

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -Name "UseWUServer" -Value 1

# Forcer la détection immédiate
wuauclt /detectnow
```

### Reporting WSUS

```powershell
# Serveurs nécessitant des mises à jour
Get-WsusComputer -All | Where-Object {
    $_.UpdatesNeededCount -gt 0
} | Select-Object FullDomainName, UpdatesNeededCount, LastReportedStatusTime

# Mises à jour non approuvées
Get-WsusUpdate -Approval Unapproved | Select-Object Title, SecurityBulletins, UpdatesSupersedingThisUpdate

# Statistiques globales
$WSUSServer = Get-WsusServer
$WSUSServer.GetStatus()
```

### Maintenance WSUS

```powershell
# Nettoyage (supprimer updates obsolètes, logs, etc.)
# Exécuter mensuellement
Invoke-WsusServerCleanup -CleanupObsoleteUpdates `
    -CleanupUnneededContentFiles `
    -CompressUpdates `
    -DeclineExpiredUpdates `
    -DeclineSupersededUpdates

# Réindexation de la base de données (améliore les performances)
# Exécuter trimestriellement
$WSUSUtil = "C:\Program Files\Update Services\Tools\wsusutil.exe"
& $WSUSUtil reset
```

!!! danger "WSUS = Maintenance Importante"
    Un serveur WSUS mal maintenu peut :

    - Consommer **100+ GB** d'espace disque avec des mises à jour obsolètes
    - Ralentir drastiquement (base de données non optimisée)
    - Ne plus synchroniser correctement

    **Action requise : Nettoyage mensuel obligatoire**

---

## Le Futur : Hotpatching & Azure Arc

### Hotpatching : La Révolution du Patching

**Hotpatching = Patcher la RAM sans redémarrer le serveur**

```
┌─────────────────────────────────────────────────────────────┐
│              PATCHING TRADITIONNEL vs HOTPATCHING            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Traditionnel                     Hotpatching                │
│  ─────────────                    ────────────               │
│  1. Télécharger patch             1. Télécharger patch       │
│  2. Installer                     2. Appliquer en mémoire    │
│  3. Redémarrer serveur (5-10min)  3. Redémarrer processus    │
│  4. Downtime = $$$ perdu          4. Serveur reste UP        │
│                                                              │
│  Reboot : Mensuel                 Reboot : Trimestriel       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Prérequis Hotpatching

**Disponibilité :**

| Élément | Requis |
|---------|--------|
| **OS** | Windows Server 2025 Datacenter Edition (Hotpatch-enabled) |
| **Image** | Azure Marketplace Image "Hotpatch" ou ISO spécifique |
| **Azure Arc** | Serveur connecté à Azure Arc (même on-premises) |
| **Licence** | Azure Arc-enabled Servers (Pay-as-you-go ou abonnement) |

!!! warning "Limitation importante"
    Hotpatching n'est **PAS** disponible sur les installations Windows Server traditionnelles.

    Vous devez utiliser :
    - **Azure VMs** avec images Hotpatch
    - **Serveurs on-premises** connectés à Azure Arc avec images Hotpatch

### Configuration Hotpatching (Azure VM)

```powershell
# Créer une VM Azure avec Hotpatching activé
$VMParams = @{
    ResourceGroupName   = "RG-Production"
    Location            = "West Europe"
    Name                = "SRV-WEB01"
    Size                = "Standard_D4s_v3"
    Image               = "MicrosoftWindowsServer:WindowsServer:2025-datacenter-azure-edition-hotpatch:latest"
    PatchMode           = "AutomaticByPlatform"
    EnableHotpatching   = $true
}
New-AzVM @VMParams

# Vérifier le statut Hotpatching
Get-AzVM -ResourceGroupName "RG-Production" -Name "SRV-WEB01" |
    Select-Object -ExpandProperty OSProfile |
    Select-Object WindowsConfiguration
```

### Configuration Hotpatching (On-Premises avec Azure Arc)

```powershell
# 1. Installer Azure Arc Agent (sur le serveur on-prem)
# Télécharger depuis Azure Portal : Servers - Azure Arc → Add

# Exemple de script de connexion
$ArcParams = @{
    SubscriptionId       = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
    ResourceGroup        = "RG-OnPrem-Servers"
    TenantId             = "YYYYYYYY-YYYY-YYYY-YYYY-YYYYYYYYYYYY"
    Location             = "westeurope"
    AuthenticationType   = "token"
}

# Télécharger et exécuter l'agent
$DownloadUrl = "https://aka.ms/AzureConnectedMachineAgent"
Invoke-WebRequest -Uri $DownloadUrl -OutFile "AzureConnectedMachineAgent.msi"
msiexec /i AzureConnectedMachineAgent.msi /quiet

# Connecter le serveur
azcmagent connect @ArcParams

# 2. Activer Update Management dans Azure Portal
# Azure Portal → Azure Arc → Servers → Votre serveur → Update Management → Enable

# 3. Configurer Hotpatching
# Azure Portal → Update Management → Settings → Enable Hotpatch
```

### Cycle de Hotpatching

**Fonctionnement :**

```
┌─────────────────────────────────────────────────────────────┐
│                   CYCLE HOTPATCHING                          │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Mois 1 : Hotpatch (pas de reboot)                          │
│  Mois 2 : Hotpatch (pas de reboot)                          │
│  Mois 3 : Baseline Update (reboot requis)                   │
│                                                              │
│  → 2 patchs sur 3 sans reboot = 66% de downtime évité       │
│                                                              │
│  Types de patchs compatibles Hotpatch :                     │
│  ✓ Security Updates (CVE critiques)                         │
│  ✓ Définitions Windows Defender                             │
│  ✗ Feature Updates                                          │
│  ✗ Kernel Updates (nécessitent baseline)                    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Monitoring Hotpatching

```powershell
# Via Azure CLI (si serveur connecté à Arc)
az rest --method get --url \
  "https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.HybridCompute/machines/{machineName}/patchAssessmentResults?api-version=2021-05-20"

# Via Azure Portal
# Azure Arc → Servers → Votre serveur → Update Management → Update history
```

### Comparaison des Méthodes

| Méthode | Reboot Fréquence | Coût | Complexité | Cas d'usage |
|---------|------------------|------|------------|-------------|
| **PSWindowsUpdate** | Mensuel | Gratuit | Faible | Petits parcs, automatisation simple |
| **WSUS** | Mensuel | Gratuit (serveur requis) | Moyenne | Parcs >50 serveurs on-prem |
| **Hotpatching** | Trimestriel | Azure Arc licensing | Élevée | Applications critiques 24/7 |
| **SCCM/Intune** | Mensuel | Licence Microsoft 365 | Élevée | Entreprise, gestion unifiée clients+serveurs |

!!! tip "Recommandation par Taille de Parc"
    - **<20 serveurs** : PSWindowsUpdate + Scheduled Tasks
    - **20-200 serveurs** : WSUS (2019/2022) ou Azure Update Management (2025)
    - **>200 serveurs** : SCCM ou Azure Update Management avec Azure Arc
    - **Applications critiques** : Hotpatching (si budget disponible)

---

## Tableau Récapitulatif : Legacy vs Modern

| Aspect | Legacy (2019/2022) | Modern (2025) |
|--------|-------------------|---------------|
| **Outil natif** | Windows Update (GUI) | Windows Update (GUI) |
| **Module PowerShell** | PSWindowsUpdate (communauté) | PSWindowsUpdate (communauté) |
| **Serveur centralisé** | WSUS (Deprecated en 2025) | Azure Update Management |
| **Patching sans reboot** | Non | Hotpatching (avec Azure Arc) |
| **Reporting** | WSUS Reports / Scripts PS | Azure Monitor / Azure Arc |
| **GPO** | Oui (WSUS + Windows Update) | Oui (compatible) |
| **Coût** | Gratuit (on-prem) | Azure Arc licensing (pay-as-you-go) |

---

## Quick Reference

```powershell
# === PSWINDOWSUPDATE ===
Install-Module PSWindowsUpdate -Force
Get-WindowsUpdate                              # Lister les mises à jour
Install-WindowsUpdate -AcceptAll -AutoReboot   # Installer tout + reboot
Get-WindowsUpdate -Category 'Security Updates' | Install-WindowsUpdate -AcceptAll
Get-WUHistory                                  # Historique

# === WSUS (Server) ===
Install-WindowsFeature UpdateServices -IncludeManagementTools
Get-WsusServer                                 # Se connecter
Get-WsusUpdate -Approval Unapproved            # Mises à jour non approuvées
Invoke-WsusServerCleanup -CleanupObsoleteUpdates  # Maintenance

# === WSUS (Client Config via Reg) ===
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
    -Name "WUServer" -Value "http://wsus.corp.local:8530"
wuauclt /detectnow                             # Forcer détection

# === AZURE ARC (Hotpatching) ===
# Installer agent
msiexec /i AzureConnectedMachineAgent.msi /quiet
azcmagent connect --subscription-id <ID> --resource-group <RG>
```
