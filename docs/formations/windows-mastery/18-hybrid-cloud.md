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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer une infrastructure hybride complète avec synchronisation Azure AD Connect, gestion des serveurs via Azure Arc, et réplication de fichiers avec Azure File Sync

    **Contexte** : Votre entreprise souhaite adopter une stratégie cloud hybride. Vous devez intégrer l'Active Directory on-premises avec Azure AD pour permettre le SSO vers les applications cloud, onboarder les serveurs Windows dans Azure Arc pour une gestion centralisée, et mettre en place Azure File Sync pour répliquer les fichiers critiques vers le cloud en conservant un cache local.

    **Tâches à réaliser** :

    1. Vérifier et ajouter un domaine personnalisé `corp.com` dans Azure AD, puis installer Azure AD Connect sur un serveur dédié avec le mode Password Hash Sync et Seamless SSO activé
    2. Configurer le filtrage OU dans Azure AD Connect pour synchroniser uniquement l'OU `OU=CloudUsers,DC=corp,DC=local` et forcer une synchronisation initiale
    3. Onboarder deux serveurs Windows (SRV01 et SRV02) dans Azure Arc en créant un Resource Group `rg-hybrid-infra` et en installant l'agent Connected Machine
    4. Déployer l'extension Log Analytics sur les serveurs Arc pour collecter les événements Windows et les métriques de performance
    5. Créer un Storage Account avec un File Share nommé `company-data`, puis déployer Azure File Sync sur SRV01 pour synchroniser le dossier `C:\SharedData` avec le cloud, en activant le Cloud Tiering avec une politique de 20% d'espace libre
    6. Tester l'infrastructure : vérifier que les utilisateurs synchronisés peuvent se connecter au portail Azure, que les serveurs Arc remontent leurs métriques dans Log Analytics, et que les fichiers ajoutés localement apparaissent dans Azure Files

    **Critères de validation** :

    - [ ] Le domaine personnalisé `corp.com` est vérifié dans Azure AD avec le statut "Verified"
    - [ ] Azure AD Connect est installé et `Get-ADSyncScheduler` montre que la synchronisation est active
    - [ ] Les utilisateurs de l'OU CloudUsers apparaissent dans Azure AD avec le suffixe UPN `@corp.com`
    - [ ] Les deux serveurs sont visibles dans Azure Arc : `az connectedmachine list` montre leur statut "Connected"
    - [ ] Les extensions Log Analytics sont installées et les logs Windows Events apparaissent dans Log Analytics Workspace
    - [ ] Azure File Sync est opérationnel : `Get-StorageSyncServer` montre le serveur enregistré et les fichiers se synchronisent vers Azure
    - [ ] Le Cloud Tiering fonctionne : les fichiers anciens deviennent des "reparse points" et sont rappelés à la demande

??? quote "Solution"
    **Étape 1 : Configuration Azure AD et domaine personnalisé**

    ```powershell
    # Installer Azure CLI et se connecter
    winget install Microsoft.AzureCLI

    # Se connecter à Azure
    az login

    # Installer le module Az PowerShell
    Install-Module -Name Az -AllowClobber -Force
    Connect-AzAccount

    # Vérifier le tenant Azure AD
    $tenant = Get-AzTenant
    Write-Host "Tenant ID : $($tenant.Id)"
    Write-Host "Domain : $($tenant.DefaultDomain)"

    # Ajouter un domaine personnalisé dans Azure AD
    # IMPORTANT : Cette étape doit être faite via le portail Azure
    # Azure Portal → Azure Active Directory → Custom domain names → Add custom domain

    # 1. Ajouter "corp.com"
    # 2. Azure fournira un enregistrement TXT DNS à créer
    # 3. Créer l'enregistrement TXT dans votre DNS :
    #    MS=ms12345678 (valeur fournie par Azure)

    # Vérifier le domaine avec PowerShell
    Install-Module -Name AzureAD -Force
    Connect-AzureAD

    # Lister les domaines
    Get-AzureADDomain

    # Le domaine corp.com devrait apparaître avec IsVerified = True

    # Définir corp.com comme domaine par défaut
    Set-AzureADDomain -Name "corp.com" -IsDefault $true
    ```

    **Étape 2 : Installation et configuration Azure AD Connect**

    ```powershell
    # Sur un serveur dédié (AADC01 recommandé)
    # Prérequis :
    # - Windows Server 2016 ou plus récent
    # - .NET Framework 4.7.1+
    # - Compte Enterprise Admin ou Domain Admin
    # - Global Administrator dans Azure AD

    # Télécharger Azure AD Connect
    $downloadUrl = "https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
    $installerPath = "$env:TEMP\AzureADConnect.msi"

    Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath

    # Lancer l'installation (GUI recommandée pour la première fois)
    Start-Process msiexec.exe -ArgumentList "/i $installerPath" -Wait

    # L'assistant guidera à travers :
    # 1. Express Settings ou Custom
    # 2. Choisir "Custom" pour plus de contrôle
    # 3. Sign-in method : Password Hash Synchronization
    # 4. Cocher "Enable single sign-on"
    # 5. Connect to Azure AD (Global Admin credentials)
    # 6. Connect to AD DS (Enterprise Admin credentials)
    # 7. Azure AD sign-in : Sélectionner corp.com
    # 8. Domain/OU filtering : Cocher "Sync selected domains and OUs"
    #    - Décocher "Sync all domains and OUs"
    #    - Cocher uniquement "OU=CloudUsers,DC=corp,DC=local"
    # 9. Uniquely identifying users : objectGUID
    # 10. Optional features : Enable "Password hash synchronization"
    # 11. Enable single sign-on : Fournir les credentials Domain Admin

    # Après l'installation, vérifier
    Import-Module ADSync

    # Vérifier le scheduler
    Get-ADSyncScheduler

    # Devrait afficher :
    # SyncCycleEnabled : True
    # NextSyncCyclePolicyType : Delta
    # NextSyncCycleStartTimeInUTC : (prochaine sync)

    # Vérifier les connecteurs
    Get-ADSyncConnector | Select-Object Name, Type, ConnectivityStatus

    # Forcer une synchronisation initiale
    Start-ADSyncSyncCycle -PolicyType Initial

    # Surveiller la progression
    Get-ADSyncConnectorRunStatus

    # Attendre la fin (peut prendre plusieurs minutes)
    do {
        Start-Sleep -Seconds 10
        $status = Get-ADSyncConnectorRunStatus
        Write-Host "Status : $($status.RunState)"
    } while ($status.RunState -ne "Idle")

    Write-Host "Synchronisation terminée!" -ForegroundColor Green

    # Vérifier les erreurs
    $errors = Get-ADSyncRunStepResult | Where-Object { $_.Result -ne "Success" }
    if ($errors) {
        Write-Host "Erreurs détectées :" -ForegroundColor Red
        $errors | Format-Table -AutoSize
    }
    ```

    **Configuration du filtrage OU**

    ```powershell
    # Si besoin de modifier le filtrage après installation

    # Créer l'OU dans AD si elle n'existe pas
    New-ADOrganizationalUnit -Name "CloudUsers" -Path "DC=corp,DC=local"

    # Créer des utilisateurs de test
    1..5 | ForEach-Object {
        $username = "clouduser$_"
        New-ADUser -Name "Cloud User $_" `
            -SamAccountName $username `
            -UserPrincipalName "$username@corp.com" `
            -Path "OU=CloudUsers,DC=corp,DC=local" `
            -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) `
            -Enabled $true `
            -PasswordNeverExpires $true
    }

    # Via l'interface Azure AD Connect
    # Ou via PowerShell (avancé)
    $connector = Get-ADSyncConnector | Where-Object { $_.Type -eq "AD" }

    # Reconfigurer (nécessite de relancer l'assistant)
    # Start-Process "C:\Program Files\Microsoft Azure Active Directory Connect\AzureADConnect.exe"
    ```

    **Vérifier la synchronisation dans Azure AD**

    ```powershell
    # Se connecter à Azure AD
    Connect-AzureAD

    # Lister les utilisateurs synchronisés
    Get-AzureADUser -Filter "dirSyncEnabled eq true" |
        Select-Object DisplayName, UserPrincipalName, DirSyncEnabled |
        Format-Table -AutoSize

    # Vérifier un utilisateur spécifique
    Get-AzureADUser -Filter "startswith(userPrincipalName,'clouduser1')" |
        Select-Object DisplayName, UserPrincipalName, OnPremisesSecurityIdentifier, DirSyncEnabled

    # Si DirSyncEnabled = True, l'utilisateur est synchronisé depuis on-prem
    ```

    **Étape 3 : Onboarding Azure Arc**

    ```powershell
    # Créer le Resource Group
    az group create --name rg-hybrid-infra --location westeurope

    # Télécharger le script d'installation Arc depuis le portail
    # Azure Portal → Azure Arc → Servers → Add servers → Generate script

    # Ou installation manuelle :

    # Sur SRV01 et SRV02
    $servers = @("SRV01", "SRV02")

    foreach ($server in $servers) {
        Invoke-Command -ComputerName $server -ScriptBlock {
            # Variables (remplacer par vos valeurs)
            $subscriptionId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            $resourceGroup = "rg-hybrid-infra"
            $location = "westeurope"
            $tenantId = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

            # Télécharger l'agent
            $agentUrl = "https://aka.ms/AzureConnectedMachineAgent"
            $installerPath = "$env:TEMP\AzureConnectedMachineAgent.msi"

            Invoke-WebRequest -Uri $agentUrl -OutFile $installerPath

            # Installer l'agent
            Start-Process msiexec.exe -ArgumentList "/i $installerPath /quiet /norestart" -Wait

            # Attendre que l'installation se termine
            Start-Sleep -Seconds 10

            # Se connecter à Azure Arc
            & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" connect `
                --resource-group $resourceGroup `
                --tenant-id $tenantId `
                --location $location `
                --subscription-id $subscriptionId `
                --cloud "AzureCloud" `
                --correlation-id (New-Guid).Guid

            # Vérifier la connexion
            & "$env:ProgramW6432\AzureConnectedMachineAgent\azcmagent.exe" show
        }
    }

    # Vérifier depuis Azure
    az connectedmachine list --resource-group rg-hybrid-infra --output table

    # Via PowerShell Az
    Get-AzConnectedMachine -ResourceGroupName "rg-hybrid-infra" |
        Select-Object Name, Status, Location, OsName, OsVersion |
        Format-Table -AutoSize
    ```

    **Étape 4 : Déployer l'extension Log Analytics**

    ```powershell
    # Créer un Log Analytics Workspace
    $workspaceName = "law-hybrid-monitoring"
    $location = "westeurope"
    $resourceGroup = "rg-hybrid-infra"

    az monitor log-analytics workspace create `
        --resource-group $resourceGroup `
        --workspace-name $workspaceName `
        --location $location

    # Obtenir le Workspace ID et Key
    $workspaceId = az monitor log-analytics workspace show `
        --resource-group $resourceGroup `
        --workspace-name $workspaceName `
        --query customerId `
        --output tsv

    $workspaceKey = az monitor log-analytics workspace get-shared-keys `
        --resource-group $resourceGroup `
        --workspace-name $workspaceName `
        --query primarySharedKey `
        --output tsv

    Write-Host "Workspace ID: $workspaceId"

    # Installer l'extension Log Analytics sur les serveurs Arc
    $servers = @("SRV01", "SRV02")

    foreach ($server in $servers) {
        az connectedmachine extension create `
            --machine-name $server `
            --resource-group $resourceGroup `
            --name "MicrosoftMonitoringAgent" `
            --type "MicrosoftMonitoringAgent" `
            --publisher "Microsoft.EnterpriseCloud.Monitoring" `
            --settings "{`"workspaceId`":`"$workspaceId`"}" `
            --protected-settings "{`"workspaceKey`":`"$workspaceKey`"}" `
            --location $location

        Write-Host "Extension installée sur $server" -ForegroundColor Green
    }

    # Vérifier les extensions
    az connectedmachine extension list `
        --machine-name "SRV01" `
        --resource-group $resourceGroup `
        --output table

    # Attendre quelques minutes puis vérifier les données dans Log Analytics
    # Azure Portal → Log Analytics Workspace → Logs
    # Requête KQL :
    # Heartbeat
    # | where Computer contains "SRV"
    # | summarize LastHeartbeat=max(TimeGenerated) by Computer
    # | order by LastHeartbeat desc
    ```

    **Configuration de la collecte de données**

    ```powershell
    # Configurer la collecte des événements Windows
    # Via le portail Azure :
    # Log Analytics Workspace → Agents configuration → Windows event logs

    # Ajouter :
    # - Application : Error, Warning
    # - System : Error, Warning
    # - Security : Audit Success, Audit Failure

    # Via Azure CLI
    $datasourceConfig = @{
        eventLogName = "Application"
        eventTypes = @(
            @{ eventType = "Error" }
            @{ eventType = "Warning" }
        )
    }

    # Configurer aussi les compteurs de performance
    # - Processor(_Total)\% Processor Time
    # - Memory\Available MBytes
    # - LogicalDisk(_Total)\% Free Space
    ```

    **Étape 5 : Déployer Azure File Sync**

    ```powershell
    # Créer un Storage Account
    $storageAccountName = "stgsynccorpdata001"  # Doit être unique globalement
    $location = "westeurope"
    $resourceGroup = "rg-hybrid-infra"

    az storage account create `
        --name $storageAccountName `
        --resource-group $resourceGroup `
        --location $location `
        --sku Standard_LRS `
        --kind StorageV2 `
        --https-only true

    # Créer un File Share
    $shareName = "company-data"

    az storage share create `
        --name $shareName `
        --account-name $storageAccountName `
        --quota 1024

    # Créer le Storage Sync Service
    $syncServiceName = "StorageSyncService-Corp"

    az resource create `
        --resource-group $resourceGroup `
        --name $syncServiceName `
        --resource-type "Microsoft.StorageSync/storageSyncServices" `
        --location $location

    # Télécharger et installer l'agent Azure File Sync sur SRV01
    Invoke-Command -ComputerName "SRV01" -ScriptBlock {
        # Télécharger l'agent
        $agentUrl = "https://aka.ms/afs/agent"
        $installerPath = "$env:TEMP\StorageSyncAgent.msi"

        Invoke-WebRequest -Uri $agentUrl -OutFile $installerPath

        # Installer
        Start-Process msiexec.exe -ArgumentList "/i $installerPath /quiet /norestart" -Wait

        # Redémarrer (si nécessaire)
        # Restart-Computer -Force
    }

    # Enregistrer le serveur dans Storage Sync Service
    # Cette étape ouvre une fenêtre de navigateur pour l'authentification
    Invoke-Command -ComputerName "SRV01" -ScriptBlock {
        Import-Module "C:\Program Files\Azure\StorageSyncAgent\StorageSync.Management.PowerShell.Cmdlets.dll"

        # Enregistrement (interactive)
        Register-AzStorageSyncServer `
            -ResourceGroupName "rg-hybrid-infra" `
            -StorageSyncServiceName "StorageSyncService-Corp"
    }

    # Créer un Sync Group
    $syncGroupName = "SyncGroup-SharedData"

    New-AzStorageSyncGroup `
        -ResourceGroupName $resourceGroup `
        -StorageSyncServiceName $syncServiceName `
        -SyncGroupName $syncGroupName

    # Ajouter le Cloud Endpoint (Azure File Share)
    $storageAccount = Get-AzStorageAccount `
        -ResourceGroupName $resourceGroup `
        -Name $storageAccountName

    New-AzStorageSyncCloudEndpoint `
        -ResourceGroupName $resourceGroup `
        -StorageSyncServiceName $syncServiceName `
        -SyncGroupName $syncGroupName `
        -StorageAccountResourceId $storageAccount.Id `
        -AzureFileShareName $shareName

    # Créer le dossier local sur SRV01
    Invoke-Command -ComputerName "SRV01" -ScriptBlock {
        New-Item -Path "C:\SharedData" -ItemType Directory -Force

        # Ajouter des fichiers de test
        1..10 | ForEach-Object {
            $content = "Fichier de test $_`n" + ("x" * 1MB)
            $content | Out-File "C:\SharedData\file$_.txt"
        }
    }

    # Ajouter le Server Endpoint
    $server = Get-AzStorageSyncServer `
        -ResourceGroupName $resourceGroup `
        -StorageSyncServiceName $syncServiceName

    New-AzStorageSyncServerEndpoint `
        -ResourceGroupName $resourceGroup `
        -StorageSyncServiceName $syncServiceName `
        -SyncGroupName $syncGroupName `
        -ServerId $server.ResourceId `
        -ServerLocalPath "C:\SharedData" `
        -CloudTiering `
        -VolumeFreeSpacePercent 20 `
        -TierFilesOlderThanDays 30

    # Vérifier l'état de la synchronisation
    Get-AzStorageSyncServerEndpoint `
        -ResourceGroupName $resourceGroup `
        -StorageSyncServiceName $syncServiceName `
        -SyncGroupName $syncGroupName |
        Select-Object ServerLocalPath, CloudTiering, SyncStatus, HealthState |
        Format-List
    ```

    **Étape 6 : Tests et validation**

    ```powershell
    # ===== TEST 1 : Synchronisation Azure AD =====

    Write-Host "`n=== TEST 1 : Azure AD Sync ===" -ForegroundColor Cyan

    # Forcer une sync
    Start-ADSyncSyncCycle -PolicyType Delta

    # Attendre
    Start-Sleep -Seconds 30

    # Vérifier dans Azure AD
    Connect-AzureAD

    $syncedUsers = Get-AzureADUser -Filter "dirSyncEnabled eq true"
    Write-Host "Utilisateurs synchronisés : $($syncedUsers.Count)" -ForegroundColor Green

    $syncedUsers | Select-Object DisplayName, UserPrincipalName |
        Format-Table -AutoSize

    # Tester le SSO (depuis un poste joint au domaine)
    # Ouvrir https://portal.azure.com
    # L'utilisateur devrait être connecté automatiquement sans saisir de mot de passe

    # ===== TEST 2 : Azure Arc =====

    Write-Host "`n=== TEST 2 : Azure Arc ===" -ForegroundColor Cyan

    # Lister les serveurs connectés
    $arcServers = Get-AzConnectedMachine -ResourceGroupName "rg-hybrid-infra"

    Write-Host "Serveurs Arc connectés : $($arcServers.Count)" -ForegroundColor Green

    $arcServers | Format-Table Name, Status, ProvisioningState -AutoSize

    # Vérifier les extensions
    Get-AzConnectedMachineExtension `
        -ResourceGroupName "rg-hybrid-infra" `
        -MachineName "SRV01" |
        Select-Object Name, ProvisioningState, TypeHandlerVersion |
        Format-Table -AutoSize

    # ===== TEST 3 : Log Analytics =====

    Write-Host "`n=== TEST 3 : Log Analytics ===" -ForegroundColor Cyan

    # Requête KQL via PowerShell
    $workspaceId = az monitor log-analytics workspace show `
        --resource-group "rg-hybrid-infra" `
        --workspace-name "law-hybrid-monitoring" `
        --query customerId `
        --output tsv

    # Installer le module Az.OperationalInsights
    Install-Module -Name Az.OperationalInsights -Force

    # Exemple de requête
    $query = @"
    Heartbeat
    | where Computer contains "SRV"
    | summarize LastHeartbeat=max(TimeGenerated) by Computer
    | order by LastHeartbeat desc
"@

    $queryResult = Invoke-AzOperationalInsightsQuery `
        -WorkspaceId $workspaceId `
        -Query $query

    if ($queryResult.Results.Count -gt 0) {
        Write-Host "Logs reçus pour $($queryResult.Results.Count) serveurs" -ForegroundColor Green
        $queryResult.Results | Format-Table -AutoSize
    } else {
        Write-Host "Aucun log reçu (attendre quelques minutes)" -ForegroundColor Yellow
    }

    # ===== TEST 4 : Azure File Sync =====

    Write-Host "`n=== TEST 4 : Azure File Sync ===" -ForegroundColor Cyan

    # Vérifier les fichiers dans Azure
    $storageContext = New-AzStorageContext `
        -StorageAccountName $storageAccountName `
        -UseConnectedAccount

    $files = Get-AzStorageFile `
        -Context $storageContext `
        -ShareName "company-data" |
        Get-AzStorageFile

    Write-Host "Fichiers synchronisés dans Azure : $($files.Count)" -ForegroundColor Green

    # Tester le Cloud Tiering
    Invoke-Command -ComputerName "SRV01" -ScriptBlock {
        # Vérifier les reparse points (fichiers tiered)
        $tieredFiles = Get-ChildItem "C:\SharedData" |
            Where-Object { $_.Attributes -match "ReparsePoint" }

        Write-Host "Fichiers tiered (dans le cloud) : $($tieredFiles.Count)"

        # Accéder à un fichier tiered provoque son rappel (recall)
        if ($tieredFiles.Count -gt 0) {
            $content = Get-Content $tieredFiles[0].FullName
            Write-Host "Fichier rappelé depuis Azure" -ForegroundColor Green
        }
    }

    # ===== RAPPORT FINAL =====

    Write-Host "`n=== RAPPORT D'INFRASTRUCTURE HYBRIDE ===" -ForegroundColor Cyan

    $report = [PSCustomObject]@{
        "Azure AD Sync" = if ($syncedUsers.Count -gt 0) { "✓ OK ($($syncedUsers.Count) users)" } else { "✗ Échec" }
        "Azure Arc Servers" = if ($arcServers.Count -eq 2) { "✓ OK (2/2 serveurs)" } else { "✗ $($arcServers.Count)/2" }
        "Log Analytics" = if ($queryResult.Results.Count -gt 0) { "✓ OK (logs reçus)" } else { "⚠ En attente" }
        "Azure File Sync" = if ($files.Count -gt 0) { "✓ OK ($($files.Count) fichiers)" } else { "✗ Échec" }
    }

    $report | Format-List
    ```

    **Script de monitoring continu**

    ```powershell
    # Monitor-HybridInfra.ps1
    # Exécuter régulièrement pour surveiller l'infrastructure hybride

    param(
        [string]$ResourceGroup = "rg-hybrid-infra"
    )

    function Get-AADSyncStatus {
        Import-Module ADSync -ErrorAction SilentlyContinue
        $scheduler = Get-ADSyncScheduler
        return [PSCustomObject]@{
            Enabled = $scheduler.SyncCycleEnabled
            LastSync = $scheduler.LastSyncCycleStartTimeInUTC
            NextSync = $scheduler.NextSyncCycleStartTimeInUTC
        }
    }

    function Get-ArcServersStatus {
        $servers = Get-AzConnectedMachine -ResourceGroupName $ResourceGroup
        return $servers | Select-Object Name, Status, LastStatusChange
    }

    function Get-FileSyncStatus {
        $syncService = Get-AzStorageSyncService -ResourceGroupName $ResourceGroup
        $syncGroups = Get-AzStorageSyncGroup -ParentObject $syncService
        return $syncGroups | Select-Object SyncGroupName, SyncStatus
    }

    Write-Host "=== MONITORING INFRASTRUCTURE HYBRIDE ===" -ForegroundColor Cyan
    Write-Host "Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

    Write-Host "Azure AD Sync :" -ForegroundColor Yellow
    Get-AADSyncStatus | Format-List

    Write-Host "`nServeurs Azure Arc :" -ForegroundColor Yellow
    Get-ArcServersStatus | Format-Table -AutoSize

    Write-Host "`nAzure File Sync :" -ForegroundColor Yellow
    Get-FileSyncStatus | Format-Table -AutoSize
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
