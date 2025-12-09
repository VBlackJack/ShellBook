---
tags:
  - formation
  - windows-server
  - ha
  - clustering
  - failover
---

# Module 16 : Haute Disponibilité

## Objectifs du Module

Ce module couvre les architectures haute disponibilité Windows Server :

- Comprendre les concepts de haute disponibilité
- Déployer un Failover Cluster
- Configurer Network Load Balancing (NLB)
- Implémenter Storage Spaces Direct
- Configurer SQL Server Always On

**Durée :** 9 heures

**Niveau :** Expert

---

## 1. Concepts de Haute Disponibilité

### 1.1 Terminologie

```text
CONCEPTS HA
───────────

Availability (Disponibilité)
• 99.9%   = 8.76 heures downtime/an
• 99.99%  = 52.56 minutes downtime/an
• 99.999% = 5.26 minutes downtime/an

Failover     - Basculement vers noeud secondaire
Failback     - Retour vers noeud primaire
Quorum       - Mécanisme de vote pour éviter split-brain
Heartbeat    - Signal de vie entre noeuds
Witness      - Arbitre pour le quorum

TYPES DE HA
───────────
• Active/Passive - Un noeud actif, un en attente
• Active/Active  - Tous les noeuds traitent du trafic
• N+1            - N noeuds actifs + 1 spare
```

### 1.2 Technologies Windows

| Technologie | Usage | Type |
|------------|-------|------|
| Failover Clustering | Workloads critiques | Active/Passive |
| NLB | Load balancing web | Active/Active |
| Storage Spaces Direct | Stockage hyperconvergé | Active/Active |
| SQL Always On | Bases de données | Active/Passive + Read |

---

## 2. Failover Clustering

### 2.1 Prérequis

```powershell
# Prérequis:
# - 2+ serveurs avec même config hardware
# - Stockage partagé (SAN, S2D) ou File Share Witness
# - Réseau redondant
# - Même domaine AD

# Installer la feature sur tous les noeuds
Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools

# Valider la configuration
Test-Cluster -Node "NODE1", "NODE2" -Include "Storage","Network","System Configuration"
```

### 2.2 Création du Cluster

```powershell
# Créer le cluster
New-Cluster -Name "CLUSTER01" `
            -Node "NODE1", "NODE2" `
            -StaticAddress "192.168.1.100" `
            -NoStorage

# Configurer le quorum (File Share Witness recommandé)
Set-ClusterQuorum -FileShareWitness "\\FileServer\ClusterWitness"

# Ou Cloud Witness (Azure)
Set-ClusterQuorum -CloudWitness `
    -AccountName "mystorageaccount" `
    -AccessKey "xxxxx"

# Vérifier le cluster
Get-Cluster
Get-ClusterNode
Get-ClusterQuorum
```

### 2.3 Ajouter des Rôles Cluster

```powershell
# File Server Role
Add-ClusterFileServerRole -Name "CLUSTFS" `
    -Storage "Cluster Disk 1" `
    -StaticAddress "192.168.1.101"

# Ajouter un partage
New-SmbShare -Name "Data" `
    -Path "C:\ClusterStorage\Volume1\Data" `
    -FullAccess "Everyone"

# Generic Service (exemple: service personnalisé)
Add-ClusterGenericServiceRole -Name "MyService" `
    -ServiceName "MyWindowsService" `
    -StaticAddress "192.168.1.102"

# Hyper-V VM Role
Add-ClusterVirtualMachineRole -VMName "VM01"
```

### 2.4 Gestion du Cluster

```powershell
# Déplacer un rôle
Move-ClusterGroup -Name "CLUSTFS" -Node "NODE2"

# Simuler une panne
Stop-ClusterNode -Name "NODE1" -Drain

# Mettre en maintenance
Suspend-ClusterNode -Name "NODE1" -Drain

# Reprendre
Resume-ClusterNode -Name "NODE1"

# Vérifier l'état
Get-ClusterGroup
Get-ClusterResource
```

---

## 3. Network Load Balancing (NLB)

### 3.1 Installation

```powershell
# Installer NLB
Install-WindowsFeature -Name NLB -IncludeManagementTools

# Sur tous les noeuds
```

### 3.2 Configuration

```powershell
# Créer le cluster NLB
New-NlbCluster -InterfaceName "Ethernet" `
               -ClusterName "WEBLB" `
               -ClusterPrimaryIP "192.168.1.200" `
               -SubnetMask "255.255.255.0" `
               -OperationMode Multicast

# Ajouter un noeud
Add-NlbClusterNode -InterfaceName "Ethernet" `
                   -NewNodeName "WEB02" `
                   -NewNodeInterface "Ethernet"

# Configurer une règle de port
Add-NlbClusterPortRule -InterfaceName "Ethernet" `
                       -StartPort 80 `
                       -EndPort 80 `
                       -Protocol TCP `
                       -Affinity Single

# Vérifier
Get-NlbCluster
Get-NlbClusterNode
```

---

## 4. Storage Spaces Direct (S2D)

### 4.1 Prérequis

```powershell
# Minimum 2 noeuds (recommandé 4+)
# Disques locaux (SSD/NVMe + HDD pour tiering)
# Réseau 10 GbE minimum

# Installer les features
Install-WindowsFeature -Name Failover-Clustering, FS-FileServer -IncludeManagementTools
```

### 4.2 Configuration

```powershell
# Créer le cluster
New-Cluster -Name "S2DCLUSTER" -Node "S2D01", "S2D02", "S2D03", "S2D04"

# Activer S2D
Enable-ClusterStorageSpacesDirect -CacheState Enabled

# Vérifier les pools
Get-StoragePool

# Créer un volume
New-Volume -FriendlyName "Volume01" `
           -FileSystem CSVFS_ReFS `
           -StoragePoolFriendlyName "S2D*" `
           -Size 1TB `
           -ResiliencySettingName Mirror

# Vérifier
Get-VirtualDisk
Get-ClusterSharedVolume
```

---

## 5. SQL Server Always On

### 5.1 Configuration de Base

```powershell
# Prérequis: Cluster Windows existant

# Activer Always On sur chaque instance SQL
Enable-SqlAlwaysOn -ServerInstance "SQL01" -Force
Enable-SqlAlwaysOn -ServerInstance "SQL02" -Force

# Créer le endpoint de mirroring
$endpoint = New-SqlHadrEndpoint -Path "SQLSERVER:\SQL\SQL01\Default" `
    -Name "Hadr_endpoint" `
    -Port 5022 `
    -EncryptionAlgorithm Aes

# Démarrer l'endpoint
Set-SqlHadrEndpoint -InputObject $endpoint -State Started

# Créer le groupe de disponibilité
New-SqlAvailabilityGroup -Name "AG01" `
    -Path "SQLSERVER:\SQL\SQL01\Default" `
    -AvailabilityReplica @(
        New-SqlAvailabilityReplica -Name "SQL01" -EndpointUrl "TCP://SQL01:5022" -AvailabilityMode SynchronousCommit -FailoverMode Automatic -AsTemplate
        New-SqlAvailabilityReplica -Name "SQL02" -EndpointUrl "TCP://SQL02:5022" -AvailabilityMode SynchronousCommit -FailoverMode Automatic -AsTemplate
    ) `
    -Database "MyDatabase"
```

---

## 6. Exercice Pratique

### Créer un Cluster File Server

```powershell
# Sur NODE1 et NODE2
Install-WindowsFeature -Name Failover-Clustering, FS-FileServer -IncludeManagementTools

# Valider
Test-Cluster -Node "NODE1", "NODE2"

# Créer le cluster
New-Cluster -Name "FSCLUSTER" -Node "NODE1", "NODE2" -StaticAddress "192.168.1.50"

# Configurer le quorum
Set-ClusterQuorum -FileShareWitness "\\DC01\ClusterWitness"

# Ajouter le disque partagé (si SAN)
Get-ClusterAvailableDisk | Add-ClusterDisk

# Ajouter le rôle File Server
Add-ClusterFileServerRole -Name "CLUSTERFS" `
    -Storage "Cluster Disk 1" `
    -StaticAddress "192.168.1.51"

# Créer le partage
New-Item -Path "C:\ClusterStorage\Volume1\Data" -ItemType Directory
New-SmbShare -Name "Data" -Path "C:\ClusterStorage\Volume1\Data" -FullAccess "Domain Users"

# Tester le failover
Move-ClusterGroup -Name "CLUSTERFS" -Node "NODE2"
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer un cluster Failover Cluster à deux nœuds avec un rôle File Server et tester les scénarios de basculement

    **Contexte** : Votre entreprise nécessite une solution de haute disponibilité pour le stockage de fichiers critiques. Vous devez mettre en place un cluster de serveurs de fichiers qui garantit une disponibilité continue même en cas de défaillance d'un nœud. Le cluster doit utiliser un File Share Witness pour le quorum et supporter le basculement automatique et manuel.

    **Tâches à réaliser** :

    1. Installer la feature Failover Clustering sur NODE1 (192.168.1.10) et NODE2 (192.168.1.11), puis valider la configuration matérielle et réseau avec `Test-Cluster`
    2. Créer un cluster nommé "PRODCLUSTER" avec une IP statique 192.168.1.50, et configurer le quorum en mode File Share Witness pointant vers `\\DC01\ClusterWitness`
    3. Ajouter un disque partagé au cluster (simulé avec iSCSI ou stockage SAN), formater en ReFS, et le rendre disponible comme ressource de cluster
    4. Déployer un rôle File Server haute disponibilité nommé "HAFILESERVER" avec l'IP 192.168.1.51, utilisant le disque partagé, et créer un partage "CriticalData"
    5. Configurer une stratégie de basculement avec un seuil de 3 pannes en 6 heures avant de mettre le rôle en mode quarantaine
    6. Tester trois scénarios : failover automatique (arrêt d'un nœud), failover manuel avec `Move-ClusterGroup`, et failback vers le nœud préféré, en mesurant le temps d'indisponibilité pour chaque scénario

    **Critères de validation** :

    - [ ] `Test-Cluster` se termine sans erreurs critiques (warnings acceptables)
    - [ ] Le cluster est créé et les deux nœuds apparaissent dans `Get-ClusterNode` avec l'état "Up"
    - [ ] Le quorum est configuré correctement : `Get-ClusterQuorum` montre "Node and File Share Majority"
    - [ ] Le rôle File Server est en ligne sur un des nœuds et le partage `\\HAFILESERVER\CriticalData` est accessible
    - [ ] Un fichier créé dans le partage reste accessible après un basculement (failover)
    - [ ] Le temps d'indisponibilité lors d'un failover automatique est inférieur à 30 secondes
    - [ ] Les événements de failover sont correctement enregistrés dans l'Event Viewer (Event ID 1069, 1205, 1206)

??? quote "Solution"
    **Étape 1 : Installation et validation du cluster**

    ```powershell
    # Sur NODE1 et NODE2 : Installer Failover Clustering
    Invoke-Command -ComputerName "NODE1", "NODE2" -ScriptBlock {
        Install-WindowsFeature -Name Failover-Clustering `
            -IncludeManagementTools `
            -IncludeAllSubFeature
    }

    # Vérifier l'installation
    Invoke-Command -ComputerName "NODE1", "NODE2" -ScriptBlock {
        Get-WindowsFeature -Name Failover-Clustering
    }

    # Validation complète du cluster (depuis NODE1 ou un poste d'administration)
    # IMPORTANT : Cette commande peut prendre 10-15 minutes
    Test-Cluster -Node "NODE1", "NODE2" `
        -Include "Storage", "Network", "System Configuration", "Inventory" `
        -ReportName "C:\ClusterValidation\Report.html"

    # Analyser le rapport
    # Des warnings sont acceptables, mais pas d'erreurs critiques
    # Ouvrir le rapport HTML pour les détails
    Invoke-Item "C:\ClusterValidation\Report.html"

    # Validation rapide (sans stockage si pas encore configuré)
    Test-Cluster -Node "NODE1", "NODE2" `
        -Include "Network", "System Configuration" `
        -Ignore Storage
    ```

    **Étape 2 : Création du cluster et configuration du quorum**

    ```powershell
    # Créer le cluster sans ajouter de stockage immédiatement
    New-Cluster -Name "PRODCLUSTER" `
        -Node "NODE1", "NODE2" `
        -StaticAddress "192.168.1.50" `
        -NoStorage

    # Vérifier la création
    Get-Cluster | Select-Object Name, Domain

    Get-ClusterNode | Select-Object Name, State, NodeWeight

    # Créer le partage témoin sur DC01
    Invoke-Command -ComputerName "DC01" -ScriptBlock {
        New-Item -Path "C:\ClusterWitness" -ItemType Directory -Force
        New-SmbShare -Name "ClusterWitness" `
            -Path "C:\ClusterWitness" `
            -FullAccess "CORP\PRODCLUSTER$", "CORP\NODE1$", "CORP\NODE2$"

        # Permissions NTFS
        $acl = Get-Acl "C:\ClusterWitness"
        $permission = "CORP\PRODCLUSTER$", "FullControl", "ContainerInherit, ObjectInherit", "None", "Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.SetAccessRule($accessRule)
        Set-Acl "C:\ClusterWitness" $acl
    }

    # Configurer le File Share Witness
    Set-ClusterQuorum -FileShareWitness "\\DC01\ClusterWitness"

    # Vérifier le quorum
    Get-ClusterQuorum | Format-List

    # Devrait afficher : QuorumResource : File Share Witness
    # QuorumType : NodeAndFileShareMajority

    # Vérifier les votes
    Get-ClusterNode | Select-Object Name, NodeWeight, State
    ```

    **Étape 3 : Configuration du stockage partagé**

    ```powershell
    # Scénario A : Avec un SAN ou iSCSI existant
    # Les disques partagés doivent être visibles sur les deux nœuds

    # Identifier les disques disponibles
    Get-ClusterAvailableDisk

    # Ajouter le disque au cluster
    Get-ClusterAvailableDisk | Add-ClusterDisk

    # Vérifier les disques du cluster
    Get-ClusterResource | Where-Object ResourceType -eq "Physical Disk"

    # Renommer le disque
    Get-ClusterResource "Cluster Disk 1" |
        Set-ClusterParameter -Name "Name" -Value "DataDisk01"

    # Scénario B : Simulation avec un disque local (pour tests uniquement)
    # ATTENTION : Ceci n'est PAS pour la production, juste pour démonstration

    # Sur NODE1 : Créer un VHD simulé
    New-VHD -Path "C:\ClusterStorage\SharedDisk.vhdx" -SizeBytes 10GB -Dynamic

    # Monter et formater
    $disk = Mount-VHD -Path "C:\ClusterStorage\SharedDisk.vhdx" -Passthru
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
    Format-Volume -DriveLetter $partition.DriveLetter `
        -FileSystem ReFS `
        -NewFileSystemLabel "ClusterData" `
        -AllocationUnitSize 65536

    # Pour production : Utiliser un disque SAN ou iSCSI partagé

    # Formater en ReFS avec le bon cluster size
    Get-ClusterSharedVolume | Format-Volume `
        -FileSystem ReFS `
        -AllocationUnitSize 65536 `
        -Confirm:$false

    # Vérifier les volumes
    Get-ClusterSharedVolume | Select-Object Name, State, OwnerNode
    ```

    **Étape 4 : Déploiement du rôle File Server**

    ```powershell
    # Créer le rôle File Server
    Add-ClusterFileServerRole -Name "HAFILESERVER" `
        -Storage "Cluster Disk 1" `
        -StaticAddress "192.168.1.51" `
        -Verbose

    # Vérifier le rôle
    Get-ClusterGroup -Name "HAFILESERVER" | Format-List
    Get-ClusterResource | Where-Object OwnerGroup -eq "HAFILESERVER"

    # Créer le répertoire pour le partage
    $clusterStoragePath = "C:\ClusterStorage\Volume1\CriticalData"
    Invoke-Command -ComputerName (Get-ClusterGroup "HAFILESERVER").OwnerNode.Name -ScriptBlock {
        param($path)
        New-Item -Path $path -ItemType Directory -Force
    } -ArgumentList $clusterStoragePath

    # Créer le partage SMB haute disponibilité
    New-SmbShare -Name "CriticalData" `
        -Path $clusterStoragePath `
        -FullAccess "Domain Admins" `
        -ChangeAccess "Domain Users" `
        -ContinuouslyAvailable $true `
        -Description "Partage hautement disponible pour données critiques"

    # Configurer les permissions NTFS
    $acl = Get-Acl $clusterStoragePath
    $permission = "CORP\Domain Users", "Modify", "ContainerInherit, ObjectInherit", "None", "Allow"
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
    $acl.SetAccessRule($accessRule)
    Set-Acl $clusterStoragePath $acl

    # Vérifier le partage
    Get-SmbShare -Name "CriticalData" | Format-List
    Get-SmbShareAccess -Name "CriticalData"

    # Tester l'accès depuis un poste client
    Test-Path "\\HAFILESERVER\CriticalData"
    "Test file" | Out-File "\\HAFILESERVER\CriticalData\test.txt"
    Get-Content "\\HAFILESERVER\CriticalData\test.txt"
    ```

    **Étape 5 : Configuration de la politique de basculement**

    ```powershell
    # Configurer le groupe de ressources HAFILESERVER
    $group = Get-ClusterGroup -Name "HAFILESERVER"

    # Seuil de basculement : 3 pannes en 6 heures
    $group | Set-ClusterGroup `
        -FailoverThreshold 3 `
        -FailoverPeriod 6

    # Configurer le délai de failback automatique (optionnel)
    # 0 = Pas de failback automatique (recommandé pour contrôler le failback)
    $group | Set-ClusterGroup -AutoFailbackType 0

    # Si vous voulez un failback automatique immédiat
    # $group | Set-ClusterGroup -AutoFailbackType 1

    # Configurer le nœud préféré (optionnel)
    $group | Set-ClusterOwnerNode -Owners "NODE1", "NODE2"

    # Définir NODE1 comme préféré
    $owners = $group | Get-ClusterOwnerNode
    $group | Set-ClusterOwnerNode -Owners @("NODE1") + ($owners | Where-Object {$_ -ne "NODE1"})

    # Vérifier la configuration
    Get-ClusterGroup -Name "HAFILESERVER" | Format-List `
        Name, OwnerNode, State, FailoverThreshold, FailoverPeriod, AutoFailbackType

    # Configurer les timeouts des ressources
    Get-ClusterResource -Name "HAFILESERVER" |
        Set-ClusterParameter -Name PendingTimeout -Value 180

    Get-ClusterResource -Name "File Server" |
        Set-ClusterParameter -Name PendingTimeout -Value 180
    ```

    **Étape 6 : Tests de basculement**

    ```powershell
    # PRÉPARATION DES TESTS

    # Créer un fichier de test
    "Test de haute disponibilité - $(Get-Date)" |
        Out-File "\\HAFILESERVER\CriticalData\ha-test.txt"

    # Identifier le nœud propriétaire actuel
    $currentOwner = (Get-ClusterGroup -Name "HAFILESERVER").OwnerNode.Name
    Write-Host "Nœud actuel : $currentOwner" -ForegroundColor Cyan

    # Script de monitoring en continu (lancer dans une autre fenêtre)
    while ($true) {
        $start = Get-Date
        try {
            $content = Get-Content "\\HAFILESERVER\CriticalData\ha-test.txt" -ErrorAction Stop
            $elapsed = ((Get-Date) - $start).TotalMilliseconds
            Write-Host "$(Get-Date -Format 'HH:mm:ss.fff') - OK ($elapsed ms)" -ForegroundColor Green
        }
        catch {
            Write-Host "$(Get-Date -Format 'HH:mm:ss.fff') - INACCESSIBLE" -ForegroundColor Red
        }
        Start-Sleep -Seconds 1
    }

    # ===== TEST 1 : FAILOVER AUTOMATIQUE =====

    Write-Host "`n=== TEST 1 : Failover Automatique ===" -ForegroundColor Yellow

    # Noter l'heure de début
    $testStart = Get-Date
    Write-Host "Début du test : $testStart"
    Write-Host "Nœud actuel : $currentOwner"

    # Arrêter le service Cluster sur le nœud propriétaire
    Invoke-Command -ComputerName $currentOwner -ScriptBlock {
        Stop-Service -Name ClusSvc -Force
    }

    # Surveiller le basculement
    Write-Host "Attente du basculement automatique..." -ForegroundColor Yellow

    do {
        Start-Sleep -Seconds 2
        $group = Get-ClusterGroup -Name "HAFILESERVER"
        $newOwner = $group.OwnerNode.Name
        $state = $group.State
        Write-Host "  État : $state - Nœud : $newOwner"
    } while ($newOwner -eq $currentOwner)

    $testEnd = Get-Date
    $failoverTime = ($testEnd - $testStart).TotalSeconds

    Write-Host "`nBasculement terminé!" -ForegroundColor Green
    Write-Host "Nouveau nœud : $newOwner"
    Write-Host "Temps de basculement : $failoverTime secondes"

    # Vérifier l'accès au fichier
    $content = Get-Content "\\HAFILESERVER\CriticalData\ha-test.txt"
    Write-Host "Accès au fichier : OK" -ForegroundColor Green

    # Redémarrer le service sur l'ancien nœud
    Invoke-Command -ComputerName $currentOwner -ScriptBlock {
        Start-Service -Name ClusSvc
    }

    # ===== TEST 2 : FAILOVER MANUEL =====

    Start-Sleep -Seconds 5

    Write-Host "`n=== TEST 2 : Failover Manuel ===" -ForegroundColor Yellow

    $currentOwner = (Get-ClusterGroup -Name "HAFILESERVER").OwnerNode.Name
    $targetNode = if ($currentOwner -eq "NODE1") { "NODE2" } else { "NODE1" }

    Write-Host "Déplacement de $currentOwner vers $targetNode"

    $testStart = Get-Date

    # Déplacer le groupe
    Move-ClusterGroup -Name "HAFILESERVER" -Node $targetNode

    $testEnd = Get-Date
    $moveTime = ($testEnd - $testStart).TotalSeconds

    Write-Host "Déplacement terminé en $moveTime secondes" -ForegroundColor Green

    # Vérifier
    $group = Get-ClusterGroup -Name "HAFILESERVER"
    Write-Host "Nouveau propriétaire : $($group.OwnerNode.Name)"
    Write-Host "État : $($group.State)"

    # ===== TEST 3 : FAILBACK =====

    Start-Sleep -Seconds 5

    Write-Host "`n=== TEST 3 : Failback vers nœud préféré ===" -ForegroundColor Yellow

    # Retour vers NODE1
    Move-ClusterGroup -Name "HAFILESERVER" -Node "NODE1"

    $group = Get-ClusterGroup -Name "HAFILESERVER"
    Write-Host "Retour vers : $($group.OwnerNode.Name)" -ForegroundColor Green

    # ===== RAPPORT FINAL =====

    Write-Host "`n=== RAPPORT DE TESTS ===" -ForegroundColor Cyan

    # Événements de cluster
    Get-WinEvent -LogName "Microsoft-Windows-FailoverClustering/Operational" `
        -MaxEvents 20 |
        Where-Object { $_.Id -in @(1069, 1205, 1206, 1230) } |
        Select-Object TimeCreated, Id, Message |
        Format-Table -Wrap

    # Statistiques du groupe
    Get-ClusterGroup -Name "HAFILESERVER" | Format-List `
        Name, OwnerNode, State, FailoverCount

    # Historique des propriétaires
    Get-ClusterLog -Node NODE1, NODE2 -TimeSpan 15 -Destination "C:\ClusterLogs"
    Write-Host "`nLogs du cluster générés dans C:\ClusterLogs" -ForegroundColor Cyan
    ```

    **Validation et monitoring continu**

    ```powershell
    # Script de monitoring pour production
    # Save as Monitor-HAFileServer.ps1

    while ($true) {
        Clear-Host
        Write-Host "=== MONITORING CLUSTER PRODCLUSTER ===" -ForegroundColor Cyan
        Write-Host "Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

        # État du cluster
        $cluster = Get-Cluster
        Write-Host "Cluster : $($cluster.Name)" -ForegroundColor Yellow
        Write-Host "  État : $($cluster.State)"

        # État des nœuds
        Write-Host "`nNœuds :" -ForegroundColor Yellow
        Get-ClusterNode | Format-Table Name, State, @{
            Label='Uptime'
            Expression={
                if ($_.State -eq 'Up') {
                    $uptime = (Get-Date) - $_.StatusInformation.LastUpTime
                    "$($uptime.Days)j $($uptime.Hours)h"
                } else { 'N/A' }
            }
        } -AutoSize

        # État des ressources
        Write-Host "Groupes :" -ForegroundColor Yellow
        Get-ClusterGroup | Format-Table Name, OwnerNode, State, FailoverCount -AutoSize

        # État du quorum
        Write-Host "Quorum :" -ForegroundColor Yellow
        Get-ClusterQuorum | Format-List QuorumType, QuorumResource

        # Test d'accès au partage
        Write-Host "Test d'accès :" -ForegroundColor Yellow
        try {
            $testResult = Test-Path "\\HAFILESERVER\CriticalData"
            if ($testResult) {
                Write-Host "  \\HAFILESERVER\CriticalData : ACCESSIBLE" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "  \\HAFILESERVER\CriticalData : INACCESSIBLE" -ForegroundColor Red
        }

        Start-Sleep -Seconds 10
    }
    ```

---

## Quiz

1. **Quel mécanisme évite le split-brain dans un cluster ?**
   - [ ] A. Heartbeat
   - [ ] B. Quorum
   - [ ] C. Failback

2. **Combien de noeuds minimum pour Storage Spaces Direct ?**
   - [ ] A. 1
   - [ ] B. 2
   - [ ] C. 4

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 15 : Backup & Disaster Recovery](15-backup-disaster-recovery.md)

**Suivant :** [Module 17 : Conteneurs Windows](17-conteneurs-windows.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 15 : Backup & Disaster Recovery](15-backup-disaster-recovery.md) | [Module 17 : Conteneurs Windows →](17-conteneurs-windows.md) |

[Retour au Programme](index.md){ .md-button }
