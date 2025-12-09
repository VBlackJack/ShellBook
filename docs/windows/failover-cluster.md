---
tags:
  - windows
  - clustering
  - high-availability
  - failover
---

# Failover Clustering Windows

Configuration et gestion des clusters de basculement Windows Server pour la haute disponibilité.

## Concepts

![Failover Cluster Architecture](../assets/diagrams/failover-cluster-architecture.jpeg)

```
ARCHITECTURE FAILOVER CLUSTER
══════════════════════════════════════════════════════════

                    ┌─────────────────────────────────┐
                    │         Cluster Name            │
                    │      (Virtual Computer Object)  │
                    │         cluster.corp.local      │
                    └──────────────┬──────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│    Node 1     │        │    Node 2     │        │    Node 3     │
│   (Active)    │◄──────►│   (Passive)   │◄──────►│   (Passive)   │
│               │        │               │        │               │
│  ┌─────────┐  │        │               │        │               │
│  │ Role A  │  │        │               │        │               │
│  └─────────┘  │        │  ┌─────────┐  │        │               │
│               │        │  │ Role B  │  │        │               │
└───────┬───────┘        │  └─────────┘  │        └───────────────┘
        │                └───────┬───────┘
        │                        │
        └────────────────────────┼────────────────────────────┐
                                 │                            │
                    ┌────────────▼────────────┐    ┌─────────▼─────────┐
                    │    Shared Storage       │    │      Quorum       │
                    │    (SAN, S2D, CSV)      │    │   (Disk/Cloud)    │
                    └─────────────────────────┘    └───────────────────┘

Composants clés :
• Nodes : Serveurs membres du cluster
• Roles : Services/applications clusterisés (VM, SQL, File Server)
• Quorum : Mécanisme de vote pour éviter split-brain
• CSV : Cluster Shared Volumes (stockage partagé)
• Heartbeat : Communication inter-nodes
```

### Types de Quorum

```
MODÈLES DE QUORUM
══════════════════════════════════════════════════════════

Node Majority :
  2 nodes → 1 failure tolerated
  3 nodes → 1 failure tolerated
  5 nodes → 2 failures tolerated
  Formule : (n/2) + 1 votes requis

Node + Disk Majority :
  Disque quorum = 1 vote supplémentaire
  Recommandé pour clusters pairs

Node + File Share Majority :
  File share witness = 1 vote
  Utile si pas de stockage SAN

Cloud Witness (Azure) :
  Blob storage Azure = witness
  Idéal pour clusters étendus ou Azure Stack
```

---

## Installation

### Prérequis

```powershell
# Vérifier la connectivité entre nodes
Test-Connection -ComputerName Node1,Node2,Node3

# Installer la fonctionnalité (sur tous les nodes)
Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools

# Sur chaque node, redémarrer si nécessaire
Restart-Computer

# Importer le module
Import-Module FailoverClusters
```

### Validation du Cluster

```powershell
# Valider la configuration (OBLIGATOIRE avant création)
Test-Cluster -Node Node1,Node2 -Include "Storage","Network","System Configuration"

# Rapport complet
Test-Cluster -Node Node1,Node2 -ReportName "C:\ClusterValidation"

# Catégories de tests :
# - Cluster Configuration
# - Hyper-V Configuration
# - Inventory
# - Network
# - Storage
# - System Configuration

# Vérifier le rapport HTML généré
Invoke-Item "C:\ClusterValidation\*.htm"
```

### Création du Cluster

```powershell
# Créer le cluster
New-Cluster -Name "MyCluster" `
    -Node Node1,Node2 `
    -StaticAddress 10.10.1.100 `
    -NoStorage

# Avec plusieurs IPs (multi-subnet)
New-Cluster -Name "MyCluster" `
    -Node Node1,Node2 `
    -StaticAddress 10.10.1.100,10.20.1.100 `
    -NoStorage

# Vérifier
Get-Cluster
Get-ClusterNode
```

---

## Configuration du Quorum

### Types de Witness

```powershell
# Voir la configuration actuelle
Get-ClusterQuorum

# Disk Witness (sur SAN partagé)
Set-ClusterQuorum -DiskWitness "Cluster Disk 1"

# File Share Witness
Set-ClusterQuorum -FileShareWitness "\\fileserver\ClusterWitness"

# Cloud Witness (Azure)
Set-ClusterQuorum -CloudWitness `
    -AccountName "mystorageaccount" `
    -AccessKey "xxxxxxxxxxxxxxxxxxxx" `
    -Endpoint "core.windows.net"

# Node Majority (pas de witness)
Set-ClusterQuorum -NodeMajority
```

### Cloud Witness Setup

```powershell
# 1. Créer un Storage Account Azure (via portal ou CLI)
# - General Purpose v1 ou v2
# - Pas besoin d'accès public
# - Récupérer la clé d'accès

# 2. Configurer le cluster
$accountName = "myclusterwitness"
$accessKey = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=="

Set-ClusterQuorum -CloudWitness `
    -AccountName $accountName `
    -AccessKey $accessKey `
    -Endpoint "core.windows.net"

# Vérifier
Get-ClusterQuorum
```

---

## Stockage Cluster

### Cluster Shared Volumes (CSV)

```powershell
# Ajouter un disque au cluster
Get-ClusterAvailableDisk | Add-ClusterDisk

# Voir les disques cluster
Get-ClusterResource -ResourceType "Physical Disk"

# Convertir en CSV
Add-ClusterSharedVolume -Name "Cluster Disk 1"

# Les CSV sont montés dans C:\ClusterStorage\VolumeX
Get-ClusterSharedVolume

# Redirected I/O vs Direct I/O
Get-ClusterSharedVolumeState

# Maintenance d'un CSV
Suspend-ClusterResource -Name "Cluster Virtual Disk (Volume1)"
# ... maintenance ...
Resume-ClusterResource -Name "Cluster Virtual Disk (Volume1)"
```

### Storage Spaces Direct (S2D)

```powershell
# Activer S2D (Windows Server 2016+)
Enable-ClusterStorageSpacesDirect

# Créer un pool
New-StoragePool -StorageSubSystemFriendlyName "*Cluster*" `
    -FriendlyName "S2DPool" `
    -ProvisioningTypeDefault Fixed `
    -PhysicalDisks (Get-PhysicalDisk -CanPool $true)

# Créer un volume
New-Volume -StoragePoolFriendlyName "S2DPool" `
    -FriendlyName "Volume1" `
    -FileSystem CSVFS_ReFS `
    -Size 1TB `
    -ResiliencySettingName Mirror

# Voir les volumes
Get-VirtualDisk
Get-Volume -FriendlyName "Volume*"
```

---

## Rôles Cluster

### File Server

```powershell
# Ajouter un rôle File Server
Add-ClusterFileServerRole -Name "FS-Cluster" `
    -Storage "Cluster Disk 2" `
    -StaticAddress 10.10.1.101

# Scale-Out File Server (SOFS) - Pour Hyper-V/SQL
Add-ClusterScaleOutFileServerRole -Name "SOFS-Cluster"

# Créer un partage sur SOFS
New-SmbShare -Name "VMStorage" `
    -Path "C:\ClusterStorage\Volume1\VMStorage" `
    -FullAccess "CORP\Hyper-V-Servers"
```

### Hyper-V

```powershell
# Les VMs Hyper-V sont des rôles cluster
# Configurer la VM pour HA
Add-ClusterVirtualMachineRole -VMName "VM01"

# Ou lors de la création
New-VM -Name "VM01" -Path "C:\ClusterStorage\Volume1" -MemoryStartupBytes 4GB
Add-ClusterVirtualMachineRole -VMName "VM01"

# Live Migration
Move-ClusterVirtualMachineRole -Name "VM01" -Node Node2 -MigrationType Live

# Quick Migration (avec downtime minimal)
Move-ClusterVirtualMachineRole -Name "VM01" -Node Node2 -MigrationType Quick
```

### Generic Service/Application

```powershell
# Cluster un service Windows
Add-ClusterGenericServiceRole -ServiceName "MyService" `
    -Name "MyService-Cluster" `
    -StaticAddress 10.10.1.102 `
    -Storage "Cluster Disk 3"

# Cluster une application
Add-ClusterGenericApplicationRole -CommandLine "C:\App\myapp.exe" `
    -Name "MyApp-Cluster" `
    -Parameters "-config C:\ClusterStorage\Volume1\App\config.xml" `
    -StaticAddress 10.10.1.103
```

### SQL Server (Référence)

```powershell
# SQL Server utilise son propre setup pour le clustering
# Installer SQL en mode "Add node to SQL Server failover cluster"

# Vérifier les ressources SQL
Get-ClusterResource | Where-Object ResourceType -like "*SQL*"

# Basculer SQL
Move-ClusterGroup -Name "SQL Server (MSSQLSERVER)" -Node Node2
```

---

## Gestion Opérationnelle

### Maintenance d'un Node

```powershell
# Mettre un node en mode maintenance
Suspend-ClusterNode -Name Node1 -Drain

# Vérifier que les rôles ont basculé
Get-ClusterGroup | Select-Object Name, OwnerNode, State

# Effectuer la maintenance...

# Sortir du mode maintenance
Resume-ClusterNode -Name Node1 -Failback Immediate

# Ou avec failback différé
Resume-ClusterNode -Name Node1 -Failback NoFailback
```

### Failover Manuel

```powershell
# Déplacer un rôle
Move-ClusterGroup -Name "MyRole" -Node Node2

# Déplacer toutes les ressources d'un node
Get-ClusterGroup | Where-Object OwnerNode -eq "Node1" |
    Move-ClusterGroup -Node Node2

# Déplacer le cluster name (CNO)
Move-ClusterGroup -Name "Cluster Group" -Node Node2
```

### Gestion des Ressources

```powershell
# Lister les ressources
Get-ClusterResource

# État des ressources
Get-ClusterResource | Select-Object Name, ResourceType, State, OwnerNode

# Démarrer/Arrêter
Start-ClusterResource -Name "MyResource"
Stop-ClusterResource -Name "MyResource"

# Mettre offline un groupe
Stop-ClusterGroup -Name "MyRole"

# Remettre online
Start-ClusterGroup -Name "MyRole"
```

---

## Réseau Cluster

### Configuration Réseau

```powershell
# Voir les réseaux cluster
Get-ClusterNetwork

# Renommer un réseau
(Get-ClusterNetwork -Name "Cluster Network 1").Name = "Heartbeat"
(Get-ClusterNetwork -Name "Cluster Network 2").Name = "Production"

# Configurer l'usage
# 0 = Not used
# 1 = Cluster only (heartbeat)
# 3 = Cluster and Client (production)
(Get-ClusterNetwork -Name "Heartbeat").Role = 1
(Get-ClusterNetwork -Name "Production").Role = 3

# Voir les interfaces
Get-ClusterNetworkInterface
```

### Live Migration Network

```powershell
# Configurer le réseau pour Live Migration
Get-ClusterResourceType -Name "Virtual Machine" |
    Set-ClusterParameter -Name MigrationNetworkOrder -Value (Get-ClusterNetwork -Name "Heartbeat").Id

# Limiter la bande passante
Set-VMHost -MaximumVirtualMachineMigrations 2
Set-VMHost -VirtualMachineMigrationPerformanceOption SMB
```

---

## Monitoring et Troubleshooting

### Événements Cluster

```powershell
# Logs cluster
Get-ClusterLog -Destination C:\Logs -TimeSpan 60

# Event logs
Get-WinEvent -LogName "Microsoft-Windows-FailoverClustering/Operational" -MaxEvents 50

# Événements critiques
Get-WinEvent -LogName "Microsoft-Windows-FailoverClustering/Operational" |
    Where-Object LevelDisplayName -in "Error","Critical" |
    Select-Object TimeCreated, Message -First 20
```

### Diagnostic

```powershell
# Test de validation (peut être fait sur cluster existant)
Test-Cluster -Node Node1,Node2 -Include "Network"

# Vérifier la santé
Get-ClusterNode | Select-Object Name, State, DrainStatus
Get-ClusterGroup | Select-Object Name, State, OwnerNode
Get-ClusterResource | Where-Object State -ne "Online"

# Vérifier le quorum
Get-ClusterQuorum | Select-Object Cluster, QuorumType, QuorumResource

# Stockage
Get-ClusterSharedVolume | Select-Object Name, State, OwnerNode
Get-ClusterSharedVolumeState
```

### Problèmes Courants

```powershell
# Node en état "Down"
# 1. Vérifier la connectivité réseau
Test-Connection -ComputerName Node1
# 2. Vérifier les services
Get-Service ClusSvc -ComputerName Node1
# 3. Redémarrer le service cluster
Restart-Service ClusSvc -ComputerName Node1

# Ressource en état "Failed"
# Voir les détails
Get-ClusterResource -Name "MyResource" | Get-ClusterParameter
# Tenter de remettre online
Start-ClusterResource -Name "MyResource"

# Split-brain (nodes isolés)
# Vérifier le quorum
Get-ClusterQuorum
# Forcer le quorum sur un node
Start-ClusterNode -Name Node1 -FixQuorum
```

---

## Cluster-Aware Updating (CAU)

### Configuration

```powershell
# Activer CAU
Add-CauClusterRole -ClusterName MyCluster `
    -VirtualComputerObjectName "MyCluster-CAU" `
    -Force

# Configurer le self-updating
Set-CauClusterRole -ClusterName MyCluster `
    -UpdateFrequency Weekly `
    -DayOfWeek Sunday `
    -RunPluginsSerially

# Options de run
Set-CauClusterRole -ClusterName MyCluster `
    -MaxRetriesPerNode 3 `
    -MaxFailedNodes 1 `
    -RequireAllNodesOnline
```

### Exécution Manuelle

```powershell
# Prévisualiser les updates
Invoke-CauScan -ClusterName MyCluster

# Appliquer les updates
Invoke-CauRun -ClusterName MyCluster -Force

# Avec rapport
Invoke-CauRun -ClusterName MyCluster -CauPluginName Microsoft.WindowsUpdatePlugin `
    -ReportOnly
```

---

## Bonnes Pratiques

```yaml
Checklist Failover Cluster:
  Design:
    - [ ] Minimum 3 nodes pour tolérance aux pannes
    - [ ] Réseaux séparés (production, heartbeat, stockage)
    - [ ] Quorum adapté (Cloud Witness recommandé)
    - [ ] Stockage redondant (RAID, S2D)

  Configuration:
    - [ ] Validation du cluster réussie
    - [ ] Anti-affinity pour rôles critiques
    - [ ] Preferred owners configurés
    - [ ] CAU activé

  Réseau:
    - [ ] Heartbeat sur réseau dédié
    - [ ] Live Migration sur réseau haut débit
    - [ ] CSV traffic optimisé

  Opérations:
    - [ ] Procédure de maintenance documentée
    - [ ] Tests de failover réguliers
    - [ ] Monitoring des événements cluster
    - [ ] Sauvegardes de la config cluster
```

---

**Voir aussi :**

- [Hyper-V](hyper-v.md) - Virtualisation
- [Disk Management](disk-management.md) - Stockage
- [Performance Monitoring](performance-monitoring.md) - Monitoring
