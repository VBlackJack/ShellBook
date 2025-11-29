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

```
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
