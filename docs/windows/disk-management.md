---
tags:
  - windows
  - storage
  - disk
  - raid
---

# Gestion des Disques Windows

Configuration avancée du stockage : Storage Spaces, RAID logiciel, iSCSI, et VHD.

## Outils de Gestion

```
OUTILS DE STOCKAGE WINDOWS
══════════════════════════════════════════════════════════

diskmgmt.msc      Interface graphique Disk Management
diskpart          CLI interactif pour partitions
PowerShell        Get-Disk, Get-Volume, Storage cmdlets
Storage Spaces    Pooling et résilience (GUI + PowerShell)
```

---

## Gestion de Base (PowerShell)

### Disques et Partitions

```powershell
# Lister les disques
Get-Disk

# Détails d'un disque
Get-Disk -Number 1 | Format-List *

# Initialiser un nouveau disque
Initialize-Disk -Number 1 -PartitionStyle GPT

# Créer une partition
New-Partition -DiskNumber 1 -UseMaximumSize -DriveLetter D

# Formater
Format-Volume -DriveLetter D -FileSystem NTFS -NewFileSystemLabel "Data" -Confirm:$false

# One-liner : initialiser, partitionner, formater
Get-Disk -Number 1 |
    Initialize-Disk -PartitionStyle GPT -PassThru |
    New-Partition -UseMaximumSize -DriveLetter D |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data"
```

### Volumes et Lettres

```powershell
# Lister les volumes
Get-Volume

# Changer la lettre d'un volume
Set-Partition -DriveLetter D -NewDriveLetter E

# Monter un volume sur un dossier (mount point)
Add-PartitionAccessPath -DriveLetter D -AccessPath "C:\Mounts\DataDisk"

# Étendre une partition
Resize-Partition -DriveLetter D -Size (Get-PartitionSupportedSize -DriveLetter D).SizeMax

# Réduire une partition
Resize-Partition -DriveLetter C -Size 100GB
```

---

## Storage Spaces

### Concepts

```
STORAGE SPACES ARCHITECTURE
══════════════════════════════════════════════════════════

Physical Disks → Storage Pool → Virtual Disk → Volume
                     ↓
              ┌──────────────────────────────┐
              │  Resiliency Options:         │
              │  • Simple (stripe, no fault) │
              │  • Mirror (2-way, 3-way)     │
              │  • Parity (like RAID5/6)     │
              └──────────────────────────────┘
```

### Création d'un Pool

```powershell
# Lister les disques physiques disponibles
Get-PhysicalDisk -CanPool $true

# Créer un Storage Pool
$disks = Get-PhysicalDisk -CanPool $true
New-StoragePool -FriendlyName "DataPool" `
    -StorageSubsystemFriendlyName "Windows Storage*" `
    -PhysicalDisks $disks

# Voir les pools
Get-StoragePool
```

### Création de Virtual Disks

```powershell
# Virtual Disk en miroir (RAID1)
New-VirtualDisk -StoragePoolFriendlyName "DataPool" `
    -FriendlyName "MirrorDisk" `
    -ResiliencySettingName Mirror `
    -Size 500GB `
    -ProvisioningType Thin

# Virtual Disk avec parité (RAID5)
New-VirtualDisk -StoragePoolFriendlyName "DataPool" `
    -FriendlyName "ParityDisk" `
    -ResiliencySettingName Parity `
    -Size 1TB `
    -ProvisioningType Thin `
    -NumberOfColumns 3

# Simple (stripe, pas de résilience)
New-VirtualDisk -StoragePoolFriendlyName "DataPool" `
    -FriendlyName "FastDisk" `
    -ResiliencySettingName Simple `
    -Size 2TB

# Initialiser et formater
Get-VirtualDisk -FriendlyName "MirrorDisk" |
    Initialize-Disk -PassThru |
    New-Partition -UseMaximumSize -DriveLetter M |
    Format-Volume -FileSystem ReFS -NewFileSystemLabel "Mirror"
```

### Tiered Storage

```powershell
# Créer des tiers SSD + HDD
$ssd = Get-PhysicalDisk | Where-Object MediaType -eq SSD
$hdd = Get-PhysicalDisk | Where-Object MediaType -eq HDD

New-StorageTier -StoragePoolFriendlyName "DataPool" -FriendlyName "SSDTier" `
    -MediaType SSD -ResiliencySettingName Mirror

New-StorageTier -StoragePoolFriendlyName "DataPool" -FriendlyName "HDDTier" `
    -MediaType HDD -ResiliencySettingName Parity

# Virtual Disk avec tiers
New-VirtualDisk -StoragePoolFriendlyName "DataPool" `
    -FriendlyName "TieredDisk" `
    -StorageTiers (Get-StorageTier -FriendlyName "SSDTier","HDDTier") `
    -StorageTierSizes 100GB,1TB
```

---

## iSCSI

### Initiateur (Client)

```powershell
# Démarrer le service
Start-Service -Name MSiSCSI
Set-Service -Name MSiSCSI -StartupType Automatic

# Découvrir les cibles
New-IscsiTargetPortal -TargetPortalAddress "10.10.1.100"

# Voir les cibles disponibles
Get-IscsiTarget

# Se connecter à une cible
Connect-IscsiTarget -NodeAddress "iqn.2024-01.corp.local:storage-lun1" -IsPersistent $true

# Avec authentification CHAP
Connect-IscsiTarget -NodeAddress "iqn.2024-01.corp.local:storage-lun1" `
    -AuthenticationType ONEWAYCHAP `
    -ChapUsername "initiator1" `
    -ChapSecret (ConvertTo-SecureString "ChapSecret123!" -AsPlainText -Force) `
    -IsPersistent $true

# Voir les sessions
Get-IscsiSession

# Déconnecter
Disconnect-IscsiTarget -NodeAddress "iqn.2024-01.corp.local:storage-lun1"
```

### Cible iSCSI (Serveur Windows)

```powershell
# Installer le rôle
Install-WindowsFeature -Name FS-iSCSITarget-Server -IncludeManagementTools

# Créer un disque virtuel iSCSI
New-IscsiVirtualDisk -Path "C:\iSCSI\Disk1.vhdx" -Size 100GB

# Créer une cible
New-IscsiServerTarget -TargetName "Target1" -InitiatorIds @("IPAddress:10.10.1.50","IPAddress:10.10.1.51")

# Associer le disque à la cible
Add-IscsiVirtualDiskTargetMapping -TargetName "Target1" -Path "C:\iSCSI\Disk1.vhdx"

# Voir les cibles
Get-IscsiServerTarget
```

---

## VHD et VHDX

### Gestion des VHD

```powershell
# Créer un VHD
New-VHD -Path "C:\VHDs\Data.vhdx" -SizeBytes 100GB -Dynamic

# VHD de taille fixe
New-VHD -Path "C:\VHDs\Fixed.vhdx" -SizeBytes 50GB -Fixed

# VHD différentiel (snapshot)
New-VHD -Path "C:\VHDs\Child.vhdx" -ParentPath "C:\VHDs\Parent.vhdx" -Differencing

# Monter un VHD
Mount-VHD -Path "C:\VHDs\Data.vhdx"

# Monter en lecture seule
Mount-VHD -Path "C:\VHDs\Data.vhdx" -ReadOnly

# Démonter
Dismount-VHD -Path "C:\VHDs\Data.vhdx"

# Voir les VHD montés
Get-VHD -Path "C:\VHDs\Data.vhdx"
```

### Conversion et Optimisation

```powershell
# Convertir VHD vers VHDX
Convert-VHD -Path "C:\VHDs\Old.vhd" -DestinationPath "C:\VHDs\New.vhdx" -VHDType Dynamic

# Convertir dynamique vers fixe
Convert-VHD -Path "C:\VHDs\Dynamic.vhdx" -DestinationPath "C:\VHDs\Fixed.vhdx" -VHDType Fixed

# Compacter un VHD dynamique
Optimize-VHD -Path "C:\VHDs\Data.vhdx" -Mode Full

# Redimensionner
Resize-VHD -Path "C:\VHDs\Data.vhdx" -SizeBytes 200GB
```

### Boot depuis VHD (Native Boot)

```powershell
# Créer un VHD bootable
New-VHD -Path "C:\VHDs\Windows.vhdx" -SizeBytes 60GB -Fixed
Mount-VHD -Path "C:\VHDs\Windows.vhdx"

# Appliquer une image Windows
Expand-WindowsImage -ImagePath "D:\sources\install.wim" -Index 1 -ApplyPath "E:\"

# Ajouter au boot manager
bcdboot E:\Windows /s C:
bcdedit /set {current} device vhd=[C:]\VHDs\Windows.vhdx
```

---

## RAID Logiciel (Diskpart/Disk Management)

### Miroir Simple (2 disques)

```cmd
diskpart
select disk 1
convert dynamic
select disk 2
convert dynamic
select volume D
add disk=2
```

### Stripe (RAID0)

```powershell
# Via Storage Spaces (recommandé) ou
# Via diskpart pour volumes dynamiques
$disks = Get-Disk | Where-Object { $_.Number -in 1,2 }
New-VirtualDisk -StoragePoolFriendlyName "DataPool" `
    -FriendlyName "StripeDisk" `
    -ResiliencySettingName Simple `
    -NumberOfColumns 2 `
    -Size 1TB
```

---

## Diagnostic et Réparation

### Vérification des Disques

```powershell
# État SMART des disques
Get-PhysicalDisk | Select-Object FriendlyName, MediaType, HealthStatus, OperationalStatus

# Détails de santé
Get-PhysicalDisk | Get-StorageReliabilityCounter

# Vérifier un volume (chkdsk)
Repair-Volume -DriveLetter C -Scan
Repair-Volume -DriveLetter C -OfflineScanAndFix  # Nécessite démontage

# Défragmenter
Optimize-Volume -DriveLetter C -Defrag -Verbose
Optimize-Volume -DriveLetter C -ReTrim  # Pour SSD
```

### Surveillance Storage Spaces

```powershell
# État du pool
Get-StoragePool | Select-Object FriendlyName, HealthStatus, OperationalStatus

# Disques dégradés
Get-PhysicalDisk | Where-Object HealthStatus -ne "Healthy"

# Alertes de stockage
Get-StorageHealthReport -CimSession "ClusterName"

# Réparer un pool dégradé (après remplacement disque)
Repair-VirtualDisk -FriendlyName "MirrorDisk"
```

### Event Logs Stockage

```powershell
# Événements disque
Get-WinEvent -LogName "Microsoft-Windows-Storage-Storport/Operational" -MaxEvents 50

# Événements Storage Spaces
Get-WinEvent -LogName "Microsoft-Windows-StorageSpaces-Driver/Operational" -MaxEvents 50

# Erreurs NTFS
Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Ntfs'} -MaxEvents 20
```

---

## Bonnes Pratiques

```yaml
Checklist Stockage:
  Planification:
    - [ ] Choisir le bon type de résilience
    - [ ] Prévoir l'espace pour la croissance
    - [ ] ReFS pour Storage Spaces (intégrité)
    - [ ] NTFS pour compatibilité

  Storage Spaces:
    - [ ] Minimum 3 disques pour parité
    - [ ] Disques de même taille si possible
    - [ ] Tiering SSD+HDD si applicable
    - [ ] Thin provisioning avec monitoring

  Maintenance:
    - [ ] Monitoring SMART
    - [ ] Alertes sur santé des pools
    - [ ] Plan de remplacement disque
    - [ ] Sauvegardes régulières
```

---

**Voir aussi :**

- [File Server](file-server.md) - Services de fichiers
- [Hyper-V](hyper-v.md) - Stockage VM
- [Performance Monitoring](performance-monitoring.md) - Monitoring disque
