---
tags:
  - formation
  - windows-server
  - stockage
  - disques
  - storage-spaces
---

# Module 08 : Stockage & Disques

## Objectifs du Module

Ce module couvre la gestion du stockage Windows Server :

- Gérer les disques et partitions
- Comprendre GPT vs MBR
- Configurer Storage Spaces
- Utiliser iSCSI et volumes partagés
- Implémenter la déduplication

**Durée :** 7 heures

**Niveau :** Administration

---

## 1. Gestion des Disques

### 1.1 Concepts de Base

```
TYPES DE DISQUES
────────────────
MBR (Master Boot Record)     GPT (GUID Partition Table)
• Legacy                     • Moderne
• Max 2 TB                   • Max 18 EB
• Max 4 partitions primaires • Max 128 partitions
• Compatible ancien BIOS     • Requiert UEFI

TYPES DE VOLUMES
────────────────
• Simple    - Un seul disque
• Spanned   - Plusieurs disques (pas de redondance)
• Striped   - RAID 0 (performance)
• Mirrored  - RAID 1 (redondance)
• RAID-5    - Parité distribuée
```

### 1.2 Gestion avec PowerShell

```powershell
# Lister les disques
Get-Disk

# Lister les partitions
Get-Partition

# Lister les volumes
Get-Volume

# Initialiser un nouveau disque
Initialize-Disk -Number 1 -PartitionStyle GPT

# Créer une partition
New-Partition -DiskNumber 1 -UseMaximumSize -AssignDriveLetter

# Formater un volume
Format-Volume -DriveLetter E -FileSystem NTFS -NewFileSystemLabel "Data"

# Commande complète (nouveau disque)
Get-Disk -Number 1 |
    Initialize-Disk -PartitionStyle GPT -PassThru |
    New-Partition -UseMaximumSize -AssignDriveLetter |
    Format-Volume -FileSystem NTFS -NewFileSystemLabel "Data"

# Étendre une partition
Resize-Partition -DriveLetter E -Size (Get-PartitionSupportedSize -DriveLetter E).SizeMax

# Changer la lettre de lecteur
Set-Partition -DriveLetter E -NewDriveLetter F
```

---

## 2. Storage Spaces

### 2.1 Concepts

```
STORAGE SPACES
──────────────
• Pool de stockage virtuel sur disques physiques
• Résilience intégrée (Simple, Mirror, Parity)
• Provisionnement fin (thin provisioning)
• Tiering automatique (SSD + HDD)

Types de résilience:
• Simple       - Pas de redondance (performance max)
• Two-way Mirror - Copie sur 2 disques (RAID 1)
• Three-way Mirror - Copie sur 3 disques
• Parity      - RAID 5/6 équivalent
```

### 2.2 Configuration avec PowerShell

```powershell
# Lister les disques physiques disponibles
Get-PhysicalDisk -CanPool $true

# Créer un pool de stockage
$disks = Get-PhysicalDisk -CanPool $true
New-StoragePool -FriendlyName "DataPool" `
                -StorageSubSystemFriendlyName "Windows Storage*" `
                -PhysicalDisks $disks

# Créer un disque virtuel (Mirror)
New-VirtualDisk -StoragePoolFriendlyName "DataPool" `
                -FriendlyName "DataDisk" `
                -ResiliencySettingName Mirror `
                -Size 100GB `
                -ProvisioningType Thin

# Initialiser et formater
Get-VirtualDisk -FriendlyName "DataDisk" |
    Get-Disk |
    Initialize-Disk -PartitionStyle GPT -PassThru |
    New-Partition -UseMaximumSize -AssignDriveLetter |
    Format-Volume -FileSystem ReFS -NewFileSystemLabel "DataVolume"
```

---

## 3. iSCSI

### 3.1 Initiateur iSCSI (Client)

```powershell
# Activer l'initiateur
Start-Service -Name MSiSCSI
Set-Service -Name MSiSCSI -StartupType Automatic

# Découvrir les targets
New-IscsiTargetPortal -TargetPortalAddress "192.168.1.100"

# Se connecter
Connect-IscsiTarget -NodeAddress "iqn.2024-01.com.storage:lun1" -IsPersistent $true

# Lister les sessions
Get-IscsiSession

# Déconnecter
Disconnect-IscsiTarget -NodeAddress "iqn.2024-01.com.storage:lun1"
```

### 3.2 Target iSCSI (Serveur)

```powershell
# Installer le rôle
Install-WindowsFeature -Name FS-iSCSITarget-Server -IncludeManagementTools

# Créer un disque virtuel iSCSI
New-IscsiVirtualDisk -Path "C:\iSCSI\Disk1.vhdx" -Size 100GB

# Créer un target
New-IscsiServerTarget -TargetName "Target1" -InitiatorIds @("IQN:iqn.1991-05.com.microsoft:client1")

# Associer le disque au target
Add-IscsiVirtualDiskTargetMapping -TargetName "Target1" -Path "C:\iSCSI\Disk1.vhdx"
```

---

## 4. Déduplication

```powershell
# Installer la feature
Install-WindowsFeature -Name FS-Data-Deduplication

# Activer sur un volume
Enable-DedupVolume -Volume "E:" -UsageType Default

# Configurer
Set-DedupVolume -Volume "E:" -MinimumFileAgeDays 3

# Vérifier l'état
Get-DedupStatus -Volume "E:"

# Statistiques d'économie
Get-DedupVolume -Volume "E:" | Select-Object Volume, SavedSpace, SavingsRate
```

---

## 5. Exercice Pratique

### Configuration Complète

```powershell
# Scénario: Nouveau disque de données

# 1. Identifier le disque
$disk = Get-Disk | Where-Object PartitionStyle -eq "RAW"

# 2. Initialiser
$disk | Initialize-Disk -PartitionStyle GPT

# 3. Créer partition
$partition = $disk | New-Partition -UseMaximumSize -AssignDriveLetter

# 4. Formater
$partition | Format-Volume -FileSystem NTFS -NewFileSystemLabel "AppData"

# 5. Vérifier
Get-Volume -DriveLetter $partition.DriveLetter
```

---

## Quiz

1. **Quelle table de partition supporte les disques > 2 TB ?**
   - [ ] A. MBR
   - [ ] B. GPT
   - [ ] C. FAT32

2. **Quel type de résilience Storage Spaces copie sur 2 disques ?**
   - [ ] A. Simple
   - [ ] B. Two-way Mirror
   - [ ] C. Parity

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 07 : Services & Processus](07-services-processus.md)

**Suivant :** [Module 09 : Réseau & DNS/DHCP](09-reseau-dns-dhcp.md)
