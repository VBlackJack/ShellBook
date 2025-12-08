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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Créer une solution de stockage multi-disques avec Storage Spaces

    **Contexte** : Votre entreprise a besoin d'une solution de stockage pour héberger des données critiques. Vous disposez de 3 disques de 100 GB chacun et devez créer un pool de stockage avec résilience, puis créer deux volumes : un pour les données d'application (ReFS) et un pour les fichiers utilisateurs (NTFS).

    **Tâches à réaliser** :

    1. Identifier et initialiser 3 nouveaux disques en GPT
    2. Créer un Storage Pool avec les 3 disques
    3. Créer un disque virtuel avec résilience "Mirror" de 150 GB
    4. Partitionner le disque virtuel en deux volumes (80 GB et 70 GB)
    5. Formater le premier volume en ReFS et le second en NTFS avec des labels appropriés
    6. Activer la déduplication sur le volume NTFS

    **Critères de validation** :

    - [ ] Les 3 disques sont initialisés en GPT
    - [ ] Le Storage Pool est créé et contient les 3 disques
    - [ ] Le disque virtuel utilise la résilience "Mirror"
    - [ ] Deux volumes sont créés avec les tailles demandées
    - [ ] Les systèmes de fichiers ReFS et NTFS sont appliqués correctement
    - [ ] La déduplication est activée sur le volume NTFS

??? quote "Solution"
    Voici la solution complète :

    **Étape 1 : Script complet de déploiement**

    ```powershell
    # Deploy-StorageSpace.ps1
    # Script de création d'une solution Storage Spaces complète

    # Configuration
    $poolName = "DataPool"
    $vdiskName = "DataVDisk"
    $vdiskSize = 150GB
    $resiliency = "Mirror"

    Write-Host "=== Configuration Storage Spaces ===" -ForegroundColor Cyan
    Write-Host "Pool: $poolName"
    Write-Host "Disque virtuel: $vdiskName ($([math]::Round($vdiskSize/1GB, 2)) GB)"
    Write-Host "Résilience: $resiliency"
    Write-Host ""

    # 1. Identifier les disques disponibles
    Write-Host "Étape 1 : Identification des disques..." -ForegroundColor Yellow

    $availableDisks = Get-PhysicalDisk -CanPool $true
    if ($availableDisks.Count -lt 3) {
        Write-Host "ERREUR: Au moins 3 disques sont requis. Trouvés: $($availableDisks.Count)" -ForegroundColor Red
        Write-Host "`nDisques disponibles:" -ForegroundColor Yellow
        Get-PhysicalDisk | Format-Table FriendlyName, Size, MediaType, HealthStatus
        exit 1
    }

    Write-Host "Disques disponibles pour le pool:" -ForegroundColor Green
    $availableDisks | Format-Table FriendlyName, @{N="SizeGB";E={[math]::Round($_.Size/1GB,2)}}, MediaType, BusType

    # Sélectionner les 3 premiers disques
    $selectedDisks = $availableDisks | Select-Object -First 3

    # 2. Initialiser les disques en GPT
    Write-Host "`nÉtape 2 : Initialisation des disques en GPT..." -ForegroundColor Yellow

    foreach ($disk in $selectedDisks) {
        $diskNumber = $disk.DeviceId
        $physicalDisk = Get-Disk -Number $diskNumber

        if ($physicalDisk.PartitionStyle -eq "RAW") {
            Write-Host "Initialisation du disque $diskNumber en GPT..."
            Initialize-Disk -Number $diskNumber -PartitionStyle GPT -Confirm:$false
            Write-Host "  → Disque $diskNumber initialisé" -ForegroundColor Green
        } else {
            Write-Host "  → Disque $diskNumber déjà initialisé ($($physicalDisk.PartitionStyle))" -ForegroundColor Gray
        }
    }

    # 3. Créer le Storage Pool
    Write-Host "`nÉtape 3 : Création du Storage Pool..." -ForegroundColor Yellow

    # Vérifier si le pool existe déjà
    $existingPool = Get-StoragePool -FriendlyName $poolName -ErrorAction SilentlyContinue
    if ($existingPool) {
        Write-Host "Le pool '$poolName' existe déjà. Suppression..." -ForegroundColor Yellow
        Remove-StoragePool -FriendlyName $poolName -Confirm:$false
    }

    # Créer le pool
    $pool = New-StoragePool -FriendlyName $poolName `
        -StorageSubSystemFriendlyName "Windows Storage*" `
        -PhysicalDisks $selectedDisks

    Write-Host "Storage Pool créé avec succès!" -ForegroundColor Green
    Write-Host "  → Nom: $($pool.FriendlyName)"
    Write-Host "  → Taille: $([math]::Round($pool.Size/1GB, 2)) GB"
    Write-Host "  → Disques: $($selectedDisks.Count)"

    # 4. Créer le disque virtuel avec résilience Mirror
    Write-Host "`nÉtape 4 : Création du disque virtuel..." -ForegroundColor Yellow

    $vdisk = New-VirtualDisk -FriendlyName $vdiskName `
        -StoragePoolFriendlyName $poolName `
        -ResiliencySettingName $resiliency `
        -Size $vdiskSize `
        -ProvisioningType Thin

    Write-Host "Disque virtuel créé avec succès!" -ForegroundColor Green
    Write-Host "  → Nom: $($vdisk.FriendlyName)"
    Write-Host "  → Taille: $([math]::Round($vdisk.Size/1GB, 2)) GB"
    Write-Host "  → Résilience: $($vdisk.ResiliencySettingName)"

    # Attendre que le disque soit prêt
    Start-Sleep -Seconds 3

    # 5. Initialiser et partitionner le disque virtuel
    Write-Host "`nÉtape 5 : Partitionnement du disque virtuel..." -ForegroundColor Yellow

    # Obtenir le numéro de disque
    $disk = Get-VirtualDisk -FriendlyName $vdiskName | Get-Disk

    Write-Host "Disque virtuel détecté: Disk $($disk.Number)"

    # Initialiser si nécessaire
    if ($disk.PartitionStyle -eq "RAW") {
        Initialize-Disk -Number $disk.Number -PartitionStyle GPT
    }

    # Créer la première partition (80 GB - ReFS)
    Write-Host "Création de la partition 1 (80 GB - ReFS)..."
    $partition1 = New-Partition -DiskNumber $disk.Number -Size 80GB -AssignDriveLetter
    Format-Volume -DriveLetter $partition1.DriveLetter `
        -FileSystem ReFS `
        -NewFileSystemLabel "AppData" `
        -Confirm:$false

    Write-Host "  → Volume ReFS créé: $($partition1.DriveLetter):\ (AppData)" -ForegroundColor Green

    # Créer la deuxième partition (70 GB - NTFS)
    Write-Host "Création de la partition 2 (70 GB - NTFS)..."
    $partition2 = New-Partition -DiskNumber $disk.Number -Size 70GB -AssignDriveLetter
    Format-Volume -DriveLetter $partition2.DriveLetter `
        -FileSystem NTFS `
        -NewFileSystemLabel "UserData" `
        -Confirm:$false

    Write-Host "  → Volume NTFS créé: $($partition2.DriveLetter):\ (UserData)" -ForegroundColor Green

    # 6. Activer la déduplication sur le volume NTFS
    Write-Host "`nÉtape 6 : Configuration de la déduplication..." -ForegroundColor Yellow

    # Vérifier si la feature est installée
    $dedupFeature = Get-WindowsFeature -Name FS-Data-Deduplication
    if (-not $dedupFeature.Installed) {
        Write-Host "Installation de la feature Data Deduplication..."
        Install-WindowsFeature -Name FS-Data-Deduplication -IncludeManagementTools
    }

    # Activer la déduplication
    Enable-DedupVolume -Volume "$($partition2.DriveLetter):" -UsageType Default

    # Configurer les paramètres
    Set-DedupVolume -Volume "$($partition2.DriveLetter):" `
        -MinimumFileAgeDays 3 `
        -MinimumFileSize 32KB

    Write-Host "Déduplication activée sur $($partition2.DriveLetter):\" -ForegroundColor Green

    # 7. Créer une structure de test
    Write-Host "`nÉtape 7 : Création de la structure de répertoires..." -ForegroundColor Yellow

    # Structure pour AppData (ReFS)
    $appDataPaths = @(
        "$($partition1.DriveLetter):\Applications",
        "$($partition1.DriveLetter):\Databases",
        "$($partition1.DriveLetter):\Logs"
    )

    foreach ($path in $appDataPaths) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
    Write-Host "  → Structure AppData créée" -ForegroundColor Green

    # Structure pour UserData (NTFS)
    $userDataPaths = @(
        "$($partition2.DriveLetter):\Shares",
        "$($partition2.DriveLetter):\Profiles",
        "$($partition2.DriveLetter):\Archives"
    )

    foreach ($path in $userDataPaths) {
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
    Write-Host "  → Structure UserData créée" -ForegroundColor Green

    # 8. Rapport final
    Write-Host "`n=== RAPPORT FINAL ===" -ForegroundColor Cyan

    # Storage Pool
    Write-Host "`nStorage Pool:" -ForegroundColor Yellow
    Get-StoragePool -FriendlyName $poolName | Format-Table FriendlyName, OperationalStatus, HealthStatus, `
        @{N="SizeGB";E={[math]::Round($_.Size/1GB,2)}}, `
        @{N="AllocatedGB";E={[math]::Round(($_.Size - $_.FreeSpace)/1GB,2)}}

    # Disque virtuel
    Write-Host "Disque Virtuel:" -ForegroundColor Yellow
    Get-VirtualDisk -FriendlyName $vdiskName | Format-Table FriendlyName, OperationalStatus, HealthStatus, `
        @{N="SizeGB";E={[math]::Round($_.Size/1GB,2)}}, ResiliencySettingName

    # Volumes
    Write-Host "Volumes créés:" -ForegroundColor Yellow
    Get-Volume | Where-Object {$_.FileSystemLabel -in @("AppData", "UserData")} | Format-Table DriveLetter, FileSystemLabel, FileSystem, `
        @{N="SizeGB";E={[math]::Round($_.Size/1GB,2)}}, `
        @{N="FreeGB";E={[math]::Round($_.SizeRemaining/1GB,2)}}, HealthStatus

    # Déduplication
    Write-Host "État de la déduplication:" -ForegroundColor Yellow
    Get-DedupVolume | Where-Object {$_.Volume -eq "$($partition2.DriveLetter):\"} | Format-Table Volume, Enabled, `
        MinimumFileAgeDays, @{N="SavedSpaceGB";E={[math]::Round($_.SavedSpace/1GB,2)}}

    Write-Host "`n=== Configuration terminée avec succès! ===" -ForegroundColor Green
    Write-Host "`nVolumes créés:"
    Write-Host "  - $($partition1.DriveLetter):\ (AppData) - ReFS - Applications critiques"
    Write-Host "  - $($partition2.DriveLetter):\ (UserData) - NTFS - Données utilisateurs (avec déduplication)"
    ```

    **Étape 2 : Script de vérification**

    ```powershell
    # Verify-StorageSpace.ps1
    # Script de vérification de la configuration

    Write-Host "=== Vérification de la configuration Storage Spaces ===" -ForegroundColor Cyan

    $checks = @()

    # 1. Vérifier le Storage Pool
    $pool = Get-StoragePool -FriendlyName "DataPool" -ErrorAction SilentlyContinue
    $checks += [PSCustomObject]@{
        Check = "Storage Pool créé"
        Status = if ($pool) { "OK" } else { "ECHEC" }
        Details = if ($pool) { "$([math]::Round($pool.Size/1GB,2)) GB" } else { "Non trouvé" }
    }

    # 2. Vérifier le disque virtuel
    $vdisk = Get-VirtualDisk -FriendlyName "DataVDisk" -ErrorAction SilentlyContinue
    $checks += [PSCustomObject]@{
        Check = "Disque virtuel créé"
        Status = if ($vdisk -and $vdisk.ResiliencySettingName -eq "Mirror") { "OK" } else { "ECHEC" }
        Details = if ($vdisk) { "Résilience: $($vdisk.ResiliencySettingName)" } else { "Non trouvé" }
    }

    # 3. Vérifier le volume ReFS
    $refsVol = Get-Volume | Where-Object {$_.FileSystemLabel -eq "AppData" -and $_.FileSystem -eq "ReFS"}
    $checks += [PSCustomObject]@{
        Check = "Volume ReFS (AppData)"
        Status = if ($refsVol) { "OK" } else { "ECHEC" }
        Details = if ($refsVol) { "$($refsVol.DriveLetter):\ - $([math]::Round($refsVol.Size/1GB,2)) GB" } else { "Non trouvé" }
    }

    # 4. Vérifier le volume NTFS
    $ntfsVol = Get-Volume | Where-Object {$_.FileSystemLabel -eq "UserData" -and $_.FileSystem -eq "NTFS"}
    $checks += [PSCustomObject]@{
        Check = "Volume NTFS (UserData)"
        Status = if ($ntfsVol) { "OK" } else { "ECHEC" }
        Details = if ($ntfsVol) { "$($ntfsVol.DriveLetter):\ - $([math]::Round($ntfsVol.Size/1GB,2)) GB" } else { "Non trouvé" }
    }

    # 5. Vérifier la déduplication
    $dedup = Get-DedupVolume | Where-Object {$_.Volume -like "*UserData*"}
    $checks += [PSCustomObject]@{
        Check = "Déduplication activée"
        Status = if ($dedup -and $dedup.Enabled) { "OK" } else { "ECHEC" }
        Details = if ($dedup) { "Activée sur $($dedup.Volume)" } else { "Non configurée" }
    }

    # Afficher le résumé
    $checks | Format-Table -AutoSize

    $failedChecks = ($checks | Where-Object Status -eq "ECHEC").Count
    if ($failedChecks -eq 0) {
        Write-Host "`nTous les tests sont REUSSIS!" -ForegroundColor Green
    } else {
        Write-Host "`n$failedChecks test(s) ECHOUE(S)" -ForegroundColor Red
    }
    ```

    **Points clés de la solution** :

    - Utilisation de Storage Spaces pour créer un pool de disques avec résilience
    - Initialisation des disques en GPT pour supporter les grandes capacités
    - Création d'un disque virtuel avec résilience Mirror (RAID 1)
    - Utilisation de ReFS pour les données d'application (meilleure intégrité)
    - Utilisation de NTFS avec déduplication pour optimiser l'espace
    - Configuration du thin provisioning pour une allocation flexible
    - Scripts de vérification pour valider la configuration

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

---

## Navigation

| | |
|:---|---:|
| [← Module 07 : Services & Processus](07-services-processus.md) | [Module 09 : Réseau & DNS/DHCP →](09-reseau-dns-dhcp.md) |

[Retour au Programme](index.md){ .md-button }
