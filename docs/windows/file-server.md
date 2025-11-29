---
tags:
  - windows
  - file-server
  - dfs
  - storage
---

# File Server Windows

Configuration et gestion des serveurs de fichiers Windows : partages SMB, DFS, FSRM et quotas.

## Partages SMB

### Créer des Partages

```powershell
# Créer un partage simple
New-SmbShare -Name "Data" -Path "D:\Data" -Description "Données partagées"

# Partage avec permissions
New-SmbShare -Name "Finance" -Path "D:\Finance" `
    -FullAccess "CORP\Finance-Admins" `
    -ChangeAccess "CORP\Finance-Users" `
    -ReadAccess "CORP\Auditors"

# Partage caché ($ à la fin)
New-SmbShare -Name "Admin$Data" -Path "D:\AdminData"

# Lister les partages
Get-SmbShare

# Modifier un partage
Set-SmbShare -Name "Data" -Description "Nouvelle description"

# Supprimer un partage
Remove-SmbShare -Name "OldShare" -Force
```

### Permissions SMB vs NTFS

```
PERMISSIONS SMB VS NTFS
══════════════════════════════════════════════════════════

Règle : La permission la PLUS restrictive gagne.

Exemple :
  SMB : Finance-Users = Change
  NTFS : Finance-Users = Read

  Résultat : Read (NTFS plus restrictif)

Bonne pratique :
  SMB  : Everyone = Full Control (ou Change)
  NTFS : Permissions granulaires

→ Gérer uniquement via NTFS pour simplicité
```

```powershell
# Voir les permissions SMB
Get-SmbShareAccess -Name "Data"

# Modifier les permissions SMB
Grant-SmbShareAccess -Name "Data" -AccountName "CORP\IT-Team" -AccessRight Change
Revoke-SmbShareAccess -Name "Data" -AccountName "Everyone"

# Permissions NTFS
$acl = Get-Acl "D:\Data"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "CORP\Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.AddAccessRule($rule)
Set-Acl "D:\Data" $acl
```

### Access-Based Enumeration (ABE)

```powershell
# Activer ABE (masque les dossiers sans accès)
Set-SmbShare -Name "Data" -FolderEnumerationMode AccessBased

# Vérifier
Get-SmbShare -Name "Data" | Select-Object Name, FolderEnumerationMode
```

---

## DFS (Distributed File System)

### DFS Namespace

```powershell
# Installer DFS
Install-WindowsFeature FS-DFS-Namespace, FS-DFS-Replication -IncludeManagementTools

# Créer un namespace Domain-based (recommandé)
New-DfsnRoot -TargetPath "\\SRV-FILE-01\DFSRoot" `
    -Type DomainV2 `
    -Path "\\corp.local\Public"

# Ajouter un dossier au namespace
New-DfsnFolder -Path "\\corp.local\Public\Finance" `
    -TargetPath "\\SRV-FILE-01\Finance"

# Ajouter un target supplémentaire (redondance)
New-DfsnFolderTarget -Path "\\corp.local\Public\Finance" `
    -TargetPath "\\SRV-FILE-02\Finance"

# Lister les namespaces
Get-DfsnRoot
Get-DfsnFolder -Path "\\corp.local\Public\*"
```

### DFS Replication

```powershell
# Créer un groupe de réplication
New-DfsReplicationGroup -GroupName "Finance-Replication"

# Ajouter les membres
Add-DfsrMember -GroupName "Finance-Replication" -ComputerName "SRV-FILE-01","SRV-FILE-02"

# Créer le dossier répliqué
New-DfsReplicatedFolder -GroupName "Finance-Replication" `
    -FolderName "Finance" `
    -DfsnPath "\\corp.local\Public\Finance"

# Définir le membre primaire (initial sync)
Set-DfsrMembership -GroupName "Finance-Replication" `
    -FolderName "Finance" `
    -ComputerName "SRV-FILE-01" `
    -ContentPath "D:\Finance" `
    -PrimaryMember $true

# Configurer la connexion de réplication
Add-DfsrConnection -GroupName "Finance-Replication" `
    -SourceComputerName "SRV-FILE-01" `
    -DestinationComputerName "SRV-FILE-02"

# Vérifier l'état
Get-DfsrState -GroupName "Finance-Replication"
Get-DfsrBacklog -GroupName "Finance-Replication" -SourceComputerName "SRV-FILE-01" -DestinationComputerName "SRV-FILE-02"
```

---

## FSRM (File Server Resource Manager)

### Installation

```powershell
# Installer FSRM
Install-WindowsFeature FS-Resource-Manager -IncludeManagementTools
```

### Quotas

```powershell
# Créer un template de quota
New-FsrmQuotaTemplate -Name "Limit-5GB" `
    -Size 5GB `
    -SoftLimit `
    -Threshold (New-FsrmQuotaThreshold -Percentage 85 -Action (
        New-FsrmAction -Type Email -MailTo "[Admin Email]" -Subject "Quota Warning"
    ))

# Appliquer un quota à un dossier
New-FsrmQuota -Path "D:\Users\jdoe" -Template "Limit-5GB"

# Quota auto-apply (appliqué aux sous-dossiers)
New-FsrmAutoQuota -Path "D:\Users" -Template "Limit-5GB"

# Voir les quotas
Get-FsrmQuota
Get-FsrmQuota -Path "D:\Users\*"
```

### File Screening (Blocage de fichiers)

```powershell
# Créer un groupe de fichiers
New-FsrmFileGroup -Name "Blocked-Executables" `
    -IncludePattern "*.exe","*.bat","*.cmd","*.ps1"

# Créer un template de screening
New-FsrmFileScreenTemplate -Name "Block-Executables" `
    -IncludeGroup "Blocked-Executables" `
    -Active

# Appliquer le screening
New-FsrmFileScreen -Path "D:\UserShares" -Template "Block-Executables"

# Voir les file screens
Get-FsrmFileScreen
```

### Rapports de Stockage

```powershell
# Générer un rapport
New-FsrmStorageReport -Name "Monthly-Report" `
    -Namespace "D:\Data" `
    -ReportType LargeFiles, DuplicateFiles, FilesByOwner `
    -MailTo "admin@corp.local"

# Lancer un rapport immédiatement
Start-FsrmStorageReport -Name "Monthly-Report"

# Planifier les rapports
Set-FsrmStorageReport -Name "Monthly-Report" `
    -Schedule (New-FsrmScheduledTask -Time "02:00" -Monthly 1)
```

---

## Shadow Copies (VSS)

```powershell
# Activer les Shadow Copies sur un volume
vssadmin add shadowstorage /for=D: /on=D: /maxsize=10GB

# Créer un snapshot manuel
vssadmin create shadow /for=D:

# Planifier via tâche (2x par jour recommandé)
$trigger1 = New-ScheduledTaskTrigger -Daily -At "07:00"
$trigger2 = New-ScheduledTaskTrigger -Daily -At "12:00"
$action = New-ScheduledTaskAction -Execute "vssadmin" -Argument "create shadow /for=D:"
Register-ScheduledTask -TaskName "VSS-Snapshot" -Trigger $trigger1,$trigger2 -Action $action

# Lister les snapshots
vssadmin list shadows /for=D:

# Supprimer les anciens snapshots
vssadmin delete shadows /for=D: /oldest
```

---

## Bonnes Pratiques

```yaml
Checklist File Server:
  Organisation:
    - [ ] Structure de dossiers claire
    - [ ] Naming convention des partages
    - [ ] ABE activé

  Permissions:
    - [ ] NTFS uniquement (SMB = Everyone Full)
    - [ ] Groupes AD (pas d'utilisateurs directs)
    - [ ] Audit des permissions régulier

  DFS:
    - [ ] Namespace domain-based
    - [ ] Réplication pour redondance
    - [ ] Monitoring du backlog

  FSRM:
    - [ ] Quotas sur home directories
    - [ ] File screening (ransomware, exe)
    - [ ] Rapports mensuels

  Backup:
    - [ ] Shadow Copies 2x/jour
    - [ ] Backup externalisé
    - [ ] Test de restauration
```

---

**Voir aussi :**

- [Disk Management](disk-management.md) - Gestion des disques
- [Active Directory](active-directory.md) - Groupes et permissions
- [Windows Security](windows-security.md) - Sécurité fichiers
