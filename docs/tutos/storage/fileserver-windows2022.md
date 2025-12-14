---
tags:
  - tutos
  - fileserver
  - smb
  - storage
  - windows
  - dfs
---

# File Server sur Windows Server 2022

Configuration du rôle **File Server** avec partages SMB et DFS.

| Composant | Version |
|-----------|---------|
| Windows Server | 2022 |
| SMB | 3.1.1 |

**Durée estimée :** 30 minutes

---

## 1. Installation du rôle

```powershell
# Installer File Server
Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools

# Installer DFS (optionnel)
Install-WindowsFeature -Name FS-DFS-Namespace, FS-DFS-Replication -IncludeManagementTools

# Vérifier
Get-WindowsFeature -Name FS-*
```

---

## 2. Créer un partage SMB

### Via PowerShell

```powershell
# Créer le dossier
New-Item -Path "D:\Shares\Commun" -ItemType Directory

# Créer le partage
New-SmbShare -Name "Commun" `
    -Path "D:\Shares\Commun" `
    -FullAccess "Domain Admins" `
    -ChangeAccess "Domain Users" `
    -ReadAccess "Everyone" `
    -Description "Partage commun"

# Vérifier
Get-SmbShare -Name "Commun"
```

### Permissions NTFS

```powershell
# Définir les permissions NTFS
$acl = Get-Acl "D:\Shares\Commun"

# Ajouter Domain Users en modification
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Domain Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "D:\Shares\Commun" $acl
```

---

## 3. Partage avec ABE (Access-Based Enumeration)

```powershell
# Créer un partage avec ABE activé
New-SmbShare -Name "Projets" `
    -Path "D:\Shares\Projets" `
    -FullAccess "Domain Admins" `
    -FolderEnumerationMode AccessBased `
    -CachingMode None

# L'ABE masque les dossiers auxquels l'utilisateur n'a pas accès
```

---

## 4. Quotas de disque

```powershell
# Installer le gestionnaire de quotas
Install-WindowsFeature -Name FS-Resource-Manager

# Créer un quota
New-FsrmQuota -Path "D:\Shares\Commun" `
    -Size 10GB `
    -Description "Quota 10GB par dossier"

# Quota avec alertes
New-FsrmQuotaThreshold -Percentage 80 -Action (
    New-FsrmAction -Type Email -MailTo "admin@example.lan" -Subject "Quota 80%"
)
```

---

## 5. DFS Namespace

### Créer un namespace

```powershell
# Namespace autonome
New-DfsnRoot -Path "\\srv-files\Partages" `
    -TargetPath "\\srv-files\Shares" `
    -Type Standalone

# Namespace domaine (recommandé)
New-DfsnRoot -Path "\\example.lan\Partages" `
    -TargetPath "\\srv-files\Shares" `
    -Type DomainV2
```

### Ajouter des dossiers DFS

```powershell
# Ajouter un dossier au namespace
New-DfsnFolder -Path "\\example.lan\Partages\Commun" `
    -TargetPath "\\srv-files\Commun"

# Avec plusieurs cibles (réplication)
New-DfsnFolderTarget -Path "\\example.lan\Partages\Commun" `
    -TargetPath "\\srv-files2\Commun"
```

---

## 6. DFS Replication

```powershell
# Créer un groupe de réplication
New-DfsReplicationGroup -GroupName "RG-Commun"

# Ajouter les membres
Add-DfsrMember -GroupName "RG-Commun" -ComputerName "srv-files", "srv-files2"

# Créer le dossier répliqué
New-DfsReplicatedFolder -GroupName "RG-Commun" `
    -FolderName "Commun" `
    -DfsnPath "\\example.lan\Partages\Commun"

# Définir le membre principal
Set-DfsrMembership -GroupName "RG-Commun" `
    -FolderName "Commun" `
    -ComputerName "srv-files" `
    -PrimaryMember $true `
    -ContentPath "D:\Shares\Commun"
```

---

## 7. Shadow Copies (VSS)

```powershell
# Activer les Shadow Copies sur D:
vssadmin add shadowstorage /for=D: /on=D: /maxsize=10GB

# Créer une shadow copy
vssadmin create shadow /for=D:

# Planifier (via tâche planifiée)
$action = New-ScheduledTaskAction -Execute "vssadmin" -Argument "create shadow /for=D:"
$trigger = New-ScheduledTaskTrigger -Daily -At "12:00"
Register-ScheduledTask -TaskName "ShadowCopy" -Action $action -Trigger $trigger
```

---

## 8. Commandes de gestion

```powershell
# Lister tous les partages
Get-SmbShare

# Sessions actives
Get-SmbSession

# Fichiers ouverts
Get-SmbOpenFile

# Fermer un fichier
Close-SmbOpenFile -FileId <id> -Force

# Statistiques
Get-SmbShareAccess -Name "Commun"

# Supprimer un partage
Remove-SmbShare -Name "Test" -Force
```

---

## 9. Sécurité SMB

```powershell
# Désactiver SMB1 (vulnérable)
Set-SmbServerConfiguration -EnableSMB1Protocol $false

# Activer le chiffrement SMB
Set-SmbServerConfiguration -EncryptData $true

# Chiffrement par partage
Set-SmbShare -Name "Confidentiel" -EncryptData $true

# Vérifier la configuration
Get-SmbServerConfiguration
```

---

## 10. Audit des accès

```powershell
# Activer l'audit sur un dossier
$acl = Get-Acl "D:\Shares\Commun"
$rule = New-Object System.Security.AccessControl.FileSystemAuditRule(
    "Everyone", "Delete,Write", "ContainerInherit,ObjectInherit", "None", "Success,Failure"
)
$acl.AddAuditRule($rule)
Set-Acl "D:\Shares\Commun" $acl

# Voir les événements d'audit
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4663]]" -MaxEvents 50
```

---

## Dépannage

```powershell
# Tester l'accès
Test-Path "\\srv-files\Commun"

# Vérifier les permissions effectives
Get-SmbShareAccess -Name "Commun"
Get-Acl "D:\Shares\Commun" | Format-List

# Logs DFS
Get-WinEvent -LogName "DFS Replication" -MaxEvents 20

# État réplication DFS
Get-DfsrState -GroupName "RG-Commun"
```

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale |
