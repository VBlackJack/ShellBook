---
tags:
  - formation
  - windows-server
  - backup
  - disaster-recovery
  - dfsr
---

# Module 15 : Backup & Disaster Recovery

## Objectifs du Module

Ce module couvre les stratégies de sauvegarde et récupération :

- Configurer Windows Server Backup
- Sauvegarder et restaurer Active Directory
- Implémenter DFS-R pour la réplication
- Planifier la reprise après sinistre
- Utiliser Azure Backup (introduction)

**Durée :** 8 heures

**Niveau :** Ingénierie

---

## 1. Windows Server Backup

### 1.1 Installation et Configuration

```powershell
# Installer la feature
Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools

# Lancer la console
wbadmin.msc
```

### 1.2 Backup avec PowerShell

```powershell
# Importer le module
Import-Module WindowsServerBackup

# Créer une politique de backup
$policy = New-WBPolicy

# Ajouter les volumes
$volume = Get-WBVolume -AllVolumes | Where-Object MountPath -eq "C:"
Add-WBVolume -Policy $policy -Volume $volume

# Ajouter System State
Add-WBSystemState -Policy $policy

# Configurer la destination
$backupDisk = Get-WBDisk | Where-Object DiskNumber -eq 1
$target = New-WBBackupTarget -Disk $backupDisk
Add-WBBackupTarget -Policy $policy -Target $target

# Configurer le schedule
Set-WBSchedule -Policy $policy -Schedule "22:00"

# Appliquer la politique
Set-WBPolicy -Policy $policy

# Backup manuel immédiat
Start-WBBackup -Policy (Get-WBPolicy)

# Vérifier le statut
Get-WBJob -Previous 1
Get-WBSummary
```

### 1.3 Backup vers Partage Réseau

```powershell
# Backup vers UNC
$policy = New-WBPolicy
Add-WBSystemState -Policy $policy

$cred = Get-Credential
$target = New-WBBackupTarget -NetworkPath "\\NAS\Backups\DC01" -Credential $cred
Add-WBBackupTarget -Policy $policy -Target $target

# Backup unique
Start-WBBackup -Policy $policy
```

---

## 2. Sauvegarde Active Directory

### 2.1 Backup du System State

```powershell
# Le System State inclut:
# - Active Directory database (NTDS.dit)
# - SYSVOL
# - Registry
# - Boot files
# - Certificate Services database (si CA)

# Backup System State
wbadmin start systemstatebackup -backuptarget:E:

# Via PowerShell
$policy = New-WBPolicy
Add-WBSystemState -Policy $policy
$target = New-WBBackupTarget -VolumePath "E:"
Add-WBBackupTarget -Policy $policy -Target $target
Start-WBBackup -Policy $policy
```

### 2.2 Restauration AD

```powershell
# 1. Démarrer en DSRM (Directory Services Restore Mode)
# - Redémarrer le serveur
# - Appuyer sur F8
# - Choisir "Directory Services Restore Mode"

# 2. Restaurer le System State
wbadmin start systemstaterecovery -version:<version> -backuptarget:E:

# 3. Types de restauration:
# Non-authoritative (par défaut): Les objets restaurés seront écrasés par la réplication
# Authoritative: Les objets restaurés seront répliqués vers les autres DC

# Restauration authoritative (après non-auth)
ntdsutil
  activate instance ntds
  authoritative restore
  restore object "CN=DeletedUser,OU=Users,DC=corp,DC=local"
  quit
  quit
```

### 2.3 Corbeille AD

```powershell
# Activer la Corbeille AD (irréversible, nécessite Forest Level 2008 R2+)
Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target "corp.local" -Confirm:$false

# Récupérer un objet supprimé
Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*DeletedUser*"' -IncludeDeletedObjects |
    Restore-ADObject

# Lister les objets supprimés
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties * |
    Select-Object Name, whenChanged, LastKnownParent

# Récupérer avec le parent correct
Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*John*"' -IncludeDeletedObjects |
    Restore-ADObject -TargetPath "OU=Users,DC=corp,DC=local"
```

---

## 3. DFS-R (Distributed File System Replication)

### 3.1 Installation

```powershell
# Installer DFS
Install-WindowsFeature -Name FS-DFS-Replication, FS-DFS-Namespace -IncludeManagementTools

# Ouvrir la console
dfsmgmt.msc
```

### 3.2 Configuration avec PowerShell

```powershell
# Créer un groupe de réplication
New-DfsReplicationGroup -GroupName "DataReplication"

# Ajouter les membres
Add-DfsrMember -GroupName "DataReplication" -ComputerName "SRV01", "SRV02"

# Configurer le dossier répliqué
New-DfsReplicatedFolder -GroupName "DataReplication" -FolderName "SharedData"

# Définir les chemins locaux
Set-DfsrMembership -GroupName "DataReplication" `
    -FolderName "SharedData" `
    -ComputerName "SRV01" `
    -ContentPath "C:\Data" `
    -PrimaryMember $true

Set-DfsrMembership -GroupName "DataReplication" `
    -FolderName "SharedData" `
    -ComputerName "SRV02" `
    -ContentPath "C:\Data"

# Créer la connexion de réplication
Add-DfsrConnection -GroupName "DataReplication" -SourceComputerName "SRV01" -DestinationComputerName "SRV02"

# Vérifier l'état
Get-DfsrState -ComputerName "SRV01"
Get-DfsReplicationGroup
```

---

## 4. Plan de Disaster Recovery

### 4.1 Documentation DR

```
PLAN DE DISASTER RECOVERY
─────────────────────────

1. INVENTAIRE
   - Liste des serveurs critiques
   - Dépendances applicatives
   - Contacts d'urgence

2. RPO/RTO
   - RPO (Recovery Point Objective): Perte de données acceptable
   - RTO (Recovery Time Objective): Temps de restauration

3. PROCÉDURES
   - Restauration DC
   - Restauration File Server
   - Restauration Application Server
   - Test de DR (planning)

4. VALIDATION
   - Tests réguliers (trimestriels)
   - Documentation des résultats
```

### 4.2 Script de Vérification des Backups

```powershell
# Verify-Backups.ps1
$servers = @("DC01", "DC02", "FILE01")
$maxAge = 24  # heures

$report = foreach ($server in $servers) {
    $lastBackup = Invoke-Command -ComputerName $server -ScriptBlock {
        Get-WBJob -Previous 1
    } -ErrorAction SilentlyContinue

    [PSCustomObject]@{
        Server = $server
        LastBackup = $lastBackup.StartTime
        Status = $lastBackup.JobState
        AgeHours = if ($lastBackup) { [math]::Round(((Get-Date) - $lastBackup.StartTime).TotalHours, 1) } else { "N/A" }
        Alert = if ($lastBackup -and ((Get-Date) - $lastBackup.StartTime).TotalHours -gt $maxAge) { "WARNING" } else { "OK" }
    }
}

$report | Format-Table -AutoSize

# Alerter si problème
if ($report | Where-Object Alert -eq "WARNING") {
    Send-MailMessage -To "admin@corp.local" -From "backup@corp.local" `
        -Subject "ALERT: Backup outdated" -Body ($report | Out-String) `
        -SmtpServer "smtp.corp.local"
}
```

---

## 5. Azure Backup (Introduction)

```powershell
# Installer l'agent Azure Backup (MARS)
# Télécharger depuis le portail Azure

# Configurer via GUI
# 1. Créer un Recovery Services Vault dans Azure
# 2. Télécharger les credentials
# 3. Installer l'agent
# 4. Enregistrer le serveur
# 5. Configurer le schedule

# PowerShell pour Azure (Az module)
# Install-Module Az.RecoveryServices

# Lister les vaults
Get-AzRecoveryServicesVault

# Vérifier les jobs
Get-AzRecoveryServicesBackupJob -From (Get-Date).AddDays(-7)
```

---

## 6. Exercice Pratique

### Configuration Backup Complète

```powershell
# 1. Installer Windows Server Backup
Install-WindowsFeature -Name Windows-Server-Backup

# 2. Créer une politique de backup quotidien
$policy = New-WBPolicy

# System State (obligatoire pour DC)
Add-WBSystemState -Policy $policy

# Volume C:
Add-WBVolume -Policy $policy -Volume (Get-WBVolume -AllVolumes | Where-Object MountPath -eq "C:")

# Destination
$target = New-WBBackupTarget -NetworkPath "\\NAS\Backups\$env:COMPUTERNAME" -Credential (Get-Credential)
Add-WBBackupTarget -Policy $policy -Target $target

# Schedule: 22h tous les jours
Set-WBSchedule -Policy $policy -Schedule "22:00"

# VSS full backup
Set-WBVssBackupOption -Policy $policy -VssCopyBackup

# Appliquer
Set-WBPolicy -Policy $policy -AllowDeleteOldBackups

# 3. Vérifier
Get-WBPolicy
Get-WBSchedule -Policy (Get-WBPolicy)
```

---

## Quiz

1. **Que contient le System State ?**
   - [ ] A. Fichiers utilisateur
   - [ ] B. AD database, SYSVOL, Registry, Boot files
   - [ ] C. Applications installées

2. **Quelle feature permet la réplication de fichiers entre serveurs ?**
   - [ ] A. Storage Replica
   - [ ] B. DFS-R
   - [ ] C. BranchCache

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 14 : Services Réseau Avancés](14-services-reseau-avances.md)

**Suivant :** [Module 16 : Haute Disponibilité](16-haute-disponibilite.md)

---

**Fin du Niveau 3 - Ingénierie**

Vous maîtrisez maintenant Active Directory, la sécurité et les services réseau avancés. Le Niveau 4 couvre les architectures haute disponibilité, les conteneurs et l'Infrastructure as Code.
