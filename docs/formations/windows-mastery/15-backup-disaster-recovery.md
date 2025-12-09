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

```text
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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer une stratégie de backup complète pour un contrôleur de domaine avec réplication DFS-R

    **Contexte** : Vous devez protéger votre infrastructure Active Directory en configurant des sauvegardes automatiques du System State, en implémentant la réplication de SYSVOL vers un second serveur avec DFS-R, et en documentant les procédures de restauration d'urgence.

    **Tâches à réaliser** :

    1. Installer Windows Server Backup sur DC01 et configurer une politique de backup quotidien incluant le System State et le volume C: vers un partage réseau `\\NAS\Backups\DC01`
    2. Configurer le schedule de backup à 23h00 chaque jour avec VSS Copy Backup pour ne pas interférer avec d'autres solutions de backup
    3. Activer la Corbeille Active Directory sur la forêt pour permettre la récupération rapide d'objets supprimés
    4. Installer et configurer DFS-R entre DC01 et DC02 pour répliquer le dossier `C:\DFSData` de manière bidirectionnelle
    5. Créer un script PowerShell `Verify-BackupHealth.ps1` qui vérifie quotidiennement que les backups de tous les DC ont moins de 24h et envoie une alerte par email si problème
    6. Documenter dans un fichier la procédure de restauration authoritative d'un objet AD supprimé par erreur

    **Critères de validation** :

    - [ ] La politique de backup est active et le premier backup s'est exécuté avec succès
    - [ ] `Get-WBPolicy` affiche correctement la configuration avec schedule et System State inclus
    - [ ] La Corbeille AD est activée : `Get-ADOptionalFeature -Filter 'name -like "Recycle*"'` montre Enabled
    - [ ] DFS-R est opérationnel entre les deux serveurs : `Get-DfsrState` montre une réplication active
    - [ ] Le script de vérification identifie correctement l'état des backups et génère des alertes appropriées
    - [ ] La documentation de restauration couvre les étapes : DSRM boot, restauration non-authoritative, puis authoritative avec ntdsutil

??? quote "Solution"
    **Étape 1 : Configuration Windows Server Backup**

    ```powershell
    # Installer Windows Server Backup sur DC01
    Install-WindowsFeature -Name Windows-Server-Backup -IncludeManagementTools

    # Créer la politique de backup
    $policy = New-WBPolicy

    # Ajouter le System State (critique pour DC)
    Add-WBSystemState -Policy $policy

    # Ajouter le volume C:
    $volume = Get-WBVolume -AllVolumes | Where-Object MountPath -eq "C:"
    Add-WBVolume -Policy $policy -Volume $volume

    # Configurer la destination réseau
    $cred = Get-Credential -Message "Entrez les credentials pour \\NAS\Backups"
    $target = New-WBBackupTarget -NetworkPath "\\NAS\Backups\DC01" -Credential $cred
    Add-WBBackupTarget -Policy $policy -Target $target

    # Configurer le schedule : 23h00 tous les jours
    Set-WBSchedule -Policy $policy -Schedule "23:00"

    # VSS Copy Backup (recommandé pour les DC)
    Set-WBVssBackupOption -Policy $policy -VssCopyBackup

    # Appliquer la politique
    Set-WBPolicy -Policy $policy -AllowDeleteOldBackups

    # Vérifier la configuration
    Get-WBPolicy
    Get-WBSchedule -Policy (Get-WBPolicy)

    # Lancer un backup de test immédiat
    Start-WBBackup -Policy (Get-WBPolicy)

    # Surveiller le job
    Get-WBJob -Previous 1
    ```

    **Étape 2 : Activation de la Corbeille AD**

    ```powershell
    # Activer la Corbeille AD (nécessite Forest Level 2008 R2 minimum)
    # ATTENTION : Cette opération est irréversible
    Enable-ADOptionalFeature -Identity "Recycle Bin Feature" `
        -Scope ForestOrConfigurationSet `
        -Target "corp.local" `
        -Confirm:$false

    # Vérifier l'activation
    Get-ADOptionalFeature -Filter 'name -like "Recycle*"'

    # Tester la récupération d'un objet
    # Créer un utilisateur de test
    New-ADUser -Name "TestRecovery" -SamAccountName "testrecovery" `
        -UserPrincipalName "testrecovery@corp.local" `
        -Path "OU=Users,DC=corp,DC=local" `
        -Enabled $false

    # Supprimer l'utilisateur
    Remove-ADUser -Identity "testrecovery" -Confirm:$false

    # Récupérer depuis la Corbeille
    Get-ADObject -Filter 'Name -eq "TestRecovery"' -IncludeDeletedObjects |
        Restore-ADObject

    # Vérifier la restauration
    Get-ADUser -Identity "testrecovery"
    ```

    **Étape 3 : Configuration DFS-R**

    ```powershell
    # Installer DFS sur DC01 et DC02
    Install-WindowsFeature -Name FS-DFS-Replication, FS-DFS-Namespace `
        -IncludeManagementTools

    # Créer les dossiers locaux sur les deux serveurs
    New-Item -Path "C:\DFSData" -ItemType Directory -Force

    # Créer le groupe de réplication
    New-DfsReplicationGroup -GroupName "DCReplication"

    # Ajouter les membres (DC01 et DC02)
    Add-DfsrMember -GroupName "DCReplication" -ComputerName "DC01", "DC02"

    # Créer le dossier répliqué
    New-DfsReplicatedFolder -GroupName "DCReplication" -FolderName "SharedData"

    # Configurer DC01 comme membre primaire
    Set-DfsrMembership -GroupName "DCReplication" `
        -FolderName "SharedData" `
        -ComputerName "DC01" `
        -ContentPath "C:\DFSData" `
        -PrimaryMember $true `
        -Force

    # Configurer DC02 comme membre secondaire
    Set-DfsrMembership -GroupName "DCReplication" `
        -FolderName "SharedData" `
        -ComputerName "DC02" `
        -ContentPath "C:\DFSData" `
        -Force

    # Créer la connexion bidirectionnelle
    Add-DfsrConnection -GroupName "DCReplication" `
        -SourceComputerName "DC01" `
        -DestinationComputerName "DC02"

    Add-DfsrConnection -GroupName "DCReplication" `
        -SourceComputerName "DC02" `
        -DestinationComputerName "DC01"

    # Vérifier l'état de la réplication
    Get-DfsrState -ComputerName "DC01"
    Get-DfsReplicationGroup | Select-Object GroupName, DomainName
    Get-DfsrConnection -GroupName "DCReplication"

    # Tester la réplication
    # Sur DC01
    "Test de réplication DFS-R" | Out-File "C:\DFSData\test.txt"

    # Attendre quelques secondes puis vérifier sur DC02
    Start-Sleep -Seconds 10
    Invoke-Command -ComputerName DC02 -ScriptBlock {
        Get-Content "C:\DFSData\test.txt"
    }
    ```

    **Étape 4 : Script de vérification des backups**

    ```powershell
    # Verify-BackupHealth.ps1
    param(
        [string[]]$Servers = @("DC01", "DC02"),
        [int]$MaxAgeHours = 24,
        [string]$SmtpServer = "smtp.corp.local",
        [string]$AlertEmail = "admin@corp.local"
    )

    # Collecter l'état des backups
    $report = foreach ($server in $Servers) {
        try {
            $lastBackup = Invoke-Command -ComputerName $server -ScriptBlock {
                Get-WBJob -Previous 1
            } -ErrorAction Stop

            $ageHours = if ($lastBackup.StartTime) {
                [math]::Round(((Get-Date) - $lastBackup.StartTime).TotalHours, 1)
            } else {
                999
            }

            [PSCustomObject]@{
                Server       = $server
                LastBackup   = $lastBackup.StartTime
                Status       = $lastBackup.JobState
                AgeHours     = $ageHours
                Alert        = if ($ageHours -gt $MaxAgeHours) { "WARNING" } else { "OK" }
                ErrorMessage = $lastBackup.ErrorDescription
            }
        }
        catch {
            [PSCustomObject]@{
                Server       = $server
                LastBackup   = "ERROR"
                Status       = "UNKNOWN"
                AgeHours     = 999
                Alert        = "CRITICAL"
                ErrorMessage = $_.Exception.Message
            }
        }
    }

    # Afficher le rapport
    Write-Host "`n=== BACKUP HEALTH REPORT ===" -ForegroundColor Cyan
    $report | Format-Table -AutoSize

    # Générer une alerte si nécessaire
    $alerts = $report | Where-Object Alert -ne "OK"

    if ($alerts) {
        Write-Host "`nALERTE : Problèmes détectés!" -ForegroundColor Red

        $emailBody = @"
ALERTE BACKUP WINDOWS SERVER
=============================

Les serveurs suivants ont des problèmes de backup :

$($alerts | Format-Table -AutoSize | Out-String)

Veuillez vérifier immédiatement.

Date du rapport : $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
"@

        # Envoyer l'email d'alerte
        try {
            Send-MailMessage -To $AlertEmail `
                -From "backup-monitor@corp.local" `
                -Subject "ALERTE: Backup outdated sur $($alerts.Count) serveur(s)" `
                -Body $emailBody `
                -SmtpServer $SmtpServer `
                -Priority High

            Write-Host "Email d'alerte envoyé à $AlertEmail" -ForegroundColor Yellow
        }
        catch {
            Write-Host "Erreur lors de l'envoi de l'email : $_" -ForegroundColor Red
        }
    }
    else {
        Write-Host "`nTous les backups sont OK!" -ForegroundColor Green
    }

    # Sauvegarder le rapport
    $reportPath = "C:\BackupReports\Backup-Health-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    New-Item -Path "C:\BackupReports" -ItemType Directory -Force | Out-Null
    $report | Export-Csv -Path $reportPath -NoTypeInformation
    Write-Host "`nRapport sauvegardé : $reportPath" -ForegroundColor Cyan

    # Retourner le statut global
    return ($alerts.Count -eq 0)
    ```

    **Étape 5 : Documentation de restauration authoritative**

    Créez un fichier `Procedure-Restauration-AD.md` :

    ```markdown
    # Procédure de Restauration Authoritative AD

    ## Scénario : Un objet AD a été supprimé par erreur

    ### Option 1 : Corbeille AD (RECOMMANDÉ si activée)

    1. Identifier l'objet supprimé :
       ```powershell
       Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*NomUtilisateur*"' `
           -IncludeDeletedObjects -Properties whenChanged, LastKnownParent
       ```text

    2. Restaurer l'objet :
       ```powershell
       Get-ADObject -Filter 'Name -eq "NomUtilisateur"' -IncludeDeletedObjects |
           Restore-ADObject
       ```text

    ### Option 2 : Restauration Authoritative (si Corbeille non disponible)

    1. **Démarrer en DSRM (Directory Services Restore Mode)** :
       - Redémarrer le DC
       - Appuyer sur F8 au démarrage
       - Sélectionner "Directory Services Restore Mode"
       - Se connecter avec le mot de passe DSRM

    2. **Restauration Non-Authoritative** :
       ```cmd
       wbadmin get versions -backuptarget:E:
       wbadmin start systemstaterecovery -version:12/01/2025-01:00 -backuptarget:E:
       ```text

    3. **Redémarrer en mode DSRM** (à nouveau)

    4. **Marquer la restauration comme Authoritative** :
       ```cmd
       ntdsutil
       activate instance ntds
       authoritative restore
       restore object "CN=John Doe,OU=Users,DC=corp,DC=local"
       quit
       quit
       ```text

    5. **Redémarrer normalement**
       - L'objet restauré sera répliqué vers tous les autres DC
       - Son USN sera incrémenté pour forcer la réplication

    ## Restauration complète du DC

    1. Installer un nouveau serveur Windows
    2. Promouvoir en DC
    3. En DSRM, restaurer le System State
    4. Effectuer une restauration authoritative si nécessaire
    5. Redémarrer et laisser la réplication se stabiliser

    ## Tests réguliers

    - Tester la restauration tous les trimestres
    - Documenter le temps de restauration (RTO)
    - Vérifier la validité des backups
    ```

    **Validation finale**

    ```powershell
    # Vérifier que tout fonctionne

    # 1. Politique de backup
    Get-WBPolicy | Select-Object -ExpandProperty Schedule
    Get-WBSummary

    # 2. Corbeille AD
    Get-ADOptionalFeature -Filter 'name -like "Recycle*"' |
        Select-Object Name, EnabledScopes

    # 3. DFS-R
    Get-DfsReplicationGroup
    Get-DfsrBacklog -GroupName "DCReplication" `
        -SourceComputerName "DC01" `
        -DestinationComputerName "DC02"

    # 4. Exécuter le script de vérification
    .\Verify-BackupHealth.ps1
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

---

## Navigation

| | |
|:---|---:|
| [← Module 14 : Services Réseau Avancés](14-services-reseau-avances.md) | [Module 16 : Haute Disponibilité →](16-haute-disponibilite.md) |

[Retour au Programme](index.md){ .md-button }
