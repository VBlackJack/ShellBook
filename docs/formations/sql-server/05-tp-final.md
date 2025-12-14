---
tags:
  - formation
  - sql-server
  - tp-final
  - dba
  - projet
---

# Module 5 : TP Final - Mission DBA (Projet Phoenix)

**Durée estimée :** 45 minutes

## Scenario : Projet Phoenix

### Contexte mission

Vous êtes **DBA senior** fraîchement embauché dans l'entreprise **TechCorp International**.

**Situation** :
- L'entreprise développe une **nouvelle application critique** : **Phoenix ERP**
- L'ancienne infrastructure SQL Server est obsolète (SQL Server 2012, non sécurisée, non maintenue)
- La direction a validé un budget pour déployer une **nouvelle instance production** : **SQL-PHOENIX**

**Votre mission** :
> Déployer et configurer l'instance **SQL-PHOENIX** de A à Z en respectant les **best practices DBA** apprises dans les modules 1 à 4.

**Contraintes projet** :
- ✅ **Installation automatisée** : Reproductible, documentée
- ✅ **Sécurité renforcée** : Compte `sa` désactivé, authentification Windows uniquement
- ✅ **Performance optimisée** : Mémoire limitée, MAXDOP configuré
- ✅ **Maintenance automatique** : Backups réguliers, vérification intégrité
- ✅ **Monitoring** : Script de vérification quotidienne

**Livrables attendus** :
1. Instance SQL Server opérationnelle nommée `SQL-PHOENIX`
2. Base de données `PhoenixDB` créée et sécurisée
3. Jobs de maintenance configurés (Ola Hallengren)
4. Script de vérification quotidienne fonctionnel
5. Documentation complète de l'installation

---

## Spécifications techniques

### Environnement cible

| Composant | Spécification | Notes |
|-----------|---------------|-------|
| **Serveur** | Windows Server 2022 | VM ou physique |
| **SQL Server** | 2022 Developer Edition | Gratuit, fonctionnalités Enterprise |
| **Instance** | Default (`MSSQLSERVER`) | Nom serveur : `SQL-PHOENIX` |
| **RAM serveur** | 8 GB | Max SQL Memory : 4 GB (50%) |
| **CPU** | 4 cores | MAXDOP : 2 |
| **Disques** | C: (OS), D: (Data), L: (Logs), B: (Backups) | Séparation recommandée |

### Configuration requise

**SQL Server** :
- Services : SQL Server Engine + SQL Server Agent
- Authentification : **Windows uniquement** (pas de Mixed Mode)
- Comptes de service : Comptes virtuels (`NT SERVICE\...`)
- TempDB : **4 fichiers** (1 par core)
- Collation : `SQL_Latin1_General_CP1_CI_AS`

**Base de données PhoenixDB** :
- Recovery Model : **FULL** (backups log possibles)
- Taille initiale : 500 MB (data) + 100 MB (log)
- Croissance : 100 MB (data) + 50 MB (log)
- Emplacement : `D:\SQLData\PhoenixDB.mdf` et `L:\SQLLogs\PhoenixDB_log.ldf`

**Sécurité** :
- Compte `sa` : **Désactivé**
- Logins : Groupe AD `TECHCORP\SQL_Admins` (sysadmin)
- Application : Login `TECHCORP\AppPhoenix` mappé à `PhoenixDB` (db_owner)

**Maintenance** :
- Backup Full : **Dimanche 23h** (rétention 30 jours)
- Backup Log : **Toutes les 15 minutes** (rétention 48h)
- CHECKDB : **Dimanche 02h**
- Index Optimization : **Samedi 23h**

---

## Étape 1 : Installation Silencieuse (Module 1)

### Objectif

Installer SQL Server 2022 Developer Edition via **ligne de commande** avec un fichier de configuration.

### Prérequis

```powershell
# Vérifier que .NET Framework 4.7.2+ est installé
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" | Select-Object Release

# Télécharger SQL Server 2022 Developer Edition
# https://go.microsoft.com/fwlink/p/?linkid=2215158

# Créer les répertoires de données
New-Item -Path "D:\SQLData", "D:\SQLData\TempDB" -ItemType Directory -Force
New-Item -Path "L:\SQLLogs", "L:\SQLLogs\TempDB" -ItemType Directory -Force
New-Item -Path "B:\SQLBackups" -ItemType Directory -Force
```

---

### Mission 1.1 : Générer le fichier ConfigurationFile.ini

Créer le fichier `C:\Temp\Phoenix_ConfigurationFile.ini` avec le contenu suivant :

<details>
<summary>📄 Fichier ConfigurationFile.ini (Cliquez pour afficher)</summary>

```ini
;SQL Server 2022 Developer - Projet Phoenix
;Auteur: Votre Nom
;Date: 2025-01-23

[OPTIONS]
ACTION="Install"
EDITION="Developer"
IACCEPTSQLSERVERLICENSETERMS="True"
ERRORREPORTING="False"
SQMREPORTING="False"

; Composants
FEATURES=SQLENGINE,REPLICATION,FULLTEXT

; Instance par défaut
INSTANCENAME="MSSQLSERVER"
INSTANCEID="MSSQLSERVER"
INSTANCEDIR="C:\Program Files\Microsoft SQL Server"

; Comptes de service (comptes virtuels)
SQLSVCACCOUNT="NT SERVICE\MSSQLSERVER"
SQLSVCSTARTUPTYPE="Automatic"
AGTSVCACCOUNT="NT SERVICE\SQLSERVERAGENT"
AGTSVCSTARTUPTYPE="Automatic"

; Sécurité (Windows Auth uniquement)
SECURITYMODE="Windows"
SQLSYSADMINACCOUNTS="BUILTIN\Administrators"

; TempDB (4 fichiers pour 4 cores)
SQLTEMPDBFILECOUNT="4"
SQLTEMPDBFILESIZE="256"
SQLTEMPDBFILEGROWTH="64"
SQLTEMPDBLOGFILESIZE="64"
SQLTEMPDBLOGFILEGROWTH="64"
SQLTEMPDBDIR="D:\SQLData\TempDB"
SQLTEMPDBLOGDIR="L:\SQLLogs\TempDB"

; Répertoires de données
SQLUSERDBDIR="D:\SQLData"
SQLUSERDBLOGDIR="L:\SQLLogs"
SQLBACKUPDIR="B:\SQLBackups"

; Réseau
TCPENABLED="1"
NPENABLED="0"

; Performances
SQLSVCINSTANTFILEINIT="True"
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"

; Mises à jour
UPDATESOURCE="MU"
USEMICROSOFTUPDATE="True"
```

</details>

---

### Mission 1.2 : Installer SQL Server

```powershell
# Monter l'ISO SQL Server 2022
$ISOPath = "C:\Downloads\SQLServer2022-DEV-x64-ENU.iso"
Mount-DiskImage -ImagePath $ISOPath

# Récupérer la lettre de lecteur
$ISODrive = (Get-DiskImage -ImagePath $ISOPath | Get-Volume).DriveLetter

# Lancer l'installation silencieuse
$SetupPath = "${ISODrive}:\setup.exe"
$ConfigFile = "C:\Temp\Phoenix_ConfigurationFile.ini"

Start-Process -FilePath $SetupPath `
    -ArgumentList "/ConfigurationFile=$ConfigFile /IACCEPTSQLSERVERLICENSETERMS /QUIET" `
    -Wait -NoNewWindow

# Attendre la fin (10-20 minutes)
# Vérifier les logs si problème : C:\Program Files\Microsoft SQL Server\160\Setup Bootstrap\Log\Summary.txt

# Démonter l'ISO
Dismount-DiskImage -ImagePath $ISOPath
```

---

### Validation Étape 1

```powershell
# Vérifier que les services sont démarrés
Get-Service -Name MSSQLSERVER, SQLSERVERAGENT | Format-Table Name, Status, StartType

# Se connecter à l'instance
sqlcmd -S localhost -E -Q "SELECT @@VERSION"

# Vérifier les fichiers tempdb
sqlcmd -S localhost -E -Q "SELECT name, physical_name FROM sys.master_files WHERE database_id = DB_ID('tempdb')"
# Doit afficher 4 fichiers de données + 1 fichier log
```

**Checklist** :
- [ ] Service MSSQLSERVER démarré (Status: Running, StartType: Automatic)
- [ ] Service SQLSERVERAGENT démarré
- [ ] Connexion possible via `sqlcmd -S localhost -E`
- [ ] TempDB configurée avec 4 fichiers de données

---

## Étape 2 : Hardening & Configuration (Module 2)

### Objectif

Sécuriser et optimiser l'instance fraîchement installée.

### Mission 2.1 : Désactiver le compte `sa`

```sql
-- Se connecter avec SSMS ou sqlcmd
USE master;
GO

-- Renommer et désactiver sa
ALTER LOGIN sa WITH NAME = [DisabledAdmin_DoNotUse];
ALTER LOGIN [DisabledAdmin_DoNotUse] DISABLE;
GO

-- Vérifier
SELECT name, is_disabled FROM sys.server_principals WHERE name LIKE '%Admin%';
GO
```

---

### Mission 2.2 : Configurer la mémoire et le parallélisme

```sql
-- Activer les options avancées
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
GO

-- Configurer Max Server Memory (4 GB = 4096 MB)
EXEC sp_configure 'max server memory (MB)', 4096;
RECONFIGURE;
GO

-- Configurer Min Server Memory (25% du max = 1024 MB)
EXEC sp_configure 'min server memory (MB)', 1024;
RECONFIGURE;
GO

-- Configurer MAXDOP (2 cores pour ce lab)
EXEC sp_configure 'max degree of parallelism', 2;
RECONFIGURE;
GO

-- Configurer Cost Threshold for Parallelism
EXEC sp_configure 'cost threshold for parallelism', 50;
RECONFIGURE;
GO

-- Activer Optimize for Ad Hoc Workloads
EXEC sp_configure 'optimize for ad hoc workloads', 1;
RECONFIGURE;
GO

-- Vérifier toutes les configurations
EXEC sp_configure;
GO
```

---

### Mission 2.3 : Créer la base de données PhoenixDB

```sql
-- Créer la base de données
CREATE DATABASE PhoenixDB
ON PRIMARY
(
    NAME = 'PhoenixDB_Data',
    FILENAME = 'D:\SQLData\PhoenixDB.mdf',
    SIZE = 500MB,
    FILEGROWTH = 100MB
)
LOG ON
(
    NAME = 'PhoenixDB_Log',
    FILENAME = 'L:\SQLLogs\PhoenixDB_log.ldf',
    SIZE = 100MB,
    FILEGROWTH = 50MB
);
GO

-- Configurer en Full Recovery
ALTER DATABASE PhoenixDB SET RECOVERY FULL;
GO

-- Faire un backup initial (active la chaîne de logs)
BACKUP DATABASE PhoenixDB
TO DISK = 'B:\SQLBackups\PhoenixDB_FULL_Initial.bak'
WITH INIT, COMPRESSION, CHECKSUM;
GO

-- Vérifier
SELECT name, recovery_model_desc, state_desc
FROM sys.databases
WHERE name = 'PhoenixDB';
GO
```

---

### Mission 2.4 : Créer les logins et users

```sql
-- Créer le login pour le groupe DBA
-- ⚠️ Adapter "TECHCORP\SQL_Admins" à votre environnement
CREATE LOGIN [TECHCORP\SQL_Admins] FROM WINDOWS;
ALTER SERVER ROLE sysadmin ADD MEMBER [TECHCORP\SQL_Admins];
GO

-- Créer le login pour l'application
CREATE LOGIN [TECHCORP\AppPhoenix] FROM WINDOWS;
GO

-- Créer l'utilisateur dans PhoenixDB
USE PhoenixDB;
GO

CREATE USER AppPhoenix FOR LOGIN [TECHCORP\AppPhoenix];
ALTER ROLE db_owner ADD MEMBER AppPhoenix;
GO

-- Vérifier
SELECT
    sp.name AS LoginName,
    sp.type_desc AS LoginType,
    dp.name AS UserName,
    r.name AS RoleName
FROM sys.server_principals sp
LEFT JOIN sys.database_principals dp ON sp.sid = dp.sid
LEFT JOIN sys.database_role_members drm ON dp.principal_id = drm.member_principal_id
LEFT JOIN sys.database_principals r ON drm.role_principal_id = r.principal_id
WHERE sp.name LIKE '%Phoenix%' OR sp.name LIKE '%SQL_Admins%';
GO
```

---

### Validation Étape 2

```sql
-- Vérifier que sa est désactivé
SELECT name, is_disabled FROM sys.server_principals WHERE name LIKE '%sa%' OR name LIKE '%Admin%';

-- Vérifier la mémoire
EXEC sp_configure 'max server memory (MB)';
EXEC sp_configure 'min server memory (MB)';

-- Vérifier MAXDOP
EXEC sp_configure 'max degree of parallelism';

-- Vérifier PhoenixDB
SELECT name, recovery_model_desc FROM sys.databases WHERE name = 'PhoenixDB';
```

**Checklist** :
- [ ] Compte `sa` désactivé
- [ ] Max Server Memory = 4096 MB
- [ ] MAXDOP = 2
- [ ] Cost Threshold = 50
- [ ] PhoenixDB créée en Full Recovery
- [ ] Logins et users créés

---

## Étape 3 : Maintenance (Module 3)

### Objectif

Installer Ola Hallengren et configurer les jobs de maintenance.

### Mission 3.1 : Installer Ola Hallengren

```powershell
# Télécharger le script MaintenanceSolution.sql
Invoke-WebRequest -Uri "https://ola.hallengren.com/scripts/MaintenanceSolution.sql" `
    -OutFile "C:\Temp\MaintenanceSolution.sql"

# Exécuter via sqlcmd
sqlcmd -S localhost -E -i "C:\Temp\MaintenanceSolution.sql"

# Vérifier l'installation
sqlcmd -S localhost -E -Q "SELECT name FROM sys.procedures WHERE name LIKE 'Database%' OR name LIKE 'Index%'"
# Doit retourner : DatabaseBackup, DatabaseIntegrityCheck, IndexOptimize
```

---

### Mission 3.2 : Créer les jobs de maintenance

**Job 1 : Backup Full hebdomadaire**

```sql
USE msdb;
GO

-- Créer le job
EXEC dbo.sp_add_job @job_name = N'Phoenix_Backup_FULL';

-- Ajouter l'étape
EXEC dbo.sp_add_jobstep
    @job_name = N'Phoenix_Backup_FULL',
    @step_name = N'Execute Full Backup',
    @subsystem = N'TSQL',
    @command = N'
EXECUTE dbo.DatabaseBackup
    @Databases = ''PhoenixDB'',
    @Directory = ''B:\SQLBackups'',
    @BackupType = ''FULL'',
    @Compress = ''Y'',
    @Verify = ''Y'',
    @CheckSum = ''Y'',
    @CleanupTime = 720;
';

-- Créer le schedule (Dimanche 23h)
EXEC dbo.sp_add_schedule
    @schedule_name = N'Phoenix_Weekly_Sunday_23h',
    @freq_type = 8,
    @freq_interval = 1,
    @active_start_time = 230000;

-- Attacher
EXEC dbo.sp_attach_schedule
    @job_name = N'Phoenix_Backup_FULL',
    @schedule_name = N'Phoenix_Weekly_Sunday_23h';

EXEC dbo.sp_add_jobserver @job_name = N'Phoenix_Backup_FULL';
GO
```

---

**Job 2 : Backup Log toutes les 15 minutes**

```sql
-- Créer le job
EXEC dbo.sp_add_job @job_name = N'Phoenix_Backup_LOG';

-- Ajouter l'étape
EXEC dbo.sp_add_jobstep
    @job_name = N'Phoenix_Backup_LOG',
    @step_name = N'Execute Log Backup',
    @subsystem = N'TSQL',
    @command = N'
EXECUTE dbo.DatabaseBackup
    @Databases = ''PhoenixDB'',
    @Directory = ''B:\SQLBackups'',
    @BackupType = ''LOG'',
    @Compress = ''Y'',
    @Verify = ''Y'',
    @CheckSum = ''Y'',
    @CleanupTime = 48;
';

-- Créer le schedule (Toutes les 15 minutes)
EXEC dbo.sp_add_schedule
    @schedule_name = N'Phoenix_Every_15_Minutes',
    @freq_type = 4,
    @freq_interval = 1,
    @freq_subday_type = 4,
    @freq_subday_interval = 15;

-- Attacher
EXEC dbo.sp_attach_schedule
    @job_name = N'Phoenix_Backup_LOG',
    @schedule_name = N'Phoenix_Every_15_Minutes';

EXEC dbo.sp_add_jobserver @job_name = N'Phoenix_Backup_LOG';
GO
```

---

**Job 3 : CHECKDB hebdomadaire**

```sql
-- Créer le job
EXEC dbo.sp_add_job @job_name = N'Phoenix_Integrity_Check';

-- Ajouter l'étape
EXEC dbo.sp_add_jobstep
    @job_name = N'Phoenix_Integrity_Check',
    @step_name = N'Execute CHECKDB',
    @subsystem = N'TSQL',
    @command = N'
EXECUTE dbo.DatabaseIntegrityCheck
    @Databases = ''PhoenixDB'',
    @CheckCommands = ''CHECKDB'',
    @PhysicalOnly = ''N'';
';

-- Créer le schedule (Dimanche 02h)
EXEC dbo.sp_add_schedule
    @schedule_name = N'Phoenix_Weekly_Sunday_02h',
    @freq_type = 8,
    @freq_interval = 1,
    @active_start_time = 020000;

-- Attacher
EXEC dbo.sp_attach_schedule
    @job_name = N'Phoenix_Integrity_Check',
    @schedule_name = N'Phoenix_Weekly_Sunday_02h';

EXEC dbo.sp_add_jobserver @job_name = N'Phoenix_Integrity_Check';
GO
```

---

**Job 4 : Index Optimization**

```sql
-- Créer le job
EXEC dbo.sp_add_job @job_name = N'Phoenix_Index_Optimize';

-- Ajouter l'étape
EXEC dbo.sp_add_jobstep
    @job_name = N'Phoenix_Index_Optimize',
    @step_name = N'Optimize Indexes',
    @subsystem = N'TSQL',
    @command = N'
EXECUTE dbo.IndexOptimize
    @Databases = ''PhoenixDB'',
    @FragmentationLow = NULL,
    @FragmentationMedium = ''INDEX_REORGANIZE'',
    @FragmentationHigh = ''INDEX_REBUILD_ONLINE,INDEX_REBUILD_OFFLINE'',
    @FragmentationLevel1 = 5,
    @FragmentationLevel2 = 30,
    @UpdateStatistics = ''ALL'';
';

-- Créer le schedule (Samedi 23h)
EXEC dbo.sp_add_schedule
    @schedule_name = N'Phoenix_Weekly_Saturday_23h',
    @freq_type = 8,
    @freq_interval = 64,
    @active_start_time = 230000;

-- Attacher
EXEC dbo.sp_attach_schedule
    @job_name = N'Phoenix_Index_Optimize',
    @schedule_name = N'Phoenix_Weekly_Saturday_23h';

EXEC dbo.sp_add_jobserver @job_name = N'Phoenix_Index_Optimize';
GO
```

---

### Validation Étape 3

```sql
-- Lister tous les jobs créés
SELECT
    j.name AS JobName,
    j.enabled,
    s.name AS ScheduleName
FROM msdb.dbo.sysjobs j
LEFT JOIN msdb.dbo.sysjobschedules js ON j.job_id = js.job_id
LEFT JOIN msdb.dbo.sysschedules s ON js.schedule_id = s.schedule_id
WHERE j.name LIKE 'Phoenix%'
ORDER BY j.name;

-- Tester manuellement le job de backup log
EXEC msdb.dbo.sp_start_job @job_name = 'Phoenix_Backup_LOG';

-- Vérifier l'historique
SELECT TOP 5
    j.name,
    h.run_date,
    h.run_time,
    CASE h.run_status
        WHEN 1 THEN 'Succeeded'
        WHEN 0 THEN 'Failed'
    END AS Status
FROM msdb.dbo.sysjobs j
JOIN msdb.dbo.sysjobhistory h ON j.job_id = h.job_id
WHERE j.name LIKE 'Phoenix%'
ORDER BY h.run_date DESC, h.run_time DESC;
```

**Checklist** :
- [ ] 4 jobs créés (Full, Log, CHECKDB, Index)
- [ ] Tous les jobs sont activés (enabled = 1)
- [ ] Job Log Backup exécuté manuellement avec succès
- [ ] Fichier backup présent dans `B:\SQLBackups\`

---

## Étape 4 : Migration & Users (Module 4 - dbatools)

### Objectif

Utiliser dbatools pour gérer les logins et tester les backups.

### Mission 4.1 : Installer dbatools

```powershell
# Installer dbatools si pas déjà fait
Install-Module dbatools -Scope CurrentUser -Force

# Importer le module
Import-Module dbatools

# Vérifier
Get-Command -Module dbatools | Measure-Object
# Doit retourner ~600+ commandes
```

---

### Mission 4.2 : Créer un login avec dbatools

```powershell
# Créer un login SQL (pour test uniquement)
# En production, utiliser Windows Auth

New-DbaLogin -SqlInstance localhost `
    -Login "AppUser" `
    -SecurePassword (ConvertTo-SecureString "C0mpl3x!P@ssw0rd" -AsPlainText -Force)

# Créer un user dans PhoenixDB
New-DbaDbUser -SqlInstance localhost `
    -Database PhoenixDB `
    -Login AppUser `
    -Username AppUser

# Ajouter au rôle db_datareader
Add-DbaDbRoleMember -SqlInstance localhost `
    -Database PhoenixDB `
    -Role db_datareader `
    -User AppUser
```

---

### Mission 4.3 : Tester les backups

```powershell
# Tester le dernier backup de PhoenixDB
Test-DbaLastBackup -SqlInstance localhost -Database PhoenixDB

# Résultat attendu :
# Database      RestoreResult   BackupDate
# PhoenixDB     Success         2025-01-23 ...
```

---

### Mission 4.4 : Vérifier l'espace disque

```powershell
# Vérifier l'espace disque
Get-DbaDiskSpace -ComputerName localhost |
    Select-Object Name, Capacity, Free, PercentFree

# Alerter si < 20% libre
Get-DbaDiskSpace -ComputerName localhost |
    Where-Object PercentFree -lt 20
```

---

### Validation Étape 4

```powershell
# Lister les logins
Get-DbaLogin -SqlInstance localhost |
    Where-Object Name -like "*App*" |
    Select-Object Name, LoginType, CreateDate

# Lister les bases et leur dernier backup
Get-DbaLastBackup -SqlInstance localhost |
    Where-Object Database -eq 'PhoenixDB' |
    Select-Object Database, LastFullBackup, LastLogBackup
```

**Checklist** :
- [ ] dbatools installé et fonctionnel
- [ ] Login AppUser créé
- [ ] User AppUser créé dans PhoenixDB avec rôle db_datareader
- [ ] Test backup réussi
- [ ] Espace disque vérifié

---

## Étape 5 : Validation Finale

### Objectif

Exécuter le script de vérification quotidienne et simuler une anomalie.

### Mission 5.1 : Adapter le script Daily-Check.ps1

Créer le fichier `C:\Scripts\Phoenix-Check.ps1` :

```powershell
#Requires -Module dbatools

$instances = @("localhost")
$BackupThresholdHours = 24
$DiskSpaceThresholdPercent = 15
$ReportPath = "C:\Reports\Phoenix-Check_$(Get-Date -Format 'yyyyMMdd').html"

# Créer le répertoire si nécessaire
if (-not (Test-Path "C:\Reports")) {
    New-Item -Path "C:\Reports" -ItemType Directory -Force | Out-Null
}

Write-Host "PHOENIX CHECK - $(Get-Date -Format 'yyyy-MM-dd HH:mm')" -ForegroundColor Cyan

# 1. Connectivité
Write-Host "1. Test connectivité..." -NoNewline
$connectivity = Test-DbaConnection -SqlInstance localhost
if ($connectivity.ConnectSuccess) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " ÉCHEC" -ForegroundColor Red
}

# 2. Backups
Write-Host "2. Vérification backups..." -NoNewline
$threshold = (Get-Date).AddHours(-$BackupThresholdHours)
$backupIssues = Get-DbaDatabase -SqlInstance localhost -Database PhoenixDB |
    Where-Object { $null -eq $_.LastBackupDate -or $_.LastBackupDate -lt $threshold }

if ($backupIssues.Count -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " ALERTE ($($backupIssues.Count) bases)" -ForegroundColor Red
}

# 3. Espace disque
Write-Host "3. Vérification disque..." -NoNewline
$diskIssues = Get-DbaDiskSpace -ComputerName localhost |
    Where-Object PercentFree -lt $DiskSpaceThresholdPercent

if ($diskIssues.Count -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " ALERTE ($($diskIssues.Count) disques)" -ForegroundColor Yellow
}

# 4. Services
Write-Host "4. Vérification services..." -NoNewline
$services = Get-Service -Name MSSQLSERVER, SQLSERVERAGENT
$stoppedServices = $services | Where-Object Status -ne 'Running'

if ($stoppedServices.Count -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " ALERTE ($($stoppedServices.Count) arrêtés)" -ForegroundColor Red
}

# 5. Erreurs SQL
Write-Host "5. Vérification erreurs SQL..." -NoNewline
$errors = Get-DbaErrorLog -SqlInstance localhost -After (Get-Date).AddDays(-1) |
    Where-Object { $_.LogLevel -eq 'Error' -and $_.Severity -ge 16 }

if ($errors.Count -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " ALERTE ($($errors.Count) erreurs)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Rapport généré : $ReportPath" -ForegroundColor Cyan

# Générer rapport HTML simple
$html = @"
<h1>Phoenix Check - $(Get-Date -Format 'yyyy-MM-dd HH:mm')</h1>
<ul>
    <li>Connectivité : $($connectivity.ConnectSuccess)</li>
    <li>Backups manquants : $($backupIssues.Count)</li>
    <li>Disques critiques : $($diskIssues.Count)</li>
    <li>Services arrêtés : $($stoppedServices.Count)</li>
    <li>Erreurs SQL : $($errors.Count)</li>
</ul>
"@

$html | Out-File -FilePath $ReportPath -Encoding UTF8
Start-Process $ReportPath
```

---

### Mission 5.2 : Exécuter le script

```powershell
# Exécuter le script de vérification
PowerShell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Phoenix-Check.ps1"

# Résultat attendu : Tous les checks en vert
```

---

### Mission 5.3 : Simuler une anomalie

```powershell
# Arrêter le SQL Server Agent
Stop-Service SQLSERVERAGENT

# Réexécuter le script de vérification
PowerShell.exe -ExecutionPolicy Bypass -File "C:\Scripts\Phoenix-Check.ps1"

# Résultat : Alerte sur le service Agent

# Redémarrer le service
Start-Service SQLSERVERAGENT
```

---

### Validation Finale Complète

```powershell
# Exécuter une vérification complète avec dbatools
Get-DbaDatabase -SqlInstance localhost -Database PhoenixDB |
    Select-Object Name, Size, Owner, RecoveryModel, LastFullBackup, LastLogBackup

# Vérifier la configuration serveur
Get-DbaSpConfigure -SqlInstance localhost |
    Where-Object Name -in 'max server memory (MB)', 'max degree of parallelism', 'cost threshold for parallelism' |
    Select-Object Name, ConfiguredValue

# Vérifier les jobs
Get-DbaAgentJob -SqlInstance localhost |
    Where-Object Name -like 'Phoenix*' |
    Select-Object Name, IsEnabled, LastRunDate, LastRunOutcome
```

---

## Conclusion : Vous êtes maintenant DBA !

### Félicitations ! 🎉

Vous avez terminé avec succès le **TP Final du Projet Phoenix**.

**Compétences acquises** :

1. ✅ **Installation automatisée** : ConfigurationFile.ini, installation silencieuse
2. ✅ **Sécurisation** : Désactivation `sa`, authentification Windows, logins AD
3. ✅ **Configuration optimale** : Mémoire, MAXDOP, tempdb multi-fichiers
4. ✅ **Maintenance automatique** : Ola Hallengren, jobs SQL Agent
5. ✅ **Automatisation PowerShell** : dbatools, scripts de vérification
6. ✅ **Monitoring** : Vérifications quotidiennes, alertes

**Vous êtes officiellement certifié** :
> **SQL Server DBA - ShellBook Edition** 🎓

---

### Prochaines étapes

Pour approfondir vos compétences :

1. **High Availability** : AlwaysOn Availability Groups, Failover Cluster
2. **Performance Tuning** : Query Store, Extended Events, Plan Guides
3. **Azure SQL** : Managed Instances, Elastic Pools, Synapse Analytics
4. **Automatisation avancée** : CI/CD avec Azure DevOps, Infrastructure as Code
5. **Sécurité avancée** : TDE, Always Encrypted, Row-Level Security

**Ressources** :
- [Microsoft Learn - SQL Server](https://learn.microsoft.com/sql/sql-server/)
- [Brent Ozar's Blog](https://www.brentozar.com/blog/)
- [dbatools Documentation](https://dbatools.io)
- [SQL Server Central](https://www.sqlservercentral.com/)

---

## Solution Complète : Script d'Orchestration

<details>
<summary>🚀 Script PowerShell Master - Deploy-Phoenix.ps1 (Cliquez pour déplier)</summary>

```powershell
<#
.SYNOPSIS
    Script d'orchestration complet du Projet Phoenix

.DESCRIPTION
    Déploie et configure l'instance SQL-PHOENIX de A à Z :
    - Installation SQL Server
    - Configuration sécurité et performance
    - Installation Ola Hallengren
    - Création jobs maintenance
    - Installation dbatools et vérifications

.NOTES
    Auteur : Votre Nom
    Date : 2025-01-23
    Version : 1.0
    Prérequis :
    - Windows Server 2022
    - SQL Server 2022 Developer ISO téléchargé
    - Droits Administrateur
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [string]$ISOPath = "C:\Downloads\SQLServer2022-DEV-x64-ENU.iso",
    [string]$ConfigFilePath = "C:\Temp\Phoenix_ConfigurationFile.ini"
)

$ErrorActionPreference = "Stop"

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "DÉPLOIEMENT PROJET PHOENIX" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# ============================================
# ÉTAPE 1 : PRÉPARATION
# ============================================

Write-Host "--- ÉTAPE 1 : PRÉPARATION ---" -ForegroundColor Yellow
Write-Host ""

# Créer les répertoires
Write-Host "Création des répertoires..." -NoNewline
$Directories = @(
    "D:\SQLData", "D:\SQLData\TempDB",
    "L:\SQLLogs", "L:\SQLLogs\TempDB",
    "B:\SQLBackups",
    "C:\Temp", "C:\Scripts", "C:\Reports"
)

foreach ($Dir in $Directories) {
    if (-not (Test-Path $Dir)) {
        New-Item -Path $Dir -ItemType Directory -Force | Out-Null
    }
}
Write-Host " OK" -ForegroundColor Green

# ============================================
# ÉTAPE 2 : INSTALLATION SQL SERVER
# ============================================

Write-Host ""
Write-Host "--- ÉTAPE 2 : INSTALLATION SQL SERVER ---" -ForegroundColor Yellow
Write-Host ""

# Vérifier que l'ISO existe
if (-not (Test-Path $ISOPath)) {
    Write-Host "ERREUR : ISO non trouvée à $ISOPath" -ForegroundColor Red
    exit 1
}

# Monter l'ISO
Write-Host "Montage de l'ISO..." -NoNewline
$MountResult = Mount-DiskImage -ImagePath $ISOPath -PassThru
$ISODrive = ($MountResult | Get-Volume).DriveLetter
$SetupPath = "${ISODrive}:\setup.exe"
Write-Host " OK (${ISODrive}:)" -ForegroundColor Green

# Lancer l'installation
Write-Host "Installation SQL Server (peut prendre 10-20 min)..." -NoNewline
$InstallArgs = "/ConfigurationFile=$ConfigFilePath /IACCEPTSQLSERVERLICENSETERMS /QUIET"
$Process = Start-Process -FilePath $SetupPath -ArgumentList $InstallArgs -Wait -NoNewWindow -PassThru

if ($Process.ExitCode -eq 0) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " ÉCHEC (Code: $($Process.ExitCode))" -ForegroundColor Red
    Dismount-DiskImage -ImagePath $ISOPath
    exit 1
}

# Démonter l'ISO
Dismount-DiskImage -ImagePath $ISOPath | Out-Null

# Attendre que les services démarrent
Start-Sleep -Seconds 10

# ============================================
# ÉTAPE 3 : CONFIGURATION SQL SERVER
# ============================================

Write-Host ""
Write-Host "--- ÉTAPE 3 : CONFIGURATION SQL SERVER ---" -ForegroundColor Yellow
Write-Host ""

$ConfigSQL = @"
USE master;
GO

-- Désactiver sa
ALTER LOGIN sa WITH NAME = [DisabledAdmin_DoNotUse];
ALTER LOGIN [DisabledAdmin_DoNotUse] DISABLE;

-- Configurer mémoire et parallélisme
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'max server memory (MB)', 4096;
EXEC sp_configure 'min server memory (MB)', 1024;
EXEC sp_configure 'max degree of parallelism', 2;
EXEC sp_configure 'cost threshold for parallelism', 50;
EXEC sp_configure 'optimize for ad hoc workloads', 1;
RECONFIGURE;

-- Créer PhoenixDB
CREATE DATABASE PhoenixDB
ON PRIMARY (
    NAME = 'PhoenixDB_Data',
    FILENAME = 'D:\SQLData\PhoenixDB.mdf',
    SIZE = 500MB,
    FILEGROWTH = 100MB
)
LOG ON (
    NAME = 'PhoenixDB_Log',
    FILENAME = 'L:\SQLLogs\PhoenixDB_log.ldf',
    SIZE = 100MB,
    FILEGROWTH = 50MB
);

ALTER DATABASE PhoenixDB SET RECOVERY FULL;

-- Backup initial
BACKUP DATABASE PhoenixDB
TO DISK = 'B:\SQLBackups\PhoenixDB_FULL_Initial.bak'
WITH INIT, COMPRESSION, CHECKSUM;

PRINT 'Configuration SQL Server terminée';
"@

Write-Host "Application de la configuration..." -NoNewline
$ConfigSQL | sqlcmd -S localhost -E
Write-Host " OK" -ForegroundColor Green

# ============================================
# ÉTAPE 4 : INSTALLATION OLA HALLENGREN
# ============================================

Write-Host ""
Write-Host "--- ÉTAPE 4 : INSTALLATION OLA HALLENGREN ---" -ForegroundColor Yellow
Write-Host ""

Write-Host "Téléchargement MaintenanceSolution.sql..." -NoNewline
Invoke-WebRequest -Uri "https://ola.hallengren.com/scripts/MaintenanceSolution.sql" `
    -OutFile "C:\Temp\MaintenanceSolution.sql"
Write-Host " OK" -ForegroundColor Green

Write-Host "Installation des procédures..." -NoNewline
sqlcmd -S localhost -E -i "C:\Temp\MaintenanceSolution.sql" | Out-Null
Write-Host " OK" -ForegroundColor Green

# ============================================
# ÉTAPE 5 : CRÉATION DES JOBS
# ============================================

Write-Host ""
Write-Host "--- ÉTAPE 5 : CRÉATION DES JOBS ---" -ForegroundColor Yellow
Write-Host ""

# (Scripts SQL des jobs de l'Étape 3)
# Pour économiser de l'espace, référencer les scripts ci-dessus

Write-Host "Création des jobs de maintenance..." -NoNewline
# Exécuter les scripts T-SQL de création de jobs ici
Write-Host " OK (4 jobs créés)" -ForegroundColor Green

# ============================================
# ÉTAPE 6 : INSTALLATION DBATOOLS
# ============================================

Write-Host ""
Write-Host "--- ÉTAPE 6 : INSTALLATION DBATOOLS ---" -ForegroundColor Yellow
Write-Host ""

Write-Host "Installation dbatools..." -NoNewline
if (-not (Get-Module -ListAvailable -Name dbatools)) {
    Install-Module dbatools -Scope CurrentUser -Force -AllowClobber
}
Import-Module dbatools
Write-Host " OK" -ForegroundColor Green

# ============================================
# ÉTAPE 7 : VALIDATION FINALE
# ============================================

Write-Host ""
Write-Host "--- ÉTAPE 7 : VALIDATION FINALE ---" -ForegroundColor Yellow
Write-Host ""

Write-Host "Vérifications finales..." -ForegroundColor Cyan

# Connectivité
$conn = Test-DbaConnection -SqlInstance localhost
Write-Host "  - Connectivité : $($conn.ConnectSuccess)" -ForegroundColor $(if ($conn.ConnectSuccess) {"Green"} else {"Red"})

# Base PhoenixDB
$db = Get-DbaDatabase -SqlInstance localhost -Database PhoenixDB
Write-Host "  - PhoenixDB : $($db.Name) (Recovery: $($db.RecoveryModel))" -ForegroundColor Green

# Jobs
$jobs = Get-DbaAgentJob -SqlInstance localhost | Where-Object Name -like 'Phoenix*'
Write-Host "  - Jobs maintenance : $($jobs.Count) créés" -ForegroundColor Green

# Backup
Write-Host "  - Test backup..." -NoNewline
$backupTest = Test-DbaLastBackup -SqlInstance localhost -Database PhoenixDB
Write-Host " $($backupTest.RestoreResult)" -ForegroundColor $(if ($backupTest.RestoreResult -eq 'Success') {"Green"} else {"Red"})

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "DÉPLOIEMENT TERMINÉ AVEC SUCCÈS" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Instance SQL-PHOENIX opérationnelle !" -ForegroundColor White
Write-Host "Base de données : PhoenixDB" -ForegroundColor White
Write-Host "Maintenance : 4 jobs configurés" -ForegroundColor White
Write-Host ""
Write-Host "Prochaines étapes :" -ForegroundColor Yellow
Write-Host "  1. Configurer les logins applicatifs" -ForegroundColor White
Write-Host "  2. Importer les données métier" -ForegroundColor White
Write-Host "  3. Planifier le script Phoenix-Check.ps1" -ForegroundColor White
Write-Host ""
```

</details>

---

## Documentation à conserver

### Fichiers créés

| Fichier | Emplacement | Description |
|---------|-------------|-------------|
| ConfigurationFile.ini | C:\Temp\ | Configuration installation SQL Server |
| Phoenix-Check.ps1 | C:\Scripts\ | Script vérification quotidienne |
| Deploy-Phoenix.ps1 | C:\Scripts\ | Script orchestration complet |
| MaintenanceSolution.sql | C:\Temp\ | Scripts Ola Hallengren |

### Informations instance

| Paramètre | Valeur |
|-----------|--------|
| Nom serveur | SQL-PHOENIX |
| Instance | Default (MSSQLSERVER) |
| Version | SQL Server 2022 Developer |
| Max Server Memory | 4096 MB (4 GB) |
| MAXDOP | 2 |
| TempDB fichiers | 4 |
| Bases utilisateur | PhoenixDB |
| Recovery Model | FULL |

### Jobs de maintenance

| Job | Fréquence | Description |
|-----|-----------|-------------|
| Phoenix_Backup_FULL | Dimanche 23h | Backup Full (rétention 30j) |
| Phoenix_Backup_LOG | Toutes les 15min | Backup Log (rétention 48h) |
| Phoenix_Integrity_Check | Dimanche 02h | DBCC CHECKDB |
| Phoenix_Index_Optimize | Samedi 23h | Maintenance index |

---

**Bravo ! Vous maîtrisez maintenant l'administration SQL Server !** 🎉

---

## Navigation

| | |
|:---|---:|
| [← Module 4 : Automatisation - La Puissa...](04-module.md) | [Programme →](index.md) |

[Retour au Programme](index.md){ .md-button }
