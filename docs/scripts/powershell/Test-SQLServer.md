---
tags:
  - scripts
  - powershell
  - sql-server
  - database
  - windows
---

# Test-SQLServer.ps1

:material-star::material-star::material-star: **Niveau : Avancé**

Vérification complète d'une instance SQL Server.

---

## Description

Ce script vérifie l'état d'une instance SQL Server :
- Connectivité et services
- État des bases de données
- Espace disque et fichiers
- Jobs SQL Agent
- Backups récents
- Performance et wait stats

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Health check SQL Server.

.DESCRIPTION
    Vérifie l'état complet d'une instance SQL Server incluant
    les bases, les jobs, les backups et la performance.

.PARAMETER ServerInstance
    Instance SQL Server (défaut: localhost).

.PARAMETER Database
    Base de données spécifique à vérifier.

.PARAMETER BackupWarningHours
    Heures sans backup avant alerte (défaut: 24).

.PARAMETER Credential
    Credentials SQL si pas d'auth Windows.

.EXAMPLE
    .\Test-SQLServer.ps1 -ServerInstance "SQL01"

.EXAMPLE
    .\Test-SQLServer.ps1 -ServerInstance "SQL01\INST1" -BackupWarningHours 48

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ServerInstance = "localhost",

    [Parameter()]
    [string]$Database,

    [Parameter()]
    [int]$BackupWarningHours = 24,

    [Parameter()]
    [int]$DiskWarningPercent = 80,

    [Parameter()]
    [PSCredential]$Credential
)

#region Functions
function Write-Check {
    param(
        [string]$Name,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info')]
        [string]$Status,
        [string]$Message
    )

    $icons = @{
        'Pass' = @('[OK]  ', 'Green')
        'Warn' = @('[WARN]', 'Yellow')
        'Fail' = @('[FAIL]', 'Red')
        'Info' = @('[INFO]', 'Cyan')
    }

    Write-Host $icons[$Status][0] -ForegroundColor $icons[$Status][1] -NoNewline
    Write-Host " $Name" -NoNewline
    if ($Message) { Write-Host " - $Message" -ForegroundColor Gray }
    else { Write-Host "" }

    switch ($Status) {
        'Pass' { $script:passed++ }
        'Warn' { $script:warnings++ }
        'Fail' { $script:failed++ }
    }
    $script:total++
}

function Invoke-SqlQuery {
    param(
        [string]$Query,
        [string]$Database = "master"
    )

    $connectionString = "Server=$ServerInstance;Database=$Database;Integrated Security=True;TrustServerCertificate=True;"

    if ($Credential) {
        $connectionString = "Server=$ServerInstance;Database=$Database;User Id=$($Credential.UserName);Password=$($Credential.GetNetworkCredential().Password);TrustServerCertificate=True;"
    }

    try {
        $connection = New-Object System.Data.SqlClient.SqlConnection($connectionString)
        $connection.Open()

        $command = New-Object System.Data.SqlClient.SqlCommand($Query, $connection)
        $adapter = New-Object System.Data.SqlClient.SqlDataAdapter($command)
        $dataset = New-Object System.Data.DataSet

        $adapter.Fill($dataset) | Out-Null
        $connection.Close()

        return $dataset.Tables[0]
    }
    catch {
        throw $_
    }
}
#endregion

#region Main
$script:total = 0
$script:passed = 0
$script:warnings = 0
$script:failed = 0

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  SQL SERVER HEALTH CHECK" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  Instance: $ServerInstance"
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("-" * 70) -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Connectivité
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Connectivité]" -ForegroundColor Cyan

# Port TCP (1433 par défaut)
$serverName = $ServerInstance.Split('\')[0]
$port = 1433
$tcpTest = Test-NetConnection -ComputerName $serverName -Port $port -WarningAction SilentlyContinue

if ($tcpTest.TcpTestSucceeded) {
    Write-Check -Name "TCP Port $port" -Status Pass -Message $serverName
} else {
    Write-Check -Name "TCP Port $port" -Status Warn -Message "May use dynamic port"
}

# Test connexion SQL
try {
    $versionQuery = "SELECT @@VERSION as Version, @@SERVERNAME as ServerName, SERVERPROPERTY('ProductVersion') as ProductVersion"
    $versionResult = Invoke-SqlQuery -Query $versionQuery

    Write-Check -Name "SQL Connection" -Status Pass -Message "Connected"
    Write-Host "       Server: $($versionResult.ServerName)" -ForegroundColor Gray
    Write-Host "       Version: $($versionResult.ProductVersion)" -ForegroundColor Gray
}
catch {
    Write-Check -Name "SQL Connection" -Status Fail -Message $_.Exception.Message
    Write-Host "`n[FATAL] Cannot connect to SQL Server. Aborting." -ForegroundColor Red
    exit 2
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Services SQL
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Services SQL]" -ForegroundColor Cyan

$sqlServices = @(
    @{ Pattern = 'MSSQLSERVER'; Name = 'SQL Server' }
    @{ Pattern = 'SQLSERVERAGENT'; Name = 'SQL Agent' }
    @{ Pattern = 'MsDtsServer*'; Name = 'SSIS' }
    @{ Pattern = 'ReportServer*'; Name = 'SSRS' }
)

foreach ($svc in $sqlServices) {
    $service = Get-Service -Name $svc.Pattern -ComputerName $serverName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($service) {
        if ($service.Status -eq 'Running') {
            Write-Check -Name $svc.Name -Status Pass -Message "Running"
        } else {
            Write-Check -Name $svc.Name -Status Warn -Message $service.Status
        }
    }
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: État des bases de données
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Bases de Données]" -ForegroundColor Cyan

$dbQuery = @"
SELECT
    name,
    state_desc,
    recovery_model_desc,
    compatibility_level,
    is_read_only
FROM sys.databases
WHERE database_id > 4 $(if ($Database) { "AND name = '$Database'" })
ORDER BY name
"@

try {
    $databases = Invoke-SqlQuery -Query $dbQuery

    foreach ($db in $databases) {
        if ($db.state_desc -eq 'ONLINE') {
            Write-Check -Name "DB: $($db.name)" -Status Pass `
                -Message "Online ($($db.recovery_model_desc))"
        } elseif ($db.state_desc -eq 'RESTORING') {
            Write-Check -Name "DB: $($db.name)" -Status Info -Message "Restoring"
        } else {
            Write-Check -Name "DB: $($db.name)" -Status Fail `
                -Message $db.state_desc
        }
    }

    Write-Check -Name "User Databases" -Status Info -Message "$($databases.Count) database(s)"
}
catch {
    Write-Check -Name "Database Status" -Status Warn -Message $_.Exception.Message
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Espace disque et fichiers
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Espace Fichiers]" -ForegroundColor Cyan

$spaceQuery = @"
SELECT
    DB_NAME(database_id) as DatabaseName,
    name as FileName,
    type_desc,
    physical_name,
    size * 8 / 1024 as SizeMB,
    CASE max_size
        WHEN -1 THEN 'Unlimited'
        WHEN 0 THEN 'No Growth'
        ELSE CAST(max_size * 8 / 1024 AS VARCHAR)
    END as MaxSizeMB,
    growth
FROM sys.master_files
WHERE database_id > 4
ORDER BY DatabaseName, type_desc
"@

try {
    $fileInfo = Invoke-SqlQuery -Query $spaceQuery

    # Vérifier l'espace sur les disques
    $drives = $fileInfo | ForEach-Object {
        $_.physical_name.Substring(0, 1)
    } | Select-Object -Unique

    foreach ($drive in $drives) {
        $diskQuery = "EXEC xp_fixeddrives"
        $diskInfo = Invoke-SqlQuery -Query $diskQuery |
            Where-Object { $_.drive -eq $drive }

        if ($diskInfo) {
            $freeGB = [math]::Round($diskInfo.MB / 1024, 1)
            if ($freeGB -lt 10) {
                Write-Check -Name "Drive $drive" -Status Fail -Message "$freeGB GB free"
            } elseif ($freeGB -lt 50) {
                Write-Check -Name "Drive $drive" -Status Warn -Message "$freeGB GB free"
            } else {
                Write-Check -Name "Drive $drive" -Status Pass -Message "$freeGB GB free"
            }
        }
    }

    # Fichiers sans autogrowth
    $noGrowth = $fileInfo | Where-Object { $_.MaxSizeMB -eq 'No Growth' -and $_.type_desc -eq 'ROWS' }
    if ($noGrowth) {
        Write-Check -Name "Files without autogrowth" -Status Warn `
            -Message "$($noGrowth.Count) file(s)"
    }
}
catch {
    Write-Check -Name "File Space" -Status Warn -Message $_.Exception.Message
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Backups
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Backups]" -ForegroundColor Cyan

$backupQuery = @"
SELECT
    d.name as DatabaseName,
    d.recovery_model_desc,
    MAX(CASE WHEN b.type = 'D' THEN b.backup_finish_date END) as LastFullBackup,
    MAX(CASE WHEN b.type = 'I' THEN b.backup_finish_date END) as LastDiffBackup,
    MAX(CASE WHEN b.type = 'L' THEN b.backup_finish_date END) as LastLogBackup
FROM sys.databases d
LEFT JOIN msdb.dbo.backupset b ON d.name = b.database_name
WHERE d.database_id > 4
    AND d.state_desc = 'ONLINE'
    AND d.name NOT IN ('tempdb')
GROUP BY d.name, d.recovery_model_desc
ORDER BY d.name
"@

try {
    $backupStatus = Invoke-SqlQuery -Query $backupQuery
    $warningThreshold = (Get-Date).AddHours(-$BackupWarningHours)

    foreach ($db in $backupStatus) {
        $lastFull = $db.LastFullBackup

        if (-not $lastFull) {
            Write-Check -Name "Backup: $($db.DatabaseName)" -Status Fail -Message "NEVER backed up!"
        } elseif ($lastFull -lt $warningThreshold) {
            $hoursAgo = [math]::Round(((Get-Date) - $lastFull).TotalHours, 1)
            Write-Check -Name "Backup: $($db.DatabaseName)" -Status Warn `
                -Message "Full: $hoursAgo hours ago"
        } else {
            Write-Check -Name "Backup: $($db.DatabaseName)" -Status Pass `
                -Message "Full: $($lastFull.ToString('yyyy-MM-dd HH:mm'))"
        }

        # Log backup pour FULL recovery
        if ($db.recovery_model_desc -eq 'FULL' -and -not $db.LastLogBackup) {
            Write-Host "       WARNING: No log backup (FULL recovery mode)" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Check -Name "Backup Status" -Status Warn -Message $_.Exception.Message
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Jobs SQL Agent
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[SQL Agent Jobs]" -ForegroundColor Cyan

$jobQuery = @"
SELECT
    j.name as JobName,
    j.enabled,
    h.run_status,
    h.run_date,
    h.run_time,
    h.message
FROM msdb.dbo.sysjobs j
LEFT JOIN (
    SELECT job_id, run_status, run_date, run_time, message,
           ROW_NUMBER() OVER (PARTITION BY job_id ORDER BY run_date DESC, run_time DESC) as rn
    FROM msdb.dbo.sysjobhistory
    WHERE step_id = 0
) h ON j.job_id = h.job_id AND h.rn = 1
WHERE j.enabled = 1
ORDER BY j.name
"@

try {
    $jobs = Invoke-SqlQuery -Query $jobQuery

    $failedJobs = $jobs | Where-Object { $_.run_status -eq 0 }
    $succeededJobs = $jobs | Where-Object { $_.run_status -eq 1 }

    Write-Check -Name "Enabled Jobs" -Status Info -Message "$($jobs.Count)"

    if ($failedJobs.Count -gt 0) {
        Write-Check -Name "Failed Jobs" -Status Fail -Message "$($failedJobs.Count) job(s)"
        foreach ($job in $failedJobs) {
            Write-Host "       - $($job.JobName)" -ForegroundColor Red
        }
    } else {
        Write-Check -Name "Failed Jobs" -Status Pass -Message "None"
    }
}
catch {
    Write-Check -Name "SQL Agent Jobs" -Status Info -Message "Could not retrieve"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Wait Statistics (Performance)
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Performance - Top Waits]" -ForegroundColor Cyan

$waitQuery = @"
SELECT TOP 5
    wait_type,
    waiting_tasks_count,
    wait_time_ms / 1000.0 as wait_time_sec,
    signal_wait_time_ms / 1000.0 as signal_wait_sec
FROM sys.dm_os_wait_stats
WHERE wait_type NOT IN (
    'CLR_SEMAPHORE', 'LAZYWRITER_SLEEP', 'RESOURCE_QUEUE',
    'SLEEP_TASK', 'SLEEP_SYSTEMTASK', 'SQLTRACE_BUFFER_FLUSH',
    'WAITFOR', 'LOGMGR_QUEUE', 'CHECKPOINT_QUEUE',
    'REQUEST_FOR_DEADLOCK_SEARCH', 'XE_TIMER_EVENT',
    'BROKER_TO_FLUSH', 'BROKER_TASK_STOP', 'CLR_MANUAL_EVENT',
    'CLR_AUTO_EVENT', 'DISPATCHER_QUEUE_SEMAPHORE',
    'FT_IFTS_SCHEDULER_IDLE_WAIT', 'XE_DISPATCHER_WAIT',
    'XE_DISPATCHER_JOIN', 'SQLTRACE_INCREMENTAL_FLUSH_SLEEP'
)
ORDER BY wait_time_ms DESC
"@

try {
    $waits = Invoke-SqlQuery -Query $waitQuery

    foreach ($wait in $waits) {
        $waitSec = [math]::Round($wait.wait_time_sec, 0)
        Write-Host "       $($wait.wait_type): ${waitSec}s" -ForegroundColor Gray
    }
    Write-Check -Name "Wait Stats" -Status Info -Message "Retrieved"
}
catch {
    Write-Check -Name "Wait Stats" -Status Info -Message "Could not retrieve"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: Blocking Sessions
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Blocking]" -ForegroundColor Cyan

$blockingQuery = @"
SELECT COUNT(*) as BlockedSessions
FROM sys.dm_exec_requests
WHERE blocking_session_id > 0
"@

try {
    $blocking = Invoke-SqlQuery -Query $blockingQuery

    if ($blocking.BlockedSessions -gt 0) {
        Write-Check -Name "Blocked Sessions" -Status Warn `
            -Message "$($blocking.BlockedSessions) session(s) blocked"
    } else {
        Write-Check -Name "Blocked Sessions" -Status Pass -Message "None"
    }
}
catch {
    Write-Check -Name "Blocking" -Status Info -Message "Could not check"
}

# ═══════════════════════════════════════════════════════════════════
# RÉSUMÉ
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
Write-Host "  RÉSUMÉ" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan

Write-Host "  Checks: $script:total total"
Write-Host "    - " -NoNewline; Write-Host "Passed: $script:passed" -ForegroundColor Green
Write-Host "    - " -NoNewline; Write-Host "Warnings: $script:warnings" -ForegroundColor Yellow
Write-Host "    - " -NoNewline; Write-Host "Failed: $script:failed" -ForegroundColor Red

Write-Host ""
if ($script:failed -gt 0) {
    Write-Host "  SQL SERVER STATUS: CRITICAL" -ForegroundColor Red
    exit 2
} elseif ($script:warnings -gt 0) {
    Write-Host "  SQL SERVER STATUS: DEGRADED" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "  SQL SERVER STATUS: HEALTHY" -ForegroundColor Green
    exit 0
}
#endregion
```

---

## Utilisation

```powershell
# Instance par défaut locale
.\Test-SQLServer.ps1

# Instance nommée distante
.\Test-SQLServer.ps1 -ServerInstance "SQL01\PROD"

# Avec seuil backup personnalisé
.\Test-SQLServer.ps1 -ServerInstance "SQL01" -BackupWarningHours 48

# Base de données spécifique
.\Test-SQLServer.ps1 -ServerInstance "SQL01" -Database "MyApp"
```

---

## Exemple de Sortie

```text
======================================================================
  SQL SERVER HEALTH CHECK
======================================================================
  Instance: SQL01\PROD
  Date: 2025-12-01 19:22:45
----------------------------------------------------------------------

[Connectivité]
[OK]   TCP Port 1433 - SQL01
[OK]   SQL Connection - Connected
       Server: SQL01\PROD
       Version: 16.0.4135.4

[Services SQL]
[OK]   SQL Server - Running
[OK]   SQL Agent - Running
[INFO] SSIS - Not installed
[INFO] SSRS - Not installed

[Bases de Données]
[OK]   DB: AppDatabase - Online (FULL)
[OK]   DB: ReportingDB - Online (SIMPLE)
[OK]   DB: ArchiveDB - Online (BULK_LOGGED)
[WARN] DB: LegacyApp - Offline
[INFO] User Databases - 4 database(s)

[Espace Fichiers]
[OK]   Drive D - 245.7 GB free
[OK]   Drive E - 512.3 GB free
[WARN] Drive L - 18.2 GB free

[Backups]
[OK]   Backup: AppDatabase - Full: 2025-12-01 06:00
[OK]   Backup: ReportingDB - Full: 2025-12-01 06:15
[WARN] Backup: ArchiveDB - Full: 48.5 hours ago
       WARNING: No log backup (FULL recovery mode)
[FAIL] Backup: LegacyApp - NEVER backed up!

[SQL Agent Jobs]
[INFO] Enabled Jobs - 12
[FAIL] Failed Jobs - 2 job(s)
       - Maintenance_IndexRebuild
       - ETL_NightlyLoad

[Performance - Top Waits]
       CXPACKET: 4523s
       PAGEIOLATCH_SH: 1247s
       LCK_M_IX: 892s
       ASYNC_NETWORK_IO: 456s
       WRITELOG: 234s
[INFO] Wait Stats - Retrieved

[Blocking]
[OK]   Blocked Sessions - None

======================================================================
  RÉSUMÉ
======================================================================
  Checks: 20 total
    - Passed: 11
    - Warnings: 3
    - Failed: 3

  SQL SERVER STATUS: CRITICAL
```

---

## Voir Aussi

- [Test-ADHealth.ps1](Test-ADHealth.md)
- [Get-ServiceStatus.ps1](Get-ServiceStatus.md)
