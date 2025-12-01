---
tags:
  - scripts
  - powershell
  - backup
  - fichiers
---

# Backup-Directory.ps1

:material-star::material-star: **Niveau : Intermédiaire**

Backup de répertoires avec rotation et compression.

---

## Description

Ce script effectue des sauvegardes de répertoires :
- Compression ZIP native
- Rotation automatique des anciennes sauvegardes
- Exclusion de fichiers/dossiers
- Vérification d'intégrité
- Logging détaillé

---

## Prérequis

- **Système** : Windows Server 2016+ ou Windows 10/11
- **PowerShell** : Version 5.1 minimum
- **Permissions** : Lecture sur le répertoire source, écriture sur la destination
- **Modules** : Aucun module externe requis

---

## Cas d'Usage

- **Sauvegardes automatisées** : Planifier des backups quotidiens avec le Planificateur de tâches
- **Protection de données** : Créer des copies de sécurité avant des migrations ou mises à jour
- **Archivage** : Conserver plusieurs versions de répertoires avec rotation automatique
- **Disaster Recovery** : Maintenir des sauvegardes hors-ligne pour la reprise après incident

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Backup de répertoires avec rotation.

.DESCRIPTION
    Crée des sauvegardes compressées de répertoires avec
    rotation automatique des anciennes sauvegardes.

.PARAMETER Source
    Chemin du répertoire source à sauvegarder.

.PARAMETER Destination
    Chemin du répertoire de destination.

.PARAMETER KeepBackups
    Nombre de sauvegardes à conserver (défaut: 7).

.PARAMETER ExcludePatterns
    Patterns à exclure (ex: *.log, temp).

.PARAMETER Verify
    Vérifie l'intégrité après création.

.PARAMETER WhatIf
    Simulation sans création.

.EXAMPLE
    .\Backup-Directory.ps1 -Source "C:\Data" -Destination "D:\Backup"

.EXAMPLE
    .\Backup-Directory.ps1 -Source "C:\Web" -Destination "\\server\backup" -KeepBackups 14 -Verify

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$Source,

    [Parameter(Mandatory)]
    [string]$Destination,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$KeepBackups = 7,

    [Parameter()]
    [string[]]$ExcludePatterns = @(),

    [Parameter()]
    [switch]$Verify
)

#region Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $colors = @{
        'Info'    = 'Cyan'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Success' = 'Green'
    }

    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host "[$Level] " -NoNewline -ForegroundColor $colors[$Level]
    Write-Host $Message
}

function Format-FileSize {
    param([long]$Bytes)

    switch ($Bytes) {
        { $_ -ge 1GB } { return "{0:N2} GB" -f ($_ / 1GB) }
        { $_ -ge 1MB } { return "{0:N2} MB" -f ($_ / 1MB) }
        { $_ -ge 1KB } { return "{0:N2} KB" -f ($_ / 1KB) }
        default { return "$_ B" }
    }
}

function Get-DirectorySize {
    param([string]$Path)

    (Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
}

function Remove-OldBackups {
    param(
        [string]$BackupPath,
        [string]$Pattern,
        [int]$KeepCount
    )

    $backups = Get-ChildItem -Path $BackupPath -Filter $Pattern -File |
        Sort-Object -Property CreationTime -Descending

    if ($backups.Count -gt $KeepCount) {
        $toDelete = $backups | Select-Object -Skip $KeepCount

        foreach ($backup in $toDelete) {
            Write-Log "Removing old backup: $($backup.Name)" -Level Warning
            Remove-Item -Path $backup.FullName -Force
        }

        return $toDelete.Count
    }

    return 0
}

function Test-ZipIntegrity {
    param([string]$ZipPath)

    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        $entryCount = $zip.Entries.Count
        $zip.Dispose()

        return @{
            Success = $true
            EntryCount = $entryCount
        }
    }
    catch {
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}
#endregion

#region Main
$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  BACKUP DIRECTORY" -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Cyan

# Préparer les chemins
$sourceName = Split-Path -Path $Source -Leaf
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupName = "${sourceName}_${timestamp}.zip"

# Créer le répertoire destination si nécessaire
if (-not (Test-Path $Destination)) {
    Write-Log "Creating destination directory: $Destination" -Level Info
    if ($PSCmdlet.ShouldProcess($Destination, "Create directory")) {
        New-Item -Path $Destination -ItemType Directory -Force | Out-Null
    }
}

$backupPath = Join-Path -Path $Destination -ChildPath $backupName

Write-Log "Source: $Source" -Level Info
Write-Log "Destination: $backupPath" -Level Info
Write-Log "Keep backups: $KeepBackups" -Level Info

# Calculer la taille source
Write-Log "Calculating source size..." -Level Info
$sourceSize = Get-DirectorySize -Path $Source
Write-Log "Source size: $(Format-FileSize $sourceSize)" -Level Info

# Préparer les fichiers à inclure (avec exclusions)
$tempFolder = $null

if ($ExcludePatterns.Count -gt 0) {
    Write-Log "Applying exclusion patterns..." -Level Info

    # Créer un dossier temporaire filtré
    $tempFolder = Join-Path -Path $env:TEMP -ChildPath "backup_$(Get-Random)"
    New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null

    # Copier avec exclusions
    $excludeRegex = ($ExcludePatterns | ForEach-Object {
        [regex]::Escape($_).Replace('\*', '.*').Replace('\?', '.')
    }) -join '|'

    Get-ChildItem -Path $Source -Recurse | Where-Object {
        $relativePath = $_.FullName.Substring($Source.Length)
        -not ($relativePath -match $excludeRegex)
    } | ForEach-Object {
        $destPath = Join-Path -Path $tempFolder -ChildPath $_.FullName.Substring($Source.Length)
        if ($_.PSIsContainer) {
            New-Item -Path $destPath -ItemType Directory -Force | Out-Null
        } else {
            $destDir = Split-Path -Path $destPath -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force | Out-Null
            }
            Copy-Item -Path $_.FullName -Destination $destPath -Force
        }
    }

    $compressSource = $tempFolder
} else {
    $compressSource = $Source
}

# Créer la sauvegarde
Write-Log "Creating backup..." -Level Info
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

if ($PSCmdlet.ShouldProcess($backupPath, "Create backup")) {
    try {
        Compress-Archive -Path "$compressSource\*" -DestinationPath $backupPath -CompressionLevel Optimal -Force

        $stopwatch.Stop()
        $backupSize = (Get-Item $backupPath).Length
        $ratio = [math]::Round(($backupSize / $sourceSize) * 100, 1)

        Write-Log "Backup created: $backupName" -Level Success
        Write-Log "Backup size: $(Format-FileSize $backupSize) ($ratio% of original)" -Level Info
        Write-Log "Duration: $($stopwatch.Elapsed.ToString('mm\:ss'))" -Level Info
    }
    catch {
        Write-Log "Backup failed: $_" -Level Error
        throw
    }
    finally {
        # Nettoyer le dossier temporaire
        if ($tempFolder -and (Test-Path $tempFolder)) {
            Remove-Item -Path $tempFolder -Recurse -Force
        }
    }

    # Check d'intégrité
    if ($Verify) {
        Write-Log "Verifying backup integrity..." -Level Info
        $integrityResult = Test-ZipIntegrity -ZipPath $backupPath

        if ($integrityResult.Success) {
            Write-Log "Integrity OK: $($integrityResult.EntryCount) entries" -Level Success
        } else {
            Write-Log "Integrity check failed: $($integrityResult.Error)" -Level Error
            throw "Backup integrity verification failed"
        }
    }

    # Rotation des anciennes sauvegardes
    Write-Log "Checking backup rotation..." -Level Info
    $pattern = "${sourceName}_*.zip"
    $deletedCount = Remove-OldBackups -BackupPath $Destination -Pattern $pattern -KeepCount $KeepBackups

    if ($deletedCount -gt 0) {
        Write-Log "Removed $deletedCount old backup(s)" -Level Info
    }
}

# Lister les sauvegardes disponibles
Write-Host ""
Write-Host ("-" * 60) -ForegroundColor Cyan
Write-Log "Available backups:" -Level Info

Get-ChildItem -Path $Destination -Filter "${sourceName}_*.zip" |
    Sort-Object -Property CreationTime -Descending |
    ForEach-Object {
        $age = (Get-Date) - $_.CreationTime
        $ageStr = if ($age.Days -gt 0) { "$($age.Days)d ago" } else { "$($age.Hours)h ago" }
        Write-Host "  $($_.Name) ($(Format-FileSize $_.Length)) - $ageStr"
    }

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Log "Backup completed successfully!" -Level Success
Write-Host ("=" * 60) -ForegroundColor Cyan
#endregion
```

---

## Utilisation

```powershell
# Backup simple
.\Backup-Directory.ps1 -Source "C:\Data" -Destination "D:\Backup"

# Avec rotation personnalisée
.\Backup-Directory.ps1 -Source "C:\Web" -Destination "D:\Backup" -KeepBackups 14

# Avec exclusions et vérification
.\Backup-Directory.ps1 -Source "C:\Project" -Destination "D:\Backup" `
    -ExcludePatterns @("*.log", "node_modules", ".git") -Verify

# Simulation
.\Backup-Directory.ps1 -Source "C:\Data" -Destination "D:\Backup" -WhatIf
```

---

## Sortie Exemple

```
============================================================
  BACKUP DIRECTORY
============================================================
[2024-01-15 14:30:22] [Info] Source: C:\Data
[2024-01-15 14:30:22] [Info] Destination: D:\Backup\Data_20240115_143022.zip
[2024-01-15 14:30:22] [Info] Keep backups: 7
[2024-01-15 14:30:22] [Info] Calculating source size...
[2024-01-15 14:30:23] [Info] Source size: 1.45 GB
[2024-01-15 14:30:23] [Info] Creating backup...
[2024-01-15 14:31:15] [Success] Backup created: Data_20240115_143022.zip
[2024-01-15 14:31:15] [Info] Backup size: 512.34 MB (35.3% of original)
[2024-01-15 14:31:15] [Info] Duration: 00:52
[2024-01-15 14:31:15] [Info] Verifying backup integrity...
[2024-01-15 14:31:18] [Success] Integrity OK: 2456 entries
[2024-01-15 14:31:18] [Info] Checking backup rotation...
[2024-01-15 14:31:18] [Warning] Removing old backup: Data_20240108_143022.zip

------------------------------------------------------------
[2024-01-15 14:31:18] [Info] Available backups:
  Data_20240115_143022.zip (512.34 MB) - 0h ago
  Data_20240114_143022.zip (508.12 MB) - 1d ago
  Data_20240113_143022.zip (505.89 MB) - 2d ago

============================================================
[2024-01-15 14:31:18] [Success] Backup completed successfully!
============================================================
```

---

## Tâche Planifiée

```powershell
# Créer une tâche planifiée pour backup quotidien
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Backup-Directory.ps1" -Source "C:\Data" -Destination "D:\Backup" -Verify'

$trigger = New-ScheduledTaskTrigger -Daily -At 2am

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

Register-ScheduledTask -TaskName "DailyBackup" `
    -Action $action -Trigger $trigger -Settings $settings `
    -Description "Daily backup of C:\Data"
```

---

## Voir Aussi

- [Test-DiskSpace.ps1](Test-DiskSpace.md)
- [Find-LargeFiles.ps1](Find-LargeFiles.md)
