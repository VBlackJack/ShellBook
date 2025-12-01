---
tags:
  - scripts
  - powershell
  - windows
  - logs
  - audit
---

# Export-EventLogs.ps1

Export des journaux d'événements Windows avec filtrage avancé.

---

## Description

- Export multi-journaux (System, Application, Security, etc.)
- Filtrage par date, niveau, source, EventID
- Export CSV, JSON ou EVTX natif
- Mode parallèle pour gros volumes
- Compression automatique des exports

---

## Utilisation

```powershell
# Export des dernières 24h du journal System
.\Export-EventLogs.ps1 -LogName System -Hours 24

# Export Security avec filtre sur EventID (logon failures)
.\Export-EventLogs.ps1 -LogName Security -EventId 4625 -Days 7

# Export multiple logs en JSON
.\Export-EventLogs.ps1 -LogName System,Application -Format JSON -OutputPath C:\Exports

# Export avec compression
.\Export-EventLogs.ps1 -LogName Security -Days 30 -Compress
```

---

## Paramètres

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-LogName` | String[] | System | Journaux à exporter |
| `-Hours` | Int | - | Filtrer les N dernières heures |
| `-Days` | Int | 1 | Filtrer les N derniers jours |
| `-Level` | String[] | - | Niveaux (Error, Warning, Information) |
| `-EventId` | Int[] | - | IDs d'événements spécifiques |
| `-Source` | String | - | Source des événements |
| `-Format` | String | CSV | Format de sortie (CSV, JSON, EVTX) |
| `-OutputPath` | String | . | Dossier de destination |
| `-Compress` | Switch | - | Compresser en ZIP |

---

## Code Source

```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Export Windows Event Logs with advanced filtering.

.DESCRIPTION
    Exports event logs to CSV, JSON, or native EVTX format with support
    for date range filtering, event levels, specific EventIDs, and compression.

.PARAMETER LogName
    Event log names to export (System, Application, Security, etc.).

.PARAMETER Hours
    Export events from the last N hours.

.PARAMETER Days
    Export events from the last N days (default: 1).

.PARAMETER Level
    Filter by event level (Error, Warning, Information, Critical).

.PARAMETER EventId
    Filter by specific Event IDs.

.PARAMETER Source
    Filter by event source.

.PARAMETER Format
    Output format: CSV, JSON, or EVTX.

.PARAMETER OutputPath
    Destination folder for exports.

.PARAMETER Compress
    Compress output to ZIP archive.

.EXAMPLE
    .\Export-EventLogs.ps1 -LogName Security -EventId 4625 -Days 7
    Export failed logon events from the last 7 days.

.NOTES
    Author: ShellBook
    Version: 1.0
    Date: 2024-01-01
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$LogName = @("System"),

    [Parameter()]
    [ValidateRange(1, 8760)]
    [int]$Hours,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$Days = 1,

    [Parameter()]
    [ValidateSet("Critical", "Error", "Warning", "Information", "Verbose")]
    [string[]]$Level,

    [Parameter()]
    [int[]]$EventId,

    [Parameter()]
    [string]$Source,

    [Parameter()]
    [ValidateSet("CSV", "JSON", "EVTX")]
    [string]$Format = "CSV",

    [Parameter()]
    [ValidateScript({ Test-Path $_ -PathType Container })]
    [string]$OutputPath = ".",

    [Parameter()]
    [switch]$Compress
)

#region Configuration
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Level mapping
$LevelMap = @{
    "Critical"    = 1
    "Error"       = 2
    "Warning"     = 3
    "Information" = 4
    "Verbose"     = 5
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ExportedFiles = [System.Collections.ArrayList]::new()
#endregion

#region Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $colors = @{
        'Info'    = 'Cyan'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Success' = 'Green'
    }

    $prefix = @{
        'Info'    = '[*]'
        'Warning' = '[!]'
        'Error'   = '[X]'
        'Success' = '[+]'
    }

    Write-Host "$($prefix[$Level]) $Message" -ForegroundColor $colors[$Level]
}

function Build-FilterXPath {
    param(
        [DateTime]$StartTime,
        [string[]]$Levels,
        [int[]]$EventIds,
        [string]$SourceName
    )

    $conditions = [System.Collections.ArrayList]::new()

    # Time filter
    $timeDiff = [Math]::Round(((Get-Date) - $StartTime).TotalMilliseconds)
    [void]$conditions.Add("TimeCreated[timediff(@SystemTime) <= $timeDiff]")

    # Level filter
    if ($Levels) {
        $levelConditions = $Levels | ForEach-Object { "Level=$($LevelMap[$_])" }
        [void]$conditions.Add("(" + ($levelConditions -join " or ") + ")")
    }

    # EventID filter
    if ($EventIds) {
        $idConditions = $EventIds | ForEach-Object { "EventID=$_" }
        [void]$conditions.Add("(" + ($idConditions -join " or ") + ")")
    }

    # Source filter
    if ($SourceName) {
        [void]$conditions.Add("Provider[@Name='$SourceName']")
    }

    return "*[System[" + ($conditions -join " and ") + "]]"
}

function Export-ToCSV {
    param(
        [object[]]$Events,
        [string]$FilePath
    )

    $Events | Select-Object @(
        'TimeCreated',
        'Id',
        'LevelDisplayName',
        'ProviderName',
        @{N='Message'; E={$_.Message -replace "`r`n", " | "}}
    ) | Export-Csv -Path $FilePath -NoTypeInformation -Encoding UTF8
}

function Export-ToJSON {
    param(
        [object[]]$Events,
        [string]$FilePath
    )

    $exportData = $Events | ForEach-Object {
        [PSCustomObject]@{
            TimeCreated  = $_.TimeCreated.ToString("o")
            EventId      = $_.Id
            Level        = $_.LevelDisplayName
            Provider     = $_.ProviderName
            MachineName  = $_.MachineName
            Message      = $_.Message
            TaskCategory = $_.TaskDisplayName
        }
    }

    $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $FilePath -Encoding UTF8
}

function Export-ToEVTX {
    param(
        [string]$LogName,
        [DateTime]$StartTime,
        [string]$FilePath
    )

    $filter = Build-FilterXPath -StartTime $StartTime -Levels $Level -EventIds $EventId -SourceName $Source

    # Use wevtutil for native EVTX export
    $tempQuery = [System.IO.Path]::GetTempFileName()
    @"
<QueryList>
  <Query Id="0" Path="$LogName">
    <Select Path="$LogName">$filter</Select>
  </Query>
</QueryList>
"@ | Out-File -FilePath $tempQuery -Encoding UTF8

    wevtutil epl $LogName $FilePath /sq:$tempQuery /ow:true 2>$null
    Remove-Item $tempQuery -Force
}
#endregion

#region Main
try {
    Write-Log "=== Windows Event Log Export ===" -Level Info
    Write-Host ""

    # Calculate time range
    if ($Hours) {
        $startTime = (Get-Date).AddHours(-$Hours)
        Write-Log "Time range: Last $Hours hour(s)" -Level Info
    } else {
        $startTime = (Get-Date).AddDays(-$Days)
        Write-Log "Time range: Last $Days day(s)" -Level Info
    }

    Write-Log "Output format: $Format" -Level Info
    Write-Log "Target logs: $($LogName -join ', ')" -Level Info
    Write-Host ""

    foreach ($log in $LogName) {
        Write-Log "Processing: $log" -Level Info

        try {
            # Check if log exists
            $logInfo = Get-WinEvent -ListLog $log -ErrorAction Stop
            Write-Log "  Log size: $([Math]::Round($logInfo.FileSize / 1MB, 2)) MB" -Level Info

            # Build output filename
            $safeLogName = $log -replace '[\\\/]', '_'
            $fileName = "EventLog_${safeLogName}_${Timestamp}"

            if ($Format -eq "EVTX") {
                $outputFile = Join-Path $OutputPath "$fileName.evtx"
                Export-ToEVTX -LogName $log -StartTime $startTime -FilePath $outputFile
            } else {
                # Build XPath filter
                $xpath = Build-FilterXPath -StartTime $startTime -Levels $Level -EventIds $EventId -SourceName $Source

                # Get events
                $events = Get-WinEvent -LogName $log -FilterXPath $xpath -ErrorAction SilentlyContinue

                if (-not $events -or $events.Count -eq 0) {
                    Write-Log "  No events matching filter" -Level Warning
                    continue
                }

                Write-Log "  Found $($events.Count) events" -Level Success

                switch ($Format) {
                    "CSV" {
                        $outputFile = Join-Path $OutputPath "$fileName.csv"
                        Export-ToCSV -Events $events -FilePath $outputFile
                    }
                    "JSON" {
                        $outputFile = Join-Path $OutputPath "$fileName.json"
                        Export-ToJSON -Events $events -FilePath $outputFile
                    }
                }
            }

            if (Test-Path $outputFile) {
                $fileSize = (Get-Item $outputFile).Length
                Write-Log "  Exported: $outputFile ($([Math]::Round($fileSize / 1KB, 2)) KB)" -Level Success
                [void]$ExportedFiles.Add($outputFile)
            }
        }
        catch [System.Diagnostics.Eventing.Reader.EventLogNotFoundException] {
            Write-Log "  Log not found: $log" -Level Error
        }
        catch {
            Write-Log "  Error: $_" -Level Error
        }
    }

    Write-Host ""

    # Compress if requested
    if ($Compress -and $ExportedFiles.Count -gt 0) {
        $zipFile = Join-Path $OutputPath "EventLogs_${Timestamp}.zip"
        Write-Log "Compressing to: $zipFile" -Level Info

        Compress-Archive -Path $ExportedFiles -DestinationPath $zipFile -Force

        # Remove original files
        $ExportedFiles | ForEach-Object { Remove-Item $_ -Force }

        $zipSize = (Get-Item $zipFile).Length
        Write-Log "Archive created: $([Math]::Round($zipSize / 1KB, 2)) KB" -Level Success
    }

    # Summary
    Write-Host ""
    Write-Log "=== Export Complete ===" -Level Success
    Write-Log "Files exported: $($ExportedFiles.Count)" -Level Info
}
catch {
    Write-Log "Fatal error: $_" -Level Error
    exit 1
}
#endregion
```

---

## Exemples de Sortie

### CSV Output

```csv
"TimeCreated","Id","LevelDisplayName","ProviderName","Message"
"2024-01-15 10:30:15","7036","Information","Service Control Manager","The Windows Update service entered the running state."
"2024-01-15 10:25:42","7045","Information","Service Control Manager","A service was installed in the system."
```

### JSON Output

```json
[
  {
    "TimeCreated": "2024-01-15T10:30:15.1234567+01:00",
    "EventId": 7036,
    "Level": "Information",
    "Provider": "Service Control Manager",
    "MachineName": "SERVER01",
    "Message": "The Windows Update service entered the running state.",
    "TaskCategory": null
  }
]
```

---

## Cas d'Usage

### Audit de Sécurité

```powershell
# Tentatives de connexion échouées
.\Export-EventLogs.ps1 -LogName Security -EventId 4625,4771 -Days 30 -Format JSON

# Changements de politique
.\Export-EventLogs.ps1 -LogName Security -EventId 4719,4739 -Days 90
```

### Diagnostic Système

```powershell
# Erreurs système critiques
.\Export-EventLogs.ps1 -LogName System -Level Critical,Error -Days 7

# Événements de service
.\Export-EventLogs.ps1 -LogName System -Source "Service Control Manager" -Hours 24
```

### Archivage

```powershell
# Archive mensuelle tous journaux
.\Export-EventLogs.ps1 -LogName System,Application,Security -Days 30 -Format EVTX -Compress
```

---

## EventIDs Courants

| EventID | Journal | Description |
|---------|---------|-------------|
| 4624 | Security | Logon réussi |
| 4625 | Security | Logon échoué |
| 4720 | Security | Compte créé |
| 4726 | Security | Compte supprimé |
| 7036 | System | Changement état service |
| 7045 | System | Service installé |
| 1001 | Application | Windows Error Reporting |
| 1014 | System | DNS timeout |

---

## Voir Aussi

- [Invoke-ServerAudit.ps1](Invoke-ServerAudit.md) - Audit complet serveur
- [Audit-LocalAdmins.ps1](Audit-LocalAdmins.md) - Audit administrateurs locaux
