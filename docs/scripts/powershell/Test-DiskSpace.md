---
tags:
  - scripts
  - powershell
  - système
  - disque
  - monitoring
---

# Test-DiskSpace.ps1

:material-star: **Niveau : Débutant**

Vérifie l'espace disque et génère des alertes.

---

## Description

Ce script surveille l'utilisation des disques Windows :
- Vérification de tous les lecteurs ou d'un lecteur spécifique
- Alertes configurables (warning/critical)
- Support des lecteurs réseau
- Export CSV ou HTML

---

## Prérequis

- **Système** : Windows Server 2016+ ou Windows 10/11
- **PowerShell** : Version 5.1 minimum
- **Permissions** : Lecture système (pas d'élévation requise)
- **Modules** : Aucun module externe requis

---

## Cas d'Usage

- **Monitoring quotidien** : Tâche planifiée pour surveillance automatique des disques
- **Alerting** : Intégration avec système de monitoring (Nagios, PRTG, Zabbix)
- **Rapports management** : Génération de rapports HTML pour documentation
- **Prévention incidents** : Détecter les disques pleins avant qu'ils ne causent des problèmes

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Vérifie l'espace disque avec alertes.

.DESCRIPTION
    Surveille l'utilisation des disques et génère des alertes
    si les seuils sont dépassés.

.PARAMETER Drive
    Lettre du lecteur à vérifier (ex: C). Par défaut, tous les lecteurs.

.PARAMETER WarningThreshold
    Seuil d'avertissement en pourcentage (défaut: 80).

.PARAMETER CriticalThreshold
    Seuil critique en pourcentage (défaut: 90).

.PARAMETER OutputFormat
    Format de sortie: Console, CSV, ou HTML.

.EXAMPLE
    .\Test-DiskSpace.ps1
    Vérifie tous les disques avec les seuils par défaut.

.EXAMPLE
    .\Test-DiskSpace.ps1 -Drive C -WarningThreshold 70 -CriticalThreshold 85
    Vérifie le disque C avec des seuils personnalisés.

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Drive,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$WarningThreshold = 80,

    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$CriticalThreshold = 90,

    [Parameter()]
    [ValidateSet('Console', 'CSV', 'HTML')]
    [string]$OutputFormat = 'Console'
)

#region Functions
function Get-DiskSpaceInfo {
    param(
        [string]$DriveLetter
    )

    $filter = if ($DriveLetter) {
        "DeviceID='$($DriveLetter):'"
    } else {
        "DriveType=3"
    }

    Get-CimInstance -ClassName Win32_LogicalDisk -Filter $filter | ForEach-Object {
        $totalGB = [math]::Round($_.Size / 1GB, 2)
        $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
        $usedGB = $totalGB - $freeGB
        $usedPercent = if ($totalGB -gt 0) {
            [math]::Round(($usedGB / $totalGB) * 100, 1)
        } else { 0 }

        # Déterminer le statut
        $status = switch ($usedPercent) {
            { $_ -ge $CriticalThreshold } { 'Critical'; break }
            { $_ -ge $WarningThreshold }  { 'Warning'; break }
            default { 'OK' }
        }

        [PSCustomObject]@{
            Drive       = $_.DeviceID
            Label       = $_.VolumeName
            FileSystem  = $_.FileSystem
            TotalGB     = $totalGB
            UsedGB      = $usedGB
            FreeGB      = $freeGB
            UsedPercent = $usedPercent
            Status      = $status
        }
    }
}

function Write-DiskStatus {
    param(
        [PSCustomObject]$DiskInfo
    )

    $color = switch ($DiskInfo.Status) {
        'Critical' { 'Red' }
        'Warning'  { 'Yellow' }
        default    { 'Green' }
    }

    $statusIcon = switch ($DiskInfo.Status) {
        'Critical' { '[CRIT]' }
        'Warning'  { '[WARN]' }
        default    { '[OK]  ' }
    }

    Write-Host $statusIcon -ForegroundColor $color -NoNewline
    Write-Host (" {0} [{1}] - {2:N1} GB / {3:N1} GB ({4:N1}%)" -f
        $DiskInfo.Drive,
        $DiskInfo.Label,
        $DiskInfo.UsedGB,
        $DiskInfo.TotalGB,
        $DiskInfo.UsedPercent)
}

function Get-DiskBar {
    param(
        [double]$Percent,
        [int]$Width = 30
    )

    $filled = [math]::Round(($Percent / 100) * $Width)
    $empty = $Width - $filled

    $bar = ('█' * $filled) + ('░' * $empty)
    return $bar
}
#endregion

#region Main
$diskInfo = Get-DiskSpaceInfo -DriveLetter $Drive

if (-not $diskInfo) {
    Write-Error "Aucun disque trouvé"
    exit 1
}

switch ($OutputFormat) {
    'CSV' {
        $diskInfo | ConvertTo-Csv -NoTypeInformation
    }

    'HTML' {
        $htmlBody = $diskInfo | ForEach-Object {
            $rowColor = switch ($_.Status) {
                'Critical' { '#ffcccc' }
                'Warning'  { '#fff3cd' }
                default    { '#d4edda' }
            }
            "<tr style='background-color: $rowColor'>
                <td>$($_.Drive)</td>
                <td>$($_.Label)</td>
                <td>$("{0:N1}" -f $_.TotalGB) GB</td>
                <td>$("{0:N1}" -f $_.UsedGB) GB</td>
                <td>$("{0:N1}" -f $_.FreeGB) GB</td>
                <td>$("{0:N1}" -f $_.UsedPercent)%</td>
                <td>$($_.Status)</td>
            </tr>"
        }

        @"
<!DOCTYPE html>
<html>
<head>
    <title>Disk Space Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>Disk Space Report</h1>
    <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    <p>Warning Threshold: $WarningThreshold% | Critical Threshold: $CriticalThreshold%</p>
    <table>
        <tr>
            <th>Drive</th>
            <th>Label</th>
            <th>Total</th>
            <th>Used</th>
            <th>Free</th>
            <th>Used %</th>
            <th>Status</th>
        </tr>
        $($htmlBody -join "`n")
    </table>
</body>
</html>
"@
    }

    default {
        # Console output
        Write-Host ""
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "  DISK SPACE CHECK" -ForegroundColor Green
        Write-Host ("=" * 60) -ForegroundColor Cyan
        Write-Host "  Warning: $WarningThreshold% | Critical: $CriticalThreshold%"
        Write-Host ("-" * 60) -ForegroundColor Cyan

        foreach ($disk in $diskInfo) {
            Write-DiskStatus -DiskInfo $disk

            # Barre de progression
            $barColor = switch ($disk.Status) {
                'Critical' { 'Red' }
                'Warning'  { 'Yellow' }
                default    { 'Green' }
            }
            $bar = Get-DiskBar -Percent $disk.UsedPercent
            Write-Host "       [$bar] $("{0:N1}%" -f $disk.UsedPercent)" -ForegroundColor $barColor
            Write-Host ""
        }

        Write-Host ("-" * 60) -ForegroundColor Cyan

        # Résumé
        $critCount = ($diskInfo | Where-Object Status -eq 'Critical').Count
        $warnCount = ($diskInfo | Where-Object Status -eq 'Warning').Count
        $okCount = ($diskInfo | Where-Object Status -eq 'OK').Count

        Write-Host "  Summary: " -NoNewline
        Write-Host "$okCount OK" -ForegroundColor Green -NoNewline
        Write-Host " | " -NoNewline
        Write-Host "$warnCount Warning" -ForegroundColor Yellow -NoNewline
        Write-Host " | " -NoNewline
        Write-Host "$critCount Critical" -ForegroundColor Red

        Write-Host ("=" * 60) -ForegroundColor Cyan

        # Code de retour
        if ($critCount -gt 0) { exit 2 }
        if ($warnCount -gt 0) { exit 1 }
        exit 0
    }
}
#endregion
```

---

## Utilisation

```powershell
# Vérifier tous les disques
.\Test-DiskSpace.ps1

# Vérifier un disque spécifique
.\Test-DiskSpace.ps1 -Drive C

# Seuils personnalisés
.\Test-DiskSpace.ps1 -WarningThreshold 70 -CriticalThreshold 85

# Export CSV
.\Test-DiskSpace.ps1 -OutputFormat CSV | Out-File disks.csv

# Rapport HTML
.\Test-DiskSpace.ps1 -OutputFormat HTML | Out-File disk-report.html
```

---

## Sortie Exemple

```
============================================================
  DISK SPACE CHECK
============================================================
  Warning: 80% | Critical: 90%
------------------------------------------------------------
[OK]   C: [System] - 234.5 GB / 500.0 GB (46.9%)
       [██████████████░░░░░░░░░░░░░░░░] 46.9%

[WARN] D: [Data] - 890.2 GB / 1000.0 GB (89.0%)
       [██████████████████████████░░░░] 89.0%

[CRIT] E: [Backup] - 475.8 GB / 500.0 GB (95.2%)
       [████████████████████████████░░] 95.2%

------------------------------------------------------------
  Summary: 1 OK | 1 Warning | 1 Critical
============================================================
```

---

## Intégration Tâche Planifiée

```powershell
# Créer une tâche planifiée pour vérification quotidienne
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Scripts\Test-DiskSpace.ps1"'

$trigger = New-ScheduledTaskTrigger -Daily -At 8am

Register-ScheduledTask -TaskName "DiskSpaceCheck" `
    -Action $action -Trigger $trigger -Description "Daily disk space check"
```

---

## Voir Aussi

- [Get-SystemInfo.ps1](Get-SystemInfo.md)
- [Find-LargeFiles.ps1](Find-LargeFiles.md)
