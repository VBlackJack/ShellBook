---
tags:
  - scripts
  - powershell
  - services
  - monitoring
---

# Get-ServiceStatus.ps1

:material-star: **Niveau : Débutant**

Gestion et monitoring des services Windows.

---

## Description

Ce script facilite la gestion des services Windows :
- Liste des services avec statut
- Filtrage par état ou nom
- Démarrage/arrêt/redémarrage
- Export des informations

---

## Prérequis

- **Système** : Windows Server 2016+ ou Windows 10/11
- **PowerShell** : Version 5.1 minimum
- **Permissions** : Droits administrateur requis pour démarrer/arrêter des services
- **Modules** : Aucun module externe requis

---

## Cas d'Usage

- **Monitoring quotidien** : Vérifier l'état des services critiques chaque matin
- **Troubleshooting** : Diagnostiquer rapidement les services en échec
- **Documentation** : Générer des rapports HTML/CSV pour audit
- **Automation** : Redémarrer automatiquement les services défaillants

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Windows service management.

.DESCRIPTION
    Liste, filtre et gère les services Windows avec
    des options de contrôle et d'export.

.PARAMETER Action
    Action à effectuer: List, Start, Stop, Restart, Status.

.PARAMETER ServiceName
    Nom du service (supporte wildcards).

.PARAMETER State
    Filtrer par état: Running, Stopped, All.

.PARAMETER OutputFormat
    Format de sortie: Console, CSV, HTML.

.EXAMPLE
    .\Get-ServiceStatus.ps1 -Action List
    Liste tous les services.

.EXAMPLE
    .\Get-ServiceStatus.ps1 -Action List -State Stopped
    Liste les services arrêtés.

.EXAMPLE
    .\Get-ServiceStatus.ps1 -Action Status -ServiceName "wuauserv"
    Affiche le statut de Windows Update.

.EXAMPLE
    .\Get-ServiceStatus.ps1 -Action Restart -ServiceName "Spooler"
    Redémarre le service d'impression.

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateSet('List', 'Start', 'Stop', 'Restart', 'Status', 'Health')]
    [string]$Action = 'List',

    [Parameter()]
    [string]$ServiceName = '*',

    [Parameter()]
    [ValidateSet('Running', 'Stopped', 'All')]
    [string]$State = 'All',

    [Parameter()]
    [ValidateSet('Console', 'CSV', 'HTML')]
    [string]$OutputFormat = 'Console'
)

#region Functions
function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

function Get-ServiceInfo {
    param(
        [string]$Name = '*',
        [string]$FilterState = 'All'
    )

    $services = Get-Service -Name $Name -ErrorAction SilentlyContinue

    if ($FilterState -ne 'All') {
        $services = $services | Where-Object Status -eq $FilterState
    }

    foreach ($svc in $services) {
        $wmiService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue

        [PSCustomObject]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            Status      = $svc.Status
            StartType   = $svc.StartType
            Account     = $wmiService.StartName
            Path        = $wmiService.PathName
            Description = $wmiService.Description
        }
    }
}

function Write-ServiceStatus {
    param([PSCustomObject]$Service)

    $statusIcon = switch ($Service.Status) {
        'Running' { "[RUN]" }
        'Stopped' { "[OFF]" }
        default   { "[???]" }
    }

    $statusColor = switch ($Service.Status) {
        'Running' { 'Green' }
        'Stopped' { 'Red' }
        default   { 'Yellow' }
    }

    Write-Host $statusIcon -ForegroundColor $statusColor -NoNewline
    Write-Host " $($Service.Name)" -NoNewline
    Write-Host " - $($Service.DisplayName)" -ForegroundColor Gray
}

function Show-ServiceDetails {
    param([string]$Name)

    $service = Get-ServiceInfo -Name $Name | Select-Object -First 1

    if (-not $service) {
        Write-Host "Service not found: $Name" -ForegroundColor Red
        return
    }

    Write-Header "SERVICE: $($service.Name)"

    Write-Host ""
    Write-Host "  Display Name : $($service.DisplayName)"
    Write-Host "  Status       : " -NoNewline

    $color = if ($service.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host $service.Status -ForegroundColor $color

    Write-Host "  Start Type   : $($service.StartType)"
    Write-Host "  Account      : $($service.Account)"
    Write-Host "  Path         : $($service.Path)"
    Write-Host ""
    Write-Host "  Description  :"
    Write-Host "  $($service.Description)" -ForegroundColor Gray
}

function Invoke-ServiceAction {
    param(
        [string]$Name,
        [ValidateSet('Start', 'Stop', 'Restart')]
        [string]$ActionType
    )

    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue

    if (-not $service) {
        Write-Host "Service not found: $Name" -ForegroundColor Red
        return $false
    }

    Write-Host "[$ActionType] $Name... " -NoNewline

    try {
        switch ($ActionType) {
            'Start' {
                if ($service.Status -eq 'Running') {
                    Write-Host "Already running" -ForegroundColor Yellow
                    return $true
                }
                Start-Service -Name $Name -ErrorAction Stop
            }
            'Stop' {
                if ($service.Status -eq 'Stopped') {
                    Write-Host "Already stopped" -ForegroundColor Yellow
                    return $true
                }
                Stop-Service -Name $Name -Force -ErrorAction Stop
            }
            'Restart' {
                Restart-Service -Name $Name -Force -ErrorAction Stop
            }
        }

        Start-Sleep -Seconds 2
        $newStatus = (Get-Service -Name $Name).Status
        Write-Host $newStatus -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "FAILED: $_" -ForegroundColor Red
        return $false
    }
}

function Get-ServiceHealth {
    Write-Header "SERVICE HEALTH CHECK"

    # Services critiques Windows
    $criticalServices = @(
        @{ Name = 'wuauserv'; DisplayName = 'Windows Update' }
        @{ Name = 'Winmgmt'; DisplayName = 'WMI' }
        @{ Name = 'EventLog'; DisplayName = 'Event Log' }
        @{ Name = 'Schedule'; DisplayName = 'Task Scheduler' }
        @{ Name = 'W32Time'; DisplayName = 'Windows Time' }
        @{ Name = 'Dhcp'; DisplayName = 'DHCP Client' }
        @{ Name = 'Dnscache'; DisplayName = 'DNS Client' }
        @{ Name = 'LanmanWorkstation'; DisplayName = 'Workstation' }
    )

    Write-Host ""
    Write-Host "  Critical Windows Services:" -ForegroundColor Cyan
    Write-Host ""

    $issues = 0

    foreach ($svcInfo in $criticalServices) {
        $svc = Get-Service -Name $svcInfo.Name -ErrorAction SilentlyContinue

        if ($svc) {
            $icon = if ($svc.Status -eq 'Running') { "[OK]" } else { "[!!]" }
            $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }

            Write-Host "  $icon " -NoNewline -ForegroundColor $color
            Write-Host "$($svcInfo.DisplayName)" -NoNewline
            Write-Host " ($($svc.Status))" -ForegroundColor Gray

            if ($svc.Status -ne 'Running') { $issues++ }
        }
    }

    # Services automatiques arrêtés
    Write-Host ""
    Write-Host "  Auto-Start Services Not Running:" -ForegroundColor Cyan
    Write-Host ""

    $autoStopped = Get-Service | Where-Object {
        $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running'
    }

    if ($autoStopped) {
        foreach ($svc in $autoStopped | Select-Object -First 10) {
            Write-Host "  [!!] $($svc.Name) - $($svc.DisplayName)" -ForegroundColor Yellow
            $issues++
        }

        if ($autoStopped.Count -gt 10) {
            Write-Host "  ... and $($autoStopped.Count - 10) more" -ForegroundColor Gray
        }
    } else {
        Write-Host "  [OK] All automatic services are running" -ForegroundColor Green
    }

    # Résumé
    Write-Host ""
    Write-Host ("-" * 60) -ForegroundColor Cyan

    if ($issues -eq 0) {
        Write-Host "  [OK] Service health: GOOD" -ForegroundColor Green
    } else {
        Write-Host "  [!!] Service health: $issues issue(s) found" -ForegroundColor Yellow
    }
}
#endregion

#region Main
switch ($Action) {
    'List' {
        $services = Get-ServiceInfo -Name $ServiceName -FilterState $State

        switch ($OutputFormat) {
            'CSV' {
                $services | Select-Object Name, DisplayName, Status, StartType, Account |
                    ConvertTo-Csv -NoTypeInformation
            }

            'HTML' {
                $htmlBody = $services | ForEach-Object {
                    $rowColor = if ($_.Status -eq 'Running') { '#d4edda' } else { '#f8d7da' }
                    "<tr style='background-color: $rowColor'>
                        <td>$($_.Name)</td>
                        <td>$($_.DisplayName)</td>
                        <td>$($_.Status)</td>
                        <td>$($_.StartType)</td>
                    </tr>"
                }

                @"
<!DOCTYPE html>
<html>
<head>
    <title>Windows Services</title>
    <style>
        body { font-family: Arial; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #4CAF50; color: white; }
    </style>
</head>
<body>
    <h1>Windows Services Report</h1>
    <p>Generated: $(Get-Date)</p>
    <table>
        <tr><th>Name</th><th>Display Name</th><th>Status</th><th>Start Type</th></tr>
        $($htmlBody -join "`n")
    </table>
</body>
</html>
"@
            }

            default {
                Write-Header "WINDOWS SERVICES"

                $running = ($services | Where-Object Status -eq 'Running').Count
                $stopped = ($services | Where-Object Status -eq 'Stopped').Count

                Write-Host "  Filter: $State | Found: $($services.Count) (Running: $running, Stopped: $stopped)"
                Write-Host ""

                foreach ($svc in $services | Sort-Object Status, Name) {
                    Write-ServiceStatus -Service $svc
                }
            }
        }
    }

    'Status' {
        Show-ServiceDetails -Name $ServiceName
    }

    'Start' {
        if ($PSCmdlet.ShouldProcess($ServiceName, "Start service")) {
            Invoke-ServiceAction -Name $ServiceName -ActionType Start
        }
    }

    'Stop' {
        if ($PSCmdlet.ShouldProcess($ServiceName, "Stop service")) {
            Invoke-ServiceAction -Name $ServiceName -ActionType Stop
        }
    }

    'Restart' {
        if ($PSCmdlet.ShouldProcess($ServiceName, "Restart service")) {
            Invoke-ServiceAction -Name $ServiceName -ActionType Restart
        }
    }

    'Health' {
        Get-ServiceHealth
    }
}
#endregion
```

---

## Utilisation

```powershell
# Liste tous les services
.\Get-ServiceStatus.ps1 -Action List

# Filtrer par état
.\Get-ServiceStatus.ps1 -Action List -State Stopped

# Rechercher par nom
.\Get-ServiceStatus.ps1 -Action List -ServiceName "*SQL*"

# Statut détaillé d'un service
.\Get-ServiceStatus.ps1 -Action Status -ServiceName wuauserv

# Gérer un service (nécessite admin)
.\Get-ServiceStatus.ps1 -Action Start -ServiceName Spooler
.\Get-ServiceStatus.ps1 -Action Restart -ServiceName wuauserv

# Health check
.\Get-ServiceStatus.ps1 -Action Health

# Export
.\Get-ServiceStatus.ps1 -Action List -OutputFormat CSV | Out-File services.csv
.\Get-ServiceStatus.ps1 -Action List -OutputFormat HTML | Out-File services.html
```

---

## Sortie Exemple

```
============================================================
  WINDOWS SERVICES
============================================================
  Filter: All | Found: 234 (Running: 89, Stopped: 145)

[RUN] BFE - Base Filtering Engine
[RUN] BITS - Background Intelligent Transfer Service
[RUN] CryptSvc - Cryptographic Services
[RUN] Dhcp - DHCP Client
[RUN] Dnscache - DNS Client
[OFF] Fax - Fax
[RUN] LanmanServer - Server
[RUN] LanmanWorkstation - Workstation
[OFF] MapsBroker - Downloaded Maps Manager
[RUN] MpsSvc - Windows Defender Firewall
...
```

---

## Voir Aussi

- [Invoke-ServerAudit.ps1](Invoke-ServerAudit.md)
- [Get-SystemInfo.ps1](Get-SystemInfo.md)
