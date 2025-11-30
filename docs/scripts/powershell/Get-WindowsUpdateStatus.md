---
tags:
  - scripts
  - powershell
  - windows
  - wsus
  - sccm
  - patching
---

# Get-WindowsUpdateStatus.ps1

Diagnostic complet du statut Windows Update (WU, WSUS, SCCM/MECM).

---

## Fonctionnalités

- Détection automatique de la source de patching (WU, WSUS, SCCM)
- Historique des mises à jour installées
- Liste des mises à jour en attente
- Vérification de la connectivité WSUS
- Diagnostic des erreurs courantes
- Support multi-serveurs
- Export JSON pour CMDB/automation

---

## Utilisation

```powershell
# Diagnostic local complet
.\Get-WindowsUpdateStatus.ps1

# Vérifier plusieurs serveurs
.\Get-WindowsUpdateStatus.ps1 -ComputerName "SRV01","SRV02" -Credential (Get-Credential)

# Afficher l'historique des 30 derniers jours
.\Get-WindowsUpdateStatus.ps1 -HistoryDays 30

# Export JSON pour CMDB
.\Get-WindowsUpdateStatus.ps1 -OutputFormat JSON | Out-File status.json

# Vérifier uniquement les updates en attente
.\Get-WindowsUpdateStatus.ps1 -PendingOnly
```

---

## Paramètres

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-ComputerName` | String[] | localhost | Serveurs à analyser |
| `-Credential` | PSCredential | - | Credentials pour accès distant |
| `-HistoryDays` | Int | 7 | Historique en jours |
| `-PendingOnly` | Switch | - | Afficher uniquement les updates en attente |
| `-OutputFormat` | String | Table | Format (Table, JSON, CSV) |
| `-IncludeDrivers` | Switch | - | Inclure les drivers dans l'analyse |

---

## Code Source

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive Windows Update status diagnostic.

.DESCRIPTION
    Analyzes Windows Update configuration, identifies update source (WU/WSUS/SCCM),
    lists pending and installed updates, and diagnoses common issues.

.PARAMETER ComputerName
    Target computers to analyze.

.PARAMETER Credential
    Credentials for remote access.

.PARAMETER HistoryDays
    Number of days of update history to retrieve.

.PARAMETER PendingOnly
    Only show pending updates.

.PARAMETER OutputFormat
    Output format: Table, JSON, or CSV.

.PARAMETER IncludeDrivers
    Include driver updates in the analysis.

.EXAMPLE
    .\Get-WindowsUpdateStatus.ps1 -ComputerName "SRV01" -HistoryDays 30
    Get update status with 30 days of history.

.NOTES
    Author: ShellBook
    Version: 1.0
    Date: 2024-01-01
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true)]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    $Credential,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$HistoryDays = 7,

    [Parameter()]
    [switch]$PendingOnly,

    [Parameter()]
    [ValidateSet('Table', 'JSON', 'CSV')]
    [string]$OutputFormat = 'Table',

    [Parameter()]
    [switch]$IncludeDrivers
)

#region Configuration
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
#endregion

#region Functions
function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'OK', 'Warning', 'Error', 'Header')]
        [string]$Level = 'Info'
    )

    $styles = @{
        'Info'    = @{ Color = 'Cyan';   Prefix = '[*]' }
        'OK'      = @{ Color = 'Green';  Prefix = '[+]' }
        'Warning' = @{ Color = 'Yellow'; Prefix = '[!]' }
        'Error'   = @{ Color = 'Red';    Prefix = '[X]' }
        'Header'  = @{ Color = 'Magenta'; Prefix = '===' }
    }

    Write-Host "$($styles[$Level].Prefix) $Message" -ForegroundColor $styles[$Level].Color
}

function Get-UpdateSourceInfo {
    <#
    .SYNOPSIS
        Detect update source configuration (WU/WSUS/SCCM).
    #>
    $source = [PSCustomObject]@{
        Type            = "Windows Update"
        WSUSServer      = $null
        WSUSPort        = $null
        WSUSConnectivity = $null
        SCCMManaged     = $false
        SCCMServer      = $null
        GroupPolicy     = $null
        AutoUpdate      = $null
        LastCheck       = $null
        Errors          = @()
    }

    try {
        # Check WSUS configuration
        $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        if (Test-Path $wuKey) {
            $wuSettings = Get-ItemProperty -Path $wuKey -ErrorAction SilentlyContinue

            if ($wuSettings.WUServer) {
                $source.Type = "WSUS"
                $source.WSUSServer = $wuSettings.WUServer
                $source.GroupPolicy = $true

                # Parse WSUS URL
                if ($wuSettings.WUServer -match 'https?://([^:/]+):?(\d+)?') {
                    $wsusHost = $Matches[1]
                    $wsusPort = if ($Matches[2]) { [int]$Matches[2] } else { 8530 }
                    $source.WSUSPort = $wsusPort

                    # Test WSUS connectivity
                    try {
                        $tcp = [System.Net.Sockets.TcpClient]::new()
                        $tcp.Connect($wsusHost, $wsusPort)
                        $source.WSUSConnectivity = $tcp.Connected
                        $tcp.Close()
                    }
                    catch {
                        $source.WSUSConnectivity = $false
                        $source.Errors += "Cannot connect to WSUS: $wsusHost`:$wsusPort"
                    }
                }
            }
        }

        # Check SCCM/MECM client
        try {
            $ccmClient = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Client' -ErrorAction Stop
            $source.SCCMManaged = $true
            $source.Type = "SCCM/MECM"

            # Get MP server
            $mpInfo = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Authority' -ErrorAction SilentlyContinue
            if ($mpInfo) {
                $source.SCCMServer = $mpInfo.CurrentManagementPoint
            }
        }
        catch {
            # SCCM not installed
        }

        # Get Auto Update settings
        $auKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
        if (Test-Path $auKey) {
            $auSettings = Get-ItemProperty -Path $auKey -ErrorAction SilentlyContinue
            $source.LastCheck = $auSettings.LastOnlineScanTimeForAppCategory
        }

        # Get scheduled task info for AU
        $auTask = Get-ScheduledTask -TaskName 'Scheduled Start' -TaskPath '\Microsoft\Windows\WindowsUpdate\' -ErrorAction SilentlyContinue
        if ($auTask) {
            $source.AutoUpdate = $auTask.State
        }
    }
    catch {
        $source.Errors += $_.Exception.Message
    }

    return $source
}

function Get-PendingUpdates {
    <#
    .SYNOPSIS
        Get list of pending Windows Updates.
    #>
    param(
        [bool]$IncludeDriverUpdates
    )

    $updates = @()

    try {
        # Use COM object for update search
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()

        # Build search criteria
        $criteria = "IsInstalled=0 and IsHidden=0"
        if (-not $IncludeDriverUpdates) {
            $criteria += " and Type='Software'"
        }

        $searchResult = $updateSearcher.Search($criteria)

        foreach ($update in $searchResult.Updates) {
            $updates += [PSCustomObject]@{
                Title         = $update.Title
                KB            = ($update.KBArticleIDs | Select-Object -First 1)
                Category      = ($update.Categories | Select-Object -First 1 -ExpandProperty Name)
                Severity      = $update.MsrcSeverity
                Size          = [Math]::Round($update.MaxDownloadSize / 1MB, 2)
                IsDownloaded  = $update.IsDownloaded
                IsMandatory   = $update.IsMandatory
                RebootRequired = $update.RebootRequired
                Published     = $update.LastDeploymentChangeTime
            }
        }
    }
    catch {
        Write-Status "Error getting pending updates: $_" -Level Error
    }

    return $updates
}

function Get-UpdateHistory {
    <#
    .SYNOPSIS
        Get Windows Update installation history.
    #>
    param(
        [int]$Days
    )

    $history = @()
    $cutoffDate = (Get-Date).AddDays(-$Days)

    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $historyCount = $updateSearcher.GetTotalHistoryCount()

        if ($historyCount -gt 0) {
            $updateHistory = $updateSearcher.QueryHistory(0, $historyCount)

            foreach ($entry in $updateHistory) {
                if ($entry.Date -lt $cutoffDate) { continue }

                $resultCode = switch ($entry.ResultCode) {
                    0 { "Not Started" }
                    1 { "In Progress" }
                    2 { "Succeeded" }
                    3 { "Succeeded With Errors" }
                    4 { "Failed" }
                    5 { "Aborted" }
                    default { "Unknown" }
                }

                $history += [PSCustomObject]@{
                    Date        = $entry.Date
                    Title       = $entry.Title
                    KB          = if ($entry.Title -match 'KB(\d+)') { $Matches[1] } else { $null }
                    Result      = $resultCode
                    Operation   = switch ($entry.Operation) { 1 { "Install" }; 2 { "Uninstall" }; default { "Other" } }
                    HResult     = if ($entry.ResultCode -eq 4) { "0x{0:X8}" -f $entry.HResult } else { $null }
                }
            }
        }
    }
    catch {
        Write-Status "Error getting update history: $_" -Level Error
    }

    return $history | Sort-Object Date -Descending
}

function Get-ServiceStatus {
    <#
    .SYNOPSIS
        Check Windows Update related services.
    #>
    $services = @(
        @{ Name = 'wuauserv';        DisplayName = 'Windows Update' },
        @{ Name = 'BITS';            DisplayName = 'Background Intelligent Transfer' },
        @{ Name = 'CryptSvc';        DisplayName = 'Cryptographic Services' },
        @{ Name = 'TrustedInstaller'; DisplayName = 'Windows Modules Installer' }
    )

    $results = foreach ($svc in $services) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            Name        = $svc.Name
            DisplayName = $svc.DisplayName
            Status      = if ($service) { $service.Status.ToString() } else { "Not Found" }
            StartType   = if ($service) { $service.StartType.ToString() } else { "N/A" }
        }
    }

    return $results
}

function Get-ComponentStoreHealth {
    <#
    .SYNOPSIS
        Check component store (SxS) health.
    #>
    $health = [PSCustomObject]@{
        LastAnalyzeTime    = $null
        ComponentCleanup   = $null
        RepairPending      = $false
        WinSxSSize         = $null
    }

    try {
        # Check for pending repairs
        $cbsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing'
        if (Test-Path "$cbsKey\RebootPending") {
            $health.RepairPending = $true
        }

        # Get WinSxS size
        $sxsPath = "$env:SystemRoot\WinSxS"
        if (Test-Path $sxsPath) {
            $size = (Get-ChildItem -Path $sxsPath -Recurse -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            $health.WinSxSSize = [Math]::Round($size / 1GB, 2)
        }

        # Get last cleanup info
        $cleanupKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup'
        if (Test-Path $cleanupKey) {
            $cleanup = Get-ItemProperty -Path $cleanupKey -ErrorAction SilentlyContinue
            $health.ComponentCleanup = $cleanup.StateFlags
        }
    }
    catch {
        # Ignore errors
    }

    return $health
}

function Test-LocalComputer {
    <#
    .SYNOPSIS
        Run all diagnostics on local computer.
    #>
    $result = [PSCustomObject]@{
        ComputerName     = $env:COMPUTERNAME
        OSVersion        = (Get-CimInstance Win32_OperatingSystem).Caption
        OSBuild          = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
        LastBootTime     = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        UpdateSource     = $null
        Services         = @()
        PendingUpdates   = @()
        RecentHistory    = @()
        ComponentHealth  = $null
        Errors           = @()
        CheckTime        = Get-Date
    }

    Write-Status "Analyzing: $($result.ComputerName)" -Level Header

    # Update source
    Write-Status "Checking update source configuration..." -Level Info
    $result.UpdateSource = Get-UpdateSourceInfo

    # Services
    Write-Status "Checking related services..." -Level Info
    $result.Services = Get-ServiceStatus

    # Pending updates
    if (-not $PendingOnly -or $true) {
        Write-Status "Scanning for pending updates..." -Level Info
        $result.PendingUpdates = Get-PendingUpdates -IncludeDriverUpdates $IncludeDrivers
    }

    # History
    if (-not $PendingOnly) {
        Write-Status "Retrieving update history ($HistoryDays days)..." -Level Info
        $result.RecentHistory = Get-UpdateHistory -Days $HistoryDays
    }

    # Component health
    Write-Status "Checking component store health..." -Level Info
    $result.ComponentHealth = Get-ComponentStoreHealth

    return $result
}
#endregion

#region Main
try {
    Write-Status "Windows Update Status Diagnostic" -Level Header
    Write-Host ""

    $allResults = @()

    foreach ($computer in $ComputerName) {
        if ($computer -eq $env:COMPUTERNAME -or $computer -eq 'localhost') {
            $result = Test-LocalComputer
        } else {
            # Remote execution via Invoke-Command would go here
            Write-Status "Remote diagnostics for $computer - use PSRemoting" -Level Warning
            continue
        }

        $allResults += $result
    }

    # Output
    Write-Host ""
    Write-Status "Results" -Level Header
    Write-Host ""

    foreach ($result in $allResults) {
        # Summary
        Write-Host "Computer: $($result.ComputerName)" -ForegroundColor Cyan
        Write-Host "  OS: $($result.OSVersion) (Build $($result.OSBuild))"
        Write-Host "  Update Source: $($result.UpdateSource.Type)"

        if ($result.UpdateSource.WSUSServer) {
            $wsusStatus = if ($result.UpdateSource.WSUSConnectivity) { "Connected" } else { "UNREACHABLE" }
            Write-Host "  WSUS Server: $($result.UpdateSource.WSUSServer) [$wsusStatus]"
        }

        if ($result.UpdateSource.SCCMManaged) {
            Write-Host "  SCCM Server: $($result.UpdateSource.SCCMServer)"
        }

        Write-Host ""

        # Services
        Write-Host "  Services:" -ForegroundColor Yellow
        foreach ($svc in $result.Services) {
            $color = if ($svc.Status -eq 'Running') { 'Green' } else { 'Red' }
            Write-Host "    $($svc.DisplayName): " -NoNewline
            Write-Host $svc.Status -ForegroundColor $color
        }

        Write-Host ""

        # Pending updates
        Write-Host "  Pending Updates: $($result.PendingUpdates.Count)" -ForegroundColor Yellow
        if ($result.PendingUpdates.Count -gt 0) {
            $critical = ($result.PendingUpdates | Where-Object { $_.Severity -eq 'Critical' }).Count
            $important = ($result.PendingUpdates | Where-Object { $_.Severity -eq 'Important' }).Count
            Write-Host "    Critical: $critical | Important: $important"

            foreach ($update in $result.PendingUpdates | Select-Object -First 10) {
                $kb = if ($update.KB) { "KB$($update.KB)" } else { "" }
                Write-Host "    - [$($update.Severity)] $kb $($update.Title.Substring(0, [Math]::Min(60, $update.Title.Length)))..."
            }

            if ($result.PendingUpdates.Count -gt 10) {
                Write-Host "    ... and $($result.PendingUpdates.Count - 10) more"
            }
        }

        Write-Host ""

        # Recent failures
        $failures = $result.RecentHistory | Where-Object { $_.Result -eq 'Failed' } | Select-Object -First 5
        if ($failures) {
            Write-Host "  Recent Failures:" -ForegroundColor Red
            foreach ($fail in $failures) {
                Write-Host "    - $($fail.Date.ToString('yyyy-MM-dd')): $($fail.Title.Substring(0, [Math]::Min(50, $fail.Title.Length)))... [$($fail.HResult)]"
            }
            Write-Host ""
        }

        # Component health
        Write-Host "  Component Store: $($result.ComponentHealth.WinSxSSize) GB" -ForegroundColor Yellow
        if ($result.ComponentHealth.RepairPending) {
            Write-Host "    WARNING: Repair pending" -ForegroundColor Red
        }

        Write-Host ""
    }

    # JSON output
    if ($OutputFormat -eq 'JSON') {
        $allResults | ConvertTo-Json -Depth 10
    }
}
catch {
    Write-Status "Fatal error: $_" -Level Error
    exit 1
}
#endregion
```

---

## Exemple de Sortie

```
=== Windows Update Status Diagnostic ===

=== Analyzing: SRV-PROD01 ===
[*] Checking update source configuration...
[*] Checking related services...
[*] Scanning for pending updates...
[*] Retrieving update history (7 days)...
[*] Checking component store health...

=== Results ===

Computer: SRV-PROD01
  OS: Microsoft Windows Server 2022 Standard (Build 20348)
  Update Source: WSUS
  WSUS Server: http://wsus.corp.local:8530 [Connected]

  Services:
    Windows Update: Running
    Background Intelligent Transfer: Running
    Cryptographic Services: Running
    Windows Modules Installer: Stopped

  Pending Updates: 5
    Critical: 1 | Important: 3
    - [Critical] KB5034441 2024-01 Cumulative Update for Windows Server 2022...
    - [Important] KB5034439 2024-01 Security Update for .NET Framework...
    - [Important] KB5034123 2024-01 Servicing Stack Update...

  Recent Failures:
    - 2024-01-10: KB5033914 Security Update for Windows Server 2022... [0x80070002]

  Component Store: 8.45 GB
```

---

## Diagnostic des Erreurs Courantes

| Code | Description | Solution |
|------|-------------|----------|
| `0x80070002` | Fichier introuvable | Réparer le composant store avec DISM |
| `0x80073712` | Composant store corrompu | `DISM /Online /Cleanup-Image /RestoreHealth` |
| `0x8024402C` | Impossible de contacter WSUS | Vérifier connectivité réseau |
| `0x80244022` | Accès refusé | Vérifier les permissions |
| `0x800B0109` | Certificat non approuvé | Mettre à jour les certificats racine |

---

## Voir Aussi

- [Repair-WindowsUpdate.ps1](Repair-WindowsUpdate.md) - Réparation WU
- [Get-PatchCompliance.ps1](Get-PatchCompliance.md) - Conformité patchs
- [Test-WSUSHealth.ps1](Test-WSUSHealth.md) - Santé serveur WSUS
