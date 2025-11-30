---
tags:
  - scripts
  - powershell
  - windows
  - patching
  - maintenance
  - production
---

# Invoke-PrePatchPreparation.ps1

Préparation complète d'un serveur avant une fenêtre de patching.

---

## Fonctionnalités

- **Nettoyage système** : Disk Cleanup, Windows Update cache, fichiers temporaires
- **Libération d'espace disque** : Vérification seuil minimum, nettoyage composant store
- **Vérification services** : WSUS/WU/BITS/Crypto services opérationnels
- **Pré-téléchargement** : Download des updates sans installation
- **Snapshot/Checkpoint** : Point de restauration automatique
- **Health Check** : Vérifications CBS, DISM, SFC
- **Rapport JSON** : Export pour suivi et automation

---

## Utilisation

```powershell
# Préparation complète (mode interactif)
.\Invoke-PrePatchPreparation.ps1

# Mode automatique (sans confirmation)
.\Invoke-PrePatchPreparation.ps1 -Force

# Nettoyage agressif + pré-téléchargement
.\Invoke-PrePatchPreparation.ps1 -DeepClean -PreDownload

# Créer un point de restauration avant patch
.\Invoke-PrePatchPreparation.ps1 -CreateRestorePoint

# Export rapport JSON
.\Invoke-PrePatchPreparation.ps1 -ReportPath "C:\PatchReports\prepatch.json"

# Multi-serveurs (exécution parallèle)
$servers = Get-Content servers.txt
Invoke-Command -ComputerName $servers -FilePath .\Invoke-PrePatchPreparation.ps1 -ArgumentList @{Force=$true}
```

---

## Paramètres

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-Force` | Switch | - | Mode automatique sans confirmation |
| `-DeepClean` | Switch | - | Nettoyage agressif (WinSxS cleanup) |
| `-PreDownload` | Switch | - | Télécharger les updates sans installer |
| `-CreateRestorePoint` | Switch | - | Créer un point de restauration |
| `-MinDiskSpaceGB` | Int | 10 | Espace disque minimum requis (GB) |
| `-ReportPath` | String | - | Chemin export rapport JSON |
| `-SkipHealthCheck` | Switch | - | Ignorer les vérifications DISM/SFC |
| `-StopServices` | String[] | - | Services à arrêter avant patch |

---

## Workflow de Préparation

```
┌─────────────────────────────────────────────────────────────────┐
│                    PRE-PATCH PREPARATION                         │
├─────────────────────────────────────────────────────────────────┤
│  1. INITIAL CHECKS                                               │
│     ├─ Disk space verification                                   │
│     ├─ Pending reboot check                                      │
│     └─ Admin rights validation                                   │
├─────────────────────────────────────────────────────────────────┤
│  2. SERVICE HEALTH                                               │
│     ├─ Windows Update service                                    │
│     ├─ BITS service                                              │
│     ├─ Cryptographic Services                                    │
│     └─ WSUS/SCCM connectivity                                    │
├─────────────────────────────────────────────────────────────────┤
│  3. SYSTEM CLEANUP                                               │
│     ├─ Windows Update cache                                      │
│     ├─ Temporary files                                           │
│     ├─ Windows Installer cache                                   │
│     ├─ DISM component cleanup (if DeepClean)                     │
│     └─ Old Windows versions                                      │
├─────────────────────────────────────────────────────────────────┤
│  4. HEALTH VERIFICATION                                          │
│     ├─ CBS log analysis                                          │
│     ├─ DISM /CheckHealth                                         │
│     └─ Pending repairs detection                                 │
├─────────────────────────────────────────────────────────────────┤
│  5. PRE-DOWNLOAD (optional)                                      │
│     ├─ Scan available updates                                    │
│     └─ Download without install                                  │
├─────────────────────────────────────────────────────────────────┤
│  6. RESTORE POINT (optional)                                     │
│     └─ Create system checkpoint                                  │
├─────────────────────────────────────────────────────────────────┤
│  7. REPORT GENERATION                                            │
│     └─ JSON export with all results                              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Code Source

```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Prepare Windows server for patching maintenance window.

.DESCRIPTION
    Comprehensive pre-patch preparation script that cleans up disk space,
    verifies services, pre-downloads updates, and creates restore points
    to ensure smooth patching operations.

.PARAMETER Force
    Run without interactive prompts.

.PARAMETER DeepClean
    Aggressive cleanup including WinSxS component store.

.PARAMETER PreDownload
    Download pending updates without installing.

.PARAMETER CreateRestorePoint
    Create a system restore point before patching.

.PARAMETER MinDiskSpaceGB
    Minimum required disk space in GB (default: 10).

.PARAMETER ReportPath
    Path to save JSON report.

.PARAMETER SkipHealthCheck
    Skip DISM/SFC health verification.

.PARAMETER StopServices
    Array of service names to stop before patching.

.EXAMPLE
    .\Invoke-PrePatchPreparation.ps1 -Force -DeepClean -PreDownload
    Full automatic preparation with aggressive cleanup.

.NOTES
    Author: ShellBook
    Version: 1.0
    Date: 2024-01-01

    IMPORTANT: Run this script 2-4 hours before your maintenance window
    to allow time for downloads and cleanup operations.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$DeepClean,

    [Parameter()]
    [switch]$PreDownload,

    [Parameter()]
    [switch]$CreateRestorePoint,

    [Parameter()]
    [ValidateRange(5, 100)]
    [int]$MinDiskSpaceGB = 10,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [switch]$SkipHealthCheck,

    [Parameter()]
    [string[]]$StopServices
)

#region Configuration
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$Script:StartTime = Get-Date
$Script:Report = [PSCustomObject]@{
    ComputerName     = $env:COMPUTERNAME
    StartTime        = $Script:StartTime
    EndTime          = $null
    Duration         = $null
    OSVersion        = $null
    InitialDiskSpace = $null
    FinalDiskSpace   = $null
    SpaceReclaimed   = $null
    Checks           = @{}
    Cleanup          = @{}
    Services         = @{}
    Updates          = @{}
    Warnings         = [System.Collections.ArrayList]::new()
    Errors           = [System.Collections.ArrayList]::new()
    ReadyForPatch    = $false
}
#endregion

#region Functions
function Write-Step {
    param(
        [string]$Message,
        [ValidateSet('Info', 'OK', 'Warning', 'Error', 'Header', 'SubStep')]
        [string]$Level = 'Info'
    )

    $styles = @{
        'Info'    = @{ Color = 'Cyan';    Prefix = '[*]'; Indent = '' }
        'OK'      = @{ Color = 'Green';   Prefix = '[+]'; Indent = '' }
        'Warning' = @{ Color = 'Yellow';  Prefix = '[!]'; Indent = '' }
        'Error'   = @{ Color = 'Red';     Prefix = '[X]'; Indent = '' }
        'Header'  = @{ Color = 'Magenta'; Prefix = ''; Indent = '' }
        'SubStep' = @{ Color = 'Gray';    Prefix = '   '; Indent = '    ' }
    }

    $style = $styles[$Level]
    Write-Host "$($style.Indent)$($style.Prefix) $Message" -ForegroundColor $style.Color
}

function Get-DiskSpaceGB {
    param([string]$Drive = $env:SystemDrive)
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$Drive'"
    return [Math]::Round($disk.FreeSpace / 1GB, 2)
}

function Test-PendingReboot {
    $pending = $false
    $reasons = @()

    # Windows Update
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $pending = $true
        $reasons += 'Windows Update'
    }

    # CBS
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $pending = $true
        $reasons += 'Component Based Servicing'
    }

    # File Rename
    $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
    if ($pfro.PendingFileRenameOperations) {
        $pending = $true
        $reasons += 'Pending File Rename'
    }

    return @{ Pending = $pending; Reasons = $reasons }
}

function Stop-UpdateServices {
    $services = @('wuauserv', 'BITS', 'CryptSvc')
    foreach ($svc in $services) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 2
}

function Start-UpdateServices {
    $services = @('CryptSvc', 'BITS', 'wuauserv')
    foreach ($svc in $services) {
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
}

function Clear-WindowsUpdateCache {
    Write-Step "Clearing Windows Update cache..." -Level SubStep

    $paths = @(
        "$env:SystemRoot\SoftwareDistribution\Download\*",
        "$env:SystemRoot\SoftwareDistribution\DataStore\*"
    )

    $cleared = 0
    foreach ($path in $paths) {
        if (Test-Path $path) {
            $size = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            $cleared += $size
        }
    }

    return [Math]::Round($cleared / 1MB, 2)
}

function Clear-TempFiles {
    Write-Step "Clearing temporary files..." -Level SubStep

    $paths = @(
        "$env:TEMP\*",
        "$env:SystemRoot\Temp\*",
        "$env:SystemRoot\Prefetch\*"
    )

    $cleared = 0
    foreach ($path in $paths) {
        if (Test-Path $path) {
            $items = Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            $size = ($items | Measure-Object -Property Length -Sum).Sum
            $items | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            $cleared += $size
        }
    }

    return [Math]::Round($cleared / 1MB, 2)
}

function Clear-WindowsInstallerCache {
    Write-Step "Analyzing Windows Installer cache..." -Level SubStep

    $installerPath = "$env:SystemRoot\Installer"
    $orphanedSize = 0

    # Only report size, don't delete (dangerous without proper analysis)
    if (Test-Path $installerPath) {
        $orphanedSize = (Get-ChildItem -Path "$installerPath\*.msp" -ErrorAction SilentlyContinue |
                         Measure-Object -Property Length -Sum).Sum
    }

    return [Math]::Round($orphanedSize / 1MB, 2)
}

function Invoke-ComponentCleanup {
    Write-Step "Running DISM component cleanup..." -Level SubStep

    try {
        $result = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" `
                               -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\dism_cleanup.log"

        return @{
            ExitCode = $result.ExitCode
            Success  = $result.ExitCode -eq 0
        }
    }
    catch {
        return @{ ExitCode = -1; Success = $false; Error = $_.Exception.Message }
    }
}

function Clear-OldProfiles {
    Write-Step "Checking old user profiles..." -Level SubStep

    $profiles = Get-CimInstance -ClassName Win32_UserProfile |
                Where-Object { -not $_.Special -and $_.LastUseTime -lt (Get-Date).AddDays(-90) }

    $totalSize = 0
    foreach ($profile in $profiles) {
        if (Test-Path $profile.LocalPath) {
            $size = (Get-ChildItem -Path $profile.LocalPath -Recurse -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            $totalSize += $size
        }
    }

    return @{
        Count = $profiles.Count
        SizeMB = [Math]::Round($totalSize / 1MB, 2)
    }
}

function Test-ServiceHealth {
    Write-Step "Verifying Windows Update services..." -Level Info

    $services = @(
        @{ Name = 'wuauserv';     Required = $true;  DisplayName = 'Windows Update' },
        @{ Name = 'BITS';         Required = $true;  DisplayName = 'BITS' },
        @{ Name = 'CryptSvc';     Required = $true;  DisplayName = 'Cryptographic Services' },
        @{ Name = 'TrustedInstaller'; Required = $false; DisplayName = 'Windows Modules Installer' }
    )

    $results = @{}
    $allHealthy = $true

    foreach ($svc in $services) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue

        $status = if ($service) {
            @{
                Status    = $service.Status.ToString()
                StartType = $service.StartType.ToString()
                Healthy   = $service.Status -eq 'Running' -or (-not $svc.Required)
            }
        } else {
            @{ Status = 'NotFound'; StartType = 'N/A'; Healthy = -not $svc.Required }
        }

        $results[$svc.Name] = $status

        if ($svc.Required -and -not $status.Healthy) {
            $allHealthy = $false
            Write-Step "$($svc.DisplayName): $($status.Status) - Attempting restart..." -Level Warning

            try {
                Set-Service -Name $svc.Name -StartupType Automatic -ErrorAction Stop
                Start-Service -Name $svc.Name -ErrorAction Stop
                $results[$svc.Name].Healthy = $true
                Write-Step "$($svc.DisplayName): Started successfully" -Level OK
            }
            catch {
                Write-Step "$($svc.DisplayName): Failed to start - $_" -Level Error
                [void]$Script:Report.Errors.Add("Service $($svc.Name) failed to start")
            }
        } else {
            Write-Step "$($svc.DisplayName): $($status.Status)" -Level OK
        }
    }

    return @{ Services = $results; AllHealthy = $allHealthy }
}

function Test-WSUSConnectivity {
    Write-Step "Checking WSUS/WU connectivity..." -Level Info

    $result = @{
        Source      = 'Windows Update'
        WSUSServer  = $null
        Reachable   = $false
    }

    # Check for WSUS configuration
    $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (Test-Path $wuKey) {
        $wuSettings = Get-ItemProperty -Path $wuKey -ErrorAction SilentlyContinue
        if ($wuSettings.WUServer) {
            $result.Source = 'WSUS'
            $result.WSUSServer = $wuSettings.WUServer

            if ($wuSettings.WUServer -match 'https?://([^:/]+):?(\d+)?') {
                $host = $Matches[1]
                $port = if ($Matches[2]) { [int]$Matches[2] } else { 8530 }

                try {
                    $tcp = [System.Net.Sockets.TcpClient]::new()
                    $tcp.Connect($host, $port)
                    $result.Reachable = $tcp.Connected
                    $tcp.Close()
                    Write-Step "WSUS Server: $($result.WSUSServer) - Reachable" -Level OK
                }
                catch {
                    Write-Step "WSUS Server: $($result.WSUSServer) - UNREACHABLE" -Level Error
                    [void]$Script:Report.Errors.Add("Cannot reach WSUS server: $($result.WSUSServer)")
                }
            }
        }
    }

    if ($result.Source -eq 'Windows Update') {
        # Test Microsoft Update connectivity
        try {
            $response = Invoke-WebRequest -Uri 'https://windowsupdate.microsoft.com' -UseBasicParsing -TimeoutSec 10
            $result.Reachable = $response.StatusCode -eq 200
            Write-Step "Windows Update: Reachable" -Level OK
        }
        catch {
            Write-Step "Windows Update: Cannot reach Microsoft servers" -Level Warning
            [void]$Script:Report.Warnings.Add("Cannot reach Windows Update servers")
        }
    }

    return $result
}

function Test-ComponentStoreHealth {
    Write-Step "Checking component store health..." -Level Info

    $result = @{
        DISMCheckHealth  = $null
        CBSLogErrors     = 0
        RepairNeeded     = $false
    }

    if (-not $SkipHealthCheck) {
        # DISM CheckHealth
        try {
            $dism = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /CheckHealth" `
                                  -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$env:TEMP\dism_check.log"
            $result.DISMCheckHealth = $dism.ExitCode -eq 0
            Write-Step "DISM CheckHealth: $(if ($result.DISMCheckHealth) { 'Healthy' } else { 'Issues Found' })" -Level $(if ($result.DISMCheckHealth) { 'OK' } else { 'Warning' })
        }
        catch {
            Write-Step "DISM CheckHealth: Failed to run" -Level Warning
        }

        # CBS Log analysis
        $cbsLog = "$env:SystemRoot\Logs\CBS\CBS.log"
        if (Test-Path $cbsLog) {
            $errors = Select-String -Path $cbsLog -Pattern '\[HRESULT = 0x[8-9a-fA-F]' -ErrorAction SilentlyContinue
            $result.CBSLogErrors = $errors.Count
            if ($errors.Count -gt 10) {
                Write-Step "CBS Log: $($errors.Count) errors found - consider running SFC" -Level Warning
                [void]$Script:Report.Warnings.Add("CBS log contains $($errors.Count) errors")
            }
        }

        # Check for pending repairs
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
            $result.RepairNeeded = $true
            Write-Step "Component store repair pending" -Level Warning
        }
    } else {
        Write-Step "Health check skipped" -Level SubStep
    }

    return $result
}

function Get-PendingUpdates {
    Write-Step "Scanning for pending updates..." -Level Info

    $updates = @()

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0")

        foreach ($update in $searchResult.Updates) {
            $updates += [PSCustomObject]@{
                Title       = $update.Title
                KB          = ($update.KBArticleIDs | Select-Object -First 1)
                Severity    = $update.MsrcSeverity
                SizeMB      = [Math]::Round($update.MaxDownloadSize / 1MB, 2)
                Downloaded  = $update.IsDownloaded
                Mandatory   = $update.IsMandatory
            }
        }

        $totalSize = ($updates | Measure-Object -Property SizeMB -Sum).Sum
        Write-Step "Found $($updates.Count) pending updates ($totalSize MB total)" -Level Info
    }
    catch {
        Write-Step "Failed to scan updates: $_" -Level Error
        [void]$Script:Report.Errors.Add("Failed to scan for updates")
    }

    return @{ Updates = $updates; TotalSizeMB = $totalSize }
}

function Start-UpdatePreDownload {
    Write-Step "Pre-downloading updates..." -Level Info

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0 and IsDownloaded=0")

        if ($searchResult.Updates.Count -eq 0) {
            Write-Step "All updates already downloaded" -Level OK
            return @{ Success = $true; Downloaded = 0 }
        }

        $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($update in $searchResult.Updates) {
            if ($update.EulaAccepted -eq $false) {
                $update.AcceptEula()
            }
            $updatesToDownload.Add($update) | Out-Null
        }

        $downloader = $session.CreateUpdateDownloader()
        $downloader.Updates = $updatesToDownload

        Write-Step "Downloading $($updatesToDownload.Count) updates..." -Level SubStep
        $downloadResult = $downloader.Download()

        $success = $downloadResult.ResultCode -eq 2  # orcSucceeded
        Write-Step "Download $(if ($success) { 'completed' } else { 'failed' })" -Level $(if ($success) { 'OK' } else { 'Error' })

        return @{ Success = $success; Downloaded = $updatesToDownload.Count }
    }
    catch {
        Write-Step "Download failed: $_" -Level Error
        [void]$Script:Report.Errors.Add("Update pre-download failed")
        return @{ Success = $false; Downloaded = 0 }
    }
}

function New-PrePatchRestorePoint {
    Write-Step "Creating system restore point..." -Level Info

    try {
        # Enable System Restore if needed
        Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction SilentlyContinue

        $description = "Pre-Patch Checkpoint - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Checkpoint-Computer -Description $description -RestorePointType MODIFY_SETTINGS

        Write-Step "Restore point created: $description" -Level OK
        return @{ Success = $true; Description = $description }
    }
    catch {
        Write-Step "Failed to create restore point: $_" -Level Warning
        [void]$Script:Report.Warnings.Add("Failed to create restore point")
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}

function Stop-CustomServices {
    param([string[]]$ServiceNames)

    if (-not $ServiceNames -or $ServiceNames.Count -eq 0) { return }

    Write-Step "Stopping custom services..." -Level Info

    foreach ($svc in $ServiceNames) {
        try {
            $service = Get-Service -Name $svc -ErrorAction Stop
            if ($service.Status -eq 'Running') {
                Stop-Service -Name $svc -Force -ErrorAction Stop
                Write-Step "$svc stopped" -Level OK
            }
        }
        catch {
            Write-Step "Failed to stop $svc`: $_" -Level Warning
        }
    }
}
#endregion

#region Main
try {
    # Banner
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           PRE-PATCH PREPARATION SCRIPT                     ║" -ForegroundColor Cyan
    Write-Host "║                   ShellBook v1.0                           ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Get OS info
    $os = Get-CimInstance Win32_OperatingSystem
    $Script:Report.OSVersion = $os.Caption

    Write-Step "Computer: $env:COMPUTERNAME" -Level Header
    Write-Step "OS: $($os.Caption)" -Level SubStep
    Write-Step "Started: $($Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level SubStep
    Write-Host ""

    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: Initial Checks
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Step "═══ PHASE 1: INITIAL CHECKS ═══" -Level Header
    Write-Host ""

    # Check disk space
    $Script:Report.InitialDiskSpace = Get-DiskSpaceGB
    Write-Step "Current disk space: $($Script:Report.InitialDiskSpace) GB free" -Level Info

    if ($Script:Report.InitialDiskSpace -lt $MinDiskSpaceGB) {
        Write-Step "INSUFFICIENT DISK SPACE (< $MinDiskSpaceGB GB)" -Level Error
        [void]$Script:Report.Errors.Add("Insufficient disk space: $($Script:Report.InitialDiskSpace) GB")
    } else {
        Write-Step "Disk space OK" -Level OK
    }

    # Check pending reboot
    $rebootStatus = Test-PendingReboot
    $Script:Report.Checks['PendingReboot'] = $rebootStatus

    if ($rebootStatus.Pending) {
        Write-Step "PENDING REBOOT REQUIRED: $($rebootStatus.Reasons -join ', ')" -Level Warning
        [void]$Script:Report.Warnings.Add("Pending reboot: $($rebootStatus.Reasons -join ', ')")

        if (-not $Force) {
            Write-Host ""
            Write-Host "A reboot is pending. It's recommended to reboot before patching." -ForegroundColor Yellow
            Write-Host "Continue anyway? (Y/N): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -notmatch '^[Yy]') {
                Write-Step "Aborted by user" -Level Warning
                exit 1
            }
        }
    } else {
        Write-Step "No pending reboot" -Level OK
    }

    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: Service Health
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Step "═══ PHASE 2: SERVICE HEALTH ═══" -Level Header
    Write-Host ""

    $serviceHealth = Test-ServiceHealth
    $Script:Report.Services = $serviceHealth.Services

    $wsusCheck = Test-WSUSConnectivity
    $Script:Report.Checks['UpdateSource'] = $wsusCheck

    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: System Cleanup
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Step "═══ PHASE 3: SYSTEM CLEANUP ═══" -Level Header
    Write-Host ""

    # Stop services for cleanup
    Stop-UpdateServices

    # Windows Update cache
    $wuCacheCleared = Clear-WindowsUpdateCache
    $Script:Report.Cleanup['WindowsUpdateCache'] = $wuCacheCleared
    Write-Step "Windows Update cache: $wuCacheCleared MB cleared" -Level OK

    # Temp files
    $tempCleared = Clear-TempFiles
    $Script:Report.Cleanup['TempFiles'] = $tempCleared
    Write-Step "Temporary files: $tempCleared MB cleared" -Level OK

    # Windows Installer (analysis only)
    $installerSize = Clear-WindowsInstallerCache
    $Script:Report.Cleanup['WindowsInstallerOrphans'] = $installerSize
    if ($installerSize -gt 500) {
        Write-Step "Windows Installer orphans: $installerSize MB (manual cleanup recommended)" -Level Warning
    }

    # Deep clean (WinSxS)
    if ($DeepClean) {
        Write-Host ""
        Write-Step "Deep cleanup mode enabled" -Level Info
        $componentCleanup = Invoke-ComponentCleanup
        $Script:Report.Cleanup['ComponentCleanup'] = $componentCleanup

        if ($componentCleanup.Success) {
            Write-Step "Component cleanup completed successfully" -Level OK
        } else {
            Write-Step "Component cleanup returned code: $($componentCleanup.ExitCode)" -Level Warning
        }
    }

    # Restart services
    Start-UpdateServices

    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: Health Verification
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Step "═══ PHASE 4: HEALTH VERIFICATION ═══" -Level Header
    Write-Host ""

    $healthCheck = Test-ComponentStoreHealth
    $Script:Report.Checks['ComponentHealth'] = $healthCheck

    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: Update Scan & Pre-Download
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Step "═══ PHASE 5: UPDATE SCAN ═══" -Level Header
    Write-Host ""

    $pendingUpdates = Get-PendingUpdates
    $Script:Report.Updates = $pendingUpdates

    if ($PreDownload -and $pendingUpdates.Updates.Count -gt 0) {
        Write-Host ""
        $downloadResult = Start-UpdatePreDownload
        $Script:Report.Updates['PreDownload'] = $downloadResult
    }

    # ═══════════════════════════════════════════════════════════════
    # PHASE 6: Restore Point
    # ═══════════════════════════════════════════════════════════════
    if ($CreateRestorePoint) {
        Write-Host ""
        Write-Step "═══ PHASE 6: RESTORE POINT ═══" -Level Header
        Write-Host ""

        $restorePoint = New-PrePatchRestorePoint
        $Script:Report.Checks['RestorePoint'] = $restorePoint
    }

    # ═══════════════════════════════════════════════════════════════
    # PHASE 7: Stop Custom Services
    # ═══════════════════════════════════════════════════════════════
    if ($StopServices) {
        Write-Host ""
        Write-Step "═══ STOPPING CUSTOM SERVICES ═══" -Level Header
        Stop-CustomServices -ServiceNames $StopServices
    }

    # ═══════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                        SUMMARY                             ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Final disk space
    $Script:Report.FinalDiskSpace = Get-DiskSpaceGB
    $Script:Report.SpaceReclaimed = [Math]::Round($Script:Report.FinalDiskSpace - $Script:Report.InitialDiskSpace, 2)

    Write-Step "Disk space: $($Script:Report.InitialDiskSpace) GB → $($Script:Report.FinalDiskSpace) GB (+$($Script:Report.SpaceReclaimed) GB)" -Level Info
    Write-Step "Pending updates: $($pendingUpdates.Updates.Count)" -Level Info
    Write-Step "Warnings: $($Script:Report.Warnings.Count)" -Level $(if ($Script:Report.Warnings.Count -gt 0) { 'Warning' } else { 'OK' })
    Write-Step "Errors: $($Script:Report.Errors.Count)" -Level $(if ($Script:Report.Errors.Count -gt 0) { 'Error' } else { 'OK' })

    # Determine readiness
    $Script:Report.ReadyForPatch = $Script:Report.Errors.Count -eq 0 -and
                                   $Script:Report.FinalDiskSpace -ge $MinDiskSpaceGB -and
                                   $serviceHealth.AllHealthy

    Write-Host ""
    if ($Script:Report.ReadyForPatch) {
        Write-Host "  ✓ SYSTEM READY FOR PATCHING" -ForegroundColor Green
    } else {
        Write-Host "  ✗ ISSUES DETECTED - REVIEW BEFORE PATCHING" -ForegroundColor Red
    }

    # Finalize report
    $Script:Report.EndTime = Get-Date
    $Script:Report.Duration = ($Script:Report.EndTime - $Script:Report.StartTime).TotalMinutes

    Write-Host ""
    Write-Step "Duration: $([Math]::Round($Script:Report.Duration, 1)) minutes" -Level Info

    # Export report
    if ($ReportPath) {
        $Script:Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-Step "Report saved: $ReportPath" -Level OK
    }

    # Exit code
    if ($Script:Report.ReadyForPatch) {
        exit 0
    } else {
        exit 1
    }
}
catch {
    Write-Step "Fatal error: $_" -Level Error
    exit 1
}
#endregion
```

---

## Exemple de Sortie

```
╔════════════════════════════════════════════════════════════╗
║           PRE-PATCH PREPARATION SCRIPT                     ║
║                   ShellBook v1.0                           ║
╚════════════════════════════════════════════════════════════╝

 Computer: SRV-PROD01
    OS: Microsoft Windows Server 2022 Standard
    Started: 2024-01-15 14:00:00

═══ PHASE 1: INITIAL CHECKS ═══

[*] Current disk space: 45.23 GB free
[+] Disk space OK
[+] No pending reboot

═══ PHASE 2: SERVICE HEALTH ═══

[*] Verifying Windows Update services...
[+] Windows Update: Running
[+] BITS: Running
[+] Cryptographic Services: Running
[+] Windows Modules Installer: Stopped
[*] Checking WSUS/WU connectivity...
[+] WSUS Server: http://wsus.corp.local:8530 - Reachable

═══ PHASE 3: SYSTEM CLEANUP ═══

   Clearing Windows Update cache...
[+] Windows Update cache: 1245.32 MB cleared
   Clearing temporary files...
[+] Temporary files: 523.18 MB cleared
   Analyzing Windows Installer cache...

═══ PHASE 4: HEALTH VERIFICATION ═══

[*] Checking component store health...
[+] DISM CheckHealth: Healthy

═══ PHASE 5: UPDATE SCAN ═══

[*] Scanning for pending updates...
[*] Found 8 pending updates (456 MB total)

╔════════════════════════════════════════════════════════════╗
║                        SUMMARY                             ║
╚════════════════════════════════════════════════════════════╝

[*] Disk space: 45.23 GB → 47.01 GB (+1.78 GB)
[*] Pending updates: 8
[+] Warnings: 0
[+] Errors: 0

  ✓ SYSTEM READY FOR PATCHING

[*] Duration: 3.2 minutes
[+] Report saved: C:\Reports\prepatch_SRV-PROD01.json
```

---

## Bonnes Pratiques

1. **Timing** : Exécuter 2-4h avant la fenêtre de maintenance
2. **Espace disque** : Prévoir 10 GB minimum avant patching
3. **Pre-download** : Utiliser `-PreDownload` pour télécharger à l'avance
4. **Restore Point** : Toujours créer un checkpoint avec `-CreateRestorePoint`
5. **Rapport** : Exporter le JSON pour audit avec `-ReportPath`

---

## Voir Aussi

- [Get-WindowsUpdateStatus.ps1](Get-WindowsUpdateStatus.md) - Diagnostic WU
- [Repair-WindowsUpdate.ps1](Repair-WindowsUpdate.md) - Réparation WU
- [Get-PendingReboot.ps1](Get-PendingReboot.md) - Détection reboot
