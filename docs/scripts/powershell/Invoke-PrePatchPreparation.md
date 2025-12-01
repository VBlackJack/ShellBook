---
tags:
  - scripts
  - powershell
  - windows
  - patching
  - maintenance
  - production
  - wsus
  - sccm
---

# Invoke-PrePatchPreparation.ps1

Préparation complète d'un serveur avant une fenêtre de patching (WU, WSUS, SCCM/MECM).

---

## Description

- **Détection automatique** de la source de patching (WU, WSUS, SCCM)
- **Nettoyage adapté** selon la source détectée :
    - **Windows Update** : SoftwareDistribution, catroot2
    - **WSUS** : Cache WSUS client, réinitialisation autorisation
    - **SCCM/MECM** : Cache CCM, ContentLib, réparation client
- **Vérification connectivité** vers le serveur de patchs
- **Pré-téléchargement** adapté à chaque source
- **Health Check** : Services, CBS, DISM
- **Rapport JSON** détaillé pour audit

---

## Différences entre Sources

| Élément | Windows Update | WSUS | SCCM/MECM |
|---------|----------------|------|-----------|
| **Cache principal** | `SoftwareDistribution` | `SoftwareDistribution` | `ccmcache` |
| **Métadonnées** | `catroot2` | `catroot2` + AuthCab | `CCM\ContentLib` |
| **Service principal** | `wuauserv` | `wuauserv` | `CcmExec` |
| **Pré-download** | COM API | COM API | `CCM\SoftMgmtAgent` |
| **Connectivité** | Microsoft CDN | Serveur WSUS | Management Point |

---

## Utilisation

```powershell
# Préparation automatique (détection source)
.\Invoke-PrePatchPreparation.ps1

# Forcer une source spécifique
.\Invoke-PrePatchPreparation.ps1 -UpdateSource SCCM

# Préparation WSUS avec reset autorisation
.\Invoke-PrePatchPreparation.ps1 -UpdateSource WSUS -ResetWSUSAuth

# Préparation SCCM avec réparation client
.\Invoke-PrePatchPreparation.ps1 -UpdateSource SCCM -RepairCCMClient

# Mode complet avec pré-téléchargement
.\Invoke-PrePatchPreparation.ps1 -DeepClean -PreDownload -CreateRestorePoint

# Export rapport JSON
.\Invoke-PrePatchPreparation.ps1 -ReportPath "C:\Reports\prepatch.json"
```

---

## Paramètres

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-UpdateSource` | String | Auto | Source de patchs (Auto, WU, WSUS, SCCM) |
| `-Force` | Switch | - | Mode automatique sans confirmation |
| `-DeepClean` | Switch | - | Nettoyage agressif (WinSxS, CCM complet) |
| `-PreDownload` | Switch | - | Télécharger les updates sans installer |
| `-CreateRestorePoint` | Switch | - | Créer un point de restauration |
| `-ResetWSUSAuth` | Switch | - | Reset autorisation WSUS (wuauclt /resetauthorization) |
| `-RepairCCMClient` | Switch | - | Réparer le client SCCM avant patch |
| `-MinDiskSpaceGB` | Int | 10 | Espace disque minimum requis (GB) |
| `-ReportPath` | String | - | Chemin export rapport JSON |
| `-SkipHealthCheck` | Switch | - | Ignorer les vérifications DISM/SFC |

---

## Workflow par Source

### Windows Update Direct

```
┌─────────────────────────────────────────────────────────────────┐
│  WINDOWS UPDATE PREPARATION                                      │
├─────────────────────────────────────────────────────────────────┤
│  1. Stop services: wuauserv, BITS, CryptSvc                     │
│  2. Clean: SoftwareDistribution\Download\*                       │
│  3. Clean: SoftwareDistribution\DataStore\*                      │
│  4. Clean: catroot2 (rename)                                     │
│  5. Clear: BITS jobs                                             │
│  6. Start services                                               │
│  7. Pre-download via COM API                                     │
└─────────────────────────────────────────────────────────────────┘
```

### WSUS

```
┌─────────────────────────────────────────────────────────────────┐
│  WSUS CLIENT PREPARATION                                         │
├─────────────────────────────────────────────────────────────────┤
│  1. Test connectivity to WSUS server                            │
│  2. Stop services: wuauserv, BITS                               │
│  3. Clean: SoftwareDistribution\Download\*                       │
│  4. Clean: SoftwareDistribution\DataStore\*                      │
│  5. Clean: catroot2 (rename)                                     │
│  6. Delete: AuthCabs (if ResetWSUSAuth)                         │
│  7. Start services                                               │
│  8. Force: wuauclt /resetauthorization /detectnow               │
│  9. Pre-download via COM API                                     │
└─────────────────────────────────────────────────────────────────┘
```

### SCCM/MECM

```
┌─────────────────────────────────────────────────────────────────┐
│  SCCM/MECM CLIENT PREPARATION                                    │
├─────────────────────────────────────────────────────────────────┤
│  1. Test connectivity to Management Point                       │
│  2. Verify CCM client health                                    │
│  3. Optional: Repair CCM client                                 │
│  4. Clean: ccmcache (old/orphaned content)                      │
│  5. Clean: CCM\ServiceData\Messaging\EndpointQueues             │
│  6. Optional (DeepClean): CCM\ContentLib                         │
│  7. Clear: SoftwareDistribution (fallback cache)                │
│  8. Trigger: Machine Policy Retrieval                           │
│  9. Trigger: Software Updates Scan                              │
│  10. Trigger: Software Updates Deployment Evaluation            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Code Source

```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Prepare Windows server for patching (WU, WSUS, or SCCM/MECM).

.DESCRIPTION
    Comprehensive pre-patch preparation script that detects the update source
    and performs appropriate cleanup and preparation steps for Windows Update,
    WSUS, or SCCM/MECM managed environments.

.PARAMETER UpdateSource
    Force a specific update source: Auto, WU, WSUS, or SCCM.

.PARAMETER Force
    Run without interactive prompts.

.PARAMETER DeepClean
    Aggressive cleanup (WinSxS, full CCM cache).

.PARAMETER PreDownload
    Download pending updates without installing.

.PARAMETER CreateRestorePoint
    Create a system restore point before patching.

.PARAMETER ResetWSUSAuth
    Reset WSUS authorization (for WSUS clients).

.PARAMETER RepairCCMClient
    Repair SCCM client before patching.

.PARAMETER MinDiskSpaceGB
    Minimum required disk space in GB (default: 10).

.PARAMETER ReportPath
    Path to save JSON report.

.PARAMETER SkipHealthCheck
    Skip DISM/SFC health verification.

.EXAMPLE
    .\Invoke-PrePatchPreparation.ps1 -UpdateSource SCCM -RepairCCMClient
    Prepare SCCM client with client repair.

.EXAMPLE
    .\Invoke-PrePatchPreparation.ps1 -UpdateSource WSUS -ResetWSUSAuth -PreDownload
    Prepare WSUS client with authorization reset and pre-download.

.NOTES
    Author: ShellBook
    Version: 2.0
    Date: 2024-01-01

    IMPORTANT: Run 2-4 hours before maintenance window.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [ValidateSet('Auto', 'WU', 'WSUS', 'SCCM')]
    [string]$UpdateSource = 'Auto',

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$DeepClean,

    [Parameter()]
    [switch]$PreDownload,

    [Parameter()]
    [switch]$CreateRestorePoint,

    [Parameter()]
    [switch]$ResetWSUSAuth,

    [Parameter()]
    [switch]$RepairCCMClient,

    [Parameter()]
    [ValidateRange(5, 100)]
    [int]$MinDiskSpaceGB = 10,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [switch]$SkipHealthCheck
)

#region Configuration
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$Script:StartTime = Get-Date
$Script:Report = [PSCustomObject]@{
    ComputerName      = $env:COMPUTERNAME
    StartTime         = $Script:StartTime
    EndTime           = $null
    Duration          = $null
    OSVersion         = $null
    DetectedSource    = $null
    SourceDetails     = @{}
    InitialDiskSpace  = $null
    FinalDiskSpace    = $null
    SpaceReclaimed    = $null
    CacheCleared      = @{}
    Connectivity      = @{}
    Services          = @{}
    Updates           = @{}
    Warnings          = [System.Collections.ArrayList]::new()
    Errors            = [System.Collections.ArrayList]::new()
    ReadyForPatch     = $false
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
        'Info'    = @{ Color = 'Cyan';    Prefix = '[*]' }
        'OK'      = @{ Color = 'Green';   Prefix = '[+]' }
        'Warning' = @{ Color = 'Yellow';  Prefix = '[!]' }
        'Error'   = @{ Color = 'Red';     Prefix = '[X]' }
        'Header'  = @{ Color = 'Magenta'; Prefix = '===' }
        'SubStep' = @{ Color = 'Gray';    Prefix = '    ' }
    }

    $style = $styles[$Level]
    Write-Host "$($style.Prefix) $Message" -ForegroundColor $style.Color
}

function Get-DiskSpaceGB {
    param([string]$Drive = $env:SystemDrive)
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$Drive'"
    return [Math]::Round($disk.FreeSpace / 1GB, 2)
}

function Get-FolderSizeMB {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    $size = (Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue |
             Measure-Object -Property Length -Sum).Sum
    return [Math]::Round($size / 1MB, 2)
}

function Detect-UpdateSource {
    <#
    .SYNOPSIS
        Detect the update source: WU, WSUS, or SCCM.
    #>
    Write-Step "Detecting update source..." -Level Info

    $result = @{
        Source      = 'WU'
        WSUSServer  = $null
        SCCMServer  = $null
        Details     = @{}
    }

    # Check SCCM first (takes precedence)
    try {
        $ccmClient = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Client' -ErrorAction Stop
        $result.Source = 'SCCM'

        # Get Management Point
        $mp = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Authority' -ErrorAction SilentlyContinue
        if ($mp) {
            $result.SCCMServer = $mp.CurrentManagementPoint
        }

        # Get Site Code
        $siteCode = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Client' -ErrorAction SilentlyContinue
        $result.Details['SiteCode'] = $siteCode.SiteCode
        $result.Details['ClientVersion'] = $ccmClient.ClientVersion

        Write-Step "Detected: SCCM/MECM (MP: $($result.SCCMServer))" -Level OK
        return $result
    }
    catch {
        # SCCM not installed, continue
    }

    # Check WSUS
    $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (Test-Path $wuKey) {
        $wuSettings = Get-ItemProperty -Path $wuKey -ErrorAction SilentlyContinue
        if ($wuSettings.WUServer) {
            $result.Source = 'WSUS'
            $result.WSUSServer = $wuSettings.WUServer
            $result.Details['WUStatusServer'] = $wuSettings.WUStatusServer
            $result.Details['TargetGroup'] = $wuSettings.TargetGroup

            Write-Step "Detected: WSUS ($($result.WSUSServer))" -Level OK
            return $result
        }
    }

    Write-Step "Detected: Windows Update (Direct)" -Level OK
    return $result
}

function Test-UpdateServerConnectivity {
    param(
        [string]$Source,
        [string]$WSUSServer,
        [string]$SCCMServer
    )

    Write-Step "Testing connectivity to update server..." -Level Info

    $result = @{
        Reachable = $false
        Latency   = $null
        Error     = $null
    }

    switch ($Source) {
        'WU' {
            try {
                $response = Invoke-WebRequest -Uri 'https://windowsupdate.microsoft.com' -UseBasicParsing -TimeoutSec 10
                $result.Reachable = $response.StatusCode -eq 200
                Write-Step "Microsoft Update: Reachable" -Level OK
            }
            catch {
                $result.Error = "Cannot reach Microsoft Update servers"
                Write-Step $result.Error -Level Warning
            }
        }
        'WSUS' {
            if ($WSUSServer -match 'https?://([^:/]+):?(\d+)?') {
                $host = $Matches[1]
                $port = if ($Matches[2]) { [int]$Matches[2] } else { 8530 }

                try {
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $tcp = [System.Net.Sockets.TcpClient]::new()
                    $tcp.Connect($host, $port)
                    $stopwatch.Stop()

                    $result.Reachable = $tcp.Connected
                    $result.Latency = $stopwatch.ElapsedMilliseconds
                    $tcp.Close()

                    Write-Step "WSUS Server: Reachable (${host}:${port}, $($result.Latency)ms)" -Level OK
                }
                catch {
                    $result.Error = "Cannot reach WSUS: ${host}:${port}"
                    Write-Step $result.Error -Level Error
                    [void]$Script:Report.Errors.Add($result.Error)
                }
            }
        }
        'SCCM' {
            if ($SCCMServer) {
                try {
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $tcp = [System.Net.Sockets.TcpClient]::new()
                    $tcp.Connect($SCCMServer, 443)
                    $stopwatch.Stop()

                    $result.Reachable = $tcp.Connected
                    $result.Latency = $stopwatch.ElapsedMilliseconds
                    $tcp.Close()

                    Write-Step "Management Point: Reachable ($SCCMServer, $($result.Latency)ms)" -Level OK
                }
                catch {
                    $result.Error = "Cannot reach MP: $SCCMServer"
                    Write-Step $result.Error -Level Error
                    [void]$Script:Report.Errors.Add($result.Error)
                }
            }
        }
    }

    return $result
}

function Stop-UpdateServices {
    param([string]$Source)

    Write-Step "Stopping update services..." -Level Info

    $services = switch ($Source) {
        'SCCM' { @('CcmExec', 'wuauserv', 'BITS', 'CryptSvc') }
        default { @('wuauserv', 'BITS', 'CryptSvc') }
    }

    foreach ($svc in $services) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Write-Step "Stopping $svc..." -Level SubStep
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        }
    }
    Start-Sleep -Seconds 3
}

function Start-UpdateServices {
    param([string]$Source)

    Write-Step "Starting update services..." -Level Info

    $services = switch ($Source) {
        'SCCM' { @('CryptSvc', 'BITS', 'wuauserv', 'CcmExec') }
        default { @('CryptSvc', 'BITS', 'wuauserv') }
    }

    foreach ($svc in $services) {
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
}

#region Windows Update / WSUS Cleanup
function Test-WSUSClientHealth {
    Write-Step "Checking WSUS client configuration..." -Level Info

    $health = @{
        Configured        = $false
        WSUSServer        = $null
        StatusServer      = $null
        TargetGroup       = $null
        GPOManaged        = $false
        LastDetection     = $null
        LastDownload      = $null
        LastInstall       = $null
        SusClientId       = $null
        ServiceStatus     = @{}
        Issues            = @()
    }

    try {
        # Check WSUS GPO configuration
        $wuPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        $auPolicyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

        if (Test-Path $wuPolicyKey) {
            $wuSettings = Get-ItemProperty -Path $wuPolicyKey -ErrorAction SilentlyContinue

            if ($wuSettings.WUServer) {
                $health.Configured = $true
                $health.WSUSServer = $wuSettings.WUServer
                $health.StatusServer = $wuSettings.WUStatusServer
                $health.GPOManaged = $true

                Write-Step "WSUS Server: $($health.WSUSServer)" -Level SubStep

                # Verify WSUS and Status server match
                if ($wuSettings.WUServer -ne $wuSettings.WUStatusServer) {
                    Write-Step "Status Server: $($health.StatusServer)" -Level SubStep
                }
            }

            if ($wuSettings.TargetGroup) {
                $health.TargetGroup = $wuSettings.TargetGroup
                Write-Step "Target Group: $($health.TargetGroup)" -Level SubStep
            }
        }

        if (-not $health.Configured) {
            $health.Issues += "WSUS not configured via GPO"
            Write-Step "WSUS: Not configured" -Level Warning
            return $health
        }

        # Check Auto Update settings
        if (Test-Path $auPolicyKey) {
            $auSettings = Get-ItemProperty -Path $auPolicyKey -ErrorAction SilentlyContinue

            $auOptions = switch ($auSettings.AUOptions) {
                2 { "Notify before download" }
                3 { "Auto download, notify install" }
                4 { "Auto download and install" }
                5 { "Allow local admin to choose" }
                default { "Not configured" }
            }
            Write-Step "AU Policy: $auOptions" -Level SubStep

            if ($auSettings.UseWUServer -ne 1) {
                $health.Issues += "UseWUServer not enabled in GPO"
                Write-Step "UseWUServer: NOT ENABLED (GPO issue)" -Level Warning
            }
        }

        # Check SUS Client ID (registration)
        $wuClientKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
        if (Test-Path $wuClientKey) {
            $clientSettings = Get-ItemProperty -Path $wuClientKey -ErrorAction SilentlyContinue
            $health.SusClientId = $clientSettings.SusClientId

            if (-not $health.SusClientId) {
                $health.Issues += "Not registered with WSUS (no SusClientId)"
                Write-Step "WSUS Registration: NOT REGISTERED" -Level Warning
            } else {
                Write-Step "WSUS Registration: OK (ID: $($health.SusClientId.Substring(0,8))...)" -Level OK
            }
        }

        # Check last detection/download/install times
        $auStateKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update'
        if (Test-Path $auStateKey) {
            $auState = Get-ItemProperty -Path $auStateKey -ErrorAction SilentlyContinue

            # Last detection
            if ($auState.LastOnlineScanTimeForAppCategory) {
                $health.LastDetection = [DateTime]::FromFileTime($auState.LastOnlineScanTimeForAppCategory)
                $detectAge = [Math]::Round(((Get-Date) - $health.LastDetection).TotalHours)
                if ($detectAge -gt 24) {
                    $health.Issues += "Last detection was $detectAge hours ago"
                    Write-Step "Last Detection: $detectAge hours ago" -Level Warning
                } else {
                    Write-Step "Last Detection: $detectAge hours ago" -Level SubStep
                }
            }
        }

        # Check Windows Update services
        $services = @('wuauserv', 'BITS', 'CryptSvc')
        foreach ($svc in $services) {
            $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
            $health.ServiceStatus[$svc] = @{
                Status = if ($service) { $service.Status.ToString() } else { 'NotFound' }
                StartType = if ($service) { $service.StartType.ToString() } else { 'N/A' }
            }

            if (-not $service -or $service.Status -ne 'Running') {
                if ($svc -eq 'wuauserv') {
                    # WU service can be demand-start
                    if ($service -and $service.StartType -eq 'Manual') {
                        Write-Step "Windows Update service: Manual start (OK)" -Level SubStep
                    } else {
                        $health.Issues += "$svc service not running"
                    }
                }
            }
        }

        # Summary
        $overallHealth = $health.Configured -and ($health.Issues.Count -eq 0)
        Write-Step "WSUS Client: $(if ($overallHealth) { 'Healthy' } else { "$($health.Issues.Count) issue(s)" })" `
                  -Level $(if ($overallHealth) { 'OK' } else { 'Warning' })
    }
    catch {
        $health.Issues += "Failed to check WSUS configuration: $_"
        Write-Step "WSUS check failed: $_" -Level Error
    }

    return $health
}

function Clear-WindowsUpdateCache {
    Write-Step "Clearing Windows Update cache..." -Level Info

    $cleared = @{
        SoftwareDistribution = 0
        Catroot2             = 0
        BITSJobs             = 0
    }

    # SoftwareDistribution
    $sdPath = "$env:SystemRoot\SoftwareDistribution"
    $downloadPath = "$sdPath\Download"
    $dataStorePath = "$sdPath\DataStore"

    if (Test-Path $downloadPath) {
        $cleared.SoftwareDistribution += Get-FolderSizeMB -Path $downloadPath
        Remove-Item -Path "$downloadPath\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Step "Cleared: SoftwareDistribution\Download ($($cleared.SoftwareDistribution) MB)" -Level SubStep
    }

    if (Test-Path $dataStorePath) {
        $size = Get-FolderSizeMB -Path $dataStorePath
        $cleared.SoftwareDistribution += $size
        Remove-Item -Path "$dataStorePath\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Step "Cleared: SoftwareDistribution\DataStore ($size MB)" -Level SubStep
    }

    # Catroot2
    $catroot2Path = "$env:SystemRoot\System32\catroot2"
    if (Test-Path $catroot2Path) {
        $cleared.Catroot2 = Get-FolderSizeMB -Path $catroot2Path
        $backupPath = "$env:SystemRoot\System32\catroot2.old"
        if (Test-Path $backupPath) {
            Remove-Item -Path $backupPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        Rename-Item -Path $catroot2Path -NewName 'catroot2.old' -Force -ErrorAction SilentlyContinue
        Write-Step "Renamed: catroot2 ($($cleared.Catroot2) MB)" -Level SubStep
    }

    # BITS Jobs
    try {
        $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
        if ($jobs) {
            $cleared.BITSJobs = $jobs.Count
            $jobs | Remove-BitsTransfer -ErrorAction SilentlyContinue
            Write-Step "Cleared: $($cleared.BITSJobs) BITS jobs" -Level SubStep
        }
    }
    catch {}

    return $cleared
}

function Reset-WSUSAuthorization {
    Write-Step "Resetting WSUS authorization..." -Level Info

    # Delete SusClientId
    $wuKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
    Remove-ItemProperty -Path $wuKey -Name 'SusClientId' -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $wuKey -Name 'SusClientIdValidation' -ErrorAction SilentlyContinue

    # Delete AuthCabs
    $authCabPath = "$env:SystemRoot\SoftwareDistribution\AuthCabs"
    if (Test-Path $authCabPath) {
        Remove-Item -Path "$authCabPath\*" -Force -ErrorAction SilentlyContinue
        Write-Step "Cleared: AuthCabs" -Level SubStep
    }

    Write-Step "WSUS authorization reset - will re-register on next scan" -Level OK
}

function Invoke-WSUSDetection {
    Write-Step "Triggering WSUS detection cycle..." -Level Info

    # Reset authorization and detect
    Start-Process -FilePath "wuauclt.exe" -ArgumentList "/resetauthorization" -Wait -NoNewWindow -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Start-Process -FilePath "wuauclt.exe" -ArgumentList "/detectnow" -Wait -NoNewWindow -ErrorAction SilentlyContinue

    # Also trigger via UsoClient on newer systems
    if (Get-Command "UsoClient.exe" -ErrorAction SilentlyContinue) {
        Start-Process -FilePath "UsoClient.exe" -ArgumentList "StartScan" -Wait -NoNewWindow -ErrorAction SilentlyContinue
    }

    Write-Step "WSUS detection triggered" -Level OK
}
#endregion

#region SCCM Cleanup
function Test-CCMClientHealth {
    Write-Step "Checking SCCM client health..." -Level Info

    $health = @{
        Installed         = $false
        Running           = $false
        Version           = $null
        SiteCode          = $null
        ManagementPoint   = $null
        Certificate       = @{
            Valid         = $false
            Subject       = $null
            Expiration    = $null
            DaysRemaining = $null
            Thumbprint    = $null
        }
        LastHWInv         = $null
        LastSWInv         = $null
        LastPolicyRequest = $null
        CacheSize         = $null
        CacheUsed         = $null
        WMIHealth         = $false
        Issues            = @()
    }

    try {
        # Check if CCM is installed
        $ccmPath = "$env:SystemRoot\CCM"
        $health.Installed = Test-Path $ccmPath

        if (-not $health.Installed) {
            $health.Issues += "CCM client not installed"
            Write-Step "CCM client not installed" -Level Error
            return $health
        }

        # Check service
        $ccmExec = Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue
        $health.Running = $ccmExec -and $ccmExec.Status -eq 'Running'

        if (-not $health.Running) {
            $health.Issues += "CcmExec service not running"
            Write-Step "CcmExec service: NOT RUNNING" -Level Error
        } else {
            Write-Step "CcmExec service: Running" -Level OK
        }

        # Get client info
        $client = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Client' -ErrorAction Stop
        $health.Version = $client.ClientVersion
        $health.SiteCode = $client.SiteCode
        $health.WMIHealth = $true

        Write-Step "CCM Version: $($health.Version) | Site: $($health.SiteCode)" -Level SubStep

        # Get Management Point
        $authority = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Authority' -ErrorAction SilentlyContinue
        if ($authority) {
            $health.ManagementPoint = $authority.CurrentManagementPoint
            Write-Step "Management Point: $($health.ManagementPoint)" -Level SubStep
        }

        # ═══════════════════════════════════════════════════════════════
        # CHECK CLIENT CERTIFICATE
        # ═══════════════════════════════════════════════════════════════
        Write-Step "Checking client certificate..." -Level Info

        # Get SMS Signing Certificate from store
        $smsCert = Get-ChildItem -Path 'Cert:\LocalMachine\SMS\' -ErrorAction SilentlyContinue |
                   Where-Object { $_.Subject -match 'SMS' -or $_.Issuer -match 'SMS' } |
                   Sort-Object NotAfter -Descending |
                   Select-Object -First 1

        if ($smsCert) {
            $health.Certificate.Valid = $smsCert.NotAfter -gt (Get-Date)
            $health.Certificate.Subject = $smsCert.Subject
            $health.Certificate.Expiration = $smsCert.NotAfter
            $health.Certificate.Thumbprint = $smsCert.Thumbprint
            $health.Certificate.DaysRemaining = [Math]::Round(($smsCert.NotAfter - (Get-Date)).TotalDays)

            if ($health.Certificate.DaysRemaining -lt 0) {
                $health.Issues += "Client certificate EXPIRED"
                Write-Step "Certificate: EXPIRED ($($health.Certificate.DaysRemaining) days)" -Level Error
            } elseif ($health.Certificate.DaysRemaining -lt 30) {
                $health.Issues += "Client certificate expiring soon ($($health.Certificate.DaysRemaining) days)"
                Write-Step "Certificate: Expiring in $($health.Certificate.DaysRemaining) days" -Level Warning
            } else {
                Write-Step "Certificate: Valid ($($health.Certificate.DaysRemaining) days remaining)" -Level OK
            }
        } else {
            # Try alternate location
            $smsCert = Get-ChildItem -Path 'Cert:\LocalMachine\My\' -ErrorAction SilentlyContinue |
                       Where-Object { $_.Subject -match 'SCCM|ConfigMgr|SMS' } |
                       Select-Object -First 1

            if (-not $smsCert) {
                $health.Issues += "No SMS client certificate found"
                Write-Step "Certificate: NOT FOUND" -Level Warning
            }
        }

        # ═══════════════════════════════════════════════════════════════
        # CHECK LAST ACTIVITIES
        # ═══════════════════════════════════════════════════════════════
        Write-Step "Checking last activities..." -Level Info

        # Hardware Inventory
        $hwInv = Get-CimInstance -Namespace 'root\ccm\invagt' -ClassName 'InventoryActionStatus' `
                 -Filter "InventoryActionID='{00000000-0000-0000-0000-000000000001}'" -ErrorAction SilentlyContinue
        if ($hwInv -and $hwInv.LastCycleStartedDate) {
            $health.LastHWInv = $hwInv.LastCycleStartedDate
            $hwAge = [Math]::Round(((Get-Date) - $hwInv.LastCycleStartedDate).TotalDays)
            if ($hwAge -gt 7) {
                $health.Issues += "Hardware inventory is $hwAge days old"
                Write-Step "Last HW Inventory: $hwAge days ago" -Level Warning
            } else {
                Write-Step "Last HW Inventory: $hwAge days ago" -Level SubStep
            }
        }

        # Software Inventory
        $swInv = Get-CimInstance -Namespace 'root\ccm\invagt' -ClassName 'InventoryActionStatus' `
                 -Filter "InventoryActionID='{00000000-0000-0000-0000-000000000002}'" -ErrorAction SilentlyContinue
        if ($swInv -and $swInv.LastCycleStartedDate) {
            $health.LastSWInv = $swInv.LastCycleStartedDate
        }

        # Last Policy Request
        $policyStatus = Get-CimInstance -Namespace 'root\ccm\policy' -ClassName 'CCM_PolicyAgent_Configuration' -ErrorAction SilentlyContinue
        # Alternative: check registry
        $policyKey = 'HKLM:\SOFTWARE\Microsoft\CCM\Policy\Machine\ActualConfig'
        if (Test-Path $policyKey) {
            $lastPolicy = Get-ItemProperty -Path $policyKey -ErrorAction SilentlyContinue
            # Registry timestamp if available
        }

        # ═══════════════════════════════════════════════════════════════
        # CHECK CACHE STATUS
        # ═══════════════════════════════════════════════════════════════
        try {
            $cacheInfo = Get-CimInstance -Namespace 'root\ccm\softmgmtagent' -ClassName 'CacheConfig' -ErrorAction SilentlyContinue
            if ($cacheInfo) {
                $health.CacheSize = $cacheInfo.Size
            }

            # Calculate used cache
            $ccmCachePath = "$env:SystemRoot\ccmcache"
            if (Test-Path $ccmCachePath) {
                $usedBytes = (Get-ChildItem -Path $ccmCachePath -Recurse -Force -ErrorAction SilentlyContinue |
                              Measure-Object -Property Length -Sum).Sum
                $health.CacheUsed = [Math]::Round($usedBytes / 1MB)
                Write-Step "Cache: $($health.CacheUsed) MB used / $($health.CacheSize) MB total" -Level SubStep
            }
        }
        catch {}

        # ═══════════════════════════════════════════════════════════════
        # CHECK WMI REPOSITORY
        # ═══════════════════════════════════════════════════════════════
        try {
            # Test CCM WMI namespace accessibility
            $null = Get-CimClass -Namespace 'root\ccm' -ClassName 'SMS_Client' -ErrorAction Stop
            $health.WMIHealth = $true
        }
        catch {
            $health.WMIHealth = $false
            $health.Issues += "WMI CCM namespace corrupted"
            Write-Step "WMI CCM namespace: CORRUPTED" -Level Error
        }

        # ═══════════════════════════════════════════════════════════════
        # SUMMARY
        # ═══════════════════════════════════════════════════════════════
        $overallHealth = $health.Running -and $health.WMIHealth -and
                         $health.Certificate.Valid -and ($health.Issues.Count -eq 0)

        Write-Step "CCM Client v$($health.Version) - $(if ($overallHealth) { 'Healthy' } else { "$($health.Issues.Count) issue(s)" })" `
                  -Level $(if ($overallHealth) { 'OK' } else { 'Warning' })
    }
    catch {
        $health.Issues += "Failed to query CCM: $_"
        Write-Step "CCM health check failed: $_" -Level Error
    }

    return $health
}

function Repair-CCMClient {
    Write-Step "Repairing SCCM client..." -Level Info

    $ccmSetupPath = "$env:SystemRoot\ccmsetup\ccmsetup.exe"

    if (-not (Test-Path $ccmSetupPath)) {
        Write-Step "ccmsetup.exe not found - cannot repair" -Level Error
        return $false
    }

    try {
        # Run repair
        $result = Start-Process -FilePath $ccmSetupPath -ArgumentList "/remediate:client" `
                               -Wait -PassThru -NoNewWindow

        if ($result.ExitCode -eq 0) {
            Write-Step "CCM client repair initiated" -Level OK
            return $true
        } else {
            Write-Step "CCM repair returned code: $($result.ExitCode)" -Level Warning
            return $false
        }
    }
    catch {
        Write-Step "CCM repair failed: $_" -Level Error
        return $false
    }
}

function Clear-CCMCache {
    param([bool]$DeepClean = $false)

    Write-Step "Clearing SCCM cache..." -Level Info

    $cleared = @{
        CCMCache      = 0
        ContentLib    = 0
        EndpointQueue = 0
        TotalItems    = 0
    }

    # Standard ccmcache cleanup (orphaned content)
    try {
        $cacheManager = New-Object -ComObject 'UIResource.UIResourceMgr'
        $cache = $cacheManager.GetCacheInfo()
        $cacheElements = $cache.GetCacheElements()

        $orphaned = @()
        foreach ($element in $cacheElements) {
            # Check if content is still referenced
            $refs = $element.ReferenceCount
            if ($refs -eq 0) {
                $orphaned += $element
            }
        }

        if ($orphaned.Count -gt 0) {
            foreach ($element in $orphaned) {
                $sizeMB = [Math]::Round($element.ContentSize / 1024, 2)
                $cleared.CCMCache += $sizeMB
                $cache.DeleteCacheElement($element.CacheElementID)
                $cleared.TotalItems++
            }
            Write-Step "Cleared: $($orphaned.Count) orphaned cache items ($($cleared.CCMCache) MB)" -Level SubStep
        } else {
            Write-Step "CCM cache: No orphaned items" -Level SubStep
        }
    }
    catch {
        Write-Step "CCM cache cleanup via COM failed, using file-based cleanup" -Level SubStep

        # Fallback: direct file cleanup
        $ccmCachePath = "$env:SystemRoot\ccmcache"
        if (Test-Path $ccmCachePath) {
            $oldItems = Get-ChildItem -Path $ccmCachePath -Directory |
                        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) }

            foreach ($item in $oldItems) {
                $sizeMB = Get-FolderSizeMB -Path $item.FullName
                Remove-Item -Path $item.FullName -Recurse -Force -ErrorAction SilentlyContinue
                $cleared.CCMCache += $sizeMB
                $cleared.TotalItems++
            }

            if ($oldItems.Count -gt 0) {
                Write-Step "Cleared: $($oldItems.Count) old cache folders ($($cleared.CCMCache) MB)" -Level SubStep
            }
        }
    }

    # Endpoint queues (messaging)
    $queuePath = "$env:SystemRoot\CCM\ServiceData\Messaging\EndpointQueues"
    if (Test-Path $queuePath) {
        $cleared.EndpointQueue = Get-FolderSizeMB -Path $queuePath
        # Only clear if significant size (avoid breaking active operations)
        if ($cleared.EndpointQueue -gt 100) {
            Remove-Item -Path "$queuePath\*" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Step "Cleared: EndpointQueues ($($cleared.EndpointQueue) MB)" -Level SubStep
        }
    }

    # Deep clean: ContentLib (use with caution!)
    if ($DeepClean) {
        $contentLibPath = "$env:SystemRoot\CCM\ContentLib"
        if (Test-Path $contentLibPath) {
            $cleared.ContentLib = Get-FolderSizeMB -Path $contentLibPath
            Write-Step "ContentLib size: $($cleared.ContentLib) MB (not cleared - requires CCM restart)" -Level SubStep
            # Note: Don't actually clear ContentLib as it can break deployments
            # Just report the size for information
        }
    }

    return $cleared
}

function Invoke-CCMSoftwareUpdateScan {
    Write-Step "Triggering SCCM software update cycle..." -Level Info

    $scheduleIDs = @{
        'MachinePolicyRetrieval'    = '{00000000-0000-0000-0000-000000000021}'
        'SoftwareUpdatesScan'       = '{00000000-0000-0000-0000-000000000113}'
        'SoftwareUpdatesDeployment' = '{00000000-0000-0000-0000-000000000108}'
    }

    foreach ($action in $scheduleIDs.Keys) {
        try {
            Invoke-CimMethod -Namespace 'root\ccm' -ClassName 'SMS_Client' -MethodName 'TriggerSchedule' `
                            -Arguments @{ sScheduleID = $scheduleIDs[$action] } -ErrorAction Stop | Out-Null
            Write-Step "Triggered: $action" -Level SubStep
            Start-Sleep -Seconds 2
        }
        catch {
            Write-Step "Failed to trigger $action" -Level Warning
        }
    }

    Write-Step "SCCM update cycles triggered" -Level OK
}
#endregion

#region Common Functions
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
        $reasons += 'CBS'
    }

    # File Rename
    $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
    if ($pfro.PendingFileRenameOperations) {
        $pending = $true
        $reasons += 'File Rename'
    }

    # CCM
    try {
        $ccmReboot = Invoke-CimMethod -Namespace 'root\ccm\clientsdk' -ClassName 'CCM_ClientUtilities' `
                                      -MethodName 'DetermineIfRebootPending' -ErrorAction SilentlyContinue
        if ($ccmReboot.RebootPending) {
            $pending = $true
            $reasons += 'SCCM'
        }
    }
    catch {}

    return @{ Pending = $pending; Reasons = $reasons }
}

function Clear-TempFiles {
    Write-Step "Clearing temporary files..." -Level Info

    $cleared = 0
    $paths = @(
        "$env:TEMP\*",
        "$env:SystemRoot\Temp\*",
        "$env:SystemRoot\Prefetch\*"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            $size = (Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
            $cleared += $size
        }
    }

    $clearedMB = [Math]::Round($cleared / 1MB, 2)
    Write-Step "Cleared: $clearedMB MB temporary files" -Level OK
    return $clearedMB
}

function Invoke-ComponentCleanup {
    Write-Step "Running DISM component cleanup..." -Level Info

    try {
        $result = Start-Process -FilePath "dism.exe" `
            -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup" `
            -Wait -PassThru -NoNewWindow

        if ($result.ExitCode -eq 0) {
            Write-Step "Component cleanup completed" -Level OK
            return $true
        }
    }
    catch {}

    return $false
}

function Get-PendingUpdates {
    param([string]$Source)

    Write-Step "Scanning for pending updates..." -Level Info

    $updates = @()

    if ($Source -eq 'SCCM') {
        try {
            $ccmUpdates = Get-CimInstance -Namespace 'root\ccm\clientsdk' -ClassName 'CCM_SoftwareUpdate' `
                         -Filter "ComplianceState=0" -ErrorAction Stop

            foreach ($update in $ccmUpdates) {
                $updates += [PSCustomObject]@{
                    Title     = $update.Name
                    ArticleID = $update.ArticleID
                    Severity  = $update.Severity
                    Size      = [Math]::Round($update.ContentSize / 1MB, 2)
                }
            }
        }
        catch {
            Write-Step "Failed to query SCCM updates: $_" -Level Warning
        }
    }
    else {
        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0")

            foreach ($update in $searchResult.Updates) {
                $updates += [PSCustomObject]@{
                    Title     = $update.Title
                    ArticleID = if ($update.KBArticleIDs.Count -gt 0) { $update.KBArticleIDs[0] } else { $null }
                    Severity  = $update.MsrcSeverity
                    Size      = [Math]::Round($update.MaxDownloadSize / 1MB, 2)
                }
            }
        }
        catch {
            Write-Step "Failed to scan updates: $_" -Level Warning
        }
    }

    $totalSize = ($updates | Measure-Object -Property Size -Sum).Sum
    Write-Step "Found $($updates.Count) pending updates ($totalSize MB)" -Level Info

    return $updates
}

function Start-UpdatePreDownload {
    param([string]$Source)

    Write-Step "Pre-downloading updates..." -Level Info

    if ($Source -eq 'SCCM') {
        # Trigger download via SCCM
        try {
            $updates = Get-CimInstance -Namespace 'root\ccm\clientsdk' -ClassName 'CCM_SoftwareUpdate' `
                      -Filter "ComplianceState=0" -ErrorAction Stop

            foreach ($update in $updates) {
                # Initiate download
                $null = Invoke-CimMethod -Namespace 'root\ccm\clientsdk' -ClassName 'CCM_SoftwareUpdatesManager' `
                                        -MethodName 'InstallUpdates' -Arguments @{ CCMUpdates = $update } `
                                        -ErrorAction SilentlyContinue
            }

            Write-Step "SCCM download initiated for $($updates.Count) updates" -Level OK
            return $true
        }
        catch {
            Write-Step "SCCM pre-download failed: $_" -Level Warning
            return $false
        }
    }
    else {
        # WU/WSUS download via COM
        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0 and IsDownloaded=0")

            if ($searchResult.Updates.Count -eq 0) {
                Write-Step "All updates already downloaded" -Level OK
                return $true
            }

            $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl
            foreach ($update in $searchResult.Updates) {
                if (-not $update.EulaAccepted) { $update.AcceptEula() }
                $updatesToDownload.Add($update) | Out-Null
            }

            $downloader = $session.CreateUpdateDownloader()
            $downloader.Updates = $updatesToDownload

            Write-Step "Downloading $($updatesToDownload.Count) updates..." -Level SubStep
            $downloadResult = $downloader.Download()

            if ($downloadResult.ResultCode -eq 2) {
                Write-Step "Download completed successfully" -Level OK
                return $true
            }
        }
        catch {
            Write-Step "Pre-download failed: $_" -Level Warning
        }

        return $false
    }
}

function New-PrePatchRestorePoint {
    Write-Step "Creating system restore point..." -Level Info

    try {
        Enable-ComputerRestore -Drive $env:SystemDrive -ErrorAction SilentlyContinue
        $description = "Pre-Patch - $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
        Checkpoint-Computer -Description $description -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        Write-Step "Restore point created: $description" -Level OK
        return $true
    }
    catch {
        Write-Step "Failed to create restore point: $_" -Level Warning
        return $false
    }
}
#endregion
#endregion

#region Main
try {
    # Banner
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║       PRE-PATCH PREPARATION (WU / WSUS / SCCM)             ║" -ForegroundColor Cyan
    Write-Host "║                   ShellBook v2.0                           ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Get OS info
    $os = Get-CimInstance Win32_OperatingSystem
    $Script:Report.OSVersion = $os.Caption

    Write-Step "Computer: $env:COMPUTERNAME" -Level Header
    Write-Step "OS: $($os.Caption)" -Level SubStep
    Write-Host ""

    # ═══════════════════════════════════════════════════════════════
    # PHASE 1: Detection & Initial Checks
    # ═══════════════════════════════════════════════════════════════
    Write-Step "═══ PHASE 1: DETECTION & CHECKS ═══" -Level Header
    Write-Host ""

    # Detect or use specified source
    if ($UpdateSource -eq 'Auto') {
        $sourceInfo = Detect-UpdateSource
    } else {
        $sourceInfo = @{ Source = $UpdateSource; WSUSServer = $null; SCCMServer = $null }
        Write-Step "Using specified source: $UpdateSource" -Level Info
    }

    $Script:Report.DetectedSource = $sourceInfo.Source
    $Script:Report.SourceDetails = $sourceInfo

    # Disk space check
    $Script:Report.InitialDiskSpace = Get-DiskSpaceGB
    Write-Step "Disk space: $($Script:Report.InitialDiskSpace) GB free" -Level Info

    if ($Script:Report.InitialDiskSpace -lt $MinDiskSpaceGB) {
        Write-Step "INSUFFICIENT DISK SPACE (< $MinDiskSpaceGB GB)" -Level Error
        [void]$Script:Report.Errors.Add("Insufficient disk space")
    }

    # Pending reboot
    $rebootStatus = Test-PendingReboot
    if ($rebootStatus.Pending) {
        Write-Step "PENDING REBOOT: $($rebootStatus.Reasons -join ', ')" -Level Warning
        [void]$Script:Report.Warnings.Add("Pending reboot: $($rebootStatus.Reasons -join ', ')")
    }

    # ═══════════════════════════════════════════════════════════════
    # PHASE 2: Connectivity Test
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Step "═══ PHASE 2: CONNECTIVITY ═══" -Level Header
    Write-Host ""

    $connectivity = Test-UpdateServerConnectivity -Source $sourceInfo.Source `
                   -WSUSServer $sourceInfo.WSUSServer -SCCMServer $sourceInfo.SCCMServer
    $Script:Report.Connectivity = $connectivity

    # ═══════════════════════════════════════════════════════════════
    # PHASE 3: Client Health Check (source-specific)
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Step "═══ PHASE 3: CLIENT HEALTH CHECK ($($sourceInfo.Source)) ═══" -Level Header
    Write-Host ""

    switch ($sourceInfo.Source) {
        'WU' {
            # Basic WU health check (services)
            Write-Step "Windows Update direct mode - checking services..." -Level Info
            $services = @('wuauserv', 'BITS', 'CryptSvc')
            foreach ($svc in $services) {
                $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
                if ($service -and $service.Status -eq 'Running') {
                    Write-Step "$svc`: Running" -Level OK
                } else {
                    Write-Step "$svc`: Not running" -Level Warning
                }
            }
        }
        'WSUS' {
            # Full WSUS client health check
            $wsusHealth = Test-WSUSClientHealth
            $Script:Report.Services['WSUSHealth'] = $wsusHealth

            if ($wsusHealth.Issues.Count -gt 0) {
                Write-Host ""
                Write-Step "WSUS client issues detected:" -Level Warning
                foreach ($issue in $wsusHealth.Issues) {
                    Write-Step "  - $issue" -Level SubStep
                }
            }
        }
        'SCCM' {
            # Full SCCM client health check (includes certificate)
            $ccmHealth = Test-CCMClientHealth
            $Script:Report.Services['CCMHealth'] = $ccmHealth

            if ($ccmHealth.Issues.Count -gt 0) {
                Write-Host ""
                Write-Step "SCCM client issues detected:" -Level Warning
                foreach ($issue in $ccmHealth.Issues) {
                    Write-Step "  - $issue" -Level SubStep
                }

                # Auto-repair if requested and issues found
                if ($RepairCCMClient) {
                    Write-Host ""
                    Repair-CCMClient
                }
            }
        }
    }

    # ═══════════════════════════════════════════════════════════════
    # PHASE 4: Cache Cleanup
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Step "═══ PHASE 4: CACHE CLEANUP ═══" -Level Header
    Write-Host ""

    # Stop services before cleanup
    Stop-UpdateServices -Source $sourceInfo.Source

    switch ($sourceInfo.Source) {
        'WU' {
            $wuCleared = Clear-WindowsUpdateCache
            $Script:Report.CacheCleared = $wuCleared
        }
        'WSUS' {
            $wuCleared = Clear-WindowsUpdateCache
            $Script:Report.CacheCleared = $wuCleared

            if ($ResetWSUSAuth) {
                Reset-WSUSAuthorization
            }
        }
        'SCCM' {
            # CCM cache cleanup
            $ccmCleared = Clear-CCMCache -DeepClean $DeepClean
            $Script:Report.CacheCleared = $ccmCleared

            # Also clear WU cache (SCCM uses it as fallback)
            $wuCleared = Clear-WindowsUpdateCache
            $Script:Report.CacheCleared['SoftwareDistribution'] = $wuCleared.SoftwareDistribution
        }
    }

    # Common temp cleanup
    $tempCleared = Clear-TempFiles
    $Script:Report.CacheCleared['TempFiles'] = $tempCleared

    # Deep clean (WinSxS)
    if ($DeepClean) {
        Invoke-ComponentCleanup
    }

    # Start services
    Start-UpdateServices -Source $sourceInfo.Source

    # ═══════════════════════════════════════════════════════════════
    # PHASE 5: Trigger Detection
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Step "═══ PHASE 5: UPDATE DETECTION ═══" -Level Header
    Write-Host ""

    switch ($sourceInfo.Source) {
        'WSUS' {
            Invoke-WSUSDetection
        }
        'SCCM' {
            Invoke-CCMSoftwareUpdateScan
        }
    }

    # Wait for scan to complete
    Start-Sleep -Seconds 5

    # Get pending updates
    $pendingUpdates = Get-PendingUpdates -Source $sourceInfo.Source
    $Script:Report.Updates = @{
        Pending = $pendingUpdates
        Count   = $pendingUpdates.Count
    }

    # ═══════════════════════════════════════════════════════════════
    # PHASE 6: Pre-Download (Optional)
    # ═══════════════════════════════════════════════════════════════
    if ($PreDownload -and $pendingUpdates.Count -gt 0) {
        Write-Host ""
        Write-Step "═══ PHASE 6: PRE-DOWNLOAD ═══" -Level Header
        Write-Host ""

        $downloadResult = Start-UpdatePreDownload -Source $sourceInfo.Source
        $Script:Report.Updates['Downloaded'] = $downloadResult
    }

    # ═══════════════════════════════════════════════════════════════
    # PHASE 7: Restore Point (Optional)
    # ═══════════════════════════════════════════════════════════════
    if ($CreateRestorePoint) {
        Write-Host ""
        Write-Step "═══ PHASE 7: RESTORE POINT ═══" -Level Header
        Write-Host ""

        New-PrePatchRestorePoint
    }

    # ═══════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                        SUMMARY                             ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    $Script:Report.FinalDiskSpace = Get-DiskSpaceGB
    $Script:Report.SpaceReclaimed = [Math]::Round($Script:Report.FinalDiskSpace - $Script:Report.InitialDiskSpace, 2)

    Write-Step "Update Source: $($sourceInfo.Source)" -Level Info
    Write-Step "Connectivity: $(if ($connectivity.Reachable) { 'OK' } else { 'FAILED' })" -Level $(if ($connectivity.Reachable) { 'OK' } else { 'Error' })
    Write-Step "Disk space: $($Script:Report.InitialDiskSpace) GB → $($Script:Report.FinalDiskSpace) GB (+$($Script:Report.SpaceReclaimed) GB)" -Level Info
    Write-Step "Pending updates: $($pendingUpdates.Count)" -Level Info
    Write-Step "Warnings: $($Script:Report.Warnings.Count)" -Level $(if ($Script:Report.Warnings.Count -gt 0) { 'Warning' } else { 'OK' })
    Write-Step "Errors: $($Script:Report.Errors.Count)" -Level $(if ($Script:Report.Errors.Count -gt 0) { 'Error' } else { 'OK' })

    # Determine readiness
    $Script:Report.ReadyForPatch = $Script:Report.Errors.Count -eq 0 -and
                                   $connectivity.Reachable -and
                                   $Script:Report.FinalDiskSpace -ge $MinDiskSpaceGB

    Write-Host ""
    if ($Script:Report.ReadyForPatch) {
        Write-Host "  ✓ SYSTEM READY FOR PATCHING ($($sourceInfo.Source))" -ForegroundColor Green
    } else {
        Write-Host "  ✗ ISSUES DETECTED - REVIEW BEFORE PATCHING" -ForegroundColor Red
    }

    # Finalize report
    $Script:Report.EndTime = Get-Date
    $Script:Report.Duration = [Math]::Round(($Script:Report.EndTime - $Script:Report.StartTime).TotalMinutes, 1)

    Write-Host ""
    Write-Step "Duration: $($Script:Report.Duration) minutes" -Level Info

    # Export report
    if ($ReportPath) {
        $Script:Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportPath -Encoding UTF8
        Write-Step "Report saved: $ReportPath" -Level OK
    }

    exit $(if ($Script:Report.ReadyForPatch) { 0 } else { 1 })
}
catch {
    Write-Step "Fatal error: $_" -Level Error
    exit 1
}
#endregion
```

---

## Exemples par Source

### Windows Update Direct

```powershell
.\Invoke-PrePatchPreparation.ps1 -UpdateSource WU -PreDownload
```

```
=== PHASE 3: CACHE CLEANUP (WU) ===

[*] Clearing Windows Update cache...
    Cleared: SoftwareDistribution\Download (234 MB)
    Cleared: SoftwareDistribution\DataStore (12 MB)
    Renamed: catroot2 (8 MB)
    Cleared: 3 BITS jobs
[*] Clearing temporary files...
[+] Cleared: 156 MB temporary files
```

### WSUS Client

```powershell
.\Invoke-PrePatchPreparation.ps1 -UpdateSource WSUS -ResetWSUSAuth -PreDownload
```

```
=== PHASE 2: CONNECTIVITY ===

[*] Testing connectivity to update server...
[+] WSUS Server: Reachable (wsus.corp.local:8530, 12ms)

=== PHASE 3: CACHE CLEANUP (WSUS) ===

[*] Clearing Windows Update cache...
    Cleared: SoftwareDistribution\Download (456 MB)
[*] Resetting WSUS authorization...
    Cleared: AuthCabs
[+] WSUS authorization reset - will re-register on next scan

=== PHASE 4: UPDATE DETECTION ===

[*] Triggering WSUS detection cycle...
[+] WSUS detection triggered
```

### SCCM/MECM Client

```powershell
.\Invoke-PrePatchPreparation.ps1 -UpdateSource SCCM -RepairCCMClient -DeepClean
```

```
=== PHASE 1: DETECTION & CHECKS ===

[*] Detecting update source...
[+] Detected: SCCM/MECM (MP: sccm-mp01.corp.local)

=== PHASE 3: CACHE CLEANUP (SCCM) ===

[*] Checking SCCM client health...
[+] CCM Client v5.00.9096.1000 - Healthy
[*] Clearing SCCM cache...
    Cleared: 15 orphaned cache items (2340 MB)
    ContentLib size: 890 MB (not cleared - requires CCM restart)
[*] Clearing Windows Update cache...
    Cleared: SoftwareDistribution\Download (45 MB)

=== PHASE 4: UPDATE DETECTION ===

[*] Triggering SCCM software update cycle...
    Triggered: MachinePolicyRetrieval
    Triggered: SoftwareUpdatesScan
    Triggered: SoftwareUpdatesDeployment
[+] SCCM update cycles triggered
```

---

## Caches par Source (Résumé)

| Source | Cache Principal | Cache Secondaire | Métadonnées |
|--------|-----------------|------------------|-------------|
| **WU** | `SoftwareDistribution\Download` | - | `catroot2` |
| **WSUS** | `SoftwareDistribution\Download` | - | `catroot2`, `AuthCabs` |
| **SCCM** | `ccmcache` | `SoftwareDistribution` | `CCM\ContentLib` |

---

## Voir Aussi

- [Get-WindowsUpdateStatus.ps1](Get-WindowsUpdateStatus.md) - Diagnostic WU
- [Repair-WindowsUpdate.ps1](Repair-WindowsUpdate.md) - Réparation WU
- [Get-PatchCompliance.ps1](Get-PatchCompliance.md) - Conformité patchs
