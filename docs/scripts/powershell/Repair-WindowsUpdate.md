---
tags:
  - scripts
  - powershell
  - windows
  - patching
  - troubleshooting
  - repair
---

# Repair-WindowsUpdate.ps1

Réparation automatique des problèmes Windows Update.

---

## Fonctionnalités

- **Diagnostic automatique** : Détection des problèmes courants
- **Réparation services** : Restart et reconfiguration WU/BITS/Crypto
- **Reset composants** : Nettoyage cache WU, catroot2, SoftwareDistribution
- **DISM Repair** : RestoreHealth automatique
- **SFC Scan** : Vérification fichiers système
- **Re-registration** : DLL Windows Update
- **Mode aggressive** : Reset complet de la stack WU

---

## Utilisation

```powershell
# Diagnostic et réparation automatique
.\Repair-WindowsUpdate.ps1

# Mode agressif (reset complet)
.\Repair-WindowsUpdate.ps1 -Aggressive

# Réparation spécifique
.\Repair-WindowsUpdate.ps1 -RepairServices -RepairComponents

# DISM + SFC uniquement
.\Repair-WindowsUpdate.ps1 -RunDISM -RunSFC

# Mode automatique sans confirmation
.\Repair-WindowsUpdate.ps1 -Force

# Export log détaillé
.\Repair-WindowsUpdate.ps1 -LogPath "C:\Logs\wu-repair.log"
```

---

## Paramètres

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-Force` | Switch | - | Mode automatique sans confirmation |
| `-Aggressive` | Switch | - | Reset complet de la stack WU |
| `-RepairServices` | Switch | - | Réparer les services uniquement |
| `-RepairComponents` | Switch | - | Reset les composants WU |
| `-RunDISM` | Switch | - | Exécuter DISM RestoreHealth |
| `-RunSFC` | Switch | - | Exécuter SFC /scannow |
| `-ReRegisterDLLs` | Switch | - | Réenregistrer les DLLs WU |
| `-LogPath` | String | - | Chemin du fichier log |
| `-SkipReboot` | Switch | - | Ne pas demander de reboot |

---

## Workflow de Réparation

```
┌─────────────────────────────────────────────────────────────────┐
│                 WINDOWS UPDATE REPAIR                            │
├─────────────────────────────────────────────────────────────────┤
│  LEVEL 1: BASIC REPAIR                                          │
│     ├─ Stop Windows Update services                              │
│     ├─ Clear WU cache (SoftwareDistribution)                    │
│     ├─ Reset catroot2                                            │
│     └─ Restart services                                          │
├─────────────────────────────────────────────────────────────────┤
│  LEVEL 2: COMPONENT REPAIR                                       │
│     ├─ Re-register Windows Update DLLs                           │
│     ├─ Reset Winsock                                             │
│     ├─ Reset WinHTTP proxy                                       │
│     └─ Reset BITS jobs                                           │
├─────────────────────────────────────────────────────────────────┤
│  LEVEL 3: SYSTEM REPAIR                                          │
│     ├─ DISM /CheckHealth                                         │
│     ├─ DISM /RestoreHealth                                       │
│     └─ SFC /scannow                                              │
├─────────────────────────────────────────────────────────────────┤
│  LEVEL 4: AGGRESSIVE RESET (if needed)                           │
│     ├─ Delete all WU folders                                     │
│     ├─ Reset Windows Update policies                             │
│     ├─ Reset security descriptors                                │
│     └─ Full component re-registration                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Code Source

```powershell
#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Automated Windows Update repair and troubleshooting.

.DESCRIPTION
    Comprehensive repair script for Windows Update issues. Supports multiple
    repair levels from basic cache clearing to aggressive stack reset.

.PARAMETER Force
    Run without interactive prompts.

.PARAMETER Aggressive
    Perform complete Windows Update stack reset.

.PARAMETER RepairServices
    Only repair Windows Update related services.

.PARAMETER RepairComponents
    Only reset Windows Update components.

.PARAMETER RunDISM
    Run DISM /RestoreHealth.

.PARAMETER RunSFC
    Run SFC /scannow.

.PARAMETER ReRegisterDLLs
    Re-register Windows Update DLLs.

.PARAMETER LogPath
    Path to save detailed log file.

.PARAMETER SkipReboot
    Don't prompt for reboot after repair.

.EXAMPLE
    .\Repair-WindowsUpdate.ps1 -Aggressive -Force
    Full automated repair with aggressive reset.

.NOTES
    Author: ShellBook
    Version: 1.0
    Date: 2024-01-01

    WARNING: Some repairs require a system reboot to complete.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$Aggressive,

    [Parameter()]
    [switch]$RepairServices,

    [Parameter()]
    [switch]$RepairComponents,

    [Parameter()]
    [switch]$RunDISM,

    [Parameter()]
    [switch]$RunSFC,

    [Parameter()]
    [switch]$ReRegisterDLLs,

    [Parameter()]
    [string]$LogPath,

    [Parameter()]
    [switch]$SkipReboot
)

#region Configuration
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$Script:StartTime = Get-Date
$Script:LogMessages = [System.Collections.ArrayList]::new()
$Script:RepairsPerformed = [System.Collections.ArrayList]::new()
$Script:RebootRequired = $false

# Windows Update services
$Script:WUServices = @(
    'wuauserv',      # Windows Update
    'BITS',          # Background Intelligent Transfer Service
    'CryptSvc',      # Cryptographic Services
    'msiserver',     # Windows Installer
    'TrustedInstaller' # Windows Modules Installer
)

# Windows Update DLLs
$Script:WUDLLs = @(
    'atl.dll', 'urlmon.dll', 'mshtml.dll', 'shdocvw.dll', 'browseui.dll',
    'jscript.dll', 'vbscript.dll', 'scrrun.dll', 'msxml.dll', 'msxml3.dll',
    'msxml6.dll', 'actxprxy.dll', 'softpub.dll', 'wintrust.dll', 'dssenh.dll',
    'rsaenh.dll', 'gpkcsp.dll', 'sccbase.dll', 'slbcsp.dll', 'cryptdlg.dll',
    'oleaut32.dll', 'ole32.dll', 'shell32.dll', 'initpki.dll', 'wuapi.dll',
    'wuaueng.dll', 'wuaueng1.dll', 'wucltui.dll', 'wups.dll', 'wups2.dll',
    'wuweb.dll', 'qmgr.dll', 'qmgrprxy.dll', 'wucltux.dll', 'muweb.dll',
    'wuwebv.dll'
)
#endregion

#region Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'OK', 'Warning', 'Error', 'Header', 'SubStep', 'Command')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    [void]$Script:LogMessages.Add($logEntry)

    $styles = @{
        'Info'    = @{ Color = 'Cyan';    Prefix = '[*]' }
        'OK'      = @{ Color = 'Green';   Prefix = '[+]' }
        'Warning' = @{ Color = 'Yellow';  Prefix = '[!]' }
        'Error'   = @{ Color = 'Red';     Prefix = '[X]' }
        'Header'  = @{ Color = 'Magenta'; Prefix = '===' }
        'SubStep' = @{ Color = 'Gray';    Prefix = '   ' }
        'Command' = @{ Color = 'DarkGray'; Prefix = '   >' }
    }

    $style = $styles[$Level]
    Write-Host "$($style.Prefix) $Message" -ForegroundColor $style.Color
}

function Test-ServiceRunning {
    param([string]$ServiceName)
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    return $svc -and $svc.Status -eq 'Running'
}

function Stop-WUServices {
    Write-Log "Stopping Windows Update services..." -Level Info

    foreach ($svc in $Script:WUServices) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            Write-Log "Stopping $svc..." -Level SubStep
            try {
                Stop-Service -Name $svc -Force -ErrorAction Stop
                Start-Sleep -Milliseconds 500
            }
            catch {
                Write-Log "Failed to stop $svc`: $_" -Level Warning
            }
        }
    }

    # Force kill if still running
    $processes = @('wuauclt', 'wuauserv')
    foreach ($proc in $processes) {
        Stop-Process -Name $proc -Force -ErrorAction SilentlyContinue
    }

    Start-Sleep -Seconds 2
    Write-Log "Services stopped" -Level OK
}

function Start-WUServices {
    Write-Log "Starting Windows Update services..." -Level Info

    # Start in reverse order (dependencies first)
    $startOrder = @('CryptSvc', 'msiserver', 'BITS', 'wuauserv')

    foreach ($svc in $startOrder) {
        try {
            Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
            Start-Service -Name $svc -ErrorAction SilentlyContinue
            Write-Log "$svc started" -Level SubStep
        }
        catch {
            Write-Log "Failed to start $svc" -Level Warning
        }
    }

    Write-Log "Services started" -Level OK
}

function Clear-WUCache {
    Write-Log "Clearing Windows Update cache..." -Level Info

    $paths = @(
        @{ Path = "$env:SystemRoot\SoftwareDistribution"; Rename = $true; NewName = "SoftwareDistribution.old" },
        @{ Path = "$env:SystemRoot\System32\catroot2"; Rename = $true; NewName = "catroot2.old" }
    )

    foreach ($item in $paths) {
        if (Test-Path $item.Path) {
            try {
                if ($item.Rename) {
                    $newPath = Join-Path (Split-Path $item.Path) $item.NewName
                    # Remove old backup if exists
                    if (Test-Path $newPath) {
                        Remove-Item -Path $newPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    Rename-Item -Path $item.Path -NewName $item.NewName -Force -ErrorAction Stop
                    Write-Log "Renamed: $($item.Path) -> $($item.NewName)" -Level SubStep
                } else {
                    Remove-Item -Path "$($item.Path)\*" -Recurse -Force -ErrorAction Stop
                    Write-Log "Cleared: $($item.Path)" -Level SubStep
                }
                [void]$Script:RepairsPerformed.Add("Cleared cache: $($item.Path)")
            }
            catch {
                Write-Log "Failed to process $($item.Path): $_" -Level Warning
            }
        }
    }

    # Additional cache locations
    $additionalPaths = @(
        "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\qmgr*.dat",
        "$env:ALLUSERSPROFILE\Microsoft\Network\Downloader\qmgr*.dat"
    )

    foreach ($path in $additionalPaths) {
        Remove-Item -Path $path -Force -ErrorAction SilentlyContinue
    }

    Write-Log "Cache cleared" -Level OK
}

function Reset-WinsockCatalog {
    Write-Log "Resetting Winsock catalog..." -Level Info

    try {
        $result = Start-Process -FilePath "netsh.exe" -ArgumentList "winsock reset" `
                               -Wait -PassThru -NoNewWindow
        if ($result.ExitCode -eq 0) {
            Write-Log "Winsock reset successful" -Level OK
            [void]$Script:RepairsPerformed.Add("Winsock reset")
            $Script:RebootRequired = $true
        }
    }
    catch {
        Write-Log "Winsock reset failed: $_" -Level Warning
    }

    # Reset WinHTTP proxy
    try {
        Start-Process -FilePath "netsh.exe" -ArgumentList "winhttp reset proxy" `
                     -Wait -NoNewWindow -ErrorAction SilentlyContinue
        Write-Log "WinHTTP proxy reset" -Level SubStep
    }
    catch {
        Write-Log "WinHTTP proxy reset failed" -Level Warning
    }
}

function Reset-BITSJobs {
    Write-Log "Resetting BITS jobs..." -Level Info

    try {
        Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | Remove-BitsTransfer -ErrorAction SilentlyContinue
        Write-Log "BITS jobs cleared" -Level OK
        [void]$Script:RepairsPerformed.Add("BITS jobs reset")
    }
    catch {
        Write-Log "BITS reset failed: $_" -Level Warning
    }
}

function Register-WUDLLs {
    Write-Log "Re-registering Windows Update DLLs..." -Level Info

    $registered = 0
    $failed = 0

    foreach ($dll in $Script:WUDLLs) {
        $dllPath = Join-Path $env:SystemRoot "System32\$dll"
        if (Test-Path $dllPath) {
            try {
                $result = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s `"$dllPath`"" `
                                       -Wait -PassThru -NoNewWindow
                if ($result.ExitCode -eq 0) {
                    $registered++
                } else {
                    $failed++
                }
            }
            catch {
                $failed++
            }
        }
    }

    Write-Log "DLLs registered: $registered success, $failed failed" -Level $(if ($failed -eq 0) { 'OK' } else { 'Warning' })
    [void]$Script:RepairsPerformed.Add("Re-registered $registered DLLs")
}

function Invoke-DISMRepair {
    Write-Log "Running DISM RestoreHealth..." -Level Info
    Write-Log "This may take 15-30 minutes..." -Level SubStep

    try {
        # First check health
        Write-Log "DISM /CheckHealth..." -Level Command
        $checkResult = Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /CheckHealth" `
                                    -Wait -PassThru -NoNewWindow

        if ($checkResult.ExitCode -ne 0) {
            # Run ScanHealth for more details
            Write-Log "DISM /ScanHealth..." -Level Command
            Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /ScanHealth" `
                         -Wait -NoNewWindow

            # Run RestoreHealth
            Write-Log "DISM /RestoreHealth..." -Level Command
            $restoreResult = Start-Process -FilePath "dism.exe" `
                -ArgumentList "/Online /Cleanup-Image /RestoreHealth" `
                -Wait -PassThru -NoNewWindow

            if ($restoreResult.ExitCode -eq 0) {
                Write-Log "DISM RestoreHealth completed successfully" -Level OK
                [void]$Script:RepairsPerformed.Add("DISM RestoreHealth")
                $Script:RebootRequired = $true
            } else {
                Write-Log "DISM RestoreHealth returned code: $($restoreResult.ExitCode)" -Level Warning
                Write-Log "May need Windows media for repair" -Level SubStep
            }
        } else {
            Write-Log "DISM: Component store is healthy" -Level OK
        }
    }
    catch {
        Write-Log "DISM failed: $_" -Level Error
    }
}

function Invoke-SFCScan {
    Write-Log "Running SFC /scannow..." -Level Info
    Write-Log "This may take 10-20 minutes..." -Level SubStep

    try {
        Write-Log "sfc /scannow..." -Level Command
        $result = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" `
                               -Wait -PassThru -NoNewWindow `
                               -RedirectStandardOutput "$env:TEMP\sfc_output.log"

        # Analyze SFC results
        $sfcLog = "$env:SystemRoot\Logs\CBS\CBS.log"
        $violations = 0

        if (Test-Path $sfcLog) {
            $recentLogs = Get-Content $sfcLog -Tail 500
            $violations = ($recentLogs | Select-String -Pattern '\[SR\].*Repair' | Measure-Object).Count
        }

        if ($result.ExitCode -eq 0) {
            if ($violations -gt 0) {
                Write-Log "SFC repaired $violations file(s)" -Level OK
                [void]$Script:RepairsPerformed.Add("SFC repaired $violations files")
                $Script:RebootRequired = $true
            } else {
                Write-Log "SFC: No integrity violations found" -Level OK
            }
        } else {
            Write-Log "SFC returned code: $($result.ExitCode)" -Level Warning
        }
    }
    catch {
        Write-Log "SFC failed: $_" -Level Error
    }
}

function Reset-WUPolicies {
    Write-Log "Resetting Windows Update policies..." -Level Info

    $keysToRemove = @(
        'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate'
    )

    foreach ($key in $keysToRemove) {
        if (Test-Path $key) {
            try {
                # Backup first
                $backupPath = "$env:TEMP\WU_Policy_Backup_$(Get-Date -Format 'yyyyMMddHHmmss').reg"
                Start-Process -FilePath "reg.exe" -ArgumentList "export `"$($key -replace 'HKLM:\\','HKEY_LOCAL_MACHINE\')`" `"$backupPath`"" `
                             -Wait -NoNewWindow -ErrorAction SilentlyContinue

                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-Log "Removed: $key" -Level SubStep
                [void]$Script:RepairsPerformed.Add("Reset WU policies")
            }
            catch {
                Write-Log "Failed to remove $key`: $_" -Level Warning
            }
        }
    }

    Write-Log "Policies reset (backup saved to TEMP)" -Level OK
}

function Reset-SecurityDescriptors {
    Write-Log "Resetting BITS security descriptor..." -Level Info

    try {
        $result = Start-Process -FilePath "sc.exe" -ArgumentList "sdset bits D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" `
                               -Wait -PassThru -NoNewWindow

        $result = Start-Process -FilePath "sc.exe" -ArgumentList "sdset wuauserv D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" `
                               -Wait -PassThru -NoNewWindow

        Write-Log "Security descriptors reset" -Level OK
        [void]$Script:RepairsPerformed.Add("Security descriptors reset")
    }
    catch {
        Write-Log "Security descriptor reset failed: $_" -Level Warning
    }
}

function Invoke-AggressiveReset {
    Write-Log "AGGRESSIVE RESET MODE" -Level Header
    Write-Log "This will completely reset Windows Update components" -Level Warning

    if (-not $Force) {
        Write-Host ""
        Write-Host "This operation will:" -ForegroundColor Yellow
        Write-Host "  - Delete all Windows Update data" -ForegroundColor Yellow
        Write-Host "  - Reset all WU policies" -ForegroundColor Yellow
        Write-Host "  - Re-register all WU components" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Continue? (Y/N): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        if ($response -notmatch '^[Yy]') {
            Write-Log "Aggressive reset cancelled by user" -Level Warning
            return
        }
    }

    # Stop all services
    Stop-WUServices

    # Delete folders completely
    $foldersToDelete = @(
        "$env:SystemRoot\SoftwareDistribution",
        "$env:SystemRoot\System32\catroot2"
    )

    foreach ($folder in $foldersToDelete) {
        if (Test-Path $folder) {
            try {
                Remove-Item -Path $folder -Recurse -Force -ErrorAction Stop
                Write-Log "Deleted: $folder" -Level SubStep
            }
            catch {
                Write-Log "Could not delete $folder (may need reboot)" -Level Warning
            }
        }
    }

    # Reset policies
    Reset-WUPolicies

    # Reset security descriptors
    Reset-SecurityDescriptors

    # Re-register all DLLs
    Register-WUDLLs

    # Reset Winsock
    Reset-WinsockCatalog

    # Reset BITS
    Reset-BITSJobs

    # Start services
    Start-WUServices

    Write-Log "Aggressive reset completed" -Level OK
    $Script:RebootRequired = $true
}

function Test-WUAfterRepair {
    Write-Log "Verifying Windows Update functionality..." -Level Info

    $results = @{
        ServicesRunning = $true
        CanSearch       = $false
        UpdatesFound    = 0
    }

    # Check services
    foreach ($svc in @('wuauserv', 'BITS', 'CryptSvc')) {
        if (-not (Test-ServiceRunning -ServiceName $svc)) {
            $results.ServicesRunning = $false
            Write-Log "$svc not running" -Level Warning
        }
    }

    # Try to search for updates
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $searcher.Online = $true

        Write-Log "Searching for updates (this may take a minute)..." -Level SubStep
        $searchResult = $searcher.Search("IsInstalled=0 and IsHidden=0")

        $results.CanSearch = $true
        $results.UpdatesFound = $searchResult.Updates.Count
        Write-Log "Update search successful: $($results.UpdatesFound) updates available" -Level OK
    }
    catch {
        Write-Log "Update search failed: $_" -Level Error
        $results.CanSearch = $false
    }

    return $results
}

function Save-RepairLog {
    param([string]$Path)

    $logContent = @"
================================================================================
WINDOWS UPDATE REPAIR LOG
================================================================================
Computer: $env:COMPUTERNAME
Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Duration: $([Math]::Round(((Get-Date) - $Script:StartTime).TotalMinutes, 1)) minutes
================================================================================

REPAIRS PERFORMED:
$($Script:RepairsPerformed | ForEach-Object { "  - $_" } | Out-String)

DETAILED LOG:
$($Script:LogMessages | Out-String)

================================================================================
"@

    $logContent | Out-File -FilePath $Path -Encoding UTF8
    Write-Log "Log saved: $Path" -Level OK
}
#endregion

#region Main
try {
    # Banner
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           WINDOWS UPDATE REPAIR TOOL                       ║" -ForegroundColor Cyan
    Write-Host "║                   ShellBook v1.0                           ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Write-Log "Computer: $env:COMPUTERNAME" -Level Header
    Write-Log "Started: $($Script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -Level SubStep
    Write-Host ""

    # Determine repair level
    $runAll = -not ($RepairServices -or $RepairComponents -or $RunDISM -or $RunSFC -or $ReRegisterDLLs)

    # ═══════════════════════════════════════════════════════════════
    # AGGRESSIVE MODE
    # ═══════════════════════════════════════════════════════════════
    if ($Aggressive) {
        Invoke-AggressiveReset
    }
    else {
        # ═══════════════════════════════════════════════════════════════
        # LEVEL 1: Service Repair
        # ═══════════════════════════════════════════════════════════════
        if ($runAll -or $RepairServices) {
            Write-Host ""
            Write-Log "═══ LEVEL 1: SERVICE REPAIR ═══" -Level Header
            Write-Host ""

            Stop-WUServices
            Start-WUServices
        }

        # ═══════════════════════════════════════════════════════════════
        # LEVEL 2: Component Reset
        # ═══════════════════════════════════════════════════════════════
        if ($runAll -or $RepairComponents) {
            Write-Host ""
            Write-Log "═══ LEVEL 2: COMPONENT RESET ═══" -Level Header
            Write-Host ""

            Stop-WUServices
            Clear-WUCache
            Reset-BITSJobs
            Start-WUServices
        }

        # ═══════════════════════════════════════════════════════════════
        # LEVEL 3: DLL Re-registration
        # ═══════════════════════════════════════════════════════════════
        if ($runAll -or $ReRegisterDLLs) {
            Write-Host ""
            Write-Log "═══ LEVEL 3: DLL RE-REGISTRATION ═══" -Level Header
            Write-Host ""

            Stop-WUServices
            Register-WUDLLs
            Start-WUServices
        }

        # ═══════════════════════════════════════════════════════════════
        # LEVEL 4: DISM Repair
        # ═══════════════════════════════════════════════════════════════
        if ($runAll -or $RunDISM) {
            Write-Host ""
            Write-Log "═══ LEVEL 4: DISM REPAIR ═══" -Level Header
            Write-Host ""

            Invoke-DISMRepair
        }

        # ═══════════════════════════════════════════════════════════════
        # LEVEL 5: SFC Scan
        # ═══════════════════════════════════════════════════════════════
        if ($runAll -or $RunSFC) {
            Write-Host ""
            Write-Log "═══ LEVEL 5: SFC SCAN ═══" -Level Header
            Write-Host ""

            Invoke-SFCScan
        }
    }

    # ═══════════════════════════════════════════════════════════════
    # VERIFICATION
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Log "═══ VERIFICATION ═══" -Level Header
    Write-Host ""

    $verifyResults = Test-WUAfterRepair

    # ═══════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                        SUMMARY                             ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Write-Log "Repairs performed: $($Script:RepairsPerformed.Count)" -Level Info
    foreach ($repair in $Script:RepairsPerformed) {
        Write-Log $repair -Level SubStep
    }

    Write-Host ""

    if ($verifyResults.ServicesRunning -and $verifyResults.CanSearch) {
        Write-Host "  ✓ WINDOWS UPDATE FUNCTIONAL" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ ADDITIONAL REPAIRS MAY BE NEEDED" -ForegroundColor Yellow
        if (-not $Aggressive) {
            Write-Host "  Try running with -Aggressive flag" -ForegroundColor Yellow
        }
    }

    Write-Host ""
    $duration = [Math]::Round(((Get-Date) - $Script:StartTime).TotalMinutes, 1)
    Write-Log "Duration: $duration minutes" -Level Info

    # Save log if requested
    if ($LogPath) {
        Save-RepairLog -Path $LogPath
    }

    # Reboot prompt
    if ($Script:RebootRequired -and -not $SkipReboot) {
        Write-Host ""
        Write-Host "A system reboot is recommended to complete repairs." -ForegroundColor Yellow

        if (-not $Force) {
            Write-Host "Reboot now? (Y/N): " -NoNewline -ForegroundColor Yellow
            $response = Read-Host
            if ($response -match '^[Yy]') {
                Write-Log "Initiating reboot..." -Level Warning
                Restart-Computer -Force
            }
        }
    }

    exit 0
}
catch {
    Write-Log "Fatal error: $_" -Level Error
    exit 1
}
#endregion
```

---

## Exemples de Sortie

```
╔════════════════════════════════════════════════════════════╗
║           WINDOWS UPDATE REPAIR TOOL                       ║
║                   ShellBook v1.0                           ║
╚════════════════════════════════════════════════════════════╝

=== Computer: SRV-PROD01
    Started: 2024-01-15 14:30:00

=== LEVEL 1: SERVICE REPAIR ===

[*] Stopping Windows Update services...
    Stopping wuauserv...
    Stopping BITS...
[+] Services stopped
[*] Starting Windows Update services...
[+] Services started

=== LEVEL 2: COMPONENT RESET ===

[*] Clearing Windows Update cache...
    Renamed: C:\Windows\SoftwareDistribution -> SoftwareDistribution.old
    Renamed: C:\Windows\System32\catroot2 -> catroot2.old
[+] Cache cleared
[*] Resetting BITS jobs...
[+] BITS jobs cleared

=== LEVEL 4: DISM REPAIR ===

[*] Running DISM RestoreHealth...
    This may take 15-30 minutes...
   > DISM /CheckHealth...
   > DISM /RestoreHealth...
[+] DISM RestoreHealth completed successfully

=== VERIFICATION ===

[*] Verifying Windows Update functionality...
    Searching for updates (this may take a minute)...
[+] Update search successful: 5 updates available

╔════════════════════════════════════════════════════════════╗
║                        SUMMARY                             ║
╚════════════════════════════════════════════════════════════╝

[*] Repairs performed: 4
    Cleared cache: C:\Windows\SoftwareDistribution
    Cleared cache: C:\Windows\System32\catroot2
    BITS jobs reset
    DISM RestoreHealth

  ✓ WINDOWS UPDATE FUNCTIONAL

[*] Duration: 22.5 minutes
```

---

## Codes d'Erreur Courants

| Code | Description | Solution |
|------|-------------|----------|
| `0x80070002` | Fichier introuvable | `-RunSFC` puis `-RunDISM` |
| `0x80073712` | Composant store corrompu | `-RunDISM -Aggressive` |
| `0x80244022` | Problème signature/accès | `-ReRegisterDLLs` |
| `0x8024402C` | Serveur WSUS injoignable | Vérifier réseau/WSUS |
| `0x800B0109` | Certificat non approuvé | Mise à jour certificats racine |
| `0x80070422` | Service désactivé | `-RepairServices` |

---

## Voir Aussi

- [Get-WindowsUpdateStatus.ps1](Get-WindowsUpdateStatus.md) - Diagnostic WU
- [Invoke-PrePatchPreparation.ps1](Invoke-PrePatchPreparation.md) - Préparation patch
- [Get-PatchCompliance.ps1](Get-PatchCompliance.md) - Conformité patchs
