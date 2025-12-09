---
tags:
  - scripts
  - powershell
  - windows
  - system
  - maintenance
---

# Get-PendingReboot.ps1

Détection des redémarrages en attente sur Windows.

---

## Description

- Vérifie toutes les sources de reboot pending
- Windows Update, CBS, File Rename, Configuration Manager
- Support serveurs locaux et distants
- Export JSON pour automation
- Codes de retour pour intégration CI/CD

---

## Prérequis

- **Système** : Windows Server 2016+ ou Windows 10/11
- **PowerShell** : Version 5.1 minimum
- **Permissions** : Droits administrateur pour lire les clés Registry
- **Modules** : Aucun module externe requis (PSRemoting pour serveurs distants)

---

## Cas d'Usage

- **Maintenance préventive** : Vérifier quels serveurs nécessitent un redémarrage avant patching
- **Monitoring** : Intégration avec Nagios, Zabbix ou PRTG pour alertes automatiques
- **Planification** : Identifier les fenêtres de maintenance nécessaires
- **CI/CD** : Validation d'état avant déploiement en production

---

## Utilisation

```powershell
# Vérifier le serveur local
.\Get-PendingReboot.ps1

# Vérifier serveurs distants
.\Get-PendingReboot.ps1 -ComputerName "SRV01","SRV02","SRV03"

# Export JSON
.\Get-PendingReboot.ps1 -ComputerName (Get-Content servers.txt) -OutputFormat JSON

# Mode silencieux (code retour uniquement)
.\Get-PendingReboot.ps1 -Quiet
```

---

## Paramètres

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-ComputerName` | String[] | localhost | Serveurs à vérifier |
| `-Credential` | PSCredential | - | Credentials pour accès distant |
| `-OutputFormat` | String | Table | Format (Table, JSON, CSV) |
| `-Quiet` | Switch | - | Pas d'output, code retour uniquement |

---

## Code Source

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Detect pending reboots on Windows systems.

.DESCRIPTION
    Checks multiple sources for pending reboot indicators including Windows Update,
    Component Based Servicing, pending file renames, Computer Rename, and
    Configuration Manager client.

.PARAMETER ComputerName
    One or more computer names to check. Defaults to local machine.

.PARAMETER Credential
    Credentials for remote computer access.

.PARAMETER OutputFormat
    Output format: Table, JSON, or CSV.

.PARAMETER Quiet
    Suppress output, only return exit code (0=no reboot, 1=reboot pending).

.EXAMPLE
    .\Get-PendingReboot.ps1 -ComputerName "SRV01","SRV02"
    Check pending reboot status on multiple servers.

.NOTES
    Author: ShellBook
    Version: 1.0
    Date: 2024-01-01
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [Alias('CN', 'Server', 'Name')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter()]
    [ValidateSet('Table', 'JSON', 'CSV')]
    [string]$OutputFormat = 'Table',

    [Parameter()]
    [switch]$Quiet
)

#region Configuration
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
#endregion

#region Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    if ($Quiet) { return }

    $colors = @{
        'Info'    = 'Cyan'
        'Warning' = 'Yellow'
        'Error'   = 'Red'
        'Success' = 'Green'
    }

    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] $Message" -ForegroundColor $colors[$Level]
}

function Test-PendingRebootLocal {
    <#
    .SYNOPSIS
        Check all pending reboot sources on local machine.
    #>
    $result = [PSCustomObject]@{
        ComputerName              = $env:COMPUTERNAME
        WindowsUpdate             = $false
        CBSRebootPending          = $false
        PendingFileRename         = $false
        PendingComputerRename     = $false
        CCMClientPending          = $false
        RebootRequired            = $false
        RebootRequiredReason      = [System.Collections.ArrayList]::new()
        LastBootTime              = $null
        CheckTime                 = Get-Date
        Error                     = $null
    }

    try {
        # Get last boot time
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        $result.LastBootTime = $os.LastBootUpTime

        # Check Windows Update
        $wuKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        if (Test-Path $wuKey) {
            $result.WindowsUpdate = $true
            [void]$result.RebootRequiredReason.Add("Windows Update")
        }

        # Check Component Based Servicing
        $cbsKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        if (Test-Path $cbsKey) {
            $result.CBSRebootPending = $true
            [void]$result.RebootRequiredReason.Add("Component Based Servicing")
        }

        # Check Pending File Rename Operations
        $pfroKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
        $pfroValue = Get-ItemProperty -Path $pfroKey -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
        if ($pfroValue.PendingFileRenameOperations) {
            $result.PendingFileRename = $true
            [void]$result.RebootRequiredReason.Add("Pending File Rename")
        }

        # Check Pending Computer Rename
        $activeNameKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName'
        $pendingNameKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName'

        $activeName = (Get-ItemProperty -Path $activeNameKey -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName
        $pendingName = (Get-ItemProperty -Path $pendingNameKey -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName

        if ($activeName -ne $pendingName) {
            $result.PendingComputerRename = $true
            [void]$result.RebootRequiredReason.Add("Computer Rename: $activeName -> $pendingName")
        }

        # Check Configuration Manager (SCCM/MECM)
        try {
            $ccmSdk = [wmiclass]'\\.\root\ccm\clientsdk:CCM_ClientUtilities'
            $ccmReboot = $ccmSdk.DetermineIfRebootPending()
            if ($ccmReboot.RebootPending) {
                $result.CCMClientPending = $true
                [void]$result.RebootRequiredReason.Add("Configuration Manager")
            }
        }
        catch {
            # CCM not installed - ignore
        }

        # Set overall status
        $result.RebootRequired = $result.WindowsUpdate -or
                                 $result.CBSRebootPending -or
                                 $result.PendingFileRename -or
                                 $result.PendingComputerRename -or
                                 $result.CCMClientPending
    }
    catch {
        $result.Error = $_.Exception.Message
    }

    return $result
}

function Test-PendingRebootRemote {
    param(
        [string]$Computer,
        [pscredential]$Cred
    )

    $scriptBlock = {
        $result = [PSCustomObject]@{
            ComputerName              = $env:COMPUTERNAME
            WindowsUpdate             = $false
            CBSRebootPending          = $false
            PendingFileRename         = $false
            PendingComputerRename     = $false
            CCMClientPending          = $false
            RebootRequired            = $false
            RebootRequiredReason      = @()
            LastBootTime              = $null
            CheckTime                 = Get-Date
            Error                     = $null
        }

        try {
            $os = Get-CimInstance -ClassName Win32_OperatingSystem
            $result.LastBootTime = $os.LastBootUpTime

            # Windows Update
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
                $result.WindowsUpdate = $true
                $result.RebootRequiredReason += "Windows Update"
            }

            # CBS
            if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
                $result.CBSRebootPending = $true
                $result.RebootRequiredReason += "Component Based Servicing"
            }

            # Pending File Rename
            $pfro = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
            if ($pfro.PendingFileRenameOperations) {
                $result.PendingFileRename = $true
                $result.RebootRequiredReason += "Pending File Rename"
            }

            # Computer Rename
            $active = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName' -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName
            $pending = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName' -Name 'ComputerName' -ErrorAction SilentlyContinue).ComputerName
            if ($active -ne $pending) {
                $result.PendingComputerRename = $true
                $result.RebootRequiredReason += "Computer Rename"
            }

            # CCM
            try {
                $ccm = [wmiclass]'\\.\root\ccm\clientsdk:CCM_ClientUtilities'
                if ($ccm.DetermineIfRebootPending().RebootPending) {
                    $result.CCMClientPending = $true
                    $result.RebootRequiredReason += "Configuration Manager"
                }
            } catch {}

            $result.RebootRequired = $result.WindowsUpdate -or $result.CBSRebootPending -or
                                     $result.PendingFileRename -or $result.PendingComputerRename -or
                                     $result.CCMClientPending
        }
        catch {
            $result.Error = $_.Exception.Message
        }

        return $result
    }

    $invokeParams = @{
        ComputerName = $Computer
        ScriptBlock  = $scriptBlock
        ErrorAction  = 'Stop'
    }

    if ($Cred -ne [System.Management.Automation.PSCredential]::Empty) {
        $invokeParams.Credential = $Cred
    }

    try {
        $result = Invoke-Command @invokeParams
        return $result
    }
    catch {
        return [PSCustomObject]@{
            ComputerName              = $Computer
            WindowsUpdate             = $null
            CBSRebootPending          = $null
            PendingFileRename         = $null
            PendingComputerRename     = $null
            CCMClientPending          = $null
            RebootRequired            = $null
            RebootRequiredReason      = @()
            LastBootTime              = $null
            CheckTime                 = Get-Date
            Error                     = $_.Exception.Message
        }
    }
}

function Format-Output {
    param(
        [object[]]$Data,
        [string]$Format
    )

    switch ($Format) {
        'Table' {
            $Data | Format-Table -AutoSize @(
                'ComputerName',
                @{N='Reboot?'; E={
                    if ($_.RebootRequired) {
                        'YES'
                    } elseif ($null -eq $_.RebootRequired) {
                        'ERROR'
                    } else {
                        'NO'
                    }
                }},
                @{N='WU'; E={if ($_.WindowsUpdate) { 'X' } else { '-' }}},
                @{N='CBS'; E={if ($_.CBSRebootPending) { 'X' } else { '-' }}},
                @{N='File'; E={if ($_.PendingFileRename) { 'X' } else { '-' }}},
                @{N='Name'; E={if ($_.PendingComputerRename) { 'X' } else { '-' }}},
                @{N='CCM'; E={if ($_.CCMClientPending) { 'X' } else { '-' }}},
                @{N='LastBoot'; E={if ($_.LastBootTime) { $_.LastBootTime.ToString('yyyy-MM-dd HH:mm') } else { 'N/A' }}},
                'Error'
            )
        }
        'JSON' {
            $Data | ConvertTo-Json -Depth 5
        }
        'CSV' {
            $Data | Select-Object ComputerName, RebootRequired,
                @{N='Reasons'; E={$_.RebootRequiredReason -join '; '}},
                WindowsUpdate, CBSRebootPending, PendingFileRename,
                PendingComputerRename, CCMClientPending, LastBootTime, Error |
            ConvertTo-Csv -NoTypeInformation
        }
    }
}
#endregion

#region Main
$allResults = [System.Collections.ArrayList]::new()
$rebootPending = $false

Write-Log "=== Pending Reboot Check ===" -Level Info
Write-Log "Checking $($ComputerName.Count) computer(s)..." -Level Info
Write-Log ""

foreach ($computer in $ComputerName) {
    Write-Log "Checking: $computer" -Level Info

    if ($computer -eq $env:COMPUTERNAME -or $computer -eq 'localhost' -or $computer -eq '.') {
        $result = Test-PendingRebootLocal
    } else {
        $result = Test-PendingRebootRemote -Computer $computer -Cred $Credential
    }

    [void]$allResults.Add($result)

    if ($result.RebootRequired) {
        $rebootPending = $true
        Write-Log "  REBOOT REQUIRED: $($result.RebootRequiredReason -join ', ')" -Level Warning
    } elseif ($result.Error) {
        Write-Log "  ERROR: $($result.Error)" -Level Error
    } else {
        Write-Log "  No reboot pending" -Level Success
    }
}

Write-Log ""

if (-not $Quiet) {
    Format-Output -Data $allResults -Format $OutputFormat

    Write-Log ""
    Write-Log "=== Summary ===" -Level Info
    $pendingCount = ($allResults | Where-Object { $_.RebootRequired -eq $true }).Count
    $okCount = ($allResults | Where-Object { $_.RebootRequired -eq $false }).Count
    $errorCount = ($allResults | Where-Object { $_.Error }).Count

    Write-Log "Pending: $pendingCount | OK: $okCount | Errors: $errorCount" -Level Info
}

# Exit code
if ($rebootPending) {
    exit 1
} else {
    exit 0
}
#endregion
```

---

## Exemples de Sortie

### Table Output

```text
ComputerName Reboot? WU CBS File Name CCM LastBoot           Error
------------ ------- -- --- ---- ---- --- --------           -----
SRV-DC01     NO      -  -   -    -    -   2024-01-10 08:00
SRV-SQL01    YES     X  -   -    -    -   2024-01-05 22:30
SRV-WEB01    YES     -  X   X    -    -   2024-01-08 14:00
SRV-APP01    ERROR   -  -   -    -    -   N/A                Access denied
```

### JSON Output

```json
[
  {
    "ComputerName": "SRV-SQL01",
    "WindowsUpdate": true,
    "CBSRebootPending": false,
    "PendingFileRename": false,
    "PendingComputerRename": false,
    "CCMClientPending": false,
    "RebootRequired": true,
    "RebootRequiredReason": ["Windows Update"],
    "LastBootTime": "2024-01-05T22:30:00",
    "CheckTime": "2024-01-15T10:00:00",
    "Error": null
  }
]
```

---

## Sources Vérifiées

| Source | Clé Registry / WMI |
|--------|-------------------|
| Windows Update | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired` |
| CBS | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending` |
| File Rename | `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations` |
| Computer Rename | Comparaison ActiveComputerName vs ComputerName |
| SCCM/MECM | `CCM_ClientUtilities.DetermineIfRebootPending()` |

---

## Intégration CI/CD

### Script de Maintenance

```powershell
# Check before patching
$servers = Get-Content "servers.txt"
$pending = .\Get-PendingReboot.ps1 -ComputerName $servers -OutputFormat JSON | ConvertFrom-Json |
           Where-Object { $_.RebootRequired }

if ($pending) {
    Write-Warning "Ces serveurs nécessitent un reboot avant patching:"
    $pending.ComputerName
    exit 1
}

# Continue with patching...
```

### Monitoring Nagios/Zabbix

```powershell
# Agent check script
$result = .\Get-PendingReboot.ps1 -Quiet
exit $result  # 0 = OK, 1 = Reboot needed
```

---

## Voir Aussi

- [Test-ADHealth.ps1](Test-ADHealth.md) - Santé Active Directory
- [Invoke-ServerAudit.ps1](Invoke-ServerAudit.md) - Audit complet serveur
