---
tags:
  - scripts
  - powershell
  - windows
  - audit
  - discovery
  - documentation
---

# Invoke-ServerAudit.ps1

Script de découverte complète d'un serveur Windows - génère un rapport Markdown prêt à documenter.

---

## Informations

| Propriété | Valeur |
|-----------|--------|
| **Langage** | PowerShell 5.1+ |
| **Catégorie** | Audit / Documentation |
| **Niveau** | :material-star::material-star::material-star: Avancé |
| **Compatibilité** | Windows Server 2012 R2+, Windows 10/11 |

---

## Description

Ce "God Script" Windows est l'équivalent de `server-discovery.sh` pour Linux. Il génère un rapport complet au format **Markdown** révélant l'identité, la configuration et le rôle d'une machine Windows.

**Fonctionnalités :**

- **Détection heuristique des rôles** : Domain Controller, IIS, SQL Server, Hyper-V, etc.
- **Inventaire matériel** : CPU, RAM, Disques avec % libre
- **Cartographie réseau** : IPs, ports ouverts avec processus associés
- **Baseline sécurité** : Windows Defender, Firewall, Administrateurs locaux
- **Sortie Markdown** : Prêt à copier/coller dans votre wiki

---

## Prérequis

```powershell
# Exécution en tant qu'Administrateur recommandée
# Vérifier la politique d'exécution
Get-ExecutionPolicy

# Si nécessaire, autoriser l'exécution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Rôles Détectés Automatiquement

Le script reconnaît automatiquement les services Windows suivants :

| Service | Rôle Assigné |
|---------|--------------|
| `NTDS` | Domain Controller |
| `W3SVC` | IIS Web Server |
| `MSSQLSERVER` / `MSSQL$*` | SQL Server |
| `vmms` | Hyper-V Host |
| `DNS` | DNS Server |
| `DHCPServer` | DHCP Server |
| `CertSvc` | Certificate Authority (AD CS) |
| `WsusService` | WSUS Server |
| `MSMQ` | Message Queue Server |
| `TermService` + RDS | Remote Desktop Services |
| `DFSR` | DFS Replication |
| `iSCSITarget` | iSCSI Target Server |

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Comprehensive Windows server/workstation audit with Markdown output.

.DESCRIPTION
    This "God Script" generates a complete identity and configuration report
    of a Windows machine in Markdown format, ready for documentation.

.PARAMETER OutputFile
    Optional path to save the report. If not specified, outputs to console.

.EXAMPLE
    .\Invoke-ServerAudit.ps1
    Generates report and displays in console.

.EXAMPLE
    .\Invoke-ServerAudit.ps1 -OutputFile "C:\Audits\server-audit.md"
    Saves report to specified file.

.EXAMPLE
    .\Invoke-ServerAudit.ps1 | Out-File -FilePath "audit.md" -Encoding UTF8
    Pipe output to file with UTF8 encoding.

.NOTES
    Author: ShellBook
    Version: 1.0
    Date: 2024-01-15
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputFile
)

#region Configuration

# Role detection patterns: ServiceName -> Role Description
$RolePatterns = @{
    'NTDS'          = 'Domain Controller'
    'W3SVC'         = 'IIS Web Server'
    'MSSQLSERVER'   = 'SQL Server'
    'DNS'           = 'DNS Server'
    'DHCPServer'    = 'DHCP Server'
    'vmms'          = 'Hyper-V Host'
    'CertSvc'       = 'Certificate Authority (AD CS)'
    'WsusService'   = 'WSUS Server'
    'DFSR'          = 'DFS Replication'
    'MSMQ'          = 'Message Queue Server'
    'TermService'   = 'Remote Desktop Services'
    'iSCSITarget'   = 'iSCSI Target Server'
    'Netlogon'      = 'Domain Member'
    'Docker'        = 'Docker Host'
    'containerd'    = 'Container Host'
    'WinRM'         = 'Remote Management Enabled'
}

#endregion

#region Helper Functions

function Get-FormattedSize {
    <#
    .SYNOPSIS
        Formats bytes into human-readable size.
    #>
    param([long]$Bytes)

    if ($Bytes -ge 1TB) {
        return "{0:N1} TB" -f ($Bytes / 1TB)
    }
    elseif ($Bytes -ge 1GB) {
        return "{0:N1} GB" -f ($Bytes / 1GB)
    }
    elseif ($Bytes -ge 1MB) {
        return "{0:N1} MB" -f ($Bytes / 1MB)
    }
    else {
        return "{0:N1} KB" -f ($Bytes / 1KB)
    }
}

function Get-SafeValue {
    <#
    .SYNOPSIS
        Safely executes a script block and returns a default value on error.
    #>
    param(
        [scriptblock]$ScriptBlock,
        [string]$Default = "N/A"
    )

    try {
        $result = & $ScriptBlock
        if ($null -eq $result -or $result -eq '') {
            return $Default
        }
        return $result
    }
    catch {
        return $Default
    }
}

#endregion

#region Discovery Functions

function Get-SystemIdentity {
    <#
    .SYNOPSIS
        Retrieves system identity information.
    #>

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

    # Calculate uptime
    $lastBoot = $os.LastBootUpTime
    $uptime = (Get-Date) - $lastBoot
    $uptimeStr = "{0}d {1}h {2}m" -f $uptime.Days, $uptime.Hours, $uptime.Minutes

    # Domain or Workgroup
    $domainStatus = if ($cs.PartOfDomain) {
        "Domain: $($cs.Domain)"
    } else {
        "Workgroup: $($cs.Workgroup)"
    }

    return @{
        Hostname     = $env:COMPUTERNAME
        OSName       = $os.Caption
        OSVersion    = $os.Version
        OSBuild      = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).DisplayVersion
        Architecture = $os.OSArchitecture
        DomainStatus = $domainStatus
        LastBoot     = $lastBoot.ToString("yyyy-MM-dd HH:mm:ss")
        Uptime       = $uptimeStr
        Manufacturer = $cs.Manufacturer
        Model        = $cs.Model
    }
}

function Get-DetectedRoles {
    <#
    .SYNOPSIS
        Detects server roles based on running services.
    #>

    $detectedRoles = @()
    $services = Get-Service -ErrorAction SilentlyContinue

    foreach ($pattern in $RolePatterns.Keys) {
        # Check exact match or pattern match for SQL instances
        $matchingService = $services | Where-Object {
            $_.Name -eq $pattern -or
            $_.Name -like "MSSQL`$*" -and $pattern -eq 'MSSQLSERVER'
        }

        if ($matchingService) {
            $runningService = $matchingService | Where-Object { $_.Status -eq 'Running' }
            if ($runningService) {
                $detectedRoles += $RolePatterns[$pattern]
            }
        }
    }

    # Check for additional SQL instances
    $sqlServices = $services | Where-Object { $_.Name -like "MSSQL`$*" -and $_.Status -eq 'Running' }
    foreach ($sql in $sqlServices) {
        $instanceName = $sql.Name -replace 'MSSQL\$', ''
        if ($instanceName -and "SQL Server" -notin $detectedRoles) {
            $detectedRoles += "SQL Server ($instanceName)"
        }
    }

    # Remove duplicates
    $detectedRoles = $detectedRoles | Select-Object -Unique

    if ($detectedRoles.Count -eq 0) {
        return "Generic Windows Machine"
    }

    return ($detectedRoles -join ", ")
}

function Get-HardwareInfo {
    <#
    .SYNOPSIS
        Retrieves hardware information (CPU, RAM).
    #>

    $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue

    return @{
        CPUName       = $cpu.Name.Trim()
        CPUCores      = $cpu.NumberOfCores
        CPULogical    = $cpu.NumberOfLogicalProcessors
        TotalRAM      = Get-FormattedSize -Bytes $cs.TotalPhysicalMemory
        TotalRAMBytes = $cs.TotalPhysicalMemory
    }
}

function Get-DiskInfo {
    <#
    .SYNOPSIS
        Retrieves disk information as Markdown table.
    #>

    $disks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue

    $lines = @()
    $lines += "| Drive | Label | Total | Free | % Free |"
    $lines += "|-------|-------|-------|------|--------|"

    foreach ($disk in $disks) {
        $percentFree = if ($disk.Size -gt 0) {
            [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
        } else { 0 }

        # Color indicator for low disk space
        $indicator = if ($percentFree -lt 10) { "⚠️" } elseif ($percentFree -lt 20) { "⚡" } else { "" }

        $lines += "| {0} {1} | {2} | {3} | {4} | {5}% |" -f `
            $disk.DeviceID,
            $indicator,
            ($disk.VolumeName -replace '\|', '-'),
            (Get-FormattedSize -Bytes $disk.Size),
            (Get-FormattedSize -Bytes $disk.FreeSpace),
            $percentFree
    }

    return $lines -join "`n"
}

function Get-NetworkInfo {
    <#
    .SYNOPSIS
        Retrieves network interface information.
    #>

    $adapters = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' }

    $lines = @()
    $lines += "| Interface | IP Address | Prefix |"
    $lines += "|-----------|------------|--------|"

    foreach ($adapter in $adapters) {
        $ifName = (Get-NetAdapter -InterfaceIndex $adapter.InterfaceIndex -ErrorAction SilentlyContinue).Name
        $lines += "| {0} | {1} | /{2} |" -f `
            ($ifName -replace '\|', '-'),
            $adapter.IPAddress,
            $adapter.PrefixLength
    }

    return $lines -join "`n"
}

function Get-ListeningPorts {
    <#
    .SYNOPSIS
        Retrieves listening TCP ports with process names.
    #>

    $connections = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Sort-Object LocalPort -Unique |
        Select-Object -First 30

    $lines = @()
    $lines += "| Port | Process | PID |"
    $lines += "|------|---------|-----|"

    foreach ($conn in $connections) {
        try {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $processName = if ($process) { $process.ProcessName } else { "System" }
        }
        catch {
            $processName = "Unknown"
        }

        # Skip ephemeral ports unless they have known processes
        if ($conn.LocalPort -gt 49151 -and $processName -in @("Unknown", "System")) {
            continue
        }

        $lines += "| {0} | {1} | {2} |" -f `
            $conn.LocalPort,
            $processName,
            $conn.OwningProcess
    }

    return $lines -join "`n"
}

function Get-DefenderStatus {
    <#
    .SYNOPSIS
        Retrieves Windows Defender status.
    #>

    try {
        $defender = Get-MpComputerStatus -ErrorAction Stop

        $status = @()
        $status += "- **Real-Time Protection:** " + $(if ($defender.RealTimeProtectionEnabled) { "✅ Enabled" } else { "❌ Disabled" })
        $status += "- **Antivirus Enabled:** " + $(if ($defender.AntivirusEnabled) { "✅ Yes" } else { "❌ No" })
        $status += "- **Signature Version:** " + $defender.AntivirusSignatureVersion
        $status += "- **Last Scan:** " + $(if ($defender.FullScanEndTime) { $defender.FullScanEndTime.ToString("yyyy-MM-dd") } else { "Never" })

        return $status -join "`n"
    }
    catch {
        return "Windows Defender status not available (may not be installed or accessible)"
    }
}

function Get-FirewallStatus {
    <#
    .SYNOPSIS
        Retrieves Windows Firewall status for all profiles.
    #>

    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop

        $lines = @()
        $lines += "| Profile | Enabled | Default Inbound | Default Outbound |"
        $lines += "|---------|---------|-----------------|------------------|"

        foreach ($profile in $profiles) {
            $enabled = if ($profile.Enabled) { "✅ Yes" } else { "❌ No" }
            $lines += "| {0} | {1} | {2} | {3} |" -f `
                $profile.Name,
                $enabled,
                $profile.DefaultInboundAction,
                $profile.DefaultOutboundAction
        }

        return $lines -join "`n"
    }
    catch {
        return "Firewall status not available"
    }
}

function Get-LocalAdministrators {
    <#
    .SYNOPSIS
        Retrieves members of the local Administrators group.
    #>

    try {
        # Use different methods for compatibility
        if (Get-Command Get-LocalGroupMember -ErrorAction SilentlyContinue) {
            $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            $memberList = $members | ForEach-Object {
                $type = switch ($_.ObjectClass) {
                    'User' { '👤' }
                    'Group' { '👥' }
                    default { '❓' }
                }
                "- $type $($_.Name)"
            }
        }
        else {
            # Fallback for older systems using net localgroup
            $output = net localgroup Administrators 2>$null
            $memberList = $output | Select-Object -Skip 6 | Select-Object -SkipLast 2 |
                Where-Object { $_ -match '\S' } |
                ForEach-Object { "- 👤 $($_.Trim())" }
        }

        return $memberList -join "`n"
    }
    catch {
        return "- Unable to retrieve (Access Denied or not available)"
    }
}

function Get-InstalledFeatures {
    <#
    .SYNOPSIS
        Retrieves installed Windows features (Server only).
    #>

    try {
        # Check if Get-WindowsFeature exists (Server OS only)
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            $features = Get-WindowsFeature | Where-Object { $_.Installed -eq $true -and $_.FeatureType -eq 'Role' }
            $featureList = $features | ForEach-Object { "- $($_.DisplayName)" }
            return $featureList -join "`n"
        }
        else {
            # Desktop OS - check optional features
            $features = Get-WindowsOptionalFeature -Online -ErrorAction SilentlyContinue |
                Where-Object { $_.State -eq 'Enabled' } |
                Select-Object -First 10
            if ($features) {
                $featureList = $features | ForEach-Object { "- $($_.FeatureName)" }
                return $featureList -join "`n"
            }
            return "Feature detection not available on this OS edition"
        }
    }
    catch {
        return "Unable to retrieve installed features"
    }
}

function Get-RecentEvents {
    <#
    .SYNOPSIS
        Retrieves recent critical/error events from System log.
    #>

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Level     = 1, 2  # Critical, Error
            StartTime = (Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction SilentlyContinue

        if ($events) {
            $lines = @()
            $lines += "| Time | Level | Source | Message |"
            $lines += "|------|-------|--------|---------|"

            foreach ($event in $events) {
                $level = switch ($event.Level) {
                    1 { "🔴 Critical" }
                    2 { "🟠 Error" }
                    default { "Unknown" }
                }
                $message = ($event.Message -split "`n")[0]
                if ($message.Length -gt 50) {
                    $message = $message.Substring(0, 47) + "..."
                }
                $lines += "| {0} | {1} | {2} | {3} |" -f `
                    $event.TimeCreated.ToString("MM-dd HH:mm"),
                    $level,
                    $event.ProviderName,
                    ($message -replace '\|', '-')
            }

            return $lines -join "`n"
        }
        else {
            return "No critical or error events in the last 7 days ✅"
        }
    }
    catch {
        return "Unable to retrieve event logs"
    }
}

#endregion

#region Main Report Generation

function New-AuditReport {
    <#
    .SYNOPSIS
        Generates the complete Markdown audit report.
    #>

    $report = [System.Text.StringBuilder]::new()

    # Gather information
    Write-Verbose "Gathering system identity..."
    $identity = Get-SystemIdentity

    Write-Verbose "Detecting roles..."
    $roles = Get-DetectedRoles

    Write-Verbose "Gathering hardware info..."
    $hardware = Get-HardwareInfo

    $dateStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Build report
    [void]$report.AppendLine("# Audit Report: $($identity.Hostname)")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("**Generated:** $dateStr")
    [void]$report.AppendLine("**Auditor:** Invoke-ServerAudit.ps1 v1.0")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("---")
    [void]$report.AppendLine("")

    # Executive Summary
    [void]$report.AppendLine("## Executive Summary")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("| Property | Value |")
    [void]$report.AppendLine("|----------|-------|")
    [void]$report.AppendLine("| **Hostname** | $($identity.Hostname) |")
    [void]$report.AppendLine("| **OS** | $($identity.OSName) |")
    [void]$report.AppendLine("| **Version** | $($identity.OSVersion) (Build $($identity.OSBuild)) |")
    [void]$report.AppendLine("| **Architecture** | $($identity.Architecture) |")
    [void]$report.AppendLine("| **Domain/Workgroup** | $($identity.DomainStatus) |")
    [void]$report.AppendLine("| **Last Boot** | $($identity.LastBoot) |")
    [void]$report.AppendLine("| **Uptime** | $($identity.Uptime) |")
    [void]$report.AppendLine("| **Detected Roles** | $roles |")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("---")
    [void]$report.AppendLine("")

    # Hardware
    [void]$report.AppendLine("## 1. Hardware")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("### CPU")
    [void]$report.AppendLine("- **Model:** $($hardware.CPUName)")
    [void]$report.AppendLine("- **Cores:** $($hardware.CPUCores) physical / $($hardware.CPULogical) logical")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("### Memory")
    [void]$report.AppendLine("- **Total RAM:** $($hardware.TotalRAM)")
    [void]$report.AppendLine("")

    Write-Verbose "Gathering disk info..."
    [void]$report.AppendLine("### Storage")
    [void]$report.AppendLine("")
    [void]$report.AppendLine((Get-DiskInfo))
    [void]$report.AppendLine("")
    [void]$report.AppendLine("---")
    [void]$report.AppendLine("")

    # Network
    [void]$report.AppendLine("## 2. Network Configuration")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("### IP Interfaces")
    [void]$report.AppendLine("")
    Write-Verbose "Gathering network info..."
    [void]$report.AppendLine((Get-NetworkInfo))
    [void]$report.AppendLine("")
    [void]$report.AppendLine("### Listening Ports")
    [void]$report.AppendLine("")
    Write-Verbose "Gathering port info..."
    [void]$report.AppendLine((Get-ListeningPorts))
    [void]$report.AppendLine("")
    [void]$report.AppendLine("---")
    [void]$report.AppendLine("")

    # Security
    [void]$report.AppendLine("## 3. Security Baseline")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("### Windows Defender")
    [void]$report.AppendLine("")
    Write-Verbose "Checking Defender status..."
    [void]$report.AppendLine((Get-DefenderStatus))
    [void]$report.AppendLine("")
    [void]$report.AppendLine("### Windows Firewall")
    [void]$report.AppendLine("")
    Write-Verbose "Checking Firewall status..."
    [void]$report.AppendLine((Get-FirewallStatus))
    [void]$report.AppendLine("")
    [void]$report.AppendLine("### Local Administrators")
    [void]$report.AppendLine("")
    Write-Verbose "Checking local admins..."
    [void]$report.AppendLine((Get-LocalAdministrators))
    [void]$report.AppendLine("")
    [void]$report.AppendLine("---")
    [void]$report.AppendLine("")

    # Installed Roles/Features
    [void]$report.AppendLine("## 4. Installed Roles & Features")
    [void]$report.AppendLine("")
    Write-Verbose "Checking installed features..."
    [void]$report.AppendLine((Get-InstalledFeatures))
    [void]$report.AppendLine("")
    [void]$report.AppendLine("---")
    [void]$report.AppendLine("")

    # Recent Events
    [void]$report.AppendLine("## 5. Recent Critical Events (7 days)")
    [void]$report.AppendLine("")
    Write-Verbose "Checking event logs..."
    [void]$report.AppendLine((Get-RecentEvents))
    [void]$report.AppendLine("")
    [void]$report.AppendLine("---")
    [void]$report.AppendLine("")

    # Quick Commands
    [void]$report.AppendLine("## Appendix: Quick Commands")
    [void]$report.AppendLine("")
    [void]$report.AppendLine('```powershell')
    [void]$report.AppendLine("# Check system info")
    [void]$report.AppendLine("Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsArchitecture")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("# Check disk space")
    [void]$report.AppendLine("Get-PSDrive -PSProvider FileSystem | Select-Object Name, Used, Free")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("# Check listening ports")
    [void]$report.AppendLine("Get-NetTCPConnection -State Listen | Select-Object LocalPort, OwningProcess")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("# Check recent errors")
    [void]$report.AppendLine("Get-WinEvent -FilterHashtable @{LogName='System';Level=2} -MaxEvents 10")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("# Check services status")
    [void]$report.AppendLine("Get-Service | Where-Object {`$_.Status -eq 'Stopped' -and `$_.StartType -eq 'Automatic'}")
    [void]$report.AppendLine('```')
    [void]$report.AppendLine("")
    [void]$report.AppendLine("---")
    [void]$report.AppendLine("")
    [void]$report.AppendLine("*Report generated by [ShellBook](https://github.com/VBlackJack/ShellBook) Invoke-ServerAudit.ps1*")

    return $report.ToString()
}

#endregion

#region Entry Point

# Check for admin rights (warning only)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning "Running without Administrator privileges. Some information may be incomplete."
}

# Generate report
$report = New-AuditReport

# Output
if ($OutputFile) {
    $report | Out-File -FilePath $OutputFile -Encoding UTF8
    Write-Host "Report saved to: $OutputFile" -ForegroundColor Green
}
else {
    Write-Output $report
}

#endregion
```

---

## Utilisation

### Exécution Basique

```powershell
# Afficher le rapport dans la console
.\Invoke-ServerAudit.ps1

# Sauvegarder dans un fichier
.\Invoke-ServerAudit.ps1 -OutputFile "C:\Audits\server-audit.md"

# Ou via pipe
.\Invoke-ServerAudit.ps1 | Out-File -FilePath "audit.md" -Encoding UTF8
```

### Exécution en tant qu'Administrateur

```powershell
# Pour un rapport complet (recommandé)
Start-Process powershell -Verb RunAs -ArgumentList "-File .\Invoke-ServerAudit.ps1 -OutputFile C:\audit.md"
```

### Exécution à Distance

```powershell
# Via PowerShell Remoting
Invoke-Command -ComputerName SERVER01 -FilePath .\Invoke-ServerAudit.ps1 |
    Out-File -FilePath ".\SERVER01-audit.md"

# Ou avec Enter-PSSession
Enter-PSSession -ComputerName SERVER01
.\Invoke-ServerAudit.ps1 > C:\audit.md
```

### Audit de Plusieurs Serveurs

```powershell
$servers = @("SRV01", "SRV02", "SRV03")

foreach ($server in $servers) {
    $report = Invoke-Command -ComputerName $server -FilePath .\Invoke-ServerAudit.ps1
    $report | Out-File -FilePath ".\Audits\$server-audit.md" -Encoding UTF8
}
```

---

## Exemple de Sortie

```markdown
# Audit Report: WEB-PROD-01

**Generated:** 2024-01-15 14:30:00
**Auditor:** Invoke-ServerAudit.ps1 v1.0

---

## Executive Summary

| Property | Value |
|----------|-------|
| **Hostname** | WEB-PROD-01 |
| **OS** | Microsoft Windows Server 2022 Standard |
| **Version** | 10.0.20348 (Build 21H2) |
| **Architecture** | 64-bit |
| **Domain/Workgroup** | Domain: corp.example.com |
| **Last Boot** | 2024-01-10 03:45:12 |
| **Uptime** | 5d 10h 45m |
| **Detected Roles** | IIS Web Server, Remote Management Enabled |

---

## 1. Hardware

### CPU
- **Model:** Intel(R) Xeon(R) Gold 6248 CPU @ 2.50GHz
- **Cores:** 4 physical / 8 logical

### Memory
- **Total RAM:** 16.0 GB

### Storage

| Drive | Label | Total | Free | % Free |
|-------|-------|-------|------|--------|
| C:  | System | 100.0 GB | 45.2 GB | 45.2% |
| D:  | Data | 500.0 GB | 320.5 GB | 64.1% |

---

## 2. Network Configuration

### IP Interfaces

| Interface | IP Address | Prefix |
|-----------|------------|--------|
| Ethernet0 | 10.0.1.50 | /24 |

### Listening Ports

| Port | Process | PID |
|------|---------|-----|
| 80 | w3wp | 4532 |
| 443 | w3wp | 4532 |
| 3389 | svchost | 1024 |
| 5985 | svchost | 876 |

---

## 3. Security Baseline

### Windows Defender

- **Real-Time Protection:** ✅ Enabled
- **Antivirus Enabled:** ✅ Yes
- **Signature Version:** 1.403.234.0
- **Last Scan:** 2024-01-14

### Windows Firewall

| Profile | Enabled | Default Inbound | Default Outbound |
|---------|---------|-----------------|------------------|
| Domain | ✅ Yes | Block | Allow |
| Private | ✅ Yes | Block | Allow |
| Public | ✅ Yes | Block | Allow |

### Local Administrators

- 👤 CORP\Domain Admins
- 👤 CORP\SRV-Admins
- 👤 Administrator
```

---

## Options

| Paramètre | Description |
|-----------|-------------|
| `-OutputFile <path>` | Chemin pour sauvegarder le rapport |
| `-Verbose` | Affiche la progression de l'audit |

---

!!! tip "Bonnes Pratiques"
    - **Exécutez en tant qu'Administrateur** pour un audit complet
    - **Sauvegardez avec la date** : `Invoke-ServerAudit.ps1 -OutputFile "audit-$(Get-Date -Format 'yyyyMMdd').md"`
    - **Versionnez les rapports** dans Git pour suivre l'évolution

!!! warning "Confidentialité"
    Le rapport peut contenir des informations sensibles :

    - Liste des administrateurs locaux
    - Ports ouverts et services
    - Configuration réseau

    **Ne partagez pas ce rapport publiquement !**

---

## Voir Aussi

- [server-discovery.sh](../bash/server-discovery-audit.md) - Équivalent Linux
- [Get-SystemInfo.ps1](Get-SystemInfo.md) - Informations système de base
- [Test-ADHealth.ps1](Test-ADHealth.md) - Audit Active Directory
