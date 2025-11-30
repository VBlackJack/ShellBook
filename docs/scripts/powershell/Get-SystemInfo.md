---
tags:
  - scripts
  - powershell
  - système
  - monitoring
---

# Get-SystemInfo.ps1

:material-star: **Niveau : Débutant**

Affiche les informations système complètes.

---

## Description

Ce script collecte et affiche les informations essentielles du système Windows :
- OS et hardware
- CPU et mémoire
- Disques
- Réseau
- Processus actifs

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Affiche les informations système complètes.

.DESCRIPTION
    Collecte et affiche les informations sur le système d'exploitation,
    le hardware, les disques, la mémoire et le réseau.

.PARAMETER OutputFormat
    Format de sortie: Console, HTML, ou JSON.

.EXAMPLE
    .\Get-SystemInfo.ps1
    Affiche les informations en console.

.EXAMPLE
    .\Get-SystemInfo.ps1 -OutputFormat HTML | Out-File report.html
    Génère un rapport HTML.

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet('Console', 'HTML', 'JSON')]
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

function Write-Info {
    param(
        [string]$Label,
        [string]$Value
    )
    Write-Host ("{0,-20} : {1}" -f $Label, $Value) -ForegroundColor White
}

function Get-OSInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $cs = Get-CimInstance -ClassName Win32_ComputerSystem

    [PSCustomObject]@{
        ComputerName   = $env:COMPUTERNAME
        OS             = $os.Caption
        Version        = $os.Version
        Build          = $os.BuildNumber
        Architecture   = $os.OSArchitecture
        InstallDate    = $os.InstallDate
        LastBoot       = $os.LastBootUpTime
        Uptime         = (Get-Date) - $os.LastBootUpTime
        Manufacturer   = $cs.Manufacturer
        Model          = $cs.Model
        Domain         = $cs.Domain
    }
}

function Get-CPUInfo {
    $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
    $cpuLoad = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average

    [PSCustomObject]@{
        Name         = $cpu.Name.Trim()
        Cores        = $cpu.NumberOfCores
        LogicalCores = $cpu.NumberOfLogicalProcessors
        MaxSpeed     = "{0:N0} MHz" -f $cpu.MaxClockSpeed
        CurrentLoad  = "{0:N1}%" -f $cpuLoad
    }
}

function Get-MemoryInfo {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 2)
    $usedGB = $totalGB - $freeGB
    $usedPercent = [math]::Round(($usedGB / $totalGB) * 100, 1)

    [PSCustomObject]@{
        TotalGB     = "{0:N2} GB" -f $totalGB
        UsedGB      = "{0:N2} GB" -f $usedGB
        FreeGB      = "{0:N2} GB" -f $freeGB
        UsedPercent = "{0:N1}%" -f $usedPercent
    }
}

function Get-DiskInfo {
    Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
        $totalGB = [math]::Round($_.Size / 1GB, 2)
        $freeGB = [math]::Round($_.FreeSpace / 1GB, 2)
        $usedGB = $totalGB - $freeGB
        $usedPercent = if ($totalGB -gt 0) { [math]::Round(($usedGB / $totalGB) * 100, 1) } else { 0 }

        [PSCustomObject]@{
            Drive       = $_.DeviceID
            Label       = $_.VolumeName
            FileSystem  = $_.FileSystem
            TotalGB     = $totalGB
            UsedGB      = $usedGB
            FreeGB      = $freeGB
            UsedPercent = $usedPercent
        }
    }
}

function Get-NetworkInfo {
    Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | ForEach-Object {
        [PSCustomObject]@{
            Interface   = $_.InterfaceAlias
            IPv4Address = $_.IPv4Address.IPAddress
            Gateway     = $_.IPv4DefaultGateway.NextHop
            DNSServer   = ($_.DNSServer.ServerAddresses | Select-Object -First 2) -join ", "
        }
    }
}

function Get-TopProcesses {
    Get-Process | Sort-Object -Property WorkingSet64 -Descending | Select-Object -First 5 | ForEach-Object {
        [PSCustomObject]@{
            Name       = $_.ProcessName
            PID        = $_.Id
            CPU        = "{0:N1}" -f $_.CPU
            MemoryMB   = [math]::Round($_.WorkingSet64 / 1MB, 1)
        }
    }
}
#endregion

#region Main
$systemInfo = @{
    Timestamp   = Get-Date
    OS          = Get-OSInfo
    CPU         = Get-CPUInfo
    Memory      = Get-MemoryInfo
    Disks       = Get-DiskInfo
    Network     = Get-NetworkInfo
    TopProcess  = Get-TopProcesses
}

switch ($OutputFormat) {
    'JSON' {
        $systemInfo | ConvertTo-Json -Depth 4
    }

    'HTML' {
        @"
<!DOCTYPE html>
<html>
<head>
    <title>System Info - $($systemInfo.OS.ComputerName)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2196F3; }
        h2 { color: #4CAF50; border-bottom: 2px solid #4CAF50; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>System Information Report</h1>
    <p>Generated: $($systemInfo.Timestamp)</p>

    <h2>Operating System</h2>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>Computer Name</td><td>$($systemInfo.OS.ComputerName)</td></tr>
        <tr><td>OS</td><td>$($systemInfo.OS.OS)</td></tr>
        <tr><td>Version</td><td>$($systemInfo.OS.Version)</td></tr>
        <tr><td>Uptime</td><td>$($systemInfo.OS.Uptime)</td></tr>
    </table>

    <h2>CPU</h2>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>Model</td><td>$($systemInfo.CPU.Name)</td></tr>
        <tr><td>Cores</td><td>$($systemInfo.CPU.Cores)</td></tr>
        <tr><td>Load</td><td>$($systemInfo.CPU.CurrentLoad)</td></tr>
    </table>

    <h2>Memory</h2>
    <table>
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>Total</td><td>$($systemInfo.Memory.TotalGB)</td></tr>
        <tr><td>Used</td><td>$($systemInfo.Memory.UsedGB) ($($systemInfo.Memory.UsedPercent))</td></tr>
        <tr><td>Free</td><td>$($systemInfo.Memory.FreeGB)</td></tr>
    </table>
</body>
</html>
"@
    }

    default {
        # Console output
        Write-Header "INFORMATIONS SYSTÈME"
        Write-Info "Hostname" $systemInfo.OS.ComputerName
        Write-Info "OS" $systemInfo.OS.OS
        Write-Info "Version" $systemInfo.OS.Version
        Write-Info "Architecture" $systemInfo.OS.Architecture
        Write-Info "Uptime" $systemInfo.OS.Uptime
        Write-Info "Domaine" $systemInfo.OS.Domain

        Write-Header "CPU"
        Write-Info "Modèle" $systemInfo.CPU.Name
        Write-Info "Cores" "$($systemInfo.CPU.Cores) ($($systemInfo.CPU.LogicalCores) logical)"
        Write-Info "Vitesse Max" $systemInfo.CPU.MaxSpeed
        Write-Info "Charge" $systemInfo.CPU.CurrentLoad

        Write-Header "MÉMOIRE"
        Write-Info "Total" $systemInfo.Memory.TotalGB
        Write-Info "Utilisée" "$($systemInfo.Memory.UsedGB) ($($systemInfo.Memory.UsedPercent))"
        Write-Info "Disponible" $systemInfo.Memory.FreeGB

        Write-Header "DISQUES"
        $systemInfo.Disks | ForEach-Object {
            $color = if ($_.UsedPercent -gt 90) { 'Red' } elseif ($_.UsedPercent -gt 75) { 'Yellow' } else { 'Green' }
            Write-Host ("{0} [{1}] - {2:N1} GB / {3:N1} GB ({4:N1}%)" -f $_.Drive, $_.Label, $_.UsedGB, $_.TotalGB, $_.UsedPercent) -ForegroundColor $color
        }

        Write-Header "RÉSEAU"
        $systemInfo.Network | ForEach-Object {
            Write-Info $_.Interface $_.IPv4Address
            if ($_.Gateway) { Write-Info "  Gateway" $_.Gateway }
        }

        Write-Header "TOP 5 PROCESSUS (MÉMOIRE)"
        $systemInfo.TopProcess | Format-Table Name, PID, @{L='Memory (MB)';E={$_.MemoryMB}} -AutoSize | Out-String | Write-Host

        Write-Host ""
    }
}
#endregion
```

---

## Utilisation

```powershell
# Affichage console
.\Get-SystemInfo.ps1

# Export JSON
.\Get-SystemInfo.ps1 -OutputFormat JSON | Out-File system-info.json

# Rapport HTML
.\Get-SystemInfo.ps1 -OutputFormat HTML | Out-File report.html
```

---

## Sortie Exemple

```
============================================================
  INFORMATIONS SYSTÈME
============================================================
Hostname             : WORKSTATION01
OS                   : Microsoft Windows 11 Pro
Version              : 10.0.22631
Architecture         : 64-bit
Uptime               : 3.14:25:30
Domaine              : WORKGROUP

============================================================
  CPU
============================================================
Modèle               : AMD Ryzen 7 5800X 8-Core Processor
Cores                : 8 (16 logical)
Vitesse Max          : 3,800 MHz
Charge               : 12.5%

============================================================
  MÉMOIRE
============================================================
Total                : 32.00 GB
Utilisée             : 18.45 GB (57.7%)
Disponible           : 13.55 GB

============================================================
  DISQUES
============================================================
C: [System] - 234.5 GB / 500.0 GB (46.9%)
D: [Data] - 890.2 GB / 1000.0 GB (89.0%)

============================================================
  RÉSEAU
============================================================
Ethernet             : 192.168.1.100
  Gateway            : 192.168.1.1

============================================================
  TOP 5 PROCESSUS (MÉMOIRE)
============================================================
Name            PID  Memory (MB)
----            ---  -----------
chrome          1234        1245.3
Teams           5678         892.1
Code            9012         567.8
explorer        4567         234.5
powershell      8901         123.4
```

---

## Voir Aussi

- [Test-DiskSpace.ps1](Test-DiskSpace.md)
- [Get-PendingReboot.ps1](Get-PendingReboot.md)
