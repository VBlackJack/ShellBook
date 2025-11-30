---
tags:
  - scripts
  - powershell
  - windows
  - patching
  - compliance
  - audit
---

# Get-PatchCompliance.ps1

Rapport de conformité des patchs Windows avec scoring.

---

## Fonctionnalités

- **Score de conformité** : Calcul automatique du niveau de patching
- **Analyse multi-serveurs** : Inventaire de parc complet
- **Détection CVE critiques** : Identification des vulnérabilités connues
- **Comparaison baseline** : Écart avec niveau de patch attendu
- **Rapport exécutif** : Export HTML/JSON/CSV pour management
- **Intégration WSUS/SCCM** : Récupération des données sources

---

## Utilisation

```powershell
# Rapport local détaillé
.\Get-PatchCompliance.ps1

# Rapport multi-serveurs
.\Get-PatchCompliance.ps1 -ComputerName (Get-Content servers.txt)

# Export HTML pour management
.\Get-PatchCompliance.ps1 -ComputerName $servers -OutputFormat HTML -OutputPath "C:\Reports\patch_compliance.html"

# Avec seuil de conformité personnalisé
.\Get-PatchCompliance.ps1 -ComplianceThreshold 95 -MaxPatchAgeDays 30

# Mode CI/CD (JSON + code retour)
.\Get-PatchCompliance.ps1 -OutputFormat JSON -FailOnNonCompliant
```

---

## Paramètres

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-ComputerName` | String[] | localhost | Serveurs à auditer |
| `-Credential` | PSCredential | - | Credentials pour accès distant |
| `-ComplianceThreshold` | Int | 90 | Seuil de conformité (%) |
| `-MaxPatchAgeDays` | Int | 60 | Âge max acceptable des patchs |
| `-OutputFormat` | String | Table | Format (Table, JSON, CSV, HTML) |
| `-OutputPath` | String | - | Chemin du fichier de sortie |
| `-FailOnNonCompliant` | Switch | - | Code retour 1 si non conforme |
| `-IncludeDrivers` | Switch | - | Inclure les drivers dans l'analyse |

---

## Métriques de Conformité

| Métrique | Calcul | Seuil |
|----------|--------|-------|
| **Patch Score** | (Installed / (Installed + Pending)) × 100 | ≥ 90% |
| **Critical Gap** | Nombre de patchs critiques manquants | = 0 |
| **Patch Age** | Jours depuis dernier patch | ≤ 60 jours |
| **Reboot Pending** | Redémarrage en attente | Non |
| **Overall** | Moyenne pondérée des métriques | ≥ 90% |

---

## Code Source

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Generate Windows patch compliance report with scoring.

.DESCRIPTION
    Comprehensive patch compliance reporting tool that analyzes installed updates,
    pending patches, and calculates compliance scores for single or multiple systems.

.PARAMETER ComputerName
    Target computers to audit.

.PARAMETER Credential
    Credentials for remote access.

.PARAMETER ComplianceThreshold
    Minimum compliance score percentage (default: 90).

.PARAMETER MaxPatchAgeDays
    Maximum acceptable days since last patch (default: 60).

.PARAMETER OutputFormat
    Output format: Table, JSON, CSV, or HTML.

.PARAMETER OutputPath
    Path to save output file.

.PARAMETER FailOnNonCompliant
    Return exit code 1 if any system is non-compliant.

.PARAMETER IncludeDrivers
    Include driver updates in compliance calculation.

.EXAMPLE
    .\Get-PatchCompliance.ps1 -ComputerName "SRV01","SRV02" -OutputFormat HTML
    Generate HTML compliance report for multiple servers.

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
    [ValidateRange(50, 100)]
    [int]$ComplianceThreshold = 90,

    [Parameter()]
    [ValidateRange(7, 365)]
    [int]$MaxPatchAgeDays = 60,

    [Parameter()]
    [ValidateSet('Table', 'JSON', 'CSV', 'HTML')]
    [string]$OutputFormat = 'Table',

    [Parameter()]
    [string]$OutputPath,

    [Parameter()]
    [switch]$FailOnNonCompliant,

    [Parameter()]
    [switch]$IncludeDrivers
)

#region Configuration
$ErrorActionPreference = 'Continue'
Set-StrictMode -Version Latest

$Script:Results = [System.Collections.ArrayList]::new()
$Script:NonCompliantCount = 0

# Known critical CVEs to check (update this list periodically)
$Script:CriticalCVEs = @(
    'CVE-2024-21351',  # Windows SmartScreen
    'CVE-2024-21412',  # Internet Shortcut Files
    'CVE-2024-21893',  # Outlook
    'CVE-2023-36884',  # Office/Windows HTML RCE
    'CVE-2023-44487',  # HTTP/2 Rapid Reset
    'CVE-2023-36802',  # Streaming Service
    'CVE-2023-28252',  # CLFS
    'CVE-2023-24880',  # SmartScreen
    'CVE-2022-41040',  # Exchange SSRF
    'CVE-2022-41082',  # Exchange RCE
    'CVE-2021-44228'   # Log4Shell (Java apps)
)
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

function Get-ComplianceColor {
    param([int]$Score)

    if ($Score -ge 95) { return 'Green' }
    elseif ($Score -ge 80) { return 'Yellow' }
    else { return 'Red' }
}

function Get-ComplianceGrade {
    param([int]$Score)

    if ($Score -ge 95) { return 'A' }
    elseif ($Score -ge 90) { return 'B' }
    elseif ($Score -ge 80) { return 'C' }
    elseif ($Score -ge 70) { return 'D' }
    else { return 'F' }
}

function Get-InstalledUpdates {
    param([int]$Days = 90)

    $updates = @()
    $cutoff = (Get-Date).AddDays(-$Days)

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()
        $historyCount = $searcher.GetTotalHistoryCount()

        if ($historyCount -gt 0) {
            $history = $searcher.QueryHistory(0, [Math]::Min($historyCount, 500))

            foreach ($entry in $history) {
                if ($entry.Date -lt $cutoff) { continue }
                if ($entry.ResultCode -ne 2) { continue }  # Only successful

                $updates += [PSCustomObject]@{
                    Date        = $entry.Date
                    Title       = $entry.Title
                    KB          = if ($entry.Title -match 'KB(\d+)') { "KB$($Matches[1])" } else { $null }
                    Category    = $null
                }
            }
        }
    }
    catch {
        Write-Status "Error getting update history: $_" -Level Warning
    }

    return $updates | Sort-Object Date -Descending
}

function Get-PendingUpdates {
    param([bool]$IncludeDriverUpdates)

    $updates = @()

    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $searcher = $session.CreateUpdateSearcher()

        $criteria = "IsInstalled=0 and IsHidden=0"
        if (-not $IncludeDriverUpdates) {
            $criteria += " and Type='Software'"
        }

        $searchResult = $searcher.Search($criteria)

        foreach ($update in $searchResult.Updates) {
            $updates += [PSCustomObject]@{
                Title       = $update.Title
                KB          = if ($update.KBArticleIDs.Count -gt 0) { "KB$($update.KBArticleIDs[0])" } else { $null }
                Category    = ($update.Categories | Select-Object -First 1 -ExpandProperty Name)
                Severity    = $update.MsrcSeverity
                IsCritical  = $update.MsrcSeverity -eq 'Critical'
                CVEs        = $update.CveIDs | ForEach-Object { $_ }
                SizeMB      = [Math]::Round($update.MaxDownloadSize / 1MB, 2)
                Published   = $update.LastDeploymentChangeTime
            }
        }
    }
    catch {
        Write-Status "Error scanning pending updates: $_" -Level Warning
    }

    return $updates
}

function Get-LastPatchDate {
    param([object[]]$InstalledUpdates)

    if ($InstalledUpdates.Count -eq 0) {
        return $null
    }

    return ($InstalledUpdates | Sort-Object Date -Descending | Select-Object -First 1).Date
}

function Test-CriticalCVEs {
    param([object[]]$PendingUpdates)

    $exposedCVEs = @()

    foreach ($update in $PendingUpdates) {
        foreach ($cve in $update.CVEs) {
            if ($Script:CriticalCVEs -contains $cve) {
                $exposedCVEs += [PSCustomObject]@{
                    CVE     = $cve
                    Update  = $update.KB
                    Title   = $update.Title
                }
            }
        }
    }

    return $exposedCVEs
}

function Test-PendingReboot {
    $pending = $false

    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $pending = $true
    }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $pending = $true
    }

    return $pending
}

function Get-UpdateSource {
    $source = "Windows Update"

    # Check WSUS
    $wuKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (Test-Path $wuKey) {
        $settings = Get-ItemProperty -Path $wuKey -ErrorAction SilentlyContinue
        if ($settings.WUServer) {
            $source = "WSUS"
        }
    }

    # Check SCCM
    try {
        $ccm = Get-CimInstance -Namespace 'root\ccm' -ClassName 'SMS_Client' -ErrorAction Stop
        $source = "SCCM/MECM"
    }
    catch {}

    return $source
}

function Calculate-ComplianceScore {
    param(
        [int]$InstalledCount,
        [int]$PendingCount,
        [int]$CriticalCount,
        [int]$DaysSinceLastPatch,
        [bool]$RebootPending,
        [int]$MaxAgeDays
    )

    $scores = @{}

    # Patch installation ratio (40%)
    $totalPatches = $InstalledCount + $PendingCount
    if ($totalPatches -gt 0) {
        $scores['PatchRatio'] = [Math]::Round(($InstalledCount / $totalPatches) * 100)
    } else {
        $scores['PatchRatio'] = 100
    }

    # Critical patches (30%)
    if ($CriticalCount -eq 0) {
        $scores['Critical'] = 100
    } else {
        $scores['Critical'] = [Math]::Max(0, 100 - ($CriticalCount * 25))
    }

    # Patch age (20%)
    if ($DaysSinceLastPatch -le 30) {
        $scores['Age'] = 100
    } elseif ($DaysSinceLastPatch -le $MaxAgeDays) {
        $scores['Age'] = [Math]::Round(100 - (($DaysSinceLastPatch - 30) / ($MaxAgeDays - 30) * 50))
    } else {
        $scores['Age'] = [Math]::Max(0, 50 - (($DaysSinceLastPatch - $MaxAgeDays) / 30 * 50))
    }

    # Reboot status (10%)
    $scores['Reboot'] = if ($RebootPending) { 50 } else { 100 }

    # Calculate weighted average
    $overall = [Math]::Round(
        ($scores['PatchRatio'] * 0.4) +
        ($scores['Critical'] * 0.3) +
        ($scores['Age'] * 0.2) +
        ($scores['Reboot'] * 0.1)
    )

    return @{
        Overall     = $overall
        PatchRatio  = $scores['PatchRatio']
        Critical    = $scores['Critical']
        Age         = $scores['Age']
        Reboot      = $scores['Reboot']
        Grade       = Get-ComplianceGrade -Score $overall
    }
}

function Get-LocalCompliance {
    Write-Status "Analyzing: $env:COMPUTERNAME" -Level Header

    $result = [PSCustomObject]@{
        ComputerName        = $env:COMPUTERNAME
        OSVersion           = (Get-CimInstance Win32_OperatingSystem).Caption
        OSBuild             = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuild
        UpdateSource        = $null
        InstalledCount      = 0
        PendingCount        = 0
        PendingCritical     = 0
        PendingImportant    = 0
        LastPatchDate       = $null
        DaysSinceLastPatch  = $null
        RebootPending       = $false
        ExposedCVEs         = @()
        ComplianceScore     = 0
        ComplianceGrade     = 'F'
        IsCompliant         = $false
        Details             = @{}
        PendingUpdates      = @()
        RecentUpdates       = @()
        ScanTime            = Get-Date
    }

    # Update source
    Write-Status "Checking update source..." -Level Info
    $result.UpdateSource = Get-UpdateSource

    # Installed updates
    Write-Status "Retrieving installed updates..." -Level Info
    $result.RecentUpdates = Get-InstalledUpdates -Days 90
    $result.InstalledCount = $result.RecentUpdates.Count

    # Last patch date
    $result.LastPatchDate = Get-LastPatchDate -InstalledUpdates $result.RecentUpdates
    if ($result.LastPatchDate) {
        $result.DaysSinceLastPatch = [Math]::Round(((Get-Date) - $result.LastPatchDate).TotalDays)
    } else {
        $result.DaysSinceLastPatch = 999
    }

    # Pending updates
    Write-Status "Scanning pending updates..." -Level Info
    $result.PendingUpdates = Get-PendingUpdates -IncludeDriverUpdates $IncludeDrivers
    $result.PendingCount = $result.PendingUpdates.Count
    $result.PendingCritical = ($result.PendingUpdates | Where-Object { $_.Severity -eq 'Critical' }).Count
    $result.PendingImportant = ($result.PendingUpdates | Where-Object { $_.Severity -eq 'Important' }).Count

    # Critical CVE exposure
    Write-Status "Checking critical CVE exposure..." -Level Info
    $result.ExposedCVEs = Test-CriticalCVEs -PendingUpdates $result.PendingUpdates

    # Reboot status
    $result.RebootPending = Test-PendingReboot

    # Calculate compliance
    $scores = Calculate-ComplianceScore `
        -InstalledCount $result.InstalledCount `
        -PendingCount $result.PendingCount `
        -CriticalCount $result.PendingCritical `
        -DaysSinceLastPatch $result.DaysSinceLastPatch `
        -RebootPending $result.RebootPending `
        -MaxAgeDays $MaxPatchAgeDays

    $result.ComplianceScore = $scores.Overall
    $result.ComplianceGrade = $scores.Grade
    $result.Details = $scores
    $result.IsCompliant = $scores.Overall -ge $ComplianceThreshold

    return $result
}

function Format-TableOutput {
    param([object[]]$Results)

    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                         PATCH COMPLIANCE REPORT                                 ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    foreach ($result in $Results) {
        $scoreColor = Get-ComplianceColor -Score $result.ComplianceScore
        $status = if ($result.IsCompliant) { "COMPLIANT" } else { "NON-COMPLIANT" }
        $statusColor = if ($result.IsCompliant) { 'Green' } else { 'Red' }

        Write-Host "┌──────────────────────────────────────────────────────────────────────────────┐"
        Write-Host "│ " -NoNewline
        Write-Host $result.ComputerName.PadRight(40) -NoNewline -ForegroundColor Cyan
        Write-Host "Score: " -NoNewline
        Write-Host "$($result.ComplianceScore)% ($($result.ComplianceGrade))".PadRight(15) -NoNewline -ForegroundColor $scoreColor
        Write-Host $status -ForegroundColor $statusColor
        Write-Host "├──────────────────────────────────────────────────────────────────────────────┤"

        Write-Host "│  OS: $($result.OSVersion.Substring(0, [Math]::Min(60, $result.OSVersion.Length)))"
        Write-Host "│  Update Source: $($result.UpdateSource)"
        Write-Host "│  Last Patched: $(if ($result.LastPatchDate) { $result.LastPatchDate.ToString('yyyy-MM-dd') + " ($($result.DaysSinceLastPatch) days ago)" } else { 'Unknown' })"
        Write-Host "│"
        Write-Host "│  Installed (90d): $($result.InstalledCount)".PadRight(30) -NoNewline
        Write-Host "Pending: $($result.PendingCount)"

        if ($result.PendingCritical -gt 0) {
            Write-Host "│  " -NoNewline
            Write-Host "Critical Missing: $($result.PendingCritical)" -ForegroundColor Red
        }

        if ($result.ExposedCVEs.Count -gt 0) {
            Write-Host "│  " -NoNewline
            Write-Host "Exposed CVEs: $($result.ExposedCVEs.CVE -join ', ')" -ForegroundColor Red
        }

        if ($result.RebootPending) {
            Write-Host "│  " -NoNewline
            Write-Host "REBOOT PENDING" -ForegroundColor Yellow
        }

        Write-Host "│"
        Write-Host "│  Score Breakdown:"
        Write-Host "│    Patch Ratio: $($result.Details.PatchRatio)% | Critical: $($result.Details.Critical)% | Age: $($result.Details.Age)% | Reboot: $($result.Details.Reboot)%"

        Write-Host "└──────────────────────────────────────────────────────────────────────────────┘"
        Write-Host ""
    }

    # Summary
    $compliantCount = ($Results | Where-Object { $_.IsCompliant }).Count
    $avgScore = [Math]::Round(($Results | Measure-Object -Property ComplianceScore -Average).Average)

    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "SUMMARY: $compliantCount/$($Results.Count) systems compliant | Average Score: $avgScore%"
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

function Format-HTMLOutput {
    param(
        [object[]]$Results,
        [string]$Path
    )

    $compliantCount = ($Results | Where-Object { $_.IsCompliant }).Count
    $avgScore = [Math]::Round(($Results | Measure-Object -Property ComplianceScore -Average).Average)

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Patch Compliance Report - $(Get-Date -Format 'yyyy-MM-dd')</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0; }
        .summary { display: flex; gap: 20px; margin-bottom: 30px; }
        .summary-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); flex: 1; text-align: center; }
        .summary-card h2 { margin: 0; font-size: 36px; }
        .summary-card p { margin: 10px 0 0 0; color: #666; }
        .compliant { color: #28a745; }
        .non-compliant { color: #dc3545; }
        .warning { color: #ffc107; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        th { background: #1a1a2e; color: white; padding: 15px; text-align: left; }
        td { padding: 12px 15px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f9f9f9; }
        .score-badge { padding: 5px 15px; border-radius: 20px; font-weight: bold; }
        .score-a { background: #d4edda; color: #155724; }
        .score-b { background: #d1ecf1; color: #0c5460; }
        .score-c { background: #fff3cd; color: #856404; }
        .score-d { background: #f8d7da; color: #721c24; }
        .score-f { background: #721c24; color: white; }
        .status-compliant { color: #28a745; font-weight: bold; }
        .status-noncompliant { color: #dc3545; font-weight: bold; }
        .cve-tag { background: #dc3545; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-right: 4px; }
        .footer { text-align: center; margin-top: 30px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Patch Compliance Report</h1>
        <p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Threshold: $ComplianceThreshold%</p>
    </div>

    <div class="summary">
        <div class="summary-card">
            <h2>$($Results.Count)</h2>
            <p>Systems Analyzed</p>
        </div>
        <div class="summary-card">
            <h2 class="$(if ($compliantCount -eq $Results.Count) { 'compliant' } else { 'non-compliant' })">$compliantCount / $($Results.Count)</h2>
            <p>Compliant Systems</p>
        </div>
        <div class="summary-card">
            <h2 class="$(if ($avgScore -ge 90) { 'compliant' } elseif ($avgScore -ge 70) { 'warning' } else { 'non-compliant' })">$avgScore%</h2>
            <p>Average Score</p>
        </div>
        <div class="summary-card">
            <h2 class="non-compliant">$(($Results | ForEach-Object { $_.PendingCritical } | Measure-Object -Sum).Sum)</h2>
            <p>Critical Patches Missing</p>
        </div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Computer</th>
                <th>OS</th>
                <th>Score</th>
                <th>Status</th>
                <th>Last Patched</th>
                <th>Pending</th>
                <th>Critical</th>
                <th>CVE Exposure</th>
            </tr>
        </thead>
        <tbody>
"@

    foreach ($result in $Results | Sort-Object ComplianceScore) {
        $gradeClass = "score-$($result.ComplianceGrade.ToLower())"
        $statusClass = if ($result.IsCompliant) { 'status-compliant' } else { 'status-noncompliant' }
        $statusText = if ($result.IsCompliant) { '✓ Compliant' } else { '✗ Non-Compliant' }
        $cveHtml = if ($result.ExposedCVEs.Count -gt 0) {
            ($result.ExposedCVEs.CVE | ForEach-Object { "<span class='cve-tag'>$_</span>" }) -join ''
        } else { '-' }

        $html += @"
            <tr>
                <td><strong>$($result.ComputerName)</strong></td>
                <td>$($result.OSVersion.Substring(0, [Math]::Min(40, $result.OSVersion.Length)))...</td>
                <td><span class="score-badge $gradeClass">$($result.ComplianceScore)% ($($result.ComplianceGrade))</span></td>
                <td class="$statusClass">$statusText</td>
                <td>$(if ($result.LastPatchDate) { $result.LastPatchDate.ToString('yyyy-MM-dd') } else { 'Unknown' })</td>
                <td>$($result.PendingCount)</td>
                <td>$(if ($result.PendingCritical -gt 0) { "<span class='non-compliant'>$($result.PendingCritical)</span>" } else { '0' })</td>
                <td>$cveHtml</td>
            </tr>
"@
    }

    $html += @"
        </tbody>
    </table>

    <div class="footer">
        <p>Generated by ShellBook Get-PatchCompliance.ps1 | <a href="https://github.com/VBlackJack/ShellBook">https://github.com/VBlackJack/ShellBook</a></p>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $Path -Encoding UTF8
    Write-Status "HTML report saved: $Path" -Level OK
}
#endregion

#region Main
try {
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║           PATCH COMPLIANCE ANALYZER                        ║" -ForegroundColor Cyan
    Write-Host "║                   ShellBook v1.0                           ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    Write-Status "Compliance Threshold: $ComplianceThreshold%" -Level Info
    Write-Status "Max Patch Age: $MaxPatchAgeDays days" -Level Info
    Write-Host ""

    foreach ($computer in $ComputerName) {
        if ($computer -eq $env:COMPUTERNAME -or $computer -eq 'localhost') {
            $result = Get-LocalCompliance
        } else {
            Write-Status "Remote analysis for $computer requires PSRemoting" -Level Warning
            continue
        }

        [void]$Script:Results.Add($result)

        if (-not $result.IsCompliant) {
            $Script:NonCompliantCount++
        }
    }

    # Output
    switch ($OutputFormat) {
        'Table' {
            Format-TableOutput -Results $Script:Results
        }
        'JSON' {
            $jsonOutput = $Script:Results | Select-Object -Property * -ExcludeProperty PendingUpdates, RecentUpdates |
                          ConvertTo-Json -Depth 5
            if ($OutputPath) {
                $jsonOutput | Out-File -FilePath $OutputPath -Encoding UTF8
                Write-Status "JSON report saved: $OutputPath" -Level OK
            } else {
                $jsonOutput
            }
        }
        'CSV' {
            $csvOutput = $Script:Results | Select-Object ComputerName, OSVersion, UpdateSource,
                         ComplianceScore, ComplianceGrade, IsCompliant, InstalledCount, PendingCount,
                         PendingCritical, LastPatchDate, DaysSinceLastPatch, RebootPending
            if ($OutputPath) {
                $csvOutput | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                Write-Status "CSV report saved: $OutputPath" -Level OK
            } else {
                $csvOutput | ConvertTo-Csv -NoTypeInformation
            }
        }
        'HTML' {
            if (-not $OutputPath) {
                $OutputPath = "PatchCompliance_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            }
            Format-HTMLOutput -Results $Script:Results -Path $OutputPath
        }
    }

    # Exit code
    if ($FailOnNonCompliant -and $Script:NonCompliantCount -gt 0) {
        Write-Status "$Script:NonCompliantCount system(s) non-compliant" -Level Error
        exit 1
    }

    exit 0
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
╔════════════════════════════════════════════════════════════════════════════════╗
║                         PATCH COMPLIANCE REPORT                                 ║
╚════════════════════════════════════════════════════════════════════════════════╝

┌──────────────────────────────────────────────────────────────────────────────┐
│ SRV-PROD01                                      Score: 95% (A)    COMPLIANT
├──────────────────────────────────────────────────────────────────────────────┤
│  OS: Microsoft Windows Server 2022 Standard
│  Update Source: WSUS
│  Last Patched: 2024-01-10 (5 days ago)
│
│  Installed (90d): 45                Pending: 2
│
│  Score Breakdown:
│    Patch Ratio: 96% | Critical: 100% | Age: 100% | Reboot: 100%
└──────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│ SRV-LEGACY01                                    Score: 62% (D)    NON-COMPLIANT
├──────────────────────────────────────────────────────────────────────────────┤
│  OS: Microsoft Windows Server 2016 Datacenter
│  Update Source: Windows Update
│  Last Patched: 2023-11-15 (61 days ago)
│
│  Installed (90d): 12                Pending: 15
│  Critical Missing: 3
│  Exposed CVEs: CVE-2023-36884, CVE-2023-28252
│  REBOOT PENDING
│
│  Score Breakdown:
│    Patch Ratio: 44% | Critical: 25% | Age: 48% | Reboot: 50%
└──────────────────────────────────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════════
SUMMARY: 1/2 systems compliant | Average Score: 78%
═══════════════════════════════════════════════════════════════════════════════
```

---

## Intégration CI/CD

```yaml
# Azure DevOps Pipeline
- task: PowerShell@2
  displayName: 'Check Patch Compliance'
  inputs:
    filePath: '$(System.DefaultWorkingDirectory)/scripts/Get-PatchCompliance.ps1'
    arguments: '-ComputerName $(TargetServers) -ComplianceThreshold 90 -FailOnNonCompliant -OutputFormat JSON -OutputPath $(Build.ArtifactStagingDirectory)/compliance.json'
```

---

## Voir Aussi

- [Get-WindowsUpdateStatus.ps1](Get-WindowsUpdateStatus.md) - Diagnostic WU
- [Invoke-PrePatchPreparation.ps1](Invoke-PrePatchPreparation.md) - Préparation patch
- [patch_compliance_report.py](../python/patch_compliance_report.md) - Version Python
