---
tags:
  - scripts
  - powershell
  - wsus
  - windows
  - patching
---

# Test-WSUSHealth.ps1

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète de la santé d'un serveur WSUS.

---

## Description

Ce script vérifie l'état d'un serveur WSUS :
- Connectivité au serveur WSUS
- État des services
- Synchronisation
- Espace disque du content store
- Clients en erreur
- Mises à jour en attente d'approbation

---

## Prérequis

```powershell
# Module WSUS (installé avec le rôle WSUS)
# Ou installer les outils d'administration RSAT
Install-WindowsFeature -Name UpdateServices-RSAT
```

---

## Script

```powershell
#Requires -Version 5.1
#Requires -Modules UpdateServices
<#
.SYNOPSIS
    Vérification santé d'un serveur WSUS.

.DESCRIPTION
    Vérifie l'état complet d'un serveur WSUS incluant
    les services, la synchronisation, l'espace disque
    et les clients.

.PARAMETER WsusServer
    Nom du serveur WSUS (défaut: localhost).

.PARAMETER Port
    Port WSUS (défaut: 8530 pour HTTP, 8531 pour HTTPS).

.PARAMETER UseSSL
    Utiliser HTTPS.

.PARAMETER DiskWarningThreshold
    Seuil d'alerte espace disque en % (défaut: 80).

.PARAMETER ClientErrorThreshold
    Nombre de clients en erreur avant alerte (défaut: 10).

.EXAMPLE
    .\Test-WSUSHealth.ps1
    Vérifie le serveur WSUS local.

.EXAMPLE
    .\Test-WSUSHealth.ps1 -WsusServer "wsus.domain.local" -UseSSL
    Vérifie un serveur WSUS distant en HTTPS.

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$WsusServer = "localhost",

    [Parameter()]
    [int]$Port = 8530,

    [Parameter()]
    [switch]$UseSSL,

    [Parameter()]
    [int]$DiskWarningThreshold = 80,

    [Parameter()]
    [int]$ClientErrorThreshold = 10
)

#region Functions
function Write-CheckResult {
    param(
        [string]$Check,
        [bool]$Success,
        [string]$Message,
        [ValidateSet('OK', 'Warning', 'Error')]
        [string]$Status = 'OK'
    )

    $icon = switch ($Status) {
        'OK'      { "[OK]  "; "Green" }
        'Warning' { "[WARN]"; "Yellow" }
        'Error'   { "[FAIL]"; "Red" }
    }

    Write-Host $icon[0] -ForegroundColor $icon[1] -NoNewline
    Write-Host " $Check" -NoNewline
    if ($Message) {
        Write-Host " - $Message" -ForegroundColor Gray
    } else {
        Write-Host ""
    }
}

function Get-WSUSServiceStatus {
    $services = @(
        @{ Name = 'WsusService'; DisplayName = 'WSUS Service' }
        @{ Name = 'W3SVC'; DisplayName = 'IIS (W3SVC)' }
        @{ Name = 'WASService'; DisplayName = 'Windows Process Activation' }
    )

    $results = @()
    foreach ($svc in $services) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            Name        = $svc.DisplayName
            Status      = if ($service) { $service.Status } else { 'NotFound' }
            IsRunning   = $service.Status -eq 'Running'
        }
    }
    return $results
}

function Get-WSUSContentStoreInfo {
    param($Wsus)

    $config = $Wsus.GetConfiguration()
    $contentPath = $config.LocalContentCachePath

    if (Test-Path $contentPath) {
        $drive = Split-Path -Path $contentPath -Qualifier
        $diskInfo = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$drive'"

        $totalGB = [math]::Round($diskInfo.Size / 1GB, 2)
        $freeGB = [math]::Round($diskInfo.FreeSpace / 1GB, 2)
        $usedPercent = [math]::Round((($totalGB - $freeGB) / $totalGB) * 100, 1)

        # Taille du content store
        $contentSize = (Get-ChildItem -Path $contentPath -Recurse -File -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
        $contentSizeGB = [math]::Round($contentSize / 1GB, 2)

        return [PSCustomObject]@{
            Path         = $contentPath
            Drive        = $drive
            TotalGB      = $totalGB
            FreeGB       = $freeGB
            UsedPercent  = $usedPercent
            ContentSizeGB = $contentSizeGB
        }
    }
    return $null
}
#endregion

#region Main
$script:checksTotal = 0
$script:checksPassed = 0
$script:checksWarning = 0
$script:checksFailed = 0

Write-Host ""
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  WSUS HEALTH CHECK" -ForegroundColor Green
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  Server: $WsusServer"
Write-Host "  Port: $Port (SSL: $UseSSL)"
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("-" * 65) -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Services Windows
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Services Windows]" -ForegroundColor Cyan

$serviceStatus = Get-WSUSServiceStatus
foreach ($svc in $serviceStatus) {
    $script:checksTotal++
    if ($svc.IsRunning) {
        Write-CheckResult -Check $svc.Name -Success $true -Message "Running" -Status OK
        $script:checksPassed++
    } else {
        Write-CheckResult -Check $svc.Name -Success $false -Message $svc.Status -Status Error
        $script:checksFailed++
    }
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Connexion WSUS
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Connexion WSUS]" -ForegroundColor Cyan

$script:checksTotal++
try {
    if ($UseSSL) { $Port = 8531 }
    $wsus = Get-WsusServer -Name $WsusServer -PortNumber $Port -UseSsl:$UseSSL

    Write-CheckResult -Check "Connexion WSUS" -Success $true -Message "Connected" -Status OK
    $script:checksPassed++
}
catch {
    Write-CheckResult -Check "Connexion WSUS" -Success $false -Message $_.Exception.Message -Status Error
    $script:checksFailed++
    Write-Host "`n[FATAL] Cannot connect to WSUS server. Aborting." -ForegroundColor Red
    exit 2
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: Dernière synchronisation
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Synchronisation]" -ForegroundColor Cyan

$script:checksTotal++
$subscription = $wsus.GetSubscription()
$lastSync = $subscription.LastSynchronizationTime
$syncStatus = $subscription.GetLastSynchronizationInfo()

$hoursSinceSync = [math]::Round(((Get-Date) - $lastSync).TotalHours, 1)

if ($syncStatus.Result -eq 'Succeeded') {
    if ($hoursSinceSync -gt 48) {
        Write-CheckResult -Check "Dernière sync" -Success $true -Message "$lastSync ($hoursSinceSync h ago)" -Status Warning
        $script:checksWarning++
    } else {
        Write-CheckResult -Check "Dernière sync" -Success $true -Message "$lastSync ($hoursSinceSync h ago)" -Status OK
        $script:checksPassed++
    }
} else {
    Write-CheckResult -Check "Dernière sync" -Success $false -Message "Status: $($syncStatus.Result)" -Status Error
    $script:checksFailed++
}

# Prochaine sync planifiée
$nextSync = $subscription.GetNextSynchronizationTime()
Write-Host "       Prochaine sync: $nextSync" -ForegroundColor Gray

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Espace disque Content Store
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Stockage]" -ForegroundColor Cyan

$script:checksTotal++
$contentInfo = Get-WSUSContentStoreInfo -Wsus $wsus

if ($contentInfo) {
    Write-Host "       Content Path: $($contentInfo.Path)" -ForegroundColor Gray
    Write-Host "       Content Size: $($contentInfo.ContentSizeGB) GB" -ForegroundColor Gray

    if ($contentInfo.UsedPercent -ge 90) {
        Write-CheckResult -Check "Espace disque ($($contentInfo.Drive))" -Success $false `
            -Message "$($contentInfo.FreeGB) GB free ($($contentInfo.UsedPercent)% used)" -Status Error
        $script:checksFailed++
    } elseif ($contentInfo.UsedPercent -ge $DiskWarningThreshold) {
        Write-CheckResult -Check "Espace disque ($($contentInfo.Drive))" -Success $true `
            -Message "$($contentInfo.FreeGB) GB free ($($contentInfo.UsedPercent)% used)" -Status Warning
        $script:checksWarning++
    } else {
        Write-CheckResult -Check "Espace disque ($($contentInfo.Drive))" -Success $true `
            -Message "$($contentInfo.FreeGB) GB free ($($contentInfo.UsedPercent)% used)" -Status OK
        $script:checksPassed++
    }
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Statistiques clients
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Clients WSUS]" -ForegroundColor Cyan

$computerScope = New-Object Microsoft.UpdateServices.Administration.ComputerTargetScope
$allComputers = $wsus.GetComputerTargets($computerScope)

$totalClients = $allComputers.Count
$clientsWithErrors = ($allComputers | Where-Object { $_.LastReportedStatusTime -lt (Get-Date).AddDays(-7) }).Count
$clientsNotReporting = ($allComputers | Where-Object { $_.LastReportedStatusTime -lt (Get-Date).AddDays(-30) }).Count

Write-Host "       Total clients: $totalClients" -ForegroundColor Gray

$script:checksTotal++
if ($clientsWithErrors -ge $ClientErrorThreshold) {
    Write-CheckResult -Check "Clients sans rapport (>7j)" -Success $false `
        -Message "$clientsWithErrors clients" -Status Warning
    $script:checksWarning++
} else {
    Write-CheckResult -Check "Clients sans rapport (>7j)" -Success $true `
        -Message "$clientsWithErrors clients" -Status OK
    $script:checksPassed++
}

$script:checksTotal++
if ($clientsNotReporting -gt 0) {
    Write-CheckResult -Check "Clients inactifs (>30j)" -Success $false `
        -Message "$clientsNotReporting clients" -Status Warning
    $script:checksWarning++
} else {
    Write-CheckResult -Check "Clients inactifs (>30j)" -Success $true `
        -Message "0 clients" -Status OK
    $script:checksPassed++
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Mises à jour
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Mises à jour]" -ForegroundColor Cyan

$updateScope = New-Object Microsoft.UpdateServices.Administration.UpdateScope
$updateScope.ApprovedStates = [Microsoft.UpdateServices.Administration.ApprovedStates]::NotApproved
$notApprovedUpdates = $wsus.GetUpdates($updateScope)

$criticalNotApproved = ($notApprovedUpdates | Where-Object {
    $_.MsrcSeverity -eq 'Critical' -and $_.IsSuperseded -eq $false
}).Count

$securityNotApproved = ($notApprovedUpdates | Where-Object {
    $_.UpdateClassificationTitle -eq 'Security Updates' -and $_.IsSuperseded -eq $false
}).Count

Write-Host "       Updates not approved: $($notApprovedUpdates.Count)" -ForegroundColor Gray

$script:checksTotal++
if ($criticalNotApproved -gt 0) {
    Write-CheckResult -Check "Critical non approuvées" -Success $false `
        -Message "$criticalNotApproved updates" -Status Warning
    $script:checksWarning++
} else {
    Write-CheckResult -Check "Critical non approuvées" -Success $true `
        -Message "0 updates" -Status OK
    $script:checksPassed++
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Database
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Base de données]" -ForegroundColor Cyan

$script:checksTotal++
$config = $wsus.GetConfiguration()
$dbConfig = $config.GetDatabaseConfiguration()

Write-Host "       Server: $($dbConfig.ServerName)" -ForegroundColor Gray
Write-Host "       Database: $($dbConfig.DatabaseName)" -ForegroundColor Gray

# Vérifier connexion DB
try {
    $dbConnection = $wsus.GetDatabaseConfiguration()
    Write-CheckResult -Check "Connexion DB" -Success $true -Message "Connected" -Status OK
    $script:checksPassed++
}
catch {
    Write-CheckResult -Check "Connexion DB" -Success $false -Message "Failed" -Status Error
    $script:checksFailed++
}

# ═══════════════════════════════════════════════════════════════════
# RÉSUMÉ
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n" + ("=" * 65) -ForegroundColor Cyan
Write-Host "  RÉSUMÉ" -ForegroundColor Green
Write-Host ("=" * 65) -ForegroundColor Cyan

Write-Host "  Checks: $script:checksTotal total"
Write-Host "    - " -NoNewline
Write-Host "Passed: $script:checksPassed" -ForegroundColor Green
Write-Host "    - " -NoNewline
Write-Host "Warnings: $script:checksWarning" -ForegroundColor Yellow
Write-Host "    - " -NoNewline
Write-Host "Failed: $script:checksFailed" -ForegroundColor Red

Write-Host ""
if ($script:checksFailed -gt 0) {
    Write-Host "  Status: UNHEALTHY" -ForegroundColor Red
    exit 2
} elseif ($script:checksWarning -gt 0) {
    Write-Host "  Status: DEGRADED" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "  Status: HEALTHY" -ForegroundColor Green
    exit 0
}
#endregion
```

---

## Utilisation

```powershell
# Vérifier le serveur WSUS local
.\Test-WSUSHealth.ps1

# Serveur distant
.\Test-WSUSHealth.ps1 -WsusServer "wsus.domain.local"

# Avec HTTPS
.\Test-WSUSHealth.ps1 -WsusServer "wsus.domain.local" -UseSSL

# Seuils personnalisés
.\Test-WSUSHealth.ps1 -DiskWarningThreshold 70 -ClientErrorThreshold 5
```

---

## Sortie Exemple

```
=================================================================
  WSUS HEALTH CHECK
=================================================================
  Server: wsus.domain.local
  Port: 8530 (SSL: False)
  Date: 2024-01-15 14:30:22
-----------------------------------------------------------------

[Services Windows]
[OK]   WSUS Service - Running
[OK]   IIS (W3SVC) - Running
[OK]   Windows Process Activation - Running

[Connexion WSUS]
[OK]   Connexion WSUS - Connected

[Synchronisation]
[OK]   Dernière sync - 2024-01-15 06:00:00 (8.5 h ago)
       Prochaine sync: 2024-01-16 06:00:00

[Stockage]
       Content Path: D:\WSUS\WsusContent
       Content Size: 125.4 GB
[OK]   Espace disque (D:) - 374.6 GB free (62.5% used)

[Clients WSUS]
       Total clients: 450
[OK]   Clients sans rapport (>7j) - 3 clients
[WARN] Clients inactifs (>30j) - 12 clients

[Mises à jour]
       Updates not approved: 45
[WARN] Critical non approuvées - 2 updates

[Base de données]
       Server: \\.\pipe\MICROSOFT##WID\tsql\query
       Database: SUSDB
[OK]   Connexion DB - Connected

=================================================================
  RÉSUMÉ
=================================================================
  Checks: 10 total
    - Passed: 8
    - Warnings: 2
    - Failed: 0

  Status: DEGRADED
```

---

## Voir Aussi

- [Test-ADHealth.ps1](Test-ADHealth.md)
- [Get-ServiceStatus.ps1](Get-ServiceStatus.md)
