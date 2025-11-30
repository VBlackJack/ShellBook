---
tags:
  - scripts
  - powershell
  - iis
  - windows
  - web
---

# Test-IISHealth.ps1

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète d'un serveur IIS Windows.

---

## Description

Ce script vérifie l'état d'un serveur IIS :
- Service W3SVC et pools d'applications
- Sites web et bindings
- Certificats SSL
- Logs et espace disque
- Performance (requêtes actives, connexions)

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Vérification santé d'un serveur IIS.

.DESCRIPTION
    Vérifie l'état complet d'un serveur IIS incluant
    les sites, pools, certificats SSL et performance.

.PARAMETER ComputerName
    Nom du serveur IIS (défaut: localhost).

.PARAMETER CheckSSL
    Vérifier les certificats SSL.

.PARAMETER CertWarningDays
    Jours avant expiration pour alerte certificat (défaut: 30).

.EXAMPLE
    .\Test-IISHealth.ps1
    Vérifie le serveur IIS local.

.EXAMPLE
    .\Test-IISHealth.ps1 -CheckSSL -CertWarningDays 60
    Vérifie IIS avec contrôle SSL.

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ComputerName = "localhost",

    [Parameter()]
    [switch]$CheckSSL,

    [Parameter()]
    [int]$CertWarningDays = 30
)

# Importer le module WebAdministration
Import-Module WebAdministration -ErrorAction Stop

#region Functions
function Write-Check {
    param(
        [string]$Name,
        [ValidateSet('Pass', 'Warn', 'Fail', 'Info')]
        [string]$Status,
        [string]$Message
    )

    $icons = @{
        'Pass' = @('[OK]  ', 'Green')
        'Warn' = @('[WARN]', 'Yellow')
        'Fail' = @('[FAIL]', 'Red')
        'Info' = @('[INFO]', 'Cyan')
    }

    Write-Host $icons[$Status][0] -ForegroundColor $icons[$Status][1] -NoNewline
    Write-Host " $Name" -NoNewline
    if ($Message) { Write-Host " - $Message" -ForegroundColor Gray }
    else { Write-Host "" }

    switch ($Status) {
        'Pass' { $script:passed++ }
        'Warn' { $script:warnings++ }
        'Fail' { $script:failed++ }
    }
    $script:total++
}
#endregion

#region Main
$script:total = 0
$script:passed = 0
$script:warnings = 0
$script:failed = 0

Write-Host ""
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  IIS HEALTH CHECK" -ForegroundColor Green
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  Server: $ComputerName"
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("-" * 65) -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Services IIS
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Services IIS]" -ForegroundColor Cyan

$iisServices = @(
    @{ Name = 'W3SVC'; Display = 'World Wide Web Publishing' }
    @{ Name = 'WAS'; Display = 'Windows Process Activation' }
    @{ Name = 'IISADMIN'; Display = 'IIS Admin Service' }
)

foreach ($svc in $iisServices) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Write-Check -Name $svc.Display -Status Pass -Message "Running"
    } elseif ($service) {
        Write-Check -Name $svc.Display -Status Fail -Message $service.Status
    } else {
        Write-Check -Name $svc.Display -Status Info -Message "Not installed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Application Pools
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Application Pools]" -ForegroundColor Cyan

$appPools = Get-ChildItem IIS:\AppPools

$runningPools = ($appPools | Where-Object { $_.State -eq 'Started' }).Count
$stoppedPools = ($appPools | Where-Object { $_.State -eq 'Stopped' }).Count

Write-Check -Name "Total App Pools" -Status Info -Message "$($appPools.Count)"

if ($stoppedPools -gt 0) {
    Write-Check -Name "Stopped Pools" -Status Warn -Message "$stoppedPools pool(s)"

    foreach ($pool in ($appPools | Where-Object { $_.State -eq 'Stopped' })) {
        Write-Host "       - $($pool.Name)" -ForegroundColor Yellow
    }
} else {
    Write-Check -Name "All Pools Running" -Status Pass -Message "$runningPools pool(s)"
}

# Vérifier la configuration des pools
foreach ($pool in $appPools | Where-Object { $_.State -eq 'Started' }) {
    $recycling = $pool.Recycling.PeriodicRestart
    $processModel = $pool.ProcessModel

    # Alerte si recycling désactivé
    if ($recycling.Time.TotalMinutes -eq 0 -and $recycling.Schedule.Count -eq 0) {
        Write-Check -Name "Pool $($pool.Name)" -Status Warn -Message "No recycling configured"
    }

    # Mode pipeline
    $pipelineMode = $pool.ManagedPipelineMode
    $runtimeVersion = $pool.ManagedRuntimeVersion
    Write-Host "       $($pool.Name): $pipelineMode, $runtimeVersion" -ForegroundColor Gray
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: Sites Web
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Sites Web]" -ForegroundColor Cyan

$sites = Get-ChildItem IIS:\Sites

$runningSites = ($sites | Where-Object { $_.State -eq 'Started' }).Count
$stoppedSites = ($sites | Where-Object { $_.State -eq 'Stopped' }).Count

Write-Check -Name "Total Sites" -Status Info -Message "$($sites.Count)"

if ($stoppedSites -gt 0) {
    Write-Check -Name "Stopped Sites" -Status Warn -Message "$stoppedSites site(s)"
}

foreach ($site in $sites) {
    $bindings = $site.Bindings.Collection
    $bindingInfo = ($bindings | ForEach-Object { $_.bindingInformation }) -join ", "

    if ($site.State -eq 'Started') {
        Write-Check -Name "Site $($site.Name)" -Status Pass -Message "Running"
    } else {
        Write-Check -Name "Site $($site.Name)" -Status Warn -Message $site.State
    }
    Write-Host "       Bindings: $bindingInfo" -ForegroundColor Gray
    Write-Host "       Path: $($site.PhysicalPath)" -ForegroundColor Gray
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Certificats SSL
# ═══════════════════════════════════════════════════════════════════
if ($CheckSSL) {
    Write-Host "`n[Certificats SSL]" -ForegroundColor Cyan

    $sslBindings = Get-ChildItem IIS:\SslBindings -ErrorAction SilentlyContinue

    if ($sslBindings) {
        foreach ($binding in $sslBindings) {
            $cert = Get-ChildItem Cert:\LocalMachine\My |
                Where-Object { $_.Thumbprint -eq $binding.Thumbprint }

            if ($cert) {
                $daysToExpiry = ($cert.NotAfter - (Get-Date)).Days
                $subject = $cert.Subject -replace 'CN=', ''

                if ($daysToExpiry -lt 0) {
                    Write-Check -Name "Cert $subject" -Status Fail `
                        -Message "EXPIRED ($($cert.NotAfter.ToString('yyyy-MM-dd')))"
                } elseif ($daysToExpiry -lt $CertWarningDays) {
                    Write-Check -Name "Cert $subject" -Status Warn `
                        -Message "Expires in $daysToExpiry days"
                } else {
                    Write-Check -Name "Cert $subject" -Status Pass `
                        -Message "Valid ($daysToExpiry days)"
                }
            }
        }
    } else {
        Write-Check -Name "SSL Bindings" -Status Info -Message "None configured"
    }
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Espace disque logs
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Logs IIS]" -ForegroundColor Cyan

$logPath = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
    -Filter 'system.applicationHost/sites/siteDefaults/logFile' -Name 'directory').Value

$logPath = [System.Environment]::ExpandEnvironmentVariables($logPath)

if (Test-Path $logPath) {
    $logSize = (Get-ChildItem -Path $logPath -Recurse -File -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    $logSizeGB = [math]::Round($logSize / 1GB, 2)

    Write-Check -Name "Log Directory" -Status Info -Message $logPath

    if ($logSizeGB -gt 10) {
        Write-Check -Name "Log Size" -Status Warn -Message "$logSizeGB GB (consider cleanup)"
    } else {
        Write-Check -Name "Log Size" -Status Pass -Message "$logSizeGB GB"
    }

    # Fichiers de log récents
    $recentLogs = Get-ChildItem -Path $logPath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
    Write-Host "       Recent logs (24h): $($recentLogs.Count) files" -ForegroundColor Gray
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Performance
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Performance]" -ForegroundColor Cyan

try {
    # Requêtes actives
    $activeRequests = (Get-Counter '\Web Service(_Total)\Current Connections' -ErrorAction Stop).CounterSamples.CookedValue
    Write-Check -Name "Active Connections" -Status Info -Message "$activeRequests"

    # Requêtes par seconde
    $reqPerSec = (Get-Counter '\Web Service(_Total)\Total Method Requests/sec' -ErrorAction Stop).CounterSamples.CookedValue
    Write-Check -Name "Requests/sec" -Status Info -Message "$([math]::Round($reqPerSec, 2))"

    # Mémoire des workers
    $w3wpProcesses = Get-Process -Name w3wp -ErrorAction SilentlyContinue
    if ($w3wpProcesses) {
        $totalMemoryMB = [math]::Round(($w3wpProcesses | Measure-Object -Property WorkingSet64 -Sum).Sum / 1MB, 0)
        Write-Check -Name "Worker Processes" -Status Info -Message "$($w3wpProcesses.Count) process(es), $totalMemoryMB MB"
    }
}
catch {
    Write-Check -Name "Performance Counters" -Status Warn -Message "Could not retrieve"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Configuration
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Configuration]" -ForegroundColor Cyan

# Vérifier les modules installés
$modules = Get-WebConfiguration -Filter 'system.webServer/modules' -PSPath 'MACHINE/WEBROOT/APPHOST'
Write-Host "       Modules loaded: $($modules.Collection.Count)" -ForegroundColor Gray

# Compression activée
$compression = Get-WebConfiguration -Filter 'system.webServer/urlCompression' -PSPath 'MACHINE/WEBROOT/APPHOST'
if ($compression.doStaticCompression -and $compression.doDynamicCompression) {
    Write-Check -Name "Compression" -Status Pass -Message "Static & Dynamic enabled"
} elseif ($compression.doStaticCompression) {
    Write-Check -Name "Compression" -Status Info -Message "Static only"
} else {
    Write-Check -Name "Compression" -Status Warn -Message "Disabled"
}

# Request filtering
$requestFiltering = Get-WebConfiguration -Filter 'system.webServer/security/requestFiltering' -PSPath 'MACHINE/WEBROOT/APPHOST'
if ($requestFiltering) {
    Write-Check -Name "Request Filtering" -Status Pass -Message "Enabled"
} else {
    Write-Check -Name "Request Filtering" -Status Warn -Message "Not configured"
}

# ═══════════════════════════════════════════════════════════════════
# RÉSUMÉ
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n" + ("=" * 65) -ForegroundColor Cyan
Write-Host "  RÉSUMÉ" -ForegroundColor Green
Write-Host ("=" * 65) -ForegroundColor Cyan

Write-Host "  Checks: $script:total total"
Write-Host "    - " -NoNewline; Write-Host "Passed: $script:passed" -ForegroundColor Green
Write-Host "    - " -NoNewline; Write-Host "Warnings: $script:warnings" -ForegroundColor Yellow
Write-Host "    - " -NoNewline; Write-Host "Failed: $script:failed" -ForegroundColor Red

Write-Host ""
if ($script:failed -gt 0) {
    Write-Host "  IIS STATUS: CRITICAL" -ForegroundColor Red
    exit 2
} elseif ($script:warnings -gt 0) {
    Write-Host "  IIS STATUS: DEGRADED" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "  IIS STATUS: HEALTHY" -ForegroundColor Green
    exit 0
}
#endregion
```

---

## Utilisation

```powershell
# Vérifier le serveur IIS local
.\Test-IISHealth.ps1

# Avec vérification SSL
.\Test-IISHealth.ps1 -CheckSSL

# Alerte certificat 60 jours avant expiration
.\Test-IISHealth.ps1 -CheckSSL -CertWarningDays 60
```

---

## Voir Aussi

- [Test-DNSServer.ps1](Test-DNSServer.md)
- [Get-ServiceStatus.ps1](Get-ServiceStatus.md)
