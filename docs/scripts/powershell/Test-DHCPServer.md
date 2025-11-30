---
tags:
  - scripts
  - powershell
  - dhcp
  - windows
  - infrastructure
---

# Test-DHCPServer.ps1

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète d'un serveur DHCP Windows.

---

## Description

Ce script vérifie l'état d'un serveur DHCP Windows :
- Service DHCP et autorisation AD
- Scopes et utilisation des adresses
- Réservations et baux
- Failover et statistiques
- Options DHCP

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Vérification santé d'un serveur DHCP Windows.

.DESCRIPTION
    Vérifie l'état complet d'un serveur DHCP incluant
    les scopes, l'utilisation, le failover et les options.

.PARAMETER DhcpServer
    Nom du serveur DHCP (défaut: localhost).

.PARAMETER ScopeWarningThreshold
    Seuil d'alerte utilisation scope en % (défaut: 80).

.PARAMETER ScopeCriticalThreshold
    Seuil critique utilisation scope en % (défaut: 95).

.EXAMPLE
    .\Test-DHCPServer.ps1
    Vérifie le serveur DHCP local.

.EXAMPLE
    .\Test-DHCPServer.ps1 -DhcpServer "DHCP01" -ScopeWarningThreshold 70

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DhcpServer = "localhost",

    [Parameter()]
    [int]$ScopeWarningThreshold = 80,

    [Parameter()]
    [int]$ScopeCriticalThreshold = 95
)

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

function Get-ScopeUsageColor {
    param([int]$Percent)

    if ($Percent -ge $ScopeCriticalThreshold) { return 'Red' }
    elseif ($Percent -ge $ScopeWarningThreshold) { return 'Yellow' }
    else { return 'Green' }
}
#endregion

#region Main
$script:total = 0
$script:passed = 0
$script:warnings = 0
$script:failed = 0

Write-Host ""
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  DHCP SERVER HEALTH CHECK" -ForegroundColor Green
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  Server: $DhcpServer"
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  Thresholds: Warning=$ScopeWarningThreshold% Critical=$ScopeCriticalThreshold%"
Write-Host ("-" * 65) -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Service DHCP
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Service DHCP]" -ForegroundColor Cyan

$dhcpService = Get-Service -Name DHCPServer -ComputerName $DhcpServer -ErrorAction SilentlyContinue
if ($dhcpService -and $dhcpService.Status -eq 'Running') {
    Write-Check -Name "DHCP Service" -Status Pass -Message "Running"
} else {
    Write-Check -Name "DHCP Service" -Status Fail -Message "Not running"
    Write-Host "`n[FATAL] DHCP service not running. Aborting." -ForegroundColor Red
    exit 2
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Autorisation AD
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Autorisation Active Directory]" -ForegroundColor Cyan

try {
    $authorizedServers = Get-DhcpServerInDC -ErrorAction Stop
    $isAuthorized = $authorizedServers | Where-Object {
        $_.DnsName -like "*$DhcpServer*" -or $_.IPAddress -like "*$DhcpServer*"
    }

    if ($isAuthorized) {
        Write-Check -Name "AD Authorization" -Status Pass -Message "Server is authorized"
    } else {
        Write-Check -Name "AD Authorization" -Status Fail -Message "Server NOT authorized in AD"
    }
}
catch {
    Write-Check -Name "AD Authorization" -Status Warn -Message "Could not verify (not in domain?)"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: Configuration serveur
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Configuration]" -ForegroundColor Cyan

try {
    $serverSettings = Get-DhcpServerSetting -ComputerName $DhcpServer -ErrorAction Stop

    Write-Check -Name "Conflict Detection" -Status Info `
        -Message "Attempts: $($serverSettings.ConflictDetectionAttempts)"

    # Database
    $dbConfig = Get-DhcpServerDatabase -ComputerName $DhcpServer -ErrorAction Stop
    Write-Check -Name "Database path" -Status Info -Message $dbConfig.FileName

    # Audit logging
    $auditLog = Get-DhcpServerAuditLog -ComputerName $DhcpServer -ErrorAction Stop
    if ($auditLog.Enable) {
        Write-Check -Name "Audit Logging" -Status Pass -Message "Enabled"
    } else {
        Write-Check -Name "Audit Logging" -Status Warn -Message "Disabled"
    }
}
catch {
    Write-Check -Name "Configuration" -Status Warn -Message "Could not retrieve"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: IPv4 Scopes
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[IPv4 Scopes]" -ForegroundColor Cyan

try {
    $scopes = Get-DhcpServerv4Scope -ComputerName $DhcpServer -ErrorAction Stop

    if ($scopes.Count -eq 0) {
        Write-Check -Name "IPv4 Scopes" -Status Warn -Message "No scopes configured"
    } else {
        Write-Check -Name "IPv4 Scopes" -Status Info -Message "$($scopes.Count) scope(s)"

        foreach ($scope in $scopes) {
            $stats = Get-DhcpServerv4ScopeStatistics -ComputerName $DhcpServer -ScopeId $scope.ScopeId

            $totalAddresses = $stats.Free + $stats.InUse
            $usagePercent = if ($totalAddresses -gt 0) {
                [math]::Round(($stats.InUse / $totalAddresses) * 100, 1)
            } else { 0 }

            $scopeName = if ($scope.Name) { $scope.Name } else { $scope.ScopeId }

            # État du scope
            if ($scope.State -ne 'Active') {
                Write-Check -Name "Scope $scopeName" -Status Warn `
                    -Message "State: $($scope.State)"
                continue
            }

            # Utilisation
            if ($usagePercent -ge $ScopeCriticalThreshold) {
                Write-Check -Name "Scope $scopeName" -Status Fail `
                    -Message "$($stats.InUse)/$totalAddresses (${usagePercent}%) - CRITICAL"
            } elseif ($usagePercent -ge $ScopeWarningThreshold) {
                Write-Check -Name "Scope $scopeName" -Status Warn `
                    -Message "$($stats.InUse)/$totalAddresses (${usagePercent}%)"
            } else {
                Write-Check -Name "Scope $scopeName" -Status Pass `
                    -Message "$($stats.InUse)/$totalAddresses (${usagePercent}%)"
            }

            # Afficher les détails
            Write-Host "       Range: $($scope.StartRange) - $($scope.EndRange)" -ForegroundColor Gray
            Write-Host "       Free: $($stats.Free) | Reserved: $($stats.Reserved)" -ForegroundColor Gray
        }
    }
}
catch {
    Write-Check -Name "IPv4 Scopes" -Status Fail -Message $_.Exception.Message
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Failover
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Failover]" -ForegroundColor Cyan

try {
    $failover = Get-DhcpServerv4Failover -ComputerName $DhcpServer -ErrorAction Stop

    if ($failover) {
        foreach ($fo in $failover) {
            $foState = $fo.State

            if ($foState -eq 'Normal') {
                Write-Check -Name "Failover $($fo.Name)" -Status Pass `
                    -Message "Partner: $($fo.PartnerServer) - State: $foState"
            } elseif ($foState -in @('CommunicationInterrupted', 'PartnerDown')) {
                Write-Check -Name "Failover $($fo.Name)" -Status Fail `
                    -Message "Partner: $($fo.PartnerServer) - State: $foState"
            } else {
                Write-Check -Name "Failover $($fo.Name)" -Status Warn `
                    -Message "Partner: $($fo.PartnerServer) - State: $foState"
            }

            Write-Host "       Mode: $($fo.Mode) | Max Client Lead: $($fo.MaxClientLeadTime)" -ForegroundColor Gray
        }
    } else {
        Write-Check -Name "Failover" -Status Info -Message "Not configured"
    }
}
catch {
    Write-Check -Name "Failover" -Status Info -Message "Not configured"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Options DHCP
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Options DHCP Server]" -ForegroundColor Cyan

try {
    $serverOptions = Get-DhcpServerv4OptionValue -ComputerName $DhcpServer -ErrorAction Stop

    # Options importantes à vérifier
    $importantOptions = @(
        @{ Id = 6; Name = 'DNS Servers' }
        @{ Id = 15; Name = 'DNS Domain Name' }
        @{ Id = 3; Name = 'Router (Gateway)' }
    )

    foreach ($opt in $importantOptions) {
        $optValue = $serverOptions | Where-Object { $_.OptionId -eq $opt.Id }
        if ($optValue) {
            Write-Check -Name "Option $($opt.Id) ($($opt.Name))" -Status Pass `
                -Message "$($optValue.Value -join ', ')"
        } else {
            Write-Check -Name "Option $($opt.Id) ($($opt.Name))" -Status Info -Message "Not set at server level"
        }
    }
}
catch {
    Write-Check -Name "Server Options" -Status Info -Message "None configured"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Réservations
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Réservations]" -ForegroundColor Cyan

$totalReservations = 0
foreach ($scope in $scopes) {
    try {
        $reservations = Get-DhcpServerv4Reservation -ComputerName $DhcpServer -ScopeId $scope.ScopeId -ErrorAction Stop
        $totalReservations += $reservations.Count
    }
    catch { }
}
Write-Check -Name "Total Reservations" -Status Info -Message "$totalReservations"

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: Baux actifs
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Baux Actifs]" -ForegroundColor Cyan

$totalLeases = 0
foreach ($scope in $scopes) {
    try {
        $leases = Get-DhcpServerv4Lease -ComputerName $DhcpServer -ScopeId $scope.ScopeId -ErrorAction Stop
        $activeLeases = $leases | Where-Object { $_.AddressState -eq 'Active' }
        $totalLeases += $activeLeases.Count

        # Baux expirant bientôt (24h)
        $expiringLeases = $activeLeases | Where-Object {
            $_.LeaseExpiryTime -and $_.LeaseExpiryTime -lt (Get-Date).AddHours(24)
        }
        if ($expiringLeases.Count -gt 0) {
            Write-Host "       $($scope.ScopeId): $($expiringLeases.Count) leases expiring < 24h" -ForegroundColor Yellow
        }
    }
    catch { }
}
Write-Check -Name "Active Leases (all scopes)" -Status Info -Message "$totalLeases"

# ═══════════════════════════════════════════════════════════════════
# CHECK 9: Statistiques serveur
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Statistiques]" -ForegroundColor Cyan

try {
    $serverStats = Get-DhcpServerv4Statistics -ComputerName $DhcpServer -ErrorAction Stop

    Write-Host "       Discovers: $($serverStats.Discovers)" -ForegroundColor Gray
    Write-Host "       Offers: $($serverStats.Offers)" -ForegroundColor Gray
    Write-Host "       Requests: $($serverStats.Requests)" -ForegroundColor Gray
    Write-Host "       Acks: $($serverStats.Acks)" -ForegroundColor Gray
    Write-Host "       Naks: $($serverStats.Naks)" -ForegroundColor Gray
    Write-Host "       Declines: $($serverStats.Declines)" -ForegroundColor Gray

    # Ratio NAK élevé ?
    if ($serverStats.Requests -gt 0) {
        $nakRatio = ($serverStats.Naks / $serverStats.Requests) * 100
        if ($nakRatio -gt 5) {
            Write-Check -Name "NAK Ratio" -Status Warn -Message "$([math]::Round($nakRatio,1))% (high)"
        } else {
            Write-Check -Name "NAK Ratio" -Status Pass -Message "$([math]::Round($nakRatio,1))%"
        }
    }
}
catch {
    Write-Check -Name "Statistics" -Status Info -Message "Could not retrieve"
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
    Write-Host "  DHCP STATUS: CRITICAL" -ForegroundColor Red
    exit 2
} elseif ($script:warnings -gt 0) {
    Write-Host "  DHCP STATUS: DEGRADED" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "  DHCP STATUS: HEALTHY" -ForegroundColor Green
    exit 0
}
#endregion
```

---

## Utilisation

```powershell
# Vérifier le serveur DHCP local
.\Test-DHCPServer.ps1

# Serveur distant
.\Test-DHCPServer.ps1 -DhcpServer "DHCP01.domain.local"

# Seuils personnalisés
.\Test-DHCPServer.ps1 -ScopeWarningThreshold 70 -ScopeCriticalThreshold 90
```

---

## Voir Aussi

- [Test-DNSServer.ps1](Test-DNSServer.md)
- [Test-ADHealth.ps1](Test-ADHealth.md)
