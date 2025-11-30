---
tags:
  - scripts
  - powershell
  - dns
  - windows
  - infrastructure
---

# Test-DNSServer.ps1

:material-star::material-star: **Niveau : Intermédiaire**

Vérification complète d'un serveur DNS Windows.

---

## Description

Ce script vérifie l'état d'un serveur DNS Windows :
- Service DNS et connectivité
- Zones DNS et réplication
- Enregistrements critiques (SOA, NS, A)
- Forwarders et résolution
- Scavenging et statistiques

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Vérification santé d'un serveur DNS Windows.

.DESCRIPTION
    Vérifie l'état complet d'un serveur DNS incluant
    les zones, la réplication, les forwarders et la résolution.

.PARAMETER DnsServer
    Nom du serveur DNS (défaut: localhost).

.PARAMETER TestDomains
    Domaines à tester pour la résolution.

.PARAMETER CheckADIntegrated
    Vérifier les zones AD-intégrées.

.EXAMPLE
    .\Test-DNSServer.ps1
    Vérifie le serveur DNS local.

.EXAMPLE
    .\Test-DNSServer.ps1 -DnsServer "DC01" -CheckADIntegrated
    Vérifie un serveur DNS AD.

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DnsServer = "localhost",

    [Parameter()]
    [string[]]$TestDomains = @("google.com", "microsoft.com", "cloudflare.com"),

    [Parameter()]
    [switch]$CheckADIntegrated
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
#endregion

#region Main
$script:total = 0
$script:passed = 0
$script:warnings = 0
$script:failed = 0

Write-Host ""
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  DNS SERVER HEALTH CHECK" -ForegroundColor Green
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  Server: $DnsServer"
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("-" * 65) -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Service DNS
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Service DNS]" -ForegroundColor Cyan

$dnsService = Get-Service -Name DNS -ComputerName $DnsServer -ErrorAction SilentlyContinue
if ($dnsService -and $dnsService.Status -eq 'Running') {
    Write-Check -Name "DNS Service" -Status Pass -Message "Running"
} else {
    Write-Check -Name "DNS Service" -Status Fail -Message "Not running"
    Write-Host "`n[FATAL] DNS service not running. Aborting." -ForegroundColor Red
    exit 2
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Connectivité DNS
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Connectivité]" -ForegroundColor Cyan

# Port 53 TCP
$tcp53 = Test-NetConnection -ComputerName $DnsServer -Port 53 -WarningAction SilentlyContinue
if ($tcp53.TcpTestSucceeded) {
    Write-Check -Name "DNS TCP/53" -Status Pass
} else {
    Write-Check -Name "DNS TCP/53" -Status Fail -Message "Port closed"
}

# Test UDP via query
try {
    $udpTest = Resolve-DnsName -Name "localhost" -Server $DnsServer -DnsOnly -ErrorAction Stop
    Write-Check -Name "DNS UDP/53" -Status Pass -Message "Responding"
}
catch {
    Write-Check -Name "DNS UDP/53" -Status Fail -Message "Not responding"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: Configuration serveur
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Configuration]" -ForegroundColor Cyan

try {
    $dnsConfig = Get-DnsServer -ComputerName $DnsServer -ErrorAction Stop

    # Recursion
    if ($dnsConfig.ServerRecursion.Enable) {
        Write-Check -Name "Recursion" -Status Info -Message "Enabled"
    } else {
        Write-Check -Name "Recursion" -Status Info -Message "Disabled"
    }

    # Cache
    $cacheSettings = $dnsConfig.ServerCache
    Write-Check -Name "Max Cache TTL" -Status Info -Message "$($cacheSettings.MaxTtl)"

    # Scavenging
    $scavenging = Get-DnsServerScavenging -ComputerName $DnsServer
    if ($scavenging.ScavengingState) {
        Write-Check -Name "Scavenging" -Status Pass -Message "Enabled (interval: $($scavenging.ScavengingInterval))"
    } else {
        Write-Check -Name "Scavenging" -Status Warn -Message "Disabled"
    }
}
catch {
    Write-Check -Name "Configuration" -Status Warn -Message "Could not retrieve: $_"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: Forwarders
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Forwarders]" -ForegroundColor Cyan

try {
    $forwarders = Get-DnsServerForwarder -ComputerName $DnsServer -ErrorAction Stop

    if ($forwarders.IPAddress.Count -gt 0) {
        Write-Check -Name "Forwarders configurés" -Status Pass -Message "$($forwarders.IPAddress.Count) forwarder(s)"

        foreach ($fw in $forwarders.IPAddress) {
            # Tester chaque forwarder
            try {
                $fwTest = Resolve-DnsName -Name "google.com" -Server $fw.ToString() -DnsOnly -ErrorAction Stop
                Write-Check -Name "Forwarder $fw" -Status Pass -Message "Responding"
            }
            catch {
                Write-Check -Name "Forwarder $fw" -Status Fail -Message "Not responding"
            }
        }
    } else {
        Write-Check -Name "Forwarders" -Status Info -Message "None configured (root hints used)"
    }
}
catch {
    Write-Check -Name "Forwarders" -Status Warn -Message "Could not check"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Zones DNS
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Zones DNS]" -ForegroundColor Cyan

try {
    $zones = Get-DnsServerZone -ComputerName $DnsServer -ErrorAction Stop

    $primaryZones = $zones | Where-Object { $_.ZoneType -eq 'Primary' }
    $secondaryZones = $zones | Where-Object { $_.ZoneType -eq 'Secondary' }
    $stubZones = $zones | Where-Object { $_.ZoneType -eq 'Stub' }
    $forwarderZones = $zones | Where-Object { $_.ZoneType -eq 'Forwarder' }

    Write-Check -Name "Primary zones" -Status Info -Message "$($primaryZones.Count)"
    Write-Check -Name "Secondary zones" -Status Info -Message "$($secondaryZones.Count)"

    if ($CheckADIntegrated) {
        $adIntegrated = $zones | Where-Object { $_.IsDsIntegrated }
        Write-Check -Name "AD-Integrated zones" -Status Info -Message "$($adIntegrated.Count)"
    }

    # Vérifier chaque zone primaire
    foreach ($zone in $primaryZones | Where-Object { $_.ZoneName -ne 'TrustAnchors' }) {
        # SOA record
        try {
            $soa = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -ComputerName $DnsServer -RRType SOA -ErrorAction Stop
            Write-Check -Name "Zone $($zone.ZoneName)" -Status Pass -Message "SOA OK"
        }
        catch {
            Write-Check -Name "Zone $($zone.ZoneName)" -Status Warn -Message "No SOA record"
        }
    }

    # Zones secondaires - vérifier le transfert
    foreach ($zone in $secondaryZones) {
        $zoneInfo = Get-DnsServerZone -Name $zone.ZoneName -ComputerName $DnsServer
        if ($zoneInfo.ZoneTransferLastSuccessTime) {
            $lastTransfer = $zoneInfo.ZoneTransferLastSuccessTime
            $hoursSince = [math]::Round(((Get-Date) - $lastTransfer).TotalHours, 1)

            if ($hoursSince -gt 24) {
                Write-Check -Name "Secondary $($zone.ZoneName)" -Status Warn -Message "Last transfer: $hoursSince h ago"
            } else {
                Write-Check -Name "Secondary $($zone.ZoneName)" -Status Pass -Message "Last transfer: $hoursSince h ago"
            }
        }
    }
}
catch {
    Write-Check -Name "Zones DNS" -Status Fail -Message $_.Exception.Message
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Résolution externe
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Résolution externe]" -ForegroundColor Cyan

foreach ($domain in $TestDomains) {
    try {
        $startTime = Get-Date
        $result = Resolve-DnsName -Name $domain -Server $DnsServer -DnsOnly -ErrorAction Stop
        $responseTime = [math]::Round(((Get-Date) - $startTime).TotalMilliseconds, 0)

        if ($responseTime -gt 1000) {
            Write-Check -Name "Resolve $domain" -Status Warn -Message "${responseTime}ms (slow)"
        } else {
            Write-Check -Name "Resolve $domain" -Status Pass -Message "${responseTime}ms"
        }
    }
    catch {
        Write-Check -Name "Resolve $domain" -Status Fail -Message "Failed"
    }
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Reverse lookup zones
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Reverse Lookup Zones]" -ForegroundColor Cyan

$reverseZones = $zones | Where-Object { $_.IsReverseLookupZone }
if ($reverseZones.Count -gt 0) {
    Write-Check -Name "Reverse zones" -Status Pass -Message "$($reverseZones.Count) zone(s)"
} else {
    Write-Check -Name "Reverse zones" -Status Warn -Message "None configured"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: Statistiques
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Statistiques]" -ForegroundColor Cyan

try {
    $stats = Get-DnsServerStatistics -ComputerName $DnsServer -ErrorAction Stop

    $queryStats = $stats.Query2Statistics
    Write-Host "       Total queries: $($queryStats.TotalQueries)" -ForegroundColor Gray
    Write-Host "       Successful: $($queryStats.Standard)" -ForegroundColor Gray
    Write-Host "       Recursive: $($queryStats.Recursive)" -ForegroundColor Gray

    $cacheStats = $stats.CacheStatistics
    Write-Host "       Cache hits: $($cacheStats.CacheHits)" -ForegroundColor Gray
    Write-Host "       Cache misses: $($cacheStats.CacheMisses)" -ForegroundColor Gray

    Write-Check -Name "Statistics" -Status Pass -Message "Retrieved"
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
    Write-Host "  DNS STATUS: CRITICAL" -ForegroundColor Red
    exit 2
} elseif ($script:warnings -gt 0) {
    Write-Host "  DNS STATUS: DEGRADED" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "  DNS STATUS: HEALTHY" -ForegroundColor Green
    exit 0
}
#endregion
```

---

## Utilisation

```powershell
# Vérifier le serveur DNS local
.\Test-DNSServer.ps1

# Serveur distant
.\Test-DNSServer.ps1 -DnsServer "DC01.domain.local"

# Avec vérification AD-intégrée
.\Test-DNSServer.ps1 -DnsServer "DC01" -CheckADIntegrated

# Domaines de test personnalisés
.\Test-DNSServer.ps1 -TestDomains @("internal.corp", "google.com")
```

---

## Voir Aussi

- [Test-ADHealth.ps1](Test-ADHealth.md)
- [Test-DHCPServer.ps1](Test-DHCPServer.md)
