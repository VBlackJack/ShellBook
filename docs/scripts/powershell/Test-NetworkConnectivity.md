---
tags:
  - scripts
  - powershell
  - réseau
  - diagnostic
---

# Test-NetworkConnectivity.ps1

:material-star: **Niveau : Débutant**

Test de connectivité réseau avec diagnostic complet.

---

## Description

Ce script vérifie la connectivité réseau :
- Test de la passerelle locale
- Test DNS
- Test de connexion Internet
- Latence et disponibilité
- Rapport détaillé

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Test de connectivité réseau avec diagnostic.

.DESCRIPTION
    Vérifie la connectivité réseau locale et Internet,
    teste les DNS et génère un rapport détaillé.

.PARAMETER TestCount
    Nombre de pings pour chaque test (défaut: 4).

.PARAMETER Timeout
    Timeout en millisecondes (défaut: 2000).

.PARAMETER IncludeTraceroute
    Inclut un traceroute vers Internet.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1
    Exécute les tests avec les paramètres par défaut.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -TestCount 10 -IncludeTraceroute
    Tests plus approfondis avec traceroute.

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateRange(1, 100)]
    [int]$TestCount = 4,

    [Parameter()]
    [int]$Timeout = 2000,

    [Parameter()]
    [switch]$IncludeTraceroute
)

#region Functions
function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Cyan
}

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Success,
        [string]$Details = ""
    )

    $icon = if ($Success) { "[PASS]" } else { "[FAIL]" }
    $color = if ($Success) { "Green" } else { "Red" }

    Write-Host $icon -ForegroundColor $color -NoNewline
    Write-Host " $TestName" -NoNewline
    if ($Details) {
        Write-Host " - $Details" -ForegroundColor Gray
    } else {
        Write-Host ""
    }
}

function Test-PingHost {
    param(
        [string]$HostName,
        [string]$DisplayName,
        [int]$Count = 4,
        [int]$TimeoutMs = 2000
    )

    try {
        $results = Test-Connection -ComputerName $HostName -Count $Count -ErrorAction SilentlyContinue

        if ($results) {
            $avgLatency = ($results | Measure-Object -Property Latency -Average).Average
            $successCount = $results.Count
            $lossPercent = [math]::Round((($Count - $successCount) / $Count) * 100, 1)

            [PSCustomObject]@{
                Host       = $DisplayName
                Target     = $HostName
                Success    = $true
                AvgLatency = [math]::Round($avgLatency, 1)
                LossPercent = $lossPercent
                Details    = "{0:N1}ms avg, {1}% loss" -f $avgLatency, $lossPercent
            }
        } else {
            [PSCustomObject]@{
                Host       = $DisplayName
                Target     = $HostName
                Success    = $false
                AvgLatency = $null
                LossPercent = 100
                Details    = "No response"
            }
        }
    }
    catch {
        [PSCustomObject]@{
            Host       = $DisplayName
            Target     = $HostName
            Success    = $false
            AvgLatency = $null
            LossPercent = 100
            Details    = $_.Exception.Message
        }
    }
}

function Test-DNSResolution {
    param(
        [string]$Domain,
        [string]$DNSServer = ""
    )

    try {
        $params = @{
            Name = $Domain
            Type = 'A'
            ErrorAction = 'Stop'
        }

        if ($DNSServer) {
            $params['Server'] = $DNSServer
        }

        $result = Resolve-DnsName @params | Select-Object -First 1

        [PSCustomObject]@{
            Domain    = $Domain
            DNSServer = if ($DNSServer) { $DNSServer } else { "Default" }
            Success   = $true
            IPAddress = $result.IPAddress
            Details   = "Resolved to $($result.IPAddress)"
        }
    }
    catch {
        [PSCustomObject]@{
            Domain    = $Domain
            DNSServer = if ($DNSServer) { $DNSServer } else { "Default" }
            Success   = $false
            IPAddress = $null
            Details   = "Resolution failed"
        }
    }
}

function Test-HttpEndpoint {
    param(
        [string]$Url,
        [int]$TimeoutSec = 5
    )

    try {
        $response = Invoke-WebRequest -Uri $Url -TimeoutSec $TimeoutSec -UseBasicParsing -ErrorAction Stop

        [PSCustomObject]@{
            Url        = $Url
            Success    = $true
            StatusCode = $response.StatusCode
            Details    = "HTTP $($response.StatusCode)"
        }
    }
    catch {
        [PSCustomObject]@{
            Url        = $Url
            Success    = $false
            StatusCode = $null
            Details    = "Connection failed"
        }
    }
}

function Get-NetworkConfiguration {
    $adapters = Get-NetIPConfiguration | Where-Object { $_.IPv4Address }

    foreach ($adapter in $adapters) {
        [PSCustomObject]@{
            Interface   = $adapter.InterfaceAlias
            Status      = (Get-NetAdapter -Name $adapter.InterfaceAlias).Status
            IPv4Address = $adapter.IPv4Address.IPAddress
            Gateway     = $adapter.IPv4DefaultGateway.NextHop
            DNS         = ($adapter.DNSServer.ServerAddresses | Where-Object { $_ -match '^\d' }) -join ", "
        }
    }
}
#endregion

#region Main
$script:totalTests = 0
$script:passedTests = 0

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "        NETWORK CONNECTIVITY DIAGNOSTIC" -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "  Host: $env:COMPUTERNAME"

# Configuration réseau
Write-Header "NETWORK CONFIGURATION"

$netConfig = Get-NetworkConfiguration
foreach ($config in $netConfig) {
    Write-Host "  Interface: $($config.Interface) [$($config.Status)]"
    Write-Host "    IPv4:    $($config.IPv4Address)"
    Write-Host "    Gateway: $($config.Gateway)"
    Write-Host "    DNS:     $($config.DNS)"
    Write-Host ""
}

# Test passerelle locale
Write-Header "LOCAL NETWORK"

$gateway = (Get-NetIPConfiguration | Where-Object IPv4DefaultGateway | Select-Object -First 1).IPv4DefaultGateway.NextHop

if ($gateway) {
    $gatewayTest = Test-PingHost -HostName $gateway -DisplayName "Gateway" -Count $TestCount
    Write-TestResult -TestName "Gateway ($gateway)" -Success $gatewayTest.Success -Details $gatewayTest.Details
    $script:totalTests++
    if ($gatewayTest.Success) { $script:passedTests++ }
} else {
    Write-TestResult -TestName "Gateway" -Success $false -Details "No default gateway"
    $script:totalTests++
}

# Test DNS
Write-Header "DNS RESOLUTION"

$dnsServers = @("8.8.8.8", "1.1.1.1", "9.9.9.9")
$testDomain = "www.google.com"

foreach ($dns in $dnsServers) {
    $dnsTest = Test-DNSResolution -Domain $testDomain -DNSServer $dns
    Write-TestResult -TestName "DNS $dns" -Success $dnsTest.Success -Details $dnsTest.Details
    $script:totalTests++
    if ($dnsTest.Success) { $script:passedTests++ }
}

# Test Internet
Write-Header "INTERNET CONNECTIVITY"

$internetHosts = @(
    @{ Name = "Google"; Host = "www.google.com" }
    @{ Name = "Cloudflare"; Host = "1.1.1.1" }
    @{ Name = "Microsoft"; Host = "www.microsoft.com" }
)

foreach ($target in $internetHosts) {
    $pingTest = Test-PingHost -HostName $target.Host -DisplayName $target.Name -Count $TestCount
    Write-TestResult -TestName $target.Name -Success $pingTest.Success -Details $pingTest.Details
    $script:totalTests++
    if ($pingTest.Success) { $script:passedTests++ }
}

# Test HTTP
Write-Header "HTTP/HTTPS CONNECTIVITY"

$httpEndpoints = @(
    "https://www.google.com"
    "https://www.cloudflare.com"
    "https://www.github.com"
)

foreach ($url in $httpEndpoints) {
    $httpTest = Test-HttpEndpoint -Url $url
    Write-TestResult -TestName "HTTP $url" -Success $httpTest.Success -Details $httpTest.Details
    $script:totalTests++
    if ($httpTest.Success) { $script:passedTests++ }
}

# Traceroute optionnel
if ($IncludeTraceroute) {
    Write-Header "TRACEROUTE TO GOOGLE"

    try {
        $trace = Test-NetConnection -ComputerName "www.google.com" -TraceRoute -WarningAction SilentlyContinue
        $hopCount = 0

        foreach ($hop in $trace.TraceRoute) {
            $hopCount++
            Write-Host "  $hopCount. $hop"
        }

        Write-Host ""
        Write-Host "  Total hops: $hopCount" -ForegroundColor Cyan
    }
    catch {
        Write-Host "  Traceroute failed: $_" -ForegroundColor Red
    }
}

# Résumé
Write-Header "SUMMARY"

$successRate = [math]::Round(($script:passedTests / $script:totalTests) * 100, 1)

Write-Host "  Tests Passed: $script:passedTests / $script:totalTests ($successRate%)"
Write-Host ""

if ($successRate -eq 100) {
    Write-Host "  [OK] Network connectivity is healthy" -ForegroundColor Green
    exit 0
} elseif ($successRate -ge 50) {
    Write-Host "  [WARN] Some connectivity issues detected" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "  [FAIL] Significant connectivity problems" -ForegroundColor Red
    exit 2
}

Write-Host ("=" * 60) -ForegroundColor Cyan
#endregion
```

---

## Utilisation

```powershell
# Test standard
.\Test-NetworkConnectivity.ps1

# Tests plus approfondis
.\Test-NetworkConnectivity.ps1 -TestCount 10

# Avec traceroute
.\Test-NetworkConnectivity.ps1 -IncludeTraceroute
```

---

## Sortie Exemple

```
============================================================
        NETWORK CONNECTIVITY DIAGNOSTIC
============================================================
  Date: 2024-01-15 14:30:22
  Host: WORKSTATION01

============================================================
  NETWORK CONFIGURATION
============================================================
  Interface: Ethernet [Up]
    IPv4:    192.168.1.100
    Gateway: 192.168.1.1
    DNS:     192.168.1.1, 8.8.8.8

============================================================
  LOCAL NETWORK
============================================================
[PASS] Gateway (192.168.1.1) - 0.8ms avg, 0% loss

============================================================
  DNS RESOLUTION
============================================================
[PASS] DNS 8.8.8.8 - Resolved to 142.250.185.68
[PASS] DNS 1.1.1.1 - Resolved to 142.250.185.68
[PASS] DNS 9.9.9.9 - Resolved to 142.250.185.68

============================================================
  INTERNET CONNECTIVITY
============================================================
[PASS] Google - 12.3ms avg, 0% loss
[PASS] Cloudflare - 8.5ms avg, 0% loss
[PASS] Microsoft - 15.2ms avg, 0% loss

============================================================
  HTTP/HTTPS CONNECTIVITY
============================================================
[PASS] HTTP https://www.google.com - HTTP 200
[PASS] HTTP https://www.cloudflare.com - HTTP 200
[PASS] HTTP https://www.github.com - HTTP 200

============================================================
  SUMMARY
============================================================
  Tests Passed: 10 / 10 (100%)

  [OK] Network connectivity is healthy
============================================================
```

---

## Voir Aussi

- [Scan-Ports.ps1](Scan-Ports.md)
- [Get-DNSInfo.ps1](Get-DNSInfo.md)
