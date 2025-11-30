---
tags:
  - scripts
  - powershell
  - windows
  - ssl
  - certificates
  - security
---

# Test-SSLCertificates.ps1

Vérification des certificats SSL/TLS sur endpoints multiples.

---

## Fonctionnalités

- Test de certificats sur endpoints HTTPS
- Vérification de la chaîne de confiance
- Alertes d'expiration (seuils configurables)
- Support SNI (Server Name Indication)
- Export JSON pour intégration CI/CD
- Vérification des certificats locaux (Store)

---

## Utilisation

```powershell
# Test d'un seul endpoint
.\Test-SSLCertificates.ps1 -Endpoint "https://example.com"

# Test multiple endpoints
.\Test-SSLCertificates.ps1 -Endpoint "example.com","api.example.com" -Port 443

# Alerte expiration < 30 jours
.\Test-SSLCertificates.ps1 -Endpoint "example.com" -WarningDays 30 -CriticalDays 7

# Export JSON pour CI/CD
.\Test-SSLCertificates.ps1 -Endpoint "example.com" -OutputFormat JSON

# Vérifier les certificats du store local
.\Test-SSLCertificates.ps1 -LocalStore -StoreName My -WarningDays 60
```

---

## Paramètres

| Paramètre | Type | Défaut | Description |
|-----------|------|--------|-------------|
| `-Endpoint` | String[] | - | URLs ou hostnames à tester |
| `-Port` | Int | 443 | Port HTTPS |
| `-WarningDays` | Int | 30 | Seuil warning (jours avant expiration) |
| `-CriticalDays` | Int | 7 | Seuil critique (jours avant expiration) |
| `-TimeoutSeconds` | Int | 10 | Timeout de connexion |
| `-LocalStore` | Switch | - | Vérifier le store local |
| `-StoreName` | String | My | Nom du store (My, Root, CA) |
| `-OutputFormat` | String | Table | Format de sortie (Table, JSON, CSV) |
| `-IgnoreValidation` | Switch | - | Ignorer erreurs de validation |

---

## Code Source

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Test SSL/TLS certificates on multiple endpoints.

.DESCRIPTION
    Validates SSL certificates, checks expiration dates, verifies chain of trust,
    and reports on certificate health. Supports both remote endpoints and local
    certificate store verification.

.PARAMETER Endpoint
    URLs or hostnames to test.

.PARAMETER Port
    HTTPS port (default: 443).

.PARAMETER WarningDays
    Days before expiration to trigger warning (default: 30).

.PARAMETER CriticalDays
    Days before expiration to trigger critical alert (default: 7).

.PARAMETER TimeoutSeconds
    Connection timeout in seconds.

.PARAMETER LocalStore
    Check local certificate store instead of remote endpoints.

.PARAMETER StoreName
    Certificate store name (My, Root, CA, etc.).

.PARAMETER OutputFormat
    Output format: Table, JSON, or CSV.

.PARAMETER IgnoreValidation
    Ignore certificate validation errors (self-signed, etc.).

.EXAMPLE
    .\Test-SSLCertificates.ps1 -Endpoint "google.com","github.com"
    Test certificates for multiple endpoints.

.NOTES
    Author: ShellBook
    Version: 1.0
    Date: 2024-01-01
#>

[CmdletBinding(DefaultParameterSetName = 'Remote')]
param(
    [Parameter(ParameterSetName = 'Remote', Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Endpoint,

    [Parameter(ParameterSetName = 'Remote')]
    [ValidateRange(1, 65535)]
    [int]$Port = 443,

    [Parameter()]
    [ValidateRange(1, 365)]
    [int]$WarningDays = 30,

    [Parameter()]
    [ValidateRange(1, 90)]
    [int]$CriticalDays = 7,

    [Parameter(ParameterSetName = 'Remote')]
    [ValidateRange(1, 60)]
    [int]$TimeoutSeconds = 10,

    [Parameter(ParameterSetName = 'Local', Mandatory = $true)]
    [switch]$LocalStore,

    [Parameter(ParameterSetName = 'Local')]
    [ValidateSet('My', 'Root', 'CA', 'TrustedPeople', 'TrustedPublisher')]
    [string]$StoreName = 'My',

    [Parameter()]
    [ValidateSet('Table', 'JSON', 'CSV')]
    [string]$OutputFormat = 'Table',

    [Parameter(ParameterSetName = 'Remote')]
    [switch]$IgnoreValidation
)

#region Configuration
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Results = [System.Collections.ArrayList]::new()
$ExitCode = 0
#endregion

#region Functions
function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('OK', 'Warning', 'Critical', 'Info', 'Error')]
        [string]$Status = 'Info'
    )

    $colors = @{
        'OK'       = 'Green'
        'Warning'  = 'Yellow'
        'Critical' = 'Red'
        'Info'     = 'Cyan'
        'Error'    = 'Magenta'
    }

    $symbols = @{
        'OK'       = '[OK]'
        'Warning'  = '[WARN]'
        'Critical' = '[CRIT]'
        'Info'     = '[*]'
        'Error'    = '[ERR]'
    }

    Write-Host "$($symbols[$Status]) $Message" -ForegroundColor $colors[$Status]
}

function Get-CertificateStatus {
    param(
        [int]$DaysRemaining,
        [int]$WarnThreshold,
        [int]$CritThreshold
    )

    if ($DaysRemaining -lt 0) {
        return "EXPIRED"
    } elseif ($DaysRemaining -le $CritThreshold) {
        return "CRITICAL"
    } elseif ($DaysRemaining -le $WarnThreshold) {
        return "WARNING"
    } else {
        return "OK"
    }
}

function Test-RemoteCertificate {
    param(
        [string]$HostName,
        [int]$HostPort,
        [int]$Timeout,
        [bool]$SkipValidation
    )

    $result = [PSCustomObject]@{
        Endpoint         = "${HostName}:${HostPort}"
        Subject          = $null
        Issuer           = $null
        NotBefore        = $null
        NotAfter         = $null
        DaysRemaining    = $null
        Status           = "UNKNOWN"
        Thumbprint       = $null
        SignatureAlgo    = $null
        KeySize          = $null
        SANs             = $null
        ChainValid       = $null
        Error            = $null
    }

    try {
        # Create TCP connection
        $tcpClient = [System.Net.Sockets.TcpClient]::new()
        $connectTask = $tcpClient.ConnectAsync($HostName, $HostPort)

        if (-not $connectTask.Wait($Timeout * 1000)) {
            throw "Connection timeout"
        }

        # SSL stream with callback
        $callback = if ($SkipValidation) {
            { $true }
        } else {
            $null
        }

        $sslStream = [System.Net.Security.SslStream]::new(
            $tcpClient.GetStream(),
            $false,
            $callback
        )

        try {
            $sslStream.AuthenticateAsClient($HostName)
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                $sslStream.RemoteCertificate
            )

            # Get certificate details
            $result.Subject = $cert.Subject
            $result.Issuer = $cert.Issuer
            $result.NotBefore = $cert.NotBefore
            $result.NotAfter = $cert.NotAfter
            $result.Thumbprint = $cert.Thumbprint
            $result.SignatureAlgo = $cert.SignatureAlgorithm.FriendlyName
            $result.KeySize = $cert.PublicKey.Key.KeySize

            # Calculate days remaining
            $result.DaysRemaining = [Math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
            $result.Status = Get-CertificateStatus -DaysRemaining $result.DaysRemaining `
                -WarnThreshold $WarningDays -CritThreshold $CriticalDays

            # Extract SANs
            $sanExtension = $cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
            if ($sanExtension) {
                $result.SANs = $sanExtension.Format($false)
            }

            # Build and verify chain
            $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
            $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
            $result.ChainValid = $chain.Build($cert)

            $cert.Dispose()
            $chain.Dispose()
        }
        finally {
            $sslStream.Dispose()
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        $result.Status = "ERROR"
    }
    finally {
        if ($tcpClient) {
            $tcpClient.Dispose()
        }
    }

    return $result
}

function Get-LocalCertificates {
    param(
        [string]$Store
    )

    $storePath = "Cert:\LocalMachine\$Store"
    $certs = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue

    $results = foreach ($cert in $certs) {
        $daysRemaining = [Math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)

        [PSCustomObject]@{
            Endpoint         = "LocalMachine\$Store"
            Subject          = $cert.Subject
            Issuer           = $cert.Issuer
            NotBefore        = $cert.NotBefore
            NotAfter         = $cert.NotAfter
            DaysRemaining    = $daysRemaining
            Status           = Get-CertificateStatus -DaysRemaining $daysRemaining `
                -WarnThreshold $WarningDays -CritThreshold $CriticalDays
            Thumbprint       = $cert.Thumbprint
            SignatureAlgo    = $cert.SignatureAlgorithm.FriendlyName
            KeySize          = if ($cert.PublicKey.Key) { $cert.PublicKey.Key.KeySize } else { $null }
            SANs             = $null
            ChainValid       = $null
            Error            = $null
        }
    }

    return $results
}

function Format-Output {
    param(
        [object[]]$Data,
        [string]$Format
    )

    switch ($Format) {
        'Table' {
            $Data | Format-Table -AutoSize @(
                'Endpoint',
                @{N='Subject'; E={if ($_.Subject.Length -gt 40) { $_.Subject.Substring(0,37) + "..." } else { $_.Subject }}},
                'NotAfter',
                @{N='Days'; E={$_.DaysRemaining}},
                @{N='Status'; E={
                    switch ($_.Status) {
                        'OK'       { Write-Host $_ -ForegroundColor Green -NoNewline; $_ }
                        'WARNING'  { Write-Host $_ -ForegroundColor Yellow -NoNewline; $_ }
                        'CRITICAL' { Write-Host $_ -ForegroundColor Red -NoNewline; $_ }
                        'EXPIRED'  { Write-Host $_ -ForegroundColor Magenta -NoNewline; $_ }
                        'ERROR'    { Write-Host $_ -ForegroundColor Red -NoNewline; $_ }
                        default    { $_ }
                    }
                }},
                'ChainValid'
            )
        }
        'JSON' {
            $Data | ConvertTo-Json -Depth 5
        }
        'CSV' {
            $Data | ConvertTo-Csv -NoTypeInformation
        }
    }
}
#endregion

#region Main
try {
    Write-Status "=== SSL/TLS Certificate Checker ===" -Status Info
    Write-Host ""

    if ($LocalStore) {
        Write-Status "Checking local certificate store: $StoreName" -Status Info
        $Results = Get-LocalCertificates -Store $StoreName
    } else {
        Write-Status "Testing $($Endpoint.Count) endpoint(s)..." -Status Info
        Write-Host ""

        foreach ($ep in $Endpoint) {
            # Clean endpoint
            $hostName = $ep -replace '^https?://' -replace '/.*$'

            Write-Status "Testing: $hostName" -Status Info

            $certResult = Test-RemoteCertificate -HostName $hostName -HostPort $Port `
                -Timeout $TimeoutSeconds -SkipValidation $IgnoreValidation

            [void]$Results.Add($certResult)

            # Log status
            switch ($certResult.Status) {
                'OK'       { Write-Status "  Valid for $($certResult.DaysRemaining) days" -Status OK }
                'WARNING'  { Write-Status "  Expires in $($certResult.DaysRemaining) days" -Status Warning; $ExitCode = 1 }
                'CRITICAL' { Write-Status "  CRITICAL: $($certResult.DaysRemaining) days left!" -Status Critical; $ExitCode = 2 }
                'EXPIRED'  { Write-Status "  EXPIRED!" -Status Critical; $ExitCode = 2 }
                'ERROR'    { Write-Status "  Error: $($certResult.Error)" -Status Error; $ExitCode = 2 }
            }
        }
    }

    Write-Host ""
    Write-Status "=== Results ===" -Status Info
    Write-Host ""

    # Output results
    Format-Output -Data $Results -Format $OutputFormat

    # Summary
    Write-Host ""
    $okCount = ($Results | Where-Object { $_.Status -eq 'OK' }).Count
    $warnCount = ($Results | Where-Object { $_.Status -eq 'WARNING' }).Count
    $critCount = ($Results | Where-Object { $_.Status -in @('CRITICAL', 'EXPIRED') }).Count
    $errCount = ($Results | Where-Object { $_.Status -eq 'ERROR' }).Count

    Write-Status "Summary: OK=$okCount, Warning=$warnCount, Critical=$critCount, Errors=$errCount" -Status Info

    exit $ExitCode
}
catch {
    Write-Status "Fatal error: $_" -Status Error
    exit 2
}
#endregion
```

---

## Exemples de Sortie

### Table Output

```
Endpoint           Subject                                  NotAfter            Days Status   ChainValid
--------           -------                                  --------            ---- ------   ----------
google.com:443     CN=*.google.com                         2024-04-15 12:00:00   89 OK       True
github.com:443     CN=github.com                           2024-03-20 23:59:59   63 OK       True
expired.badssl.com CN=*.badssl.com                         2023-12-01 00:00:00  -45 EXPIRED  False
```

### JSON Output

```json
[
  {
    "Endpoint": "google.com:443",
    "Subject": "CN=*.google.com",
    "Issuer": "CN=GTS CA 1C3, O=Google Trust Services LLC, C=US",
    "NotBefore": "2024-01-15T08:00:00",
    "NotAfter": "2024-04-15T12:00:00",
    "DaysRemaining": 89,
    "Status": "OK",
    "Thumbprint": "ABC123...",
    "SignatureAlgo": "sha256RSA",
    "KeySize": 2048,
    "SANs": "DNS Name=*.google.com, DNS Name=google.com",
    "ChainValid": true,
    "Error": null
  }
]
```

---

## Intégration CI/CD

### GitHub Actions

```yaml
- name: Check SSL Certificates
  shell: pwsh
  run: |
    $result = .\Test-SSLCertificates.ps1 -Endpoint "api.example.com" -OutputFormat JSON
    if ($LASTEXITCODE -ne 0) {
      Write-Error "Certificate check failed!"
      exit 1
    }
```

### Monitoring avec Alertes

```powershell
# Script de monitoring quotidien
$endpoints = @("prod-api.example.com", "staging-api.example.com", "cdn.example.com")
$results = .\Test-SSLCertificates.ps1 -Endpoint $endpoints -WarningDays 30 -OutputFormat JSON | ConvertFrom-Json

$expiring = $results | Where-Object { $_.Status -in @('WARNING', 'CRITICAL') }

if ($expiring) {
    # Envoyer alerte (Slack, Email, PagerDuty...)
    Send-SlackMessage -Message "Certificats expirant bientôt: $($expiring.Endpoint -join ', ')"
}
```

---

## Voir Aussi

- [cert_checker.py](../python/cert_checker.md) - Version Python
- [ssl-csr-wizard.sh](../bash/ssl-csr-wizard.md) - Générateur CSR
