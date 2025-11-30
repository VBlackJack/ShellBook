---
tags:
  - scripts
  - powershell
  - pki
  - certificates
  - windows
  - security
---

# Test-PKIHealth.ps1

:material-star::material-star::material-star: **Niveau : Avancé**

Vérification complète d'une autorité de certification Windows (AD CS).

---

## Description

Ce script vérifie l'état d'une PKI Windows :
- Services CA et disponibilité
- Validité du certificat CA
- CRL et Delta CRL
- Templates de certificats
- Certificats émis expirés ou à renouveler
- Espace disque base de données

---

## Script

```powershell
#Requires -Version 5.1
<#
.SYNOPSIS
    Health check d'une PKI Windows (AD CS).

.DESCRIPTION
    Vérifie l'état complet d'une autorité de certification
    incluant CA, CRL, templates et certificats.

.PARAMETER CAName
    Nom de la CA (défaut: auto-détection).

.PARAMETER CRLWarningHours
    Heures avant expiration CRL pour alerte (défaut: 24).

.PARAMETER CertExpiryDays
    Jours pour vérifier certificats expirants (défaut: 30).

.EXAMPLE
    .\Test-PKIHealth.ps1
    Vérifie la CA locale.

.EXAMPLE
    .\Test-PKIHealth.ps1 -CRLWarningHours 48 -CertExpiryDays 60

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$CAName,

    [Parameter()]
    [int]$CRLWarningHours = 24,

    [Parameter()]
    [int]$CertExpiryDays = 30
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

function Get-CAInfo {
    try {
        $caInfo = certutil -cainfo name 2>$null
        if ($LASTEXITCODE -eq 0) {
            $caName = ($caInfo | Select-String "CA name:").ToString() -replace ".*CA name:\s*", ""
            return $caName.Trim()
        }
    }
    catch { }
    return $null
}
#endregion

#region Main
$script:total = 0
$script:passed = 0
$script:warnings = 0
$script:failed = 0

Write-Host ""
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  PKI / AD CS HEALTH CHECK" -ForegroundColor Green
Write-Host ("=" * 65) -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("-" * 65) -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════════
# CHECK 1: Service CA
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Service Autorité de Certification]" -ForegroundColor Cyan

$certsvc = Get-Service -Name CertSvc -ErrorAction SilentlyContinue
if ($certsvc -and $certsvc.Status -eq 'Running') {
    Write-Check -Name "Certificate Services" -Status Pass -Message "Running"
} elseif ($certsvc) {
    Write-Check -Name "Certificate Services" -Status Fail -Message $certsvc.Status
    Write-Host "`n[FATAL] CA service not running. Aborting." -ForegroundColor Red
    exit 2
} else {
    Write-Check -Name "Certificate Services" -Status Fail -Message "Not installed"
    Write-Host "`n[FATAL] AD CS not installed. Aborting." -ForegroundColor Red
    exit 2
}

# Détecter le nom de la CA
if (-not $CAName) {
    $CAName = Get-CAInfo
}
Write-Host "  CA Name: $CAName" -ForegroundColor White

# ═══════════════════════════════════════════════════════════════════
# CHECK 2: Certificat CA
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Certificat CA]" -ForegroundColor Cyan

try {
    $caCertOutput = certutil -ca.cert 2>$null
    $caCert = Get-ChildItem Cert:\LocalMachine\CA |
        Where-Object { $_.Subject -match $CAName } |
        Sort-Object NotAfter -Descending |
        Select-Object -First 1

    if ($caCert) {
        $daysToExpiry = ($caCert.NotAfter - (Get-Date)).Days

        if ($daysToExpiry -lt 0) {
            Write-Check -Name "CA Certificate" -Status Fail -Message "EXPIRED"
        } elseif ($daysToExpiry -lt 365) {
            Write-Check -Name "CA Certificate" -Status Warn `
                -Message "Expires in $daysToExpiry days ($($caCert.NotAfter.ToString('yyyy-MM-dd')))"
        } else {
            Write-Check -Name "CA Certificate" -Status Pass `
                -Message "Valid until $($caCert.NotAfter.ToString('yyyy-MM-dd')) ($daysToExpiry days)"
        }

        Write-Host "       Subject: $($caCert.Subject)" -ForegroundColor Gray
        Write-Host "       Thumbprint: $($caCert.Thumbprint)" -ForegroundColor Gray
    } else {
        Write-Check -Name "CA Certificate" -Status Warn -Message "Could not retrieve"
    }
}
catch {
    Write-Check -Name "CA Certificate" -Status Warn -Message "Error: $_"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 3: CRL (Certificate Revocation List)
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[CRL Status]" -ForegroundColor Cyan

try {
    # Récupérer les infos CRL
    $crlInfo = certutil -crl 2>$null

    # CRL de base
    $baseCRL = certutil -getcrl 2>$null
    if ($LASTEXITCODE -eq 0) {
        # Parser les dates
        $crlOutput = certutil -dump (Get-ChildItem "$env:SystemRoot\System32\CertSrv\CertEnroll\*.crl" |
            Select-Object -First 1).FullName 2>$null

        $nextUpdate = ($crlOutput | Select-String "Next Update:").ToString() -replace ".*Next Update:\s*", ""

        if ($nextUpdate) {
            $nextUpdateDate = [DateTime]::Parse($nextUpdate)
            $hoursToExpiry = ($nextUpdateDate - (Get-Date)).TotalHours

            if ($hoursToExpiry -lt 0) {
                Write-Check -Name "Base CRL" -Status Fail -Message "EXPIRED"
            } elseif ($hoursToExpiry -lt $CRLWarningHours) {
                Write-Check -Name "Base CRL" -Status Warn `
                    -Message "Expires in $([math]::Round($hoursToExpiry, 1)) hours"
            } else {
                Write-Check -Name "Base CRL" -Status Pass `
                    -Message "Valid ($([math]::Round($hoursToExpiry, 1)) hours)"
            }
        }
    } else {
        Write-Check -Name "CRL" -Status Warn -Message "Could not retrieve"
    }

    # Delta CRL
    $deltaCRL = Get-ChildItem "$env:SystemRoot\System32\CertSrv\CertEnroll\*+.crl" -ErrorAction SilentlyContinue
    if ($deltaCRL) {
        Write-Check -Name "Delta CRL" -Status Pass -Message "Configured"
    } else {
        Write-Check -Name "Delta CRL" -Status Info -Message "Not configured"
    }
}
catch {
    Write-Check -Name "CRL" -Status Warn -Message "Error checking CRL"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 4: CDP et AIA
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Points de Distribution]" -ForegroundColor Cyan

try {
    $cdpOutput = certutil -getreg CA\CRLPublicationURLs 2>$null
    if ($cdpOutput) {
        $cdpCount = ($cdpOutput | Select-String "http://|ldap://|file://").Count
        Write-Check -Name "CDP Configured" -Status Info -Message "$cdpCount location(s)"
    }

    $aiaOutput = certutil -getreg CA\CACertPublicationURLs 2>$null
    if ($aiaOutput) {
        $aiaCount = ($aiaOutput | Select-String "http://|ldap://|file://").Count
        Write-Check -Name "AIA Configured" -Status Info -Message "$aiaCount location(s)"
    }
}
catch {
    Write-Check -Name "CDP/AIA" -Status Warn -Message "Could not verify"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 5: Templates de certificats
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Templates de Certificats]" -ForegroundColor Cyan

try {
    $templates = certutil -catemplates 2>$null
    if ($templates) {
        $templateCount = ($templates | Where-Object { $_ -match ":" }).Count
        Write-Check -Name "Certificate Templates" -Status Info -Message "$templateCount template(s) available"

        # Templates courants
        $commonTemplates = @("User", "Computer", "WebServer", "CodeSigning", "SmartcardLogon")
        foreach ($tpl in $commonTemplates) {
            if ($templates | Where-Object { $_ -match $tpl }) {
                Write-Host "       [+] $tpl" -ForegroundColor Gray
            }
        }
    }
}
catch {
    Write-Check -Name "Templates" -Status Warn -Message "Could not retrieve"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 6: Certificats en attente
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Requêtes en Attente]" -ForegroundColor Cyan

try {
    $pendingRequests = certutil -view -out "RequestID,CommonName,SubmittedWhen" -restrict "Disposition=9" 2>$null
    $pendingCount = ($pendingRequests | Select-String "Row \d+:").Count

    if ($pendingCount -gt 10) {
        Write-Check -Name "Pending Requests" -Status Warn -Message "$pendingCount request(s)"
    } else {
        Write-Check -Name "Pending Requests" -Status Info -Message "$pendingCount request(s)"
    }
}
catch {
    Write-Check -Name "Pending Requests" -Status Info -Message "0"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 7: Certificats expirant bientôt
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Certificats Expirants]" -ForegroundColor Cyan

try {
    $futureDate = (Get-Date).AddDays($CertExpiryDays).ToString("MM/dd/yyyy")
    $today = (Get-Date).ToString("MM/dd/yyyy")

    $expiringCerts = certutil -view -out "RequestID,CommonName,NotAfter" `
        -restrict "Disposition=20,NotAfter<=$futureDate,NotAfter>=$today" 2>$null

    $expiringCount = ($expiringCerts | Select-String "Row \d+:").Count

    if ($expiringCount -gt 0) {
        Write-Check -Name "Certs expiring (${CertExpiryDays}d)" -Status Warn `
            -Message "$expiringCount certificate(s)"
    } else {
        Write-Check -Name "Certs expiring (${CertExpiryDays}d)" -Status Pass `
            -Message "None"
    }
}
catch {
    Write-Check -Name "Expiring Certificates" -Status Info -Message "Could not check"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 8: Base de données CA
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Base de Données CA]" -ForegroundColor Cyan

try {
    $dbPath = (certutil -getreg CA\DBDirectory 2>$null | Select-String "REG_SZ").ToString() -replace ".*REG_SZ\s*=\s*", ""
    $dbPath = $dbPath.Trim()

    if (Test-Path $dbPath) {
        $dbFiles = Get-ChildItem -Path $dbPath -File
        $dbSizeMB = [math]::Round(($dbFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 2)

        Write-Check -Name "Database Location" -Status Info -Message $dbPath
        Write-Check -Name "Database Size" -Status Info -Message "$dbSizeMB MB"

        # Espace disque
        $drive = Split-Path -Path $dbPath -Qualifier
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$drive'"
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)

        if ($freeGB -lt 5) {
            Write-Check -Name "Disk Space ($drive)" -Status Fail -Message "$freeGB GB free"
        } elseif ($freeGB -lt 20) {
            Write-Check -Name "Disk Space ($drive)" -Status Warn -Message "$freeGB GB free"
        } else {
            Write-Check -Name "Disk Space ($drive)" -Status Pass -Message "$freeGB GB free"
        }
    }
}
catch {
    Write-Check -Name "Database" -Status Warn -Message "Could not check"
}

# ═══════════════════════════════════════════════════════════════════
# CHECK 9: Audit logging
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n[Audit & Sécurité]" -ForegroundColor Cyan

try {
    $auditFilter = certutil -getreg CA\AuditFilter 2>$null
    if ($auditFilter -match "0x7f") {
        Write-Check -Name "CA Auditing" -Status Pass -Message "Full auditing enabled"
    } elseif ($auditFilter -match "0x0") {
        Write-Check -Name "CA Auditing" -Status Warn -Message "Auditing disabled"
    } else {
        Write-Check -Name "CA Auditing" -Status Info -Message "Partial auditing"
    }
}
catch {
    Write-Check -Name "Auditing" -Status Info -Message "Could not verify"
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
    Write-Host "  PKI STATUS: CRITICAL" -ForegroundColor Red
    exit 2
} elseif ($script:warnings -gt 0) {
    Write-Host "  PKI STATUS: DEGRADED" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "  PKI STATUS: HEALTHY" -ForegroundColor Green
    exit 0
}
#endregion
```

---

## Utilisation

```powershell
# Vérifier la CA locale
.\Test-PKIHealth.ps1

# Avec paramètres personnalisés
.\Test-PKIHealth.ps1 -CRLWarningHours 48 -CertExpiryDays 60

# CA spécifique
.\Test-PKIHealth.ps1 -CAName "Corp-Root-CA"
```

---

## Voir Aussi

- [Test-ADHealth.ps1](Test-ADHealth.md)
- [Test-DNSServer.ps1](Test-DNSServer.md)
