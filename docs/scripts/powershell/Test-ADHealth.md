---
tags:
  - scripts
  - powershell
  - active-directory
  - ldap
  - windows
---

# Test-ADHealth.ps1

:material-star::material-star::material-star: **Niveau : Avancé**

Vérification complète de la santé Active Directory.

---

## Description

Ce script vérifie l'état d'Active Directory :
- Réplication entre DC
- Services AD (NTDS, KDC, DNS, etc.)
- FSMO roles
- Sysvol et Netlogon
- DNS AD-integrated
- Certificats DC
- Espace disque NTDS

---

## Prérequis

```powershell
# Module Active Directory
Install-WindowsFeature -Name RSAT-AD-PowerShell
```

---

## Script

```powershell
#Requires -Version 5.1
#Requires -Modules ActiveDirectory
<#
.SYNOPSIS
    Vérification santé Active Directory.

.DESCRIPTION
    Vérifie l'état complet d'Active Directory incluant
    la réplication, les services, FSMO, DNS et plus.

.PARAMETER DomainController
    DC spécifique à vérifier. Par défaut, tous les DC.

.PARAMETER SkipReplication
    Ne pas vérifier la réplication (plus rapide).

.PARAMETER Detailed
    Afficher les détails de chaque vérification.

.EXAMPLE
    .\Test-ADHealth.ps1
    Vérifie tous les DC du domaine.

.EXAMPLE
    .\Test-ADHealth.ps1 -DomainController "DC01"
    Vérifie un DC spécifique.

.NOTES
    Author: ShellBook
    Version: 1.0
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$DomainController,

    [Parameter()]
    [switch]$SkipReplication,

    [Parameter()]
    [switch]$Detailed
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

    # Compteurs globaux
    switch ($Status) {
        'Pass' { $script:passed++ }
        'Warn' { $script:warnings++ }
        'Fail' { $script:failed++ }
    }
    $script:total++
}

function Test-DCServices {
    param([string]$DC)

    $services = @(
        @{ Name = 'NTDS'; Display = 'AD Domain Services' }
        @{ Name = 'kdc'; Display = 'Kerberos KDC' }
        @{ Name = 'DNS'; Display = 'DNS Server' }
        @{ Name = 'DFSR'; Display = 'DFS Replication' }
        @{ Name = 'Netlogon'; Display = 'Netlogon' }
        @{ Name = 'W32Time'; Display = 'Windows Time' }
    )

    foreach ($svc in $services) {
        try {
            $service = Get-Service -Name $svc.Name -ComputerName $DC -ErrorAction Stop
            if ($service.Status -eq 'Running') {
                Write-Check -Name "$($svc.Display)" -Status Pass -Message "Running on $DC"
            } else {
                Write-Check -Name "$($svc.Display)" -Status Fail -Message "$($service.Status) on $DC"
            }
        }
        catch {
            Write-Check -Name "$($svc.Display)" -Status Fail -Message "Not found on $DC"
        }
    }
}

function Test-DCConnectivity {
    param([string]$DC)

    # LDAP (389)
    $ldap = Test-NetConnection -ComputerName $DC -Port 389 -WarningAction SilentlyContinue
    if ($ldap.TcpTestSucceeded) {
        Write-Check -Name "LDAP (389)" -Status Pass -Message "$DC"
    } else {
        Write-Check -Name "LDAP (389)" -Status Fail -Message "$DC unreachable"
    }

    # LDAPS (636)
    $ldaps = Test-NetConnection -ComputerName $DC -Port 636 -WarningAction SilentlyContinue
    if ($ldaps.TcpTestSucceeded) {
        Write-Check -Name "LDAPS (636)" -Status Pass -Message "$DC"
    } else {
        Write-Check -Name "LDAPS (636)" -Status Warn -Message "$DC (not configured?)"
    }

    # Kerberos (88)
    $krb = Test-NetConnection -ComputerName $DC -Port 88 -WarningAction SilentlyContinue
    if ($krb.TcpTestSucceeded) {
        Write-Check -Name "Kerberos (88)" -Status Pass -Message "$DC"
    } else {
        Write-Check -Name "Kerberos (88)" -Status Fail -Message "$DC unreachable"
    }

    # DNS (53)
    $dns = Test-NetConnection -ComputerName $DC -Port 53 -WarningAction SilentlyContinue
    if ($dns.TcpTestSucceeded) {
        Write-Check -Name "DNS (53)" -Status Pass -Message "$DC"
    } else {
        Write-Check -Name "DNS (53)" -Status Fail -Message "$DC unreachable"
    }
}

function Test-Replication {
    Write-Host "`n[Réplication AD]" -ForegroundColor Cyan

    try {
        $replStatus = Get-ADReplicationPartnerMetadata -Target * -Partition * -ErrorAction Stop

        $failures = $replStatus | Where-Object { $_.LastReplicationResult -ne 0 }

        if ($failures) {
            foreach ($fail in $failures) {
                Write-Check -Name "Replication $($fail.Partner)" -Status Fail `
                    -Message "Error $($fail.LastReplicationResult)"
            }
        } else {
            Write-Check -Name "Réplication inter-DC" -Status Pass -Message "All partitions OK"
        }

        # Vérifier l'âge de la dernière réplication
        $oldReplications = $replStatus | Where-Object {
            $_.LastReplicationSuccess -lt (Get-Date).AddHours(-2)
        }

        if ($oldReplications) {
            Write-Check -Name "Réplication récente" -Status Warn `
                -Message "$($oldReplications.Count) partenaires > 2h"
        } else {
            Write-Check -Name "Réplication récente" -Status Pass -Message "< 2h pour tous"
        }
    }
    catch {
        Write-Check -Name "Réplication" -Status Fail -Message $_.Exception.Message
    }

    # DCDiag replication test
    try {
        $dcdiag = dcdiag /test:replications /q 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Check -Name "DCDiag Replications" -Status Pass
        } else {
            Write-Check -Name "DCDiag Replications" -Status Warn -Message "Issues detected"
        }
    }
    catch {
        Write-Check -Name "DCDiag Replications" -Status Warn -Message "Could not run dcdiag"
    }
}

function Test-FSMORoles {
    Write-Host "`n[FSMO Roles]" -ForegroundColor Cyan

    try {
        $forest = Get-ADForest
        $domain = Get-ADDomain

        $fsmoRoles = @(
            @{ Name = 'Schema Master'; Holder = $forest.SchemaMaster }
            @{ Name = 'Domain Naming Master'; Holder = $forest.DomainNamingMaster }
            @{ Name = 'PDC Emulator'; Holder = $domain.PDCEmulator }
            @{ Name = 'RID Master'; Holder = $domain.RIDMaster }
            @{ Name = 'Infrastructure Master'; Holder = $domain.InfrastructureMaster }
        )

        foreach ($role in $fsmoRoles) {
            # Vérifier que le DC holder est accessible
            if (Test-Connection -ComputerName $role.Holder -Count 1 -Quiet) {
                Write-Check -Name $role.Name -Status Pass -Message $role.Holder
            } else {
                Write-Check -Name $role.Name -Status Fail -Message "$($role.Holder) unreachable!"
            }
        }
    }
    catch {
        Write-Check -Name "FSMO Roles" -Status Fail -Message $_.Exception.Message
    }
}

function Test-SysvolNetlogon {
    param([string]$DC)

    Write-Host "`n[Sysvol & Netlogon - $DC]" -ForegroundColor Cyan

    # Test Sysvol
    $sysvolPath = "\\$DC\SYSVOL"
    if (Test-Path $sysvolPath) {
        Write-Check -Name "Sysvol share" -Status Pass -Message $sysvolPath
    } else {
        Write-Check -Name "Sysvol share" -Status Fail -Message "$sysvolPath inaccessible"
    }

    # Test Netlogon
    $netlogonPath = "\\$DC\NETLOGON"
    if (Test-Path $netlogonPath) {
        Write-Check -Name "Netlogon share" -Status Pass -Message $netlogonPath
    } else {
        Write-Check -Name "Netlogon share" -Status Fail -Message "$netlogonPath inaccessible"
    }

    # Vérifier le contenu Sysvol
    $domainName = (Get-ADDomain).DNSRoot
    $policiesPath = "\\$DC\SYSVOL\$domainName\Policies"
    if (Test-Path $policiesPath) {
        $gpoCount = (Get-ChildItem $policiesPath -Directory).Count
        Write-Check -Name "GPO Policies folder" -Status Pass -Message "$gpoCount GPOs found"
    } else {
        Write-Check -Name "GPO Policies folder" -Status Warn -Message "Cannot access"
    }
}

function Test-DNSHealth {
    param([string]$DC)

    Write-Host "`n[DNS AD-Integrated - $DC]" -ForegroundColor Cyan

    try {
        # Vérifier zones DNS
        $zones = Get-DnsServerZone -ComputerName $DC -ErrorAction Stop |
            Where-Object { $_.ZoneType -eq 'Primary' -and $_.IsDsIntegrated }

        Write-Check -Name "AD-Integrated Zones" -Status Pass -Message "$($zones.Count) zones"

        # Vérifier _msdcs
        $msdcsZone = $zones | Where-Object { $_.ZoneName -like "_msdcs.*" }
        if ($msdcsZone) {
            Write-Check -Name "_msdcs zone" -Status Pass
        } else {
            Write-Check -Name "_msdcs zone" -Status Warn -Message "Not found"
        }

        # Vérifier les SRV records
        $domainName = (Get-ADDomain).DNSRoot
        $srvRecords = Resolve-DnsName -Name "_ldap._tcp.dc._msdcs.$domainName" -Type SRV -Server $DC -ErrorAction Stop
        Write-Check -Name "DC SRV records" -Status Pass -Message "$($srvRecords.Count) records"
    }
    catch {
        Write-Check -Name "DNS Health" -Status Warn -Message $_.Exception.Message
    }
}

function Test-DCDiskSpace {
    param([string]$DC)

    Write-Host "`n[Espace Disque - $DC]" -ForegroundColor Cyan

    try {
        $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $DC `
            -Filter "DriveType=3" -ErrorAction Stop

        foreach ($disk in $disks) {
            $freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 1)
            $freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)

            if ($freePercent -lt 10) {
                Write-Check -Name "Disk $($disk.DeviceID)" -Status Fail `
                    -Message "$freeGB GB free ($freePercent%)"
            } elseif ($freePercent -lt 20) {
                Write-Check -Name "Disk $($disk.DeviceID)" -Status Warn `
                    -Message "$freeGB GB free ($freePercent%)"
            } else {
                Write-Check -Name "Disk $($disk.DeviceID)" -Status Pass `
                    -Message "$freeGB GB free ($freePercent%)"
            }
        }

        # Vérifier taille NTDS
        $ntdsPath = Invoke-Command -ComputerName $DC -ScriptBlock {
            (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters").'DSA Database file'
        } -ErrorAction SilentlyContinue

        if ($ntdsPath) {
            $ntdsSize = Invoke-Command -ComputerName $DC -ScriptBlock {
                param($path)
                (Get-Item $path).Length / 1GB
            } -ArgumentList $ntdsPath -ErrorAction SilentlyContinue

            Write-Check -Name "NTDS.dit size" -Status Info `
                -Message "$([math]::Round($ntdsSize, 2)) GB"
        }
    }
    catch {
        Write-Check -Name "Disk space check" -Status Warn -Message $_.Exception.Message
    }
}

function Test-DCCertificates {
    param([string]$DC)

    Write-Host "`n[Certificats DC - $DC]" -ForegroundColor Cyan

    try {
        $certs = Invoke-Command -ComputerName $DC -ScriptBlock {
            Get-ChildItem Cert:\LocalMachine\My |
                Where-Object { $_.Subject -like "*$env:COMPUTERNAME*" -or $_.DnsNameList -contains $env:COMPUTERNAME }
        } -ErrorAction Stop

        foreach ($cert in $certs) {
            $daysToExpiry = ($cert.NotAfter - (Get-Date)).Days

            if ($daysToExpiry -lt 0) {
                Write-Check -Name "Cert: $($cert.Subject.Substring(0,30))" -Status Fail `
                    -Message "EXPIRED"
            } elseif ($daysToExpiry -lt 30) {
                Write-Check -Name "Cert: $($cert.Subject.Substring(0,30))" -Status Warn `
                    -Message "Expires in $daysToExpiry days"
            } else {
                Write-Check -Name "Cert: $($cert.Subject.Substring(0,30))" -Status Pass `
                    -Message "Valid for $daysToExpiry days"
            }
        }
    }
    catch {
        Write-Check -Name "Certificate check" -Status Warn -Message "Could not retrieve"
    }
}
#endregion

#region Main
# Compteurs
$script:total = 0
$script:passed = 0
$script:warnings = 0
$script:failed = 0

Write-Host ""
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  ACTIVE DIRECTORY HEALTH CHECK" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan
Write-Host "  Domain: $((Get-ADDomain).DNSRoot)"
Write-Host "  Forest: $((Get-ADForest).Name)"
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ("-" * 70) -ForegroundColor Cyan

# Obtenir les DC à vérifier
if ($DomainController) {
    $dcs = @($DomainController)
} else {
    $dcs = (Get-ADDomainController -Filter *).HostName
}

Write-Host "  Domain Controllers: $($dcs.Count)"
Write-Host ("-" * 70) -ForegroundColor Cyan

# FSMO Roles (une seule fois)
Test-FSMORoles

# Réplication (une seule fois)
if (-not $SkipReplication) {
    Test-Replication
}

# Tests par DC
foreach ($dc in $dcs) {
    Write-Host "`n" + ("=" * 70) -ForegroundColor Magenta
    Write-Host "  DC: $dc" -ForegroundColor Magenta
    Write-Host ("=" * 70) -ForegroundColor Magenta

    Write-Host "`n[Connectivité]" -ForegroundColor Cyan
    Test-DCConnectivity -DC $dc

    Write-Host "`n[Services AD]" -ForegroundColor Cyan
    Test-DCServices -DC $dc

    Test-SysvolNetlogon -DC $dc
    Test-DNSHealth -DC $dc
    Test-DCDiskSpace -DC $dc
    Test-DCCertificates -DC $dc
}

# ═══════════════════════════════════════════════════════════════════
# RÉSUMÉ
# ═══════════════════════════════════════════════════════════════════
Write-Host "`n" + ("=" * 70) -ForegroundColor Cyan
Write-Host "  RÉSUMÉ GLOBAL" -ForegroundColor Green
Write-Host ("=" * 70) -ForegroundColor Cyan

Write-Host "  Total checks: $script:total"
Write-Host "    - " -NoNewline
Write-Host "Passed: $script:passed" -ForegroundColor Green
Write-Host "    - " -NoNewline
Write-Host "Warnings: $script:warnings" -ForegroundColor Yellow
Write-Host "    - " -NoNewline
Write-Host "Failed: $script:failed" -ForegroundColor Red

Write-Host ""
if ($script:failed -gt 0) {
    Write-Host "  AD STATUS: CRITICAL" -ForegroundColor Red
    exit 2
} elseif ($script:warnings -gt 0) {
    Write-Host "  AD STATUS: DEGRADED" -ForegroundColor Yellow
    exit 1
} else {
    Write-Host "  AD STATUS: HEALTHY" -ForegroundColor Green
    exit 0
}
#endregion
```

---

## Utilisation

```powershell
# Vérifier tous les DC
.\Test-ADHealth.ps1

# Vérifier un DC spécifique
.\Test-ADHealth.ps1 -DomainController "DC01.domain.local"

# Sans vérification de réplication (plus rapide)
.\Test-ADHealth.ps1 -SkipReplication

# Mode détaillé
.\Test-ADHealth.ps1 -Detailed
```

---

## Sortie Exemple

```
======================================================================
  ACTIVE DIRECTORY HEALTH CHECK
======================================================================
  Domain: corp.contoso.com
  Forest: contoso.com
  Date: 2024-01-15 14:30:22
----------------------------------------------------------------------
  Domain Controllers: 3
----------------------------------------------------------------------

[FSMO Roles]
[OK]   Schema Master - DC01.corp.contoso.com
[OK]   Domain Naming Master - DC01.corp.contoso.com
[OK]   PDC Emulator - DC01.corp.contoso.com
[OK]   RID Master - DC01.corp.contoso.com
[OK]   Infrastructure Master - DC02.corp.contoso.com

[Réplication AD]
[OK]   Réplication inter-DC - All partitions OK
[OK]   Réplication récente - < 2h pour tous
[OK]   DCDiag Replications

======================================================================
  DC: DC01.corp.contoso.com
======================================================================

[Connectivité]
[OK]   LDAP (389) - DC01.corp.contoso.com
[OK]   LDAPS (636) - DC01.corp.contoso.com
[OK]   Kerberos (88) - DC01.corp.contoso.com
[OK]   DNS (53) - DC01.corp.contoso.com

[Services AD]
[OK]   AD Domain Services - Running on DC01
[OK]   Kerberos KDC - Running on DC01
[OK]   DNS Server - Running on DC01
[OK]   DFS Replication - Running on DC01
[OK]   Netlogon - Running on DC01
[OK]   Windows Time - Running on DC01

[Sysvol & Netlogon - DC01]
[OK]   Sysvol share - \\DC01\SYSVOL
[OK]   Netlogon share - \\DC01\NETLOGON
[OK]   GPO Policies folder - 45 GPOs found

======================================================================
  RÉSUMÉ GLOBAL
======================================================================
  Total checks: 52
    - Passed: 50
    - Warnings: 2
    - Failed: 0

  AD STATUS: DEGRADED
```

---

## Voir Aussi

- [Test-WSUSHealth.ps1](Test-WSUSHealth.md)
- [Test-DNSServer.ps1](Test-DNSServer.md)
