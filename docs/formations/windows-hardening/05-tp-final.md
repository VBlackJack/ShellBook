---
tags:
  - formation
  - windows
  - securite
  - hardening
  - tp
---

# Module 5 : TP Final - Audit et Remédiation

## Objectifs du TP

- Réaliser un audit de sécurité complet
- Identifier les écarts avec les baselines
- Appliquer les remédiations
- Documenter et reporter

**Durée :** 2 heures

---

## Contexte

Vous êtes missionné pour auditer et sécuriser un serveur Windows Server 2022 nouvellement déployé. Le serveur hébergera une application métier critique et doit respecter les standards CIS Level 1.

---

## Partie 1 : Audit Initial (30 min)

### 1.1 Script d'Audit Complet

```powershell
# audit-windows-hardening.ps1
# Audit complet de la sécurité Windows

$Results = @()
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ComputerName = $env:COMPUTERNAME

Write-Host "=== AUDIT SECURITE WINDOWS ===" -ForegroundColor Cyan
Write-Host "Serveur: $ComputerName"
Write-Host "Date: $Timestamp"
Write-Host ""

# ═══════════════════════════════════════════════════════════════
# 1. SERVICES
# ═══════════════════════════════════════════════════════════════
Write-Host "[1/7] Audit des services..." -ForegroundColor Yellow

$DangerousServices = @("RemoteRegistry", "Fax", "XblAuthManager", "XblGameSave")
foreach ($svc in $DangerousServices) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        $Results += [PSCustomObject]@{
            Category = "Services"
            Check = "$svc should be disabled"
            Status = "FAIL"
            Current = "Running"
            Expected = "Disabled"
        }
    } else {
        $Results += [PSCustomObject]@{
            Category = "Services"
            Check = "$svc disabled"
            Status = "PASS"
            Current = "Stopped/Disabled"
            Expected = "Disabled"
        }
    }
}

# ═══════════════════════════════════════════════════════════════
# 2. PROTOCOLES (SMB, RDP)
# ═══════════════════════════════════════════════════════════════
Write-Host "[2/7] Audit des protocoles..." -ForegroundColor Yellow

# SMBv1
$SMB1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
$Results += [PSCustomObject]@{
    Category = "Protocols"
    Check = "SMBv1 Disabled"
    Status = if ($SMB1.State -eq "Disabled") { "PASS" } else { "FAIL" }
    Current = $SMB1.State
    Expected = "Disabled"
}

# SMB Signing
$SMBConfig = Get-SmbServerConfiguration
$Results += [PSCustomObject]@{
    Category = "Protocols"
    Check = "SMB Signing Required"
    Status = if ($SMBConfig.RequireSecuritySignature) { "PASS" } else { "FAIL" }
    Current = $SMBConfig.RequireSecuritySignature
    Expected = "True"
}

# NLA for RDP
$NLA = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue).UserAuthentication
$Results += [PSCustomObject]@{
    Category = "Protocols"
    Check = "RDP NLA Enabled"
    Status = if ($NLA -eq 1) { "PASS" } else { "FAIL" }
    Current = $NLA
    Expected = "1"
}

# ═══════════════════════════════════════════════════════════════
# 3. FIREWALL
# ═══════════════════════════════════════════════════════════════
Write-Host "[3/7] Audit du firewall..." -ForegroundColor Yellow

$FWProfiles = Get-NetFirewallProfile
foreach ($profile in $FWProfiles) {
    $Results += [PSCustomObject]@{
        Category = "Firewall"
        Check = "Firewall $($profile.Name) Enabled"
        Status = if ($profile.Enabled) { "PASS" } else { "FAIL" }
        Current = $profile.Enabled
        Expected = "True"
    }
}

# ═══════════════════════════════════════════════════════════════
# 4. COMPTES
# ═══════════════════════════════════════════════════════════════
Write-Host "[4/7] Audit des comptes..." -ForegroundColor Yellow

# Guest Account
$Guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
$Results += [PSCustomObject]@{
    Category = "Accounts"
    Check = "Guest Account Disabled"
    Status = if ($Guest.Enabled -eq $false) { "PASS" } else { "FAIL" }
    Current = $Guest.Enabled
    Expected = "False"
}

# Administrator renamed
$Admin = Get-LocalUser | Where-Object { $_.SID -like "*-500" }
$Results += [PSCustomObject]@{
    Category = "Accounts"
    Check = "Administrator Renamed"
    Status = if ($Admin.Name -ne "Administrator") { "PASS" } else { "WARN" }
    Current = $Admin.Name
    Expected = "Not 'Administrator'"
}

# ═══════════════════════════════════════════════════════════════
# 5. WINDOWS DEFENDER
# ═══════════════════════════════════════════════════════════════
Write-Host "[5/7] Audit Windows Defender..." -ForegroundColor Yellow

$Defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($Defender) {
    $Results += [PSCustomObject]@{
        Category = "Defender"
        Check = "Real-Time Protection"
        Status = if ($Defender.RealTimeProtectionEnabled) { "PASS" } else { "FAIL" }
        Current = $Defender.RealTimeProtectionEnabled
        Expected = "True"
    }
    $Results += [PSCustomObject]@{
        Category = "Defender"
        Check = "Antivirus Signatures Updated"
        Status = if ($Defender.AntivirusSignatureAge -lt 7) { "PASS" } else { "WARN" }
        Current = "$($Defender.AntivirusSignatureAge) days old"
        Expected = "< 7 days"
    }
}

# ═══════════════════════════════════════════════════════════════
# 6. POWERSHELL
# ═══════════════════════════════════════════════════════════════
Write-Host "[6/7] Audit PowerShell..." -ForegroundColor Yellow

$PSLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
$Results += [PSCustomObject]@{
    Category = "PowerShell"
    Check = "Script Block Logging"
    Status = if ($PSLogging.EnableScriptBlockLogging -eq 1) { "PASS" } else { "FAIL" }
    Current = $PSLogging.EnableScriptBlockLogging
    Expected = "1"
}

# ═══════════════════════════════════════════════════════════════
# 7. AUDIT POLICY
# ═══════════════════════════════════════════════════════════════
Write-Host "[7/7] Audit des politiques d'audit..." -ForegroundColor Yellow

$AuditLogon = auditpol /get /subcategory:"Logon" 2>$null | Select-String "Success and Failure"
$Results += [PSCustomObject]@{
    Category = "Audit"
    Check = "Logon Auditing"
    Status = if ($AuditLogon) { "PASS" } else { "FAIL" }
    Current = if ($AuditLogon) { "Success and Failure" } else { "Incomplete" }
    Expected = "Success and Failure"
}

# ═══════════════════════════════════════════════════════════════
# RAPPORT
# ═══════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "=== RESULTATS ===" -ForegroundColor Cyan

$Results | Format-Table -AutoSize

# Résumé
$Passed = ($Results | Where-Object Status -eq "PASS").Count
$Failed = ($Results | Where-Object Status -eq "FAIL").Count
$Warnings = ($Results | Where-Object Status -eq "WARN").Count
$Total = $Results.Count

Write-Host ""
Write-Host "SCORE: $Passed/$Total PASS" -ForegroundColor $(if ($Failed -eq 0) { "Green" } else { "Yellow" })
Write-Host "  - PASS: $Passed" -ForegroundColor Green
Write-Host "  - FAIL: $Failed" -ForegroundColor Red
Write-Host "  - WARN: $Warnings" -ForegroundColor Yellow

# Export
$Results | Export-Csv "C:\Audit\audit-$ComputerName-$(Get-Date -Format 'yyyyMMdd').csv" -NoTypeInformation
Write-Host ""
Write-Host "Rapport exporté vers C:\Audit\" -ForegroundColor Cyan
```

### 1.2 Exécuter l'Audit

```powershell
# Créer le répertoire d'audit
New-Item -Path "C:\Audit" -ItemType Directory -Force

# Exécuter le script
.\audit-windows-hardening.ps1

# Analyser les résultats
$AuditResults = Import-Csv "C:\Audit\audit-*.csv"
$AuditResults | Where-Object Status -eq "FAIL" | Format-Table
```

---

## Partie 2 : Remédiation (45 min)

### 2.1 Script de Remédiation

```powershell
# remediate-windows-hardening.ps1
param(
    [switch]$WhatIf,
    [switch]$Force
)

$Remediations = @()

Write-Host "=== REMEDIATION SECURITE WINDOWS ===" -ForegroundColor Cyan

# ═══════════════════════════════════════════════════════════════
# 1. DESACTIVER LES SERVICES INUTILES
# ═══════════════════════════════════════════════════════════════
Write-Host "[1/6] Désactivation des services..." -ForegroundColor Yellow

$ServicesToDisable = @("RemoteRegistry", "Fax", "XblAuthManager", "XblGameSave", "XboxNetApiSvc")
foreach ($svc in $ServicesToDisable) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        if ($WhatIf) {
            Write-Host "  [WHATIF] Would disable $svc"
        } else {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled
            $Remediations += "Disabled service: $svc"
            Write-Host "  [OK] Disabled $svc" -ForegroundColor Green
        }
    }
}

# ═══════════════════════════════════════════════════════════════
# 2. SECURISER SMB
# ═══════════════════════════════════════════════════════════════
Write-Host "[2/6] Sécurisation SMB..." -ForegroundColor Yellow

# Désactiver SMBv1
$SMB1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
if ($SMB1.State -ne "Disabled") {
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would disable SMBv1"
    } else {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
        $Remediations += "Disabled SMBv1"
        Write-Host "  [OK] SMBv1 disabled" -ForegroundColor Green
    }
}

# Activer SMB Signing
$SMBConfig = Get-SmbServerConfiguration
if (-not $SMBConfig.RequireSecuritySignature) {
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would enable SMB Signing"
    } else {
        Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
        $Remediations += "Enabled SMB Signing"
        Write-Host "  [OK] SMB Signing enabled" -ForegroundColor Green
    }
}

# ═══════════════════════════════════════════════════════════════
# 3. SECURISER RDP
# ═══════════════════════════════════════════════════════════════
Write-Host "[3/6] Sécurisation RDP..." -ForegroundColor Yellow

$NLA = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
if ($NLA -ne 1) {
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would enable NLA"
    } else {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name "UserAuthentication" -Value 1
        $Remediations += "Enabled NLA for RDP"
        Write-Host "  [OK] NLA enabled" -ForegroundColor Green
    }
}

# ═══════════════════════════════════════════════════════════════
# 4. FIREWALL
# ═══════════════════════════════════════════════════════════════
Write-Host "[4/6] Configuration Firewall..." -ForegroundColor Yellow

$FWProfiles = Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }
foreach ($profile in $FWProfiles) {
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would enable Firewall $($profile.Name)"
    } else {
        Set-NetFirewallProfile -Profile $profile.Name -Enabled True
        $Remediations += "Enabled Firewall: $($profile.Name)"
        Write-Host "  [OK] Firewall $($profile.Name) enabled" -ForegroundColor Green
    }
}

# Activer le logging
Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked True -LogFileName "%systemroot%\system32\LogFiles\Firewall\pfirewall.log"

# ═══════════════════════════════════════════════════════════════
# 5. COMPTES
# ═══════════════════════════════════════════════════════════════
Write-Host "[5/6] Sécurisation des comptes..." -ForegroundColor Yellow

# Désactiver Guest
$Guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
if ($Guest -and $Guest.Enabled) {
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would disable Guest account"
    } else {
        Disable-LocalUser -Name "Guest"
        $Remediations += "Disabled Guest account"
        Write-Host "  [OK] Guest account disabled" -ForegroundColor Green
    }
}

# ═══════════════════════════════════════════════════════════════
# 6. POWERSHELL LOGGING
# ═══════════════════════════════════════════════════════════════
Write-Host "[6/6] Configuration PowerShell Logging..." -ForegroundColor Yellow

$PSLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $PSLogPath)) {
    if ($WhatIf) {
        Write-Host "  [WHATIF] Would enable PowerShell logging"
    } else {
        New-Item -Path $PSLogPath -Force | Out-Null
        Set-ItemProperty -Path $PSLogPath -Name "EnableScriptBlockLogging" -Value 1
        $Remediations += "Enabled PowerShell Script Block Logging"
        Write-Host "  [OK] PowerShell logging enabled" -ForegroundColor Green
    }
}

# ═══════════════════════════════════════════════════════════════
# RAPPORT
# ═══════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "=== REMEDIATIONS APPLIQUEES ===" -ForegroundColor Cyan
$Remediations | ForEach-Object { Write-Host "  - $_" }
Write-Host ""
Write-Host "Total: $($Remediations.Count) remédiations" -ForegroundColor Green

if (-not $WhatIf) {
    Write-Host ""
    Write-Host "ATTENTION: Un redémarrage peut être nécessaire pour SMBv1" -ForegroundColor Yellow
}
```

### 2.2 Exécuter la Remédiation

```powershell
# Mode test (WhatIf)
.\remediate-windows-hardening.ps1 -WhatIf

# Appliquer les remédiations
.\remediate-windows-hardening.ps1

# Vérifier avec un nouvel audit
.\audit-windows-hardening.ps1
```

---

## Partie 3 : Documentation (30 min)

### 3.1 Générer le Rapport Final

```powershell
# generate-report.ps1
$ReportPath = "C:\Audit\Report-$(Get-Date -Format 'yyyyMMdd').html"

$HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>Rapport Hardening Windows - $env:COMPUTERNAME</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #4CAF50; color: white; }
        .pass { background-color: #c8e6c9; }
        .fail { background-color: #ffcdd2; }
        .warn { background-color: #fff9c4; }
        .summary { margin: 20px 0; padding: 15px; background-color: #e3f2fd; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Rapport de Sécurité - $env:COMPUTERNAME</h1>
    <p>Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>

    <div class="summary">
        <h2>Résumé</h2>
        <p>Baseline appliquée: CIS Windows Server 2022 Level 1</p>
        <p>Score de conformité: <strong>XX%</strong></p>
    </div>

    <h2>Résultats détaillés</h2>
    <table>
        <tr>
            <th>Catégorie</th>
            <th>Contrôle</th>
            <th>Statut</th>
            <th>Valeur actuelle</th>
            <th>Valeur attendue</th>
        </tr>
        <!-- Insérer les résultats ici -->
    </table>

    <h2>Remédiations appliquées</h2>
    <ul>
        <!-- Liste des remédiations -->
    </ul>

    <h2>Exceptions documentées</h2>
    <ul>
        <li>Aucune exception pour ce serveur</li>
    </ul>

    <h2>Recommandations</h2>
    <ul>
        <li>Planifier un audit mensuel</li>
        <li>Activer le monitoring SIEM</li>
        <li>Former les administrateurs au Tiering Model</li>
    </ul>
</body>
</html>
"@

$HTML | Out-File $ReportPath -Encoding UTF8
Write-Host "Rapport généré: $ReportPath"
```

---

## Partie 4 : Validation (15 min)

### Checklist Finale

```powershell
# checklist-validation.ps1
$Checklist = @(
    @{Item="SMBv1 désactivé"; Check={(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State -eq "Disabled"}},
    @{Item="SMB Signing activé"; Check={(Get-SmbServerConfiguration).RequireSecuritySignature}},
    @{Item="NLA RDP activé"; Check={(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -eq 1}},
    @{Item="Firewall Domain actif"; Check={(Get-NetFirewallProfile -Profile Domain).Enabled}},
    @{Item="Firewall Private actif"; Check={(Get-NetFirewallProfile -Profile Private).Enabled}},
    @{Item="Firewall Public actif"; Check={(Get-NetFirewallProfile -Profile Public).Enabled}},
    @{Item="Guest désactivé"; Check={-not (Get-LocalUser -Name Guest).Enabled}},
    @{Item="RemoteRegistry désactivé"; Check={(Get-Service RemoteRegistry).Status -ne "Running"}},
    @{Item="PowerShell Logging"; Check={(Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1}},
    @{Item="Windows Defender actif"; Check={(Get-MpComputerStatus).RealTimeProtectionEnabled}}
)

Write-Host "=== VALIDATION FINALE ===" -ForegroundColor Cyan
$AllPassed = $true

foreach ($item in $Checklist) {
    $result = & $item.Check
    $status = if ($result) { "[OK]" } else { "[FAIL]"; $AllPassed = $false }
    $color = if ($result) { "Green" } else { "Red" }
    Write-Host "$status $($item.Item)" -ForegroundColor $color
}

Write-Host ""
if ($AllPassed) {
    Write-Host "VALIDATION REUSSIE - Serveur conforme" -ForegroundColor Green
} else {
    Write-Host "VALIDATION ECHOUEE - Corrections nécessaires" -ForegroundColor Red
}
```

---

## Livrables Attendus

1. **Rapport d'audit initial** (CSV)
2. **Script de remédiation** exécuté
3. **Rapport d'audit final** (CSV)
4. **Rapport HTML** de conformité
5. **Checklist de validation** passée

---

## Critères d'Évaluation

| Critère | Points |
|---------|--------|
| Audit initial complet | 20 |
| Remédiations appliquées | 30 |
| Documentation | 20 |
| Validation finale | 20 |
| Scripts réutilisables | 10 |
| **Total** | **100** |

---

**Précédent :** [Module 4 - Active Directory](04-module.md)

**Retour au :** [Programme de la Formation](index.md)
