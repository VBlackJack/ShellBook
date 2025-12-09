---
tags:
  - formation
  - windows
  - securite
  - hardening
  - baselines
---

# Module 1 : Security Baselines

## Objectifs du Module

- Comprendre les frameworks de sécurité (CIS, ANSSI, Microsoft)
- Appliquer les Security Baselines avec LGPO
- Comparer et personnaliser les baselines
- Automatiser le déploiement

**Durée :** 2 heures

---

## 1. Frameworks de Sécurité

### 1.1 Vue d'Ensemble

```text
FRAMEWORKS DE SECURITE WINDOWS
══════════════════════════════

┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   CIS Benchmark │  │ Microsoft SCT   │  │     ANSSI       │
│                 │  │                 │  │                 │
│ - Level 1 (L1)  │  │ - Windows 11    │  │ - AD Tiering    │
│ - Level 2 (L2)  │  │ - Server 2022   │  │ - Recommandations│
│ - Scored/Not    │  │ - Office 365    │  │ - Guides FR     │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                   │                    │
         └───────────────────┼────────────────────┘
                             ▼
                   ┌─────────────────┐
                   │   GPO / LGPO    │
                   │   Déploiement   │
                   └─────────────────┘
```

### 1.2 CIS Benchmarks

```powershell
# Niveaux CIS
# Level 1 (L1) : Sécurité de base, impact minimal
# Level 2 (L2) : Sécurité renforcée, peut impacter fonctionnalités

# Exemples de contrôles L1
# - Politique de mots de passe
# - Verrouillage de compte
# - Audit de base

# Exemples de contrôles L2
# - Désactivation SMBv1
# - Restrictions PowerShell
# - AppLocker
```

### 1.3 Microsoft Security Compliance Toolkit

```powershell
# Télécharger SCT
# https://www.microsoft.com/download/details.aspx?id=55319

# Contenu du toolkit
# - LGPO.exe : Applique les GPO localement
# - PolicyAnalyzer : Compare les configurations
# - Baselines : GPO préconfigurées par OS

# Structure des baselines
<#
Windows Server 2022 Security Baseline/
├── Documentation/
│   └── Server 2022 Security Baseline.xlsx
├── GP Reports/
│   └── *.htm
├── GPOs/
│   ├── {GUID}/
│   │   ├── Machine/
│   │   └── User/
└── Scripts/
    └── Baseline-LocalInstall.ps1
#>
```

---

## 2. Installation et Configuration

### 2.1 Téléchargement des Outils

```powershell
# Créer le répertoire de travail
$BaseDir = "C:\Security\Baselines"
New-Item -Path $BaseDir -ItemType Directory -Force

# Télécharger LGPO (depuis SCT)
# Manuel : https://www.microsoft.com/download/details.aspx?id=55319

# Vérifier LGPO
& "$BaseDir\LGPO.exe" /h
```

### 2.2 Structure des Baselines

```powershell
# Organisation recommandée
<#
C:\Security\
├── Baselines\
│   ├── CIS\
│   │   ├── Windows_Server_2022_L1.zip
│   │   └── Windows_Server_2022_L2.zip
│   ├── Microsoft\
│   │   ├── Server2022\
│   │   └── Windows11\
│   └── Custom\
│       └── Corp_Baseline\
├── Tools\
│   ├── LGPO.exe
│   └── PolicyAnalyzer\
├── Reports\
└── Scripts\
#>
```

---

## 3. Application des Baselines

### 3.1 Avec LGPO

```powershell
# Backup de la configuration actuelle
$BackupPath = "C:\Security\Backup\$(Get-Date -Format 'yyyyMMdd')"
New-Item -Path $BackupPath -ItemType Directory -Force
& LGPO.exe /b $BackupPath

# Appliquer une baseline Microsoft
$BaselinePath = "C:\Security\Baselines\Microsoft\Server2022\GPOs\{GUID}"
& LGPO.exe /g $BaselinePath

# Appliquer depuis un fichier .pol
& LGPO.exe /m "C:\Path\To\Machine\registry.pol"
& LGPO.exe /u "C:\Path\To\User\registry.pol"

# Forcer la mise à jour
gpupdate /force
```

### 3.2 Script d'Application Automatisé

```powershell
# apply-baseline.ps1
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("CIS-L1", "CIS-L2", "Microsoft", "Custom")]
    [string]$Baseline,

    [switch]$Backup,
    [switch]$WhatIf
)

$BaseDir = "C:\Security\Baselines"
$LGPOPath = "C:\Security\Tools\LGPO.exe"

# Mapping des baselines
$BaselinePaths = @{
    "CIS-L1"    = "$BaseDir\CIS\Server2022_L1\GPOs"
    "CIS-L2"    = "$BaseDir\CIS\Server2022_L2\GPOs"
    "Microsoft" = "$BaseDir\Microsoft\Server2022\GPOs"
    "Custom"    = "$BaseDir\Custom\Corp\GPOs"
}

# Backup si demandé
if ($Backup) {
    $BackupPath = "C:\Security\Backup\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -Path $BackupPath -ItemType Directory -Force
    Write-Host "[INFO] Backup vers $BackupPath"
    & $LGPOPath /b $BackupPath
}

# Appliquer la baseline
$GPOPath = $BaselinePaths[$Baseline]

if ($WhatIf) {
    Write-Host "[WHATIF] Appliquerait: $GPOPath"
} else {
    Write-Host "[INFO] Application de $Baseline..."
    Get-ChildItem -Path $GPOPath -Directory | ForEach-Object {
        Write-Host "  - Applying: $($_.Name)"
        & $LGPOPath /g $_.FullName
    }
    gpupdate /force
    Write-Host "[OK] Baseline $Baseline appliquée"
}
```

---

## 4. Personnalisation

### 4.1 Créer une Baseline Custom

```powershell
# Exporter la config actuelle en baseline
$ExportPath = "C:\Security\Baselines\Custom\Corp_Baseline"
New-Item -Path $ExportPath -ItemType Directory -Force

# Backup GPO locale
& LGPO.exe /b $ExportPath

# Structure créée
<#
Corp_Baseline/
├── {GUID}/
│   ├── DomainSysvol/
│   │   └── GPO/
│   │       ├── Machine/
│   │       │   └── registry.pol
│   │       └── User/
│   │           └── registry.pol
│   └── GPT.ini
└── gpreport.xml
#>
```

### 4.2 Modifier avec Policy Analyzer

```powershell
# Policy Analyzer permet de :
# - Comparer 2 baselines
# - Identifier les différences
# - Exporter en Excel

# Lancer Policy Analyzer
& "C:\Security\Tools\PolicyAnalyzer\PolicyAnalyzer.exe"

# Comparaison en ligne de commande (PowerShell)
# Comparer 2 fichiers registry.pol
function Compare-RegistryPol {
    param(
        [string]$Baseline1,
        [string]$Baseline2
    )

    # Utiliser LGPO pour parser
    $temp1 = [System.IO.Path]::GetTempFileName()
    $temp2 = [System.IO.Path]::GetTempFileName()

    & LGPO.exe /parse /m $Baseline1 > $temp1
    & LGPO.exe /parse /m $Baseline2 > $temp2

    Compare-Object (Get-Content $temp1) (Get-Content $temp2)

    Remove-Item $temp1, $temp2
}
```

### 4.3 Exceptions Documentées

```powershell
# exceptions.json - Documenter les écarts
$Exceptions = @{
    "CIS-2.3.1.1" = @{
        Control = "Accounts: Administrator account status"
        Baseline = "Disabled"
        Current = "Enabled"
        Justification = "Requis pour Break Glass procedure"
        ApprovedBy = "CISO"
        Date = "2024-01-15"
        ReviewDate = "2024-07-15"
    }
    "CIS-18.9.102.1" = @{
        Control = "Windows Defender SmartScreen"
        Baseline = "Enabled"
        Current = "Disabled"
        Justification = "Conflit avec solution EDR CrowdStrike"
        ApprovedBy = "Security Team"
        Date = "2024-02-01"
        ReviewDate = "2024-08-01"
    }
}

# Exporter
$Exceptions | ConvertTo-Json -Depth 3 | Out-File "C:\Security\exceptions.json"
```

---

## 5. Vérification et Audit

### 5.1 Script d'Audit Rapide

```powershell
# audit-baseline.ps1
function Test-SecurityBaseline {
    $Results = @()

    # Password Policy
    $PasswordPolicy = Get-ADDefaultDomainPasswordPolicy -ErrorAction SilentlyContinue
    if ($PasswordPolicy) {
        $Results += [PSCustomObject]@{
            Check = "Min Password Length >= 14"
            Expected = "14"
            Actual = $PasswordPolicy.MinPasswordLength
            Status = if ($PasswordPolicy.MinPasswordLength -ge 14) { "PASS" } else { "FAIL" }
        }
    }

    # SMBv1
    $SMB1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
    $Results += [PSCustomObject]@{
        Check = "SMBv1 Disabled"
        Expected = "Disabled"
        Actual = $SMB1.State
        Status = if ($SMB1.State -eq "Disabled") { "PASS" } else { "FAIL" }
    }

    # Windows Firewall
    $FWProfiles = Get-NetFirewallProfile
    foreach ($Profile in $FWProfiles) {
        $Results += [PSCustomObject]@{
            Check = "Firewall $($Profile.Name) Enabled"
            Expected = "True"
            Actual = $Profile.Enabled
            Status = if ($Profile.Enabled) { "PASS" } else { "FAIL" }
        }
    }

    # NLA for RDP
    $NLA = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue
    $Results += [PSCustomObject]@{
        Check = "NLA Enabled for RDP"
        Expected = "1"
        Actual = $NLA.UserAuthentication
        Status = if ($NLA.UserAuthentication -eq 1) { "PASS" } else { "FAIL" }
    }

    # Guest Account
    $Guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    $Results += [PSCustomObject]@{
        Check = "Guest Account Disabled"
        Expected = "False"
        Actual = $Guest.Enabled
        Status = if ($Guest.Enabled -eq $false) { "PASS" } else { "FAIL" }
    }

    return $Results
}

# Exécuter et afficher
$AuditResults = Test-SecurityBaseline
$AuditResults | Format-Table -AutoSize

# Résumé
$Passed = ($AuditResults | Where-Object Status -eq "PASS").Count
$Total = $AuditResults.Count
Write-Host "`nScore: $Passed/$Total ($([math]::Round($Passed/$Total*100))%)" -ForegroundColor $(if ($Passed -eq $Total) { "Green" } else { "Yellow" })
```

---

## 6. Exercice : À Vous de Jouer

!!! example "Mise en Pratique : Appliquer une Baseline de Sécurité"
    **Objectif** : Appliquer et valider une baseline de sécurité CIS sur un serveur Windows Server 2022.

    **Contexte** : Votre entreprise doit mettre en conformité un nouveau serveur avant sa mise en production.

    **Tâches à réaliser** :

    1. Télécharger Microsoft Security Compliance Toolkit depuis le site Microsoft
    2. Faire un backup de la configuration actuelle avec LGPO
    3. Appliquer la baseline Windows Server 2022 Member Server
    4. Exécuter l'audit et documenter les écarts
    5. Créer une exception documentée et justifiée

    **Critères de validation** :

    - [ ] Backup créé avant modification
    - [ ] Baseline appliquée sans erreur
    - [ ] Audit exécuté avec moins de 5 FAIL
    - [ ] Exception documentée avec justification business

??? quote "Solution"
    ```powershell
    # 1. Backup de la configuration actuelle
    New-Item -Path "C:\SecurityBackup" -ItemType Directory -Force
    .\LGPO.exe /b "C:\SecurityBackup"

    # 2. Appliquer la baseline
    .\Baseline-LocalInstall.ps1 -WSMember

    # 3. Vérifier l'application
    Test-SecurityBaseline | Where-Object Status -eq "FAIL"

    # 4. Documenter les exceptions
    $Exception = @{
        Setting = "Interactive logon: Message text"
        Reason = "Custom corporate banner required"
        ApprovedBy = "Security Team"
        Date = Get-Date
    }
    $Exception | Export-Csv "C:\SecurityBackup\Exceptions.csv" -Append
    ```

    !!! tip "Bonnes pratiques"
        Toujours tester les baselines en environnement de test avant la production.

---

## Quiz

1. **Quelle est la différence entre CIS L1 et L2 ?**
   - [ ] A. L1 est pour serveurs, L2 pour postes
   - [ ] B. L1 est sécurité de base, L2 est renforcé avec impact potentiel
   - [ ] C. L1 est gratuit, L2 est payant

2. **Quel outil applique les GPO localement sans AD ?**
   - [ ] A. gpupdate
   - [ ] B. LGPO
   - [ ] C. secedit

3. **Pourquoi documenter les exceptions ?**
   - [ ] A. Pour les audits de conformité
   - [ ] B. Pour contourner la sécurité
   - [ ] C. Ce n'est pas nécessaire

**Réponses :** 1-B, 2-B, 3-A

---

**Suivant :** [Module 2 - Services & Protocoles](02-module.md)

---

## Navigation

| | |
|:---|---:|
| [← Programme](index.md) | [Module 2 : Services & Protocoles →](02-module.md) |

[Retour au Programme](index.md){ .md-button }
