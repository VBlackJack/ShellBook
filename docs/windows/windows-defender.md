---
tags:
  - windows
  - defender
  - security
  - antivirus
  - edr
---

# Windows Defender

Configuration et gestion de Windows Defender Antivirus et Microsoft Defender for Endpoint.

## Architecture

```
WINDOWS DEFENDER COMPONENTS
══════════════════════════════════════════════════════════

Windows Defender Antivirus (Gratuit, intégré):
├── Real-time Protection
├── Cloud-delivered Protection
├── Behavior Monitoring
├── Exploit Protection
├── Network Protection
├── Controlled Folder Access
└── Attack Surface Reduction (ASR)

Microsoft Defender for Endpoint (Licence E5):
├── Tout ce qui précède +
├── Endpoint Detection & Response (EDR)
├── Threat & Vulnerability Management
├── Automated Investigation
├── Microsoft Threat Experts
└── Integration SIEM/SOAR

Architecture :
┌─────────────────────────────────────────────────────────┐
│                    Client Windows                       │
├─────────────────────────────────────────────────────────┤
│  MsMpEng.exe (Antimalware Service Executable)          │
│  NisSrv.exe (Network Inspection Service)               │
│  MpCmdRun.exe (CLI)                                    │
├─────────────────────────────────────────────────────────┤
│                    Cloud Protection                     │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────┐    │
│  │ MAPS       │  │ Sample      │  │ Threat       │    │
│  │ (Telemetry)│  │ Submission  │  │ Intelligence │    │
│  └─────────────┘  └─────────────┘  └──────────────┘    │
└─────────────────────────────────────────────────────────┘
```

---

## PowerShell Management

### État et Configuration

```powershell
# Importer le module
Import-Module Defender

# État de Defender
Get-MpComputerStatus

# Propriétés importantes
Get-MpComputerStatus | Select-Object `
    AntivirusEnabled,
    AntispywareEnabled,
    RealTimeProtectionEnabled,
    BehaviorMonitorEnabled,
    IoavProtectionEnabled,  # IE/Edge downloads
    AntivirusSignatureLastUpdated,
    QuickScanAge,
    FullScanAge

# Voir la configuration
Get-MpPreference
```

### Mises à Jour des Signatures

```powershell
# Mettre à jour les définitions
Update-MpSignature

# Forcer la mise à jour depuis Microsoft
Update-MpSignature -UpdateSource MicrosoftUpdateServer

# Depuis un partage réseau
Update-MpSignature -UpdateSource FileShares -DefinitionUpdateFileSharesSources "\\server\updates"

# Vérifier l'âge des signatures
(Get-MpComputerStatus).AntivirusSignatureAge  # Jours depuis la dernière MAJ

# Version des signatures
(Get-MpComputerStatus).AntivirusSignatureVersion
```

### Scans

```powershell
# Scan rapide
Start-MpScan -ScanType QuickScan

# Scan complet
Start-MpScan -ScanType FullScan

# Scan d'un chemin spécifique
Start-MpScan -ScanPath "D:\Downloads"

# Scan hors ligne (au reboot) - pour rootkits
Start-MpWDOScan

# Voir le statut du dernier scan
Get-MpComputerStatus | Select-Object LastQuickScanSource, LastQuickScanEndTime, LastFullScanEndTime
```

---

## Configuration

### Protection en Temps Réel

```powershell
# Activer/Désactiver (temporairement)
Set-MpPreference -DisableRealtimeMonitoring $false  # Activer
Set-MpPreference -DisableRealtimeMonitoring $true   # Désactiver

# Behavior Monitoring
Set-MpPreference -DisableBehaviorMonitoring $false

# Heuristiques
Set-MpPreference -DisableHeuristicsMonitoring $false

# Script Scanning
Set-MpPreference -DisableScriptScanning $false

# Protection réseau
Set-MpPreference -EnableNetworkProtection Enabled  # ou AuditMode, Disabled
```

### Cloud Protection

```powershell
# Activer la protection cloud (MAPS)
Set-MpPreference -MAPSReporting Advanced  # ou Basic, Disabled

# Niveau de protection cloud
Set-MpPreference -CloudBlockLevel High  # Default, Moderate, High, HighPlus, ZeroTolerance

# Timeout cloud (secondes)
Set-MpPreference -CloudExtendedTimeout 50

# Envoi automatique d'échantillons
Set-MpPreference -SubmitSamplesConsent SendAllSamples
# Options: NeverSend, AlwaysPrompt, SendSafeSamples, SendAllSamples
```

### Exclusions

```powershell
# Ajouter des exclusions de chemin
Add-MpPreference -ExclusionPath "C:\DevTools"
Add-MpPreference -ExclusionPath "D:\VMs"

# Exclusions d'extension
Add-MpPreference -ExclusionExtension ".log",".tmp"

# Exclusions de processus
Add-MpPreference -ExclusionProcess "devenv.exe","code.exe"

# Voir les exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess

# Supprimer une exclusion
Remove-MpPreference -ExclusionPath "C:\OldPath"
```

### Actions sur les Menaces

```powershell
# Configurer l'action par niveau de sévérité
Set-MpPreference -LowThreatDefaultAction Quarantine
Set-MpPreference -ModerateThreatDefaultAction Quarantine
Set-MpPreference -HighThreatDefaultAction Remove
Set-MpPreference -SevereThreatDefaultAction Remove

# Actions possibles :
# Clean, Quarantine, Remove, Allow, UserDefined, NoAction, Block
```

---

## Attack Surface Reduction (ASR)

### Règles ASR

```powershell
# Les règles ASR bloquent des comportements exploités par les malwares

# Voir les règles disponibles
Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids

# Activer des règles (par GUID)
# Mode: 0=Disabled, 1=Block, 2=Audit

# Bloquer le contenu exécutable des clients email
Add-MpPreference -AttackSurfaceReductionRules_Ids BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 -AttackSurfaceReductionRules_Actions Enabled

# Règles recommandées (en mode Block)
$rules = @{
    # Block executable content from email client and webmail
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = 1
    # Block all Office applications from creating child processes
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = 1
    # Block Office applications from creating executable content
    "3B576869-A4EC-4529-8536-B80A7769E899" = 1
    # Block Office applications from injecting code into other processes
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = 1
    # Block JavaScript or VBScript from launching downloaded executable content
    "D3E037E1-3EB8-44C8-A917-57927947596D" = 1
    # Block execution of potentially obfuscated scripts
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = 1
    # Block Win32 API calls from Office macros
    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = 1
    # Block credential stealing from LSASS
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = 1
    # Block untrusted and unsigned processes that run from USB
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = 1
    # Use advanced protection against ransomware
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = 1
}

foreach ($rule in $rules.GetEnumerator()) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Key -AttackSurfaceReductionRules_Actions $rule.Value
}

# Mode Audit (pour tester)
Add-MpPreference -AttackSurfaceReductionRules_Ids "GUID" -AttackSurfaceReductionRules_Actions AuditMode
```

### Exploit Protection

```powershell
# Voir la configuration
Get-ProcessMitigation -System

# Configurer pour un processus
Set-ProcessMitigation -Name "notepad.exe" -Enable DEP,SEHOP -Disable CFG

# Options disponibles :
# DEP, SEHOP, ASLR, CFG, StrictHandle, DisableWin32kSystemCalls, etc.

# Exporter la configuration
Get-ProcessMitigation -RegistryConfigFilePath "C:\ExploitProtection.xml"

# Importer une configuration
Set-ProcessMitigation -PolicyFilePath "C:\ExploitProtection.xml"
```

### Controlled Folder Access

```powershell
# Protège les dossiers contre les ransomwares

# Activer
Set-MpPreference -EnableControlledFolderAccess Enabled  # ou AuditMode

# Dossiers protégés par défaut :
# Documents, Pictures, Videos, Music, Desktop, Favorites

# Ajouter un dossier protégé
Add-MpPreference -ControlledFolderAccessProtectedFolders "D:\CriticalData"

# Autoriser une application
Add-MpPreference -ControlledFolderAccessAllowedApplications "C:\Apps\TrustedApp.exe"
```

---

## Gestion des Menaces

### Historique et Quarantaine

```powershell
# Voir l'historique des menaces
Get-MpThreatDetection

# Détails des menaces
Get-MpThreat

# Menaces en quarantaine
Get-MpThreat | Where-Object { $_.IsActive -eq $false }

# Supprimer une menace de la quarantaine
Remove-MpThreat -ThreatID 12345

# Restaurer un fichier (attention!)
# Via l'historique Windows Defender dans Settings
```

### Threat Catalog

```powershell
# Informations sur une menace spécifique
Get-MpThreatCatalog | Where-Object { $_.ThreatName -like "*Trojan*" }

# Catégories de menaces
Get-MpThreatCatalog | Group-Object CategoryID
```

---

## GPO et Intune

### Configuration via GPO

```
Computer Configuration > Administrative Templates >
Windows Components > Microsoft Defender Antivirus

Sections importantes :
├── Real-time Protection
│   ├── Turn off real-time protection
│   └── Configure monitoring for incoming/outgoing files
├── Scan
│   ├── Specify scan type (Quick/Full)
│   └── Specify scan schedule
├── Security Intelligence Updates
│   ├── Define file shares for downloading
│   └── Specify interval for updates
├── Exclusions
│   ├── Path Exclusions
│   ├── Extension Exclusions
│   └── Process Exclusions
├── MAPS (Cloud Protection)
│   ├── Join Microsoft MAPS
│   └── Configure local setting override
└── Attack Surface Reduction
    └── Configure Attack Surface Reduction rules
```

### Configuration via Intune/SCCM

```powershell
# Exporter la configuration actuelle
Get-MpPreference | Export-Clixml "C:\Defender-Config.xml"

# Pour Intune, utiliser les Endpoint Security Policies :
# - Antivirus policies
# - Attack Surface Reduction policies
# - Endpoint Detection and Response policies
```

---

## Defender for Endpoint (MDE)

### Onboarding

```powershell
# L'onboarding nécessite un script du portail Security Center
# security.microsoft.com > Settings > Endpoints > Onboarding

# Vérifier l'onboarding
Get-MpComputerStatus | Select-Object AMServiceEnabled, OnboardingState

# Ou via le service
Get-Service -Name "Sense"  # MDE service
Get-Service -Name "WinDefend"  # Defender AV service

# Logs d'onboarding
Get-WinEvent -LogName "Microsoft-Windows-SENSE/Operational" -MaxEvents 20
```

### Indicateurs (IOCs)

```powershell
# Les IOCs sont gérés via le portail Security Center
# ou via API Microsoft Graph

# API pour créer un indicateur
# POST https://api.securitycenter.microsoft.com/api/indicators

# Types d'indicateurs :
# - FileSha1, FileSha256, FileMd5
# - IpAddress, Url, DomainName
# - CertificateThumbprint
```

---

## Monitoring et Alertes

### Event Logs

```powershell
# Logs Defender
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 50

# Événements importants :
# 1116 : Malware detected
# 1117 : Malware action taken
# 1118 : Malware action failed
# 1119 : Malware action critical failure
# 1006 : Scan started
# 1007 : Scan completed
# 2001 : Signature update
# 5001 : Real-time protection disabled
# 5010 : Scanning for malware disabled

# Filtrer les détections
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    Id = 1116,1117
} -MaxEvents 100

# Logs ASR
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" |
    Where-Object { $_.Id -in 1121,1122,1129 }  # ASR block, audit, rule triggered
```

### Rapports

```powershell
# Script de rapport quotidien
function Get-DefenderReport {
    $status = Get-MpComputerStatus
    $threats = Get-MpThreatDetection | Where-Object { $_.InitialDetectionTime -gt (Get-Date).AddDays(-1) }

    [PSCustomObject]@{
        Date = Get-Date -Format "yyyy-MM-dd"
        Computer = $env:COMPUTERNAME
        AVEnabled = $status.AntivirusEnabled
        RTProtection = $status.RealTimeProtectionEnabled
        SignatureAge = $status.AntivirusSignatureAge
        ThreatsLast24h = $threats.Count
        LastQuickScan = $status.LastQuickScanEndTime
        LastFullScan = $status.LastFullScanEndTime
    }
}

Get-DefenderReport | Export-Csv "C:\Reports\defender-report.csv" -Append
```

---

## Troubleshooting

### Diagnostics

```powershell
# Outil de diagnostic intégré
MpCmdRun.exe -GetFiles  # Collecte les logs dans C:\ProgramData\Microsoft\Windows Defender\Support

# Vérifier l'état des services
Get-Service WinDefend, WdNisSvc, Sense

# Performance
# Le processus MsMpEng.exe consomme trop de CPU ?
# → Vérifier les exclusions
# → Réduire la fréquence des scans

# Conflits avec autre AV
# Defender se désactive si un autre AV est installé
Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled
```

### MpCmdRun (CLI)

```powershell
# Emplacement
$mpcmd = "${env:ProgramFiles}\Windows Defender\MpCmdRun.exe"

# Mise à jour signatures
& $mpcmd -SignatureUpdate

# Scan
& $mpcmd -Scan -ScanType 1  # Quick
& $mpcmd -Scan -ScanType 2  # Full
& $mpcmd -Scan -ScanType 3 -File "C:\suspect.exe"

# Restaurer un fichier en quarantaine
& $mpcmd -Restore -Name "ThreatName"

# Collecter les logs
& $mpcmd -GetFiles

# Réinitialiser le moteur
& $mpcmd -RemoveDefinitions -All
& $mpcmd -SignatureUpdate
```

---

## Bonnes Pratiques

```yaml
Checklist Windows Defender:
  Configuration:
    - [ ] Real-time protection activé
    - [ ] Cloud protection (MAPS) activé
    - [ ] Behavior monitoring activé
    - [ ] Signatures à jour (< 1 jour)

  ASR:
    - [ ] Règles ASR en mode Audit (test)
    - [ ] Puis passer en Block après validation
    - [ ] Controlled Folder Access pour données critiques

  Exclusions:
    - [ ] Exclure les dossiers de développement
    - [ ] Exclure les processus de backup/AV tiers
    - [ ] Documenter toutes les exclusions
    - [ ] Réviser régulièrement

  Monitoring:
    - [ ] Alertes sur détections
    - [ ] Rapports de conformité
    - [ ] Intégration SIEM si MDE
```

---

**Voir aussi :**

- [Windows Security](windows-security.md) - Sécurité globale
- [AppLocker](applocker.md) - Contrôle des applications
- [Event Logs](event-logs.md) - Journaux d'événements
