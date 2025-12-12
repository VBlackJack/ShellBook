---
tags:
  - defender
  - firewall
  - windows
  - security
---

# Windows Firewall & Defender

Protection périmétrique Windows : Firewall et antivirus intégré.

---

## Windows Firewall (NetSecurity)

### Profils Firewall

| Profil | Description | Quand actif |
|--------|-------------|-------------|
| **Domain** | Réseau d'entreprise | Connecté à un domaine AD |
| **Private** | Réseau de confiance | Réseau marqué "Privé" |
| **Public** | Réseau non fiable | WiFi public, par défaut |

```powershell
# État des profils
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Configurer la politique par défaut (RECOMMANDÉ)
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow `
    -Enabled True
```

### Gestion des Règles

```powershell
# Lister toutes les règles
Get-NetFirewallRule

# Règles actives entrantes
Get-NetFirewallRule -Direction Inbound -Enabled True |
    Select-Object Name, DisplayName, Action

# Rechercher une règle par nom
Get-NetFirewallRule -DisplayName "*Remote Desktop*"

# Détails complets d'une règle (avec ports)
Get-NetFirewallRule -DisplayName "Remote Desktop*" |
    Get-NetFirewallPortFilter
```

### Créer des Règles

```powershell
# Autoriser un port entrant (ex: SSH)
New-NetFirewallRule `
    -DisplayName "Allow SSH" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 22 `
    -Action Allow `
    -Profile Domain,Private

# Autoriser une application
New-NetFirewallRule `
    -DisplayName "Allow MyApp" `
    -Direction Inbound `
    -Program "C:\Program Files\MyApp\app.exe" `
    -Action Allow

# Bloquer une IP spécifique
New-NetFirewallRule `
    -DisplayName "Block Malicious IP" `
    -Direction Inbound `
    -RemoteAddress "1.2.3.4" `
    -Action Block

# Autoriser un sous-réseau
New-NetFirewallRule `
    -DisplayName "Allow LAN" `
    -Direction Inbound `
    -RemoteAddress "192.168.1.0/24" `
    -Action Allow

# Autoriser une plage de ports
New-NetFirewallRule `
    -DisplayName "Allow High Ports" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 49152-65535 `
    -Action Allow
```

### Modifier / Supprimer

```powershell
# Désactiver une règle
Disable-NetFirewallRule -DisplayName "Allow SSH"

# Activer une règle
Enable-NetFirewallRule -DisplayName "Allow SSH"

# Supprimer une règle
Remove-NetFirewallRule -DisplayName "Allow SSH"

# Modifier une règle
Set-NetFirewallRule -DisplayName "Allow SSH" -LocalPort 2222
```

---

## Windows Defender

### État et Informations

```powershell
# État complet de Defender
Get-MpComputerStatus

# Propriétés importantes
Get-MpComputerStatus | Select-Object `
    AntivirusEnabled,
    RealTimeProtectionEnabled,
    AntivirusSignatureLastUpdated,
    QuickScanAge,
    FullScanAge

# Préférences actuelles
Get-MpPreference
```

### Scans

```powershell
# Scan rapide
Start-MpScan -ScanType QuickScan

# Scan complet
Start-MpScan -ScanType FullScan

# Scan d'un chemin spécifique
Start-MpScan -ScanPath "C:\Users\Public\Downloads"

# Mettre à jour les signatures
Update-MpSignature
```

### Gestion des Exclusions

!!! warning "Exclusions : À utiliser avec parcimonie"
    Chaque exclusion est une brèche potentielle. Documenter et justifier chaque exclusion.

```powershell
# Voir les exclusions actuelles
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Get-MpPreference | Select-Object -ExpandProperty ExclusionProcess
Get-MpPreference | Select-Object -ExpandProperty ExclusionExtension

# Ajouter une exclusion de chemin
Add-MpPreference -ExclusionPath "C:\DevTools"

# Ajouter une exclusion de processus
Add-MpPreference -ExclusionProcess "devenv.exe"

# Ajouter une exclusion d'extension
Add-MpPreference -ExclusionExtension ".log"

# Supprimer une exclusion
Remove-MpPreference -ExclusionPath "C:\DevTools"
```

### Menaces Détectées

```powershell
# Historique des menaces
Get-MpThreatDetection

# Détails des menaces
Get-MpThreat

# Supprimer les menaces actives
Remove-MpThreat
```

---

## Référence Rapide

```powershell
# === FIREWALL ===
Get-NetFirewallProfile                            # État des profils
Get-NetFirewallRule -Direction Inbound -Enabled True
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
Remove-NetFirewallRule -DisplayName "Allow SSH"

# === DEFENDER ===
Get-MpComputerStatus                              # État
Start-MpScan -ScanType QuickScan                  # Scan rapide
Update-MpSignature                                # MAJ signatures
Add-MpPreference -ExclusionPath "C:\Path"         # Exclusion
```

---

## Firewall - Règles via GPO

### Emplacement

```text
Computer Configuration > Policies > Windows Settings >
Security Settings > Windows Defender Firewall with Advanced Security
```

### Logging

```powershell
# Activer le logging
Set-NetFirewallProfile -Profile Domain `
    -LogFileName "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" `
    -LogMaxSizeKilobytes 16384 `
    -LogAllowed True `
    -LogBlocked True
```

### Règles Prédéfinies

```powershell
# Activer les règles prédéfinies (ex: Remote Desktop)
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Voir les groupes disponibles
Get-NetFirewallRule | Select-Object -ExpandProperty DisplayGroup -Unique | Sort-Object

# Groupes courants :
# - Remote Desktop
# - File and Printer Sharing
# - Windows Remote Management
# - Core Networking
# - Remote Event Log Management
```

### IPSec et Connection Security

```powershell
# Créer une règle de sécurité de connexion (IPSec)
New-NetIPsecRule -DisplayName "Require Auth to Servers" `
    -InboundSecurity Require `
    -OutboundSecurity Request `
    -LocalAddress 10.10.1.0/24 `
    -RemoteAddress 10.10.2.0/24

# Voir les associations de sécurité
Get-NetIPsecMainModeSA
Get-NetIPsecQuickModeSA
```

### Scénarios Courants

```powershell
# === SQL Server ===
New-NetFirewallRule -DisplayName "SQL Server" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow
New-NetFirewallRule -DisplayName "SQL Browser" -Direction Inbound -Protocol UDP -LocalPort 1434 -Action Allow

# === Domain Controller ===
$dcPorts = @(
    @{Name="DNS-TCP"; Port=53; Protocol="TCP"},
    @{Name="DNS-UDP"; Port=53; Protocol="UDP"},
    @{Name="Kerberos-TCP"; Port=88; Protocol="TCP"},
    @{Name="Kerberos-UDP"; Port=88; Protocol="UDP"},
    @{Name="RPC"; Port=135; Protocol="TCP"},
    @{Name="LDAP"; Port=389; Protocol="TCP"},
    @{Name="LDAPS"; Port=636; Protocol="TCP"},
    @{Name="SMB"; Port=445; Protocol="TCP"},
    @{Name="GC"; Port=3268; Protocol="TCP"}
)

foreach ($port in $dcPorts) {
    New-NetFirewallRule -DisplayName "DC-$($port.Name)" `
        -Direction Inbound `
        -Protocol $port.Protocol `
        -LocalPort $port.Port `
        -Action Allow
}
```

---

## Defender - Configuration Avancée

### Architecture

```text
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

### Attack Surface Reduction (ASR)

```powershell
# Règles ASR recommandées (en mode Block)
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
```

### Defender for Endpoint (MDE)

```powershell
# Vérifier l'onboarding
Get-MpComputerStatus | Select-Object AMServiceEnabled, OnboardingState

# Services
Get-Service -Name "Sense"  # MDE service
Get-Service -Name "WinDefend"  # Defender AV service

# Logs d'onboarding
Get-WinEvent -LogName "Microsoft-Windows-SENSE/Operational" -MaxEvents 20
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
# 5001 : Real-time protection disabled

# Filtrer les détections
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-Windows Defender/Operational"
    Id = 1116,1117
} -MaxEvents 100

# Logs Firewall
Get-WinEvent -LogName "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" -MaxEvents 50
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
```

---

## Bonnes Pratiques

```yaml
Checklist Firewall:
  Configuration:
    - [ ] Activé sur tous les profils
    - [ ] Inbound = Block par défaut
    - [ ] Outbound = Allow (ou Block + whitelist)
    - [ ] Logging activé

  Règles:
    - [ ] Noms descriptifs
    - [ ] Scope IP restreint si possible
    - [ ] Profil approprié (Domain vs Public)
    - [ ] Documenter chaque règle

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
```

---

!!! tip "À lire aussi"
    - [Hardening ANSSI](hardening-anssi.md) - GPO de sécurité et audit
    - [BitLocker](bitlocker.md) - Chiffrement des disques
    - [AppLocker](../applocker.md) - Contrôle des applications
    - [Event Logs](../event-logs.md) - Journaux d'événements
