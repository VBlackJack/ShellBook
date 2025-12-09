---
tags:
  - windows
  - applocker
  - security
  - application-control
---

# AppLocker

Contrôle des applications autorisées à s'exécuter via AppLocker et WDAC.

## Concepts

```text
APPLOCKER VS WDAC
══════════════════════════════════════════════════════════

AppLocker :
• Plus simple à configurer
• Règles par utilisateur/groupe possibles
• Nécessite le service "Application Identity"
• Windows Enterprise/Education requis
• Peut être contourné par admin local

WDAC (Windows Defender Application Control) :
• Plus sécurisé (kernel-level)
• Règles machine uniquement
• Intégré avec Credential Guard
• Windows 10/11 toutes éditions
• Résiste aux admins locaux
```

---

## Configuration AppLocker

### Activer le Service

```powershell
# Démarrer le service Application Identity (obligatoire)
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc

# Vérifier
Get-Service AppIDSvc
```

### Créer des Règles par Défaut

```powershell
# Créer les règles par défaut (recommandé comme base)
# Via GPO ou localement :

# Via PowerShell local
Set-AppLockerPolicy -XMLPolicy (
    New-AppLockerPolicy -RuleType Exe, Msi, Script -User Everyone -RuleNamePrefix "Default"
).ToXml() -Merge

# Les règles par défaut autorisent :
# - Tout dans C:\Windows\*
# - Tout dans C:\Program Files\*
# - Tout pour les Admins
```

### Règles par Type

```powershell
# Types de règles :
# - Executable (*.exe, *.com)
# - Windows Installer (*.msi, *.msp, *.mst)
# - Script (*.ps1, *.bat, *.cmd, *.vbs, *.js)
# - Packaged Apps (APPX)
# - DLL (désactivé par défaut, impact perf)

# Exemple : Bloquer les exécutables des profils utilisateur
$rule = New-AppLockerPolicy -RuleType Path -RuleNamePrefix "Block" `
    -Path "%USERPROFILE%\*" `
    -User "Everyone" `
    -Action Deny

# Exemple : Autoriser une application signée (Publisher)
$rule = New-AppLockerPolicy -RuleType Publisher `
    -PublisherName "O=MICROSOFT CORPORATION" `
    -User "Everyone" `
    -Action Allow

# Exemple : Autoriser par hash de fichier
$hash = Get-AppLockerFileInformation -Path "C:\Apps\MyApp.exe"
$rule = New-AppLockerPolicy -RuleType FileHash -FileInformation $hash -User "Everyone" -Action Allow
```

---

## Déploiement via GPO

### Emplacement

```text
Computer Configuration > Policies > Windows Settings >
Security Settings > Application Control Policies > AppLocker
```

### Configuration Recommandée

```bash
1. Executable Rules :
   - [Allow] %WINDIR%\* (Everyone)
   - [Allow] %PROGRAMFILES%\* (Everyone)
   - [Allow] * (BUILTIN\Administrators)
   - [Deny] %USERPROFILE%\* (Everyone)  # Bloquer exécution depuis profils

2. Script Rules :
   - [Allow] %WINDIR%\* (Everyone)
   - [Allow] %PROGRAMFILES%\* (Everyone)
   - [Allow] * (BUILTIN\Administrators)

3. Windows Installer Rules :
   - [Allow] * (BUILTIN\Administrators)  # Seuls les admins peuvent installer

4. Packaged App Rules :
   - [Allow] * (Everyone)  # Ou spécifique si Store restreint
```

### Mode Audit

```powershell
# Toujours commencer en mode Audit !
# GPO > AppLocker > Executable Rules > Properties
# Enforcement : Audit only

# Voir les événements d'audit
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 100 |
    Where-Object { $_.Id -eq 8003 }  # Would be blocked

# Analyser les blocages potentiels
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" |
    Where-Object { $_.Id -in 8003,8004 } |
    Select-Object TimeCreated, @{N='File';E={$_.Properties[10].Value}} |
    Group-Object File |
    Sort-Object Count -Descending
```

---

## Règles Avancées

### Exceptions

```powershell
# Règle avec exception
# "Bloquer tout dans %USERPROFILE% SAUF %USERPROFILE%\AppData\Local\Microsoft\*"

# Via GPO : créer la règle Allow avec le chemin d'exception
```

### Conditions de Publisher

```text
PUBLISHER RULE CONDITIONS
══════════════════════════════════════════════════════════

Publisher:        O=MICROSOFT CORPORATION
Product name:     MICROSOFT® WINDOWS® OPERATING SYSTEM
File name:        CMD.EXE
File version:     10.0.0.0 and above

Plus le curseur est haut, plus la règle est spécifique.
```

### Règles DLL (Performance!)

```powershell
# Activer les règles DLL (attention aux performances)
# GPO > AppLocker > Properties > Advanced > Enable DLL rule collection

# ⚠️ ATTENTION : Impact important sur les performances
# À utiliser uniquement si nécessaire (compliance, etc.)
```

---

## Gestion des Règles

```powershell
# Exporter les règles
Get-AppLockerPolicy -Effective -Xml | Out-File "C:\AppLocker-Policy.xml"

# Importer des règles
Set-AppLockerPolicy -XmlPolicy (Get-Content "C:\AppLocker-Policy.xml") -Merge

# Voir les règles effectives
Get-AppLockerPolicy -Effective | Select-Object -ExpandProperty RuleCollections

# Tester si un fichier serait autorisé
Test-AppLockerPolicy -Path "C:\test\app.exe" -User "CORP\jdoe"

# Supprimer toutes les règles locales
Set-AppLockerPolicy -XmlPolicy "<AppLockerPolicy Version=\"1\"/>"
```

---

## Troubleshooting

```powershell
# Event logs AppLocker
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL"
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/MSI and Script"
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/Packaged app-Execution"

# Event IDs importants :
# 8002 - Fichier autorisé
# 8003 - Fichier serait bloqué (audit)
# 8004 - Fichier bloqué (enforce)
# 8006 - Policy appliquée
# 8007 - Erreur de politique

# Vérifier le service
Get-Service AppIDSvc

# Forcer le rafraîchissement de la politique
gpupdate /force
```

---

## WDAC (Alternative Moderne)

```powershell
# Créer une politique WDAC depuis une machine de référence
New-CIPolicy -Level Publisher -FilePath "C:\WDAC\BasePolicy.xml" -UserPEs

# Convertir en binaire
ConvertFrom-CIPolicy -XmlFilePath "C:\WDAC\BasePolicy.xml" `
    -BinaryFilePath "C:\Windows\System32\CodeIntegrity\SIPolicy.p7b"

# Mode Audit
Set-RuleOption -FilePath "C:\WDAC\BasePolicy.xml" -Option 3

# Déployer via GPO
# Computer Configuration > Administrative Templates > System > Device Guard
# Deploy Windows Defender Application Control
```

---

## Bonnes Pratiques

```yaml
Checklist AppLocker:
  Préparation:
    - [ ] Inventaire des applications légitimes
    - [ ] Tester en mode Audit (2-4 semaines minimum)
    - [ ] Analyser les logs d'audit
    - [ ] Créer les exceptions nécessaires

  Règles:
    - [ ] Règles par défaut comme base
    - [ ] Publisher rules si possible (plus maintenable)
    - [ ] Hash rules pour apps non signées
    - [ ] Bloquer %USERPROFILE% pour les exécutables

  Déploiement:
    - [ ] Pilote sur groupe restreint
    - [ ] Communication aux utilisateurs
    - [ ] Procédure d'exception documentée
    - [ ] Monitoring continu
```

---

**Voir aussi :**

- [Windows Security](windows-security.md) - Sécurité Windows
- [Credential Guard](credential-guard.md) - WDAC et VBS
- [GPO](ad-gpo.md) - Déploiement des politiques
