---
tags:
  - formation
  - windows-server
  - gpo
  - group-policy
---

# Module 12 : GPO & Configuration

## Objectifs du Module

Ce module couvre la gestion des stratégies de groupe (GPO) :

- Comprendre l'architecture et l'héritage des GPO
- Créer et configurer des GPO
- Utiliser les préférences GPO
- Filtrer les GPO avec WMI et Security Filtering
- Dépanner les problèmes de GPO

**Durée :** 8 heures

**Niveau :** Ingénierie

---

## 1. Architecture GPO

### 1.1 Ordre de Traitement (LSDOU)

```
ORDRE DE TRAITEMENT DES GPO
───────────────────────────

Local     → GPO locale (gpedit.msc)
   ↓
Site      → GPO liée au site AD
   ↓
Domain    → GPO liée au domaine
   ↓
OU        → GPO liée aux OU (parent → enfant)

Note: Le dernier appliqué gagne (sauf si Enforced)

OPTIONS SPÉCIALES
─────────────────
• Block Inheritance  - Bloque l'héritage sur l'OU
• Enforced          - Force l'application (ignore Block)
• Security Filtering - Applique à certains groupes
• WMI Filtering     - Applique selon critères WMI
```

### 1.2 Composants GPO

```
STRUCTURE D'UNE GPO
───────────────────

GPO
├── Computer Configuration
│   ├── Policies
│   │   ├── Software Settings
│   │   ├── Windows Settings
│   │   │   ├── Scripts (Startup/Shutdown)
│   │   │   └── Security Settings
│   │   └── Administrative Templates
│   └── Preferences
│       ├── Control Panel Settings
│       ├── Windows Settings
│       └── ...
└── User Configuration
    ├── Policies
    │   └── (même structure)
    └── Preferences
        └── (même structure)
```

---

## 2. Gestion des GPO avec PowerShell

### 2.1 Opérations de Base

```powershell
# Importer le module
Import-Module GroupPolicy

# Lister les GPO
Get-GPO -All

# Créer une GPO
New-GPO -Name "Security-Baseline" -Comment "Paramètres de sécurité de base"

# Lier à une OU
New-GPLink -Name "Security-Baseline" -Target "OU=Computers,OU=Corp,DC=corp,DC=local"

# Modifier l'ordre de liaison
Set-GPLink -Name "Security-Baseline" -Target "OU=Computers,OU=Corp,DC=corp,DC=local" -Order 1

# Désactiver une liaison
Set-GPLink -Name "Security-Baseline" -Target "OU=Computers,OU=Corp,DC=corp,DC=local" -LinkEnabled No

# Supprimer une liaison
Remove-GPLink -Name "Security-Baseline" -Target "OU=Computers,OU=Corp,DC=corp,DC=local"

# Supprimer une GPO
Remove-GPO -Name "Security-Baseline"
```

### 2.2 Configurer des Paramètres

```powershell
# Configurer un paramètre de registre
Set-GPRegistryValue -Name "Security-Baseline" `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -ValueName "NoAutoUpdate" `
    -Type DWord `
    -Value 0

# Configurer plusieurs paramètres
$settings = @(
    @{Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender"; Name="DisableAntiSpyware"; Type="DWord"; Value=0},
    @{Key="HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Name="DisableRealtimeMonitoring"; Type="DWord"; Value=0}
)

foreach ($setting in $settings) {
    Set-GPRegistryValue -Name "Security-Baseline" `
        -Key $setting.Key `
        -ValueName $setting.Name `
        -Type $setting.Type `
        -Value $setting.Value
}

# Supprimer un paramètre
Remove-GPRegistryValue -Name "Security-Baseline" `
    -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" `
    -ValueName "NoAutoUpdate"
```

### 2.3 Backup et Restore

```powershell
# Sauvegarder toutes les GPO
Backup-GPO -All -Path "C:\GPOBackup"

# Sauvegarder une GPO spécifique
Backup-GPO -Name "Security-Baseline" -Path "C:\GPOBackup"

# Restaurer
Restore-GPO -Name "Security-Baseline" -Path "C:\GPOBackup"

# Importer depuis une autre GPO
Import-GPO -BackupGpoName "Source-GPO" -TargetName "Destination-GPO" -Path "C:\GPOBackup"

# Copier une GPO
Copy-GPO -SourceName "Security-Baseline" -TargetName "Security-Baseline-Test"
```

---

## 3. GPO Courantes

### 3.1 Sécurité

```powershell
# Créer une GPO de sécurité
New-GPO -Name "SEC-Password-Policy"

# Politique de mots de passe (via secpol)
# Note: Les politiques de MDP sont au niveau du domaine uniquement

# Restreindre l'accès au Panneau de configuration
Set-GPRegistryValue -Name "SEC-Restrictions" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -ValueName "NoControlPanel" `
    -Type DWord -Value 1

# Désactiver le compte Invité
Set-GPRegistryValue -Name "SEC-Restrictions" `
    -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" `
    -ValueName "PasswordExpiryWarning" `
    -Type DWord -Value 14

# Bannière de connexion
Set-GPRegistryValue -Name "SEC-Banner" `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "legalnoticecaption" `
    -Type String -Value "Avertissement"

Set-GPRegistryValue -Name "SEC-Banner" `
    -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "legalnoticetext" `
    -Type String -Value "Accès réservé aux utilisateurs autorisés."
```

### 3.2 Configuration Desktop

```powershell
# Fond d'écran uniforme
New-GPO -Name "Desktop-Standard"

Set-GPRegistryValue -Name "Desktop-Standard" `
    -Key "HKCU\Control Panel\Desktop" `
    -ValueName "Wallpaper" `
    -Type String -Value "\\corp.local\NETLOGON\wallpaper.jpg"

Set-GPRegistryValue -Name "Desktop-Standard" `
    -Key "HKCU\Control Panel\Desktop" `
    -ValueName "WallpaperStyle" `
    -Type String -Value "2"  # Stretch

# Désactiver le changement de fond d'écran
Set-GPRegistryValue -Name "Desktop-Standard" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" `
    -ValueName "NoChangingWallPaper" `
    -Type DWord -Value 1
```

---

## 4. Préférences GPO

### 4.1 Avantages des Préférences

```
POLICIES vs PREFERENCES
───────────────────────

Policies (Stratégies)        Preferences (Préférences)
• Forcées                    • Configurables par l'utilisateur
• Tatouage du registre       • Pas de tatouage (peuvent être modifiées)
• Strictes                   • Flexibles
• Paramètres limités         • Beaucoup plus d'options

Cas d'usage Preferences:
• Mappages de lecteurs
• Imprimantes
• Variables d'environnement
• Raccourcis
• Fichiers/Dossiers
• Registre avancé
```

### 4.2 Configuration via GPMC

Les préférences se configurent principalement via la console GPMC :

```
Computer/User Configuration
└── Preferences
    ├── Control Panel Settings
    │   ├── Devices
    │   ├── Folder Options
    │   ├── Internet Settings
    │   ├── Local Users and Groups
    │   ├── Network Options
    │   ├── Power Options
    │   ├── Printers
    │   ├── Regional Options
    │   ├── Scheduled Tasks
    │   └── Services
    └── Windows Settings
        ├── Applications
        ├── Drive Maps
        ├── Environment
        ├── Files
        ├── Folders
        ├── Ini Files
        ├── Network Shares
        ├── Registry
        └── Shortcuts
```

---

## 5. Filtrage GPO

### 5.1 Security Filtering

```powershell
# Voir les permissions actuelles
Get-GPPermission -Name "Security-Baseline" -All

# Retirer Authenticated Users (par défaut)
Set-GPPermission -Name "Security-Baseline" -PermissionLevel None -TargetName "Authenticated Users" -TargetType Group

# Ajouter un groupe spécifique
Set-GPPermission -Name "Security-Baseline" -PermissionLevel GpoApply -TargetName "IT-Computers" -TargetType Group
Set-GPPermission -Name "Security-Baseline" -PermissionLevel GpoRead -TargetName "IT-Computers" -TargetType Group
```

### 5.2 WMI Filtering

```powershell
# Créer un filtre WMI (Windows 10/11 uniquement)
$wmiFilter = @"
SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%"
"@

# Via GPMC ou ADSI pour créer le filtre WMI
# Puis l'attacher à la GPO

# Exemples de requêtes WMI utiles:
# OS Windows 10/11: SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%"
# Laptops: SELECT * FROM Win32_Battery
# RAM > 8GB: SELECT * FROM Win32_ComputerSystem WHERE TotalPhysicalMemory > 8589934592
# Disk > 500GB: SELECT * FROM Win32_DiskDrive WHERE Size > 500000000000
```

---

## 6. Dépannage GPO

### 6.1 Outils de Diagnostic

```powershell
# Résultat des GPO sur un ordinateur
gpresult /r

# Rapport HTML détaillé
gpresult /h C:\GPOReport.html

# Pour un utilisateur spécifique
gpresult /user CORP\jdoe /h C:\GPOReport.html

# Forcer la mise à jour des GPO
gpupdate /force

# Avec redémarrage si nécessaire
gpupdate /force /boot

# PowerShell
Invoke-GPUpdate -Force
Invoke-GPUpdate -Computer "PC001" -Force

# Vérifier la réplication des GPO
Get-GPO -All | ForEach-Object {
    $gpo = $_
    Get-ADDomainController -Filter * | ForEach-Object {
        [PSCustomObject]@{
            GPO = $gpo.DisplayName
            DC = $_.Name
            Version = (Get-GPO -Name $gpo.DisplayName -Server $_.Name).GpoStatus
        }
    }
}
```

### 6.2 Problèmes Courants

```powershell
# Vérifier la connectivité au DC
nltest /dsgetdc:corp.local

# Vérifier SYSVOL
dir \\corp.local\SYSVOL

# Vérifier les permissions
icacls "\\corp.local\SYSVOL\corp.local\Policies"

# Journal d'événements GPO
Get-WinEvent -LogName "Microsoft-Windows-GroupPolicy/Operational" -MaxEvents 50

# RSoP (Resultant Set of Policy)
# gpresult /r donne le RSoP de base
```

---

## 7. Exercice Pratique

### Créer une Stratégie de Sécurité

```powershell
# Créer les GPO
$gpos = @(
    @{Name="SEC-Password"; Comment="Politique de mots de passe"},
    @{Name="SEC-Lockout"; Comment="Verrouillage de compte"},
    @{Name="SEC-Desktop"; Comment="Restrictions bureau"}
)

foreach ($gpo in $gpos) {
    New-GPO -Name $gpo.Name -Comment $gpo.Comment
}

# Lier au domaine
New-GPLink -Name "SEC-Password" -Target "DC=corp,DC=local" -Enforced Yes
New-GPLink -Name "SEC-Lockout" -Target "DC=corp,DC=local"

# Lier aux OU utilisateurs
New-GPLink -Name "SEC-Desktop" -Target "OU=Users,OU=Corp,DC=corp,DC=local"

# Configurer les restrictions desktop
Set-GPRegistryValue -Name "SEC-Desktop" `
    -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
    -ValueName "DisableTaskMgr" `
    -Type DWord -Value 0

Set-GPRegistryValue -Name "SEC-Desktop" `
    -Key "HKCU\Software\Policies\Microsoft\Windows\System" `
    -ValueName "DisableCMD" `
    -Type DWord -Value 0

# Générer un rapport
Get-GPOReport -All -ReportType HTML -Path "C:\GPOReports\AllGPOs.html"
```

---

## Quiz

1. **Quel est l'ordre de traitement des GPO ?**
   - [ ] A. OU, Domain, Site, Local
   - [ ] B. Local, Site, Domain, OU
   - [ ] C. Domain, OU, Site, Local

2. **Quelle option force l'application malgré Block Inheritance ?**
   - [ ] A. Override
   - [ ] B. Enforced
   - [ ] C. Force

**Réponses :** 1-B (LSDOU), 2-B

---

**Précédent :** [Module 11 : Active Directory Core](11-active-directory-core.md)

**Suivant :** [Module 13 : Sécurité & Hardening](13-securite-hardening.md)
