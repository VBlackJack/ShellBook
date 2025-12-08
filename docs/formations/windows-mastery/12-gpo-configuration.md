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

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Mettre en place une stratégie de groupe complète pour sécuriser et standardiser les postes de travail

    **Contexte** : Votre entreprise souhaite appliquer des politiques de sécurité et de configuration différentes selon les départements. Le département IT doit avoir des restrictions minimales, tandis que les départements RH et Finance nécessitent des contrôles renforcés.

    **Tâches à réaliser** :

    1. Créer 4 GPO : "SEC-Password-Policy", "SEC-Desktop-Lockdown", "CFG-Desktop-Standard", "CFG-Drive-Mapping"
    2. Configurer la GPO "SEC-Password-Policy" au niveau du domaine avec les paramètres de sécurité
    3. Configurer la GPO "SEC-Desktop-Lockdown" avec restrictions (désactiver le Panneau de configuration, cmd, modifier le registre)
    4. Configurer la GPO "CFG-Desktop-Standard" avec un fond d'écran uniforme et configuration d'écran de veille
    5. Lier les GPO aux bonnes OU avec l'ordre approprié
    6. Appliquer un Security Filtering pour que "SEC-Desktop-Lockdown" ne s'applique qu'aux groupes RH et Finance
    7. Créer un rapport HTML de toutes les GPO et tester l'application avec gpresult

    **Critères de validation** :

    - [ ] 4 GPO créées avec des noms et descriptions appropriés
    - [ ] GPO de mot de passe liée au domaine avec "Enforced"
    - [ ] GPO Desktop-Lockdown appliquée uniquement aux bonnes OUs avec Security Filtering
    - [ ] Fond d'écran configuré via GPO sur tous les utilisateurs
    - [ ] Ordre de liaison des GPO correct (1 = priorité la plus haute)
    - [ ] Rapport HTML généré montrant toutes les configurations
    - [ ] `gpresult /h` sur un poste de test montre les GPO appliquées correctement

??? quote "Solution"
    **Étape 1 : Création des GPO**

    ```powershell
    Import-Module GroupPolicy

    # Créer les 4 GPO
    $gpos = @(
        @{Name="SEC-Password-Policy"; Comment="Politique de mots de passe pour le domaine"},
        @{Name="SEC-Desktop-Lockdown"; Comment="Restrictions desktop pour RH et Finance"},
        @{Name="CFG-Desktop-Standard"; Comment="Configuration desktop standard"},
        @{Name="CFG-Drive-Mapping"; Comment="Mappage de lecteurs réseau"}
    )

    foreach ($gpo in $gpos) {
        New-GPO -Name $gpo.Name -Comment $gpo.Comment
        Write-Host "GPO créée: $($gpo.Name)"
    }
    ```

    **Étape 2 : Configuration de la politique de mot de passe**

    ```powershell
    # Note: Les politiques de mot de passe au niveau domaine se configurent via secedit
    # ou via la console GPMC. Voici la configuration via GPO au niveau domaine

    # Lier au domaine avec Enforced
    $baseDN = "DC=corp,DC=local"
    New-GPLink -Name "SEC-Password-Policy" -Target $baseDN -LinkEnabled Yes -Enforced Yes

    # Configurer des paramètres de registre pour auditing
    Set-GPRegistryValue -Name "SEC-Password-Policy" `
        -Key "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" `
        -ValueName "FullPrivilegeAuditing" `
        -Type DWord -Value 1

    Write-Host "✓ Politique de mot de passe configurée et liée au domaine"

    # Note: Pour une vraie politique de mot de passe, utiliser:
    # Computer Configuration → Policies → Windows Settings →
    # Security Settings → Account Policies → Password Policy
    # Via GPMC (Interface graphique recommandée pour les politiques de sécurité)
    ```

    **Étape 3 : Configuration Desktop Lockdown**

    ```powershell
    # Désactiver le Panneau de configuration
    Set-GPRegistryValue -Name "SEC-Desktop-Lockdown" `
        -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -ValueName "NoControlPanel" `
        -Type DWord -Value 1

    # Désactiver CMD
    Set-GPRegistryValue -Name "SEC-Desktop-Lockdown" `
        -Key "HKCU\Software\Policies\Microsoft\Windows\System" `
        -ValueName "DisableCMD" `
        -Type DWord -Value 2  # 2 = désactiver aussi les scripts batch

    # Désactiver l'éditeur de registre
    Set-GPRegistryValue -Name "SEC-Desktop-Lockdown" `
        -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
        -ValueName "DisableRegistryTools" `
        -Type DWord -Value 1

    # Désactiver le Gestionnaire des tâches
    Set-GPRegistryValue -Name "SEC-Desktop-Lockdown" `
        -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" `
        -ValueName "DisableTaskMgr" `
        -Type DWord -Value 1

    # Masquer les lecteurs dans l'Explorateur
    Set-GPRegistryValue -Name "SEC-Desktop-Lockdown" `
        -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
        -ValueName "NoDrives" `
        -Type DWord -Value 0  # 0 = afficher tous, modifier selon besoins

    Write-Host "✓ Restrictions desktop configurées"
    ```

    **Étape 4 : Configuration Desktop Standard**

    ```powershell
    # Créer le répertoire pour le fond d'écran sur NETLOGON
    $wallpaperPath = "\\corp.local\NETLOGON\wallpapers"
    if (!(Test-Path $wallpaperPath)) {
        New-Item -Path $wallpaperPath -ItemType Directory -Force
    }

    # Copier un fond d'écran (supposons qu'il existe)
    # Copy-Item "C:\Temp\corporate-wallpaper.jpg" "$wallpaperPath\wallpaper.jpg"

    # Configurer le fond d'écran
    Set-GPRegistryValue -Name "CFG-Desktop-Standard" `
        -Key "HKCU\Control Panel\Desktop" `
        -ValueName "Wallpaper" `
        -Type String -Value "\\corp.local\NETLOGON\wallpapers\wallpaper.jpg"

    Set-GPRegistryValue -Name "CFG-Desktop-Standard" `
        -Key "HKCU\Control Panel\Desktop" `
        -ValueName "WallpaperStyle" `
        -Type String -Value "2"  # 2 = Stretch

    # Empêcher la modification du fond d'écran
    Set-GPRegistryValue -Name "CFG-Desktop-Standard" `
        -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop" `
        -ValueName "NoChangingWallPaper" `
        -Type DWord -Value 1

    # Configurer l'écran de veille
    Set-GPRegistryValue -Name "CFG-Desktop-Standard" `
        -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" `
        -ValueName "ScreenSaveActive" `
        -Type String -Value "1"

    Set-GPRegistryValue -Name "CFG-Desktop-Standard" `
        -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" `
        -ValueName "ScreenSaveTimeOut" `
        -Type String -Value "600"  # 10 minutes

    Set-GPRegistryValue -Name "CFG-Desktop-Standard" `
        -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" `
        -ValueName "ScreenSaverIsSecure" `
        -Type String -Value "1"  # Verrouiller avec mot de passe

    Write-Host "✓ Configuration desktop standard appliquée"
    ```

    **Étape 5 : Liaison des GPO aux OU**

    ```powershell
    $baseDN = "DC=corp,DC=local"

    # Lier CFG-Desktop-Standard à tous les utilisateurs
    New-GPLink -Name "CFG-Desktop-Standard" `
        -Target "OU=Users,OU=Corp,$baseDN" `
        -LinkEnabled Yes `
        -Order 2

    # Lier SEC-Desktop-Lockdown à l'OU Users (sera filtré par sécurité)
    New-GPLink -Name "SEC-Desktop-Lockdown" `
        -Target "OU=Users,OU=Corp,$baseDN" `
        -LinkEnabled Yes `
        -Order 1  # Priorité la plus haute

    # Lier CFG-Drive-Mapping
    New-GPLink -Name "CFG-Drive-Mapping" `
        -Target "OU=Users,OU=Corp,$baseDN" `
        -LinkEnabled Yes `
        -Order 3

    # Vérifier les liaisons
    Get-GPInheritance -Target "OU=Users,OU=Corp,$baseDN"

    Write-Host "✓ GPO liées aux OU avec ordre correct"
    ```

    **Étape 6 : Security Filtering**

    ```powershell
    # Retirer Authenticated Users de SEC-Desktop-Lockdown
    Set-GPPermission -Name "SEC-Desktop-Lockdown" `
        -PermissionLevel None `
        -TargetName "Authenticated Users" `
        -TargetType Group

    # Ajouter les groupes RH et Finance
    $targetGroups = @("GRP-RH", "GRP-Finance")

    foreach ($group in $targetGroups) {
        # Donner les permissions de lecture et d'application
        Set-GPPermission -Name "SEC-Desktop-Lockdown" `
            -PermissionLevel GpoApply `
            -TargetName $group `
            -TargetType Group

        Write-Host "✓ Security filtering appliqué pour $group"
    }

    # Vérifier les permissions
    Get-GPPermission -Name "SEC-Desktop-Lockdown" -All |
        Select-Object Trustee, Permission |
        Format-Table -AutoSize
    ```

    **Étape 7 : Génération de rapports et tests**

    ```powershell
    # Créer le répertoire de rapports
    $reportPath = "C:\GPOReports"
    if (!(Test-Path $reportPath)) {
        New-Item -Path $reportPath -ItemType Directory -Force
    }

    # Générer un rapport HTML de toutes les GPO
    Get-GPOReport -All -ReportType HTML -Path "$reportPath\All-GPOs.html"
    Write-Host "✓ Rapport HTML généré: $reportPath\All-GPOs.html"

    # Rapport individuel pour chaque GPO
    $gpoNames = @("SEC-Password-Policy", "SEC-Desktop-Lockdown", "CFG-Desktop-Standard", "CFG-Drive-Mapping")
    foreach ($gpoName in $gpoNames) {
        Get-GPOReport -Name $gpoName -ReportType HTML -Path "$reportPath\$gpoName.html"
    }

    # Générer un rapport XML pour analyse
    Get-GPOReport -All -ReportType XML -Path "$reportPath\All-GPOs.xml"

    # Script de test pour un utilisateur
    Write-Host "`n=== INSTRUCTIONS DE TEST ===" -ForegroundColor Cyan
    Write-Host "1. Se connecter sur un poste avec un compte du groupe RH ou Finance"
    Write-Host "2. Exécuter: gpupdate /force"
    Write-Host "3. Exécuter: gpresult /h C:\GPResult.html"
    Write-Host "4. Ouvrir C:\GPResult.html et vérifier que SEC-Desktop-Lockdown est appliquée"
    Write-Host "5. Tester que le Panneau de configuration est inaccessible"
    Write-Host "6. Se connecter avec un compte IT et vérifier que les restrictions ne s'appliquent pas`n"

    # Vérification de la configuration
    Write-Host "`n=== RÉSUMÉ DE LA CONFIGURATION ===" -ForegroundColor Yellow

    # Lister toutes les GPO
    $allGPOs = Get-GPO -All | Where-Object { $_.DisplayName -match "^(SEC|CFG)-" }
    Write-Host "GPO créées: $($allGPOs.Count)"

    # Vérifier les liens
    $links = Get-GPInheritance -Target "OU=Users,OU=Corp,$baseDN"
    Write-Host "GPO liées à Users OU: $($links.GpoLinks.Count)"

    # Afficher l'ordre de traitement
    Write-Host "`nOrdre de traitement des GPO:"
    $links.GpoLinks | Sort-Object Order | ForEach-Object {
        Write-Host "  [$($_.Order)] $($_.DisplayName) - Enabled: $($_.Enabled)"
    }

    # Vérifier le security filtering
    Write-Host "`nSecurity Filtering pour SEC-Desktop-Lockdown:"
    Get-GPPermission -Name "SEC-Desktop-Lockdown" -All |
        Where-Object { $_.Permission -eq "GpoApply" } |
        ForEach-Object {
            Write-Host "  - $($_.Trustee.Name)"
        }
    ```

    **Script de validation finale**

    ```powershell
    # Validation-GPO.ps1
    function Test-GPOConfiguration {
        $results = @()

        # Test 1: Vérifier que toutes les GPO existent
        $requiredGPOs = @("SEC-Password-Policy", "SEC-Desktop-Lockdown", "CFG-Desktop-Standard", "CFG-Drive-Mapping")
        foreach ($gpoName in $requiredGPOs) {
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            $results += [PSCustomObject]@{
                Test = "GPO existe: $gpoName"
                Status = if ($gpo) { "✓ PASS" } else { "✗ FAIL" }
            }
        }

        # Test 2: Vérifier la liaison au domaine
        $domainLink = Get-GPInheritance -Target "DC=corp,DC=local"
        $pwdPolicy = $domainLink.GpoLinks | Where-Object { $_.DisplayName -eq "SEC-Password-Policy" }
        $results += [PSCustomObject]@{
            Test = "SEC-Password-Policy liée au domaine"
            Status = if ($pwdPolicy) { "✓ PASS" } else { "✗ FAIL" }
        }

        # Test 3: Vérifier Enforced
        $results += [PSCustomObject]@{
            Test = "SEC-Password-Policy en mode Enforced"
            Status = if ($pwdPolicy.Enforced) { "✓ PASS" } else { "✗ FAIL" }
        }

        # Test 4: Vérifier les liaisons Users OU
        $userLinks = Get-GPInheritance -Target "OU=Users,OU=Corp,DC=corp,DC=local"
        $linkedCount = ($userLinks.GpoLinks | Where-Object { $_.DisplayName -match "^(SEC|CFG)-" }).Count
        $results += [PSCustomObject]@{
            Test = "GPO liées à Users OU (attendu: 3)"
            Status = if ($linkedCount -ge 3) { "✓ PASS ($linkedCount)" } else { "✗ FAIL ($linkedCount)" }
        }

        # Test 5: Vérifier Security Filtering
        $lockdownPerms = Get-GPPermission -Name "SEC-Desktop-Lockdown" -All |
            Where-Object { $_.Permission -eq "GpoApply" }
        $hasRH = $lockdownPerms.Trustee.Name -contains "GRP-RH"
        $hasFinance = $lockdownPerms.Trustee.Name -contains "GRP-Finance"
        $results += [PSCustomObject]@{
            Test = "Security Filtering configuré (RH + Finance)"
            Status = if ($hasRH -and $hasFinance) { "✓ PASS" } else { "✗ FAIL" }
        }

        # Test 6: Vérifier les rapports
        $reportExists = Test-Path "C:\GPOReports\All-GPOs.html"
        $results += [PSCustomObject]@{
            Test = "Rapport HTML généré"
            Status = if ($reportExists) { "✓ PASS" } else { "✗ FAIL" }
        }

        # Afficher les résultats
        Write-Host "`n=== RÉSULTATS DE VALIDATION ===" -ForegroundColor Cyan
        $results | Format-Table -AutoSize

        $passed = ($results | Where-Object { $_.Status -like "*PASS*" }).Count
        $total = $results.Count
        $percentage = [math]::Round(($passed / $total) * 100, 0)

        Write-Host "`nScore: $passed/$total ($percentage%)" -ForegroundColor $(if ($percentage -ge 85) { "Green" } else { "Yellow" })
    }

    # Exécuter la validation
    Test-GPOConfiguration
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

---

## Navigation

| | |
|:---|---:|
| [← Module 11 : Active Directory Core](11-active-directory-core.md) | [Module 13 : Sécurité & Hardening →](13-securite-hardening.md) |

[Retour au Programme](index.md){ .md-button }
