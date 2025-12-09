---
tags:
  - powershell
  - security
  - execution-policy
  - scripting
  - automation
---

# Execution Policy & Script Launcher

Maîtriser l'Execution Policy et créer un framework de lancement de scripts PowerShell.

---

## Execution Policy

### Comprendre les Niveaux

L'Execution Policy contrôle quels scripts peuvent s'exécuter sur le système.

| Policy | Description | Usage |
|--------|-------------|-------|
| `Restricted` | Aucun script ne peut s'exécuter | Default Windows client |
| `AllSigned` | Seuls les scripts signés peuvent s'exécuter | Production sécurisée |
| `RemoteSigned` | Scripts locaux OK, distants doivent être signés | **Recommandé serveurs** |
| `Unrestricted` | Tous les scripts, avertissement pour distants | Développement |
| `Bypass` | Aucune restriction, aucun avertissement | Automatisation CI/CD |
| `Undefined` | Pas de policy définie à ce scope | - |

### Scopes (Priorité décroissante)

```powershell
# Voir toutes les policies par scope
Get-ExecutionPolicy -List

# Scope          ExecutionPolicy
# -----          ---------------
# MachinePolicy  Undefined        # GPO Machine (priorité max)
# UserPolicy     Undefined        # GPO User
# Process        Undefined        # Session PowerShell actuelle
# CurrentUser    RemoteSigned     # Registre utilisateur
# LocalMachine   RemoteSigned     # Registre machine
```

### Consulter et Modifier

```powershell
# Voir la policy effective
Get-ExecutionPolicy

# Modifier pour la machine (nécessite Admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# Modifier pour l'utilisateur courant (sans Admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Modifier pour la session uniquement
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

---

## Contourner les Restrictions

### Méthodes Sans Modifier la Policy

```powershell
# 1. Bypass en ligne de commande
powershell.exe -ExecutionPolicy Bypass -File "C:\Scripts\script.ps1"

# 2. Bypass avec NoProfile (plus rapide)
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "script.ps1"

# 3. Lire et exécuter le contenu
Get-Content "script.ps1" | Invoke-Expression

# 4. Télécharger et exécuter (attention sécurité!)
iex (New-Object Net.WebClient).DownloadString('https://example.com/script.ps1')

# 5. Encoder en Base64
$command = Get-Content "script.ps1" -Raw
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
powershell.exe -EncodedCommand $encoded
```

### Via Batch Wrapper

```batch
@echo off
REM launcher.bat - Lance un script PowerShell en bypass
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0%1"
pause
```

---

## Script Launcher Framework

### Launcher Simple (GUI)

```powershell
<#
.SYNOPSIS
    Script Launcher - Liste et exécute les scripts du répertoire courant.

.DESCRIPTION
    Framework interactif pour lancer des scripts PowerShell avec élévation Admin.

.NOTES
    Placer dans le répertoire contenant vos scripts.
    Double-cliquer ou lancer via le .bat associé.
#>

#Requires -Version 5.1

# === Configuration ===
$ScriptPath = $PSScriptRoot
if (-not $ScriptPath) { $ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Definition }

# === Fonctions ===
function Show-Menu {
    param(
        [string]$Title,
        [array]$Options
    )

    Clear-Host
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  $Title" -ForegroundColor Cyan -NoNewline
    Write-Host (" " * (60 - $Title.Length - 3)) -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╠════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan

    for ($i = 0; $i -lt $Options.Count; $i++) {
        $num = $i + 1
        $option = $Options[$i]
        Write-Host "║  " -ForegroundColor Cyan -NoNewline
        Write-Host "[$num]" -ForegroundColor Yellow -NoNewline
        Write-Host " $option" -NoNewline
        $padding = 60 - 7 - $option.Length
        Write-Host (" " * [Math]::Max(0, $padding)) -NoNewline
        Write-Host "║" -ForegroundColor Cyan
    }

    Write-Host "║  " -ForegroundColor Cyan -NoNewline
    Write-Host "[0]" -ForegroundColor Red -NoNewline
    Write-Host " Quitter" -NoNewline
    Write-Host (" " * 45) -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-AsAdmin {
    param([string]$ScriptPath)

    $arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$ScriptPath`""

    Start-Process -FilePath "powershell.exe" `
                  -ArgumentList $arguments `
                  -Verb RunAs `
                  -Wait
}

# === Main ===
$isAdmin = Test-Administrator
$adminStatus = if ($isAdmin) { "[ADMIN]" } else { "[USER]" }

# Récupérer les scripts (exclure ce launcher)
$scripts = Get-ChildItem -Path $ScriptPath -Filter "*.ps1" |
           Where-Object { $_.Name -ne $MyInvocation.MyCommand.Name } |
           Sort-Object Name

if ($scripts.Count -eq 0) {
    Write-Host "Aucun script trouvé dans: $ScriptPath" -ForegroundColor Red
    Read-Host "Appuyez sur Entrée pour quitter"
    exit
}

# Boucle principale
do {
    $scriptNames = $scripts | ForEach-Object { $_.BaseName }
    Show-Menu -Title "SCRIPT LAUNCHER $adminStatus" -Options $scriptNames

    Write-Host "Admin actuel: " -NoNewline
    if ($isAdmin) {
        Write-Host "Oui" -ForegroundColor Green
    } else {
        Write-Host "Non (tapez 'admin' + numéro pour élever)" -ForegroundColor Yellow
    }
    Write-Host ""

    $choice = Read-Host "Choix"

    if ($choice -eq "0") {
        break
    }
    elseif ($choice -match "^admin\s*(\d+)$") {
        $num = [int]$Matches[1]
        if ($num -ge 1 -and $num -le $scripts.Count) {
            $selectedScript = $scripts[$num - 1].FullName
            Write-Host "`nLancement en tant qu'Admin: $($scripts[$num - 1].Name)" -ForegroundColor Magenta
            Invoke-AsAdmin -ScriptPath $selectedScript
        }
    }
    elseif ($choice -match "^\d+$") {
        $num = [int]$choice
        if ($num -ge 1 -and $num -le $scripts.Count) {
            $selectedScript = $scripts[$num - 1].FullName
            Write-Host "`nExécution: $($scripts[$num - 1].Name)" -ForegroundColor Green
            Write-Host ("-" * 60)

            try {
                & $selectedScript
            }
            catch {
                Write-Host "Erreur: $_" -ForegroundColor Red
            }

            Write-Host ("-" * 60)
            Read-Host "`nAppuyez sur Entrée pour continuer"
        }
    }
} while ($true)

Write-Host "`nAu revoir!" -ForegroundColor Cyan
```

### Fichier Batch Associé

```batch
@echo off
REM ScriptLauncher.bat - Double-cliquer pour lancer le menu
REM Placer dans le même répertoire que ScriptLauncher.ps1

cd /d "%~dp0"
powershell.exe -ExecutionPolicy Bypass -NoProfile -File "%~dp0ScriptLauncher.ps1"
```

---

## Launcher Avancé avec Catégories

```powershell
<#
.SYNOPSIS
    Advanced Script Launcher avec catégories et logging.
#>

#Requires -Version 5.1

param(
    [switch]$NoMenu,
    [string]$RunScript
)

# === Configuration ===
$Config = @{
    ScriptPath    = $PSScriptRoot
    LogPath       = Join-Path $PSScriptRoot "Logs"
    Categories    = @{
        "Install_"   = "Installation"
        "Config_"    = "Configuration"
        "Audit_"     = "Audit & Rapports"
        "Maint_"     = "Maintenance"
        "Deploy_"    = "Déploiement"
    }
    DefaultCategory = "Autres"
}

# === Classes ===
class ScriptInfo {
    [string]$Name
    [string]$FullPath
    [string]$Category
    [string]$Description
    [bool]$RequiresAdmin

    ScriptInfo([System.IO.FileInfo]$file, [hashtable]$categories, [string]$default) {
        $this.Name = $file.BaseName
        $this.FullPath = $file.FullName
        $this.Category = $default

        # Déterminer la catégorie
        foreach ($prefix in $categories.Keys) {
            if ($file.Name.StartsWith($prefix)) {
                $this.Category = $categories[$prefix]
                break
            }
        }

        # Parser les métadonnées du script
        $content = Get-Content $file.FullName -TotalCount 30 -ErrorAction SilentlyContinue
        $this.Description = ($content | Where-Object { $_ -match '^\s*\.SYNOPSIS' } |
                            Select-Object -First 1) -replace '^\s*\.SYNOPSIS\s*', ''
        $this.RequiresAdmin = ($content -match '#Requires\s+-RunAsAdministrator').Count -gt 0
    }
}

# === Fonctions ===
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    # Créer le dossier Logs si nécessaire
    if (-not (Test-Path $Config.LogPath)) {
        New-Item -ItemType Directory -Path $Config.LogPath -Force | Out-Null
    }

    $logFile = Join-Path $Config.LogPath "launcher_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $logFile -Value $logEntry

    # Console
    $color = switch ($Level) {
        "INFO"    { "White" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }
    Write-Host $logEntry -ForegroundColor $color
}

function Get-ScriptsByCategory {
    param([array]$Scripts)

    $grouped = @{}
    foreach ($script in $Scripts) {
        if (-not $grouped.ContainsKey($script.Category)) {
            $grouped[$script.Category] = @()
        }
        $grouped[$script.Category] += $script
    }
    return $grouped
}

function Show-CategoryMenu {
    param([hashtable]$GroupedScripts)

    Clear-Host
    $isAdmin = Test-Administrator

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║              SCRIPT LAUNCHER - MENU PRINCIPAL                ║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan

    # Status Admin
    Write-Host "  ║  Status: " -ForegroundColor Cyan -NoNewline
    if ($isAdmin) {
        Write-Host "ADMINISTRATEUR" -ForegroundColor Green -NoNewline
    } else {
        Write-Host "UTILISATEUR STANDARD" -ForegroundColor Yellow -NoNewline
    }
    Write-Host (" " * (48 - $(if ($isAdmin) { 14 } else { 20 }))) -NoNewline
    Write-Host "║" -ForegroundColor Cyan

    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan

    $index = 1
    $categoryIndex = @{}

    foreach ($category in ($GroupedScripts.Keys | Sort-Object)) {
        $count = $GroupedScripts[$category].Count
        $categoryIndex[$index] = $category

        Write-Host "  ║  " -ForegroundColor Cyan -NoNewline
        Write-Host "[$index]" -ForegroundColor Yellow -NoNewline
        Write-Host " $category " -NoNewline -ForegroundColor White
        Write-Host "($count scripts)" -ForegroundColor DarkGray -NoNewline

        $padding = 60 - 7 - $category.Length - " ($count scripts)".Length
        Write-Host (" " * [Math]::Max(0, $padding)) -NoNewline
        Write-Host "║" -ForegroundColor Cyan

        $index++
    }

    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  " -ForegroundColor Cyan -NoNewline
    Write-Host "[R]" -ForegroundColor Magenta -NoNewline
    Write-Host " Rafraîchir    " -NoNewline
    Write-Host "[L]" -ForegroundColor Magenta -NoNewline
    Write-Host " Logs    " -NoNewline
    Write-Host "[0]" -ForegroundColor Red -NoNewline
    Write-Host " Quitter                   ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    return $categoryIndex
}

function Show-ScriptsMenu {
    param(
        [string]$Category,
        [array]$Scripts
    )

    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║  Catégorie: $Category" -ForegroundColor Cyan -NoNewline
    Write-Host (" " * (50 - $Category.Length)) -NoNewline
    Write-Host "║" -ForegroundColor Cyan
    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan

    for ($i = 0; $i -lt $Scripts.Count; $i++) {
        $script = $Scripts[$i]
        $num = $i + 1
        $adminIcon = if ($script.RequiresAdmin) { "[A]" } else { "   " }

        Write-Host "  ║  " -ForegroundColor Cyan -NoNewline
        Write-Host "[$num]" -ForegroundColor Yellow -NoNewline
        Write-Host " $adminIcon " -ForegroundColor Red -NoNewline
        Write-Host $script.Name -NoNewline

        $padding = 60 - 10 - $script.Name.Length
        Write-Host (" " * [Math]::Max(0, $padding)) -NoNewline
        Write-Host "║" -ForegroundColor Cyan
    }

    Write-Host "  ╠══════════════════════════════════════════════════════════════╣" -ForegroundColor Cyan
    Write-Host "  ║  " -ForegroundColor Cyan -NoNewline
    Write-Host "[A]" -ForegroundColor Red -NoNewline
    Write-Host " = Requiert Admin    " -NoNewline
    Write-Host "[B]" -ForegroundColor Magenta -NoNewline
    Write-Host " Retour    " -NoNewline
    Write-Host "[0]" -ForegroundColor Red -NoNewline
    Write-Host " Quitter      ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Préfixez avec 'admin ' pour forcer l'élévation (ex: admin 1)" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-Script {
    param(
        [ScriptInfo]$Script,
        [switch]$AsAdmin
    )

    Write-Log "Exécution: $($Script.Name)" -Level INFO

    $needsElevation = $Script.RequiresAdmin -or $AsAdmin

    if ($needsElevation -and -not (Test-Administrator)) {
        Write-Log "Élévation requise pour: $($Script.Name)" -Level WARN

        $arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$($Script.FullPath)`""
        Start-Process -FilePath "powershell.exe" -ArgumentList $arguments -Verb RunAs -Wait

        Write-Log "Script terminé (élevé): $($Script.Name)" -Level SUCCESS
    }
    else {
        try {
            & $Script.FullPath
            Write-Log "Script terminé: $($Script.Name)" -Level SUCCESS
        }
        catch {
            Write-Log "Erreur: $($_.Exception.Message)" -Level ERROR
        }
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# === Main ===

# Charger les scripts
$scriptFiles = Get-ChildItem -Path $Config.ScriptPath -Filter "*.ps1" |
               Where-Object { $_.Name -notmatch "^(ScriptLauncher|Launcher)" }

$scripts = $scriptFiles | ForEach-Object {
    [ScriptInfo]::new($_, $Config.Categories, $Config.DefaultCategory)
}

if ($scripts.Count -eq 0) {
    Write-Host "Aucun script trouvé dans: $($Config.ScriptPath)" -ForegroundColor Red
    exit 1
}

# Mode non-interactif
if ($RunScript) {
    $target = $scripts | Where-Object { $_.Name -eq $RunScript }
    if ($target) {
        Invoke-Script -Script $target
    } else {
        Write-Host "Script non trouvé: $RunScript" -ForegroundColor Red
    }
    exit
}

# Mode interactif
$groupedScripts = Get-ScriptsByCategory -Scripts $scripts

do {
    $categoryIndex = Show-CategoryMenu -GroupedScripts $groupedScripts
    $choice = Read-Host "  Choix"

    switch -Regex ($choice) {
        "^0$" {
            Write-Host "`n  Au revoir!" -ForegroundColor Cyan
            exit
        }
        "^[Rr]$" {
            # Rafraîchir
            continue
        }
        "^[Ll]$" {
            # Ouvrir les logs
            if (Test-Path $Config.LogPath) {
                Invoke-Item $Config.LogPath
            }
        }
        "^\d+$" {
            $num = [int]$choice
            if ($categoryIndex.ContainsKey($num)) {
                $selectedCategory = $categoryIndex[$num]
                $categoryScripts = $groupedScripts[$selectedCategory]

                do {
                    Show-ScriptsMenu -Category $selectedCategory -Scripts $categoryScripts
                    $scriptChoice = Read-Host "  Choix"

                    if ($scriptChoice -eq "0") { exit }
                    if ($scriptChoice -match "^[Bb]$") { break }

                    $forceAdmin = $false
                    if ($scriptChoice -match "^admin\s*(\d+)$") {
                        $forceAdmin = $true
                        $scriptChoice = $Matches[1]
                    }

                    if ($scriptChoice -match "^\d+$") {
                        $scriptNum = [int]$scriptChoice
                        if ($scriptNum -ge 1 -and $scriptNum -le $categoryScripts.Count) {
                            $selectedScript = $categoryScripts[$scriptNum - 1]

                            Write-Host ""
                            Write-Host ("=" * 60) -ForegroundColor DarkGray
                            Invoke-Script -Script $selectedScript -AsAdmin:$forceAdmin
                            Write-Host ("=" * 60) -ForegroundColor DarkGray
                            Read-Host "`n  Appuyez sur Entrée pour continuer"
                        }
                    }
                } while ($true)
            }
        }
    }
} while ($true)
```

---

## Créer un Raccourci Bureau

```powershell
# CreateLauncherShortcut.ps1 - Crée un raccourci sur le bureau

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Script Launcher.lnk")

$Shortcut.TargetPath = "powershell.exe"
$Shortcut.Arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$PSScriptRoot\ScriptLauncher.ps1`""
$Shortcut.WorkingDirectory = $PSScriptRoot
$Shortcut.IconLocation = "powershell.exe,0"
$Shortcut.Description = "Lance le menu des scripts PowerShell"
$Shortcut.Save()

Write-Host "Raccourci créé sur le bureau!" -ForegroundColor Green
```

---

## Conventions de Nommage

Pour utiliser les catégories automatiques :

| Préfixe | Catégorie | Exemple |
|---------|-----------|---------|
| `Install_` | Installation | `Install_Office365.ps1` |
| `Config_` | Configuration | `Config_Firewall.ps1` |
| `Audit_` | Audit & Rapports | `Audit_Users.ps1` |
| `Maint_` | Maintenance | `Maint_CleanTemp.ps1` |
| `Deploy_` | Déploiement | `Deploy_Agent.ps1` |

---

## Sécurité : Signer vos Scripts

### Créer un Certificat Auto-Signé (Dev)

```powershell
# Créer un certificat de signature de code
$cert = New-SelfSignedCertificate `
    -Subject "CN=MonEntreprise PowerShell Signing" `
    -Type CodeSigningCert `
    -CertStoreLocation Cert:\CurrentUser\My `
    -NotAfter (Get-Date).AddYears(5)

# Exporter le certificat (pour le distribuer)
Export-Certificate -Cert $cert -FilePath "C:\Certs\PowerShellSigning.cer"

# L'ajouter aux éditeurs de confiance (sur chaque machine)
Import-Certificate -FilePath "C:\Certs\PowerShellSigning.cer" `
                   -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
```

### Signer un Script

```powershell
# Récupérer le certificat
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Subject -match "MonEntreprise" }

# Signer le script
Set-AuthenticodeSignature -FilePath "C:\Scripts\MonScript.ps1" -Certificate $cert

# Vérifier la signature
Get-AuthenticodeSignature -FilePath "C:\Scripts\MonScript.ps1"
```

### Script de Signature en Masse

```powershell
# SignAllScripts.ps1 - Signe tous les scripts d'un répertoire

param(
    [Parameter(Mandatory)]
    [string]$Path,

    [string]$CertSubject = "MonEntreprise"
)

$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert |
        Where-Object { $_.Subject -match $CertSubject } |
        Select-Object -First 1

if (-not $cert) {
    throw "Certificat de signature non trouvé"
}

$scripts = Get-ChildItem -Path $Path -Filter "*.ps1" -Recurse

foreach ($script in $scripts) {
    $sig = Get-AuthenticodeSignature -FilePath $script.FullName

    if ($sig.Status -ne "Valid") {
        Write-Host "Signature: $($script.Name)" -ForegroundColor Yellow
        Set-AuthenticodeSignature -FilePath $script.FullName -Certificate $cert | Out-Null
    }
}

Write-Host "`nTerminé! $($scripts.Count) scripts traités." -ForegroundColor Green
```

---

## GPO : Configurer l'Execution Policy

### Via GPO (Domaine AD)

```text
Computer Configuration
└── Policies
    └── Administrative Templates
        └── Windows Components
            └── Windows PowerShell
                └── Turn on Script Execution
                    → Enabled
                    → Execution Policy: Allow only signed scripts (AllSigned)
                                     ou Allow local scripts and remote signed scripts (RemoteSigned)
```

### Via Registre (Local)

```powershell
# Machine
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" `
                 -Name "ExecutionPolicy" -Value "RemoteSigned"

# Utilisateur
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" `
                 -Name "ExecutionPolicy" -Value "RemoteSigned"
```

---

## Troubleshooting

### Script Bloqué (Zone Internet)

```powershell
# Voir si un fichier est bloqué
Get-Item "script.ps1" -Stream Zone.Identifier -ErrorAction SilentlyContinue

# Débloquer un fichier
Unblock-File -Path "script.ps1"

# Débloquer tous les fichiers d'un répertoire
Get-ChildItem -Path "C:\Scripts" -Recurse | Unblock-File
```

### Vérifier la Signature

```powershell
# Vérifier la signature d'un script
Get-AuthenticodeSignature -FilePath "script.ps1"

# Status possibles :
# - Valid : Signature valide
# - NotSigned : Pas signé
# - HashMismatch : Script modifié après signature
# - UnknownError : Certificat non approuvé
```

### Debugger les Problèmes de Policy

```powershell
# Voir quelle policy bloque
$policy = Get-ExecutionPolicy -List | Where-Object { $_.ExecutionPolicy -ne 'Undefined' }
$policy | Format-Table -AutoSize

# Voir si une GPO force la policy
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell" -ErrorAction SilentlyContinue
```

---

## Voir Aussi

- [PowerShell Fondamentaux](powershell-foundations.md)
- [Modules PowerShell](powershell-modules.md)
- [Tâches Planifiées](scheduled-tasks.md)
