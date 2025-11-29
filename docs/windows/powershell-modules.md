---
tags:
  - windows
  - powershell
  - modules
  - development
---

# PowerShell Modules

Création, publication et gestion des modules PowerShell.

## Concepts

```
STRUCTURE DE MODULE POWERSHELL
══════════════════════════════════════════════════════════

MyModule/
├── MyModule.psd1          Manifeste (métadonnées)
├── MyModule.psm1          Module script (code)
├── Public/                Fonctions exportées
│   ├── Get-Something.ps1
│   └── Set-Something.ps1
├── Private/               Fonctions internes
│   └── Helper.ps1
├── Classes/               Classes PowerShell
│   └── MyClass.ps1
├── en-US/                 Aide localisée
│   └── about_MyModule.help.txt
└── Tests/                 Tests Pester
    └── MyModule.Tests.ps1
```

---

## Création de Module

### Module Simple (Fichier Unique)

```powershell
# MyModule.psm1
function Get-Greeting {
    param([string]$Name = "World")
    "Hello, $Name!"
}

function Set-Greeting {
    param([string]$Prefix)
    $script:GreetingPrefix = $Prefix
}

# Exporter les fonctions
Export-ModuleMember -Function Get-Greeting, Set-Greeting
```

### Créer le Manifeste

```powershell
# Générer un manifeste
New-ModuleManifest -Path "C:\Modules\MyModule\MyModule.psd1" `
    -RootModule "MyModule.psm1" `
    -ModuleVersion "1.0.0" `
    -Author "John Doe" `
    -CompanyName "Corp" `
    -Description "Module de démonstration" `
    -PowerShellVersion "5.1" `
    -FunctionsToExport @("Get-Greeting", "Set-Greeting") `
    -CmdletsToExport @() `
    -VariablesToExport @() `
    -AliasesToExport @() `
    -Tags @("demo", "example") `
    -ProjectUri "https://github.com/corp/mymodule" `
    -LicenseUri "https://github.com/corp/mymodule/LICENSE"
```

### Structure Recommandée

```powershell
# MyModule.psm1 avec chargement automatique
$Public = @(Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue)
$Private = @(Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue)

# Dot source les fichiers
foreach ($import in @($Public + $Private)) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

# Exporter les fonctions publiques
Export-ModuleMember -Function $Public.BaseName

# Public/Get-ServerInfo.ps1
function Get-ServerInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$ComputerName
    )

    process {
        foreach ($computer in $ComputerName) {
            [PSCustomObject]@{
                ComputerName = $computer
                OS = (Get-CimInstance Win32_OperatingSystem -ComputerName $computer).Caption
                Memory = (Get-CimInstance Win32_ComputerSystem -ComputerName $computer).TotalPhysicalMemory
            }
        }
    }
}

# Private/Format-Bytes.ps1
function Format-Bytes {
    param([int64]$Bytes)
    switch ($Bytes) {
        { $_ -gt 1TB } { "{0:N2} TB" -f ($_ / 1TB); break }
        { $_ -gt 1GB } { "{0:N2} GB" -f ($_ / 1GB); break }
        { $_ -gt 1MB } { "{0:N2} MB" -f ($_ / 1MB); break }
        default { "{0:N2} KB" -f ($_ / 1KB) }
    }
}
```

---

## Classes PowerShell

### Définir une Classe

```powershell
# Classes/Server.ps1
class Server {
    [string]$Name
    [string]$IPAddress
    [string]$Role
    [datetime]$LastCheck

    # Constructeur par défaut
    Server() {
        $this.LastCheck = Get-Date
    }

    # Constructeur avec paramètres
    Server([string]$name, [string]$ip) {
        $this.Name = $name
        $this.IPAddress = $ip
        $this.LastCheck = Get-Date
    }

    # Méthode
    [bool] Ping() {
        return Test-Connection -ComputerName $this.Name -Count 1 -Quiet
    }

    # Méthode statique
    static [Server[]] GetAll([string]$OUPath) {
        $servers = Get-ADComputer -Filter * -SearchBase $OUPath
        return $servers | ForEach-Object { [Server]::new($_.Name, $null) }
    }

    # Override ToString
    [string] ToString() {
        return "$($this.Name) ($($this.Role))"
    }
}

# Utilisation
$srv = [Server]::new("server01", "10.10.1.50")
$srv.Role = "WebServer"
$srv.Ping()
```

### Énumérations

```powershell
# Enum
enum ServerRole {
    WebServer
    Database
    DomainController
    FileServer
}

enum ServerStatus {
    Online = 1
    Offline = 2
    Maintenance = 3
}

# Utilisation
[ServerRole]$role = "WebServer"
[ServerStatus]$status = 1  # Online
```

---

## Aide et Documentation

### Aide Basée sur les Commentaires

```powershell
function Get-ServerHealth {
<#
.SYNOPSIS
    Vérifie la santé d'un ou plusieurs serveurs.

.DESCRIPTION
    Cette fonction collecte des métriques de santé (CPU, mémoire, disque)
    pour les serveurs spécifiés et retourne un rapport consolidé.

.PARAMETER ComputerName
    Nom(s) des serveurs à analyser. Accepte le pipeline.

.PARAMETER Credential
    Credentials pour l'authentification distante.

.PARAMETER Threshold
    Seuil d'alerte pour l'utilisation CPU (défaut: 80).

.EXAMPLE
    Get-ServerHealth -ComputerName "server01"

    Vérifie la santé du serveur server01.

.EXAMPLE
    "server01", "server02" | Get-ServerHealth -Threshold 90

    Vérifie la santé de plusieurs serveurs avec un seuil personnalisé.

.INPUTS
    System.String[]

.OUTPUTS
    PSCustomObject

.NOTES
    Auteur: John Doe
    Version: 1.0.0
    Date: 2024-01-15

.LINK
    https://docs.corp.local/Get-ServerHealth
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("CN", "Server")]
        [string[]]$ComputerName,

        [PSCredential]$Credential,

        [ValidateRange(1,100)]
        [int]$Threshold = 80
    )

    begin {
        Write-Verbose "Starting health check..."
    }

    process {
        foreach ($computer in $ComputerName) {
            # Implementation
        }
    }

    end {
        Write-Verbose "Health check complete."
    }
}
```

### Fichier d'Aide About

```
# en-US/about_MyModule.help.txt

TOPIC
    about_MyModule

SHORT DESCRIPTION
    Module pour la gestion des serveurs d'entreprise.

LONG DESCRIPTION
    Ce module fournit des cmdlets pour :
    - Surveiller la santé des serveurs
    - Gérer les configurations
    - Générer des rapports

EXAMPLES
    Import-Module MyModule
    Get-ServerHealth -ComputerName "server01"

SEE ALSO
    Get-ServerHealth
    Set-ServerConfig
    New-ServerReport
```

---

## Tests avec Pester

### Structure de Tests

```powershell
# Tests/Get-ServerHealth.Tests.ps1
BeforeAll {
    $ModulePath = Split-Path -Parent $PSScriptRoot
    Import-Module "$ModulePath\MyModule.psd1" -Force
}

Describe "Get-ServerHealth" {
    Context "Avec des paramètres valides" {
        It "Retourne un objet pour un serveur valide" {
            $result = Get-ServerHealth -ComputerName "localhost"
            $result | Should -Not -BeNullOrEmpty
        }

        It "Accepte le pipeline" {
            $result = "localhost" | Get-ServerHealth
            $result | Should -Not -BeNullOrEmpty
        }

        It "Respecte le threshold personnalisé" {
            $result = Get-ServerHealth -ComputerName "localhost" -Threshold 50
            $result.Threshold | Should -Be 50
        }
    }

    Context "Avec des paramètres invalides" {
        It "Lance une erreur pour un serveur inexistant" {
            { Get-ServerHealth -ComputerName "serveur-inexistant" -ErrorAction Stop } |
                Should -Throw
        }
    }

    Context "Mock des dépendances" {
        BeforeAll {
            Mock Get-CimInstance {
                [PSCustomObject]@{
                    TotalVisibleMemorySize = 16000000
                    FreePhysicalMemory = 8000000
                }
            }
        }

        It "Utilise le mock correctement" {
            $result = Get-ServerHealth -ComputerName "mocked"
            $result.MemoryUsedPercent | Should -Be 50
        }
    }
}

AfterAll {
    Remove-Module MyModule -ErrorAction SilentlyContinue
}
```

### Exécuter les Tests

```powershell
# Installer Pester
Install-Module -Name Pester -Force -SkipPublisherCheck

# Exécuter les tests
Invoke-Pester -Path ".\Tests" -Output Detailed

# Avec couverture de code
Invoke-Pester -Path ".\Tests" -CodeCoverage ".\Public\*.ps1" -Output Detailed
```

---

## Publication

### PowerShell Gallery

```powershell
# Créer une clé API sur PowerShellGallery.com
$apiKey = "votre-api-key"

# Vérifier le module avant publication
Test-ModuleManifest -Path ".\MyModule.psd1"

# Publier
Publish-Module -Path ".\MyModule" -NuGetApiKey $apiKey

# Ou depuis le nom du module
Publish-Module -Name MyModule -NuGetApiKey $apiKey
```

### Repository Privé

```powershell
# Enregistrer un repository privé
Register-PSRepository -Name "CorpRepo" `
    -SourceLocation "https://nuget.corp.local/api/v2" `
    -PublishLocation "https://nuget.corp.local/api/v2/package" `
    -InstallationPolicy Trusted

# Publier vers le repo privé
Publish-Module -Path ".\MyModule" -Repository "CorpRepo" -NuGetApiKey $apiKey

# Installer depuis le repo privé
Install-Module -Name MyModule -Repository "CorpRepo"
```

### Fichier Repository SMB

```powershell
# Créer un repo sur un partage réseau
Register-PSRepository -Name "FileShareRepo" `
    -SourceLocation "\\fileserver\PSModules" `
    -InstallationPolicy Trusted

# Publier
Publish-Module -Path ".\MyModule" -Repository "FileShareRepo"
```

---

## Gestion des Modules

### Installation et Mise à Jour

```powershell
# Rechercher des modules
Find-Module -Name "*Azure*"

# Installer
Install-Module -Name Az -Scope CurrentUser

# Mettre à jour
Update-Module -Name Az

# Voir les modules installés
Get-InstalledModule

# Voir toutes les versions
Get-InstalledModule -Name Az -AllVersions

# Désinstaller
Uninstall-Module -Name Az -AllVersions
```

### Chemins de Modules

```powershell
# Voir les chemins de modules
$env:PSModulePath -split ';'

# Chemins standards :
# User:    $HOME\Documents\PowerShell\Modules
# System:  $PSHOME\Modules
# Program: C:\Program Files\WindowsPowerShell\Modules

# Ajouter un chemin
$env:PSModulePath += ";C:\CustomModules"
```

---

## Bonnes Pratiques

```yaml
Checklist Module:
  Structure:
    - [ ] Séparation Public/Private
    - [ ] Manifeste complet (psd1)
    - [ ] Versionning sémantique
    - [ ] Documentation (aide en commentaires)

  Code:
    - [ ] CmdletBinding sur toutes les fonctions
    - [ ] Paramètres typés et validés
    - [ ] Support du pipeline
    - [ ] Gestion des erreurs

  Qualité:
    - [ ] Tests Pester
    - [ ] Couverture de code > 80%
    - [ ] PSScriptAnalyzer sans warnings
    - [ ] CI/CD pour publication

  Distribution:
    - [ ] README.md
    - [ ] CHANGELOG.md
    - [ ] LICENSE
    - [ ] Exemples d'utilisation
```

### Script Analyzer

```powershell
# Installer PSScriptAnalyzer
Install-Module -Name PSScriptAnalyzer

# Analyser un module
Invoke-ScriptAnalyzer -Path ".\MyModule" -Recurse

# Avec des règles spécifiques
Invoke-ScriptAnalyzer -Path ".\MyModule" -ExcludeRule PSUseShouldProcessForStateChangingFunctions
```

---

**Voir aussi :**

- [PowerShell Remoting](powershell-remoting.md) - Administration à distance
- [PowerShell DSC](powershell-dsc.md) - Configuration as Code
- [Windows Security](windows-security.md) - Sécurité
