---
tags:
  - windows
  - powershell
  - dsc
  - configuration-management
---

# PowerShell DSC

Desired State Configuration (DSC) pour la gestion de configuration déclarative.

## Concepts

```
DSC ARCHITECTURE
══════════════════════════════════════════════════════════

Configuration (.ps1)  →  MOF File  →  LCM  →  Target Node
                              ↓
                      ┌──────────────────┐
                      │  Local Config    │
                      │  Manager (LCM)   │
                      │                  │
                      │  • Push Mode     │
                      │  • Pull Mode     │
                      │  • Compliance    │
                      └──────────────────┘
                              ↓
                      ┌──────────────────┐
                      │   Resources      │
                      │   (built-in &    │
                      │    community)    │
                      └──────────────────┘
```

---

## Configuration de Base

### Structure d'une Configuration

```powershell
# Définition de configuration
Configuration MyServerConfig {
    # Importer les modules de ressources
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName ComputerManagementDsc

    # Paramètres
    param (
        [string[]]$ComputerName = "localhost"
    )

    # Noeud cible
    Node $ComputerName {
        # Ressource: Fonctionnalité Windows
        WindowsFeature IIS {
            Name   = "Web-Server"
            Ensure = "Present"
        }

        # Ressource: Service
        Service W3SVC {
            Name        = "W3SVC"
            StartupType = "Automatic"
            State       = "Running"
            DependsOn   = "[WindowsFeature]IIS"
        }

        # Ressource: Fichier
        File WebContent {
            DestinationPath = "C:\inetpub\wwwroot\index.html"
            Contents        = "<html><body><h1>Hello DSC</h1></body></html>"
            Ensure          = "Present"
            Type            = "File"
            DependsOn       = "[WindowsFeature]IIS"
        }
    }
}

# Générer le MOF
MyServerConfig -OutputPath "C:\DSC\MyServerConfig"

# Appliquer la configuration
Start-DscConfiguration -Path "C:\DSC\MyServerConfig" -Wait -Verbose -Force
```

### Ressources Built-in

```powershell
Configuration CommonResources {
    Node "localhost" {
        # Fichier ou dossier
        File CreateFolder {
            DestinationPath = "C:\MyApp"
            Type            = "Directory"
            Ensure          = "Present"
        }

        # Copier depuis une source
        File CopyConfig {
            SourcePath      = "\\fileserver\configs\app.config"
            DestinationPath = "C:\MyApp\app.config"
            Ensure          = "Present"
            Type            = "File"
            Checksum        = "SHA-256"
        }

        # Archive (ZIP)
        Archive ExtractApp {
            Path        = "C:\Downloads\app.zip"
            Destination = "C:\MyApp"
            Ensure      = "Present"
        }

        # Variable d'environnement
        Environment SetPath {
            Name   = "MYAPP_HOME"
            Value  = "C:\MyApp"
            Ensure = "Present"
            Target = "Machine"
        }

        # Clé de registre
        Registry EnableFeature {
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\MyApp"
            ValueName = "Enabled"
            ValueData = "1"
            ValueType = "Dword"
            Ensure    = "Present"
        }

        # Script personnalisé
        Script CustomAction {
            GetScript = { @{ Result = (Test-Path "C:\MyApp\installed.txt") } }
            TestScript = { Test-Path "C:\MyApp\installed.txt" }
            SetScript = {
                # Actions à effectuer
                New-Item "C:\MyApp\installed.txt" -Force
            }
        }

        # Utilisateur local
        User AppServiceAccount {
            UserName                 = "AppSvc"
            Password                 = $Node.AppSvcPassword
            PasswordNeverExpires     = $true
            PasswordChangeNotAllowed = $true
            Ensure                   = "Present"
        }

        # Groupe local
        Group AppAdmins {
            GroupName        = "AppAdministrators"
            MembersToInclude = @("CORP\AppAdmins", "AppSvc")
            Ensure           = "Present"
        }
    }
}
```

---

## Configuration LCM

### Local Configuration Manager

```powershell
# Voir la configuration LCM actuelle
Get-DscLocalConfigurationManager

# Configurer le LCM
[DSCLocalConfigurationManager()]
Configuration LCMConfig {
    Node "localhost" {
        Settings {
            RefreshMode                    = "Push"  # ou "Pull"
            ConfigurationMode              = "ApplyAndAutoCorrect"  # ApplyOnly, ApplyAndMonitor
            ConfigurationModeFrequencyMins = 15
            RebootNodeIfNeeded             = $true
            ActionAfterReboot              = "ContinueConfiguration"
            AllowModuleOverwrite           = $true
        }
    }
}

LCMConfig -OutputPath "C:\DSC\LCM"
Set-DscLocalConfigurationManager -Path "C:\DSC\LCM" -Verbose
```

### Modes de Configuration

```
MODES LCM
══════════════════════════════════════════════════════════

RefreshMode:
  Push    Configuration poussée manuellement
  Pull    Configuration tirée depuis un serveur

ConfigurationMode:
  ApplyOnly           Applique une fois, ne vérifie plus
  ApplyAndMonitor     Applique et rapporte les dérives
  ApplyAndAutoCorrect Applique et corrige automatiquement
```

---

## Pull Server

### Installation

```powershell
# Installer les fonctionnalités requises
Install-WindowsFeature -Name DSC-Service, Web-Server -IncludeManagementTools

# Configurer le Pull Server
Configuration DscPullServer {
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Node "localhost" {
        WindowsFeature DSCService {
            Name   = "DSC-Service"
            Ensure = "Present"
        }

        xDscWebService PullServer {
            Endpoint            = "https://pullserver.corp.local:8080/PSDSCPullServer.svc"
            Port                = 8080
            PhysicalPath        = "C:\inetpub\PullServer"
            CertificateThumbprint = "AllowUnencryptedTraffic"  # ou thumbprint réel
            ModulePath          = "C:\Program Files\WindowsPowerShell\DscService\Modules"
            ConfigurationPath   = "C:\Program Files\WindowsPowerShell\DscService\Configuration"
            State               = "Started"
            DependsOn           = "[WindowsFeature]DSCService"
        }
    }
}
```

### Configuration Client Pull

```powershell
[DSCLocalConfigurationManager()]
Configuration PullClientConfig {
    Node "localhost" {
        Settings {
            RefreshMode          = "Pull"
            ConfigurationMode    = "ApplyAndAutoCorrect"
            RefreshFrequencyMins = 30
        }

        ConfigurationRepositoryWeb PullServer {
            ServerURL          = "https://pullserver.corp.local:8080/PSDSCPullServer.svc"
            RegistrationKey    = "abc123-registration-key"
            ConfigurationNames = @("WebServerConfig")
        }

        ReportServerWeb ReportServer {
            ServerURL       = "https://pullserver.corp.local:8080/PSDSCPullServer.svc"
            RegistrationKey = "abc123-registration-key"
        }
    }
}
```

---

## Configurations Avancées

### Données de Configuration

```powershell
# Fichier de données (ConfigData.psd1)
@{
    AllNodes = @(
        @{
            NodeName                    = "*"
            PSDscAllowPlainTextPassword = $true  # Non recommandé en prod
        },
        @{
            NodeName = "WebServer01"
            Role     = "WebServer"
            Features = @("Web-Server", "Web-Asp-Net45")
        },
        @{
            NodeName = "WebServer02"
            Role     = "WebServer"
            Features = @("Web-Server", "Web-Asp-Net45")
        },
        @{
            NodeName = "DBServer01"
            Role     = "Database"
            Features = @()
        }
    )
    NonNodeData = @{
        DomainName = "corp.local"
        OUPath     = "OU=Servers,DC=corp,DC=local"
    }
}

# Configuration utilisant les données
Configuration MultiServerConfig {
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node $AllNodes.Where{$_.Role -eq "WebServer"}.NodeName {
        foreach ($feature in $Node.Features) {
            WindowsFeature $feature {
                Name   = $feature
                Ensure = "Present"
            }
        }
    }

    Node $AllNodes.Where{$_.Role -eq "Database"}.NodeName {
        # Configuration DB
    }
}

# Générer avec ConfigData
$configData = Import-PowerShellDataFile "C:\DSC\ConfigData.psd1"
MultiServerConfig -ConfigurationData $configData -OutputPath "C:\DSC\Output"
```

### Credentials Sécurisés

```powershell
# Certificat pour chiffrer les mots de passe
$cert = New-SelfSignedCertificate -Type DocumentEncryptionCertLegacyCsp `
    -DnsName "DscEncryptionCert" `
    -HashAlgorithm SHA256

# ConfigData avec certificat
$configData = @{
    AllNodes = @(
        @{
            NodeName                    = "Server01"
            CertificateFile             = "C:\Certs\DscPublicKey.cer"
            Thumbprint                  = $cert.Thumbprint
            PSDscAllowDomainUser        = $true
        }
    )
}

# Configuration avec credential
Configuration SecureConfig {
    param (
        [PSCredential]$Credential
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node $AllNodes.NodeName {
        User ServiceAccount {
            UserName = "SvcAccount"
            Password = $Credential
            Ensure   = "Present"
        }
    }
}

$cred = Get-Credential
SecureConfig -ConfigurationData $configData -Credential $cred -OutputPath "C:\DSC"
```

### Configurations Composites

```powershell
# Configuration composite (réutilisable)
Configuration BaseServerConfig {
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    WindowsFeature Telnet {
        Name   = "Telnet-Client"
        Ensure = "Present"
    }

    Service WinRM {
        Name        = "WinRM"
        StartupType = "Automatic"
        State       = "Running"
    }
}

# Utilisation dans une autre config
Configuration FullServerConfig {
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node "Server01" {
        BaseServerConfig Base {}

        WindowsFeature IIS {
            Name   = "Web-Server"
            Ensure = "Present"
        }
    }
}
```

---

## Modules de Ressources

### Modules Populaires

```powershell
# Installer des modules DSC
Install-Module -Name ComputerManagementDsc
Install-Module -Name NetworkingDsc
Install-Module -Name SqlServerDsc
Install-Module -Name ActiveDirectoryDsc
Install-Module -Name xWebAdministration

# Voir les ressources disponibles
Get-DscResource
Get-DscResource -Module ComputerManagementDsc

# Documentation d'une ressource
Get-DscResource -Name Computer -Syntax
```

### Créer une Ressource Custom

```powershell
# Structure du module
# MyDscResource/
#   ├── MyDscResource.psd1
#   └── DSCResources/
#       └── MyResource/
#           ├── MyResource.schema.mof
#           └── MyResource.psm1

# MyResource.schema.mof
[ClassVersion("1.0.0"), FriendlyName("MyResource")]
class MyResource : OMI_BaseResource
{
    [Key] String Name;
    [Write] String Value;
    [Write, ValueMap{"Present","Absent"}] String Ensure;
};

# MyResource.psm1
function Get-TargetResource {
    param([string]$Name, [string]$Value, [string]$Ensure)
    # Retourner l'état actuel
    @{ Name = $Name; Value = "current"; Ensure = "Present" }
}

function Set-TargetResource {
    param([string]$Name, [string]$Value, [string]$Ensure)
    # Appliquer la configuration
}

function Test-TargetResource {
    param([string]$Name, [string]$Value, [string]$Ensure)
    # Retourner $true si conforme, $false sinon
    return $false
}

Export-ModuleMember -Function *-TargetResource
```

---

## Opérations

### Appliquer et Vérifier

```powershell
# Appliquer une configuration
Start-DscConfiguration -Path "C:\DSC\Config" -Wait -Verbose -Force

# Tester la conformité
Test-DscConfiguration -Detailed

# Voir la configuration actuelle
Get-DscConfiguration

# Voir la configuration désirée
Get-DscConfigurationStatus

# Forcer une resynchronisation
Update-DscConfiguration -Wait -Verbose
```

### Supprimer une Configuration

```powershell
# Supprimer la configuration MOF
Remove-DscConfigurationDocument -Stage Current, Previous, Pending

# Remettre le LCM en état initial
[DSCLocalConfigurationManager()]
Configuration ResetLCM {
    Node "localhost" {
        Settings {
            RefreshMode = "Push"
        }
    }
}
ResetLCM -OutputPath "C:\DSC"
Set-DscLocalConfigurationManager -Path "C:\DSC" -Force
```

---

## Troubleshooting

```powershell
# Logs DSC
Get-WinEvent -LogName "Microsoft-Windows-DSC/Operational" -MaxEvents 50

# Logs détaillés
Get-WinEvent -LogName "Microsoft-Windows-DSC/Analytic" -MaxEvents 50

# État du dernier run
Get-DscConfigurationStatus -All

# Debug mode
$DebugPreference = "Continue"
Start-DscConfiguration -Path "C:\DSC\Config" -Wait -Verbose -Debug

# Erreurs communes
# - "Resource not found" → Installer le module DSC
# - "Access denied" → Vérifier les permissions et credentials
# - "MOF syntax error" → Valider le fichier MOF
```

---

## Bonnes Pratiques

```yaml
Checklist DSC:
  Design:
    - [ ] Configurations modulaires et réutilisables
    - [ ] Données séparées du code (ConfigData)
    - [ ] Credentials chiffrés avec certificats
    - [ ] Versionner les configurations (Git)

  Déploiement:
    - [ ] Tester en dev avant prod
    - [ ] Mode ApplyAndAutoCorrect pour auto-remediation
    - [ ] Pull Server pour environnements larges
    - [ ] Reporting centralisé

  Maintenance:
    - [ ] Monitoring de la conformité
    - [ ] Alertes sur les dérives
    - [ ] Documentation des configurations
    - [ ] Plan de rollback
```

---

**Voir aussi :**

- [PowerShell Remoting](powershell-remoting.md) - Administration à distance
- [PowerShell Modules](powershell-modules.md) - Création de modules
- [Windows Security](windows-security.md) - Sécurité Windows
