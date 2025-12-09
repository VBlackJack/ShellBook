---
tags:
  - windows
  - iis
  - web-server
  - asp-net
---

# IIS - Internet Information Services

Configuration et administration du serveur web IIS : sites, app pools, bindings, et certificats.

## Architecture

```text
ARCHITECTURE IIS
══════════════════════════════════════════════════════════

                    ┌─────────────────────────────────┐
                    │          HTTP.sys               │
                    │    (Kernel-mode driver)         │
                    │    Port 80/443 listener         │
                    └──────────────┬──────────────────┘
                                   │
                    ┌──────────────▼──────────────────┐
                    │      W3SVC (World Wide Web      │
                    │      Publishing Service)        │
                    └──────────────┬──────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        ▼                          ▼                          ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│  App Pool 1   │        │  App Pool 2   │        │  App Pool 3   │
│  (w3wp.exe)   │        │  (w3wp.exe)   │        │  (w3wp.exe)   │
├───────────────┤        ├───────────────┤        ├───────────────┤
│   Site A      │        │   Site B      │        │   Site C      │
│   Site B      │        │   App 1       │        │               │
└───────────────┘        └───────────────┘        └───────────────┘

Concepts clés :
• Site : Conteneur pour contenu web (host headers, ports)
• Application : Sous-ensemble d'un site avec son propre pool
• App Pool : Processus worker isolé (identité, recyclage)
• Virtual Directory : Mapping vers un dossier physique
```

---

## Installation

### Rôles et Fonctionnalités

```powershell
# Installation basique (Web Server)
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Installation complète pour ASP.NET
Install-WindowsFeature -Name Web-Server,Web-Asp-Net45,Web-Net-Ext45,`
    Web-ISAPI-Ext,Web-ISAPI-Filter,Web-Mgmt-Console,Web-Mgmt-Service

# Fonctionnalités courantes
$features = @(
    "Web-Server",
    "Web-WebServer",
    "Web-Common-Http",
    "Web-Static-Content",
    "Web-Default-Doc",
    "Web-Dir-Browsing",
    "Web-Http-Errors",
    "Web-App-Dev",
    "Web-Asp-Net45",
    "Web-Net-Ext45",
    "Web-ISAPI-Ext",
    "Web-ISAPI-Filter",
    "Web-Health",
    "Web-Http-Logging",
    "Web-Log-Libraries",
    "Web-Request-Monitor",
    "Web-Security",
    "Web-Filtering",
    "Web-Basic-Auth",
    "Web-Windows-Auth",
    "Web-Performance",
    "Web-Stat-Compression",
    "Web-Dyn-Compression",
    "Web-Mgmt-Tools",
    "Web-Mgmt-Console",
    "Web-Scripting-Tools"
)
Install-WindowsFeature -Name $features

# Vérifier l'installation
Get-WindowsFeature Web-* | Where-Object Installed | Select-Object Name
```

### Module PowerShell

```powershell
# Le module WebAdministration est inclus
Import-Module WebAdministration

# Accès via PSDrive
Get-PSDrive IIS
Set-Location IIS:\Sites
Get-ChildItem

# Module IISAdministration (moderne, recommandé)
Import-Module IISAdministration
```

---

## Gestion des Sites

### Créer un Site

```powershell
# Créer le dossier
New-Item -Path "C:\inetpub\mysite" -ItemType Directory

# Créer le site
New-IISSite -Name "MySite" `
    -PhysicalPath "C:\inetpub\mysite" `
    -BindingInformation "*:80:mysite.corp.local"

# Ou avec New-Website (WebAdministration)
New-Website -Name "MySite" `
    -PhysicalPath "C:\inetpub\mysite" `
    -Port 80 `
    -HostHeader "mysite.corp.local" `
    -ApplicationPool "MySitePool"
```

### Bindings

```powershell
# Lister les bindings
Get-IISSiteBinding -Name "MySite"

# Ajouter un binding HTTP
New-IISSiteBinding -Name "MySite" `
    -BindingInformation "*:80:www.mysite.com" `
    -Protocol http

# Ajouter un binding HTTPS
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "*mysite*"
New-IISSiteBinding -Name "MySite" `
    -BindingInformation "*:443:mysite.corp.local" `
    -Protocol https `
    -CertificateThumbPrint $cert.Thumbprint `
    -CertStoreLocation "Cert:\LocalMachine\My"

# Supprimer un binding
Remove-IISSiteBinding -Name "MySite" -BindingInformation "*:80:old.mysite.com"

# Modifier (via WebAdministration)
Set-WebBinding -Name "MySite" -BindingInformation "*:80:" -PropertyName Port -Value 8080
```

### Gérer les Sites

```powershell
# Lister les sites
Get-IISSite
Get-Website  # WebAdministration

# Démarrer/Arrêter
Start-IISSite -Name "MySite"
Stop-IISSite -Name "MySite"

# Statut
Get-IISSite -Name "MySite" | Select-Object Name, State

# Supprimer
Remove-IISSite -Name "MySite" -Confirm:$false
```

---

## Application Pools

### Créer un App Pool

```powershell
# Créer un pool
New-IISAppPool -Name "MySitePool"

# Configurer
$pool = Get-IISAppPool -Name "MySitePool"
$pool.ManagedRuntimeVersion = "v4.0"
$pool.ManagedPipelineMode = "Integrated"  # ou "Classic"
$pool.Enable32BitAppOnWin64 = $false
$pool | Set-IISAppPool

# Configuration complète
$poolDefaults = @{
    managedRuntimeVersion = "v4.0"
    managedPipelineMode = "Integrated"
    startMode = "AlwaysRunning"
    processModel = @{
        identityType = "ApplicationPoolIdentity"  # ou "SpecificUser"
        idleTimeout = "00:20:00"
        loadUserProfile = $true
    }
    recycling = @{
        periodicRestart = @{
            time = "00:00:00"  # Désactiver recyclage périodique
            schedule = @(
                @{ value = "03:00:00" }  # Recycler à 3h du matin
            )
        }
    }
}
```

### Identité du Pool

```powershell
# Types d'identité :
# - ApplicationPoolIdentity (défaut, recommandé)
# - NetworkService
# - LocalService
# - LocalSystem
# - SpecificUser

# Configurer un compte de service
$pool = Get-IISAppPool -Name "MySitePool"
$pool.ProcessModel.IdentityType = "SpecificUser"
$pool.ProcessModel.UserName = "CORP\svc_web"
$pool.ProcessModel.Password = "P@ssw0rd"
$pool | Set-IISAppPool

# Via WebAdministration
Set-ItemProperty "IIS:\AppPools\MySitePool" -Name processModel.identityType -Value 3
Set-ItemProperty "IIS:\AppPools\MySitePool" -Name processModel.userName -Value "CORP\svc_web"
Set-ItemProperty "IIS:\AppPools\MySitePool" -Name processModel.password -Value "P@ssw0rd"
```

### Recyclage

```powershell
# Configuration du recyclage
Set-ItemProperty "IIS:\AppPools\MySitePool" -Name recycling.periodicRestart.time -Value "00:00:00"

# Recycler à des heures spécifiques
Clear-ItemProperty "IIS:\AppPools\MySitePool" -Name recycling.periodicRestart.schedule
Add-WebConfiguration "/system.applicationHost/applicationPools/add[@name='MySitePool']/recycling/periodicRestart/schedule" -Value @{value="02:00:00"}
Add-WebConfiguration "/system.applicationHost/applicationPools/add[@name='MySitePool']/recycling/periodicRestart/schedule" -Value @{value="14:00:00"}

# Recycler sur mémoire
Set-ItemProperty "IIS:\AppPools\MySitePool" -Name recycling.periodicRestart.privateMemory -Value 1048576  # 1GB

# Recycler manuellement
Restart-WebAppPool -Name "MySitePool"

# Ou via IISAdministration
(Get-IISAppPool -Name "MySitePool").Recycle()
```

---

## Applications et Virtual Directories

### Applications

```powershell
# Créer une application dans un site
New-WebApplication -Site "MySite" `
    -Name "api" `
    -PhysicalPath "C:\inetpub\mysite\api" `
    -ApplicationPool "MySitePool"

# L'application sera accessible à : http://mysite.corp.local/api

# Lister les applications
Get-WebApplication -Site "MySite"

# Supprimer
Remove-WebApplication -Site "MySite" -Name "api"
```

### Virtual Directories

```powershell
# Créer un virtual directory
New-WebVirtualDirectory -Site "MySite" `
    -Name "docs" `
    -PhysicalPath "D:\SharedDocs"

# Accessible à : http://mysite.corp.local/docs

# Avec authentification pour UNC path
New-WebVirtualDirectory -Site "MySite" `
    -Name "shared" `
    -PhysicalPath "\\fileserver\share" `
    -UserName "CORP\svc_iis" `
    -Password "P@ssw0rd"

# Lister
Get-WebVirtualDirectory -Site "MySite"
```

---

## Certificats SSL/TLS

### Importer un Certificat

```powershell
# Importer un PFX
$password = ConvertTo-SecureString "CertPassword" -AsPlainText -Force
Import-PfxCertificate -FilePath "C:\Certs\mysite.pfx" `
    -CertStoreLocation Cert:\LocalMachine\My `
    -Password $password

# Lister les certificats
Get-ChildItem Cert:\LocalMachine\My | Select-Object Thumbprint, Subject, NotAfter

# Créer un certificat auto-signé (dev/test)
New-SelfSignedCertificate -DnsName "mysite.corp.local","www.mysite.corp.local" `
    -CertStoreLocation Cert:\LocalMachine\My `
    -NotAfter (Get-Date).AddYears(2)
```

### Configurer HTTPS

```powershell
# Obtenir le thumbprint
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "*mysite*"

# Ajouter binding HTTPS
New-IISSiteBinding -Name "MySite" `
    -BindingInformation "*:443:mysite.corp.local" `
    -Protocol https `
    -CertificateThumbPrint $cert.Thumbprint `
    -CertStoreLocation "Cert:\LocalMachine\My"

# Configurer SSL (exiger HTTPS)
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/security/access" `
    -Name "sslFlags" `
    -Value "Ssl,SslNegotiateCert"
```

### Redirection HTTP vers HTTPS

```powershell
# Via URL Rewrite (nécessite le module)
# Installer : Web Platform Installer > URL Rewrite

# Ou via web.config
$webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <rewrite>
            <rules>
                <rule name="HTTP to HTTPS" stopProcessing="true">
                    <match url="(.*)" />
                    <conditions>
                        <add input="{HTTPS}" pattern="off" ignoreCase="true" />
                    </conditions>
                    <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
                </rule>
            </rules>
        </rewrite>
    </system.webServer>
</configuration>
"@

$webConfig | Out-File "C:\inetpub\mysite\web.config" -Encoding UTF8
```

---

## Authentification

### Types d'Authentification

```powershell
# Voir les authentifications configurées
Get-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/security/authentication/*" `
    -Name "enabled"

# Activer/Désactiver l'authentification anonyme
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/security/authentication/anonymousAuthentication" `
    -Name "enabled" `
    -Value $false

# Activer Windows Authentication
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/security/authentication/windowsAuthentication" `
    -Name "enabled" `
    -Value $true

# Configurer les providers Windows Auth
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/security/authentication/windowsAuthentication/providers" `
    -Name "." `
    -Value @{value="Negotiate";"NTLM"}
```

### Basic Authentication

```powershell
# Activer Basic Auth
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/security/authentication/basicAuthentication" `
    -Name "enabled" `
    -Value $true

# ⚠️ Basic Auth transmet les credentials en Base64 (pas chiffré)
# → Toujours utiliser avec HTTPS
```

---

## Logging et Monitoring

### Configurer les Logs

```powershell
# Emplacement des logs
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.applicationHost/sites/site[@name='MySite']/logFile" `
    -Name "directory" `
    -Value "D:\Logs\IIS"

# Format de log (W3C recommandé)
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.applicationHost/sites/site[@name='MySite']/logFile" `
    -Name "logFormat" `
    -Value "W3C"

# Rotation quotidienne
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.applicationHost/sites/site[@name='MySite']/logFile" `
    -Name "period" `
    -Value "Daily"

# Champs à logger
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.applicationHost/sites/site[@name='MySite']/logFile" `
    -Name "logExtFileFlags" `
    -Value "Date,Time,ClientIP,UserName,ServerIP,Method,UriStem,UriQuery,HttpStatus,TimeTaken,UserAgent"
```

### Failed Request Tracing

```powershell
# Activer le tracing
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/tracing/traceFailedRequests" `
    -Name "enabled" `
    -Value $true

# Configurer les règles (tracer les erreurs 500)
Add-WebConfiguration -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/tracing/traceFailedRequests" `
    -Value @{
        path = "*"
        provider = "WWW Server"
        traceAllAfterTimeout = $true
    }
```

### Monitoring

```powershell
# Statut des sites
Get-IISSite | Select-Object Name, State, Bindings

# Statut des pools
Get-IISAppPool | Select-Object Name, State, ManagedRuntimeVersion

# Worker processes
Get-Process w3wp | Select-Object Id, CPU, WorkingSet64, @{N='Pool';E={
    (Get-WmiObject Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine -replace '.*-ap "(.+?)".*','$1'
}}

# Requêtes en cours
Get-WebRequest | Select-Object url, timeElapsed, clientIP
```

---

## Performances

### Configuration Recommandée

```powershell
# Compression dynamique
Set-WebConfigurationProperty -PSPath "MACHINE/WEBROOT/APPHOST" `
    -Filter "system.webServer/urlCompression" `
    -Name "doDynamicCompression" `
    -Value $true

# Output caching
Add-WebConfiguration -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/caching/profiles" `
    -Value @{
        extension = ".aspx"
        policy = "CacheUntilChange"
        kernelCachePolicy = "CacheUntilChange"
    }

# App Pool - Always Running (évite cold start)
Set-ItemProperty "IIS:\AppPools\MySitePool" -Name startMode -Value "AlwaysRunning"
Set-ItemProperty "IIS:\AppPools\MySitePool" -Name processModel.idleTimeout -Value "00:00:00"

# Application Initialization (préchauffe)
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/applicationInitialization" `
    -Name "doAppInitAfterRestart" `
    -Value $true
```

---

## Sécurité

### Request Filtering

```powershell
# Bloquer des extensions
Add-WebConfiguration -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/security/requestFiltering/fileExtensions" `
    -Value @{fileExtension=".config"; allowed=$false}

# Limiter les verbes HTTP
Set-WebConfiguration -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/security/requestFiltering/verbs" `
    -Value @{verb="TRACE"; allowed=$false}

# Limiter la taille des requêtes
Set-WebConfigurationProperty -PSPath "IIS:\Sites\MySite" `
    -Filter "system.webServer/security/requestFiltering/requestLimits" `
    -Name "maxAllowedContentLength" `
    -Value 30000000  # 30MB
```

### Headers de Sécurité

```xml
<!-- web.config -->
<configuration>
    <system.webServer>
        <httpProtocol>
            <customHeaders>
                <add name="X-Content-Type-Options" value="nosniff" />
                <add name="X-Frame-Options" value="SAMEORIGIN" />
                <add name="X-XSS-Protection" value="1; mode=block" />
                <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains" />
                <remove name="X-Powered-By" />
            </customHeaders>
        </httpProtocol>
    </system.webServer>
</configuration>
```

---

## Bonnes Pratiques

```yaml
Checklist IIS:
  Configuration:
    - [ ] Un App Pool par application
    - [ ] Identité ApplicationPoolIdentity
    - [ ] Recycling à heure fixe (nuit)
    - [ ] Logs sur partition séparée

  Sécurité:
    - [ ] HTTPS obligatoire
    - [ ] Headers de sécurité
    - [ ] Request filtering actif
    - [ ] Authentification Windows si intranet

  Performance:
    - [ ] Compression activée
    - [ ] Always Running pour apps critiques
    - [ ] Application Initialization
    - [ ] Output caching si applicable

  Monitoring:
    - [ ] Failed Request Tracing
    - [ ] Logs W3C avec TimeTaken
    - [ ] Alertes sur erreurs 500
```

---

**Voir aussi :**

- [Certificate Services](certificate-services.md) - Gestion PKI
- [Windows Firewall](windows-firewall.md) - Règles pare-feu
- [Performance Monitoring](performance-monitoring.md) - Monitoring
