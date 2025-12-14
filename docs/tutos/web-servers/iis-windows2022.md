---
tags:
  - tutos
  - iis
  - php
  - windows
  - web-server
---

# IIS + PHP sur Windows Server 2022

Stack **IIS** (Internet Information Services) avec support **PHP** sur Windows Server 2022.

| Composant | Version |
|-----------|---------|
| Windows Server | 2022 |
| IIS | 10.0 |
| PHP | 8.2 |

**Durée estimée :** 30 minutes

**Prérequis :**

- Windows Server 2022 installé
- Accès Administrateur
- Connexion internet

---

## 1. Installation d'IIS

### Via PowerShell (recommandé)

```powershell
# Installer IIS avec les fonctionnalités essentielles
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Installer les modules supplémentaires utiles
Install-WindowsFeature -Name `
    Web-Default-Doc, `
    Web-Dir-Browsing, `
    Web-Http-Errors, `
    Web-Static-Content, `
    Web-Http-Logging, `
    Web-Stat-Compression, `
    Web-Dyn-Compression, `
    Web-Filtering, `
    Web-CGI, `
    Web-ISAPI-Ext, `
    Web-ISAPI-Filter

# Vérifier l'installation
Get-WindowsFeature -Name Web-* | Where-Object Installed -eq $true
```

### Vérifier le service

```powershell
# Vérifier le statut du service
Get-Service -Name W3SVC

# Démarrer si nécessaire
Start-Service -Name W3SVC

# Configurer le démarrage automatique
Set-Service -Name W3SVC -StartupType Automatic
```

### Test

```powershell
# Tester localement
Invoke-WebRequest -Uri http://localhost -UseBasicParsing | Select-Object StatusCode
```

Ouvrir un navigateur sur `http://localhost` - la page par défaut IIS doit s'afficher.

---

## 2. Configuration du Firewall

```powershell
# Vérifier les règles existantes
Get-NetFirewallRule -DisplayName "*IIS*" | Select-Object DisplayName, Enabled

# Autoriser HTTP (80) si non configuré
New-NetFirewallRule -DisplayName "HTTP (80)" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow

# Autoriser HTTPS (443)
New-NetFirewallRule -DisplayName "HTTPS (443)" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
```

---

## 3. Installation de PHP

### Télécharger PHP

```powershell
# Créer le répertoire PHP
New-Item -Path "C:\PHP" -ItemType Directory -Force

# Télécharger PHP 8.2 (Non-Thread Safe pour IIS)
$phpUrl = "https://windows.php.net/downloads/releases/php-8.2.13-nts-Win32-vs16-x64.zip"
$phpZip = "C:\Temp\php.zip"

New-Item -Path "C:\Temp" -ItemType Directory -Force
Invoke-WebRequest -Uri $phpUrl -OutFile $phpZip

# Extraire
Expand-Archive -Path $phpZip -DestinationPath "C:\PHP" -Force

# Nettoyer
Remove-Item $phpZip
```

!!! info "Version PHP"
    Vérifiez la dernière version sur [windows.php.net](https://windows.php.net/download/).
    Utilisez toujours la version **Non-Thread Safe (NTS)** pour IIS + FastCGI.

### Configurer PHP

```powershell
# Copier le fichier de configuration
Copy-Item "C:\PHP\php.ini-production" "C:\PHP\php.ini"

# Configurer php.ini
$phpIni = "C:\PHP\php.ini"

# Activer les extensions essentielles
(Get-Content $phpIni) -replace ';extension_dir = "ext"', 'extension_dir = "C:\PHP\ext"' | Set-Content $phpIni
(Get-Content $phpIni) -replace ';extension=curl', 'extension=curl' | Set-Content $phpIni
(Get-Content $phpIni) -replace ';extension=gd', 'extension=gd' | Set-Content $phpIni
(Get-Content $phpIni) -replace ';extension=mbstring', 'extension=mbstring' | Set-Content $phpIni
(Get-Content $phpIni) -replace ';extension=mysqli', 'extension=mysqli' | Set-Content $phpIni
(Get-Content $phpIni) -replace ';extension=openssl', 'extension=openssl' | Set-Content $phpIni
(Get-Content $phpIni) -replace ';extension=pdo_mysql', 'extension=pdo_mysql' | Set-Content $phpIni

# Paramètres de production
(Get-Content $phpIni) -replace 'display_errors = On', 'display_errors = Off' | Set-Content $phpIni
(Get-Content $phpIni) -replace 'log_errors = Off', 'log_errors = On' | Set-Content $phpIni
```

### Ajouter PHP au PATH

```powershell
# Ajouter au PATH système
$path = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($path -notlike "*C:\PHP*") {
    [Environment]::SetEnvironmentVariable("Path", "$path;C:\PHP", "Machine")
}

# Recharger le PATH dans la session
$env:Path = [Environment]::GetEnvironmentVariable("Path", "Machine")

# Vérifier
php -v
```

---

## 4. Configurer IIS pour PHP (FastCGI)

### Installer le module CGI

```powershell
# Vérifier que Web-CGI est installé
Get-WindowsFeature -Name Web-CGI

# Installer si nécessaire
Install-WindowsFeature -Name Web-CGI
```

### Configurer le Handler PHP

```powershell
# Importer le module IIS
Import-Module WebAdministration

# Ajouter le handler PHP FastCGI
New-WebHandler -Name "PHP-FastCGI" `
    -Path "*.php" `
    -Verb "*" `
    -Modules "FastCgiModule" `
    -ScriptProcessor "C:\PHP\php-cgi.exe" `
    -ResourceType File

# Configurer FastCGI
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
    -filter "system.webServer/fastCgi" `
    -name "." `
    -value @{
        fullPath = 'C:\PHP\php-cgi.exe'
        activityTimeout = '600'
        requestTimeout = '600'
        instanceMaxRequests = '10000'
    }
```

### Alternative : Configuration via IIS Manager

1. Ouvrir **IIS Manager** (`inetmgr`)
2. Sélectionner le serveur
3. Double-cliquer sur **Handler Mappings**
4. Cliquer sur **Add Module Mapping...**
   - Request path: `*.php`
   - Module: `FastCgiModule`
   - Executable: `C:\PHP\php-cgi.exe`
   - Name: `PHP-FastCGI`
5. Cliquer **OK**

### Redémarrer IIS

```powershell
iisreset /restart
```

---

## 5. Test PHP

### Créer une page de test

```powershell
# Créer info.php
$phpInfo = @'
<?php
phpinfo();
'@

Set-Content -Path "C:\inetpub\wwwroot\info.php" -Value $phpInfo
```

### Tester

```powershell
# Test via PowerShell
Invoke-WebRequest -Uri http://localhost/info.php -UseBasicParsing | Select-Object StatusCode
```

Ouvrir `http://localhost/info.php` dans un navigateur - la page phpinfo() doit s'afficher.

!!! warning "Supprimer info.php en production"
    ```powershell
    Remove-Item "C:\inetpub\wwwroot\info.php"
    ```

---

## 6. Document par défaut

### Ajouter index.php comme document par défaut

```powershell
# Via PowerShell
Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
    -filter "system.webServer/defaultDocument/files" `
    -name "." `
    -value @{value='index.php'}

# Vérifier
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
    -filter "system.webServer/defaultDocument/files" `
    -name "."
```

---

## 7. Créer un site web

### Via PowerShell

```powershell
# Créer le répertoire du site
New-Item -Path "C:\inetpub\monsite" -ItemType Directory -Force

# Créer une page d'accueil
$indexPhp = @'
<!DOCTYPE html>
<html>
<head><title>Mon Site</title></head>
<body>
<h1>Mon Site fonctionne!</h1>
<p>PHP Version: <?php echo phpversion(); ?></p>
</body>
</html>
'@
Set-Content -Path "C:\inetpub\monsite\index.php" -Value $indexPhp

# Créer le site IIS
New-Website -Name "MonSite" `
    -PhysicalPath "C:\inetpub\monsite" `
    -Port 8080 `
    -HostHeader ""

# Démarrer le site
Start-Website -Name "MonSite"

# Vérifier
Get-Website -Name "MonSite"
```

### Binding avec nom de domaine

```powershell
# Ajouter un binding avec hostname
New-WebBinding -Name "MonSite" -Protocol "http" -Port 80 -HostHeader "monsite.local"

# Supprimer le binding port 8080
Remove-WebBinding -Name "MonSite" -Port 8080
```

---

## 8. Sécurisation

### Désactiver la signature serveur

```powershell
# Supprimer le header Server
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
    -filter "system.webServer/security/requestFiltering" `
    -name "removeServerHeader" `
    -value "True"
```

### Configurer les permissions

```powershell
# Définir les permissions sur le répertoire web
$acl = Get-Acl "C:\inetpub\monsite"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "IIS_IUSRS",
    "ReadAndExecute",
    "ContainerInherit,ObjectInherit",
    "None",
    "Allow"
)
$acl.SetAccessRule($rule)
Set-Acl "C:\inetpub\monsite" $acl
```

### Activer HTTPS (certificat auto-signé pour test)

```powershell
# Créer un certificat auto-signé
$cert = New-SelfSignedCertificate -DnsName "monsite.local" `
    -CertStoreLocation "cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(1)

# Ajouter le binding HTTPS
New-WebBinding -Name "MonSite" -Protocol "https" -Port 443 -HostHeader "monsite.local"

# Associer le certificat
$binding = Get-WebBinding -Name "MonSite" -Protocol "https"
$binding.AddSslCertificate($cert.Thumbprint, "My")
```

---

## 9. Logs et monitoring

### Configurer les logs

```powershell
# Voir la configuration des logs
Get-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
    -filter "system.applicationHost/sites/siteDefaults/logFile" `
    -name "directory"

# Changer le répertoire des logs
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
    -filter "system.applicationHost/sites/siteDefaults/logFile" `
    -name "directory" `
    -value "D:\Logs\IIS"
```

### Vérifier les logs

```powershell
# Lister les logs récents
Get-ChildItem "C:\inetpub\logs\LogFiles" -Recurse | Sort-Object LastWriteTime -Descending | Select-Object -First 10
```

---

## 10. Commandes utiles

### Gestion IIS

```powershell
# Lister tous les sites
Get-Website

# Lister les pools d'applications
Get-IISAppPool

# Arrêter/Démarrer un site
Stop-Website -Name "MonSite"
Start-Website -Name "MonSite"

# Recycler un pool d'applications
Restart-WebAppPool -Name "DefaultAppPool"

# Reset complet IIS
iisreset /restart
```

### Diagnostic

```powershell
# Tester la configuration
& "$env:SystemRoot\System32\inetsrv\appcmd.exe" list config

# Vérifier les handlers
Get-WebHandler

# Vérifier les modules
Get-WebGlobalModule
```

---

## Dépannage

### PHP ne s'exécute pas (erreur 500)

```powershell
# Vérifier les logs PHP
Get-Content "C:\PHP\php_errors.log" -Tail 20

# Vérifier que php-cgi.exe fonctionne
& "C:\PHP\php-cgi.exe" -v

# Vérifier les dépendances Visual C++
# Télécharger VC++ Redistributable si nécessaire
```

### Erreur 403 Forbidden

```powershell
# Vérifier les permissions NTFS
Get-Acl "C:\inetpub\monsite" | Format-List

# Ajouter IIS_IUSRS
icacls "C:\inetpub\monsite" /grant "IIS_IUSRS:(OI)(CI)RX"
```

### FastCGI timeout

```powershell
# Augmenter les timeouts
Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
    -filter "system.webServer/fastCgi/application[@fullPath='C:\PHP\php-cgi.exe']" `
    -name "activityTimeout" `
    -value 600
```

---

## Pour aller plus loin

- [Certificat SSL avec Let's Encrypt (win-acme)](../security/letsencrypt-windows.md)
- [SQL Server Express](../databases/sqlserver-express.md)
- [IIS URL Rewrite](iis-url-rewrite.md)

---

## Changelog

| Date | Modification |
|------|--------------|
| 2024-12 | Création initiale - Windows Server 2022 + PHP 8.2 |
