---
tags:
  - formation
  - windows-server
  - roles
  - features
  - iis
---

# Module 06 : Rôles & Features

## Objectifs du Module

Ce module couvre l'installation et la gestion des rôles Windows Server :

- Comprendre la différence entre rôles et features
- Installer et configurer IIS (Web Server)
- Configurer un serveur de fichiers
- Gérer les rôles avec PowerShell
- Comprendre les dépendances

**Durée :** 7 heures

**Niveau :** Administration

---

## 1. Rôles vs Features

### 1.1 Concepts

```
RÔLES                          FEATURES
─────                          ────────
Fonction principale            Fonctionnalité additionnelle
du serveur                     transversale

Exemples:                      Exemples:
• Active Directory DS          • .NET Framework
• DNS Server                   • PowerShell
• DHCP Server                  • Telnet Client
• Web Server (IIS)             • BitLocker
• File Services                • Failover Clustering
• Hyper-V                      • RSAT
```

### 1.2 Installation avec PowerShell

```powershell
# Lister les rôles disponibles
Get-WindowsFeature | Where-Object FeatureType -eq "Role"

# Lister les features installées
Get-WindowsFeature | Where-Object Installed

# Installer un rôle
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Installer avec sous-features
Install-WindowsFeature -Name Web-Server -IncludeAllSubFeature

# Désinstaller
Uninstall-WindowsFeature -Name Web-Server -Remove
```

---

## 2. Web Server (IIS)

### 2.1 Installation Complète

```powershell
# Installation IIS avec features courantes
Install-WindowsFeature -Name Web-Server,
    Web-Common-Http,
    Web-Default-Doc,
    Web-Static-Content,
    Web-Http-Errors,
    Web-Http-Redirect,
    Web-App-Dev,
    Web-Asp-Net45,
    Web-Net-Ext45,
    Web-ISAPI-Ext,
    Web-ISAPI-Filter,
    Web-Security,
    Web-Filtering,
    Web-Mgmt-Tools,
    Web-Mgmt-Console -IncludeManagementTools
```

### 2.2 Gestion IIS avec PowerShell

```powershell
# Importer le module
Import-Module WebAdministration

# Lister les sites
Get-IISSite

# Créer un site
New-IISSite -Name "MonSite" -PhysicalPath "C:\inetpub\monsite" -BindingInformation "*:80:monsite.local"

# Démarrer/Arrêter un site
Start-IISSite -Name "MonSite"
Stop-IISSite -Name "MonSite"

# Créer un pool d'applications
New-WebAppPool -Name "MonPool"
Set-ItemProperty "IIS:\AppPools\MonPool" -Name "managedRuntimeVersion" -Value "v4.0"

# Associer site au pool
Set-ItemProperty "IIS:\Sites\MonSite" -Name "applicationPool" -Value "MonPool"
```

---

## 3. File Server

### 3.1 Installation

```powershell
# Installer le rôle File Server
Install-WindowsFeature -Name FS-FileServer, FS-Resource-Manager -IncludeManagementTools

# Avec déduplication et quotas
Install-WindowsFeature -Name FS-Data-Deduplication, FS-Resource-Manager
```

### 3.2 Gestion des Partages

```powershell
# Créer un partage
New-SmbShare -Name "Data" -Path "C:\Data" -FullAccess "Administrators" -ChangeAccess "Users"

# Lister les partages
Get-SmbShare

# Modifier un partage
Set-SmbShare -Name "Data" -Description "Données partagées"

# Permissions de partage
Grant-SmbShareAccess -Name "Data" -AccountName "Finance" -AccessRight Change
Revoke-SmbShareAccess -Name "Data" -AccountName "Guest"

# Supprimer un partage
Remove-SmbShare -Name "Data" -Force
```

---

## 4. Autres Rôles Courants

### 4.1 Print Server

```powershell
# Installer le rôle
Install-WindowsFeature -Name Print-Server -IncludeManagementTools

# Ajouter une imprimante
Add-Printer -Name "HP-RDC" -DriverName "HP Universal Printing PCL 6" -PortName "IP_192.168.1.100"
```

### 4.2 Remote Desktop Services

```powershell
# Installer RDS (basique)
Install-WindowsFeature -Name RDS-RD-Server -IncludeManagementTools

# Configurer le licensing
Set-RDLicenseConfiguration -LicenseServer "RDS-LIC01" -Mode PerUser
```

---

## 5. Exercice Pratique

### Déployer un Serveur Web

```powershell
# 1. Installer IIS
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# 2. Créer le répertoire
New-Item -Path "C:\WebSites\Demo" -ItemType Directory

# 3. Créer la page d'accueil
@"
<!DOCTYPE html>
<html>
<head><title>Demo Site</title></head>
<body><h1>Site de démonstration</h1></body>
</html>
"@ | Set-Content "C:\WebSites\Demo\index.html"

# 4. Créer le site IIS
Import-Module WebAdministration
New-IISSite -Name "Demo" -PhysicalPath "C:\WebSites\Demo" -BindingInformation "*:8080:"

# 5. Ouvrir le pare-feu
New-NetFirewallRule -DisplayName "HTTP 8080" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow

# 6. Tester
Start-Process "http://localhost:8080"
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Déployer un serveur multi-rôles avec IIS et File Server

    **Contexte** : Vous devez configurer un serveur qui hébergera à la fois un site web interne et des partages de fichiers pour le département IT. Le site web doit être accessible sur le port 8080 et les fichiers doivent être organisés par service.

    **Tâches à réaliser** :

    1. Installer les rôles Web Server (IIS) et File Server avec toutes les fonctionnalités nécessaires
    2. Créer un site web nommé "IntranetIT" sur le port 8080 avec une page d'accueil personnalisée
    3. Créer une structure de partages réseau : "IT-Scripts", "IT-Docs" et "IT-Tools"
    4. Configurer les permissions NTFS et de partage appropriées
    5. Ouvrir les ports nécessaires dans le pare-feu Windows

    **Critères de validation** :

    - [ ] Les rôles IIS et File Server sont installés et opérationnels
    - [ ] Le site web est accessible via http://localhost:8080
    - [ ] Les trois partages réseau sont créés et accessibles via \\SERVEUR\IT-*
    - [ ] Les permissions permettent aux utilisateurs du groupe "IT-Team" d'accéder aux partages
    - [ ] Les règles de pare-feu autorisent HTTP (8080) et SMB (445)

??? quote "Solution"
    Voici la solution complète étape par étape :

    ```powershell
    # 1. Installer les rôles nécessaires
    Install-WindowsFeature -Name Web-Server, FS-FileServer `
        -IncludeSubFeature `
        -IncludeManagementTools

    # Vérifier l'installation
    Get-WindowsFeature | Where-Object Installed | Where-Object Name -match "Web|File"

    # 2. Créer le site web IntranetIT
    Import-Module WebAdministration

    # Créer le répertoire du site
    New-Item -Path "C:\WebSites\IntranetIT" -ItemType Directory -Force

    # Créer une page d'accueil
    @"
    <!DOCTYPE html>
    <html>
    <head>
        <title>Intranet IT</title>
        <style>
            body { font-family: Arial; margin: 50px; background-color: #f0f0f0; }
            h1 { color: #0066cc; }
        </style>
    </head>
    <body>
        <h1>Bienvenue sur l'Intranet IT</h1>
        <p>Portail du département informatique</p>
        <ul>
            <li><a href="\\$env:COMPUTERNAME\IT-Scripts">Scripts</a></li>
            <li><a href="\\$env:COMPUTERNAME\IT-Docs">Documentation</a></li>
            <li><a href="\\$env:COMPUTERNAME\IT-Tools">Outils</a></li>
        </ul>
    </body>
    </html>
    "@ | Set-Content "C:\WebSites\IntranetIT\index.html"

    # Créer le site IIS
    New-IISSite -Name "IntranetIT" `
        -PhysicalPath "C:\WebSites\IntranetIT" `
        -BindingInformation "*:8080:"

    # Démarrer le site
    Start-IISSite -Name "IntranetIT"

    # 3. Créer la structure de partages
    $shareRoot = "C:\Shares"
    $shares = @("IT-Scripts", "IT-Docs", "IT-Tools")

    foreach ($share in $shares) {
        # Créer le dossier
        $path = Join-Path $shareRoot $share
        New-Item -Path $path -ItemType Directory -Force

        # Créer le partage SMB
        New-SmbShare -Name $share `
            -Path $path `
            -FullAccess "Administrators" `
            -ChangeAccess "IT-Team" `
            -ReadAccess "Domain Users"
    }

    # 4. Configurer les permissions NTFS
    foreach ($share in $shares) {
        $path = Join-Path $shareRoot $share

        # Supprimer l'héritage
        $acl = Get-Acl $path
        $acl.SetAccessRuleProtection($true, $true)
        Set-Acl $path $acl

        # Ajouter les permissions
        $acl = Get-Acl $path

        # IT-Team : Modify
        $permission = "DOMAIN\IT-Team", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow"
        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
        $acl.AddAccessRule($accessRule)

        # Appliquer
        Set-Acl $path $acl
    }

    # 5. Configurer le pare-feu
    # Règle pour HTTP 8080
    New-NetFirewallRule -DisplayName "Intranet IT - HTTP 8080" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 8080 `
        -Action Allow `
        -Profile Domain

    # Règle pour SMB (si pas déjà activée)
    New-NetFirewallRule -DisplayName "File Sharing - SMB" `
        -Direction Inbound `
        -Protocol TCP `
        -LocalPort 445 `
        -Action Allow `
        -Profile Domain `
        -ErrorAction SilentlyContinue

    # Vérification finale
    Write-Host "`n=== VERIFICATION ===" -ForegroundColor Green

    # Vérifier IIS
    Write-Host "`nSite IIS:" -ForegroundColor Yellow
    Get-IISSite | Select-Object Name, State, @{N="Bindings";E={$_.Bindings.BindingInformation}}

    # Vérifier les partages
    Write-Host "`nPartages SMB:" -ForegroundColor Yellow
    Get-SmbShare | Where-Object Name -like "IT-*" | Format-Table Name, Path, Description

    # Vérifier le pare-feu
    Write-Host "`nRègles de pare-feu:" -ForegroundColor Yellow
    Get-NetFirewallRule | Where-Object DisplayName -match "Intranet IT|File Sharing" |
        Select-Object DisplayName, Enabled, Direction, Action

    # Test d'accès au site
    Write-Host "`nTest du site web:" -ForegroundColor Yellow
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:8080" -UseBasicParsing
        Write-Host "Site accessible - Code: $($response.StatusCode)" -ForegroundColor Green
    } catch {
        Write-Host "Erreur d'accès au site: $_" -ForegroundColor Red
    }

    Write-Host "`n=== Configuration terminée ===" -ForegroundColor Green
    Write-Host "Site web: http://localhost:8080"
    Write-Host "Partages: \\$env:COMPUTERNAME\IT-Scripts, IT-Docs, IT-Tools"
    ```

    **Points clés de la solution** :

    - Utilisation de `Install-WindowsFeature` avec `-IncludeManagementTools` pour installer les outils d'administration
    - Création d'un site IIS avec `New-IISSite` sur un port personnalisé
    - Configuration des partages SMB avec des permissions différenciées par groupe
    - Configuration des permissions NTFS pour un contrôle d'accès granulaire
    - Création de règles de pare-feu spécifiques pour les services déployés
    - Script de vérification pour valider chaque composant

---

## Quiz

1. **Quelle cmdlet installe un rôle Windows ?**
   - [ ] A. Add-WindowsFeature
   - [ ] B. Install-WindowsFeature
   - [ ] C. Enable-WindowsFeature

2. **Quel paramètre inclut les outils de gestion ?**
   - [ ] A. -IncludeTools
   - [ ] B. -IncludeManagementTools
   - [ ] C. -WithTools

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 05 : Introduction au Scripting](05-scripting-intro.md)

**Suivant :** [Module 07 : Services & Processus](07-services-processus.md)
