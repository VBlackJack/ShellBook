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
