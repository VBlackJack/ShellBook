---
tags:
  - windows
  - rds
  - remote-desktop
  - terminal-services
---

# RDS - Remote Desktop Services

Configuration et administration des services Bureau à distance : Session Host, Gateway, Licensing.

## Architecture

```
ARCHITECTURE RDS
══════════════════════════════════════════════════════════

              Internet/WAN                    LAN
                   │                           │
                   ▼                           │
         ┌─────────────────┐                   │
         │   RD Gateway    │                   │
         │  (HTTPS 443)    │                   │
         └────────┬────────┘                   │
                  │                            │
                  ▼                            │
         ┌─────────────────┐                   │
         │   RD Web Access │                   │
         │   (Portal web)  │                   │
         └────────┬────────┘                   │
                  │                            │
                  ▼                            ▼
         ┌─────────────────┐          ┌─────────────────┐
         │  RD Connection  │          │    Clients      │
         │     Broker      │◄─────────│   (mstsc.exe)   │
         └────────┬────────┘          └─────────────────┘
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
┌───────────────┐   ┌───────────────┐
│ RD Session    │   │ RD Session    │
│ Host 1        │   │ Host 2        │
│ (Sessions)    │   │ (Sessions)    │
└───────────────┘   └───────────────┘
        │                   │
        └─────────┬─────────┘
                  ▼
         ┌─────────────────┐
         │  RD Licensing   │
         │  (CALs)         │
         └─────────────────┘

Rôles RDS :
• RD Session Host (RDSH) : Héberge les sessions/applications
• RD Connection Broker : Load balancing, reconnexion
• RD Web Access : Portail web RemoteApp/Desktop
• RD Gateway : Accès sécurisé HTTPS depuis Internet
• RD Licensing : Gestion des licences CAL
• RD Virtualization Host : VDI (optionnel)
```

---

## Installation

### Déploiement Standard

```powershell
# Installer les rôles RDS (déploiement basé sur session)
# Sur le serveur Connection Broker :

Install-WindowsFeature -Name RDS-Connection-Broker -IncludeManagementTools
Install-WindowsFeature -Name RDS-Web-Access -IncludeManagementTools
Install-WindowsFeature -Name RDS-Licensing -IncludeManagementTools

# Sur les Session Hosts :
Install-WindowsFeature -Name RDS-RD-Server -IncludeManagementTools

# Gateway (si accès externe) :
Install-WindowsFeature -Name RDS-Gateway -IncludeManagementTools
```

### Déploiement via Server Manager (Recommandé)

```
Server Manager > Manage > Add Roles and Features
  → Remote Desktop Services installation
  → Standard deployment ou Quick Start

Standard Deployment :
1. Sélectionner "Session-based desktop deployment"
2. Désigner le Connection Broker
3. Désigner le(s) Session Host(s)
4. Désigner le Web Access
```

### Déploiement PowerShell Complet

```powershell
# Importer le module
Import-Module RemoteDesktop

# Créer le déploiement
New-RDSessionDeployment -ConnectionBroker "broker.corp.local" `
    -WebAccessServer "broker.corp.local" `
    -SessionHost "rdsh1.corp.local","rdsh2.corp.local"

# Ajouter la Gateway
Add-RDServer -Server "gateway.corp.local" -Role "RDS-GATEWAY" `
    -ConnectionBroker "broker.corp.local"

# Ajouter le Licensing
Add-RDServer -Server "license.corp.local" -Role "RDS-LICENSING" `
    -ConnectionBroker "broker.corp.local"
```

---

## Configuration du Licensing

### Activer le Serveur de Licences

```powershell
# Installer le rôle
Install-WindowsFeature -Name RDS-Licensing -IncludeManagementTools

# Activer (via GUI ou script)
# RD Licensing Manager > Activer le serveur

# Définir le mode de licence
Set-RDLicenseConfiguration -LicenseServer "license.corp.local" `
    -Mode PerUser `
    -ConnectionBroker "broker.corp.local"

# Modes :
# - PerUser : 1 CAL par utilisateur unique
# - PerDevice : 1 CAL par appareil client
```

### Vérifier les Licences

```powershell
# Voir la configuration
Get-RDLicenseConfiguration -ConnectionBroker "broker.corp.local"

# Rapport de licences
$licenses = Invoke-Command -ComputerName "license.corp.local" -ScriptBlock {
    Get-WmiObject -Class Win32_TSLicenseKeyPack -Namespace "root\cimv2"
}
$licenses | Select-Object ProductVersion, TypeAndModel, TotalLicenses, IssuedLicenses
```

---

## Session Host

### Configuration de Base

```powershell
# Configurer les limites de session
$sessionHost = "rdsh1.corp.local"

# Timeout de session inactive
Set-RDSessionCollectionConfiguration -CollectionName "Desktop Collection" `
    -IdleSessionLimitMin 30 `
    -ConnectionBroker "broker.corp.local"

# Déconnexion après timeout
Set-RDSessionCollectionConfiguration -CollectionName "Desktop Collection" `
    -DisconnectedSessionLimitMin 60 `
    -ConnectionBroker "broker.corp.local"

# Timeout de session active
Set-RDSessionCollectionConfiguration -CollectionName "Desktop Collection" `
    -ActiveSessionLimitMin 0 `  # 0 = pas de limite
    -ConnectionBroker "broker.corp.local"
```

### Collections

```powershell
# Créer une collection de sessions
New-RDSessionCollection -CollectionName "Standard Desktops" `
    -SessionHost "rdsh1.corp.local","rdsh2.corp.local" `
    -ConnectionBroker "broker.corp.local" `
    -CollectionDescription "Bureaux standards pour les utilisateurs"

# Voir les collections
Get-RDSessionCollection -ConnectionBroker "broker.corp.local"

# Configurer les groupes autorisés
Set-RDSessionCollectionConfiguration -CollectionName "Standard Desktops" `
    -UserGroup "CORP\RDS-Users" `
    -ConnectionBroker "broker.corp.local"
```

### User Profile Disks (UPD)

```powershell
# Activer les UPD (profils sur disque partagé)
Set-RDSessionCollectionConfiguration -CollectionName "Standard Desktops" `
    -EnableUserProfileDisk `
    -MaxUserProfileDiskSizeGB 10 `
    -DiskPath "\\fileserver\UserProfileDisks" `
    -ConnectionBroker "broker.corp.local"

# Configurer ce qui est inclus/exclu
Set-RDSessionCollectionConfiguration -CollectionName "Standard Desktops" `
    -IncludeFolderPath @("\AppData\Local\Microsoft\Office") `
    -ExcludeFolderPath @("\AppData\Local\Temp") `
    -ConnectionBroker "broker.corp.local"
```

---

## RemoteApp

### Publier des Applications

```powershell
# Publier une application
New-RDRemoteApp -CollectionName "Standard Desktops" `
    -DisplayName "Microsoft Word" `
    -FilePath "C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" `
    -Alias "Word" `
    -ConnectionBroker "broker.corp.local"

# Publier avec paramètres
New-RDRemoteApp -CollectionName "Standard Desktops" `
    -DisplayName "Notepad++" `
    -FilePath "C:\Program Files\Notepad++\notepad++.exe" `
    -Alias "NotepadPlusPlus" `
    -CommandLineSetting Require `
    -RequiredCommandLine "-multiInst" `
    -ConnectionBroker "broker.corp.local"

# Lister les RemoteApps
Get-RDRemoteApp -ConnectionBroker "broker.corp.local"
```

### Configurer les RemoteApps

```powershell
# Modifier une RemoteApp
Set-RDRemoteApp -CollectionName "Standard Desktops" `
    -Alias "Word" `
    -UserGroups "CORP\Office-Users" `
    -ConnectionBroker "broker.corp.local"

# Désactiver temporairement
Set-RDRemoteApp -CollectionName "Standard Desktops" `
    -Alias "Word" `
    -ShowInWebAccess $false `
    -ConnectionBroker "broker.corp.local"

# Supprimer
Remove-RDRemoteApp -CollectionName "Standard Desktops" `
    -Alias "OldApp" `
    -ConnectionBroker "broker.corp.local"
```

---

## RD Gateway

### Configuration

```powershell
# Le Gateway permet l'accès RDP via HTTPS (port 443)
# Utile pour les clients externes

# Installer le rôle
Install-WindowsFeature -Name RDS-Gateway -IncludeManagementTools

# Configurer le certificat SSL
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "*gateway*"
Set-RDCertificate -Role RDGateway `
    -Thumbprint $cert.Thumbprint `
    -ConnectionBroker "broker.corp.local"

# Configurer les CAP et RAP (via GUI recommandé)
# RD Gateway Manager > Policies
```

### Connection Authorization Policy (CAP)

```powershell
# CAP : Qui peut se connecter au Gateway
# Via PowerShell (basique) :

Import-Module RemoteDesktopServices
Set-Location RDS:\GatewayServer\CAP

# Créer une CAP
New-Item -Name "CorpUsers-CAP" `
    -UserGroups "CORP\RDS-Users" `
    -AuthMethod 1  # 1=Password, 2=Smartcard, 3=Both
```

### Resource Authorization Policy (RAP)

```powershell
# RAP : À quelles ressources on peut accéder
Set-Location RDS:\GatewayServer\RAP

# Créer une RAP
New-Item -Name "AllServers-RAP" `
    -UserGroups "CORP\RDS-Users" `
    -ComputerGroupType 2 `  # 2=Specified group
    -ComputerGroup "CORP\RDS-Servers"
```

---

## RD Web Access

### Configuration

```powershell
# Accès via : https://server/RDWeb

# Personnaliser la page
$webConfig = @{
    WorkspaceName = "Corp Remote Desktop"
    ShowDesktops = $true
}

# Le Web Access récupère automatiquement les collections du Broker

# Configurer les certificats
Set-RDCertificate -Role RDWebAccess `
    -Thumbprint $cert.Thumbprint `
    -ConnectionBroker "broker.corp.local"
```

### Fichiers RDP

```powershell
# Générer un fichier .rdp pour distribution
$rdpContent = @"
full address:s:gateway.corp.local
gatewayhostname:s:gateway.corp.local
gatewayusagemethod:i:1
gatewayprofileusagemethod:i:1
gatewayaccesstoken:s:
use redirection server name:i:1
alternate shell:s:rdpinit.exe
remoteapplicationmode:i:1
remoteapplicationprogram:s:||Word
remoteapplicationname:s:Microsoft Word
"@

$rdpContent | Out-File "C:\Deploy\Word.rdp" -Encoding ASCII
```

---

## Connection Broker

### Load Balancing

```powershell
# Le Broker distribue les connexions entre Session Hosts

# Voir la répartition
Get-RDSessionHost -CollectionName "Standard Desktops" `
    -ConnectionBroker "broker.corp.local" |
    Select-Object SessionHost, NewConnectionAllowed, Sessions

# Drain un serveur (maintenance)
Set-RDSessionHost -SessionHost "rdsh1.corp.local" `
    -NewConnectionAllowed No `
    -ConnectionBroker "broker.corp.local"

# Réactiver
Set-RDSessionHost -SessionHost "rdsh1.corp.local" `
    -NewConnectionAllowed Yes `
    -ConnectionBroker "broker.corp.local"
```

### Haute Disponibilité du Broker

```powershell
# Configurer le Broker HA (nécessite SQL Server)
Set-RDConnectionBrokerHighAvailability `
    -ConnectionBroker "broker1.corp.local" `
    -DatabaseConnectionString "DRIVER=SQL Server Native Client 11.0;SERVER=sqlserver;Trusted_Connection=Yes;APP=Remote Desktop Services Connection Broker;DATABASE=RDCB" `
    -DatabaseSecondaryConnectionString "DRIVER=SQL Server Native Client 11.0;SERVER=sqlserver-dr;Trusted_Connection=Yes;APP=Remote Desktop Services Connection Broker;DATABASE=RDCB" `
    -ClientAccessName "rdbroker.corp.local"

# Ajouter un second Broker
Add-RDServer -Server "broker2.corp.local" `
    -Role "RDS-CONNECTION-BROKER" `
    -ConnectionBroker "broker1.corp.local"
```

---

## Gestion des Sessions

### Monitoring

```powershell
# Voir les sessions actives
Get-RDUserSession -ConnectionBroker "broker.corp.local"

# Sessions par collection
Get-RDUserSession -CollectionName "Standard Desktops" `
    -ConnectionBroker "broker.corp.local" |
    Select-Object UserName, HostServer, SessionState, CreateTime

# Sessions sur un serveur spécifique
query session /server:rdsh1.corp.local
```

### Actions sur les Sessions

```powershell
# Déconnecter un utilisateur
Disconnect-RDUser -HostServer "rdsh1.corp.local" `
    -UnifiedSessionID 5 `
    -Force

# Fermer une session (logoff)
Invoke-RDUserLogoff -HostServer "rdsh1.corp.local" `
    -UnifiedSessionID 5 `
    -Force

# Envoyer un message
Send-RDUserMessage -HostServer "rdsh1.corp.local" `
    -UnifiedSessionID 5 `
    -MessageTitle "Maintenance" `
    -MessageBody "Le serveur redémarrera dans 15 minutes"

# Shadow (prendre le contrôle)
mstsc /shadow:5 /v:rdsh1.corp.local /control
```

### GPO pour RDS

```
Computer Configuration > Policies > Administrative Templates >
Windows Components > Remote Desktop Services

Session Host:
├── Connections
│   ├── Limit number of connections
│   └── Set rules for remote control
├── Device and Resource Redirection
│   ├── Allow/Deny clipboard, drives, printers
│   └── Do not allow drive redirection
├── Licensing
│   ├── Set the Remote Desktop licensing mode
│   └── Use the specified RD license servers
├── Session Time Limits
│   ├── Set time limit for disconnected sessions
│   └── Set time limit for active sessions
└── Security
    ├── Require secure RPC communication
    └── Set client connection encryption level
```

---

## Sécurité

### Certificats

```powershell
# Voir les certificats configurés
Get-RDCertificate -ConnectionBroker "broker.corp.local"

# Configurer tous les certificats
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -like "*rds.corp.local*"

Set-RDCertificate -Role RDGateway -Thumbprint $cert.Thumbprint -ConnectionBroker "broker.corp.local"
Set-RDCertificate -Role RDWebAccess -Thumbprint $cert.Thumbprint -ConnectionBroker "broker.corp.local"
Set-RDCertificate -Role RDRedirector -Thumbprint $cert.Thumbprint -ConnectionBroker "broker.corp.local"
Set-RDCertificate -Role RDPublishing -Thumbprint $cert.Thumbprint -ConnectionBroker "broker.corp.local"
```

### NLA (Network Level Authentication)

```powershell
# Forcer NLA (recommandé)
# Via GPO ou Registry :
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" `
    -Value 1

# Vérifier
Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication"
```

---

## Troubleshooting

### Diagnostic

```powershell
# Tester la connectivité
Test-NetConnection -ComputerName rdsh1.corp.local -Port 3389

# Event logs
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -MaxEvents 50
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational" -MaxEvents 50

# Logs du Gateway
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-Gateway/Operational" -MaxEvents 50

# Vérifier le service
Get-Service -Name TermService -ComputerName rdsh1.corp.local

# Vérifier le port RDP
netstat -an | findstr 3389
```

### Problèmes Courants

```powershell
# "Licensing mode not configured"
# → Configurer le serveur de licences et le mode

# "Certificate warnings"
# → Installer un certificat valide et le configurer

# "Session déconnectée"
# → Vérifier les timeouts et les GPO

# "Cannot connect through Gateway"
# → Vérifier CAP/RAP et le certificat Gateway
```

---

## Bonnes Pratiques

```yaml
Checklist RDS:
  Infrastructure:
    - [ ] Session Hosts en HA (2+ serveurs)
    - [ ] Connection Broker HA si critique
    - [ ] Licensing configuré correctement
    - [ ] Certificats valides sur tous les rôles

  Sécurité:
    - [ ] NLA activé
    - [ ] Gateway pour accès externe
    - [ ] MFA si possible (via Gateway)
    - [ ] Chiffrement TLS 1.2+

  Performance:
    - [ ] User Profile Disks
    - [ ] FSLogix si O365 (recommandé)
    - [ ] Timeouts configurés
    - [ ] Monitoring des sessions

  Opérations:
    - [ ] Procédure de drain pour maintenance
    - [ ] Sauvegarde de la config Broker
    - [ ] Plan de capacité
```

---

**Voir aussi :**

- [Certificate Services](certificate-services.md) - PKI pour certificats
- [Failover Cluster](failover-cluster.md) - HA Session Hosts
- [Windows Firewall](windows-firewall.md) - Règles RDS
