# Windows Server: Build & Modern Admin

`#windows-server` `#core` `#wac` `#openssh` `#2025` `#winget` `#chocolatey`

Administration Windows Server moderne : Build, WAC, PowerShell et gestion des versions 2019/2022/2025.

---

## Le Build : Installation & Initialisation

### Server Core vs Desktop Experience : Le Choix Stratégique

```
┌─────────────────────────────────────────────────────────────┐
│              SERVER CORE vs DESKTOP EXPERIENCE               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Server Core                    Desktop Experience           │
│  ────────────                   ──────────────────           │
│  ✓ Surface d'attaque réduite    ✗ Plus de composants         │
│  ✓ Moins de mises à jour        ✗ Plus de patchs mensuels    │
│  ✓ Consommation RAM réduite     ✗ GUI = ~2GB RAM en plus     │
│  ✓ Pas de RDP accidentel        ✗ Tentant d'utiliser RDP     │
│  ✓ Force l'automatisation       ✗ Encourage le "clic-clic"   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

| Aspect | Server Core | Desktop Experience |
|--------|-------------|-------------------|
| **GUI** | Non (CLI/PowerShell) | Oui (Explorer, MMC) |
| **Taille disque** | ~6 GB | ~10+ GB |
| **RAM au démarrage** | ~800 MB | ~2.5 GB |
| **Surface d'attaque** | Réduite (~60% moins de composants) | Élevée |
| **Patchs mensuels** | ~30% moins de patchs | Plus de patchs (GUI, IE, etc.) |
| **Administration** | PowerShell, WAC, RSAT à distance | GUI locale + PowerShell |
| **Performance** | Meilleure (pas de GUI overhead) | Inférieure |
| **Cas d'usage** | Production, Hyperviseurs, DC, Fichiers | Lab, Formation, Legacy Apps |
| **Versions supportées** | 2019, 2022, 2025 | 2019, 2022, 2025 |

### sconfig : Le Menu Magique

Au démarrage de Server Core, lancez `sconfig` pour un menu de configuration rapide :

```
┌─────────────────────────────────────────────────────────────┐
│                 Server Configuration                         │
├─────────────────────────────────────────────────────────────┤
│  1) Domain/Workgroup                                        │
│  2) Computer Name                                           │
│  3) Add Local Administrator                                 │
│  4) Configure Remote Management                             │
│  5) Windows Update Settings                                 │
│  6) Download and Install Updates                            │
│  7) Remote Desktop                                          │
│  8) Network Settings                                        │
│  9) Date and Time                                          │
│  10) Telemetry settings                                     │
│  11) Windows Activation                                     │
│  12) Log Off User                                          │
│  13) Restart Server                                         │
│  14) Shut Down Server                                       │
│  15) Exit to Command Line                                   │
└─────────────────────────────────────────────────────────────┘
```

```powershell
# Lancer sconfig
sconfig

# Option 8 : Configurer IP statique
# Option 1 : Joindre un domaine
# Option 6 : Installer les updates
```

!!! tip "Sur Server Core, sconfig est votre meilleur ami"
    `sconfig` fonctionne sur **toutes les versions** (2019, 2022, 2025) et facilite la configuration initiale sans GUI. Pour l'automatisation complète, utilisez le script PowerShell ci-dessous.

### Script de Post-Installation (Automatisation)

**Scénario :** Nouveau serveur déployé, configuration rapide avant jonction au domaine.

```powershell
# ============================================================
# Script de Post-Installation Windows Server
# Compatible : 2019, 2022, 2025 (Server Core & Desktop)
# ============================================================

# 1. Renommer le serveur
$NewName = "SRV-DC01"
Rename-Computer -NewName $NewName -Force

# 2. Configurer le fuseau horaire
Set-TimeZone -Id "Romance Standard Time"  # Paris (GMT+1)
# Autres exemples :
# "Eastern Standard Time"   # New York
# "Pacific Standard Time"   # Los Angeles

# 3. Configurer IP statique
$InterfaceAlias = "Ethernet"  # Adapter avec Get-NetAdapter
$IPAddress = "192.168.1.10"
$PrefixLength = 24
$Gateway = "192.168.1.1"
$DNS = @("192.168.1.1", "8.8.8.8")

New-NetIPAddress -InterfaceAlias $InterfaceAlias `
    -IPAddress $IPAddress `
    -PrefixLength $PrefixLength `
    -DefaultGateway $Gateway

Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias `
    -ServerAddresses $DNS

# 4. Désactiver IPv6 (si non utilisé)
Disable-NetAdapterBinding -Name $InterfaceAlias -ComponentID ms_tcpip6

# 5. Activer WinRM (pour administration à distance)
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# 6. Configurer le firewall (RDP + WinRM)
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"

# 7. Joindre le domaine (remplacer par vos valeurs)
$Domain = "corp.local"
$Credential = Get-Credential -Message "Compte avec droits de jonction au domaine"
Add-Computer -DomainName $Domain -Credential $Credential -Restart

# Le serveur redémarre automatiquement après jonction
```

**Usage :**

```powershell
# Sauvegarder le script dans C:\Temp\PostInstall.ps1
# Exécuter en administrateur
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\Temp\PostInstall.ps1
```

### Installer des Rôles (PowerShell)

```powershell
# Lister les rôles disponibles
Get-WindowsFeature

# Lister les rôles installés
Get-WindowsFeature | Where-Object Installed

# Installer Active Directory Domain Services
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Installer IIS (Web Server)
Install-WindowsFeature -Name Web-Server -IncludeManagementTools

# Installer Hyper-V
Install-WindowsFeature -Name Hyper-V -IncludeManagementTools -Restart

# Installer DNS
Install-WindowsFeature -Name DNS -IncludeManagementTools

# Installer DHCP
Install-WindowsFeature -Name DHCP -IncludeManagementTools

# Supprimer un rôle
Uninstall-WindowsFeature -Name Web-Server
```

---

## Package Management

### Fini les .exe et "Suivant > Suivant"

```
┌─────────────────────────────────────────────────────────────┐
│                      AVANT (2010)                            │
│  1. Télécharger setup.exe                                   │
│  2. Suivant > Suivant > J'accepte > Suivant > Installer     │
│  3. Redémarrer                                              │
│  4. Répéter x50 serveurs                                    │
├─────────────────────────────────────────────────────────────┤
│                    MAINTENANT (2024)                         │
│  winget install Git.Git 7zip.7zip VSCode.VSCode -y          │
│  ou                                                          │
│  choco install git 7zip vscode -y                           │
└─────────────────────────────────────────────────────────────┘
```

### Winget (Natif Microsoft)

Winget est le gestionnaire de paquets officiel Microsoft (Windows 10/11, Server 2022+).

```powershell
# Rechercher un paquet
winget search git
winget search "visual studio"

# Installer
winget install Git.Git
winget install Microsoft.VisualStudioCode
winget install 7zip.7zip

# Installation silencieuse
winget install Git.Git --silent

# Installer plusieurs paquets
winget install Git.Git 7zip.7zip Notepad++.Notepad++ --silent

# Mettre à jour un paquet
winget upgrade Git.Git

# Mettre à jour tous les paquets
winget upgrade --all

# Lister les paquets installés
winget list

# Désinstaller
winget uninstall Git.Git

# Exporter la liste (pour répliquer)
winget export -o packages.json

# Importer sur une autre machine
winget import -i packages.json
```

### Chocolatey (Le Standard Historique)

Chocolatey est le gestionnaire communautaire, plus mature et avec plus de paquets.

```powershell
# Installation de Chocolatey (en admin)
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# Rechercher
choco search firefox

# Installer
choco install firefox -y
choco install git 7zip vscode -y

# Mettre à jour
choco upgrade firefox -y
choco upgrade all -y

# Lister les paquets installés
choco list

# Désinstaller
choco uninstall firefox -y

# Installer une version spécifique
choco install nodejs --version=18.17.0 -y
```

### Comparatif

| Aspect | Winget | Chocolatey |
|--------|--------|------------|
| Origine | Microsoft | Communauté |
| Paquets | ~5,000 | ~10,000+ |
| Intégration | Natif Windows 11 | À installer |
| Licence | Gratuit | Gratuit + Pro |
| Serveur interne | Non | Oui (Pro) |

!!! tip "Automatisation (Ansible/Terraform)"
    Les deux supportent l'installation silencieuse, essentielle pour :

    - **Ansible** : Module `win_chocolatey` ou `win_package`
    - **Terraform** : Provisioner avec scripts PowerShell
    - **DSC** : Configuration déclarative

    ```yaml
    # Ansible avec Chocolatey
    - name: Install packages
      win_chocolatey:
        name:
          - git
          - 7zip
          - vscode
        state: present
    ```

---

## Active Directory (Concepts Flash)

### Les Termes Essentiels

```
┌─────────────────────────────────────────────────────────────┐
│                         FOREST                               │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                    DOMAIN                              │  │
│  │                  (corp.local)                          │  │
│  │                                                        │  │
│  │  ┌──────────────┐    ┌──────────────┐                 │  │
│  │  │     DC01     │    │     DC02     │                 │  │
│  │  │   (Primary)  │◄──►│  (Secondary) │                 │  │
│  │  │  Kerberos    │    │  Réplication │                 │  │
│  │  └──────────────┘    └──────────────┘                 │  │
│  │                                                        │  │
│  │  Users, Computers, Groups, GPOs                       │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

| Terme | Description |
|-------|-------------|
| **Domain Controller (DC)** | Serveur qui authentifie les utilisateurs via Kerberos. Stocke l'annuaire AD. |
| **Forest** | Limite de sécurité ultime. Ensemble de domaines qui se font confiance. |
| **Domain** | Unité d'administration. Ex: `corp.local`, `paris.corp.local` |
| **OU (Organizational Unit)** | Dossier logique pour organiser users/computers. Cible des GPOs. |
| **GPO (Group Policy Object)** | Règles de configuration déployées automatiquement (config, scripts, restrictions). |
| **LDAP** | Protocole de requête de l'annuaire (port 389/636). |
| **Kerberos** | Protocole d'authentification (tickets, pas de mot de passe sur le réseau). |

### GPO : Le Config Management Natif

```
GPO = Configuration as Code (mais en GUI... ou ADMX)

Exemples de GPOs :
├── Désactiver USB sur les postes
├── Configurer le proxy IE/Edge
├── Déployer un fond d'écran corporate
├── Mapper des lecteurs réseau
├── Exécuter un script au login
└── Forcer le verrouillage écran après 5 min
```

### Outils d'Administration

| Outil | Type | Usage |
|-------|------|-------|
| **RSAT** | GUI locale | Consoles MMC (AD Users, DNS, DHCP, GPO) installées sur un poste admin |
| **Windows Admin Center** | Web UI | Administration centralisée moderne (navigateur) |
| **PowerShell AD Module** | CLI | Automatisation, scripts, requêtes en masse |

```powershell
# Installer RSAT (Windows 10/11)
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0

# Module AD PowerShell
Import-Module ActiveDirectory

# Exemples de requêtes
Get-ADUser -Filter * | Select-Object Name, Enabled
Get-ADComputer -Filter * | Select-Object Name, LastLogonDate
Get-ADGroup -Filter * | Select-Object Name, GroupScope
```

---

## Services & Processus

### Gestion des Services

```powershell
# Lister tous les services
Get-Service

# Filtrer par état
Get-Service | Where-Object Status -eq "Running"
Get-Service | Where-Object Status -eq "Stopped"

# État d'un service spécifique
Get-Service -Name wuauserv
Get-Service -DisplayName "Windows Update"

# Démarrer / Arrêter / Redémarrer
Start-Service -Name wuauserv
Stop-Service -Name wuauserv
Restart-Service -Name wuauserv

# Configurer le démarrage automatique
Set-Service -Name wuauserv -StartupType Automatic
Set-Service -Name wuauserv -StartupType Manual
Set-Service -Name wuauserv -StartupType Disabled

# Services avec leur type de démarrage
Get-Service | Select-Object Name, Status, StartType

# Dépendances d'un service
Get-Service -Name wuauserv -DependentServices
Get-Service -Name wuauserv -RequiredServices
```

### Gestion des Processus

```powershell
# Lister les processus
Get-Process

# Trier par utilisation CPU/RAM
Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 Name, @{N='RAM_MB';E={[int]($_.WorkingSet64/1MB)}}

# Trouver un processus par nom
Get-Process -Name notepad
Get-Process -Name *chrome*

# Tuer un processus
Stop-Process -Name notepad
Stop-Process -Name notepad -Force    # Force kill
Stop-Process -Id 1234 -Force         # Par PID

# Lancer un processus
Start-Process notepad
Start-Process "C:\Program Files\App\app.exe"
Start-Process cmd -ArgumentList "/c", "dir" -NoNewWindow -Wait

# Processus avec ligne de commande complète
Get-CimInstance Win32_Process | Select-Object Name, ProcessId, CommandLine
```

### Services Critiques Windows

| Service | Nom | Rôle |
|---------|-----|------|
| `wuauserv` | Windows Update | Mises à jour |
| `W32Time` | Windows Time | Synchronisation NTP |
| `Netlogon` | Netlogon | Auth domaine |
| `DNS` | DNS Server | Résolution DNS (sur DC) |
| `NTDS` | AD Domain Services | Base AD (sur DC) |
| `WinRM` | Windows Remote Management | PowerShell Remoting |

---

## Administration Moderne : Windows Admin Center (WAC)

### Qu'est-ce que WAC ?

**Windows Admin Center = La Console Web pour Server Core**

```
┌─────────────────────────────────────────────────────────────┐
│                   ÉVOLUTION DE L'ADMIN                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  2000-2012 : MMC Consoles (RSAT)                            │
│  ────────────────────────────────                            │
│  ✗ GUI locale uniquement                                    │
│  ✗ Nécessite Windows sur le poste admin                     │
│  ✗ Pas de gestion centralisée                               │
│                                                              │
│  2012-2019 : PowerShell Remoting                            │
│  ──────────────────────────────                              │
│  ✓ Gestion à distance                                       │
│  ✗ CLI uniquement (pas user-friendly)                       │
│                                                              │
│  2019+ : Windows Admin Center (WAC)                         │
│  ─────────────────────────────────────                       │
│  ✓ Interface Web moderne (HTML5)                            │
│  ✓ Gestion multi-serveurs centralisée                       │
│  ✓ Extensions (Azure, Monitoring, etc.)                     │
│  ✓ Fonctionne sur Server Core                               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Installation

**Deux modes de déploiement :**

#### Mode 1 : Gateway (Production)

**WAC installé sur un serveur dédié pour gérer tout le datacenter.**

```powershell
# Télécharger WAC (https://aka.ms/wacdownload)
# Installation en mode Gateway
msiexec /i WindowsAdminCenter.msi /qn /L*v log.txt ^
  SME_PORT=443 ^
  SSL_CERTIFICATE_OPTION=generate

# Ou via PowerShell
Start-Process msiexec.exe -ArgumentList @(
  "/i", "WindowsAdminCenter.msi",
  "/qn",
  "SME_PORT=443",
  "SSL_CERTIFICATE_OPTION=generate"
) -Wait
```

**Accès :** `https://wac-server.corp.local`

**Avantages :**
- ✅ Gestion centralisée de tous les serveurs
- ✅ Accès depuis n'importe quel navigateur
- ✅ Certificat SSL centralisé
- ✅ RBAC (délégation d'accès)

#### Mode 2 : Local (Poste Admin)

**WAC installé sur Windows 10/11 pour gérer quelques serveurs.**

```powershell
# Installation en mode Desktop
msiexec /i WindowsAdminCenter.msi /qn /L*v log.txt ^
  SME_PORT=6516 ^
  SME_THUMBPRINT=auto

# Accès local
start https://localhost:6516
```

**Cas d'usage :**
- Poste d'admin pour gérer 5-10 serveurs
- Environnement de lab/test
- Pas besoin de serveur dédié

### Configuration Post-Installation

```powershell
# Autoriser WinRM sur les serveurs cibles
Enable-PSRemoting -Force

# Activer CredSSP (si nécessaire pour certaines tâches)
Enable-WSManCredSSP -Role Server -Force

# Ajouter WAC aux hôtes de confiance (sur les serveurs cibles)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "wac-server.corp.local" -Force
```

### Fonctionnalités Clés & Killer Features

**Dashboard centralisé pour gérer le parc 2019/2022/2025 de manière unifiée :**

| Fonctionnalité | Description | Killer Feature |
|----------------|-------------|----------------|
| **Server Manager** | Vue d'ensemble CPU/RAM/Disque en temps réel | |
| **Certificate Management** | Gestion des certificats SSL (création, renouvellement, ACME) | ⭐ **OUI** |
| **Event Viewer** | Visualisation moderne des logs (filtres, recherche, export) | ⭐ **OUI** |
| **Firewall** | Configuration GUI du firewall (équivalent `wf.msc`) | |
| **Files & File Sharing** | Explorateur de fichiers web, gestion des partages SMB | |
| **Local Users & Groups** | Gestion des comptes locaux | |
| **Roles & Features** | Installation/désinstallation de rôles (GUI) | |
| **Updates** | Windows Update centralisé | |
| **PowerShell** | Console PowerShell intégrée au navigateur (pas de SSH/RDP) | ⭐ **OUI** |
| **Remote Desktop** | RDP directement dans le navigateur (HTML5) | |

**Les 3 Killer Features de WAC :**

1. **Gestion des Certificats** : Créer, importer, renouveler des certificats SSL sans ligne de commande (voir section dédiée ci-dessous)
2. **Event Viewer Moderne** : Filtrage intelligent, recherche full-text, export CSV/JSON sans scripts PowerShell
3. **PowerShell Web** : Console PowerShell dans le navigateur, idéal pour administrer Server Core sans SSH

### Extensions WAC

**Étendre les fonctionnalités via des extensions :**

```powershell
# Lister les extensions disponibles
Get-WACSoftwareUpdate

# Installer une extension (via GUI)
# Settings → Extensions → Available Extensions
```

**Extensions populaires :**

| Extension | Usage |
|-----------|-------|
| **Azure Hybrid Services** | Intégration Azure Arc, Backup, Update Management |
| **Active Directory** | Gestion AD (Users, Groups, OUs) via Web |
| **DNS** | Gestion des zones DNS |
| **DHCP** | Gestion des scopes DHCP |
| **Storage Replica** | Réplication de stockage entre serveurs |
| **Cluster Manager** | Gestion de clusters Failover |

### Gestion des Certificats (Killer Feature)

**Problème classique :** Certificat auto-signé expiré sur IIS/RDP.

**Solution avec WAC :**

1. Se connecter au serveur via WAC
2. Aller dans **Settings → Access → SSL Certificate**
3. Options :
   - **Générer** un certificat auto-signé
   - **Importer** un certificat existant (PFX)
   - **Demander** un certificat via ACME (Let's Encrypt)

```powershell
# Automatiser avec PowerShell (Let's Encrypt via Posh-ACME)
Install-Module -Name Posh-ACME
New-PACertificate -Domain "web.corp.local" -AcceptTOS
```

### Avantages pour SecNumCloud

| Exigence SecNumCloud | WAC Répond |
|---------------------|-----------|
| **Audit & Logs** | Tous les accès tracés (Event Viewer + Syslog) |
| **RBAC** | Délégation granulaire (qui peut gérer quoi) |
| **MFA** | Intégration Azure AD (avec Conditional Access) |
| **Chiffrement** | HTTPS obligatoire (TLS 1.2+) |
| **Gestion Centralisée** | Un seul point d'administration |

!!! tip "Astuce : Intégration Azure Arc"
    Connecter WAC à Azure Arc permet :

    - **Update Management** : Centraliser les patchs de tous les serveurs on-prem
    - **Azure Monitor** : Métriques et logs dans Azure
    - **Azure Policy** : Appliquer des policies de conformité
    - **Azure Backup** : Sauvegardes automatiques vers Azure

---

## Windows Server 2025 Features

### Les Nouveautés Majeures

**Windows Server 2025 = Focus sur Cloud Hybride & Sécurité**

```
┌─────────────────────────────────────────────────────────────┐
│           ÉVOLUTION WINDOWS SERVER                           │
├─────────────────────────────────────────────────────────────┤
│  2019 : Conteneurs, Storage Replica                         │
│  2022 : Secured-core, Azure Arc                             │
│  2025 : Hotpatching, SMB over QUIC, SSH Natif               │
└─────────────────────────────────────────────────────────────┘
```

### Feature 1 : Hotpatching (Game Changer)

**Le Problème :**

```
Admin   : "On patche le serveur web ce soir"
Business: "Mais on a une vente flash cette nuit !"
Admin   : "Tant pis, reboot obligatoire pour les updates de sécurité"
Business: "On perd 100k€ de CA pendant 10 minutes de downtime..."
```

**La Solution : Hotpatching**

**Hotpatching = Mise à jour sans reboot**

```powershell
# Activer Hotpatching (nécessite Azure Arc)
# 1. Connecter le serveur à Azure Arc
azcmagent connect --tenant-id <TENANT_ID> --subscription-id <SUB_ID>

# 2. Activer Hotpatch via Azure Portal
# Settings → Update Management → Enable Hotpatch

# 3. Les updates de sécurité s'appliquent sans reboot
```

**Comment ça marche :**

```
┌─────────────────────────────────────────────────────────────┐
│                    HOTPATCH WORKFLOW                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Azure Update Management détecte une CVE                 │
│  2. Téléchargement du patch hotpatch-compatible             │
│  3. Application en mémoire (patching du code en live)       │
│  4. Processus redémarré (pas le serveur)                    │
│  5. Serveur reste online                                    │
│                                                              │
│  Reboot requis uniquement tous les 3-6 mois                 │
│  (pour les mises à jour majeures ou kernel)                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Limitations :**
- Nécessite **Azure Arc** (connexion cloud)
- Disponible uniquement sur **Datacenter Edition**
- Pas pour toutes les mises à jour (kernel updates nécessitent reboot)

**Bénéfices :**
- ✅ 90%+ des patchs de sécurité sans reboot
- ✅ Réduction du downtime planifié
- ✅ Conformité SecNumCloud facilitée (patchs rapides)

### Feature 2 : SSH Natif (OpenSSH Server)

**Le Problème Historique :**

```
Admin Linux : "ssh user@serveur"  → Connecté en 1 seconde
Admin Windows: "Télécharger PuTTY, configurer, lancer..."
               "Ou activer WinRM/PSRemoting..."
```

**La Solution : OpenSSH Server Intégré**

**OpenSSH est maintenant pré-installé et facile à activer.**

```powershell
# Vérifier si OpenSSH Server est installé
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'

# Installer si nécessaire (déjà présent sur Server 2025)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Activer et démarrer le service
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Ouvrir le port firewall (automatique sur Server 2025)
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

**Connexion depuis Linux/macOS :**

```bash
# Connexion SSH classique
ssh administrator@windows-server.corp.local

# Avec clé SSH (recommandé)
ssh -i ~/.ssh/id_rsa administrator@windows-server.corp.local

# SCP pour transférer des fichiers
scp file.txt administrator@windows-server.corp.local:C:\Temp\
```

**Configuration Avancée :**

```powershell
# Fichier de config SSH
notepad C:\ProgramData\ssh\sshd_config

# Options importantes
# PasswordAuthentication yes      # Auth par mot de passe
# PubkeyAuthentication yes         # Auth par clé SSH (recommandé)
# PermitRootLogin no               # Interdire login direct admin

# Redémarrer après modification
Restart-Service sshd
```

**Authentification par Clé SSH :**

```powershell
# Sur le serveur Windows (en admin)
# Créer le dossier .ssh
mkdir C:\Users\Administrator\.ssh

# Copier la clé publique (depuis Linux)
# Sur Linux : ssh-copy-id administrator@windows-server
# Ou manuellement :
echo "ssh-rsa AAAAB3Nza..." >> C:\Users\Administrator\.ssh\authorized_keys

# Permissions (importantes)
icacls C:\Users\Administrator\.ssh\authorized_keys /inheritance:r
icacls C:\Users\Administrator\.ssh\authorized_keys /grant "Administrator:F"
icacls C:\Users\Administrator\.ssh\authorized_keys /remove "NT AUTHORITY\Authenticated Users"
```

**Avantages :**
- ✅ Standard universel (compatibilité totale avec Linux/macOS)
- ✅ Authentification par clé SSH (plus sûr que mot de passe)
- ✅ SCP/SFTP natif pour transfert de fichiers
- ✅ Pas besoin de PuTTY ou autre outil tiers

!!! tip "Astuce : Shell par Défaut PowerShell"
    Configurer PowerShell comme shell SSH par défaut :

    ```powershell
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" `
      -Name DefaultShell `
      -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
      -PropertyType String -Force
    ```

### Feature 3 : SMB over QUIC (Révolutionnaire)

**Le Problème : Partages de Fichiers via Internet**

```
Scénario classique :
- Utilisateur en télétravail veut accéder à \\fileserver\share
- SMB (port 445) bloqué par les FAI et dangereux sur Internet
- Solution actuelle : VPN (lent, complexe, coûteux)
```

**La Solution : SMB over QUIC**

**SMB over QUIC = SMB chiffré via UDP 443 (comme HTTPS)**

```
┌─────────────────────────────────────────────────────────────┐
│                    SMB TRADITIONNEL                          │
│  Client ───TCP 445──→ Serveur                               │
│  ✗ Port 445 bloqué sur Internet                             │
│  ✗ Pas de chiffrement (sauf SMB 3.1.1)                      │
│  ✗ Nécessite VPN                                            │
├─────────────────────────────────────────────────────────────┤
│                    SMB over QUIC                             │
│  Client ───UDP 443──→ Serveur                               │
│  ✓ Port 443 (comme HTTPS, jamais bloqué)                    │
│  ✓ Chiffrement obligatoire (TLS 1.3)                        │
│  ✓ Pas besoin de VPN                                        │
│  ✓ Protocole QUIC (HTTP/3, ultra rapide)                    │
└─────────────────────────────────────────────────────────────┘
```

**Configuration :**

```powershell
# Sur le serveur (File Server)
# 1. Installer le rôle File Server
Install-WindowsFeature -Name FS-FileServer -IncludeManagementTools

# 2. Activer SMB over QUIC
Install-WindowsFeature -Name FS-SMB-OverQUIC

# 3. Créer un partage avec QUIC activé
New-SmbShare -Name "QuicShare" -Path "C:\Shares\QuicShare" `
  -EncryptData $true `
  -QUICTransport $true

# 4. Configurer le certificat (Let's Encrypt recommandé)
# Le serveur doit avoir un certificat SSL valide
# Le FQDN doit être résolvable publiquement
```

**Connexion depuis le client :**

```powershell
# Sur le client Windows 11
# Connexion via QUIC (automatique si le serveur l'expose)
net use Z: \\fileserver.corp.com\QuicShare

# Vérifier que QUIC est utilisé
Get-SmbConnection | Select-Object ServerName, TransportName

# Output attendu
# ServerName           TransportName
# ----------           -------------
# fileserver.corp.com  QUIC
```

**Cas d'Usage :**

| Scénario | Avant (VPN) | Après (SMB over QUIC) |
|----------|-------------|------------------------|
| **Télétravail** | VPN obligatoire | Accès direct via Internet |
| **Sites distants** | VPN site-to-site | Connexion directe sécurisée |
| **Cloud Hybride** | ExpressRoute/VPN | Connexion publique chiffrée |
| **Latence** | VPN overhead | QUIC ultra-rapide (UDP) |

**Prérequis :**
- Windows Server 2025 (File Server)
- Windows 11 22H2+ (Client)
- Certificat SSL valide sur le serveur
- Port UDP 443 ouvert (firewall)

**Avantages SecNumCloud :**
- ✅ Chiffrement TLS 1.3 obligatoire
- ✅ Authentification mutuelle (certificats client/serveur)
- ✅ Pas d'exposition du port 445 sur Internet
- ✅ Protocole moderne et performant (QUIC = HTTP/3)

!!! warning "Attention : DNS Public Requis"
    Le serveur SMB over QUIC doit avoir un FQDN résolvable publiquement :

    ```
    ✓ fileserver.company.com  (DNS public + certificat Let's Encrypt)
    ✗ fileserver.local        (DNS interne uniquement)
    ```

### Feature 4 : NVMe & Performance (Optimisations Stockage)

**Windows Server 2025 = Support NVMe Avancé**

**Nouveautés stockage dans Server 2025 :**

| Amélioration | Description | Gain |
|--------------|-------------|------|
| **NVMe over Fabrics** | Support natif de NVMe-oF (Ethernet, Fibre Channel) | Latence ultra-basse (<100µs) |
| **ReFS v3.8** | Nouvelle version du système de fichiers résilient | +20% IOPS sur NVMe |
| **Storage Spaces Direct** | Optimisations pour NVMe pooling | Débit agrégé +30% |
| **DirectStorage API** | API pour I/O directes (bypass kernel) | Latence réduite de 50% |

```powershell
# Vérifier les disques NVMe
Get-PhysicalDisk | Where-Object MediaType -eq "SSD" |
    Select-Object FriendlyName, BusType, Size, HealthStatus

# Optimiser NVMe (alignement, trim)
Optimize-Volume -DriveLetter C -Defrag -Verbose

# Activer ReFS sur un volume de données
Format-Volume -DriveLetter D -FileSystem ReFS -SetIntegrityStreams $true
```

**Gains de Performance Mesurés (Tests Microsoft) :**

```
Scénario : Serveur Hyper-V avec VMs sur NVMe

Windows Server 2022  →  2025
────────────────────────────
IOPS séquentiels   : 850K  →  1.1M (+29%)
Latence moyenne    : 120µs →  65µs  (-46%)
Throughput agrégé  : 12GB/s → 16GB/s (+33%)
```

!!! tip "Astuce Production"
    Pour les charges de travail intensives (SQL, VMs, containers) :

    - Privilégier **ReFS** sur les volumes de données NVMe (meilleur que NTFS pour les gros fichiers)
    - Activer **Storage Spaces Direct** pour pooler plusieurs NVMe en un volume unique ultra-rapide
    - Utiliser **NVMe-oF** pour les clusters Hyper-V (stockage partagé sans SAN traditionnel)

---

## Référence Rapide

```powershell
# === SERVER CORE ===
sconfig                                    # Menu configuration

# === RÔLES ===
Get-WindowsFeature                         # Lister les rôles
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# === PACKAGE MANAGEMENT ===
# Winget
winget search git
winget install Git.Git --silent
winget upgrade --all

# Chocolatey
choco install git 7zip -y
choco upgrade all -y

# === SERVICES ===
Get-Service -Name wuauserv                 # État
Start-Service -Name wuauserv               # Démarrer
Stop-Service -Name wuauserv                # Arrêter
Set-Service -Name wuauserv -StartupType Automatic

# === PROCESSUS ===
Get-Process                                # Lister
Get-Process | Sort-Object CPU -Desc | Select-Object -First 10
Stop-Process -Name notepad -Force          # Tuer

# === AD (si module installé) ===
Import-Module ActiveDirectory
Get-ADUser -Filter *
Get-ADComputer -Filter *
```
