---
tags:
  - formation
  - windows-server
  - administration
  - outils
---

# Module 04 : Outils d'Administration

## Objectifs du Module

Ce module présente les outils d'administration Windows Server :

- Maîtriser Windows Admin Center (WAC)
- Utiliser les consoles MMC et snap-ins
- Exploiter l'Observateur d'événements
- Monitorer les performances
- Administrer à distance avec RSAT

**Durée :** 6 heures

**Niveau :** Débutant

---

## 1. Windows Admin Center (WAC)

### 1.1 Présentation

Windows Admin Center est l'interface moderne d'administration Microsoft :

```
┌─────────────────────────────────────────────────────────────┐
│              WINDOWS ADMIN CENTER                            │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ✓ Interface web moderne (HTML5)                            │
│  ✓ Remplace progressivement les MMC                         │
│  ✓ Gestion centralisée de plusieurs serveurs                │
│  ✓ PowerShell intégré                                       │
│  ✓ Extensible via extensions                                │
│  ✓ Gratuit                                                  │
│                                                              │
│  Fonctionnalités :                                          │
│  • Dashboard système                                         │
│  • Gestion des fichiers                                      │
│  • Configuration réseau                                      │
│  • Gestion des rôles et features                            │
│  • Hyper-V management                                        │
│  • Azure integration                                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 1.2 Installation

```powershell
# Télécharger WAC
# https://aka.ms/wacdownload

# Ou via PowerShell
$wacUrl = "https://aka.ms/wacdownload"
$wacInstaller = "C:\Temp\WindowsAdminCenter.msi"
Invoke-WebRequest -Uri $wacUrl -OutFile $wacInstaller

# Installation silencieuse
msiexec /i $wacInstaller /qn /L*v C:\Temp\wac_install.log SME_PORT=6516 SSL_CERTIFICATE_OPTION=generate

# Ou installation avec certificat existant
# msiexec /i $wacInstaller /qn SME_PORT=443 SME_THUMBPRINT=<thumbprint>
```

### 1.3 Modes de Déploiement

| Mode | Description | Usage |
|------|-------------|-------|
| **Desktop** | Sur Windows 10/11 | Administration personnelle |
| **Gateway** | Sur un serveur | Multi-utilisateurs, centralisé |
| **Failover Cluster** | Haute disponibilité | Production critique |

### 1.4 Accès et Connexion

```powershell
# Accès local
https://localhost:6516

# Accès distant
https://wac-server.domain.com:6516

# Ajouter un serveur à gérer
# 1. Cliquer "Add"
# 2. Choisir "Server"
# 3. Entrer le nom du serveur
# 4. Credentials si nécessaire
```

### 1.5 Fonctionnalités Principales

**Dashboard :**
- Vue d'ensemble CPU, RAM, Disque, Réseau
- Alertes et événements récents
- État des services

**Outils disponibles :**

| Outil | Description |
|-------|-------------|
| Overview | Dashboard système |
| Certificates | Gestion certificats |
| Devices | Périphériques |
| Events | Journaux d'événements |
| Files & file sharing | Explorateur + partages |
| Firewall | Windows Firewall |
| Installed apps | Applications installées |
| Local users & groups | Gestion utilisateurs |
| Network | Configuration réseau |
| PowerShell | Console PowerShell distante |
| Processes | Gestionnaire de processus |
| Registry | Éditeur du registre |
| Roles & Features | Installation rôles |
| Scheduled tasks | Tâches planifiées |
| Services | Gestion services |
| Storage | Stockage et disques |
| Updates | Windows Update |
| Virtual Machines | Hyper-V (si installé) |

---

## 2. Consoles MMC

### 2.1 Microsoft Management Console

```powershell
# Lancer une console vide
mmc

# Structure d'une console MMC
# ┌─────────────────────────────────────────┐
# │ Console Root                            │
# ├─────────────────────────────────────────┤
# │ ├── Snap-in 1                          │
# │ │   ├── Noeud 1                        │
# │ │   └── Noeud 2                        │
# │ └── Snap-in 2                          │
# └─────────────────────────────────────────┘
```

### 2.2 Consoles Préconfigurées

```powershell
# Consoles courantes (fichiers .msc)

# Système
compmgmt.msc      # Computer Management (tout-en-un)
devmgmt.msc       # Device Manager
diskmgmt.msc      # Disk Management
services.msc      # Services
taskschd.msc      # Task Scheduler

# Sécurité
secpol.msc        # Local Security Policy
gpedit.msc        # Local Group Policy Editor
lusrmgr.msc       # Local Users and Groups
certlm.msc        # Certificates (Local Machine)
certmgr.msc       # Certificates (Current User)

# Journaux et monitoring
eventvwr.msc      # Event Viewer
perfmon.msc       # Performance Monitor
resmon.exe        # Resource Monitor

# Réseau
wf.msc            # Windows Firewall Advanced
ncpa.cpl          # Network Connections (Control Panel)

# Active Directory (si RSAT installé)
dsa.msc           # Active Directory Users and Computers
dssite.msc        # Active Directory Sites and Services
domain.msc        # Active Directory Domains and Trusts
gpmc.msc          # Group Policy Management

# Serveur
dnsmgmt.msc       # DNS Manager
dhcpmgmt.msc      # DHCP Manager
```

### 2.3 Créer une Console Personnalisée

```powershell
# 1. Lancer mmc
mmc

# 2. File → Add/Remove Snap-in (Ctrl+M)

# 3. Sélectionner les snap-ins souhaités :
#    - Event Viewer
#    - Services
#    - Computer Management
#    - etc.

# 4. Pour chaque snap-in, choisir :
#    - Local computer
#    - Another computer (pour admin distante)

# 5. File → Save As → MaConsole.msc

# 6. Lancer la console personnalisée
C:\Admin\MaConsole.msc
```

---

## 3. Observateur d'Événements

### 3.1 Structure des Journaux

```
┌─────────────────────────────────────────────────────────────┐
│              OBSERVATEUR D'ÉVÉNEMENTS                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Event Viewer                                                │
│  ├── Custom Views                                           │
│  │   └── Administrative Events (erreurs et warnings)        │
│  ├── Windows Logs                                           │
│  │   ├── Application    (apps et services)                  │
│  │   ├── Security       (authentification, audit)           │
│  │   ├── Setup          (installation Windows)              │
│  │   ├── System         (kernel, drivers, services)         │
│  │   └── Forwarded Events                                   │
│  └── Applications and Services Logs                         │
│      ├── Microsoft                                          │
│      │   └── Windows                                        │
│      │       ├── PowerShell                                 │
│      │       ├── TaskScheduler                              │
│      │       └── ...                                        │
│      └── [Applications tierces]                             │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Niveaux d'Événements

| Niveau | Description | Icône |
|--------|-------------|-------|
| **Critical** | Échec critique | Rouge avec X |
| **Error** | Erreur significative | Rouge avec X |
| **Warning** | Problème potentiel | Jaune avec ! |
| **Information** | Opération normale | Bleu avec i |
| **Verbose** | Détails supplémentaires | Gris |

### 3.3 Événements de Sécurité Importants

| Event ID | Description | Importance |
|----------|-------------|------------|
| **4624** | Connexion réussie | Info |
| **4625** | Échec de connexion | Attention |
| **4634** | Déconnexion | Info |
| **4648** | Connexion avec identifiants explicites | Attention |
| **4720** | Compte utilisateur créé | Audit |
| **4722** | Compte activé | Audit |
| **4723** | Tentative changement mot de passe | Audit |
| **4724** | Reset mot de passe par admin | Audit |
| **4725** | Compte désactivé | Audit |
| **4726** | Compte supprimé | Audit |
| **4728** | Membre ajouté à groupe de sécurité | Audit |
| **4732** | Membre ajouté à groupe local | Audit |
| **4756** | Membre ajouté à groupe universel | Audit |

### 3.4 Consultation avec PowerShell

```powershell
# Lister les journaux
Get-EventLog -List

# Derniers événements System
Get-EventLog -LogName System -Newest 10

# Filtrer par type
Get-EventLog -LogName System -EntryType Error -Newest 20

# Rechercher par Event ID
Get-EventLog -LogName Security -InstanceId 4624 -Newest 10

# Utiliser Get-WinEvent (plus moderne)
Get-WinEvent -LogName System -MaxEvents 10

# Filtrer avec FilterHashtable (recommandé)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624, 4625
    StartTime = (Get-Date).AddDays(-1)
}

# Filtrer les erreurs récentes
Get-WinEvent -FilterHashtable @{
    LogName = 'System'
    Level = 2  # Error
    StartTime = (Get-Date).AddHours(-24)
}

# Exporter en CSV
Get-WinEvent -LogName Security -MaxEvents 1000 |
    Select-Object TimeCreated, Id, Message |
    Export-Csv C:\Temp\security-events.csv -NoTypeInformation
```

### 3.5 Créer une Vue Personnalisée

```powershell
# Via GUI : Event Viewer → Custom Views → Create Custom View

# Via PowerShell (XML filter)
$filter = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625) and
        TimeCreated[timediff(@SystemTime) &lt;= 86400000]]]
    </Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $filter
```

---

## 4. Moniteur de Performances

### 4.1 Présentation

```powershell
# Lancer le moniteur de performances
perfmon.msc

# Resource Monitor (vue temps réel)
resmon.exe
```

### 4.2 Compteurs Importants

| Catégorie | Compteur | Seuil d'Alerte |
|-----------|----------|----------------|
| **Processor** | % Processor Time | > 80% soutenu |
| **Memory** | Available MBytes | < 200 MB |
| **Memory** | Pages/sec | > 1000 |
| **PhysicalDisk** | Avg. Disk Queue Length | > 2 |
| **PhysicalDisk** | % Disk Time | > 90% |
| **Network** | Bytes Total/sec | Selon capacité |

### 4.3 Utiliser PowerShell

```powershell
# Lister les compteurs disponibles
Get-Counter -ListSet * | Select-Object CounterSetName

# Obtenir des compteurs spécifiques
Get-Counter -Counter "\Processor(_Total)\% Processor Time"

# Plusieurs compteurs
Get-Counter -Counter @(
    "\Processor(_Total)\% Processor Time",
    "\Memory\Available MBytes",
    "\PhysicalDisk(_Total)\Avg. Disk Queue Length"
)

# Monitoring continu
Get-Counter -Counter "\Processor(_Total)\% Processor Time" -Continuous -SampleInterval 2

# Exporter vers fichier
Get-Counter -Counter "\Processor(_Total)\% Processor Time" -MaxSamples 60 -SampleInterval 1 |
    Export-Counter -Path C:\Temp\cpu.blg
```

### 4.4 Data Collector Sets

```powershell
# Via GUI : perfmon → Data Collector Sets

# Créer via PowerShell (utilise logman)
logman create counter CPUMemory -c "\Processor(_Total)\% Processor Time" "\Memory\Available MBytes" -si 5 -f csv -o C:\Temp\perf

# Démarrer la collecte
logman start CPUMemory

# Arrêter la collecte
logman stop CPUMemory

# Supprimer
logman delete CPUMemory
```

---

## 5. RSAT (Remote Server Administration Tools)

### 5.1 Installation

```powershell
# Lister les fonctionnalités RSAT disponibles
Get-WindowsCapability -Name RSAT* -Online

# Installer toutes les RSAT
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

# Installer des outils spécifiques
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.Dns.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0
Add-WindowsCapability -Online -Name Rsat.ServerManager.Tools~~~~0.0.1.0

# Vérifier l'installation
Get-WindowsCapability -Name RSAT* -Online | Where-Object State -eq "Installed"
```

### 5.2 Outils RSAT Principaux

| Outil | Fonctionnalité |
|-------|----------------|
| Active Directory Users and Computers | Gestion AD |
| Active Directory Sites and Services | Réplication AD |
| Group Policy Management | GPO |
| DNS Manager | DNS |
| DHCP Manager | DHCP |
| Server Manager | Vue d'ensemble serveurs |
| Hyper-V Manager | Virtualisation |
| Failover Cluster Manager | Clustering |

### 5.3 Administration Distante

```powershell
# Se connecter à un serveur distant via RSAT
# 1. Lancer l'outil (dsa.msc, dnsmgmt.msc, etc.)
# 2. Action → Connect to another computer
# 3. Entrer le nom du serveur

# Ou depuis PowerShell
# Lancer AD Users & Computers connecté à un DC
mmc dsa.msc /server:DC01.domain.com

# DNS Manager sur un serveur DNS
mmc dnsmgmt.msc /server:DNS01.domain.com
```

---

## 6. Server Manager

### 6.1 Présentation

Server Manager est la console centralisée de Windows Server :

```powershell
# Lancer Server Manager
servermanager.exe

# Ou depuis PowerShell
sconfig  # Sur Server Core, alternative simplifiée
```

### 6.2 Fonctionnalités

```
┌─────────────────────────────────────────────────────────────┐
│                   SERVER MANAGER                             │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Dashboard                                                   │
│  ├── Serveurs gérés                                         │
│  ├── Rôles installés                                        │
│  └── Alertes et événements                                  │
│                                                              │
│  Fonctionnalités :                                          │
│  • Ajouter/supprimer des rôles et features                  │
│  • Gérer plusieurs serveurs depuis un point                 │
│  • Accéder aux outils d'administration                      │
│  • Best Practices Analyzer                                  │
│  • Créer des groupes de serveurs                            │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 Ajouter des Serveurs

```powershell
# Via GUI : Server Manager → Manage → Add Servers

# Via PowerShell
# Les serveurs ajoutés sont stockés dans le profil de l'utilisateur

# Alternative : Utiliser PowerShell pour interroger plusieurs serveurs
$servers = "SRV01", "SRV02", "SRV03"
Invoke-Command -ComputerName $servers -ScriptBlock { Get-Service | Where-Object Status -eq "Running" }
```

---

## 7. Task Scheduler

### 7.1 Présentation

```powershell
# Ouvrir le planificateur
taskschd.msc
```

### 7.2 Créer une Tâche Planifiée (GUI)

```
1. Task Scheduler → Create Task
2. General :
   - Nom de la tâche
   - Run whether user is logged on or not
   - Run with highest privileges (si admin nécessaire)
3. Triggers :
   - Daily, Weekly, At startup, etc.
4. Actions :
   - Start a program
   - Program: powershell.exe
   - Arguments: -ExecutionPolicy Bypass -File C:\Scripts\myscript.ps1
5. Conditions et Settings selon besoins
```

### 7.3 Créer avec PowerShell

```powershell
# Créer une action
$action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -File C:\Scripts\backup.ps1"

# Créer un trigger (quotidien à 2h)
$trigger = New-ScheduledTaskTrigger -Daily -At "02:00"

# Créer les paramètres
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1)

# Créer le principal (compte d'exécution)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Enregistrer la tâche
Register-ScheduledTask -TaskName "Daily Backup" `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal

# Lister les tâches
Get-ScheduledTask | Where-Object TaskName -like "*Backup*"

# Exécuter manuellement
Start-ScheduledTask -TaskName "Daily Backup"

# Désactiver
Disable-ScheduledTask -TaskName "Daily Backup"

# Supprimer
Unregister-ScheduledTask -TaskName "Daily Backup" -Confirm:$false
```

---

## 8. Exercices Pratiques

### Exercice 1 : Installation WAC

**Objectif :** Installer et configurer Windows Admin Center.

**Tâches :**

1. Télécharger WAC
2. Installer en mode Gateway sur port 443
3. Ajouter le serveur local
4. Explorer les différents outils

**Solution :**

```powershell
# Télécharger
$wacUrl = "https://aka.ms/wacdownload"
Invoke-WebRequest -Uri $wacUrl -OutFile C:\Temp\wac.msi

# Installer
msiexec /i C:\Temp\wac.msi /qn SME_PORT=443 SSL_CERTIFICATE_OPTION=generate

# Attendre l'installation
Start-Sleep -Seconds 60

# Ouvrir dans le navigateur
Start-Process "https://localhost"
```

---

### Exercice 2 : Analyse des Événements

**Objectif :** Analyser les journaux d'événements.

**Tâches :**

1. Trouver les 10 dernières erreurs système
2. Compter les échecs de connexion des dernières 24h
3. Exporter les événements de sécurité critiques

**Solution :**

```powershell
# 1. Dernières erreurs système
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 10 |
    Format-Table TimeCreated, Id, Message -Wrap

# 2. Échecs de connexion (4625) dernières 24h
$loginFailures = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4625
    StartTime = (Get-Date).AddDays(-1)
} -ErrorAction SilentlyContinue

Write-Host "Nombre d'échecs de connexion: $($loginFailures.Count)"

# 3. Export événements sécurité critiques
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Level = 1, 2  # Critical et Error
} -MaxEvents 100 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Export-Csv C:\Temp\security-critical.csv -NoTypeInformation
```

---

### Exercice 3 : Monitoring Performance

**Objectif :** Créer un Data Collector Set personnalisé.

**Tâches :**

1. Créer un collecteur pour CPU, RAM, Disque
2. Collecter pendant 1 minute avec intervalle de 5 secondes
3. Analyser les résultats

**Solution :**

```powershell
# Créer le collecteur
logman create counter "LabPerfMon" -c `
    "\Processor(_Total)\% Processor Time" `
    "\Memory\Available MBytes" `
    "\Memory\% Committed Bytes In Use" `
    "\PhysicalDisk(_Total)\Avg. Disk Queue Length" `
    -si 5 -f csv -o C:\Temp\perf_data

# Démarrer
logman start "LabPerfMon"

# Attendre 1 minute
Start-Sleep -Seconds 60

# Arrêter
logman stop "LabPerfMon"

# Analyser
$data = Import-Csv "C:\Temp\perf_data*.csv"
$data | Format-Table

# Nettoyer
logman delete "LabPerfMon"
```

---

## 9. Quiz de Validation

### Questions

1. **Quel port utilise WAC par défaut ?**
   - [ ] A. 443
   - [ ] B. 6516
   - [ ] C. 3389

2. **Quel Event ID correspond à une connexion réussie ?**
   - [ ] A. 4625
   - [ ] B. 4624
   - [ ] C. 4720

3. **Quelle commande liste les compteurs de performance ?**
   - [ ] A. Get-Counter -ListSet *
   - [ ] B. Get-PerfCounter
   - [ ] C. List-Counter

4. **Où sont stockés les journaux Windows ?**
   - [ ] A. C:\Logs
   - [ ] B. C:\Windows\System32\winevt\Logs
   - [ ] C. C:\Windows\Logs\Events

5. **Quelle cmdlet crée une tâche planifiée ?**
   - [ ] A. New-Task
   - [ ] B. Register-ScheduledTask
   - [ ] C. Create-ScheduledTask

### Réponses

1. **B** - 6516 (ou 443 si configuré)
2. **B** - 4624
3. **A** - Get-Counter -ListSet *
4. **B** - C:\Windows\System32\winevt\Logs
5. **B** - Register-ScheduledTask

---

## 10. Ressources

- [Windows Admin Center Documentation](https://docs.microsoft.com/windows-server/manage/windows-admin-center/)
- [Event Log Reference](https://docs.microsoft.com/windows/security/threat-protection/auditing/)
- [Performance Monitor Guide](https://docs.microsoft.com/windows-server/administration/performance-tuning/)

---

**Précédent :** [Module 03 : Utilisateurs & NTFS](03-utilisateurs-ntfs.md)

**Suivant :** [Module 05 : Introduction au Scripting](05-scripting-intro.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 03 : Utilisateurs & NTFS](03-utilisateurs-ntfs.md) | [Module 05 : Introduction au Scripting →](05-scripting-intro.md) |

[Retour au Programme](index.md){ .md-button }
