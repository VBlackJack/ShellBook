---
tags:
  - windows
  - active-directory
  - gpo
  - group-policy
---

# Group Policy Objects (GPO) - Guide Complet

Les GPO permettent de configurer et sécuriser de manière centralisée les postes et utilisateurs d'un domaine Active Directory.

## Architecture des GPO

### Hiérarchie d'Application

```
ORDRE D'APPLICATION DES GPO (LSDOU)
══════════════════════════════════════════════════════════

Local Policy          ← Appliquée en premier (moins prioritaire)
    │
    ▼
Site Policy           ← GPO liées aux sites AD
    │
    ▼
Domain Policy         ← GPO liées au domaine
    │
    ▼
OU Policy             ← GPO liées aux OUs (ordre hiérarchique)
    │
    ▼
Child OU Policy       ← Plus prioritaire (appliquée en dernier)

RÈGLE : La dernière GPO appliquée "gagne" en cas de conflit.
```

### Composants d'une GPO

```
STRUCTURE D'UNE GPO
══════════════════════════════════════════════════════════

GPO "Corporate Security"
├── Computer Configuration
│   ├── Policies
│   │   ├── Software Settings
│   │   ├── Windows Settings
│   │   │   ├── Security Settings
│   │   │   └── Scripts (Startup/Shutdown)
│   │   └── Administrative Templates
│   └── Preferences
│       ├── Windows Settings
│       └── Control Panel Settings
│
└── User Configuration
    ├── Policies
    │   ├── Software Settings
    │   ├── Windows Settings
    │   │   └── Scripts (Logon/Logoff)
    │   └── Administrative Templates
    └── Preferences
        ├── Windows Settings
        └── Control Panel Settings
```

---

## Gestion des GPO

### Commandes PowerShell de Base

```powershell
# Importer le module
Import-Module GroupPolicy

# Lister toutes les GPO
Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime

# Créer une nouvelle GPO
New-GPO -Name "Security-Baseline-Workstations" -Comment "Baseline sécurité postes"

# Lier une GPO à une OU
New-GPLink -Name "Security-Baseline-Workstations" `
    -Target "OU=Workstations,OU=Computers,DC=corp,DC=local"

# Copier une GPO existante
Copy-GPO -SourceName "Template-Security" -TargetName "Security-Paris"

# Supprimer une GPO
Remove-GPO -Name "Old-Policy"

# Backup d'une GPO
Backup-GPO -Name "Security-Baseline" -Path "C:\GPO-Backups"

# Backup de toutes les GPO
Backup-GPO -All -Path "C:\GPO-Backups"

# Restaurer une GPO
Restore-GPO -Name "Security-Baseline" -Path "C:\GPO-Backups"
```

### Rapports et Documentation

```powershell
# Rapport HTML d'une GPO
Get-GPOReport -Name "Security-Baseline" -ReportType HTML -Path "C:\Reports\baseline.html"

# Rapport de toutes les GPO
Get-GPO -All | ForEach-Object {
    Get-GPOReport -Guid $_.Id -ReportType HTML -Path "C:\Reports\$($_.DisplayName).html"
}

# Rapport XML (pour parsing)
Get-GPOReport -Name "Security-Baseline" -ReportType XML -Path "C:\Reports\baseline.xml"

# Résultat des GPO appliquées (RSoP)
Get-GPResultantSetOfPolicy -Computer "PC001" -User "CORP\jdoe" -ReportType HTML -Path "C:\rsop.html"
```

---

## Filtrage des GPO

### Filtrage de Sécurité

```powershell
# Voir les permissions d'une GPO
Get-GPPermission -Name "Security-Baseline" -All

# Retirer "Authenticated Users" (appliqué par défaut à tous)
Set-GPPermission -Name "Security-Baseline" `
    -TargetName "Authenticated Users" `
    -TargetType Group `
    -PermissionLevel None

# Appliquer uniquement à un groupe spécifique
Set-GPPermission -Name "Security-Baseline" `
    -TargetName "GRP-Workstations" `
    -TargetType Group `
    -PermissionLevel GpoApply

# Autoriser la lecture (pour admin)
Set-GPPermission -Name "Security-Baseline" `
    -TargetName "IT-Admins" `
    -TargetType Group `
    -PermissionLevel GpoRead
```

### Filtrage WMI

Les filtres WMI permettent d'appliquer une GPO selon des critères dynamiques.

```powershell
# Créer un filtre WMI - Windows 11 uniquement
$wmiFilter = @"
SELECT * FROM Win32_OperatingSystem
WHERE Version LIKE "10.0.22%" AND ProductType = "1"
"@

New-GPWmiFilter -Name "Windows 11 Workstations" `
    -Expression $wmiFilter `
    -Description "Filtre pour Windows 11"

# Lier le filtre WMI à une GPO (via GPMC GUI ou ADSI)
```

#### Exemples de Filtres WMI

```sql
-- Windows 11 uniquement
SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.0.22%"

-- Windows Server 2022
SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.0.20348%"

-- Serveurs uniquement (ProductType: 1=Workstation, 2=DC, 3=Server)
SELECT * FROM Win32_OperatingSystem WHERE ProductType > 1

-- Postes avec plus de 8 GB RAM
SELECT * FROM Win32_ComputerSystem WHERE TotalPhysicalMemory >= 8589934592

-- Laptops uniquement
SELECT * FROM Win32_ComputerSystem WHERE PCSystemType = 2

-- Architecture 64-bit
SELECT * FROM Win32_Processor WHERE AddressWidth = 64

-- Membre d'un groupe (via nom de machine)
SELECT * FROM Win32_ComputerSystem WHERE Name LIKE "PC-PARIS%"
```

```powershell
# Tester un filtre WMI localement
Get-WmiObject -Query "SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10.0.22%'"
```

---

## Preferences vs Policies

```
PREFERENCES VS POLICIES
══════════════════════════════════════════════════════════

POLICIES (Stratégies)
─────────────────────
• Forcent une configuration
• L'utilisateur ne peut PAS modifier
• Paramètre "tatoué" dans le registre
• Supprimé si GPO retirée (selon paramètre)

Exemple : Désactiver le panneau de configuration
→ L'utilisateur ne voit pas l'option


PREFERENCES (Préférences)
─────────────────────────
• Définissent une valeur par défaut
• L'utilisateur PEUT modifier
• Configuration initiale uniquement
• Reste si GPO retirée

Exemple : Définir le fond d'écran par défaut
→ L'utilisateur peut le changer après
```

### Item-Level Targeting (Preferences)

```xml
<!-- Ciblage fin des préférences -->
<!-- Exemple : Mapper un lecteur réseau pour le département Finance -->

<Filters>
  <FilterGroup name="Finance-Users" sid="S-1-5-21-xxx" userContext="1" />
  <FilterOrgUnit name="OU=Finance,OU=Users,DC=corp,DC=local" userContext="1" />
</Filters>
```

Critères de ciblage disponibles :
- Groupe de sécurité
- Utilisateur/Ordinateur
- Unité d'organisation
- Site AD
- Plage IP
- Système d'exploitation
- Variable d'environnement
- Requête WMI
- Registre
- Fichier/Dossier existant

---

## GPO Courantes

### Sécurité - Mot de Passe

```
Computer Configuration
└── Policies
    └── Windows Settings
        └── Security Settings
            └── Account Policies
                └── Password Policy

Paramètres recommandés :
• Enforce password history: 24 passwords
• Maximum password age: 90 days
• Minimum password age: 1 day
• Minimum password length: 14 characters
• Password must meet complexity: Enabled
```

### Sécurité - Verrouillage de Compte

```
Computer Configuration
└── Policies
    └── Windows Settings
        └── Security Settings
            └── Account Policies
                └── Account Lockout Policy

Paramètres recommandés :
• Account lockout duration: 30 minutes
• Account lockout threshold: 5 invalid attempts
• Reset lockout counter after: 30 minutes
```

### Restriction Logicielle

```
Computer Configuration
└── Policies
    └── Windows Settings
        └── Security Settings
            └── Software Restriction Policies

Ou mieux : AppLocker / WDAC (voir ad-applocker.md)
```

### Mappage de Lecteurs (Preferences)

```
User Configuration
└── Preferences
    └── Windows Settings
        └── Drive Maps

Action: Create
Location: \\fileserver\share$
Label: "Données Partagées"
Letter: S:
```

### Scripts de Démarrage

```
Computer Configuration
└── Policies
    └── Windows Settings
        └── Scripts (Startup/Shutdown)
            └── Startup

Script: \\corp.local\NETLOGON\Scripts\startup.ps1
```

---

## Héritage et Blocage

### Bloquer l'Héritage

```powershell
# Bloquer l'héritage sur une OU
Set-GPInheritance -Target "OU=Servers,DC=corp,DC=local" -IsBlocked Yes

# Vérifier le blocage
Get-GPInheritance -Target "OU=Servers,DC=corp,DC=local"
```

### Forcer une GPO (Enforced)

```powershell
# Forcer une GPO (ignore le blocage d'héritage)
Set-GPLink -Name "Security-Mandatory" `
    -Target "DC=corp,DC=local" `
    -Enforced Yes

# L'option "Enforced" garantit que la GPO s'applique même si
# une OU enfant bloque l'héritage
```

```
HÉRITAGE ET ENFORCEMENT
══════════════════════════════════════════════════════════

Domain (GPO-A)
    │
    ├── OU=Corp (GPO-B)
    │       │
    │       └── OU=Servers [Block Inheritance] (GPO-C)
    │               │
    │               └── SRV-WEB-01

Sans Enforced :
  SRV-WEB-01 reçoit : GPO-C uniquement (héritage bloqué)

Avec GPO-A Enforced :
  SRV-WEB-01 reçoit : GPO-A (forcée) + GPO-C
```

---

## Loopback Processing

Le Loopback permet d'appliquer des GPO utilisateur selon l'ordinateur.

```
LOOPBACK PROCESSING
══════════════════════════════════════════════════════════

Cas d'usage : Kiosques, salles de formation, serveurs RDS

Mode "Replace" :
  Les GPO utilisateur de l'OU de l'ordinateur REMPLACENT
  celles de l'OU de l'utilisateur.

Mode "Merge" :
  Les GPO utilisateur de l'OU de l'ordinateur S'AJOUTENT
  à celles de l'OU de l'utilisateur.

Configuration :
Computer Configuration
└── Policies
    └── Administrative Templates
        └── System
            └── Group Policy
                └── Configure user Group Policy loopback processing mode
                    → Enabled, Mode: Replace (ou Merge)
```

---

## Troubleshooting

### Diagnostic de Base

```powershell
# Forcer la mise à jour des GPO
gpupdate /force

# Mise à jour avec redémarrage si nécessaire
gpupdate /force /boot /logoff

# Résultat des GPO (mode interactif)
gpresult /r

# RSoP détaillé en HTML
gpresult /h C:\gpresult.html /f

# RSoP pour un utilisateur spécifique
gpresult /user CORP\jdoe /h C:\gpresult-jdoe.html

# RSoP distant
gpresult /s PC001 /user CORP\jdoe /h C:\gpresult-remote.html
```

### Vérification du Traitement

```powershell
# Event Log Group Policy
Get-WinEvent -LogName "Microsoft-Windows-GroupPolicy/Operational" -MaxEvents 50 |
    Select-Object TimeCreated, Id, Message | Format-Table -Wrap

# Événements d'erreur GPO
Get-WinEvent -FilterHashtable @{
    LogName = "Microsoft-Windows-GroupPolicy/Operational"
    Level = 2  # Error
} -MaxEvents 20
```

### Problèmes Courants

```
TROUBLESHOOTING GPO
══════════════════════════════════════════════════════════

GPO non appliquée :
───────────────────
1. Vérifier le lien : Get-GPLink
2. Vérifier le filtrage de sécurité
3. Vérifier le filtre WMI
4. Vérifier l'héritage bloqué
5. Vérifier le status (Enabled/Disabled)

gpresult /r | findstr "applied"

Lenteur au démarrage :
──────────────────────
1. Trop de GPO (consolider)
2. Scripts longs au startup
3. Preferences mal configurées
4. Filtres WMI complexes

Activer le logging détaillé :
HKLM\Software\Policies\Microsoft\Windows\Group Policy\
  {35378EAC-683F-11D2-A89A-00C04FBBCFA2}
    LogLevel = 0x10002 (DWORD)
    TraceLevel = 2 (DWORD)

Conflit de paramètres :
───────────────────────
Utiliser RSoP pour identifier la GPO "gagnante"
gpresult /h report.html
```

### Réplication SYSVOL

```powershell
# Vérifier la réplication SYSVOL (DFS-R)
Get-DfsrBacklog -GroupName "Domain System Volume" `
    -SourceComputerName DC01 `
    -DestinationComputerName DC02

# Forcer la réplication
Sync-DfsReplicationGroup -GroupName "Domain System Volume" -SourceComputerName DC01

# Vérifier l'état DFS-R
dfsrdiag pollad
```

---

## Bonnes Pratiques

### Naming Convention

```
Préfixe par type :
• SEC-     Sécurité (SEC-Baseline-Workstations)
• CFG-     Configuration (CFG-Office-Settings)
• APP-     Applications (APP-Chrome-Deploy)
• USR-     Utilisateurs (USR-Folder-Redirection)
• SRV-     Serveurs (SRV-IIS-Hardening)
• DRV-     Drivers/Printers (DRV-Printer-Mapping)

Suffixe par scope :
• -WKS     Workstations
• -SRV     Servers
• -DC      Domain Controllers
• -ALL     Tous
```

### Organisation

```yaml
Bonnes pratiques GPO:
  Structure:
    - [ ] Une GPO par fonction (pas de "fourre-tout")
    - [ ] Documenter chaque GPO (description, commentaires)
    - [ ] Utiliser des noms explicites
    - [ ] Versionner les modifications

  Performance:
    - [ ] Désactiver la partie non utilisée (User/Computer)
    - [ ] Éviter les filtres WMI complexes
    - [ ] Consolider les GPO similaires
    - [ ] Limiter les scripts de démarrage

  Sécurité:
    - [ ] Tester en lab avant production
    - [ ] Utiliser le filtrage de sécurité
    - [ ] Backup régulier des GPO
    - [ ] Audit des modifications (AGPM si disponible)

  Maintenance:
    - [ ] Revoir régulièrement les GPO inutilisées
    - [ ] Supprimer les liens orphelins
    - [ ] Documenter les exceptions
```

---

## Références

- [Microsoft Docs - Group Policy](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/)
- [Group Policy Settings Reference](https://docs.microsoft.com/en-us/windows/client-management/group-policy-settings-reference)
- [Security Baselines](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)

---

**Voir aussi :**

- [Active Directory](active-directory.md) - Fondamentaux AD
- [AppLocker](applocker.md) - Restriction des applications
- [Windows Security](windows-security.md) - Sécurité Windows
