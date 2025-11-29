---
tags:
  - formation
  - windows-server
  - active-directory
  - domaine
---

# Module 11 : Active Directory Core

## Objectifs du Module

Ce module couvre les fondamentaux d'Active Directory :

- Comprendre l'architecture AD (Forest, Domain, OU)
- Installer un contrôleur de domaine
- Gérer les utilisateurs, groupes et ordinateurs
- Comprendre la réplication AD
- Maîtriser les rôles FSMO

**Durée :** 8 heures

**Niveau :** Ingénierie

---

## 1. Architecture Active Directory

### 1.1 Concepts Fondamentaux

```
HIÉRARCHIE ACTIVE DIRECTORY
────────────────────────────

Forest (corp.com)
├── Domain (corp.com)
│   ├── OU (Users)
│   │   ├── User: john.doe
│   │   └── User: jane.smith
│   ├── OU (Computers)
│   │   └── Computer: PC001
│   └── OU (Groups)
│       └── Group: IT-Team
└── Child Domain (paris.corp.com)
    └── OU (Users)
        └── User: marie.dupont

COMPOSANTS
──────────
• Forest    - Limite de sécurité ultime, schéma partagé
• Domain    - Limite d'administration, réplication
• OU        - Container pour organisation et GPO
• Site      - Topologie réseau, réplication
```

### 1.2 Rôles FSMO

```
FSMO ROLES (Flexible Single Master Operations)
──────────────────────────────────────────────

Forest-wide (1 par forêt):
• Schema Master       - Modifications du schéma AD
• Domain Naming Master - Ajout/suppression de domaines

Domain-wide (1 par domaine):
• PDC Emulator       - Sync temps, changements MDP, GPO
• RID Master         - Attribution des SID
• Infrastructure Master - Références inter-domaines
```

---

## 2. Installation d'un Contrôleur de Domaine

### 2.1 Premier DC (Nouvelle Forêt)

```powershell
# Installer le rôle AD DS
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promouvoir en DC (nouvelle forêt)
$securePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

Install-ADDSForest `
    -DomainName "corp.local" `
    -DomainNetbiosName "CORP" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns:$true `
    -SafeModeAdministratorPassword $securePassword `
    -Force:$true

# Le serveur redémarrera automatiquement
```

### 2.2 DC Supplémentaire (Réplication)

```powershell
# Sur le second serveur
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Promouvoir comme DC supplémentaire
$credential = Get-Credential "CORP\Administrator"
$securePassword = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force

Install-ADDSDomainController `
    -DomainName "corp.local" `
    -Credential $credential `
    -InstallDns:$true `
    -SafeModeAdministratorPassword $securePassword `
    -Force:$true
```

---

## 3. Gestion des Objets AD

### 3.1 Utilisateurs

```powershell
# Importer le module
Import-Module ActiveDirectory

# Créer un utilisateur
New-ADUser -Name "John Doe" `
           -GivenName "John" `
           -Surname "Doe" `
           -SamAccountName "jdoe" `
           -UserPrincipalName "jdoe@corp.local" `
           -Path "OU=Users,OU=Corp,DC=corp,DC=local" `
           -AccountPassword (ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force) `
           -Enabled $true `
           -ChangePasswordAtLogon $true

# Créer depuis CSV
Import-Csv "C:\Users.csv" | ForEach-Object {
    New-ADUser -Name "$($_.FirstName) $($_.LastName)" `
               -GivenName $_.FirstName `
               -Surname $_.LastName `
               -SamAccountName $_.Username `
               -UserPrincipalName "$($_.Username)@corp.local" `
               -Department $_.Department `
               -Enabled $true `
               -AccountPassword (ConvertTo-SecureString $_.Password -AsPlainText -Force)
}

# Rechercher des utilisateurs
Get-ADUser -Filter * -SearchBase "OU=Users,DC=corp,DC=local"
Get-ADUser -Filter {Department -eq "IT"} -Properties Department, Title
Get-ADUser -Identity "jdoe" -Properties *

# Modifier un utilisateur
Set-ADUser -Identity "jdoe" -Department "IT" -Title "Engineer"

# Désactiver/Activer
Disable-ADAccount -Identity "jdoe"
Enable-ADAccount -Identity "jdoe"

# Réinitialiser le mot de passe
Set-ADAccountPassword -Identity "jdoe" -Reset -NewPassword (ConvertTo-SecureString "NewP@ss!" -AsPlainText -Force)
```

### 3.2 Groupes

```powershell
# Types de groupes
# Security  - Permissions et sécurité
# Distribution - Listes de diffusion email

# Portées
# DomainLocal - Ressources locales au domaine
# Global      - Utilisateurs du domaine
# Universal   - Multi-domaines (forêt)

# Créer un groupe
New-ADGroup -Name "IT-Admins" `
            -GroupScope Global `
            -GroupCategory Security `
            -Path "OU=Groups,DC=corp,DC=local" `
            -Description "Administrateurs IT"

# Ajouter des membres
Add-ADGroupMember -Identity "IT-Admins" -Members "jdoe", "jsmith"

# Retirer un membre
Remove-ADGroupMember -Identity "IT-Admins" -Members "jdoe" -Confirm:$false

# Lister les membres
Get-ADGroupMember -Identity "IT-Admins"

# Groupes imbriqués
Add-ADGroupMember -Identity "Domain Admins" -Members "IT-Admins"
```

### 3.3 Ordinateurs

```powershell
# Lister les ordinateurs
Get-ADComputer -Filter *
Get-ADComputer -Filter * -Properties OperatingSystem | Select-Object Name, OperatingSystem

# Ordinateurs inactifs (90 jours)
$date = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonDate -lt $date} -Properties LastLogonDate

# Déplacer vers une OU
Move-ADObject -Identity "CN=PC001,CN=Computers,DC=corp,DC=local" `
              -TargetPath "OU=Workstations,DC=corp,DC=local"

# Désactiver
Disable-ADAccount -Identity "PC001$"
```

### 3.4 Unités d'Organisation (OU)

```powershell
# Créer une structure d'OU
$baseDN = "DC=corp,DC=local"

# OU racine
New-ADOrganizationalUnit -Name "Corp" -Path $baseDN

# Sous-OUs
$corpOU = "OU=Corp,$baseDN"
New-ADOrganizationalUnit -Name "Users" -Path $corpOU
New-ADOrganizationalUnit -Name "Computers" -Path $corpOU
New-ADOrganizationalUnit -Name "Groups" -Path $corpOU
New-ADOrganizationalUnit -Name "Servers" -Path $corpOU

# Protéger contre la suppression accidentelle
Get-ADOrganizationalUnit -Filter * | Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $true
```

---

## 4. Réplication AD

### 4.1 Vérification de la Réplication

```powershell
# État de la réplication
repadmin /replsummary
repadmin /showrepl

# Forcer la réplication
repadmin /syncall /APed

# Vérifier la santé AD
dcdiag /v

# Test DNS
dcdiag /test:dns
```

### 4.2 Sites AD

```powershell
# Lister les sites
Get-ADReplicationSite -Filter *

# Créer un site
New-ADReplicationSite -Name "Paris"

# Créer un subnet
New-ADReplicationSubnet -Name "192.168.2.0/24" -Site "Paris"

# Créer un lien de site
New-ADReplicationSiteLink -Name "HQ-Paris" -SitesIncluded "Default-First-Site-Name", "Paris" -Cost 100 -ReplicationFrequencyInMinutes 15
```

---

## 5. Rôles FSMO

```powershell
# Voir les détenteurs FSMO
netdom query fsmo

# Avec PowerShell
Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster
Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster

# Transférer un rôle
Move-ADDirectoryServerOperationMasterRole -Identity "DC02" -OperationMasterRole PDCEmulator

# Transférer tous les rôles
Move-ADDirectoryServerOperationMasterRole -Identity "DC02" -OperationMasterRole SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster, InfrastructureMaster

# Seize (si ancien DC indisponible - DANGER!)
Move-ADDirectoryServerOperationMasterRole -Identity "DC02" -OperationMasterRole PDCEmulator -Force
```

---

## 6. Exercice Pratique

### Déployer une Infrastructure AD

```powershell
# Structure à créer:
# corp.local
# ├── OU=Corp
# │   ├── OU=Users
# │   │   ├── OU=IT
# │   │   ├── OU=HR
# │   │   └── OU=Finance
# │   ├── OU=Computers
# │   │   ├── OU=Workstations
# │   │   └── OU=Servers
# │   └── OU=Groups

$baseDN = "DC=corp,DC=local"

# Créer la structure
New-ADOrganizationalUnit -Name "Corp" -Path $baseDN -ProtectedFromAccidentalDeletion $true

$departments = @("Users", "Computers", "Groups")
foreach ($dept in $departments) {
    New-ADOrganizationalUnit -Name $dept -Path "OU=Corp,$baseDN"
}

$userDepts = @("IT", "HR", "Finance")
foreach ($dept in $userDepts) {
    New-ADOrganizationalUnit -Name $dept -Path "OU=Users,OU=Corp,$baseDN"
}

# Créer les groupes
$groups = @(
    @{Name="IT-Team"; Path="OU=Groups,OU=Corp,$baseDN"},
    @{Name="HR-Team"; Path="OU=Groups,OU=Corp,$baseDN"},
    @{Name="Finance-Team"; Path="OU=Groups,OU=Corp,$baseDN"}
)

foreach ($grp in $groups) {
    New-ADGroup -Name $grp.Name -GroupScope Global -Path $grp.Path
}

# Créer des utilisateurs de test
$users = @(
    @{First="John"; Last="Doe"; Dept="IT"},
    @{First="Jane"; Last="Smith"; Dept="HR"},
    @{First="Bob"; Last="Wilson"; Dept="Finance"}
)

foreach ($user in $users) {
    $sam = ($user.First[0] + $user.Last).ToLower()
    New-ADUser -Name "$($user.First) $($user.Last)" `
               -SamAccountName $sam `
               -UserPrincipalName "$sam@corp.local" `
               -GivenName $user.First `
               -Surname $user.Last `
               -Department $user.Dept `
               -Path "OU=$($user.Dept),OU=Users,OU=Corp,$baseDN" `
               -AccountPassword (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force) `
               -Enabled $true

    Add-ADGroupMember -Identity "$($user.Dept)-Team" -Members $sam
}
```

---

## 7. Relations d'Approbation (Trusts)

Les trusts permettent l'authentification entre domaines et forêts.

### 7.1 Types de Trusts

```
TYPES DE TRUSTS
───────────────────────────────────────────────────

Parent-Child    Automatique, bidirectionnel, transitif
                (entre domaine parent et enfant)

Forest          Entre deux forêts distinctes
                Bidirectionnel ou unidirectionnel

External        Vers un domaine spécifique hors forêt
                Non-transitif

Shortcut        Optimisation entre domaines distants
                Dans la même forêt
```

### 7.2 Commandes de Base

```powershell
# Lister les trusts
Get-ADTrust -Filter *

# Créer un Forest Trust
New-ADTrust -Name "partner.com" `
    -Type Forest `
    -Direction Bidirectional `
    -RemoteDomainName "partner.com"

# Vérifier un trust
Test-ADTrust -Identity "partner.com"

# Valider via netdom
netdom trust corp.local /domain:partner.com /verify
```

### 7.3 Sécurité des Trusts

- **SID Filtering** : Filtre les SIDs étrangers (activé par défaut)
- **Selective Authentication** : Contrôle granulaire des accès

!!! tip "Documentation Complète"
    Pour une documentation approfondie sur les trusts (types, création, sécurité, troubleshooting, architectures multi-forêts), consultez le guide de référence :

    **[Active Directory : Relations d'Approbation (Trusts)](../../windows/ad-trusts.md)**

---

## Quiz

1. **Combien de Schema Masters par forêt ?**
   - [ ] A. 1 par domaine
   - [ ] B. 1 par forêt
   - [ ] C. Illimité

2. **Quel rôle gère la synchronisation du temps ?**
   - [ ] A. RID Master
   - [ ] B. PDC Emulator
   - [ ] C. Infrastructure Master

**Réponses :** 1-B, 2-B

---

**Précédent :** [Module 10 : Automatisation Basique](10-automatisation-basique.md)

**Suivant :** [Module 12 : GPO & Configuration](12-gpo-configuration.md)
