---
tags:
  - windows
  - active-directory
  - delegation
  - rbac
  - security
---

# Délégation d'Administration Active Directory

La délégation permet d'accorder des permissions granulaires sans donner les droits Domain Admin. Principe du moindre privilège appliqué à AD.

## Concepts Fondamentaux

### Pourquoi Déléguer ?

```text
PROBLÈME SANS DÉLÉGATION
══════════════════════════════════════════════════════════

Option 1 : Donner Domain Admin
  → RISQUE : Accès total, pas de traçabilité, surface d'attaque

Option 2 : Ne rien donner
  → PROBLÈME : IT dépendant, tickets pour chaque action

SOLUTION : DÉLÉGATION GRANULAIRE
────────────────────────────────
Accorder uniquement les droits nécessaires :
• Helpdesk : Reset password sur OU=Users
• HR : Créer/modifier users dans OU=HR
• IT-Local : Gérer ordinateurs dans OU=Paris

Avantages :
✓ Moindre privilège
✓ Traçabilité (qui a fait quoi)
✓ Autonomie des équipes
✓ Réduction de la surface d'attaque
```

### Niveaux de Délégation

```text
NIVEAUX DE DÉLÉGATION
══════════════════════════════════════════════════════════

Niveau 1 : Tâches spécifiques
─────────────────────────────
• Reset password
• Unlock account
• Modifier certains attributs

Niveau 2 : Gestion d'objets
───────────────────────────
• Créer/supprimer users
• Gérer groupes
• Joindre ordinateurs au domaine

Niveau 3 : Administration d'OU
──────────────────────────────
• Full control sur une OU
• Déléguer à d'autres
• Gérer les GPO liées

Niveau 4 : Administration de domaine
────────────────────────────────────
• Créer des OU
• Gérer la réplication
• Modifier les policies domaine
```

---

## Assistant de Délégation (GUI)

### Accès

```text
1. Active Directory Users and Computers (dsa.msc)
2. Clic droit sur l'OU cible
3. "Delegate Control..."
4. Suivre l'assistant
```

### Tâches Prédéfinies

L'assistant propose des tâches courantes :

| Tâche | Permissions accordées |
|-------|----------------------|
| Create, delete, manage user accounts | Full control sur objets User |
| Reset user passwords and force change | Reset Password + Write pwdLastSet |
| Read all user information | Read all properties |
| Manage groups | Full control sur objets Group |
| Join computers to domain | Create Computer objects |
| Manage Group Policy links | Write gPLink, gPOptions |

---

## Délégation via PowerShell

### Voir les Permissions Actuelles

```powershell
# Importer le module AD
Import-Module ActiveDirectory

# Voir l'ACL d'une OU
$ou = "OU=Users,OU=Corp,DC=corp,DC=local"
(Get-Acl "AD:\$ou").Access |
    Select-Object IdentityReference, ActiveDirectoryRights, ObjectType |
    Format-Table

# Voir les permissions d'un groupe spécifique
$ou = "OU=Users,OU=Corp,DC=corp,DC=local"
(Get-Acl "AD:\$ou").Access |
    Where-Object { $_.IdentityReference -like "*Helpdesk*" }
```

### GUIDs des Attributs et Classes

```powershell
# Les permissions AD utilisent des GUIDs pour les objets/attributs
# Quelques GUIDs courants :

$guids = @{
    # Classes d'objets
    "User"              = "bf967aba-0de6-11d0-a285-00aa003049e2"
    "Group"             = "bf967a9c-0de6-11d0-a285-00aa003049e2"
    "Computer"          = "bf967a86-0de6-11d0-a285-00aa003049e2"

    # Attributs
    "pwdLastSet"        = "bf967a0a-0de6-11d0-a285-00aa003049e2"
    "lockoutTime"       = "28630ebf-41d5-11d1-a9c1-0000f80367c1"
    "userAccountControl"= "bf967a68-0de6-11d0-a285-00aa003049e2"
    "member"            = "bf9679c0-0de6-11d0-a285-00aa003049e2"

    # Extended Rights
    "Reset Password"    = "00299570-246d-11d0-a768-00aa006e0529"
    "Change Password"   = "ab721a53-1e2f-11d0-9819-00aa0040529b"
}

# Trouver un GUID dans le schéma
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
    -Filter { name -eq "user" } -Properties schemaIDGUID |
    Select-Object name, @{N='GUID';E={[guid]$_.schemaIDGUID}}
```

### Déléguer le Reset Password

```powershell
# Déléguer le reset password sur une OU
$ou = "OU=Users,OU=Corp,DC=corp,DC=local"
$group = "CORP\Helpdesk"

# GUID pour "Reset Password" extended right
$resetPwdGuid = [guid]"00299570-246d-11d0-a768-00aa006e0529"
# GUID pour la classe User
$userGuid = [guid]"bf967aba-0de6-11d0-a285-00aa003049e2"

# Obtenir le SID du groupe
$groupSid = (Get-ADGroup $group.Split('\')[1]).SID

# Créer l'ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $groupSid,
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    $resetPwdGuid,
    [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
    $userGuid
)

# Appliquer l'ACE
$acl = Get-Acl "AD:\$ou"
$acl.AddAccessRule($ace)
Set-Acl -Path "AD:\$ou" -AclObject $acl

Write-Host "Reset Password délégué à $group sur $ou"
```

### Déléguer la Création d'Utilisateurs

```powershell
function Set-ADDelegationCreateUsers {
    param(
        [string]$OU,
        [string]$Group
    )

    $userGuid = [guid]"bf967aba-0de6-11d0-a285-00aa003049e2"
    $groupSid = (Get-ADGroup $Group).SID
    $acl = Get-Acl "AD:\$OU"

    # Create User objects
    $aceCreate = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $userGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    )

    # Delete User objects
    $aceDelete = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $userGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    )

    # Full control on User objects (descendants)
    $aceFullControl = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $userGuid
    )

    $acl.AddAccessRule($aceCreate)
    $acl.AddAccessRule($aceDelete)
    $acl.AddAccessRule($aceFullControl)

    Set-Acl -Path "AD:\$OU" -AclObject $acl
}

# Utilisation
Set-ADDelegationCreateUsers -OU "OU=HR,OU=Users,DC=corp,DC=local" -Group "HR-Admins"
```

### Déléguer la Gestion des Groupes

```powershell
function Set-ADDelegationManageGroups {
    param(
        [string]$OU,
        [string]$Group
    )

    $groupClassGuid = [guid]"bf967a9c-0de6-11d0-a285-00aa003049e2"
    $memberAttrGuid = [guid]"bf9679c0-0de6-11d0-a285-00aa003049e2"
    $groupSid = (Get-ADGroup $Group).SID
    $acl = Get-Acl "AD:\$OU"

    # Write member attribute (ajouter/retirer des membres)
    $aceMember = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $memberAttrGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $groupClassGuid
    )

    # Read all properties
    $aceRead = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $groupClassGuid
    )

    $acl.AddAccessRule($aceMember)
    $acl.AddAccessRule($aceRead)

    Set-Acl -Path "AD:\$OU" -AclObject $acl
}
```

---

## Modèles de Délégation

### Modèle Helpdesk

```powershell
# Permissions Helpdesk niveau 1
# - Reset password
# - Unlock account
# - Lire les propriétés utilisateur

function Set-HelpdeskDelegation {
    param(
        [string]$OU,
        [string]$HelpdeskGroup
    )

    $userGuid = [guid]"bf967aba-0de6-11d0-a285-00aa003049e2"
    $resetPwdGuid = [guid]"00299570-246d-11d0-a768-00aa006e0529"
    $lockoutTimeGuid = [guid]"28630ebf-41d5-11d1-a9c1-0000f80367c1"

    $groupSid = (Get-ADGroup $HelpdeskGroup).SID
    $acl = Get-Acl "AD:\$OU"

    # Reset Password
    $aceResetPwd = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $resetPwdGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $userGuid
    )

    # Write lockoutTime (unlock account)
    $aceUnlock = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $lockoutTimeGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $userGuid
    )

    # Read all properties
    $aceRead = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $userGuid
    )

    $acl.AddAccessRule($aceResetPwd)
    $acl.AddAccessRule($aceUnlock)
    $acl.AddAccessRule($aceRead)

    Set-Acl -Path "AD:\$OU" -AclObject $acl

    Write-Host "Helpdesk delegation configured for $HelpdeskGroup on $OU"
}

# Appliquer
Set-HelpdeskDelegation -OU "OU=Users,OU=Corp,DC=corp,DC=local" -HelpdeskGroup "Helpdesk-L1"
```

### Modèle Administrateur Local (par site/département)

```powershell
# Permissions Admin local
# - Gérer users dans son OU
# - Gérer groupes dans son OU
# - Gérer ordinateurs dans son OU
# - Lier des GPO (pas créer)

function Set-LocalAdminDelegation {
    param(
        [string]$SiteOU,        # OU=Paris,OU=Sites,DC=corp,DC=local
        [string]$AdminGroup     # Paris-IT-Admins
    )

    $userGuid = [guid]"bf967aba-0de6-11d0-a285-00aa003049e2"
    $groupGuid = [guid]"bf967a9c-0de6-11d0-a285-00aa003049e2"
    $computerGuid = [guid]"bf967a86-0de6-11d0-a285-00aa003049e2"

    $groupSid = (Get-ADGroup $AdminGroup).SID
    $acl = Get-Acl "AD:\$SiteOU"

    # Full control sur Users
    $aceUsers = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $userGuid
    )

    # Full control sur Groups
    $aceGroups = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $groupGuid
    )

    # Full control sur Computers
    $aceComputers = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents,
        $computerGuid
    )

    # Create child objects (toutes classes)
    $aceCreate = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $groupSid,
        [System.DirectoryServices.ActiveDirectoryRights]::CreateChild,
        [System.Security.AccessControl.AccessControlType]::Allow,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    )

    $acl.AddAccessRule($aceUsers)
    $acl.AddAccessRule($aceGroups)
    $acl.AddAccessRule($aceComputers)
    $acl.AddAccessRule($aceCreate)

    Set-Acl -Path "AD:\$SiteOU" -AclObject $acl
}
```

---

## Audit des Délégations

### Lister Toutes les Délégations

```powershell
function Get-ADDelegations {
    param(
        [string]$SearchBase = (Get-ADDomain).DistinguishedName
    )

    $results = @()

    # Parcourir toutes les OUs
    Get-ADOrganizationalUnit -Filter * -SearchBase $SearchBase | ForEach-Object {
        $ou = $_
        $acl = Get-Acl "AD:\$($ou.DistinguishedName)"

        $acl.Access | Where-Object {
            $_.IdentityReference -notlike "NT AUTHORITY\*" -and
            $_.IdentityReference -notlike "BUILTIN\*" -and
            $_.IdentityReference -notlike "S-1-5-*" -and
            $_.IsInherited -eq $false
        } | ForEach-Object {
            $results += [PSCustomObject]@{
                OU = $ou.Name
                Path = $ou.DistinguishedName
                Identity = $_.IdentityReference
                Rights = $_.ActiveDirectoryRights
                Type = $_.AccessControlType
                Inherited = $_.IsInherited
            }
        }
    }

    return $results
}

# Exporter en CSV
Get-ADDelegations | Export-Csv -Path "C:\AD-Delegations.csv" -NoTypeInformation

# Afficher
Get-ADDelegations | Format-Table -AutoSize
```

### Comparer avec une Baseline

```powershell
# Exporter la baseline (à faire après configuration initiale)
Get-ADDelegations | Export-Clixml -Path "C:\Baseline-Delegations.xml"

# Comparer avec l'état actuel
$baseline = Import-Clixml -Path "C:\Baseline-Delegations.xml"
$current = Get-ADDelegations

$differences = Compare-Object -ReferenceObject $baseline -DifferenceObject $current -Property OU, Identity, Rights

if ($differences) {
    Write-Host "Différences détectées :" -ForegroundColor Yellow
    $differences | Format-Table
} else {
    Write-Host "Aucune différence avec la baseline" -ForegroundColor Green
}
```

---

## Sécurité et Bonnes Pratiques

### Principe du Moindre Privilège

```yaml
Checklist Délégation:
  Analyse:
    - [ ] Identifier les tâches réelles (pas "au cas où")
    - [ ] Limiter au scope nécessaire (OU spécifique)
    - [ ] Préférer les attributs aux objets complets

  Implémentation:
    - [ ] Utiliser des groupes (pas des utilisateurs)
    - [ ] Documenter chaque délégation
    - [ ] Tester avant déploiement

  Maintenance:
    - [ ] Auditer régulièrement
    - [ ] Retirer les délégations obsolètes
    - [ ] Revoir lors des changements d'organisation
```

### Groupes de Délégation

```powershell
# Structure recommandée des groupes

# Tier 0 - Domain/Forest
# AUCUNE délégation - Domain Admins uniquement

# Tier 1 - Serveurs
New-ADGroup -Name "DLG-Server-Admins" -GroupScope DomainLocal -Path "OU=Delegation,DC=corp,DC=local"

# Tier 2 - Workstations/Users
New-ADGroup -Name "DLG-Helpdesk-L1" -GroupScope DomainLocal -Path "OU=Delegation,DC=corp,DC=local"
New-ADGroup -Name "DLG-Helpdesk-L2" -GroupScope DomainLocal -Path "OU=Delegation,DC=corp,DC=local"
New-ADGroup -Name "DLG-HR-UserAdmin" -GroupScope DomainLocal -Path "OU=Delegation,DC=corp,DC=local"
New-ADGroup -Name "DLG-Paris-IT" -GroupScope DomainLocal -Path "OU=Delegation,DC=corp,DC=local"
```

### Protéger les Comptes Sensibles

```powershell
# Protéger les comptes admin contre la délégation
$adminAccounts = Get-ADGroupMember "Domain Admins"

foreach ($admin in $adminAccounts) {
    # AdminSDHolder protège automatiquement, mais vérifier
    $user = Get-ADUser $admin -Properties adminCount
    if ($user.adminCount -ne 1) {
        Write-Warning "$($user.SamAccountName) n'est pas protégé par AdminSDHolder"
    }
}

# Les comptes dans Protected Groups sont protégés par AdminSDHolder
# Toutes les 60 min, les ACL sont réinitialisées
```

---

## Références

- [Microsoft Docs - Delegate Administration](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/delegating-administration)
- [AD Security - Delegation](https://adsecurity.org/?p=3700)
- [Best Practices for Delegation](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)

---

**Voir aussi :**

- [Active Directory](active-directory.md) - Fondamentaux AD
- [AD Trusts](ad-trusts.md) - Relations d'approbation
- [Windows Security](security/index.md) - Sécurité Windows
