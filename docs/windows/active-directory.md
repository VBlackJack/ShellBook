# Active Directory PowerShell

`#active-directory` `#powershell` `#users` `#groups` `#audit`

Administration Active Directory via PowerShell.

---

## Prérequis

```powershell
# Importer le module AD
Import-Module ActiveDirectory

# Vérifier la connexion au domaine
Get-ADDomain

# Si RSAT non installé (Windows 10/11)
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

---

## Gestion des Utilisateurs (CRUD)

### Créer un Utilisateur

```powershell
# Création basique
New-ADUser -Name "Jean Dupont" -SamAccountName "jdupont" -Enabled $true

# Création complète et sécurisée
$password = Read-Host -AsSecureString "Enter password"
New-ADUser `
    -Name "Jean Dupont" `
    -GivenName "Jean" `
    -Surname "Dupont" `
    -SamAccountName "jdupont" `
    -UserPrincipalName "jdupont@corp.local" `
    -Path "OU=Users,OU=Paris,DC=corp,DC=local" `
    -AccountPassword $password `
    -Enabled $true `
    -ChangePasswordAtLogon $true `
    -Department "IT" `
    -Title "SysAdmin"

# Création en masse depuis CSV
Import-Csv users.csv | ForEach-Object {
    New-ADUser `
        -Name "$($_.Prenom) $($_.Nom)" `
        -SamAccountName $_.Login `
        -UserPrincipalName "$($_.Login)@corp.local" `
        -Path "OU=Users,DC=corp,DC=local" `
        -AccountPassword (ConvertTo-SecureString $_.Password -AsPlainText -Force) `
        -Enabled $true
}
```

### Modifier un Utilisateur

```powershell
# Modifier des attributs
Set-ADUser -Identity jdupont -Department "Security" -Title "Security Engineer"

# Modifier plusieurs attributs
Set-ADUser -Identity jdupont -Replace @{
    telephoneNumber = "+33 1 23 45 67 89"
    physicalDeliveryOfficeName = "Paris - Floor 3"
}

# Désactiver un compte
Disable-ADAccount -Identity jdupont

# Activer un compte
Enable-ADAccount -Identity jdupont

# Réinitialiser le mot de passe
Set-ADAccountPassword -Identity jdupont -Reset -NewPassword (Read-Host -AsSecureString "New password")

# Forcer le changement de mot de passe à la prochaine connexion
Set-ADUser -Identity jdupont -ChangePasswordAtLogon $true
```

### Rechercher des Utilisateurs

```powershell
# Tous les utilisateurs (ATTENTION : performance !)
Get-ADUser -Filter *

# Filtrer côté serveur (RECOMMANDÉ)
Get-ADUser -Filter 'Department -eq "IT"'
Get-ADUser -Filter 'Name -like "Jean*"'
Get-ADUser -Filter 'Enabled -eq $false'

# Avec propriétés supplémentaires
Get-ADUser -Identity jdupont -Properties *
Get-ADUser -Filter * -Properties Department, Title, LastLogonDate |
    Select-Object Name, Department, Title, LastLogonDate

# Recherche dans une OU spécifique
Get-ADUser -Filter * -SearchBase "OU=Paris,DC=corp,DC=local"

# Utilisateurs créés cette semaine
$date = (Get-Date).AddDays(-7)
Get-ADUser -Filter 'Created -gt $date' -Properties Created |
    Select-Object Name, Created
```

!!! warning "Performance : Filtrer côté serveur"
    ```powershell
    # MAUVAIS (charge tous les users puis filtre)
    Get-ADUser -Filter * | Where-Object { $_.Department -eq "IT" }

    # BON (filtre côté AD)
    Get-ADUser -Filter 'Department -eq "IT"'
    ```

### Débloquer un Compte

```powershell
# Débloquer
Unlock-ADAccount -Identity jdupont

# Vérifier si verrouillé
Get-ADUser -Identity jdupont -Properties LockedOut | Select-Object Name, LockedOut

# Trouver tous les comptes verrouillés
Search-ADAccount -LockedOut | Select-Object Name, SamAccountName
```

---

## Gestion des Groupes

### Créer et Gérer des Groupes

```powershell
# Créer un groupe
New-ADGroup -Name "IT-Admins" -GroupScope Global -GroupCategory Security `
    -Path "OU=Groups,DC=corp,DC=local"

# Types de groupes
# -GroupScope : DomainLocal, Global, Universal
# -GroupCategory : Security, Distribution
```

### Ajouter / Retirer des Membres

```powershell
# Ajouter un membre
Add-ADGroupMember -Identity "IT-Admins" -Members jdupont

# Ajouter plusieurs membres
Add-ADGroupMember -Identity "IT-Admins" -Members jdupont, mmartin, pdurand

# Retirer un membre
Remove-ADGroupMember -Identity "IT-Admins" -Members jdupont -Confirm:$false
```

### Lister les Membres

```powershell
# Membres directs
Get-ADGroupMember -Identity "IT-Admins"

# Membres récursifs (inclut les groupes imbriqués)
Get-ADGroupMember -Identity "IT-Admins" -Recursive |
    Select-Object Name, SamAccountName, objectClass

# Compter les membres
(Get-ADGroupMember -Identity "IT-Admins" -Recursive).Count
```

### Groupes d'un Utilisateur

```powershell
# Groupes directs d'un utilisateur
Get-ADPrincipalGroupMembership -Identity jdupont |
    Select-Object Name

# Avec le DN complet
Get-ADUser -Identity jdupont -Properties MemberOf |
    Select-Object -ExpandProperty MemberOf
```

---

## Audit & Sécurité AD

### Comptes Inactifs (Stale Accounts)

```powershell
# Comptes non connectés depuis 90 jours
$90days = (Get-Date).AddDays(-90)
Get-ADUser -Filter 'LastLogonDate -lt $90days' -Properties LastLogonDate |
    Select-Object Name, SamAccountName, LastLogonDate, Enabled |
    Sort-Object LastLogonDate

# Utiliser Search-ADAccount (plus précis)
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly |
    Select-Object Name, SamAccountName, LastLogonDate

# Comptes jamais connectés
Search-ADAccount -AccountInactive -UsersOnly |
    Where-Object { $_.LastLogonDate -eq $null } |
    Select-Object Name, SamAccountName, Created
```

### Mots de Passe Expirés / Problèmes

```powershell
# Comptes avec mot de passe expiré
Search-ADAccount -PasswordExpired |
    Select-Object Name, SamAccountName, PasswordExpired

# Comptes avec mot de passe qui n'expire jamais (RISQUE)
Get-ADUser -Filter 'PasswordNeverExpires -eq $true' -Properties PasswordNeverExpires |
    Select-Object Name, SamAccountName

# Comptes sans mot de passe requis (CRITIQUE)
Get-ADUser -Filter 'PasswordNotRequired -eq $true' -Properties PasswordNotRequired |
    Select-Object Name, SamAccountName
```

### Audit des Privilèges (Domain Admins)

```powershell
# Membres du groupe Domain Admins
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Select-Object Name, SamAccountName, objectClass

# Membres du groupe Enterprise Admins
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive |
    Select-Object Name, SamAccountName

# Membres du groupe Administrators
Get-ADGroupMember -Identity "Administrators" -Recursive |
    Select-Object Name, SamAccountName

# Audit complet des groupes privilégiés
$privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
foreach ($group in $privilegedGroups) {
    Write-Host "=== $group ===" -ForegroundColor Yellow
    Get-ADGroupMember -Identity $group -Recursive |
        Select-Object Name, SamAccountName
}
```

### Rapport d'Audit Complet

```powershell
# Export des comptes à risque
$report = @()

# Comptes inactifs
$report += Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00 -UsersOnly |
    Select-Object Name, SamAccountName, @{N='Issue';E={'Inactive 90+ days'}}

# Mots de passe expirés
$report += Search-ADAccount -PasswordExpired |
    Select-Object Name, SamAccountName, @{N='Issue';E={'Password Expired'}}

# Password Never Expires
$report += Get-ADUser -Filter 'PasswordNeverExpires -eq $true' |
    Select-Object Name, SamAccountName, @{N='Issue';E={'Password Never Expires'}}

# Export CSV
$report | Export-Csv -Path "AD_Audit_Report.csv" -NoTypeInformation
```

---

## FSMO & Santé Domaine

### Rôles FSMO

```powershell
# Voir tous les rôles FSMO du domaine
Get-ADDomain | Select-Object InfrastructureMaster, RIDMaster, PDCEmulator

# Voir les rôles FSMO de la forêt
Get-ADForest | Select-Object DomainNamingMaster, SchemaMaster

# Commande complète
netdom query fsmo
```

| Rôle | Portée | Description |
|------|--------|-------------|
| Schema Master | Forêt | Modifications du schéma AD |
| Domain Naming Master | Forêt | Ajout/suppression de domaines |
| RID Master | Domaine | Attribution des RID (SID) |
| PDC Emulator | Domaine | Auth, GPO, temps |
| Infrastructure Master | Domaine | Références inter-domaines |

### Vérifier la Réplication

```powershell
# État de la réplication
Get-ADReplicationPartnerMetadata -Target "dc01.corp.local" |
    Select-Object Partner, LastReplicationSuccess, LastReplicationResult

# Tous les DCs
Get-ADDomainController -Filter * |
    ForEach-Object {
        Get-ADReplicationPartnerMetadata -Target $_.HostName
    } | Select-Object Server, Partner, LastReplicationSuccess

# Échecs de réplication
Get-ADReplicationFailure -Target "dc01.corp.local"

# Outil classique (CMD)
repadmin /replsummary
repadmin /showrepl
```

### Santé des Domain Controllers

```powershell
# Lister les DCs
Get-ADDomainController -Filter * |
    Select-Object Name, IPv4Address, Site, IsGlobalCatalog, OperatingSystem

# Vérifier les services AD
Get-Service -ComputerName dc01 -Name NTDS, DNS, Netlogon, W32Time |
    Select-Object Name, Status

# Test de connectivité DC
Test-ComputerSecureChannel -Server dc01.corp.local
```

---

## Quick Reference

```powershell
# === MODULE ===
Import-Module ActiveDirectory

# === USERS ===
Get-ADUser -Identity jdupont -Properties *
Get-ADUser -Filter 'Department -eq "IT"'
New-ADUser -Name "User" -SamAccountName "user" -Enabled $true
Set-ADUser -Identity jdupont -Department "Security"
Unlock-ADAccount -Identity jdupont

# === GROUPS ===
Get-ADGroupMember -Identity "IT-Admins" -Recursive
Add-ADGroupMember -Identity "IT-Admins" -Members jdupont
Get-ADPrincipalGroupMembership -Identity jdupont

# === AUDIT ===
Search-ADAccount -AccountInactive -TimeSpan 90.00:00:00
Search-ADAccount -PasswordExpired
Search-ADAccount -LockedOut
Get-ADGroupMember -Identity "Domain Admins" -Recursive

# === FSMO & REPLICATION ===
Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
Get-ADReplicationPartnerMetadata -Target dc01
repadmin /replsummary
```
