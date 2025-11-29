---
tags:
  - formation
  - windows-server
  - active-directory
  - cheatsheet
---

# Cheatsheet Active Directory

Guide de référence rapide pour Active Directory.

---

## Installation AD DS

```powershell
# Installer le rôle
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Premier DC (nouvelle forêt)
$password = ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force
Install-ADDSForest -DomainName "corp.local" `
                   -SafeModeAdministratorPassword $password `
                   -InstallDns:$true -Force:$true

# DC supplémentaire
$cred = Get-Credential CORP\Administrator
Install-ADDSDomainController -DomainName "corp.local" `
                             -Credential $cred `
                             -InstallDns:$true `
                             -SafeModeAdministratorPassword $password
```

---

## Utilisateurs

```powershell
# Créer
New-ADUser -Name "John Doe" `
           -SamAccountName "jdoe" `
           -UserPrincipalName "jdoe@corp.local" `
           -GivenName "John" -Surname "Doe" `
           -Path "OU=Users,DC=corp,DC=local" `
           -AccountPassword (ConvertTo-SecureString "P@ss!" -AsPlainText -Force) `
           -Enabled $true

# Lire
Get-ADUser -Identity jdoe
Get-ADUser -Identity jdoe -Properties *
Get-ADUser -Filter {Department -eq "IT"}
Get-ADUser -Filter * -SearchBase "OU=Users,DC=corp,DC=local"

# Modifier
Set-ADUser -Identity jdoe -Department "IT" -Title "Engineer"
Set-ADUser -Identity jdoe -Description "Senior Developer"

# Compte
Enable-ADAccount -Identity jdoe
Disable-ADAccount -Identity jdoe
Unlock-ADAccount -Identity jdoe

# Mot de passe
Set-ADAccountPassword -Identity jdoe -Reset -NewPassword (ConvertTo-SecureString "NewP@ss!" -AsPlainText -Force)
Set-ADUser -Identity jdoe -ChangePasswordAtLogon $true
Set-ADUser -Identity jdoe -PasswordNeverExpires $true

# Supprimer
Remove-ADUser -Identity jdoe
```

---

## Groupes

```powershell
# Types de groupes
# Security vs Distribution
# DomainLocal, Global, Universal

# Créer
New-ADGroup -Name "IT-Admins" `
            -GroupScope Global `
            -GroupCategory Security `
            -Path "OU=Groups,DC=corp,DC=local" `
            -Description "Administrateurs IT"

# Membres
Get-ADGroupMember -Identity "IT-Admins"
Get-ADGroupMember -Identity "IT-Admins" -Recursive
Add-ADGroupMember -Identity "IT-Admins" -Members "jdoe", "jsmith"
Remove-ADGroupMember -Identity "IT-Admins" -Members "jdoe" -Confirm:$false

# Groupes d'un utilisateur
Get-ADPrincipalGroupMembership -Identity jdoe

# Supprimer
Remove-ADGroup -Identity "IT-Admins"
```

---

## Ordinateurs

```powershell
# Lire
Get-ADComputer -Filter *
Get-ADComputer -Identity PC001
Get-ADComputer -Filter * -Properties OperatingSystem, LastLogonDate

# Inactifs (90 jours)
$date = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonDate -lt $date} -Properties LastLogonDate

# Déplacer
Move-ADObject -Identity "CN=PC001,CN=Computers,DC=corp,DC=local" `
              -TargetPath "OU=Workstations,DC=corp,DC=local"

# Désactiver/Supprimer
Disable-ADAccount -Identity "PC001$"
Remove-ADComputer -Identity PC001
```

---

## Unités d'Organisation (OU)

```powershell
# Créer
New-ADOrganizationalUnit -Name "Corp" -Path "DC=corp,DC=local"
New-ADOrganizationalUnit -Name "Users" -Path "OU=Corp,DC=corp,DC=local"

# Protection contre suppression
Set-ADOrganizationalUnit -Identity "OU=Corp,DC=corp,DC=local" -ProtectedFromAccidentalDeletion $true

# Pour supprimer une OU protégée
Set-ADOrganizationalUnit -Identity "OU=Test,DC=corp,DC=local" -ProtectedFromAccidentalDeletion $false
Remove-ADOrganizationalUnit -Identity "OU=Test,DC=corp,DC=local"
```

---

## GPO

```powershell
# Lister
Get-GPO -All

# Créer
New-GPO -Name "Security-Baseline"

# Lier
New-GPLink -Name "Security-Baseline" -Target "OU=Computers,DC=corp,DC=local"
Set-GPLink -Name "Security-Baseline" -Target "OU=Computers,DC=corp,DC=local" -Enforced Yes

# Registre
Set-GPRegistryValue -Name "Security-Baseline" `
    -Key "HKLM\SOFTWARE\Policies\Example" `
    -ValueName "Setting" -Type DWord -Value 1

# Backup/Restore
Backup-GPO -All -Path "C:\GPOBackup"
Restore-GPO -Name "Security-Baseline" -Path "C:\GPOBackup"

# Rapport
Get-GPOReport -All -ReportType HTML -Path "C:\GPOReport.html"

# Forcer mise à jour
Invoke-GPUpdate -Computer "PC001" -Force
gpupdate /force  # Local
```

---

## Réplication

```powershell
# État
repadmin /replsummary
repadmin /showrepl
Get-ADReplicationPartnerMetadata -Target DC01

# Forcer
repadmin /syncall /APed
Sync-ADObject -Object "CN=jdoe,OU=Users,DC=corp,DC=local" -Source DC01

# Sites
Get-ADReplicationSite -Filter *
New-ADReplicationSite -Name "Paris"
New-ADReplicationSubnet -Name "192.168.2.0/24" -Site "Paris"

# Diagnostic
dcdiag /v
dcdiag /test:replications
```

---

## FSMO

```powershell
# Voir les détenteurs
netdom query fsmo
Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster
Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster

# Transférer
Move-ADDirectoryServerOperationMasterRole -Identity DC02 -OperationMasterRole PDCEmulator

# Transférer tous
Move-ADDirectoryServerOperationMasterRole -Identity DC02 `
    -OperationMasterRole SchemaMaster, DomainNamingMaster, PDCEmulator, RIDMaster, InfrastructureMaster

# Seize (URGENCE - ancien DC indisponible)
Move-ADDirectoryServerOperationMasterRole -Identity DC02 -OperationMasterRole PDCEmulator -Force
```

---

## Corbeille AD

```powershell
# Activer (irréversible)
Enable-ADOptionalFeature -Identity "Recycle Bin Feature" `
    -Scope ForestOrConfigurationSet -Target "corp.local"

# Voir objets supprimés
Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties *

# Restaurer
Get-ADObject -Filter 'isDeleted -eq $true -and Name -like "*jdoe*"' -IncludeDeletedObjects |
    Restore-ADObject
```

---

## DNS

```powershell
# Zones
Get-DnsServerZone
Add-DnsServerPrimaryZone -Name "corp.local" -ZoneFile "corp.local.dns"
Add-DnsServerPrimaryZone -NetworkId "192.168.1.0/24" -ZoneFile "1.168.192.in-addr.arpa.dns"

# Enregistrements
Get-DnsServerResourceRecord -ZoneName "corp.local"
Add-DnsServerResourceRecordA -ZoneName "corp.local" -Name "srv01" -IPv4Address "192.168.1.20"
Add-DnsServerResourceRecordCName -ZoneName "corp.local" -Name "www" -HostNameAlias "srv01.corp.local"
Remove-DnsServerResourceRecord -ZoneName "corp.local" -RRType A -Name "oldserver"

# Diagnostic
Resolve-DnsName srv01.corp.local
nslookup srv01.corp.local
```

---

## DHCP

```powershell
# Scope
Get-DhcpServerv4Scope
Add-DhcpServerv4Scope -Name "LAN" -StartRange 192.168.1.100 -EndRange 192.168.1.200 -SubnetMask 255.255.255.0

# Options
Set-DhcpServerv4OptionValue -ScopeId 192.168.1.0 -DnsServer 192.168.1.10 -Router 192.168.1.1

# Exclusions
Add-DhcpServerv4ExclusionRange -ScopeId 192.168.1.0 -StartRange 192.168.1.1 -EndRange 192.168.1.50

# Réservations
Add-DhcpServerv4Reservation -ScopeId 192.168.1.0 -IPAddress 192.168.1.150 -ClientId "00-15-5D-01-02-03"

# Baux
Get-DhcpServerv4Lease -ScopeId 192.168.1.0
```

---

## Sécurité

```powershell
# Protected Users
Add-ADGroupMember -Identity "Protected Users" -Members "admin"

# Comptes privilégiés
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive

# Comptes sans expiration MDP
Get-ADUser -Filter {PasswordNeverExpires -eq $true}

# Comptes inactifs
Get-ADUser -Filter {LastLogonDate -lt $date} -Properties LastLogonDate
Get-ADComputer -Filter {LastLogonDate -lt $date} -Properties LastLogonDate

# Audit des permissions
dsacls "OU=Users,DC=corp,DC=local"
```

---

## Recherches Utiles

```powershell
# Utilisateurs verrouillés
Search-ADAccount -LockedOut

# Comptes expirés
Search-ADAccount -AccountExpired

# Comptes désactivés
Search-ADAccount -AccountDisabled

# MDP expiré
Search-ADAccount -PasswordExpired

# MDP jamais défini
Search-ADAccount -PasswordNeverSet

# Tous les DC
Get-ADDomainController -Filter *

# Niveau fonctionnel
(Get-ADForest).ForestMode
(Get-ADDomain).DomainMode
```

---

**Retour au :** [Programme de la Formation](index.md)
