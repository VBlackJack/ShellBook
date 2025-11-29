---
tags:
  - windows
  - laps
  - security
  - passwords
  - active-directory
---

# LAPS - Local Administrator Password Solution

Gestion automatique des mots de passe administrateur local avec LAPS (Legacy et Windows LAPS).

## Concepts

```
POURQUOI LAPS ?
══════════════════════════════════════════════════════════

Problème sans LAPS :
• Même mot de passe admin local sur toutes les machines
• Compromission d'une machine = compromission de toutes
• Pass-the-Hash trivial en mouvement latéral
• Impossible de changer régulièrement (effort manuel)

Avec LAPS :
• Mot de passe unique par machine
• Rotation automatique (ex: tous les 30 jours)
• Stocké dans Active Directory (attribut sécurisé)
• Accès contrôlé par ACL AD
```

### Legacy LAPS vs Windows LAPS

```
COMPARAISON
══════════════════════════════════════════════════════════

Legacy LAPS (2015):
• Téléchargement séparé (Microsoft LAPS)
• Client-side Extension (CSE) à déployer
• Mot de passe stocké en clair dans AD (attribut protégé)
• PowerShell module séparé
• Pas de chiffrement natif

Windows LAPS (2023, Windows Server 2019+):
• Intégré à Windows (April 2023 update)
• Chiffrement du mot de passe dans AD
• Historique des mots de passe
• Support Azure AD (Entra ID)
• Backup vers Azure AD possible
• Gestion DSRM password (DC)
• Pas besoin de schema extension (utilise nouveaux attributs)
```

---

## Legacy LAPS - Déploiement

### Prérequis

```powershell
# Télécharger LAPS.x64.msi depuis Microsoft
# https://www.microsoft.com/en-us/download/details.aspx?id=46899

# Composants :
# - AdmPwd GPO Extension (client, sur toutes les machines)
# - Fat client UI (console de gestion)
# - PowerShell module
# - GPO templates (ADMX)
```

### Extension du Schéma AD

```powershell
# Sur un DC, en tant que Schema Admin
Import-Module AdmPwd.PS

# Étendre le schéma (ajoute 2 attributs)
Update-AdmPwdADSchema

# Attributs ajoutés :
# - ms-Mcs-AdmPwd : stocke le mot de passe
# - ms-Mcs-AdmPwdExpirationTime : date d'expiration
```

### Configuration des Permissions

```powershell
# Donner aux machines le droit d'écrire leur mot de passe
# (Sur l'OU contenant les ordinateurs)
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=corp,DC=local"
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Servers,DC=corp,DC=local"

# Donner le droit de lecture aux admins
Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Workstations,DC=corp,DC=local" `
    -AllowedPrincipals "CORP\Helpdesk"

Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Servers,DC=corp,DC=local" `
    -AllowedPrincipals "CORP\Server-Admins"

# Droit de forcer le reset
Set-AdmPwdResetPasswordPermission -OrgUnit "OU=Servers,DC=corp,DC=local" `
    -AllowedPrincipals "CORP\Server-Admins"

# Vérifier les permissions
Find-AdmPwdExtendedRights -Identity "OU=Workstations,DC=corp,DC=local"
```

### Déploiement Client (GPO)

```
1. Copier les ADMX dans le Central Store :
   \\corp.local\SYSVOL\corp.local\Policies\PolicyDefinitions\

2. Créer une GPO "LAPS Configuration"

3. Computer Configuration > Administrative Templates > LAPS :

   ✓ Enable local admin password management : Enabled

   ✓ Password Settings :
     - Complexity: Large + small + numbers + specials
     - Length: 20 characters
     - Age: 30 days

   ✓ Name of administrator account to manage : Administrator
     (ou nom personnalisé si renommé)

   ✓ Do not allow password expiration time longer than required : Enabled
```

### Déploiement MSI

```powershell
# Via GPO Software Installation ou SCCM/Intune
# Installer uniquement "AdmPwd GPO Extension" sur les clients

# Ou via script :
msiexec /i "LAPS.x64.msi" /quiet ADDLOCAL=CSE

# Sur les postes d'admin, installer aussi :
msiexec /i "LAPS.x64.msi" /quiet ADDLOCAL=CSE,Management.UI,Management.PS
```

### Récupération du Mot de Passe

```powershell
# Via PowerShell
Import-Module AdmPwd.PS
Get-AdmPwdPassword -ComputerName "PC001"

# Résultat :
# ComputerName    : PC001
# DistinguishedName : CN=PC001,OU=Workstations,DC=corp,DC=local
# Password        : x7#kL9$mNp2@qRs
# ExpirationTimestamp : 2024-02-15 10:30:00

# Via GUI : LAPS UI (laps.exe)

# Forcer le reset au prochain GPO refresh
Reset-AdmPwdPassword -ComputerName "PC001"
gpupdate /target:PC001 /force
```

---

## Windows LAPS (Moderne)

### Prérequis

```powershell
# Windows Server 2019/2022 avec April 2023 update
# Windows 10/11 22H2 avec April 2023 update
# Functional level : Windows Server 2016+

# Vérifier si Windows LAPS est disponible
Get-Command -Module LAPS

# Le module est intégré, pas d'installation nécessaire
```

### Préparation Active Directory

```powershell
# Sur un DC, en tant que Schema Admin (si pas déjà fait automatiquement)
# Windows Server 2022 avec les updates récentes a déjà le schéma

# Vérifier les attributs
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
    -Filter {name -like "ms-LAPS-*"} -Properties * | Select-Object name

# Attributs Windows LAPS :
# - msLAPS-Password : mot de passe chiffré
# - msLAPS-PasswordExpirationTime
# - msLAPS-EncryptedPassword
# - msLAPS-EncryptedPasswordHistory
# - msLAPS-EncryptedDSRMPassword (pour DC)
```

### Configuration Permissions

```powershell
# Importer le module
Import-Module LAPS

# Permissions pour les machines (écriture)
Set-LapsADComputerSelfPermission -Identity "OU=Servers,DC=corp,DC=local"

# Permissions de lecture pour les admins
Set-LapsADReadPasswordPermission -Identity "OU=Servers,DC=corp,DC=local" `
    -AllowedPrincipals "CORP\Server-Admins"

# Permission de reset
Set-LapsADResetPasswordPermission -Identity "OU=Servers,DC=corp,DC=local" `
    -AllowedPrincipals "CORP\Server-Admins"

# Vérifier
Get-LapsADOrganizationalUnit -Identity "OU=Servers,DC=corp,DC=local"
```

### Configuration GPO

```
Computer Configuration > Administrative Templates >
System > LAPS :

✓ Configure password backup directory : Active Directory

✓ Password Settings :
  - Complexity: 4 (all character types)
  - Length: 20
  - Age: 30 days

✓ Configure authorized password decryptors :
  - CORP\Server-Admins (groupe autorisé à déchiffrer)

✓ Enable password encryption : Enabled

✓ Enable password backup for DSRM accounts : Enabled (sur les DC)

✓ Configure size of encrypted password history : 12
  (garde 12 anciens mots de passe)

✓ Name of administrator account to manage : Administrator
  (ou laisser vide pour le built-in Administrator)
```

### Récupération du Mot de Passe

```powershell
# Récupérer le mot de passe actuel
Get-LapsADPassword -Identity "SERVER01" -AsPlainText

# Résultat :
# ComputerName        : SERVER01
# DistinguishedName   : CN=SERVER01,OU=Servers,DC=corp,DC=local
# Account             : Administrator
# Password            : x7#kL9$mNp2@qRsT5
# PasswordUpdateTime  : 2024-01-15 08:30:00
# ExpirationTimestamp : 2024-02-14 08:30:00
# Source              : EncryptedPassword
# DecryptionStatus    : Success

# Avec historique
Get-LapsADPassword -Identity "SERVER01" -AsPlainText -IncludeHistory

# Forcer la rotation
Reset-LapsPassword -Identity "SERVER01"

# Vérifier le statut sur la machine locale
Get-LapsLocalPassword
```

### Azure AD / Entra ID Backup

```powershell
# Windows LAPS peut aussi sauvegarder dans Azure AD

# GPO :
# Configure password backup directory : Azure Active Directory

# Prérequis :
# - Machine jointe à Azure AD ou Hybrid Azure AD Join
# - Licence appropriée (Azure AD Premium ?)

# Récupérer depuis Azure AD
# Via Intune ou Microsoft Graph API
```

---

## Gestion Opérationnelle

### Audit et Reporting

```powershell
# Machines sans mot de passe LAPS
Get-ADComputer -Filter * -SearchBase "OU=Servers,DC=corp,DC=local" -Properties ms-Mcs-AdmPwdExpirationTime |
    Where-Object { $_.'ms-Mcs-AdmPwdExpirationTime' -eq $null } |
    Select-Object Name, DistinguishedName

# Mots de passe expirés (Legacy LAPS)
$now = Get-Date
Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwdExpirationTime |
    Where-Object {
        $_.'ms-Mcs-AdmPwdExpirationTime' -and
        [DateTime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime') -lt $now
    } |
    Select-Object Name, @{N='Expiration';E={[DateTime]::FromFileTime($_.'ms-Mcs-AdmPwdExpirationTime')}}

# Windows LAPS - Rapport complet
Get-ADComputer -Filter * -SearchBase "OU=Servers,DC=corp,DC=local" |
    ForEach-Object {
        $laps = Get-LapsADPassword -Identity $_.Name -AsPlainText -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            ComputerName = $_.Name
            HasPassword = [bool]$laps
            ExpirationTime = $laps.ExpirationTimestamp
            LastUpdate = $laps.PasswordUpdateTime
        }
    } | Export-Csv "C:\Reports\laps-status.csv" -NoTypeInformation
```

### Troubleshooting

```powershell
# Vérifier si LAPS est actif sur une machine
# (Exécuter sur la machine cible)
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -ErrorAction SilentlyContinue

# Event logs Legacy LAPS
Get-WinEvent -LogName "Application" -MaxEvents 100 |
    Where-Object { $_.ProviderName -eq "AdmPwd" }

# Event logs Windows LAPS
Get-WinEvent -LogName "Microsoft-Windows-LAPS/Operational" -MaxEvents 50

# Forcer le traitement GPO
gpupdate /force

# Vérifier la CSE Legacy LAPS
Get-ChildItem "C:\Program Files\LAPS\CSE"

# Tester la connectivité AD
nltest /dsgetdc:corp.local
```

### Migration Legacy vers Windows LAPS

```powershell
# Windows LAPS peut coexister avec Legacy LAPS
# Mais il faut migrer progressivement

# 1. Déployer Windows LAPS GPO sur un groupe pilote
# 2. Désactiver Legacy LAPS GPO pour ce groupe
# 3. Vérifier que Windows LAPS fonctionne
# 4. Étendre progressivement

# Les attributs sont différents :
# Legacy : ms-Mcs-AdmPwd
# Windows LAPS : msLAPS-Password, msLAPS-EncryptedPassword

# Après migration, nettoyer les anciens attributs si souhaité
```

---

## Intégration avec PAM/PIM

### Utilisation avec un Coffre-Fort

```powershell
# Exemple : Récupération automatisée pour CyberArk/Thycotic
# Script à exécuter par le PAM pour récupérer les credentials

param($ComputerName)

Import-Module LAPS

$password = Get-LapsADPassword -Identity $ComputerName -AsPlainText
if ($password) {
    # Retourner au format attendu par le PAM
    [PSCustomObject]@{
        Username = ".\Administrator"
        Password = $password.Password
        Expiration = $password.ExpirationTimestamp
    } | ConvertTo-Json
}
```

### Rotation Manuelle Sécurisée

```powershell
# Script de connexion sécurisée avec rotation post-utilisation
function Connect-WithLaps {
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [switch]$RotateAfter
    )

    $laps = Get-LapsADPassword -Identity $ComputerName -AsPlainText
    if (-not $laps) {
        Write-Error "No LAPS password found for $ComputerName"
        return
    }

    $secPassword = ConvertTo-SecureString $laps.Password -AsPlainText -Force
    $cred = New-Object PSCredential("$ComputerName\Administrator", $secPassword)

    # Connexion
    Enter-PSSession -ComputerName $ComputerName -Credential $cred

    # Après déconnexion, forcer la rotation
    if ($RotateAfter) {
        Reset-LapsPassword -Identity $ComputerName
        Write-Host "Password rotated for $ComputerName" -ForegroundColor Green
    }
}
```

---

## Bonnes Pratiques

```yaml
Checklist LAPS:
  Déploiement:
    - [ ] Utiliser Windows LAPS si possible (chiffrement)
    - [ ] Tester sur un groupe pilote
    - [ ] Documenter les permissions accordées
    - [ ] Former le helpdesk à la récupération

  Sécurité:
    - [ ] Limiter les droits de lecture au strict nécessaire
    - [ ] Activer le chiffrement (Windows LAPS)
    - [ ] Activer l'historique des mots de passe
    - [ ] Auditer les accès aux mots de passe

  Opérations:
    - [ ] Monitoring des machines sans LAPS
    - [ ] Alertes sur échecs de rotation
    - [ ] Rotation après chaque utilisation sensible
    - [ ] Plan de migration Legacy → Windows LAPS

  Mot de passe:
    - [ ] Longueur minimum 14-20 caractères
    - [ ] Tous les types de caractères
    - [ ] Rotation 30 jours (ou moins si sensible)
```

---

**Voir aussi :**

- [Active Directory](active-directory.md) - Fondamentaux AD
- [AD Delegation](ad-delegation.md) - Délégation de permissions
- [Windows Security](windows-security.md) - Sécurité Windows
- [Credential Guard](credential-guard.md) - Protection des credentials
