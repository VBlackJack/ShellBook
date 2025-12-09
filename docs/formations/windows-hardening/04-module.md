---
tags:
  - formation
  - windows
  - securite
  - hardening
  - active-directory
---

# Module 4 : Active Directory

## Objectifs du Module

- Implémenter le Tiering Model Microsoft
- Déployer LAPS pour les mots de passe locaux
- Configurer les Protected Users
- Sécuriser les comptes privilégiés

**Durée :** 2 heures

---

## 1. Tiering Model

### 1.1 Concept

```text
TIERING MODEL - SEPARATION DES PRIVILEGES
══════════════════════════════════════════

┌─────────────────────────────────────────────────────────┐
│                      TIER 0                             │
│              Contrôle de l'identité                     │
│  Domain Controllers, CA, Azure AD Connect, PAM         │
│  → Comptes: Domain Admins, Enterprise Admins           │
└─────────────────────────────────────────────────────────┘
                         ▲
                         │ Jamais de connexion descendante
                         ▼
┌─────────────────────────────────────────────────────────┐
│                      TIER 1                             │
│              Serveurs et Applications                   │
│  Serveurs membres, SQL, Exchange, SCCM                 │
│  → Comptes: Server Admins, Application Admins          │
└─────────────────────────────────────────────────────────┘
                         ▲
                         │ Jamais de connexion descendante
                         ▼
┌─────────────────────────────────────────────────────────┐
│                      TIER 2                             │
│              Postes de travail                          │
│  Workstations, Laptops, VDI                            │
│  → Comptes: Helpdesk, Desktop Support                  │
└─────────────────────────────────────────────────────────┘

REGLE D'OR: Un admin Tier N ne se connecte JAMAIS sur Tier N+1
```

### 1.2 Structure d'OU Recommandée

```powershell
# Créer la structure d'OU pour le Tiering
$Domain = "DC=corp,DC=local"

# Tier 0
New-ADOrganizationalUnit -Name "Tier 0" -Path $Domain
New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier 0,$Domain"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Tier 0,$Domain"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Tier 0,$Domain"
New-ADOrganizationalUnit -Name "PAW" -Path "OU=Tier 0,$Domain"

# Tier 1
New-ADOrganizationalUnit -Name "Tier 1" -Path $Domain
New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier 1,$Domain"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Tier 1,$Domain"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Tier 1,$Domain"

# Tier 2
New-ADOrganizationalUnit -Name "Tier 2" -Path $Domain
New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier 2,$Domain"
New-ADOrganizationalUnit -Name "Groups" -Path "OU=Tier 2,$Domain"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=Tier 2,$Domain"

# Protéger contre la suppression
Get-ADOrganizationalUnit -Filter 'Name -like "Tier*"' |
    Set-ADOrganizationalUnit -ProtectedFromAccidentalDeletion $true
```

### 1.3 GPO de Restriction de Connexion

```powershell
# Créer les GPO de restriction
# Tier 0 : Seuls les admins Tier 0 peuvent se connecter

# Via GPO - User Rights Assignment
# "Allow log on locally" = Tier0-Admins
# "Deny log on locally" = Tier1-Admins, Tier2-Admins

# Script pour documenter les restrictions
$TieringRestrictions = @{
    "Tier0-Servers" = @{
        AllowLogon = @("Tier0-Admins")
        DenyLogon = @("Tier1-Admins", "Tier2-Admins", "Domain Users")
    }
    "Tier1-Servers" = @{
        AllowLogon = @("Tier1-Admins")
        DenyLogon = @("Tier0-Admins", "Tier2-Admins")
    }
    "Tier2-Workstations" = @{
        AllowLogon = @("Tier2-Admins", "Domain Users")
        DenyLogon = @("Tier0-Admins", "Tier1-Admins")
    }
}
```

---

## 2. LAPS (Local Administrator Password Solution)

### 2.1 Installation

```powershell
# Télécharger LAPS
# https://www.microsoft.com/download/details.aspx?id=46899

# Installer sur le serveur de gestion
msiexec /i "LAPS.x64.msi" /quiet

# Installer le module PowerShell
Import-Module AdmPwd.PS

# Étendre le schéma AD (nécessite Schema Admin)
Update-AdmPwdADSchema

# Vérifier l'extension
Get-ADObject -SearchBase "CN=Schema,CN=Configuration,DC=corp,DC=local" `
    -Filter {name -eq "ms-Mcs-AdmPwd"} -Properties *
```

### 2.2 Configuration des Permissions

```powershell
# Donner aux ordinateurs le droit de mettre à jour leur mot de passe
$TargetOU = "OU=Workstations,OU=Tier 2,DC=corp,DC=local"
Set-AdmPwdComputerSelfPermission -OrgUnit $TargetOU

# Donner aux admins le droit de lire les mots de passe
Set-AdmPwdReadPasswordPermission -OrgUnit $TargetOU -AllowedPrincipals "Tier2-Admins"

# Donner le droit de forcer le reset
Set-AdmPwdResetPasswordPermission -OrgUnit $TargetOU -AllowedPrincipals "Tier2-Admins"

# Vérifier les permissions
Find-AdmPwdExtendedRights -OrgUnit $TargetOU
```

### 2.3 Déploiement via GPO

```powershell
# Créer la GPO LAPS
$GPOName = "LAPS-Configuration"
New-GPO -Name $GPOName

# Configurer les paramètres (via GPMC ou registre)
# Computer Configuration > Administrative Templates > LAPS

# Paramètres recommandés :
# - Password Settings:
#   - Complexity: Large letters + small letters + numbers + specials
#   - Length: 20 characters
#   - Age: 30 days
# - Enable local admin password management: Enabled
# - Name of administrator account to manage: (laisser vide pour Administrator)

# Lier la GPO
New-GPLink -Name $GPOName -Target "OU=Workstations,OU=Tier 2,DC=corp,DC=local"
```

### 2.4 Utilisation

```powershell
# Récupérer le mot de passe d'un ordinateur
Get-AdmPwdPassword -ComputerName "PC001"

# Forcer le renouvellement
Reset-AdmPwdPassword -ComputerName "PC001"

# Script de récupération sécurisé avec logging
function Get-LAPSPassword {
    param([string]$ComputerName)

    $Caller = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Log l'accès
    $LogEntry = "$Timestamp | $Caller | Retrieved LAPS password for $ComputerName"
    Add-Content -Path "C:\Logs\LAPS-Access.log" -Value $LogEntry

    # Récupérer le mot de passe
    Get-AdmPwdPassword -ComputerName $ComputerName
}
```

---

## 3. Protected Users

### 3.1 Concept et Fonctionnalités

```powershell
# Le groupe "Protected Users" applique automatiquement :
# - Pas de mise en cache des credentials
# - Pas de délégation Kerberos
# - Pas d'authentification NTLM
# - Ticket Kerberos : durée de vie 4h (non renouvelable)
# - Pas de DES ou RC4 pour Kerberos

# Prérequis :
# - Niveau fonctionnel domaine : Windows Server 2012 R2+
# - DC : Windows Server 2012 R2+
# - Clients : Windows 8.1+ / Server 2012 R2+
```

### 3.2 Ajout de Membres

```powershell
# Ajouter les comptes sensibles
$ProtectedAccounts = @(
    "admin.t0",
    "svc.backup",
    "admin.security"
)

foreach ($account in $ProtectedAccounts) {
    Add-ADGroupMember -Identity "Protected Users" -Members $account
    Write-Host "Added $account to Protected Users"
}

# Vérifier les membres
Get-ADGroupMember -Identity "Protected Users" | Select-Object Name, SamAccountName
```

### 3.3 Précautions

```powershell
# NE PAS ajouter à Protected Users :
# - Comptes de service (problèmes de délégation)
# - Comptes utilisés pour des tâches planifiées
# - Comptes nécessitant NTLM (legacy apps)

# Tester avant de déployer
# 1. Ajouter le compte en environnement de test
# 2. Vérifier toutes les fonctionnalités
# 3. Monitorer les erreurs Kerberos (Event ID 4768, 4769)

# Événements à surveiller
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4768, 4769
} -MaxEvents 50 | Where-Object {
    $_.Message -match "Protected Users"
}
```

---

## 4. Sécurisation des Comptes Privilégiés

### 4.1 Audit des Groupes Sensibles

```powershell
# Groupes critiques à auditer
$CriticalGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators"
)

# Rapport des membres
$Report = foreach ($group in $CriticalGroups) {
    $members = Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue
    foreach ($member in $members) {
        [PSCustomObject]@{
            Group = $group
            Member = $member.SamAccountName
            Type = $member.objectClass
            Enabled = (Get-ADUser -Identity $member.SamAccountName -ErrorAction SilentlyContinue).Enabled
        }
    }
}

$Report | Format-Table -AutoSize
$Report | Export-Csv "C:\Reports\PrivilegedGroups.csv" -NoTypeInformation
```

### 4.2 Politique de Mots de Passe Granulaire (Fine-Grained)

```powershell
# Créer une PSO (Password Settings Object) stricte pour les admins
New-ADFineGrainedPasswordPolicy -Name "PSO-Admins" `
    -Precedence 10 `
    -MinPasswordLength 16 `
    -PasswordHistoryCount 24 `
    -MaxPasswordAge "30.00:00:00" `
    -MinPasswordAge "1.00:00:00" `
    -ComplexityEnabled $true `
    -ReversibleEncryptionEnabled $false `
    -LockoutThreshold 3 `
    -LockoutDuration "00:30:00" `
    -LockoutObservationWindow "00:30:00"

# Appliquer aux groupes d'admins
Add-ADFineGrainedPasswordPolicySubject -Identity "PSO-Admins" -Subjects "Domain Admins"
Add-ADFineGrainedPasswordPolicySubject -Identity "PSO-Admins" -Subjects "Tier0-Admins"

# Vérifier l'application
Get-ADUserResultantPasswordPolicy -Identity "admin.t0"
```

### 4.3 Comptes de Service Gérés (gMSA)

```powershell
# Créer la clé KDS (une seule fois par forêt)
Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))

# Créer un gMSA
New-ADServiceAccount -Name "gMSA-SQLService" `
    -DNSHostName "gmsa-sqlservice.corp.local" `
    -PrincipalsAllowedToRetrieveManagedPassword "SQL-Servers" `
    -KerberosEncryptionType AES256

# Installer sur le serveur cible
Install-ADServiceAccount -Identity "gMSA-SQLService"

# Tester
Test-ADServiceAccount -Identity "gMSA-SQLService"

# Utiliser dans un service
# Nom d'utilisateur : CORP\gMSA-SQLService$
# Mot de passe : (laisser vide, géré automatiquement)
```

---

## 5. Audit et Surveillance

### 5.1 Configuration de l'Audit

```powershell
# Activer l'audit avancé via GPO ou commande
# Audit logon events
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable

# Audit account management
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable

# Audit directory service
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable

# Vérifier
auditpol /get /category:*
```

### 5.2 Surveillance des Événements Critiques

```powershell
# Événements à surveiller
$CriticalEvents = @{
    4720 = "User account created"
    4722 = "User account enabled"
    4725 = "User account disabled"
    4726 = "User account deleted"
    4728 = "Member added to security-enabled global group"
    4732 = "Member added to security-enabled local group"
    4756 = "Member added to security-enabled universal group"
    4740 = "Account locked out"
    4767 = "Account unlocked"
    4624 = "Successful logon"
    4625 = "Failed logon"
    4648 = "Explicit credential logon"
    4672 = "Special privileges assigned"
}

# Script de surveillance
$Events = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = $CriticalEvents.Keys
    StartTime = (Get-Date).AddHours(-24)
} -ErrorAction SilentlyContinue

$Events | ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        EventID = $_.Id
        Description = $CriticalEvents[$_.Id]
        Message = $_.Message.Split("`n")[0]
    }
} | Format-Table -AutoSize
```

---

## 6. Exercice : À Vous de Jouer

!!! example "Mise en Pratique : Implémenter le Tiering Model et LAPS"
    **Objectif** : Déployer une architecture de sécurité AD conforme aux bonnes pratiques Microsoft.

    **Contexte** : Suite à un audit de sécurité, vous devez implémenter le Tiering Model et sécuriser les comptes privilégiés.

    **Tâches à réaliser** :

    1. Créer la structure d'OU pour le Tiering Model (Tier 0, Tier 1, Tier 2)
    2. Déployer LAPS sur une OU de test avec rotation automatique
    3. Ajouter un compte admin critique à Protected Users
    4. Créer une Fine-Grained Password Policy (PSO) pour les administrateurs
    5. Configurer l'audit des modifications de comptes privilégiés

    **Critères de validation** :

    - [ ] OUs Tier 0/1/2 créées avec GPO liées
    - [ ] LAPS fonctionnel (mot de passe récupérable)
    - [ ] Compte admin dans Protected Users
    - [ ] PSO avec complexité renforcée (20 caractères, 1 jour historique)
    - [ ] Audit des modifications activé

??? quote "Solution"
    ```powershell
    # 1. Créer la structure Tiering
    $BaseDN = "DC=corp,DC=local"
    @("Tier 0", "Tier 1", "Tier 2") | ForEach-Object {
        New-ADOrganizationalUnit -Name $_ -Path $BaseDN
    }

    # 2. Déployer LAPS
    Import-Module AdmPwd.PS
    Update-AdmPwdADSchema
    Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,DC=corp,DC=local"

    # 3. Protected Users
    Add-ADGroupMember -Identity "Protected Users" -Members "Admin-T0"

    # 4. PSO pour admins
    New-ADFineGrainedPasswordPolicy -Name "PSO-Admins" `
        -Precedence 10 -MinPasswordLength 20 -PasswordHistoryCount 24 `
        -ComplexityEnabled $true -LockoutThreshold 3

    # 5. Audit
    $AuditPath = "AD:\DC=corp,DC=local"
    $Acl = Get-Acl $AuditPath
    # Configure auditing for privileged groups changes
    ```

    **Validation** :
    ```powershell
    Get-ADOrganizationalUnit -Filter 'Name -like "Tier*"' | Select-Object Name
    Get-AdmPwdPassword -ComputerName "PC-TEST"
    Get-ADGroupMember -Identity "Protected Users"
    Get-ADFineGrainedPasswordPolicy -Filter *
    ```

---

## Quiz

1. **Quel est le principe du Tiering Model ?**
   - [ ] A. Tous les admins ont les mêmes droits
   - [ ] B. Séparation des privilèges par niveau de criticité
   - [ ] C. Les admins n'utilisent que PowerShell

2. **Que fait LAPS ?**
   - [ ] A. Chiffre les disques
   - [ ] B. Gère les mots de passe admin locaux automatiquement
   - [ ] C. Bloque les malwares

3. **Quelle restriction Protected Users impose-t-il ?**
   - [ ] A. Pas d'authentification NTLM
   - [ ] B. Pas d'accès Internet
   - [ ] C. Pas de connexion RDP

**Réponses :** 1-B, 2-B, 3-A

---

**Précédent :** [Module 3 - Réseau & Firewall](03-module.md)

**Suivant :** [Module 5 - TP Final](05-tp-final.md)

---

## Navigation

| | |
|:---|---:|
| [← Module 3 : Réseau & Firewall](03-module.md) | [Module 5 : TP Final - Audit et Remédi... →](05-tp-final.md) |

[Retour au Programme](index.md){ .md-button }
