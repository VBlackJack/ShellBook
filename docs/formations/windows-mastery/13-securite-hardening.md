---
tags:
  - formation
  - windows-server
  - securite
  - hardening
  - tiering
---

# Module 13 : Sécurité & Hardening

## Objectifs du Module

Ce module couvre la sécurisation d'Active Directory et Windows Server :

- Implémenter le modèle de Tiering
- Configurer LAPS pour les mots de passe admin locaux
- Utiliser Protected Users et Authentication Policies
- Auditer et détecter les menaces
- Appliquer les bonnes pratiques de hardening

**Durée :** 8 heures

**Niveau :** Ingénierie

---

## 1. Modèle de Tiering

### 1.1 Concept

```
TIERING MODEL - MICROSOFT
─────────────────────────

Tier 0 - Contrôle de l'identité
├── Domain Controllers
├── PKI / CA
├── ADFS
└── Comptes: Domain Admins, Enterprise Admins

Tier 1 - Contrôle des serveurs
├── Serveurs membres
├── Applications métier
└── Comptes: Server Admins

Tier 2 - Contrôle des postes de travail
├── Workstations
├── Laptops
└── Comptes: Helpdesk, Desktop Support

RÈGLE FONDAMENTALE
──────────────────
Un compte d'un Tier supérieur ne doit JAMAIS
se connecter à un système d'un Tier inférieur.

Tier 0 → Tier 0 uniquement
Tier 1 → Tier 1 et Tier 2
Tier 2 → Tier 2 uniquement
```

### 1.2 Implémentation avec OU et GPO

```powershell
# Créer la structure Tiering
$baseDN = "DC=corp,DC=local"

# OU Tier 0
New-ADOrganizationalUnit -Name "Tier0" -Path $baseDN
New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier0,$baseDN"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Tier0,$baseDN"
New-ADOrganizationalUnit -Name "PAW" -Path "OU=Tier0,$baseDN"

# OU Tier 1
New-ADOrganizationalUnit -Name "Tier1" -Path $baseDN
New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier1,$baseDN"
New-ADOrganizationalUnit -Name "Servers" -Path "OU=Tier1,$baseDN"

# OU Tier 2
New-ADOrganizationalUnit -Name "Tier2" -Path $baseDN
New-ADOrganizationalUnit -Name "Accounts" -Path "OU=Tier2,$baseDN"
New-ADOrganizationalUnit -Name "Workstations" -Path "OU=Tier2,$baseDN"

# Créer les groupes de restriction
New-ADGroup -Name "Tier0-Admins" -GroupScope Global -Path "OU=Accounts,OU=Tier0,$baseDN"
New-ADGroup -Name "Tier1-Admins" -GroupScope Global -Path "OU=Accounts,OU=Tier1,$baseDN"
New-ADGroup -Name "Tier2-Admins" -GroupScope Global -Path "OU=Accounts,OU=Tier2,$baseDN"
```

---

## 2. LAPS (Local Administrator Password Solution)

### 2.1 Installation

```powershell
# Télécharger LAPS depuis Microsoft
# https://www.microsoft.com/download/details.aspx?id=46899

# Installer sur le DC (composants de gestion)
msiexec /i LAPS.x64.msi ADDDEFAULT=ALL /quiet

# Étendre le schéma AD
Import-Module AdmPwd.PS
Update-AdmPwdADSchema

# Configurer les permissions
Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Computers,OU=Corp,DC=corp,DC=local"

# Donner les droits de lecture aux admins
Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Computers,OU=Corp,DC=corp,DC=local" -AllowedPrincipals "IT-Admins"
Set-AdmPwdResetPasswordPermission -OrgUnit "OU=Computers,OU=Corp,DC=corp,DC=local" -AllowedPrincipals "IT-Admins"
```

### 2.2 Configuration GPO

```powershell
# Créer la GPO LAPS
New-GPO -Name "LAPS-Config"

# Activer LAPS
Set-GPRegistryValue -Name "LAPS-Config" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
    -ValueName "AdmPwdEnabled" `
    -Type DWord -Value 1

# Complexité du mot de passe
Set-GPRegistryValue -Name "LAPS-Config" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
    -ValueName "PasswordComplexity" `
    -Type DWord -Value 4  # Lettres + chiffres + spéciaux

# Longueur
Set-GPRegistryValue -Name "LAPS-Config" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
    -ValueName "PasswordLength" `
    -Type DWord -Value 20

# Âge (jours)
Set-GPRegistryValue -Name "LAPS-Config" `
    -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
    -ValueName "PasswordAgeDays" `
    -Type DWord -Value 30

# Lier la GPO
New-GPLink -Name "LAPS-Config" -Target "OU=Computers,OU=Corp,DC=corp,DC=local"
```

### 2.3 Utilisation

```powershell
# Récupérer le mot de passe admin local d'un ordinateur
Get-AdmPwdPassword -ComputerName "PC001"

# Forcer le renouvellement
Reset-AdmPwdPassword -ComputerName "PC001"

# Via GUI
# Exécuter "LAPS UI" sur une machine avec les outils installés
```

---

## 3. Protected Users et Policies

### 3.1 Protected Users Group

```powershell
# Le groupe Protected Users offre :
# - Pas de NTLM (Kerberos uniquement)
# - Pas de délégation
# - Pas de cache de credentials
# - TGT de 4h max

# Ajouter un utilisateur
Add-ADGroupMember -Identity "Protected Users" -Members "admin-tier0"

# Vérifier les membres
Get-ADGroupMember -Identity "Protected Users"

# ATTENTION: Ne pas ajouter les comptes de service !
# Les comptes dans Protected Users ne peuvent pas utiliser NTLM
```

### 3.2 Authentication Policies

```powershell
# Créer une politique d'authentification (Tier 0)
New-ADAuthenticationPolicy -Name "Tier0-Auth-Policy" `
    -UserAllowedToAuthenticateFrom "O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == `"Tier0-Silo`"))" `
    -UserTGTLifetimeMins 240 `
    -Enforce

# Créer un silo d'authentification
New-ADAuthenticationPolicySilo -Name "Tier0-Silo" `
    -UserAuthenticationPolicy "Tier0-Auth-Policy" `
    -ComputerAuthenticationPolicy "Tier0-Auth-Policy" `
    -ServiceAuthenticationPolicy "Tier0-Auth-Policy" `
    -Enforce

# Assigner au silo
Set-ADAccountAuthenticationPolicySilo -Identity "admin-tier0" -AuthenticationPolicySilo "Tier0-Silo"
Grant-ADAuthenticationPolicySiloAccess -Identity "Tier0-Silo" -Account "admin-tier0"
```

---

## 4. Audit et Détection

### 4.1 Configuration de l'Audit

```powershell
# Activer l'audit avancé via GPO
# Computer Configuration → Policies → Windows Settings → Security Settings → Advanced Audit Policy

# Événements critiques à surveiller:
# 4624 - Connexion réussie
# 4625 - Échec de connexion
# 4648 - Connexion avec credentials explicites
# 4672 - Privilèges spéciaux assignés
# 4720 - Création de compte
# 4728 - Ajout à groupe de sécurité
# 4732 - Ajout à groupe local
# 4756 - Ajout à groupe universel
# 4768 - Demande de TGT Kerberos
# 4769 - Demande de ticket de service

# Script de surveillance basique
$criticalEvents = @(4625, 4720, 4728, 4732, 4756)

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = $criticalEvents
    StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, Id, Message | Format-Table -Wrap
```

### 4.2 Détection des Attaques Courantes

```powershell
# Détection Kerberoasting (demandes TGS anormales)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4769
} | Where-Object { $_.Message -match "0x17" }  # RC4 encryption

# Détection DCSync (réplication non autorisée)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4662
} | Where-Object { $_.Message -match "Replicating Directory Changes" }

# Détection Pass-the-Hash (connexions NTLM suspectes)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ID = 4624
} | Where-Object {
    $_.Message -match "NTLM" -and
    $_.Message -match "Network"
}
```

---

## 5. Hardening Windows Server

### 5.1 Checklist de Base

```powershell
# 1. Désactiver SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# 2. Activer le signing SMB
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# 3. Désactiver LLMNR
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force

# 4. Désactiver NetBIOS sur toutes les interfaces
Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
    $_.SetTcpipNetbios(2)  # 2 = Disable
}

# 5. Configurer Windows Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# 6. Désactiver les services inutiles
$servicesToDisable = @("Browser", "RemoteRegistry", "TapiSrv")
foreach ($svc in $servicesToDisable) {
    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
}

# 7. Configurer NTP
w32tm /config /manualpeerlist:"time.windows.com" /syncfromflags:manual /reliable:YES /update
```

### 5.2 Sécurité des Comptes

```powershell
# Renommer le compte Administrator
Rename-LocalUser -Name "Administrator" -NewName "SysAdmin01"

# Désactiver le compte Guest
Disable-LocalUser -Name "Guest"

# Configurer le verrouillage de compte (via GPO)
# - Seuil: 5 tentatives
# - Durée: 30 minutes
# - Réinitialisation: 30 minutes

# Audit des comptes privilégiés
Get-ADGroupMember -Identity "Domain Admins" -Recursive
Get-ADGroupMember -Identity "Enterprise Admins" -Recursive
Get-ADGroupMember -Identity "Schema Admins" -Recursive
```

---

## 6. Exercice Pratique

### Audit de Sécurité

```powershell
# Script d'audit de sécurité AD
$report = @()

# Comptes Domain Admins
$report += [PSCustomObject]@{
    Check = "Domain Admins"
    Count = (Get-ADGroupMember "Domain Admins" -Recursive).Count
    Status = if ((Get-ADGroupMember "Domain Admins" -Recursive).Count -gt 5) { "WARNING" } else { "OK" }
}

# Comptes sans expiration de MDP
$noExpire = Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires
$report += [PSCustomObject]@{
    Check = "Password Never Expires"
    Count = $noExpire.Count
    Status = if ($noExpire.Count -gt 10) { "WARNING" } else { "OK" }
}

# Comptes inactifs (90 jours)
$date = (Get-Date).AddDays(-90)
$inactive = Get-ADUser -Filter {LastLogonDate -lt $date} -Properties LastLogonDate
$report += [PSCustomObject]@{
    Check = "Inactive Accounts (90d)"
    Count = $inactive.Count
    Status = if ($inactive.Count -gt 20) { "WARNING" } else { "OK" }
}

# SMBv1
$smb1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
$report += [PSCustomObject]@{
    Check = "SMBv1 Disabled"
    Count = if ($smb1.State -eq "Disabled") { "Yes" } else { "No" }
    Status = if ($smb1.State -eq "Disabled") { "OK" } else { "CRITICAL" }
}

# Afficher le rapport
$report | Format-Table -AutoSize
```

---

## Exercice : À Vous de Jouer

!!! example "Mise en Pratique"
    **Objectif** : Implémenter une infrastructure Active Directory sécurisée selon le modèle de Tiering

    **Contexte** : Vous devez renforcer la sécurité de l'AD de votre entreprise en appliquant le modèle de Tiering, en déployant LAPS, en configurant Protected Users, et en mettant en place un système d'audit robuste.

    **Tâches à réaliser** :

    1. Créer la structure Tiering (Tier 0, 1, 2) avec les OUs appropriées
    2. Créer des comptes administrateurs dédiés par Tier (admin-t0, admin-t1, admin-t2)
    3. Déployer LAPS sur l'OU des ordinateurs avec rotation tous les 30 jours
    4. Ajouter les comptes Tier 0 au groupe Protected Users
    5. Configurer l'audit avancé pour détecter les activités suspectes
    6. Appliquer le hardening de base (désactiver SMBv1, LLMNR, NetBIOS)
    7. Générer un rapport d'audit de sécurité complet

    **Critères de validation** :

    - [ ] Structure Tiering créée avec protection des OUs
    - [ ] 3 comptes administrateurs créés et placés dans les bonnes OUs
    - [ ] LAPS installé et fonctionnel avec permissions configurées
    - [ ] Comptes Tier 0 dans Protected Users
    - [ ] Audit avancé activé (connexions, modifications AD, privilèges)
    - [ ] SMBv1 désactivé, LLMNR et NetBIOS désactivés
    - [ ] Rapport d'audit montrant moins de 5 vulnérabilités

??? quote "Solution"
    **Étape 1 : Création de la structure Tiering**

    ```powershell
    $baseDN = "DC=corp,DC=local"

    # Créer les OUs principales pour chaque Tier
    $tiers = @("Tier0", "Tier1", "Tier2")
    foreach ($tier in $tiers) {
        New-ADOrganizationalUnit -Name $tier -Path $baseDN `
            -ProtectedFromAccidentalDeletion $true
        Write-Host "✓ OU $tier créée"

        # Créer les sous-OUs pour chaque Tier
        $subOUs = @("Accounts", "Servers", "Groups")
        if ($tier -eq "Tier0") {
            $subOUs += "PAW"  # Privileged Access Workstation
        }
        if ($tier -eq "Tier2") {
            $subOUs = $subOUs | Where-Object { $_ -ne "Servers" }
            $subOUs += "Workstations"
        }

        foreach ($subOU in $subOUs) {
            New-ADOrganizationalUnit -Name $subOU -Path "OU=$tier,$baseDN" `
                -ProtectedFromAccidentalDeletion $true
            Write-Host "  - Sous-OU $subOU créée"
        }
    }

    Write-Host "`n✓ Structure Tiering créée avec succès"
    ```

    **Étape 2 : Création des comptes administrateurs par Tier**

    ```powershell
    # Définir les comptes admin
    $adminAccounts = @(
        @{Name="admin-t0"; Tier="Tier0"; Description="Administrateur Tier 0 - Domaine et PKI"; Groups=@("Domain Admins")},
        @{Name="admin-t1"; Tier="Tier1"; Description="Administrateur Tier 1 - Serveurs"; Groups=@()},
        @{Name="admin-t2"; Tier="Tier2"; Description="Administrateur Tier 2 - Workstations"; Groups=@()}
    )

    foreach ($admin in $adminAccounts) {
        $path = "OU=Accounts,OU=$($admin.Tier),$baseDN"

        # Créer le compte
        New-ADUser -Name $admin.Name `
                   -SamAccountName $admin.Name `
                   -UserPrincipalName "$($admin.Name)@corp.local" `
                   -Description $admin.Description `
                   -Path $path `
                   -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!Change" -AsPlainText -Force) `
                   -Enabled $true `
                   -ChangePasswordAtLogon $true `
                   -PasswordNeverExpires $false

        # Ajouter aux groupes si spécifié
        foreach ($group in $admin.Groups) {
            Add-ADGroupMember -Identity $group -Members $admin.Name
        }

        Write-Host "✓ Compte $($admin.Name) créé dans $($admin.Tier)"
    }

    # Créer les groupes de restriction
    $tierGroups = @(
        @{Name="Tier0-Admins"; Tier="Tier0"; Description="Administrateurs Tier 0"},
        @{Name="Tier1-Admins"; Tier="Tier1"; Description="Administrateurs Tier 1"},
        @{Name="Tier2-Admins"; Tier="Tier2"; Description="Administrateurs Tier 2"}
    )

    foreach ($tierGroup in $tierGroups) {
        $path = "OU=Groups,OU=$($tierGroup.Tier),$baseDN"
        New-ADGroup -Name $tierGroup.Name `
                    -GroupScope Global `
                    -GroupCategory Security `
                    -Path $path `
                    -Description $tierGroup.Description

        # Ajouter le compte admin correspondant
        Add-ADGroupMember -Identity $tierGroup.Name -Members "admin-$($tierGroup.Tier.ToLower())"
        Write-Host "✓ Groupe $($tierGroup.Name) créé"
    }
    ```

    **Étape 3 : Déploiement de LAPS**

    ```powershell
    # Installer LAPS (doit être téléchargé depuis Microsoft)
    # msiexec /i LAPS.x64.msi ADDDEFAULT=ALL /quiet

    # Importer le module
    Import-Module AdmPwd.PS

    # Étendre le schéma AD
    Update-AdmPwdADSchema

    # Configurer les permissions sur l'OU Computers
    # Permettre aux ordinateurs de mettre à jour leur propre mot de passe
    Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Workstations,OU=Tier2,$baseDN"
    Set-AdmPwdComputerSelfPermission -OrgUnit "OU=Servers,OU=Tier1,$baseDN"

    # Donner les droits de lecture aux groupes d'admin appropriés
    Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Workstations,OU=Tier2,$baseDN" `
        -AllowedPrincipals "Tier2-Admins"
    Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Servers,OU=Tier1,$baseDN" `
        -AllowedPrincipals "Tier1-Admins"
    Set-AdmPwdReadPasswordPermission -OrgUnit "OU=Servers,OU=Tier0,$baseDN" `
        -AllowedPrincipals "Tier0-Admins"

    # Donner les droits de reset
    Set-AdmPwdResetPasswordPermission -OrgUnit "OU=Workstations,OU=Tier2,$baseDN" `
        -AllowedPrincipals "Tier2-Admins"

    Write-Host "✓ LAPS configuré avec permissions appropriées"

    # Créer la GPO LAPS
    New-GPO -Name "LAPS-Configuration"

    # Activer LAPS
    Set-GPRegistryValue -Name "LAPS-Configuration" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "AdmPwdEnabled" `
        -Type DWord -Value 1

    # Complexité maximale (lettres + chiffres + spéciaux)
    Set-GPRegistryValue -Name "LAPS-Configuration" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PasswordComplexity" `
        -Type DWord -Value 4

    # Longueur 20 caractères
    Set-GPRegistryValue -Name "LAPS-Configuration" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PasswordLength" `
        -Type DWord -Value 20

    # Rotation tous les 30 jours
    Set-GPRegistryValue -Name "LAPS-Configuration" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd" `
        -ValueName "PasswordAgeDays" `
        -Type DWord -Value 30

    # Lier la GPO aux OUs appropriées
    New-GPLink -Name "LAPS-Configuration" -Target "OU=Workstations,OU=Tier2,$baseDN"
    New-GPLink -Name "LAPS-Configuration" -Target "OU=Servers,OU=Tier1,$baseDN"
    New-GPLink -Name "LAPS-Configuration" -Target "OU=Servers,OU=Tier0,$baseDN"

    Write-Host "✓ GPO LAPS créée et liée"
    ```

    **Étape 4 : Configuration Protected Users**

    ```powershell
    # Ajouter les comptes Tier 0 au groupe Protected Users
    $tier0Admins = Get-ADUser -Filter * -SearchBase "OU=Accounts,OU=Tier0,$baseDN"

    foreach ($admin in $tier0Admins) {
        Add-ADGroupMember -Identity "Protected Users" -Members $admin.SamAccountName
        Write-Host "✓ $($admin.Name) ajouté à Protected Users"
    }

    # Vérifier les membres
    $protectedMembers = Get-ADGroupMember -Identity "Protected Users"
    Write-Host "`nMembres de Protected Users:"
    $protectedMembers | ForEach-Object { Write-Host "  - $($_.Name)" }

    Write-Host "`n⚠ ATTENTION: Les comptes dans Protected Users:"
    Write-Host "  - Ne peuvent pas utiliser NTLM (Kerberos uniquement)"
    Write-Host "  - TGT valide 4h maximum"
    Write-Host "  - Pas de délégation"
    Write-Host "  - Pas de cache des credentials"
    ```

    **Étape 5 : Configuration de l'audit avancé**

    ```powershell
    # Créer une GPO d'audit
    New-GPO -Name "SEC-Advanced-Audit"

    # Configurer l'audit via la GPO
    # Note: La configuration détaillée se fait via GPMC
    # Computer Configuration → Policies → Windows Settings →
    # Security Settings → Advanced Audit Policy Configuration

    # Configurer les tailles des journaux d'événements
    Set-GPRegistryValue -Name "SEC-Advanced-Audit" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
        -ValueName "MaxSize" `
        -Type DWord -Value 1048576  # 1 GB

    Set-GPRegistryValue -Name "SEC-Advanced-Audit" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security" `
        -ValueName "Retention" `
        -Type String -Value "0"  # Écraser au besoin

    # Lier au domaine
    New-GPLink -Name "SEC-Advanced-Audit" -Target $baseDN -Enforced Yes

    Write-Host "✓ GPO d'audit créée"

    # Script de surveillance des événements critiques
    $auditScript = @'
    # Surveillance des événements de sécurité critiques
    $criticalEvents = @(
        4625,  # Échec de connexion
        4720,  # Création de compte
        4728,  # Ajout à groupe de sécurité global
        4732,  # Ajout à groupe de sécurité local
        4756,  # Ajout à groupe universel
        4672   # Privilèges spéciaux assignés
    )

    Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = $criticalEvents
        StartTime = (Get-Date).AddHours(-24)
    } | Select-Object TimeCreated, Id, Message |
        Export-Csv "C:\Logs\Security-Audit-$(Get-Date -Format 'yyyyMMdd').csv"
'@

    $auditScript | Out-File "C:\Scripts\Security-Audit.ps1" -Force
    Write-Host "✓ Script d'audit créé: C:\Scripts\Security-Audit.ps1"
    ```

    **Étape 6 : Hardening de base**

    ```powershell
    # Créer une GPO de hardening
    New-GPO -Name "SEC-Server-Hardening"

    # 1. Désactiver SMBv1
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Host "✓ SMBv1 désactivé"

    # Configurer via GPO pour tous les serveurs
    Set-GPRegistryValue -Name "SEC-Server-Hardening" `
        -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -ValueName "SMB1" `
        -Type DWord -Value 0

    # 2. Activer le signing SMB
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
    Set-GPRegistryValue -Name "SEC-Server-Hardening" `
        -Key "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
        -ValueName "RequireSecuritySignature" `
        -Type DWord -Value 1
    Write-Host "✓ SMB Signing activé"

    # 3. Désactiver LLMNR
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "EnableMulticast" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue

    Set-GPRegistryValue -Name "SEC-Server-Hardening" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -ValueName "EnableMulticast" `
        -Type DWord -Value 0
    Write-Host "✓ LLMNR désactivé"

    # 4. Désactiver NetBIOS
    Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled } | ForEach-Object {
        $_.SetTcpipNetbios(2)  # 2 = Disable
    }
    Write-Host "✓ NetBIOS désactivé sur toutes les interfaces"

    # 5. Activer Windows Firewall
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
    Set-GPRegistryValue -Name "SEC-Server-Hardening" `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" `
        -ValueName "EnableFirewall" `
        -Type DWord -Value 1
    Write-Host "✓ Windows Firewall activé"

    # 6. Désactiver les services inutiles
    $servicesToDisable = @("Browser", "RemoteRegistry", "TapiSrv", "WMPNetworkSvc")
    foreach ($svc in $servicesToDisable) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Set-Service -Name $svc -StartupType Disabled
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Write-Host "  - Service $svc désactivé"
        }
    }

    # Lier la GPO de hardening
    New-GPLink -Name "SEC-Server-Hardening" -Target "OU=Servers,OU=Tier1,$baseDN"
    New-GPLink -Name "SEC-Server-Hardening" -Target "OU=Servers,OU=Tier0,$baseDN"
    Write-Host "✓ GPO de hardening liée"
    ```

    **Étape 7 : Rapport d'audit de sécurité**

    ```powershell
    # Script de génération de rapport d'audit complet
    $reportPath = "C:\Reports\Security-Audit-$(Get-Date -Format 'yyyyMMdd-HHmm').html"

    $htmlHeader = @"
    <html>
    <head>
        <title>Rapport d'Audit de Sécurité - $(Get-Date -Format 'dd/MM/yyyy HH:mm')</title>
        <style>
            body { font-family: Arial; margin: 20px; }
            h1 { color: #0066cc; }
            h2 { color: #0099cc; margin-top: 30px; }
            table { border-collapse: collapse; width: 100%; margin-top: 10px; }
            th { background-color: #0066cc; color: white; padding: 10px; text-align: left; }
            td { border: 1px solid #ddd; padding: 8px; }
            .pass { color: green; font-weight: bold; }
            .fail { color: red; font-weight: bold; }
            .warning { color: orange; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>Rapport d'Audit de Sécurité AD</h1>
        <p>Date: $(Get-Date -Format 'dd/MM/yyyy HH:mm')</p>
"@

    $htmlContent = $htmlHeader

    # 1. Structure Tiering
    $htmlContent += "<h2>1. Structure Tiering</h2><table><tr><th>Tier</th><th>OUs</th><th>Comptes Admin</th><th>Status</th></tr>"
    foreach ($tier in @("Tier0", "Tier1", "Tier2")) {
        $ouExists = Get-ADOrganizationalUnit -Filter "Name -eq '$tier'" -ErrorAction SilentlyContinue
        $adminCount = (Get-ADUser -Filter * -SearchBase "OU=Accounts,OU=$tier,$baseDN" -ErrorAction SilentlyContinue).Count
        $status = if ($ouExists -and $adminCount -gt 0) { "PASS" } else { "FAIL" }
        $class = $status.ToLower()
        $htmlContent += "<tr><td>$tier</td><td>$(if($ouExists){'✓'}else{'✗'})</td><td>$adminCount</td><td class='$class'>$status</td></tr>"
    }
    $htmlContent += "</table>"

    # 2. LAPS
    $htmlContent += "<h2>2. LAPS</h2><table><tr><th>Vérification</th><th>Status</th></tr>"
    $lapsGPO = Get-GPO -Name "LAPS-Configuration" -ErrorAction SilentlyContinue
    $htmlContent += "<tr><td>GPO LAPS existe</td><td class='$(if($lapsGPO){"pass"}else{"fail"})'>$(if($lapsGPO){'✓ PASS'}else{'✗ FAIL'})</td></tr>"
    $htmlContent += "</table>"

    # 3. Protected Users
    $htmlContent += "<h2>3. Protected Users</h2><table><tr><th>Membre</th><th>OU</th></tr>"
    $protectedUsers = Get-ADGroupMember -Identity "Protected Users"
    foreach ($user in $protectedUsers) {
        $userObj = Get-ADUser -Identity $user.SamAccountName -Properties CanonicalName
        $htmlContent += "<tr><td>$($user.Name)</td><td>$($userObj.CanonicalName)</td></tr>"
    }
    $htmlContent += "</table>"

    # 4. Hardening
    $htmlContent += "<h2>4. Hardening</h2><table><tr><th>Contrôle</th><th>Status</th></tr>"

    $smb1Status = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
    $htmlContent += "<tr><td>SMBv1 désactivé</td><td class='$(if($smb1Status.State -eq "Disabled"){"pass"}else{"fail"})'>$(if($smb1Status.State -eq "Disabled"){'✓ PASS'}else{'✗ FAIL'})</td></tr>"

    $llmnrValue = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
    $htmlContent += "<tr><td>LLMNR désactivé</td><td class='$(if($llmnrValue.EnableMulticast -eq 0){"pass"}else{"fail"})'>$(if($llmnrValue.EnableMulticast -eq 0){'✓ PASS'}else{'✗ FAIL'})</td></tr>"

    $fwStatus = (Get-NetFirewallProfile -Profile Domain).Enabled
    $htmlContent += "<tr><td>Firewall activé</td><td class='$(if($fwStatus){"pass"}else{"fail"})'>$(if($fwStatus){'✓ PASS'}else{'✗ FAIL'})</td></tr>"

    $htmlContent += "</table>"

    # 5. Comptes à risque
    $htmlContent += "<h2>5. Comptes à risque</h2><table><tr><th>Type</th><th>Nombre</th><th>Status</th></tr>"

    $domainAdmins = (Get-ADGroupMember "Domain Admins" -Recursive).Count
    $htmlContent += "<tr><td>Domain Admins</td><td>$domainAdmins</td><td class='$(if($domainAdmins -le 5){"pass"}else{"warning"})'>$(if($domainAdmins -le 5){'✓ OK'}else{'⚠ WARNING'})</td></tr>"

    $noExpire = (Get-ADUser -Filter {PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires).Count
    $htmlContent += "<tr><td>MDP n'expirent jamais</td><td>$noExpire</td><td class='$(if($noExpire -le 5){"pass"}else{"warning"})'>$(if($noExpire -le 5){'✓ OK'}else{'⚠ WARNING'})</td></tr>"

    $date = (Get-Date).AddDays(-90)
    $inactive = (Get-ADUser -Filter {LastLogonDate -lt $date} -Properties LastLogonDate).Count
    $htmlContent += "<tr><td>Comptes inactifs (90j)</td><td>$inactive</td><td class='$(if($inactive -le 10){"pass"}else{"warning"})'>$(if($inactive -le 10){'✓ OK'}else{'⚠ WARNING'})</td></tr>"

    $htmlContent += "</table>"

    # Conclusion
    $htmlContent += "<h2>Conclusion</h2>"
    $htmlContent += "<p>Audit complété avec succès. Vérifiez les points en WARNING/FAIL.</p>"
    $htmlContent += "</body></html>"

    # Sauvegarder le rapport
    $htmlContent | Out-File $reportPath -Encoding UTF8
    Write-Host "`n✓ Rapport d'audit généré: $reportPath"
    Write-Host "Ouvrir le rapport avec: Start-Process '$reportPath'"

    # Afficher un résumé dans la console
    Write-Host "`n=== RÉSUMÉ DE L'AUDIT ===" -ForegroundColor Cyan
    Write-Host "Structure Tiering: ✓"
    Write-Host "LAPS déployé: $(if($lapsGPO){'✓'}else{'✗'})"
    Write-Host "Protected Users: $($protectedUsers.Count) membres"
    Write-Host "SMBv1: $(if($smb1Status.State -eq 'Disabled'){'✓ Désactivé'}else{'✗ Activé'})"
    Write-Host "Domain Admins: $domainAdmins $(if($domainAdmins -le 5){'✓'}else{'⚠'})"
    Write-Host "`nRapport complet: $reportPath"
    }
    ```

---

## Quiz

1. **Dans le modèle de Tiering, où se trouvent les DC ?**
   - [ ] A. Tier 2
   - [ ] B. Tier 1
   - [ ] C. Tier 0

2. **Que fait LAPS ?**
   - [ ] A. Chiffre les disques
   - [ ] B. Gère les mots de passe admin locaux
   - [ ] C. Filtre le trafic réseau

**Réponses :** 1-C, 2-B

---

**Précédent :** [Module 12 : GPO & Configuration](12-gpo-configuration.md)

**Suivant :** [Module 14 : Services Réseau Avancés](14-services-reseau-avances.md)
