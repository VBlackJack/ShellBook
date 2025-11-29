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
