---
tags:
  - formation
  - windows-server
  - tp-final
  - domain-controller
  - hardening
  - hands-on
---

# Module 4 : TP Final - Déploiement DC Sécurisé

**Objectif :** Déployer un Domain Controller sécurisé pour une succursale en consolidant les compétences des Modules 1, 2 et 3.

---

## Scénario : Branch Office Deployment

### Le Contexte

Vous êtes admin système chez **GlobalCorp**, une entreprise internationale. Votre direction ouvre une **nouvelle succursale à Lyon** et vous demande de déployer l'infrastructure Active Directory pour ce site.

```text
┌─────────────────────────────────────────────────────────────┐
│                     CAHIER DES CHARGES                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Infrastructure :                                           │
│  ────────────────                                            │
│  • 1 Domain Controller pour le site Lyon                   │
│  • Server Core (pas de GUI)                                 │
│  • Domaine : branch.local (pour ce lab)                    │
│  • IP statique : 192.168.100.10/24                          │
│  • DNS : 127.0.0.1 (le DC sera le serveur DNS)             │
│                                                              │
│  Structure AD :                                             │
│  ───────────────                                             │
│  • OU=Users (utilisateurs standards)                        │
│  • OU=Computers (postes de travail)                         │
│  • OU=Groups (groupes de sécurité)                          │
│  • OU=Admins (comptes privilégiés - Tiering Model)          │
│                                                              │
│  Sécurité (Hardening) :                                     │
│  ───────────────────────                                     │
│  • SMBv1 désactivé                                          │
│  • Audit Process Creation activé (4688)                     │
│  • Firewall actif (règles AD uniquement)                    │
│  • BitLocker activé (si TPM disponible)                     │
│                                                              │
│  Utilisateurs de test :                                     │
│  ──────────────────────                                      │
│  • admin-t0-dc (Domain Admin - Tier 0)                      │
│  • jdupont (utilisateur standard)                           │
│  • mmartin (utilisateur standard)                           │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Prérequis

**Matériel/VM :**

- Windows Server 2022 (ou 2025) fraîchement installé
- Server Core Edition (pas de GUI)
- 4 GB RAM minimum
- 60 GB disque
- 1 vCPU minimum (2 vCPU recommandé)
- Snapshot/Backup de la VM (pour pouvoir revenir en arrière)

**Connaissances :**

- Avoir suivi les Modules 1, 2 et 3
- Savoir utiliser PowerShell sur Server Core
- Comprendre Active Directory (Forest, Domain, OU)

### Temps Estimé

**Durée totale :** 2-3 heures

- Étape 1 (Préparation) : 30 min
- Étape 2 (Promotion DC) : 45 min
- Étape 3 (Structure AD) : 30 min
- Étape 4 (Hardening) : 30 min
- Étape 5 (Validation) : 15 min

---

## Étape 1 : Préparation Server Core (Module 1)

### Objectif

Préparer le serveur Server Core : nom, IP statique, WinRM, outils RSAT.

### 1.1 Vérification Initiale

```powershell
# Se connecter au serveur Server Core (console physique ou KVM)
# Une invite PowerShell s'affiche automatiquement

# Vérifier la version Windows
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsArchitecture

# Output attendu:
# WindowsProductName : Windows Server 2022 Datacenter
# WindowsVersion     : 2009
# OsArchitecture     : 64-bit

# Vérifier le type d'installation
Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' |
    Select-Object InstallationType

# Output attendu:
# InstallationType : Server Core
```

### 1.2 Renommer le Serveur

```powershell
# Renommer en DC-BRANCH-01
Rename-Computer -NewName "DC-BRANCH-01" -Force

# Vérifier (le nouveau nom sera actif après redémarrage)
$env:COMPUTERNAME
# Affiche encore l'ancien nom (WIN-XXXXX)

# Redémarrer
Restart-Computer -Force

# Attendre le redémarrage (environ 2 minutes)
# Reconnecter à la console
```

### 1.3 Configuration Réseau

```powershell
# Lister les adaptateurs réseau
Get-NetAdapter

# Identifier l'adaptateur actif (généralement "Ethernet")
$InterfaceAlias = (Get-NetAdapter | Where-Object Status -eq "Up").Name

# Supprimer la configuration DHCP existante
Remove-NetIPAddress -InterfaceAlias $InterfaceAlias -Confirm:$false -ErrorAction SilentlyContinue
Remove-NetRoute -InterfaceAlias $InterfaceAlias -Confirm:$false -ErrorAction SilentlyContinue

# Configurer IP statique
$IPAddress = "192.168.100.10"
$PrefixLength = 24
$Gateway = "192.168.100.1"
$DNS = "127.0.0.1"  # Le DC sera son propre serveur DNS

New-NetIPAddress -InterfaceAlias $InterfaceAlias `
    -IPAddress $IPAddress `
    -PrefixLength $PrefixLength `
    -DefaultGateway $Gateway

Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias `
    -ServerAddresses $DNS

# Vérifier la configuration
Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 |
    Select-Object IPAddress, PrefixLength

Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 |
    Select-Object ServerAddresses

# Test de connectivité (Google DNS)
Test-NetConnection -ComputerName 8.8.8.8 -InformationLevel Detailed
```

### 1.4 Configurer le Fuseau Horaire

```powershell
# Configurer le fuseau horaire Paris (GMT+1)
Set-TimeZone -Id "Romance Standard Time"

# Vérifier
Get-TimeZone

# Output attendu:
# Id                         : Romance Standard Time
# DisplayName                : (UTC+01:00) Brussels, Copenhagen, Madrid, Paris
# StandardName               : Romance Standard Time
```

### 1.5 Activer WinRM (Administration à Distance)

```powershell
# Activer PowerShell Remoting
Enable-PSRemoting -Force

# Configurer TrustedHosts (pour ce lab, autoriser tous)
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force

# Activer la règle Firewall pour WinRM
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"

# Vérifier que WinRM fonctionne
Get-Service WinRM

# Output attendu:
# Status : Running
```

### 1.6 Installer les Outils RSAT

```powershell
# Installer RSAT AD Tools (nécessaire pour gérer AD en PowerShell)
Install-WindowsFeature -Name RSAT-AD-PowerShell, RSAT-AD-AdminCenter

# Vérifier l'installation
Get-WindowsFeature -Name RSAT-AD-* | Where-Object Installed

# Output attendu: Liste des outils RSAT installés
```

### ✅ Checkpoint Étape 1

Vérifier que tout est OK avant de continuer :

```powershell
# Résumé de la configuration
Write-Host "`n=== Configuration Server Core ===" -ForegroundColor Cyan
Write-Host "Nom du serveur   : $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Adresse IP       : $($(Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4).IPAddress)" -ForegroundColor White
Write-Host "DNS              : $($(Get-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4).ServerAddresses)" -ForegroundColor White
Write-Host "Fuseau horaire   : $($(Get-TimeZone).Id)" -ForegroundColor White
Write-Host "WinRM Status     : $($(Get-Service WinRM).Status)" -ForegroundColor White
```

**Résultat attendu :**

```text
=== Configuration Server Core ===
Nom du serveur   : DC-BRANCH-01
Adresse IP       : 192.168.100.10
DNS              : 127.0.0.1
Fuseau horaire   : Romance Standard Time
WinRM Status     : Running
```

---

## Étape 2 : Promotion Active Directory (Module 2)

### Objectif

Installer le rôle AD DS et promouvoir le serveur en Domain Controller.

### 2.1 Installer le Rôle AD Domain Services

```powershell
# Installer AD DS (Active Directory Domain Services)
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# Vérifier l'installation
Get-WindowsFeature -Name AD-Domain-Services

# Output attendu:
# Install State : Installed
```

### 2.2 Promouvoir en Domain Controller (Nouvelle Forêt)

```powershell
# Importer le module AD DS
Import-Module ADDSDeployment

# Configurer le mot de passe DSRM (Directory Services Restore Mode)
# ⚠️ IMPORTANT : Conserver ce mot de passe en lieu sûr !
$DSRMPassword = ConvertTo-SecureString "P@ssw0rd-DSRM-2024!" -AsPlainText -Force

# Promouvoir en DC (créer une nouvelle forêt)
Install-ADDSForest `
    -DomainName "branch.local" `
    -DomainNetbiosName "BRANCH" `
    -ForestMode "WinThreshold" `
    -DomainMode "WinThreshold" `
    -InstallDns `
    -SafeModeAdministratorPassword $DSRMPassword `
    -Force

# Le serveur redémarre automatiquement après la promotion
# Attendre environ 5 minutes pour le redémarrage complet
```

!!! warning "Redémarrage Automatique"
    Le serveur va **redémarrer automatiquement** après la promotion.
    Attendez environ **5 minutes** puis reconnectez-vous.

### 2.3 Vérification Post-Promotion

```powershell
# Reconnecter à la console après redémarrage
# Se connecter avec le compte BRANCH\Administrator

# Vérifier que le DC fonctionne
Get-ADDomainController

# Output attendu:
# ComputerObjectDN  : CN=DC-BRANCH-01,OU=Domain Controllers,DC=branch,DC=local
# Domain            : branch.local
# Enabled           : True
# Forest            : branch.local
# IsGlobalCatalog   : True
# OperatingSystem   : Windows Server 2022 Datacenter

# Vérifier le domaine
Get-ADDomain

# Output attendu:
# DistinguishedName : DC=branch,DC=local
# DNSRoot           : branch.local
# NetBIOSName       : BRANCH
# Forest            : branch.local

# Vérifier la forêt
Get-ADForest

# Output attendu:
# Name              : branch.local
# ForestMode        : Windows2016Forest
# RootDomain        : branch.local
```

### 2.4 Vérifier DNS

```powershell
# Lister les zones DNS
Get-DnsServerZone

# Output attendu:
# ZoneName                   ZoneType
# --------                   --------
# branch.local               Primary
# _msdcs.branch.local        Primary
# 100.168.192.in-addr.arpa   Primary  (zone inverse)

# Tester la résolution DNS
nslookup dc-branch-01.branch.local 127.0.0.1

# Output attendu:
# Server:  localhost
# Address:  127.0.0.1
# Name:    dc-branch-01.branch.local
# Address:  192.168.100.10
```

### 2.5 Vérifier SYSVOL

```powershell
# Vérifier que SYSVOL est répliqué
Get-SmbShare | Where-Object Name -like "SYSVOL"

# Output attendu:
# Name      ScopeName Path                                 Description
# ----      --------- ----                                 -----------
# SYSVOL    *         C:\Windows\SYSVOL\sysvol             Logon server share

# Vérifier le contenu de SYSVOL
Get-ChildItem C:\Windows\SYSVOL\sysvol\branch.local

# Output attendu:
# Policies
# scripts
```

### ✅ Checkpoint Étape 2

```powershell
# Script de vérification rapide
Write-Host "`n=== Vérification Domain Controller ===" -ForegroundColor Cyan

# 1. DC Status
$DC = Get-ADDomainController
Write-Host "✅ DC Name       : $($DC.Name)" -ForegroundColor Green
Write-Host "✅ Domain        : $($DC.Domain)" -ForegroundColor Green
Write-Host "✅ Global Catalog: $($DC.IsGlobalCatalog)" -ForegroundColor Green

# 2. DNS Status
$DNSZones = (Get-DnsServerZone).Count
Write-Host "✅ DNS Zones     : $DNSZones zones configurées" -ForegroundColor Green

# 3. SYSVOL Status
$SYSVOL = Test-Path "C:\Windows\SYSVOL\sysvol\branch.local"
if ($SYSVOL) {
    Write-Host "✅ SYSVOL        : Répliqué" -ForegroundColor Green
} else {
    Write-Host "❌ SYSVOL        : Non répliqué" -ForegroundColor Red
}
```

---

## Étape 3 : Structure AD & Utilisateurs (Module 2)

### Objectif

Créer la structure d'OU et les utilisateurs de test selon le Tiering Model.

### 3.1 Créer la Structure d'OU

```powershell
# Récupérer le DN du domaine
$DomainDN = (Get-ADDomain).DistinguishedName
# Résultat : DC=branch,DC=local

# Créer les OU principales
New-ADOrganizationalUnit -Name "Users" -Path $DomainDN
New-ADOrganizationalUnit -Name "Computers" -Path $DomainDN
New-ADOrganizationalUnit -Name "Groups" -Path $DomainDN
New-ADOrganizationalUnit -Name "Admins" -Path $DomainDN -Description "Tier 0 Admin Accounts"

# Créer des sous-OU dans Admins (Tiering Model)
New-ADOrganizationalUnit -Name "Tier0" -Path "OU=Admins,$DomainDN" -Description "Domain Admins"
New-ADOrganizationalUnit -Name "Tier1" -Path "OU=Admins,$DomainDN" -Description "Server Admins"
New-ADOrganizationalUnit -Name "Tier2" -Path "OU=Admins,$DomainDN" -Description "Workstation Admins"

# Vérifier la structure
Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName |
    Sort-Object DistinguishedName

# Output attendu:
# Name      DistinguishedName
# ----      -----------------
# Admins    OU=Admins,DC=branch,DC=local
# Tier0     OU=Tier0,OU=Admins,DC=branch,DC=local
# Tier1     OU=Tier1,OU=Admins,DC=branch,DC=local
# Tier2     OU=Tier2,OU=Admins,DC=branch,DC=local
# Computers OU=Computers,DC=branch,DC=local
# Groups    OU=Groups,DC=branch,DC=local
# Users     OU=Users,DC=branch,DC=local
```

### 3.2 Créer les Groupes de Sécurité

```powershell
# Groupe pour les utilisateurs standards
New-ADGroup -Name "G_Users_Lyon" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Groups,$DomainDN" `
    -Description "Tous les utilisateurs du site Lyon"

# Groupe pour les admins Tier 0
New-ADGroup -Name "G_Admins_Tier0" `
    -GroupScope Global `
    -GroupCategory Security `
    -Path "OU=Groups,$DomainDN" `
    -Description "Administrateurs Tier 0 (Domain Admins)"

# Vérifier
Get-ADGroup -Filter * -SearchBase "OU=Groups,$DomainDN" |
    Select-Object Name, GroupScope, GroupCategory
```

### 3.3 Créer les Utilisateurs

#### Utilisateur Admin Tier 0 (Domain Admin)

```powershell
# Créer le compte admin-t0-dc
$Password = ConvertTo-SecureString "P@ssw0rd-Admin-2024!" -AsPlainText -Force

New-ADUser `
    -Name "Admin Tier 0 DC" `
    -SamAccountName "admin-t0-dc" `
    -UserPrincipalName "admin-t0-dc@branch.local" `
    -GivenName "Admin" `
    -Surname "Tier0" `
    -DisplayName "Admin Tier 0 DC" `
    -Path "OU=Tier0,OU=Admins,$DomainDN" `
    -AccountPassword $Password `
    -Enabled $true `
    -ChangePasswordAtLogon $false `
    -PasswordNeverExpires $true `
    -Description "Compte admin Tier 0 - Gestion DC uniquement"

# Ajouter au groupe Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "admin-t0-dc"
Add-ADGroupMember -Identity "G_Admins_Tier0" -Members "admin-t0-dc"

# Vérifier
Get-ADUser -Identity "admin-t0-dc" -Properties MemberOf |
    Select-Object Name, SamAccountName, MemberOf
```

#### Utilisateurs Standards

```powershell
# Créer Jean Dupont
$Password = ConvertTo-SecureString "Welcome2024!" -AsPlainText -Force

New-ADUser `
    -Name "Jean Dupont" `
    -SamAccountName "jdupont" `
    -UserPrincipalName "jdupont@branch.local" `
    -GivenName "Jean" `
    -Surname "Dupont" `
    -DisplayName "Jean Dupont" `
    -Path "OU=Users,$DomainDN" `
    -AccountPassword $Password `
    -Enabled $true `
    -ChangePasswordAtLogon $true `
    -Department "IT" `
    -Title "Technicien IT"

# Créer Marie Martin
New-ADUser `
    -Name "Marie Martin" `
    -SamAccountName "mmartin" `
    -UserPrincipalName "mmartin@branch.local" `
    -GivenName "Marie" `
    -Surname "Martin" `
    -DisplayName "Marie Martin" `
    -Path "OU=Users,$DomainDN" `
    -AccountPassword $Password `
    -Enabled $true `
    -ChangePasswordAtLogon $true `
    -Department "Finance" `
    -Title "Analyste Financier"

# Ajouter les utilisateurs au groupe G_Users_Lyon
Add-ADGroupMember -Identity "G_Users_Lyon" -Members jdupont, mmartin

# Vérifier
Get-ADUser -Filter * -SearchBase "OU=Users,$DomainDN" |
    Select-Object Name, SamAccountName, Enabled
```

### ✅ Checkpoint Étape 3

```powershell
# Vérification de la structure AD
Write-Host "`n=== Structure Active Directory ===" -ForegroundColor Cyan

# Compter les OU
$OUCount = (Get-ADOrganizationalUnit -Filter *).Count
Write-Host "✅ OUs créées     : $OUCount" -ForegroundColor Green

# Compter les groupes (hors groupes par défaut)
$GroupCount = (Get-ADGroup -Filter * -SearchBase "OU=Groups,$DomainDN").Count
Write-Host "✅ Groupes créés  : $GroupCount" -ForegroundColor Green

# Compter les utilisateurs (hors Administrator)
$UserCount = (Get-ADUser -Filter * -SearchBase "OU=Users,$DomainDN").Count +
             (Get-ADUser -Filter * -SearchBase "OU=Admins,$DomainDN").Count
Write-Host "✅ Users créés    : $UserCount (hors Administrator)" -ForegroundColor Green

# Lister les utilisateurs
Get-ADUser -Filter * -SearchBase "OU=Users,$DomainDN" |
    Select-Object Name, SamAccountName | Format-Table

Get-ADUser -Filter * -SearchBase "OU=Admins,$DomainDN" |
    Select-Object Name, SamAccountName | Format-Table
```

---

## Étape 4 : Hardening (Module 3)

### Objectif

Appliquer les best practices de sécurité : désactiver SMBv1, activer les audits, configurer le firewall.

### 4.1 Désactiver SMBv1

```powershell
# Vérifier l'état actuel de SMBv1
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Output actuel:
# State : Enabled  ← MAUVAIS

# Désactiver SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Vérifier
Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol

# Output attendu:
# EnableSMB1Protocol
# ------------------
# False  ← BON
```

### 4.2 Désactiver LLMNR et NBT-NS

```powershell
# Désactiver LLMNR (Link-Local Multicast Name Resolution)
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast" -Value 0 -Type DWord

# Désactiver NBT-NS sur toutes les interfaces
$Adapters = Get-WmiObject Win32_NetworkAdapterConfiguration |
    Where-Object { $_.TcpipNetbiosOptions -ne $null }

foreach ($Adapter in $Adapters) {
    $Adapter.SetTcpipNetbios(2)  # 2 = Disable
}

# Vérifier
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
    -Name "EnableMulticast"

Get-WmiObject Win32_NetworkAdapterConfiguration |
    Select-Object Description, TcpipNetbiosOptions
# TcpipNetbiosOptions = 2 (Disabled) ← BON
```

### 4.3 Activer les Audit Logs (Process Creation 4688)

```powershell
# Activer l'audit des créations de processus
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Process Termination" /success:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable

# Activer la ligne de commande dans les logs 4688
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# Augmenter la taille du log Security à 1 GB
wevtutil sl Security /ms:1073741824

# Vérifier
auditpol /get /category:*

# Output attendu: Liste des audits activés (Success)
```

### 4.4 Configurer le Firewall (Règles AD)

```powershell
# Activer le Firewall sur tous les profils
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True

# Configurer la politique par défaut (Deny All, Allow Outbound)
Set-NetFirewallProfile -Profile Domain,Private,Public `
    -DefaultInboundAction Block `
    -DefaultOutboundAction Allow

# Activer les règles Firewall pour Active Directory
Enable-NetFirewallRule -DisplayGroup "Active Directory Domain Services"
Enable-NetFirewallRule -DisplayGroup "DNS Service"
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"

# Vérifier les profils Firewall
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction

# Vérifier les règles AD activées
Get-NetFirewallRule -DisplayGroup "Active Directory Domain Services" -Enabled True |
    Select-Object DisplayName, Direction, Action
```

### 4.5 Configurer Windows Defender

```powershell
# Vérifier l'état de Defender
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusSignatureLastUpdated

# Mettre à jour les signatures
Update-MpSignature

# Activer RealTime Protection (si désactivé)
Set-MpPreference -DisableRealtimeMonitoring $false

# Lancer un scan rapide
Start-MpScan -ScanType QuickScan
```

### 4.6 BitLocker (Optionnel - si TPM disponible)

```powershell
# Vérifier si le TPM est présent
Get-Tpm

# Si TPM disponible, activer BitLocker
# ⚠️ ATTENTION : Sauvegarder la clé de récupération AVANT !

# Activer BitLocker sur C:
# Enable-BitLocker -MountPoint "C:" `
#     -EncryptionMethod XtsAes256 `
#     -TpmProtector `
#     -RecoveryPasswordProtector

# Sauvegarder la clé dans AD
# $RecoveryProtector = (Get-BitLockerVolume -MountPoint "C:").KeyProtector |
#     Where-Object KeyProtectorType -eq "RecoveryPassword"
# Backup-BitLockerKeyProtector -MountPoint "C:" `
#     -KeyProtectorId $RecoveryProtector.KeyProtectorId
```

### ✅ Checkpoint Étape 4

```powershell
# Vérification du Hardening
Write-Host "`n=== Vérification Hardening ===" -ForegroundColor Cyan

# 1. SMBv1
$SMB1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
if ($SMB1 -eq $false) {
    Write-Host "✅ SMBv1         : Désactivé" -ForegroundColor Green
} else {
    Write-Host "❌ SMBv1         : Activé (MAUVAIS)" -ForegroundColor Red
}

# 2. Firewall
$FWProfiles = Get-NetFirewallProfile
$AllEnabled = ($FWProfiles | Where-Object Enabled -eq $false).Count -eq 0
if ($AllEnabled) {
    Write-Host "✅ Firewall      : Activé sur tous les profils" -ForegroundColor Green
} else {
    Write-Host "❌ Firewall      : Désactivé sur au moins un profil" -ForegroundColor Red
}

# 3. Audit 4688
$Audit4688 = auditpol /get /subcategory:"Process Creation"
if ($Audit4688 -match "Success") {
    Write-Host "✅ Audit 4688    : Activé" -ForegroundColor Green
} else {
    Write-Host "❌ Audit 4688    : Désactivé" -ForegroundColor Red
}

# 4. Defender
$Defender = Get-MpComputerStatus
if ($Defender.RealTimeProtectionEnabled -eq $true) {
    Write-Host "✅ Defender      : RealTime Protection activée" -ForegroundColor Green
} else {
    Write-Host "❌ Defender      : RealTime Protection désactivée" -ForegroundColor Red
}
```

---

## Étape 5 : Validation - Le Script de Test

### Objectif

Valider que le Domain Controller est conforme aux exigences avec un script automatisé.

### 5.1 Script de Validation Complet

```powershell
# ============================================================
# Test-DC-Compliance.ps1
# Validation complète du Domain Controller
# ============================================================

Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       VALIDATION DOMAIN CONTROLLER - BRANCH LYON         ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nServeur : $env:COMPUTERNAME" -ForegroundColor Gray
Write-Host "Date    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Compteurs
$totalChecks = 0
$passedChecks = 0
$failedChecks = 0

# ============================================================
# CHECK 1 : Est-ce un Domain Controller ?
# ============================================================
Write-Host "[1/10] Domain Controller Status" -ForegroundColor Yellow
$totalChecks++

try {
    $DC = Get-ADDomainController -ErrorAction Stop

    if ($DC.Enabled -eq $true) {
        Write-Host "  ✅ Le serveur est un DC actif" -ForegroundColor Green
        Write-Host "     Domain : $($DC.Domain)" -ForegroundColor Gray
        Write-Host "     Forest : $($DC.Forest)" -ForegroundColor Gray
        Write-Host "     Global Catalog : $($DC.IsGlobalCatalog)" -ForegroundColor Gray
        $passedChecks++
    } else {
        Write-Host "  ❌ Le DC est désactivé" -ForegroundColor Red
        $failedChecks++
    }
} catch {
    Write-Host "  ❌ Le serveur n'est PAS un Domain Controller" -ForegroundColor Red
    $failedChecks++
}

# ============================================================
# CHECK 2 : DNS Zones
# ============================================================
Write-Host "`n[2/10] DNS Zones Configuration" -ForegroundColor Yellow
$totalChecks++

try {
    $DNSZones = Get-DnsServerZone -ErrorAction Stop
    $RequiredZones = @("branch.local", "_msdcs.branch.local")
    $MissingZones = @()

    foreach ($Zone in $RequiredZones) {
        if ($DNSZones.ZoneName -notcontains $Zone) {
            $MissingZones += $Zone
        }
    }

    if ($MissingZones.Count -eq 0) {
        Write-Host "  ✅ Toutes les zones DNS requises sont présentes" -ForegroundColor Green
        Write-Host "     Zones : $($DNSZones.ZoneName -join ', ')" -ForegroundColor Gray
        $passedChecks++
    } else {
        Write-Host "  ❌ Zones DNS manquantes : $($MissingZones -join ', ')" -ForegroundColor Red
        $failedChecks++
    }
} catch {
    Write-Host "  ❌ Impossible de vérifier les zones DNS" -ForegroundColor Red
    $failedChecks++
}

# ============================================================
# CHECK 3 : SYSVOL Replication
# ============================================================
Write-Host "`n[3/10] SYSVOL Replication" -ForegroundColor Yellow
$totalChecks++

$SYSVOLPath = "C:\Windows\SYSVOL\sysvol\branch.local"
if (Test-Path $SYSVOLPath) {
    $SYSVOLContent = Get-ChildItem $SYSVOLPath -ErrorAction SilentlyContinue
    if ($SYSVOLContent.Count -gt 0) {
        Write-Host "  ✅ SYSVOL est répliqué et contient des données" -ForegroundColor Green
        $passedChecks++
    } else {
        Write-Host "  ⚠️  SYSVOL existe mais est vide" -ForegroundColor Yellow
        $failedChecks++
    }
} else {
    Write-Host "  ❌ SYSVOL n'existe pas" -ForegroundColor Red
    $failedChecks++
}

# ============================================================
# CHECK 4 : Structure OU
# ============================================================
Write-Host "`n[4/10] Structure Organizational Units" -ForegroundColor Yellow
$totalChecks++

$RequiredOUs = @("Users", "Computers", "Groups", "Admins")
$DomainDN = (Get-ADDomain).DistinguishedName
$MissingOUs = @()

foreach ($OU in $RequiredOUs) {
    $OUExists = Get-ADOrganizationalUnit -Filter "Name -eq '$OU'" -SearchBase $DomainDN -ErrorAction SilentlyContinue
    if (-not $OUExists) {
        $MissingOUs += $OU
    }
}

if ($MissingOUs.Count -eq 0) {
    Write-Host "  ✅ Toutes les OU requises sont créées" -ForegroundColor Green
    Write-Host "     OUs : $($RequiredOUs -join ', ')" -ForegroundColor Gray
    $passedChecks++
} else {
    Write-Host "  ❌ OUs manquantes : $($MissingOUs -join ', ')" -ForegroundColor Red
    $failedChecks++
}

# ============================================================
# CHECK 5 : Utilisateurs de Test
# ============================================================
Write-Host "`n[5/10] Utilisateurs de Test" -ForegroundColor Yellow
$totalChecks++

$RequiredUsers = @("admin-t0-dc", "jdupont", "mmartin")
$MissingUsers = @()

foreach ($User in $RequiredUsers) {
    $UserExists = Get-ADUser -Filter "SamAccountName -eq '$User'" -ErrorAction SilentlyContinue
    if (-not $UserExists) {
        $MissingUsers += $User
    }
}

if ($MissingUsers.Count -eq 0) {
    Write-Host "  ✅ Tous les utilisateurs de test sont créés" -ForegroundColor Green
    Write-Host "     Users : $($RequiredUsers -join ', ')" -ForegroundColor Gray
    $passedChecks++
} else {
    Write-Host "  ❌ Utilisateurs manquants : $($MissingUsers -join ', ')" -ForegroundColor Red
    $failedChecks++
}

# ============================================================
# CHECK 6 : SMBv1 Désactivé
# ============================================================
Write-Host "`n[6/10] SMBv1 Protocol" -ForegroundColor Yellow
$totalChecks++

$SMB1Status = (Get-SmbServerConfiguration).EnableSMB1Protocol

if ($SMB1Status -eq $false) {
    Write-Host "  ✅ SMBv1 est désactivé (CONFORME)" -ForegroundColor Green
    $passedChecks++
} else {
    Write-Host "  ❌ SMBv1 est activé (NON CONFORME)" -ForegroundColor Red
    $failedChecks++
}

# ============================================================
# CHECK 7 : Firewall Actif
# ============================================================
Write-Host "`n[7/10] Windows Firewall" -ForegroundColor Yellow
$totalChecks++

$FWProfiles = Get-NetFirewallProfile
$DisabledProfiles = $FWProfiles | Where-Object Enabled -eq $false

if ($DisabledProfiles.Count -eq 0) {
    Write-Host "  ✅ Firewall activé sur tous les profils" -ForegroundColor Green
    $passedChecks++
} else {
    Write-Host "  ❌ Firewall désactivé sur : $($DisabledProfiles.Name -join ', ')" -ForegroundColor Red
    $failedChecks++
}

# ============================================================
# CHECK 8 : Audit Process Creation (4688)
# ============================================================
Write-Host "`n[8/10] Audit Policy - Process Creation" -ForegroundColor Yellow
$totalChecks++

$AuditPolicy = auditpol /get /subcategory:"Process Creation"

if ($AuditPolicy -match "Success") {
    Write-Host "  ✅ Audit Process Creation est activé" -ForegroundColor Green
    $passedChecks++
} else {
    Write-Host "  ❌ Audit Process Creation est désactivé" -ForegroundColor Red
    $failedChecks++
}

# ============================================================
# CHECK 9 : Windows Defender
# ============================================================
Write-Host "`n[9/10] Windows Defender" -ForegroundColor Yellow
$totalChecks++

try {
    $Defender = Get-MpComputerStatus -ErrorAction Stop

    if ($Defender.RealTimeProtectionEnabled -eq $true) {
        Write-Host "  ✅ RealTime Protection est activée" -ForegroundColor Green
        Write-Host "     Signatures : $($Defender.AntivirusSignatureLastUpdated)" -ForegroundColor Gray
        $passedChecks++
    } else {
        Write-Host "  ❌ RealTime Protection est désactivée" -ForegroundColor Red
        $failedChecks++
    }
} catch {
    Write-Host "  ⚠️  Impossible de vérifier Defender" -ForegroundColor Yellow
    $failedChecks++
}

# ============================================================
# CHECK 10 : Services AD Critiques
# ============================================================
Write-Host "`n[10/10] Services Active Directory" -ForegroundColor Yellow
$totalChecks++

$RequiredServices = @("NTDS", "DNS", "Netlogon", "W32Time")
$StoppedServices = @()

foreach ($Service in $RequiredServices) {
    $ServiceStatus = Get-Service -Name $Service -ErrorAction SilentlyContinue
    if ($ServiceStatus.Status -ne "Running") {
        $StoppedServices += $Service
    }
}

if ($StoppedServices.Count -eq 0) {
    Write-Host "  ✅ Tous les services AD sont actifs (Running)" -ForegroundColor Green
    $passedChecks++
} else {
    Write-Host "  ❌ Services arrêtés : $($StoppedServices -join ', ')" -ForegroundColor Red
    $failedChecks++
}

# ============================================================
# RÉSUMÉ FINAL
# ============================================================
Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    RÉSUMÉ VALIDATION                     ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

Write-Host "`nTotal checks        : $totalChecks" -ForegroundColor White
Write-Host "✅ Conformes        : $passedChecks" -ForegroundColor Green
Write-Host "❌ Non conformes    : $failedChecks" -ForegroundColor Red

$conformityRate = [math]::Round(($passedChecks / $totalChecks) * 100, 2)
Write-Host "`nTaux de conformité  : $conformityRate%" -ForegroundColor $(
    if ($conformityRate -eq 100) { "Green" }
    elseif ($conformityRate -ge 80) { "Yellow" }
    else { "Red" }
)

if ($failedChecks -eq 0) {
    Write-Host "`n╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║  🎉 FÉLICITATIONS ! DOMAIN CONTROLLER 100% CONFORME !  🎉 ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host "`n✅ Votre DC est prêt pour la production !" -ForegroundColor Green
} else {
    Write-Host "`n⚠️  Domain Controller NON CONFORME : $failedChecks problème(s) détecté(s)" -ForegroundColor Red
    Write-Host "Corrigez les problèmes avant de passer en production." -ForegroundColor Yellow
}

Write-Host "`n=== Validation Terminée ===`n" -ForegroundColor Cyan
```

### 5.2 Exécution du Script de Validation

```powershell
# Sauvegarder le script dans un fichier
# Copier le contenu ci-dessus dans C:\Scripts\Test-DC-Compliance.ps1

# Exécuter le script
Set-ExecutionPolicy Bypass -Scope Process -Force
C:\Scripts\Test-DC-Compliance.ps1
```

**Résultat attendu (100% conforme) :**

```text
╔═══════════════════════════════════════════════════════════╗
║       VALIDATION DOMAIN CONTROLLER - BRANCH LYON         ║
╚═══════════════════════════════════════════════════════════╝

Serveur : DC-BRANCH-01
Date    : 2024-01-22 17:30:00

[1/10] Domain Controller Status
  ✅ Le serveur est un DC actif
     Domain : branch.local
     Forest : branch.local
     Global Catalog : True

[2/10] DNS Zones Configuration
  ✅ Toutes les zones DNS requises sont présentes
     Zones : branch.local, _msdcs.branch.local, 100.168.192.in-addr.arpa

[3/10] SYSVOL Replication
  ✅ SYSVOL est répliqué et contient des données

[4/10] Structure Organizational Units
  ✅ Toutes les OU requises sont créées
     OUs : Users, Computers, Groups, Admins

[5/10] Utilisateurs de Test
  ✅ Tous les utilisateurs de test sont créés
     Users : admin-t0-dc, jdupont, mmartin

[6/10] SMBv1 Protocol
  ✅ SMBv1 est désactivé (CONFORME)

[7/10] Windows Firewall
  ✅ Firewall activé sur tous les profils

[8/10] Audit Policy - Process Creation
  ✅ Audit Process Creation est activé

[9/10] Windows Defender
  ✅ RealTime Protection est activée
     Signatures : 2024-01-22 12:00:00

[10/10] Services Active Directory
  ✅ Tous les services AD sont actifs (Running)

╔═══════════════════════════════════════════════════════════╗
║                    RÉSUMÉ VALIDATION                     ║
╚═══════════════════════════════════════════════════════════╝

Total checks        : 10
✅ Conformes        : 10
❌ Non conformes    : 0

Taux de conformité  : 100%

╔═══════════════════════════════════════════════════════════╗
║  🎉 FÉLICITATIONS ! DOMAIN CONTROLLER 100% CONFORME !  🎉 ║
╚═══════════════════════════════════════════════════════════╝

✅ Votre DC est prêt pour la production !

=== Validation Terminée ===
```

---

## Conclusion : Vous êtes maintenant un Expert Windows Server

### Ce Que Vous Avez Accompli

En complétant ce TP Final, vous avez démontré votre maîtrise de :

**Module 1 - Modern Admin :**

- ✅ Configuration Server Core (nom, IP, WinRM)
- ✅ Installation RSAT via PowerShell
- ✅ Gestion sans GUI (sconfig, PowerShell uniquement)

**Module 2 - Active Directory :**

- ✅ Installation AD Domain Services
- ✅ Promotion en Domain Controller (nouvelle forêt)
- ✅ Création structure d'OU (Tiering Model)
- ✅ Création utilisateurs et groupes via PowerShell
- ✅ Vérification DNS et SYSVOL

**Module 3 - Sécurité & Hardening :**

- ✅ Désactivation SMBv1 (protection WannaCry)
- ✅ Désactivation LLMNR/NBT-NS (protection Responder)
- ✅ Activation Audit Logs (forensic 4688)
- ✅ Configuration Firewall (règles AD uniquement)
- ✅ Configuration Defender (RealTime Protection)

**Compétences Transversales :**

- ✅ Automatisation PowerShell (scripts production-ready)
- ✅ Validation et testing (script de conformité)
- ✅ Documentation (ce TP est votre référence)

### Prochaines Étapes

Vous êtes maintenant qualifié pour :

1. **Environnements de Production**
   - Déployer des DC en production réelle
   - Gérer des forêts AD multi-sites
   - Implémenter le Tiering Model en entreprise

2. **Certifications Microsoft**
   - **AZ-800** : Administering Windows Server Hybrid Core Infrastructure
   - **AZ-801** : Configuring Windows Server Hybrid Advanced Services
   - **SC-900** : Microsoft Security Fundamentals (partie AD)

3. **Compétences Avancées**
   - PowerShell DSC (Desired State Configuration)
   - Ansible pour Windows (automatisation cross-platform)
   - Azure AD Connect (environnements hybrides)
   - SIEM Integration (Splunk, ELK pour les logs AD)

### Ressources pour Continuer

- **Microsoft Learn** : [https://learn.microsoft.com/windows-server/](https://learn.microsoft.com/windows-server/)
- **PowerShell Gallery** : [https://www.powershellgallery.com/](https://www.powershellgallery.com/)
- **Active Directory Security** : [https://adsecurity.org/](https://adsecurity.org/)
- **Reddit r/sysadmin** : [https://reddit.com/r/sysadmin](https://reddit.com/r/sysadmin)

---

## Solution Complète (Aide-Mémoire)

??? quote "Séquence Complète des Commandes PowerShell"

    ### Script de Déploiement Complet

    ```powershell
    # ============================================================
    # Deploy-DC-Branch.ps1
    # Déploiement automatisé d'un Domain Controller sécurisé
    # ============================================================

    Write-Host "`n=== DÉPLOIEMENT DC BRANCH LYON ===" -ForegroundColor Cyan

    # ============================================================
    # ÉTAPE 1 : PRÉPARATION SERVER CORE
    # ============================================================
    Write-Host "`n[Étape 1/5] Préparation Server Core..." -ForegroundColor Yellow

    # Renommer le serveur
    Rename-Computer -NewName "DC-BRANCH-01" -Force
    Write-Host "  ✅ Serveur renommé : DC-BRANCH-01" -ForegroundColor Green

    # Configuration réseau
    $InterfaceAlias = (Get-NetAdapter | Where-Object Status -eq "Up").Name
    Remove-NetIPAddress -InterfaceAlias $InterfaceAlias -Confirm:$false -ErrorAction SilentlyContinue
    Remove-NetRoute -InterfaceAlias $InterfaceAlias -Confirm:$false -ErrorAction SilentlyContinue

    New-NetIPAddress -InterfaceAlias $InterfaceAlias `
        -IPAddress "192.168.100.10" `
        -PrefixLength 24 `
        -DefaultGateway "192.168.100.1"

    Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias `
        -ServerAddresses "127.0.0.1"

    Write-Host "  ✅ IP configurée : 192.168.100.10" -ForegroundColor Green

    # Fuseau horaire
    Set-TimeZone -Id "Romance Standard Time"
    Write-Host "  ✅ Fuseau horaire : Romance Standard Time" -ForegroundColor Green

    # WinRM
    Enable-PSRemoting -Force
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
    Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
    Write-Host "  ✅ WinRM activé" -ForegroundColor Green

    # RSAT
    Install-WindowsFeature -Name RSAT-AD-PowerShell, RSAT-AD-AdminCenter
    Write-Host "  ✅ RSAT installé" -ForegroundColor Green

    # Redémarrer
    Write-Host "`n⚠️  Redémarrage requis. Appuyez sur une touche pour continuer..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Restart-Computer -Force

    # ============================================================
    # APRÈS REDÉMARRAGE : EXÉCUTER LA SUITE
    # ============================================================

    # ============================================================
    # ÉTAPE 2 : PROMOTION ACTIVE DIRECTORY
    # ============================================================
    Write-Host "`n[Étape 2/5] Promotion Active Directory..." -ForegroundColor Yellow

    # Installer AD DS
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    Write-Host "  ✅ AD-Domain-Services installé" -ForegroundColor Green

    # Importer le module
    Import-Module ADDSDeployment

    # Promouvoir en DC
    $DSRMPassword = ConvertTo-SecureString "P@ssw0rd-DSRM-2024!" -AsPlainText -Force

    Install-ADDSForest `
        -DomainName "branch.local" `
        -DomainNetbiosName "BRANCH" `
        -ForestMode "WinThreshold" `
        -DomainMode "WinThreshold" `
        -InstallDns `
        -SafeModeAdministratorPassword $DSRMPassword `
        -Force

    Write-Host "  ✅ Promotion en cours... Redémarrage automatique" -ForegroundColor Green

    # Le serveur redémarre automatiquement
    # Attendre 5 minutes puis reconnecter avec BRANCH\Administrator

    # ============================================================
    # APRÈS PROMOTION : EXÉCUTER LA SUITE
    # ============================================================

    # ============================================================
    # ÉTAPE 3 : STRUCTURE AD & UTILISATEURS
    # ============================================================
    Write-Host "`n[Étape 3/5] Structure AD & Utilisateurs..." -ForegroundColor Yellow

    # Variables
    $DomainDN = (Get-ADDomain).DistinguishedName

    # Créer les OU
    New-ADOrganizationalUnit -Name "Users" -Path $DomainDN
    New-ADOrganizationalUnit -Name "Computers" -Path $DomainDN
    New-ADOrganizationalUnit -Name "Groups" -Path $DomainDN
    New-ADOrganizationalUnit -Name "Admins" -Path $DomainDN
    New-ADOrganizationalUnit -Name "Tier0" -Path "OU=Admins,$DomainDN"
    New-ADOrganizationalUnit -Name "Tier1" -Path "OU=Admins,$DomainDN"
    New-ADOrganizationalUnit -Name "Tier2" -Path "OU=Admins,$DomainDN"
    Write-Host "  ✅ OUs créées" -ForegroundColor Green

    # Créer les groupes
    New-ADGroup -Name "G_Users_Lyon" `
        -GroupScope Global `
        -GroupCategory Security `
        -Path "OU=Groups,$DomainDN"

    New-ADGroup -Name "G_Admins_Tier0" `
        -GroupScope Global `
        -GroupCategory Security `
        -Path "OU=Groups,$DomainDN"
    Write-Host "  ✅ Groupes créés" -ForegroundColor Green

    # Créer admin-t0-dc
    $Password = ConvertTo-SecureString "P@ssw0rd-Admin-2024!" -AsPlainText -Force
    New-ADUser `
        -Name "Admin Tier 0 DC" `
        -SamAccountName "admin-t0-dc" `
        -UserPrincipalName "admin-t0-dc@branch.local" `
        -Path "OU=Tier0,OU=Admins,$DomainDN" `
        -AccountPassword $Password `
        -Enabled $true `
        -PasswordNeverExpires $true

    Add-ADGroupMember -Identity "Domain Admins" -Members "admin-t0-dc"
    Write-Host "  ✅ admin-t0-dc créé" -ForegroundColor Green

    # Créer jdupont et mmartin
    $Password = ConvertTo-SecureString "Welcome2024!" -AsPlainText -Force

    New-ADUser `
        -Name "Jean Dupont" `
        -SamAccountName "jdupont" `
        -UserPrincipalName "jdupont@branch.local" `
        -Path "OU=Users,$DomainDN" `
        -AccountPassword $Password `
        -Enabled $true `
        -ChangePasswordAtLogon $true

    New-ADUser `
        -Name "Marie Martin" `
        -SamAccountName "mmartin" `
        -UserPrincipalName "mmartin@branch.local" `
        -Path "OU=Users,$DomainDN" `
        -AccountPassword $Password `
        -Enabled $true `
        -ChangePasswordAtLogon $true

    Add-ADGroupMember -Identity "G_Users_Lyon" -Members jdupont, mmartin
    Write-Host "  ✅ Utilisateurs créés" -ForegroundColor Green

    # ============================================================
    # ÉTAPE 4 : HARDENING
    # ============================================================
    Write-Host "`n[Étape 4/5] Hardening..." -ForegroundColor Yellow

    # Désactiver SMBv1
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart
    Write-Host "  ✅ SMBv1 désactivé" -ForegroundColor Green

    # Désactiver LLMNR
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" `
        -Name "EnableMulticast" -Value 0 -Type DWord
    Write-Host "  ✅ LLMNR désactivé" -ForegroundColor Green

    # Désactiver NBT-NS
    $Adapters = Get-WmiObject Win32_NetworkAdapterConfiguration |
        Where-Object { $_.TcpipNetbiosOptions -ne $null }
    foreach ($Adapter in $Adapters) {
        $Adapter.SetTcpipNetbios(2)
    }
    Write-Host "  ✅ NBT-NS désactivé" -ForegroundColor Green

    # Activer Audit 4688
    auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
        -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
    wevtutil sl Security /ms:1073741824
    Write-Host "  ✅ Audit 4688 activé" -ForegroundColor Green

    # Firewall
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
    Set-NetFirewallProfile -Profile Domain,Private,Public `
        -DefaultInboundAction Block `
        -DefaultOutboundAction Allow
    Enable-NetFirewallRule -DisplayGroup "Active Directory Domain Services"
    Enable-NetFirewallRule -DisplayGroup "DNS Service"
    Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
    Enable-NetFirewallRule -DisplayGroup "Windows Remote Management"
    Write-Host "  ✅ Firewall configuré" -ForegroundColor Green

    # Defender
    Update-MpSignature
    Set-MpPreference -DisableRealtimeMonitoring $false
    Write-Host "  ✅ Defender à jour" -ForegroundColor Green

    # ============================================================
    # ÉTAPE 5 : VALIDATION
    # ============================================================
    Write-Host "`n[Étape 5/5] Validation..." -ForegroundColor Yellow
    Write-Host "  Exécuter le script Test-DC-Compliance.ps1 pour valider" -ForegroundColor Yellow

    Write-Host "`n=== DÉPLOIEMENT TERMINÉ ===" -ForegroundColor Cyan
    Write-Host "✅ Domain Controller prêt !" -ForegroundColor Green
    ```

---

**[← Retour au Module 3](03-module.md)** | **[Retour à l'Introduction](index.md)**

---

## Navigation

| | |
|:---|---:|
| [← Module 3 : Sécurité & Hardening - Déf...](03-module.md) | [Programme →](index.md) |

[Retour au Programme](index.md){ .md-button }
